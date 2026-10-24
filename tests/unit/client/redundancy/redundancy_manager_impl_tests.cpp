// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 ua::client::detail::RedundancyManagerImpl (client design section 8.11): the
// own-strand non-transparent redundancy / failover engine. Drives the strand-bearing Impl against a
// FakeRedundancyManagerHost (no ConnectionImpl, Session, or wire stack - the mockable host interface is the
// whole point) and asserts its OWN section 8.11.4 FSM logic: the transition table, the cause-variant mapping,
// the scoring function + ScoringBackups fanout, the hysteresis ring + window, the RecoveryWindow anti-thrash
// gate, the mGeneration stale-callback guard, and the CL-REDUN-001..010 behavioural contracts. Every test is
// FALSIFIABLE: it asserts the host calls issued (which primitive, with what args) AND the resulting state /
// snapshot / observer fire.
//
// The io_context is single-threaded; state is read via RedundancyManagerTestAccess only AFTER draining, so
// there is no cross-strand race. A per-fixture injectable clock makes the time-based hysteresis window and
// probe/failover timestamps deterministic; RecoveryWindow timing is driven by policy.recoveryWindow (0s to
// fire on drain, large to keep the window open) - no real sleeping.

#include "ua_redundancy_manager_impl.h"

#include "fake_redundancy_manager_host.h"
#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_test_access.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace
{

using ua::RedundancySupport;
using ua::Status;
using ua::VoidResult;
using ua::client::ReconnectOutcome;
using ua::client::RedundancyDegradeReason;
using ua::client::RedundancyManagerState;
using ua::client::RedundancyPolicy;
using ua::client::RedundancySwitchInfo;
using ua::client::detail::RedundancyManagerImpl;
using ua::client::detail::RedundancyManagerTestAccess;
using ua::testing::FakeRedundancyManagerHost;

constexpr const char* a = "urn:server:a";
constexpr const char* b = "urn:server:b";
constexpr const char* c = "urn:server:c";
constexpr const char* urlB = "opc.tcp://b";
constexpr const char* urlC = "opc.tcp://c";

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeRedundancyManagerHost> host = std::make_shared<FakeRedundancyManagerHost>();
  RedundancyPolicy policy;
  std::shared_ptr<ua::DateTime> clock = std::make_shared<ua::DateTime>(ua::DateTime::now());

  std::shared_ptr<RedundancyManagerImpl> make()
  {
    auto impl = RedundancyManagerImpl::create(ctx.get_executor(), host, ua::Logger{}, policy);
    RedundancyManagerTestAccess::set_now_fn(*impl, [clock = clock] { return *clock; });
    return impl;
  }

  // Poll-based draining: runs every ready handler (including already-expired timers, e.g. a
  // recoveryWindow=0s test) to a fixed point, but NEVER blocks on a still-pending timer (e.g. a
  // recoveryWindow=3600s suppression test) - so a manager sitting in RecoveryWindow with an armed long timer
  // does not hang the test thread. Poll, don't sleep (testing.md).
  void drain()
  {
    for (;;)
    {
      ctx.restart();
      if (ctx.poll() == 0)
      {
        break;
      }
    }
  }

  // Bounded blocking run that SERVICES a freshly-armed already-expired timer (poll() does not fire a
  // recoveryWindow=0s steady_timer within the same cycle). run_for returns as soon as work is exhausted, so
  // for a 0s timer the re-discovery cascade runs and it returns well under the cap - never a real wall wait.
  void settle_timers()
  {
    ctx.restart();
    ctx.run_for(std::chrono::milliseconds{200});
    // Under heavy parallel shard load the 200ms wall budget can be starved of CPU before the
    // timer-triggered cascade (e.g. window-timer -> enter_scoring -> probe -> score -> failover) completes,
    // leaving the manager mid-transition. Finish it with an unbounded poll-drain - poll() runs only
    // already-ready/expired handlers, so a still-pending long timer (e.g. a 3600s recoveryWindow
    // suppression test) is left armed and never blocks the thread.
    for (;;)
    {
      ctx.restart();
      if (ctx.poll() == 0)
      {
        break;
      }
    }
  }

  void advance(std::chrono::seconds seconds)
  {
    *clock =
      ua::DateTime{clock->value() + std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(seconds)};
  }
};

// Scripts a full Cold/Warm/Hot/HotAndMirrored discovery of the {a,b,c} redundant set (active = a).
void script_discovery(FakeRedundancyManagerHost& host, RedundancySupport mode)
{
  host.applicationUri = a;
  host.set_redundancy_support(mode);
  host.set_server_uri_array({a, b, c});
  host.add_find_server(a, {"opc.tcp://a"});
  host.add_find_server(b, {urlB});
  host.add_find_server(c, {urlC});
}

// Brings an already-scripted manager from Dormant to Monitoring.
void activate(Fixture& fixture, RedundancyManagerImpl& impl)
{
  impl.on_session_active_async(ua::NodeId{}, [](VoidResult) {});
  fixture.drain();
}

const RedundancySwitchInfo* switch_info(const ua::client::ReconnectCause& cause)
{
  return std::get_if<RedundancySwitchInfo>(&cause);
}

// Drives a below-healthy hysteresis ring (default capacity 5) so Monitoring enters ScoringBackups.
void deliver_below_healthy_ring(Fixture& fixture, FakeRedundancyManagerHost& host, std::uint8_t level)
{
  for (std::size_t i = 0; i < fixture.policy.hysteresisRingCapacity; ++i)
  {
    host.deliver_service_level(level);
  }
  fixture.drain();
}

// @relation(AC-SVR-DISC-CAP-003-NTRS-CAPABILITY, scope=function)

// ============================================================================
// Discovery - CL-REDUN-001 / 002 / 003
// ============================================================================

// @verifies CL-REDUN-001
// transition: Dormant --on_session_active--> Discovering --all good--> Monitoring
// @relation(CL-REDUN-001, scope=function)
TEST(ClientRedundancyDiscovery, ReadsRedundancySupportAfterActivate)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();

  activate(f, *impl);

  ASSERT_FALSE(f.host->readCalls.empty());
  EXPECT_EQ(f.host->readCalls.front().front().node_id(),
    ua::NodeId{ua::VariableId::Server_ServerRedundancy_RedundancySupport});
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// @verifies CL-REDUN-001
// transition: Discovering --RedundancySupport None--> Dormant
// @relation(CL-REDUN-001, scope=function)
TEST(ClientRedundancyDiscovery, NoneSkipsManager)
{
  Fixture f;
  f.host->set_redundancy_support(RedundancySupport::None);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_EQ(f.host->readCalls.size(), 1u);  // did NOT read ServerUriArray
  EXPECT_TRUE(f.host->monitorCalls.empty());  // did NOT install a MonitoredItem
}

// @relation(AC-SVR-AC-084-TRANSPARENT-NO-ACTION, scope=function)

// @verifies CL-REDUN-001
// transition: Discovering --RedundancySupport Transparent--> Dormant
// @relation(CL-REDUN-001, scope=function)
TEST(ClientRedundancyDiscovery, TransparentSkipsManager)
{
  Fixture f;
  f.host->set_redundancy_support(RedundancySupport::Transparent);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_EQ(f.host->readCalls.size(), 1u);
  EXPECT_TRUE(f.host->monitorCalls.empty());
}

// @verifies CL-REDUN-002
// @relation(CL-REDUN-002, scope=function)
TEST(ClientRedundancyDiscovery, ReadsServerUriArrayWhenNonTransparent)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();

  activate(f, *impl);

  ASSERT_EQ(f.host->readCalls.size(), 2u);
  EXPECT_EQ(f.host->readCalls[1].front().node_id(),
    ua::NodeId{ua::VariableId::Server_ServerRedundancy_ServerUriArray});
  EXPECT_EQ(RedundancyManagerTestAccess::server_uri_array(*impl).size(), 3u);
}

// @verifies CL-REDUN-002
// @relation(CL-REDUN-002, scope=function)
TEST(ClientRedundancyDiscovery, HandlesEmptyArrayGracefully)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({});  // empty - server bug; treat as redundant set of one
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.server_uri_array_empty"));
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 1u);  // active only
}

// @relation(AC-SVR-BASE-002-SERVERARRAY-SELF, scope=function)
// @relation(AC-SVR-BASE-055-NONREDUNDANT-REPORTS-NONE, scope=function)
// @relation(AC-SVR-BASE-059-NONTRANSPARENT-VALUES, scope=function)

// @verifies CL-REDUN-002
// @relation(CL-REDUN-002, scope=function)
TEST(ClientRedundancyDiscovery, HandlesArrayContainingOnlySelf)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Warm);
  f.host->set_server_uri_array({a});
  f.host->add_find_server(a, {"opc.tcp://a"});
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 1u);
}

// section 3.1 defensive: the spec mandates the active server appear in a NON-empty ServerUriArray; a server
// bug that omits it (while still listing others) must advise (not only the fully-empty case), and the active
// is still appended as a candidate.
TEST(ClientRedundancyDiscovery, NonEmptyArrayMissingSelfAdvises)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({b, c});  // non-empty but omits self (a)
  f.host->add_find_server(b, {urlB});
  f.host->add_find_server(c, {urlC});
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.server_uri_array_missing_self"));
  const auto candidateA = RedundancyManagerTestAccess::candidate(*impl, a);
  ASSERT_TRUE(candidateA.has_value());  // active appended despite the omission
  EXPECT_TRUE(candidateA->isActive);
}

// @verifies CL-REDUN-003
// @relation(CL-REDUN-003, scope=function)
TEST(ClientRedundancyDiscovery, CallsFindServersAfterServerUriArray)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(f.host->findServersCalls, 1);
  const auto candidateB = RedundancyManagerTestAccess::candidate(*impl, b);
  ASSERT_TRUE(candidateB.has_value());
  ASSERT_TRUE(candidateB->applicationDescription.has_value());
  ASSERT_EQ(candidateB->discoveryUrls.size(), 1u);
  EXPECT_EQ(candidateB->discoveryUrls.front(), urlB);
}

// @verifies CL-REDUN-003
// @relation(CL-REDUN-003, scope=function)
TEST(ClientRedundancyDiscovery, HandlesPartialFindServersResult)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({a, b, c});
  f.host->add_find_server(a, {"opc.tcp://a"});
  f.host->add_find_server(b, {urlB});  // c deliberately unresolved
  auto impl = f.make();

  activate(f, *impl);

  const auto candidateC = RedundancyManagerTestAccess::candidate(*impl, c);
  ASSERT_TRUE(candidateC.has_value());
  EXPECT_FALSE(candidateC->applicationDescription.has_value());
  EXPECT_TRUE(candidateC->discoveryUrls.empty());
}

// @verifies CL-REDUN-003
// @relation(CL-REDUN-003, scope=function)
TEST(ClientRedundancyDiscovery, UsesDiscoveryUrlsAtFailoverTime)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_FALSE(f.host->probeCalls.empty());
  EXPECT_NE(std::find(f.host->probeCalls.begin(), f.host->probeCalls.end(), urlB), f.host->probeCalls.end());
}

// transition: Discovering --RedundancySupport Read Bad--> Dormant
TEST(ClientRedundancyDiscovery, RedundancySupportReadBadGoesDormant)
{
  Fixture f;
  f.host->fail_redundancy_support(Status::BadNodeIdUnknown);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.discovery_redundancysupport_read_failed"));
}

// transition: Discovering --ServerUriArray Read Bad--> Dormant
TEST(ClientRedundancyDiscovery, ServerUriArrayReadBadGoesDormant)
{
  Fixture f;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->fail_server_uri_array(Status::BadNodeIdUnknown);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.discovery_serveruriarray_read_failed"));
  EXPECT_TRUE(f.host->monitorCalls.empty());
}

// The manager decides on the RedundancySupport answer, so an Uncertain one holding a usable value is not
// acted on: the manager goes Dormant as for a failed read, without reading the ServerUriArray.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientRedundancyDiscovery, UncertainRedundancySupportReadGoesDormant)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->redundancySupportResponse = FakeRedundancyManagerHost::ReadResult{
    std::vector<ua::DataValue>{ua::DataValue{ua::Variant{static_cast<std::int32_t>(RedundancySupport::Hot)}}},
    ua::StatusCode{Status::UncertainLastUsableValue}};
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.discovery_redundancysupport_read_failed"));
  EXPECT_EQ(f.host->readCalls.size(), 1u) << "the ServerUriArray must not be read after an Uncertain answer";
  EXPECT_TRUE(f.host->monitorCalls.empty());
}

// The redundant set is not taken from an Uncertain ServerUriArray answer: the manager goes Dormant and
// monitors nothing.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(ClientRedundancyDiscovery, UncertainServerUriArrayReadGoesDormant)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  ua::Array<ua::String> uris;
  for (const char* uri : {a, b, c})
  {
    uris.push_back(ua::String{uri});
  }
  f.host->serverUriArrayResponse = FakeRedundancyManagerHost::ReadResult{
    std::vector<ua::DataValue>{ua::DataValue{ua::Variant{std::move(uris)}}},
    ua::StatusCode{Status::UncertainLastUsableValue}};
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.discovery_serveruriarray_read_failed"));
  EXPECT_TRUE(f.host->monitorCalls.empty());
  EXPECT_TRUE(RedundancyManagerTestAccess::server_uri_array(*impl).empty());
}

// The manager decides its mode on the RedundancySupport value itself, so a value whose own status is
// Uncertain is not used: the manager goes Dormant as for a failed read, without reading the ServerUriArray.
// @relation(CL-REDUN-001, AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientRedundancyDiscovery, AnUncertainRedundancySupportValueGoesDormant)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  ua::DataValue support{ua::Variant{static_cast<std::int32_t>(RedundancySupport::Hot)}};
  support.status() = ua::StatusCode{Status::UncertainLastUsableValue};
  f.host->redundancySupportResponse =
    FakeRedundancyManagerHost::ReadResult{std::vector<ua::DataValue>{std::move(support)}};
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.discovery_redundancysupport_read_failed"));
  EXPECT_EQ(f.host->readCalls.size(), 1u) << "the ServerUriArray must not be read after an Uncertain value";
  EXPECT_TRUE(f.host->monitorCalls.empty());
}

// The redundant set is not taken from a ServerUriArray value whose own status is Uncertain: the array counts
// as empty, as a Bad one does, so the manager advises and monitors the active Server alone.
// @relation(CL-REDUN-002, AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientRedundancyDiscovery, AnUncertainServerUriArrayValueIsNotTheRedundantSet)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  ua::Array<ua::String> uris;
  for (const char* uri : {a, b, c})
  {
    uris.push_back(ua::String{uri});
  }
  ua::DataValue array{ua::Variant{std::move(uris)}};
  array.status() = ua::StatusCode{Status::UncertainLastUsableValue};
  f.host->serverUriArrayResponse =
    FakeRedundancyManagerHost::ReadResult{std::vector<ua::DataValue>{std::move(array)}};
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.server_uri_array_empty"));
  EXPECT_EQ(RedundancyManagerTestAccess::server_uri_array(*impl), std::vector<std::string>{a})
    << "the array is treated as empty, and the active Server is added to it";
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 1u) << "the active Server alone";
}

// FindServers Bad still enters Monitoring (candidates keep nullopt applicationDescription).
TEST(ClientRedundancyDiscovery, FindServersBadStillEntersMonitoring)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({a, b});
  f.host->fail_find_servers(Status::BadServiceUnsupported);
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.findservers_read_failed"));
  const auto candidateB = RedundancyManagerTestAccess::candidate(*impl, b);
  ASSERT_TRUE(candidateB.has_value());
  EXPECT_FALSE(candidateB->applicationDescription.has_value());
}

// transition: Discovering --MI install Bad (after one retry)--> Dormant
TEST(ClientRedundancyDiscovery, MiInstallBadAfterOneRetryGoesDormant)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->monitorInstallFailsRemaining = 2;  // fail both the first attempt and the single retry
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(f.host->monitorCalls.size(), 2u);  // initial + one retry
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.servicelevel_mi_install_failed"));
}

TEST(ClientRedundancyDiscovery, MiInstallRetriesOnceThenSucceeds)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->monitorInstallFailsRemaining = 1;  // fail once, succeed on the retry
  auto impl = f.make();

  activate(f, *impl);

  EXPECT_EQ(f.host->monitorCalls.size(), 2u);
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// A ServiceLevel-monitor install whose CreateMonitoredItems reply lands AFTER its discovery generation was
// superseded (a session-close during the install round-trip) must be CANCELLED, not silently dropped - a
// dropped stale MI orphans a MonitoredItem on the transfer-surviving ServiceLevel Subscription.
TEST(ClientRedundancyDiscovery, SupersededServiceLevelMonitorIsCancelledNotOrphaned)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_hold_monitor(true);  // park the install so we can bump the generation mid-flight
  auto impl = f.make();

  activate(f, *impl);  // discovery runs to the install step; the monitor create is parked
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Discovering);
  ASSERT_EQ(f.host->monitorCalls.size(), 1u) << "the install was issued and is now parked";
  const std::uint64_t installGeneration = RedundancyManagerTestAccess::generation(*impl);

  // Supersede the generation: a session-close during the install round-trip bumps mGeneration and falls back
  // to Dormant (the in-flight install is now stale).
  impl->on_session_closed_async([](VoidResult) {});
  f.drain();
  ASSERT_GT(RedundancyManagerTestAccess::generation(*impl), installGeneration)
    << "the session-close superseded the install generation";
  ASSERT_EQ(f.host->cancelCalls, 0) << "nothing cancelled yet - the stale MI reply has not landed";

  // The held install now completes Good, at the superseded generation. The manager must cancel this orphaned
  // MonitoredItem rather than drop it.
  f.host->complete_held_monitor_good();
  f.drain();

  EXPECT_EQ(f.host->cancelCalls, 1)
    << "the superseded-generation ServiceLevel MonitoredItem is cancelled, not orphaned";
}

// The CLOSED-path counterpart: when the manager is fully CLOSED (do_close resets mHost to null) while a
// ServiceLevel install is still in flight, the superseded-generation completion must NOT dereference the
// now-null mHost. is_current() is false for BOTH a generation bump AND the Closed state, so the stale branch
// runs while mHost is gone - the `&& mHost` guard makes it skip the cancel (the MI is reclaimed by
// connection/session teardown) instead of crashing. Without the guard this test segfaults (null mHost->call).
TEST(ClientRedundancyDiscovery, ClosedDuringServiceLevelInstallSkipsCancelWithoutCrash)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_hold_monitor(true);  // park the install so we can close mid-flight
  auto impl = f.make();

  activate(f, *impl);  // discovery runs to the install step; the monitor create is parked
  ASSERT_EQ(f.host->monitorCalls.size(), 1u) << "the install was issued and is now parked";

  // Fully close the manager: do_close bumps the generation, sets state Closed, and RESETS mHost to null.
  std::optional<VoidResult> closeResult;
  impl->close_async([&closeResult](VoidResult result) { closeResult = result; });
  f.drain();
  ASSERT_TRUE(closeResult.has_value());
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
  ASSERT_EQ(f.host->cancelCalls, 0) << "nothing cancelled yet - the stale MI reply has not landed";

  // The held install now completes Good at the superseded (Closed) generation. With mHost released, the
  // manager must SKIP the cancel (no null deref, no crash) rather than orphaning-vs-crashing.
  f.host->complete_held_monitor_good();
  f.drain();

  EXPECT_EQ(f.host->cancelCalls, 0)
    << "with the manager Closed (mHost released), the stale-MI cancel is skipped (teardown reclaims it)";
}

// ============================================================================
// Monitoring / hysteresis - CL-REDUN-004
// ============================================================================

// @verifies CL-REDUN-004
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, NoFailoverWhileHealthyRange)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 250);  // 5 Healthy samples

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->degradedFires.empty());
  EXPECT_TRUE(f.host->reconnectCalls.empty());
}

// @verifies CL-REDUN-004
// transition: Monitoring --ring all < threshold--> ScoringBackups
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, FailoverWhenBelowHealthy)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  EXPECT_EQ(f.host->degradedFires.front().second, RedundancyDegradeReason::ServiceLevelBelowHealthy);
  EXPECT_FALSE(f.host->probeCalls.empty());  // entered ScoringBackups
}

// @verifies CL-REDUN-004
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, SingleHealthySampleMidRingDoesNotTrigger)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  // Ring = [100,100,250,100,100]: the single Healthy sample keeps "all below" false.
  f.host->deliver_service_level(100);
  f.host->deliver_service_level(100);
  f.host->deliver_service_level(250);
  f.host->deliver_service_level(100);
  f.host->deliver_service_level(100);
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->degradedFires.empty());
}

// @verifies CL-REDUN-004
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, ServiceLevelJitterAroundThresholdDoesNotThrash)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  f.host->deliver_service_level(199);
  f.host->deliver_service_level(201);
  f.host->deliver_service_level(199);
  f.host->deliver_service_level(201);
  f.host->deliver_service_level(199);
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->degradedFires.empty());
}

// @verifies CL-REDUN-004
// transition: Monitoring --MI Bad for hysteresisWindow--> ScoringBackups (ServiceLevelInaccessible)
// section 3.1 H3: an OPC-UA MonitoredItem is change-only - a stays-Bad active delivers ONE Bad then goes
// silent, so the "MI Bad for hysteresisWindow" degrade must be driven by a one-shot window TIMER, not by a
// second Bad delivery. A SINGLE Bad sample (no further deliveries) must still degrade once the window
// elapses. Poll (drain) does not service the freshly-armed 0s window timer; settle_timers does.
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, FailoverWhenServiceLevelLost)
{
  Fixture f;
  // Real (non-zero) window the wait-free drain() poll-loop cannot reach in its microsecond life, but
  // settle_timers()'s run_for + poll-drain will - so the "not fired synchronously on delivery" assertion
  // below holds deterministically even under heavy shard load (a 0s already-expired timer fires during
  // drain).
  f.policy.hysteresisWindow = std::chrono::milliseconds{100};
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  f.host->deliver_service_level_bad();  // ONE Bad; change-only MI delivers nothing further
  f.drain();
  EXPECT_TRUE(f.host->degradedFires.empty());  // must NOT fire synchronously on the delivery

  f.settle_timers();  // the armed window timer fires with no second delivery

  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  EXPECT_EQ(f.host->degradedFires.front().second, RedundancyDegradeReason::ServiceLevelInaccessible);
}

// @verifies CL-REDUN-004
// @relation(CL-REDUN-004, scope=function)
TEST(ClientRedundancyMonitoring, ServiceLevelInaccessibleUsesWindowNotRing)
{
  Fixture f;
  f.policy.hysteresisWindow = std::chrono::seconds{5};
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  // Two Bad deliveries with NO virtual-time advance: the window never elapses, so no failover - the ring
  // is not involved in the Bad path.
  f.host->deliver_service_level_bad();
  f.host->deliver_service_level_bad();
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->degradedFires.empty());
}

// The manager decides its failover on the active Server's ServiceLevel itself, so a sample whose own status
// is Uncertain counts as inaccessible, as a Bad one does: held for the hysteresis window, it degrades with
// ServiceLevelInaccessible although the value it holds is in the Healthy range.
// @relation(CL-REDUN-004, AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientRedundancyMonitoring, AnUncertainServiceLevelCountsAsInaccessible)
{
  Fixture f;
  f.policy.hysteresisWindow = std::chrono::milliseconds{100};
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  f.host->deliver_service_level_with_status(250, Status::UncertainLastUsableValue);
  f.drain();
  EXPECT_TRUE(f.host->degradedFires.empty());

  f.settle_timers();

  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  EXPECT_EQ(f.host->degradedFires.front().second, RedundancyDegradeReason::ServiceLevelInaccessible);
}

// @verifies CL-REDUN-006
// @relation(CL-REDUN-006, scope=function)
TEST(ClientRedundancyMonitoring, RefreshesCacheOnServiceLevelChange)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  f.host->deliver_service_level(230);
  f.drain();

  const auto active = RedundancyManagerTestAccess::candidate(*impl, a);
  ASSERT_TRUE(active.has_value());
  ASSERT_TRUE(active->lastServiceLevel.has_value());
  EXPECT_EQ(*active->lastServiceLevel, 230);
  EXPECT_EQ(impl->redundancy_info()->activeServiceLevel, std::optional<std::uint8_t>{230});
}

// section 3.1 M9: with hysteresisRingCapacity == 0 the sample ring is disabled; the history deque must NOT
// accumulate (a server pushing frequent samples would otherwise grow it without bound).
TEST(ClientRedundancyMonitoring, HistoryBoundedWhenRingCapacityZero)
{
  Fixture f;
  f.policy.hysteresisRingCapacity = 0;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  for (int i = 0; i < 10000; ++i)
  {
    f.host->deliver_service_level(250);
  }
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::history_size(*impl), 0u);
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// ============================================================================
// ScoringBackups - CL-REDUN-005 + fanout
// ============================================================================

// @verifies CL-REDUN-005
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyScoring, PicksHighestServiceLevelWhenFailingOver)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);  // Healthy
  f.host->set_probe_result(urlC, 180);  // Degraded
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->toUri, b);  // 240 > 180
}

// @verifies CL-REDUN-005
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyScoring, FallsBackToDegradedWhenNoHealthyAvailable)
{
  Fixture f;
  f.policy.fallbackToDegraded = true;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 100);  // Degraded but > active 50
  f.host->set_probe_result(urlC, 60);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 50);  // active = 50

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->toUri, b);
}

// @verifies CL-REDUN-005
// transition: ScoringBackups --no eligible candidate--> Monitoring
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyScoring, NoEligibleCandidateStaysInMonitoringWithAdvisory)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 80);  // both worse than active 100
  f.host->set_probe_result(urlC, 70);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);  // active = 100

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->reconnectCalls.empty());
  // section 3.1 W10: the transition table (client_design.md:11612) names this advisory
  // `no_eligible_candidate`.
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.no_eligible_candidate"));
}

// @verifies CL-REDUN-005
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyScoring, TieBrokenByUriWhenLevelAndProbeAtEqual)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);  // same level, same (frozen) clock -> tie-break by uri (b < c)
  f.host->set_probe_result(urlC, 240);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->toUri, b);
}

// @verifies CL-REDUN-009
// @relation(CL-REDUN-009, scope=function)
TEST(ClientRedundancyScoring, ScoringFanoutProbesInParallel)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->probeCalls.size(), 2u);  // both backups probed in the one fanout pass
  EXPECT_NE(std::find(f.host->probeCalls.begin(), f.host->probeCalls.end(), urlB), f.host->probeCalls.end());
  EXPECT_NE(std::find(f.host->probeCalls.begin(), f.host->probeCalls.end(), urlC), f.host->probeCalls.end());
}

// @verifies CL-REDUN-009
// @relation(CL-REDUN-009, scope=function)
TEST(ClientRedundancyScoring, ProbeFailureMarksLastServiceLevelNullopt)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->fail_probe(urlB);  // b probe fails
  f.host->set_probe_result(urlC, 240);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  const auto candidateB = RedundancyManagerTestAccess::candidate(*impl, b);
  ASSERT_TRUE(candidateB.has_value());
  EXPECT_FALSE(candidateB->lastServiceLevel.has_value());  // marked unknown
  EXPECT_TRUE(candidateB->lastProbeAt.has_value());  // but the probe attempt is recorded
}

// @verifies CL-REDUN-009 - the manager NEVER installs a backup MonitoredItem in ANY mode; backup levels are
// learned reactively via the probe Read.
// @relation(CL-REDUN-009, scope=function)
TEST(ClientRedundancyScoring, NoModeInstallsMiOnBackup)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->monitorCalls.size(), 1u);  // exactly the active ServiceLevel MI
  EXPECT_EQ(f.host->monitorCalls.front().nodeId, ua::NodeId{ua::VariableId::Server_ServiceLevel});
  EXPECT_FALSE(f.host->probeCalls.empty());  // backups via probe, not subscription
}

// @verifies CL-REDUN-009
// @relation(CL-REDUN-009, scope=function)
TEST(ClientRedundancyScoring, HotAndMirroredPollsBackupServiceLevelViaRead)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::HotAndMirrored);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);

  EXPECT_EQ(f.host->monitorCalls.size(), 1u);  // no backup subscription
  EXPECT_FALSE(f.host->probeCalls.empty());  // backup level via probe Read
}

// section 3.1 H1: a backup whose ServiceLevel probe never calls back must NOT pin the FSM in ScoringBackups.
// A per-fanout probe-deadline timer must, on expiry, drop every still-pending probe (level -> unknown) and
// score on whatever replied - so a healthy backup that DID answer still wins the failover.
TEST(ClientRedundancyScoring, HungProbeTimesOutAndScores)
{
  Fixture f;
  // A real (non-zero) deadline the poll-based drain() cannot reach in its microsecond loop but the 200ms
  // settle_timers() run_for will - so the "wedged in ScoringBackups until the deadline" assertion below
  // holds, then the deadline fires under settle_timers(). (probeTimeout=0 would fire eagerly during the ring
  // drain.)
  f.policy.probeTimeout = std::chrono::milliseconds{100};
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->hang_probe(urlB);  // b's probe is captured but never answered
  f.host->set_probe_result(urlC, 240);  // c answers Healthy
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);  // enter ScoringBackups; c replies, b hangs

  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::ScoringBackups);
  EXPECT_EQ(RedundancyManagerTestAccess::pending_probe_count(*impl), 1u);  // b still outstanding
  EXPECT_TRUE(f.host->reconnectCalls.empty());  // wedged until the deadline

  f.settle_timers();  // probe-deadline timer fires -> drop b -> score on c

  EXPECT_EQ(RedundancyManagerTestAccess::pending_probe_count(*impl), 0u);
  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->toUri, c);  // failed over to the backup that answered
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.probe_timeout"));
}

// section 3.1 M6: on ServiceLevelInaccessible the active's cached lastServiceLevel is its last GOOD value; if
// it is left stale-high, scoring's Degraded/Unknown fallback branches can never select a working backup and a
// dead active is never abandoned. Entering scoring via Inaccessible must reset the active's cached level so a
// strictly-better (even Degraded) backup becomes eligible.
TEST(ClientRedundancyScoring, InaccessibleResetsStaleActiveLevelAndFallsBack)
{
  Fixture f;
  f.policy.hysteresisWindow =
    std::chrono::milliseconds{100};  // real window (see FailoverWhenServiceLevelLost)
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({a, b});
  f.host->add_find_server(a, {"opc.tcp://a"});
  f.host->add_find_server(b, {urlB});
  f.host->set_probe_result(urlB, 120);  // Degraded, but the only backup
  auto impl = f.make();
  activate(f, *impl);

  f.host->deliver_service_level(250);  // active last observed Healthy 250
  f.drain();
  f.host->deliver_service_level_bad();  // active goes inaccessible
  f.drain();
  EXPECT_TRUE(f.host->reconnectCalls.empty());

  f.settle_timers();  // window timer -> enter_scoring(Inaccessible) -> probe b -> score

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->toUri, b);  // abandoned the dead active for the degraded-but-live backup
  // section 3.1 defensive: a ServiceLevel MI gone Bad maps to BadNoCommunication (not BadOutOfService).
  EXPECT_EQ(f.host->reconnectCalls.front().degradeStatus.as_status(), Status::BadNoCommunication);
}

// section 3.1 M7: returning to Monitoring from a no-eligible scoring pass must clear the hysteresis ring
// (require a fresh full ring) AND fire on_redundancy_degraded only on the Monitoring->ScoringBackups edge -
// otherwise the next below-healthy sample immediately re-enters scoring, re-firing degraded and re-probing
// every sample.
TEST(ClientRedundancyScoring, NoEligibleReturnDoesNotStormOnNextSample)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 80);  // both worse than active 100 -> no eligible
  f.host->set_probe_result(urlC, 70);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);  // scoring -> no eligible -> Monitoring
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  const std::size_t probesBefore = f.host->probeCalls.size();

  f.host->deliver_service_level(100);  // ONE more below-healthy sample
  f.drain();

  EXPECT_EQ(f.host->degradedFires.size(), 1u);  // no re-fire on the very next sample
  EXPECT_EQ(f.host->probeCalls.size(), probesBefore);  // no re-probe storm
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// section 3.1 M8: a Bad probe reply carries an ErrorDetail; dropping it silently loses the per-backup
// diagnosis. The manager must surface an advisory chaining the probe failure.
TEST(ClientRedundancyScoring, ProbeFailureSurfacesAdvisory)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->fail_probe(urlB, Status::BadNoCommunication);
  f.host->set_probe_result(urlC, 240);
  auto impl = f.make();
  activate(f, *impl);

  deliver_below_healthy_ring(f, *f.host, 100);

  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.probe_failed"));
}

// ============================================================================
// Cause-variant mapping - section 8.11.4 / CL-REDUN-007 / CL-REDUN-010
// ============================================================================

void run_failover_and_assert_mode(RedundancySupport advertisedMode, RedundancySupport expectedCauseMode)
{
  Fixture f;
  script_discovery(*f.host, advertisedMode);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const RedundancySwitchInfo* info = switch_info(f.host->reconnectCalls.front().cause);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->mode, expectedCauseMode);
  EXPECT_EQ(info->fromUri, a);
}

// @verifies CL-REDUN-010 - Cold cause delegates the ConditionRefresh to the tracker (section 8.8 CL-AC-013).
// @relation(CL-AC-013, CL-REDUN-010, scope=function)
TEST(ClientRedundancyCause, ColdKicksWithRedundancySwitchCold)
{
  run_failover_and_assert_mode(RedundancySupport::Cold, RedundancySupport::Cold);
}

TEST(ClientRedundancyCause, WarmKicksWithRedundancySwitchWarm)
{
  run_failover_and_assert_mode(RedundancySupport::Warm, RedundancySupport::Warm);
}

TEST(ClientRedundancyCause, HotKicksWithRedundancySwitchHot)
{
  run_failover_and_assert_mode(RedundancySupport::Hot, RedundancySupport::Hot);
}

// @verifies CL-REDUN-010 - HotAndMirrored cause: the tracker no-ops (events server-mirrored).
// @relation(CL-REDUN-010, scope=function)
TEST(ClientRedundancyCause, HotAndMirroredKicksWithRedundancySwitchHotAndMirrored)
{
  run_failover_and_assert_mode(RedundancySupport::HotAndMirrored, RedundancySupport::HotAndMirrored);
}

// @relation(AC-SVR-AC-081-REDUNDANT-EVENTID-IDENTICAL, scope=function)

// @verifies CL-REDUN-008 - the failover kick carries a RedundancySwitch.* cause; downstream actors
// (EventSubscriber dedup reset, Browse continuation-point invalidation) consume it. Their handling is wired
// in a later slice; here we assert the manager-level contract: the cause IS a RedundancySwitchInfo.
// @relation(CL-REDUN-008, scope=function)
TEST(ClientRedundancyCause, FailoverEmitsRedundancySwitchCauseForDownstream)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  EXPECT_NE(switch_info(f.host->reconnectCalls.front().cause), nullptr);
  ASSERT_EQ(f.host->failoverStartedFires.size(), 1u);
  EXPECT_NE(switch_info(f.host->failoverStartedFires.front().cause), nullptr);
}

// @verifies CL-REDUN-007 - downgrade-only override: advertised Hot may be run as Cold.
// @relation(CL-REDUN-007, scope=function)
TEST(ClientRedundancyCause, HotMayDowngradeToCold)
{
  Fixture f;
  f.policy.overrideMode = RedundancySupport::Cold;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::effective_mode(*impl), RedundancySupport::Cold);

  deliver_below_healthy_ring(f, *f.host, 100);
  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  EXPECT_EQ(switch_info(f.host->reconnectCalls.front().cause)->mode, RedundancySupport::Cold);
}

// @verifies CL-REDUN-007 - HotAndMirrored is sticky: the override is ignored.
// @relation(CL-REDUN-007, scope=function)
TEST(ClientRedundancyCause, OverrideModeIgnoredForHotAndMirrored)
{
  Fixture f;
  f.policy.overrideMode = RedundancySupport::Cold;
  script_discovery(*f.host, RedundancySupport::HotAndMirrored);
  auto impl = f.make();
  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::effective_mode(*impl), RedundancySupport::HotAndMirrored);
}

// @verifies CL-REDUN-007 - an UPGRADE override is silently ignored.
// @relation(CL-REDUN-007, scope=function)
TEST(ClientRedundancyCause, OverrideModeUpgradeSilentlyIgnored)
{
  Fixture f;
  f.policy.overrideMode = RedundancySupport::Hot;  // upgrade attempt over an advertised Cold
  script_discovery(*f.host, RedundancySupport::Cold);
  auto impl = f.make();
  activate(f, *impl);

  EXPECT_EQ(RedundancyManagerTestAccess::effective_mode(*impl), RedundancySupport::Cold);
}

// ============================================================================
// FailingOver / RecoveryWindow - section 8.11.4
// ============================================================================

// Brings a Hot manager through degrade + scoring into FailingOver (reconnect kick pending).
std::shared_ptr<RedundancyManagerImpl> reach_failing_over(Fixture& f)
{
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::FailingOver);
  return impl;
}

// @verifies CL-REDUN-005
// transition: FailingOver --reconnect good--> RecoveryWindow
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyFailover, ReconnectGoodEntersRecoveryWindow)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{3600};  // keep the window open for the assertions
  auto impl = reach_failing_over(f);

  f.host->complete_reconnect(VoidResult{});  // FSM reached Active
  f.drain();
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::RecoveryWindow);
  EXPECT_EQ(RedundancyManagerTestAccess::failover_count(*impl), 1u);
  EXPECT_EQ(RedundancyManagerTestAccess::active_uri(*impl), b);
  const auto candidateA = RedundancyManagerTestAccess::candidate(*impl, a);
  const auto candidateB = RedundancyManagerTestAccess::candidate(*impl, b);
  ASSERT_TRUE(candidateA && candidateB);
  EXPECT_FALSE(candidateA->isActive);
  EXPECT_TRUE(candidateB->isActive);
  ASSERT_EQ(f.host->failoverCompletedFires.size(), 1u);
  EXPECT_EQ(f.host->failoverCompletedFires.front().nowActiveUri, b);
  // section 8.11.3: the manager SURVIVES its own switch - the candidate set is retained, not reset.
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 3u);
}

// @verifies CL-REDUN-005 - section 8.11.5 error chain shape.
// transition: FailingOver --reconnect Bad--> Monitoring
// @relation(CL-REDUN-005, scope=function)
TEST(ClientRedundancyFailover, ReconnectBadReturnsToMonitoring)
{
  Fixture f;
  auto impl = reach_failing_over(f);

  f.host->complete_reconnect(VoidResult{ua::StatusCode{Status::BadConnectionClosed,
    ua::make_error_detail("FSM_EXHAUSTED", "reconnect exhausted", "client.tier1.reconnect")}});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->failoverCompletedFires.empty());  // NOT fired on Bad
  const auto snapshot = impl->redundancy_info();
  ASSERT_TRUE(snapshot->lastFailoverError != nullptr);
  EXPECT_EQ(snapshot->lastFailoverError->source, "client.tier1.redundancy.failover");
  EXPECT_EQ(snapshot->lastFailoverError->code, "REDUNDANCY_FAILOVER_FAILED");
  ASSERT_TRUE(snapshot->lastFailoverError->cause != nullptr);  // threads the FSM chain
}

// section 3.1 W11: on_reconnect_completed_async keys on mState==FailingOver and blindly swaps active to
// mFailoverTarget, ignoring the outcome. A non-RedundancySwitch reconnect that merely completes while
// FailingOver must NOT be misread as a redundancy switch - no counter bump, no failover_completed; re-run
// discovery instead.
TEST(ClientRedundancyFailover, NonRedundancyReconnectWhileFailingOverDoesNotPhantomSwitch)
{
  Fixture f;
  auto impl = reach_failing_over(f);
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::FailingOver);
  const std::uint64_t failoverBefore = RedundancyManagerTestAccess::failover_count(*impl);

  ReconnectOutcome outcome;
  outcome.cause = ua::client::TransportDropped{};  // an unrelated reconnect, NOT a redundancy switch
  impl->on_reconnect_completed_async(outcome, [](VoidResult) {});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::failover_count(*impl), failoverBefore);  // no phantom bump
  EXPECT_TRUE(f.host->failoverCompletedFires.empty());
  EXPECT_EQ(RedundancyManagerTestAccess::active_uri(*impl), a);  // active NOT swapped to the target
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);  // re-discovered
}

// transition: RecoveryWindow --timer expiry--> Discovering
TEST(ClientRedundancyFailover, RecoveryWindowExpiryReturnsToDiscovering)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{0};  // fires on the next drain
  auto impl = reach_failing_over(f);
  const std::size_t readsBefore = f.host->readCalls.size();

  f.host->complete_reconnect(VoidResult{});
  f.drain();
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.settle_timers();  // enters RecoveryWindow, arms the 0s timer, it fires -> re-discovery -> Monitoring

  EXPECT_GT(f.host->readCalls.size(), readsBefore);  // re-ran discovery against the new active
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// transition: RecoveryWindow --degrade event--> (suppressed)
TEST(ClientRedundancyFailover, NoFailoverDuringRecoveryWindow)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{3600};
  auto impl = reach_failing_over(f);
  f.host->complete_reconnect(VoidResult{});
  f.drain();
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::RecoveryWindow);
  const std::size_t reconnectsBefore = f.host->reconnectCalls.size();

  deliver_below_healthy_ring(f, *f.host, 50);  // degrade while stabilizing - must be suppressed

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::RecoveryWindow);
  EXPECT_EQ(f.host->reconnectCalls.size(), reconnectsBefore);
}

// @design(section 8.11.3) - a failover to a peer advertising a DIFFERENT mode is re-detected when the
// RecoveryWindow expires and discovery re-runs.
TEST(ClientRedundancyFailover, RedetectsModeAfterFailoverToDifferentMode)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{0};
  auto impl = reach_failing_over(f);

  f.host->complete_reconnect(VoidResult{});
  f.drain();
  f.host->set_redundancy_support(RedundancySupport::Warm);  // the new active advertises Warm
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.settle_timers();  // RecoveryWindow -> 0s timer -> re-discovery reads Warm

  EXPECT_EQ(RedundancyManagerTestAccess::effective_mode(*impl), RedundancySupport::Warm);
  EXPECT_TRUE(f.host->has_advisory_source("client.tier1.redundancy.redundancy_mode_changed"));
}

// ============================================================================
// force_switch - section 8.11.4
// ============================================================================

// transition: Monitoring --force_switch valid--> ScoringBackups(manual) -> FailingOver (probes skipped)
TEST(ClientRedundancyForceSwitch, KicksFsmWithManualTargetSkippingProbes)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> switchResult;
  impl->force_switch_async(b, [&](VoidResult result) { switchResult = result; });
  f.drain();

  EXPECT_TRUE(f.host->probeCalls.empty());  // manual target - no probing
  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  EXPECT_EQ(switch_info(f.host->reconnectCalls.front().cause)->toUri, b);
  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  EXPECT_EQ(f.host->degradedFires.front().second, RedundancyDegradeReason::ForceSwitchRequested);
  EXPECT_TRUE(RedundancyManagerTestAccess::has_force_switch_pending(*impl));
}

// transition: Monitoring --force_switch unknown uri--> Monitoring (Bad_NotFound)
TEST(ClientRedundancyForceSwitch, UnknownUriReturnsBadNotFound)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> result;
  impl->force_switch_async("urn:server:z", [&](VoidResult value) { result = value; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status_code().as_status(), Status::BadNotFound);
  ASSERT_TRUE(result->shared_detail() != nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier1.redundancy.force_switch_unknown");
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->reconnectCalls.empty());
}

// transition: Monitoring --force_switch == active uri--> Monitoring (Good no-op)
TEST(ClientRedundancyForceSwitch, ToActiveUriIsNoopGood)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> result;
  impl->force_switch_async(a, [&](VoidResult value) { result = value; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_good());
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_TRUE(f.host->reconnectCalls.empty());
}

// transition: RecoveryWindow --force_switch--> Bad_InvalidState
TEST(ClientRedundancyForceSwitch, DuringRecoveryWindowRejected)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{3600};
  auto impl = reach_failing_over(f);
  f.host->complete_reconnect(VoidResult{});
  f.drain();
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::RecoveryWindow);

  std::optional<VoidResult> result;
  impl->force_switch_async(c, [&](VoidResult value) { result = value; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status_code().as_status(), Status::BadInvalidState);
  ASSERT_TRUE(result->shared_detail() != nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier1.redundancy.force_switch_during_recovery_window");
}

TEST(ClientRedundancyForceSwitch, CompletesGoodOnFailoverSuccess)
{
  Fixture f;
  f.policy.recoveryWindow = std::chrono::seconds{3600};
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> switchResult;
  impl->force_switch_async(b, [&](VoidResult value) { switchResult = value; });
  f.drain();
  f.host->complete_reconnect(VoidResult{});
  f.drain();
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();

  ASSERT_TRUE(switchResult.has_value());
  EXPECT_TRUE(switchResult->is_good());
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::RecoveryWindow);
}

// @design(section 8.11.5) - a terminal force_switch failure completes the caller's callback with the FSM
// chain.
TEST(ClientRedundancyForceSwitch, FailureCompletesWithFsmChain)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> switchResult;
  impl->force_switch_async(b, [&](VoidResult value) { switchResult = value; });
  f.drain();
  f.host->complete_reconnect(VoidResult{ua::StatusCode{Status::BadConnectionClosed,
    ua::make_error_detail("FSM_EXHAUSTED", "reconnect exhausted", "client.tier1.reconnect")}});
  f.drain();

  ASSERT_TRUE(switchResult.has_value());
  EXPECT_TRUE(switchResult->is_bad());
  ASSERT_TRUE(switchResult->shared_detail() != nullptr);
  EXPECT_EQ(switchResult->shared_detail()->source, "client.tier1.redundancy.failover");
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
}

// force_switch pending on close -> callback fires Cancelled (section 8.11.3 close ordering).
TEST(ClientRedundancyForceSwitch, CancelCallbacksFireOnClose)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> switchResult;
  impl->force_switch_async(b, [&](VoidResult value) { switchResult = value; });
  f.drain();
  ASSERT_TRUE(RedundancyManagerTestAccess::has_force_switch_pending(*impl));

  impl->close_async([](VoidResult) {});
  f.drain();

  ASSERT_TRUE(switchResult.has_value());
  EXPECT_EQ(switchResult->status_code().as_status(), Status::BadRequestCancelledByClient);
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
}

// force_switch to a KNOWN uri while not in a switchable state (FailingOver) -> Bad_InvalidState.
TEST(ClientRedundancyForceSwitch, RejectedWhenNotMonitoring)
{
  Fixture f;
  auto impl = reach_failing_over(f);  // array populated (a,b,c); state FailingOver

  std::optional<VoidResult> result;
  impl->force_switch_async(c, [&](VoidResult value) { result = value; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status_code().as_status(), Status::BadInvalidState);
  ASSERT_TRUE(result->shared_detail() != nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier1.redundancy.force_switch_invalid_state");
}

// ============================================================================
// on_transport_fatal - section 8.11.3 / CL-REDUN-006
// ============================================================================

// @verifies CL-REDUN-006 - cached candidates are used when the active transport dies.
// transition: Monitoring --on_transport_fatal + backups--> ScoringBackups (TransportFatalWithBackups)
// @relation(CL-REDUN-006, scope=function)
TEST(ClientRedundancyTransportFatal, UsesCachedCandidatesWhenActiveUnreachable)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  f.host->set_probe_result(urlC, 180);
  auto impl = f.make();
  activate(f, *impl);

  impl->on_transport_fatal_async(ua::StatusCode{Status::BadConnectionClosed}, nullptr, [](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->degradedFires.size(), 1u);
  EXPECT_EQ(f.host->degradedFires.front().second, RedundancyDegradeReason::TransportFatalWithBackups);
  EXPECT_FALSE(f.host->probeCalls.empty());  // used the cached candidate set
}

// @verifies CL-REDUN-006 - merge-not-replace: a partial FindServers on re-discovery keeps cached URLs.
// @relation(CL-REDUN-006, scope=function)
TEST(ClientRedundancyTransportFatal, CacheMergePreservesDiscoveryUrlsOnPartialFindServers)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);  // discovery 1 resolves b with urlB
  auto impl = f.make();
  activate(f, *impl);
  ASSERT_TRUE(RedundancyManagerTestAccess::candidate(*impl, b)->discoveryUrls.size() == 1u);

  // Re-discovery 2 with a FindServers that no longer includes b.
  f.host->findServersResponse.reset();
  f.host->add_find_server(a, {"opc.tcp://a"});  // partial: only a
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();

  const auto candidateB = RedundancyManagerTestAccess::candidate(*impl, b);
  ASSERT_TRUE(candidateB.has_value());
  ASSERT_EQ(candidateB->discoveryUrls.size(), 1u);  // retained across the partial re-discovery
  EXPECT_EQ(candidateB->discoveryUrls.front(), urlB);
}

// section 3.1 H5: the transport-fatal ErrorDetail chain must be threaded as the inner cause of the failover
// degrade detail (source client.tier1.redundancy.failover) - not dropped as a fresh root.
TEST(ClientRedundancyTransportFatal, ThreadsIncomingChainIntoFailoverDegradeDetail)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);

  std::shared_ptr<const ua::ErrorDetail> injected =
    ua::make_error_detail("TRANSPORT_FATAL", "socket reset", "client.tier1.transport");
  impl->on_transport_fatal_async(ua::StatusCode{Status::BadConnectionClosed}, injected, [](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);
  const auto& degradeChain = f.host->reconnectCalls.front().chain;
  ASSERT_TRUE(degradeChain != nullptr);
  EXPECT_EQ(degradeChain->source, "client.tier1.redundancy.failover");
  ASSERT_TRUE(degradeChain->cause != nullptr);  // the incoming transport chain is the inner cause
  EXPECT_EQ(degradeChain->cause->source, "client.tier1.transport");
}

// section 3.1 H5: on a transport-fatal with NO cached backups the manager must not be silent - it must emit
// an advisory that chains the incoming transport chain (so the fatal cause is not lost).
TEST(ClientRedundancyTransportFatal, NoBackupEmitsAdvisoryChainingIncomingChain)
{
  Fixture f;
  f.host->applicationUri = a;
  f.host->set_redundancy_support(RedundancySupport::Hot);
  f.host->set_server_uri_array({a});  // redundant set of one - no backups
  f.host->add_find_server(a, {"opc.tcp://a"});
  auto impl = f.make();
  activate(f, *impl);
  ASSERT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 1u);

  std::shared_ptr<const ua::ErrorDetail> injected =
    ua::make_error_detail("TRANSPORT_FATAL", "socket reset", "client.tier1.transport");
  impl->on_transport_fatal_async(ua::StatusCode{Status::BadConnectionClosed}, injected, [](VoidResult) {});
  f.drain();

  EXPECT_TRUE(f.host->reconnectCalls.empty());  // nothing to fail over to
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  std::shared_ptr<const ua::ErrorDetail> advisory;
  for (const auto& detail : f.host->advisoryFires)
  {
    if (detail && detail->source == "client.tier1.redundancy.transport_fatal_no_backup")
    {
      advisory = detail;
    }
  }
  ASSERT_TRUE(advisory != nullptr);
  ASSERT_TRUE(advisory->cause != nullptr);
  EXPECT_EQ(advisory->cause->source, "client.tier1.transport");
}

// ============================================================================
// Lifecycle / close / stale generation - section 8.11.3 / section 8.11.4
// ============================================================================

// @design(section 8.11.3) - the manager survives a regular reconnect (re-runs discovery, retains candidates).
TEST(ClientRedundancyLifecycle, SurvivesRegularReconnect)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);
  const std::size_t readsBefore = f.host->readCalls.size();

  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();

  EXPECT_GT(f.host->readCalls.size(), readsBefore);  // re-ran discovery
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Monitoring);
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 3u);
}

// on_session_closed drops the MI and falls back to Dormant.
TEST(ClientRedundancyLifecycle, SessionClosedDropsMonitorAndGoesDormant)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);
  ASSERT_TRUE(RedundancyManagerTestAccess::has_service_level_handle(*impl));

  impl->on_session_closed_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_FALSE(RedundancyManagerTestAccess::has_service_level_handle(*impl));
}

// section 3.1 H2: on_session_closed_async must bump mGeneration - otherwise an in-flight discovery reply
// captured at the pre-close generation still passes is_current() and drives the closed session into
// Monitoring with a spurious on_redundancy_recovered. Active immediately followed by Closed (NO drain
// between) must land Dormant with no recovered fire.
TEST(ClientRedundancyLifecycle, SessionClosedBumpsGenerationDropsInflightDiscovery)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();

  impl->on_session_active_async(ua::NodeId{}, [](VoidResult) {});
  impl->on_session_closed_async([](VoidResult) {});  // NO drain between: discovery reply is still in flight
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Dormant);
  EXPECT_TRUE(f.host->recoveredFires.empty());  // the stale discovery reply must not reach Monitoring
}

// section 3.1 H4: re-discovery merges the current ServerUriArray but must EVICT candidates whose URI left the
// set - a server rotating its array each reconnect must not accrete candidates without bound.
TEST(ClientRedundancyLifecycle, CandidatesEvictedOnServerUriArrayRotation)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);  // {a,b,c}
  auto impl = f.make();
  activate(f, *impl);
  ASSERT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 3u);

  f.host->set_server_uri_array({a, "urn:server:d", "urn:server:e"});
  f.host->findServersResponse.reset();
  f.host->add_find_server(a, {"opc.tcp://a"});
  f.host->add_find_server("urn:server:d", {"opc.tcp://d"});
  f.host->add_find_server("urn:server:e", {"opc.tcp://e"});
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();
  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 3u);  // b,c evicted; a,d,e kept

  f.host->set_server_uri_array({a, "urn:server:f", "urn:server:g"});
  f.host->findServersResponse.reset();
  f.host->add_find_server(a, {"opc.tcp://a"});
  f.host->add_find_server("urn:server:f", {"opc.tcp://f"});
  f.host->add_find_server("urn:server:g", {"opc.tcp://g"});
  impl->on_reconnect_completed_async(ReconnectOutcome{}, [](VoidResult) {});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::candidate_count(*impl), 3u);  // d,e evicted; not 7
}

// transition: any --close--> Closed (cancels timers, drops the MI)
TEST(ClientRedundancyClose, FromMonitoringGoesClosed)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  std::optional<VoidResult> closeResult;
  impl->close_async([&](VoidResult result) { closeResult = result; });
  f.drain();

  ASSERT_TRUE(closeResult.has_value());
  EXPECT_TRUE(closeResult->is_good());
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
  EXPECT_GE(f.host->cancelCalls, 1);  // MI dropped via cancel_monitored_item_async
}

TEST(ClientRedundancyClose, IsIdempotent)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  impl->close_async([](VoidResult) {});
  f.drain();
  std::optional<VoidResult> secondClose;
  impl->close_async([&](VoidResult result) { secondClose = result; });
  f.drain();

  ASSERT_TRUE(secondClose.has_value());
  EXPECT_TRUE(secondClose->is_good());
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
}

// transition: any --stale tier-1 callback--> (unchanged; dropped silently)
TEST(ClientRedundancyClose, StaleGenerationCallbackDroppedSilently)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  impl->close_async([](VoidResult) {});
  f.drain();
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);

  // A late MI delivery captured a now-stale generation -> dropped; no crash, no state change.
  f.host->deliver_service_level(100);
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
  EXPECT_TRUE(f.host->degradedFires.empty());
  EXPECT_TRUE(f.host->reconnectCalls.empty());
}

// @design(section 8.11.3) - close during FailingOver: a late FSM completion is dropped by the generation
// guard (the close-before-FSM-cancel ordering invariant, from the manager's side).
TEST(ClientRedundancyClose, LateReconnectCompletionAfterCloseIsDropped)
{
  Fixture f;
  auto impl = reach_failing_over(f);

  impl->close_async([](VoidResult) {});
  f.drain();
  ASSERT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);

  f.host->complete_reconnect(VoidResult{});  // stale - generation bumped by close
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
  EXPECT_TRUE(f.host->failoverCompletedFires.empty());
}

// @verifies CL-MULTI-001 - one manager per Connection; no static state.
// @relation(CL-MULTI-001, scope=function)
TEST(ClientRedundancyLifecycle, TwoConnectionsHaveIndependentManagers)
{
  Fixture f;
  auto host2 = std::make_shared<FakeRedundancyManagerHost>();
  host2->set_redundancy_support(RedundancySupport::None);

  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl1 = f.make();
  auto impl2 = RedundancyManagerImpl::create(f.ctx.get_executor(), host2, ua::Logger{}, RedundancyPolicy{});

  impl1->on_session_active_async(ua::NodeId{}, [](VoidResult) {});
  impl2->on_session_active_async(ua::NodeId{}, [](VoidResult) {});
  f.drain();

  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl1), RedundancyManagerState::Monitoring);
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl2), RedundancyManagerState::Dormant);
}

// @verifies CL-RECONN-005 (cross-ref) - the manager is UNAWARE of backup cert handling: it just kicks the
// switch; the FSM's OpeningChannel step runs GetEndpoints on a novel cert transparently (deferred slice).
// @relation(CL-RECONN-005, scope=function)
TEST(ClientRedundancyLifecycle, BackupWithNovelCertHandledByFsmNotManager)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  f.host->set_probe_result(urlB, 240);
  auto impl = f.make();
  activate(f, *impl);
  deliver_below_healthy_ring(f, *f.host, 100);

  ASSERT_EQ(f.host->reconnectCalls.size(), 1u);  // manager kicked; cert refresh is the FSM's concern
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::FailingOver);
}

// ============================================================================
// Public facade
// ============================================================================

TEST(ClientRedundancyFacade, ForwardsConsumerSurfaceToImpl)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  ua::client::RedundancyManager facade = ua::client::detail::RedundancyManagerFactory::wrap(impl);

  EXPECT_EQ(facade.redundancy_info()->state, RedundancyManagerState::Monitoring);
  ASSERT_TRUE(facade.current_active_endpoint().has_value());
  EXPECT_EQ(*facade.current_active_endpoint(), a);

  std::optional<VoidResult> closeResult;
  facade.close_async([&](VoidResult result) { closeResult = result; });
  f.drain();
  ASSERT_TRUE(closeResult.has_value());
  EXPECT_TRUE(closeResult->is_good());
  EXPECT_EQ(RedundancyManagerTestAccess::state(*impl), RedundancyManagerState::Closed);
}

TEST(ClientRedundancyFacade, MovedFromFacadeIsSafe)
{
  Fixture f;
  script_discovery(*f.host, RedundancySupport::Hot);
  auto impl = f.make();
  activate(f, *impl);

  ua::client::RedundancyManager facade = ua::client::detail::RedundancyManagerFactory::wrap(impl);
  ua::client::RedundancyManager moved = std::move(facade);

  EXPECT_EQ(moved.redundancy_info()->state, RedundancyManagerState::Monitoring);
  // The moved-from facade returns a benign empty snapshot rather than crashing.
  EXPECT_EQ(
    facade.redundancy_info()->state, RedundancyManagerState::Dormant);  // NOLINT(bugprone-use-after-move)
}

}  // namespace
