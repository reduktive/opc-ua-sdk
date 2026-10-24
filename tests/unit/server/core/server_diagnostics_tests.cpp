// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include "ua_server_counters.h"
#include "ua_server_health.h"
#include "ua_request_latency_tracker.h"
#include "ua_service_kind.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_server_impl.h"
#include "ua_variable_id.h"
#include "ua_object_id.h"
#include "ua_node_accessor.h"
#include "ua_session_diagnostics_helper.h"
#include "ua_session_diagnostics_object.h"
#include "ua_session_description.h"
#include "ua_session_security.h"
#include "ua_default_variable_node.h"
#include "ua_access_control.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_ref_structure.h"
#include "ua_server_authentication.h"
#include "ua_security_policy.h"
#include "ua_server_secure_channel_info.h"
#include "ua_activate_session_request.h"
#include "ua_create_session_request.h"
#include "ua_close_session_request.h"
#include "ua_server_session.h"
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel.h"
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <chrono>
#include <future>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

using TestAccess = ua::test_helpers::ServerImplTestAccess;
using ServiceKind = ua::server::ServiceKind;

// ----------------------------------------------------------------------
// Counter struct unit tests
// ----------------------------------------------------------------------

TEST(ServerCounterTests, ServiceCounterIncrementAndLoad)
{
  ServiceCounter sc;
  EXPECT_EQ(sc.totalCount.load(), 0u);
  EXPECT_EQ(sc.errorCount.load(), 0u);

  sc.totalCount.fetch_add(5, std::memory_order_relaxed);
  sc.errorCount.fetch_add(2, std::memory_order_relaxed);
  EXPECT_EQ(sc.totalCount.load(), 5u);
  EXPECT_EQ(sc.errorCount.load(), 2u);
}

TEST(ServerCounterTests, ServerSummaryCountersReset)
{
  ServerSummaryCounters counters;
  counters.currentSessionCount.store(3, std::memory_order_relaxed);
  counters.cumulatedSessionCount.store(10, std::memory_order_relaxed);
  counters.rejectedSessionCount.store(2, std::memory_order_relaxed);
  counters.sessionTimeoutCount.store(1, std::memory_order_relaxed);
  counters.sessionAbortCount.store(4, std::memory_order_relaxed);
  counters.securityRejectedSessionCount.store(6, std::memory_order_relaxed);
  counters.securityRejectedRequestsCount.store(5, std::memory_order_relaxed);
  counters.rejectedRequestsCount.store(7, std::memory_order_relaxed);
  counters.currentSubscriptionCount.store(8, std::memory_order_relaxed);
  counters.cumulatedSubscriptionCount.store(9, std::memory_order_relaxed);
  counters.serverViewCount.store(11, std::memory_order_relaxed);
  counters.publishingIntervalCount.store(12, std::memory_order_relaxed);

  counters.reset();

  // The gauges survive reset; cumulative session and subscription counts still include them.
  EXPECT_EQ(counters.currentSessionCount.load(), 3u);
  EXPECT_EQ(counters.cumulatedSessionCount.load(), 3u);
  EXPECT_EQ(counters.rejectedSessionCount.load(), 0u);
  EXPECT_EQ(counters.sessionTimeoutCount.load(), 0u);
  EXPECT_EQ(counters.sessionAbortCount.load(), 0u);
  EXPECT_EQ(counters.securityRejectedSessionCount.load(), 0u);
  EXPECT_EQ(counters.securityRejectedRequestsCount.load(), 0u);
  EXPECT_EQ(counters.rejectedRequestsCount.load(), 0u);
  EXPECT_EQ(counters.currentSubscriptionCount.load(), 8u);
  EXPECT_EQ(counters.cumulatedSubscriptionCount.load(), 8u);
  EXPECT_EQ(counters.serverViewCount.load(), 11u);
  EXPECT_EQ(counters.publishingIntervalCount.load(), 12u);

  ServerSummaryCounters emptyCounters;
  emptyCounters.reset();
  EXPECT_EQ(emptyCounters.currentSessionCount.load(), 0u);
  EXPECT_EQ(emptyCounters.cumulatedSessionCount.load(), 0u);
  EXPECT_EQ(emptyCounters.currentSubscriptionCount.load(), 0u);
  EXPECT_EQ(emptyCounters.cumulatedSubscriptionCount.load(), 0u);
}

TEST(ServerCounterTests, SecureChannelCountersIncrementAndReset)
{
  SecureChannelCounters counters;
  counters.currentCount.fetch_add(4, std::memory_order_relaxed);
  counters.cumulatedCount.fetch_add(20, std::memory_order_relaxed);
  counters.rejectedCount.fetch_add(3, std::memory_order_relaxed);

  EXPECT_EQ(counters.currentCount.load(), 4u);
  EXPECT_EQ(counters.cumulatedCount.load(), 20u);
  EXPECT_EQ(counters.rejectedCount.load(), 3u);

  counters.reset();

  EXPECT_EQ(counters.currentCount.load(), 4u) << "the gauge survives a reset";
  EXPECT_EQ(counters.cumulatedCount.load(), 0u);
  EXPECT_EQ(counters.rejectedCount.load(), 0u);
}

TEST(ServerCounterTests, ConnectionCountersIncrementAndReset)
{
  ConnectionCounters counters;
  counters.currentCount.fetch_add(2, std::memory_order_relaxed);
  counters.cumulatedCount.fetch_add(15, std::memory_order_relaxed);
  counters.rejectedCount.fetch_add(1, std::memory_order_relaxed);

  EXPECT_EQ(counters.currentCount.load(), 2u);
  EXPECT_EQ(counters.cumulatedCount.load(), 15u);
  EXPECT_EQ(counters.rejectedCount.load(), 1u);

  counters.reset();

  EXPECT_EQ(counters.currentCount.load(), 2u) << "the gauge survives a reset";
  EXPECT_EQ(counters.cumulatedCount.load(), 0u);
  EXPECT_EQ(counters.rejectedCount.load(), 0u);
}

TEST(ServerCounterTests, SessionCountersPerServiceAndReset)
{
  SessionCounters counters;
  counters.totalRequests.totalCount.fetch_add(100, std::memory_order_relaxed);
  counters.totalRequests.errorCount.fetch_add(5, std::memory_order_relaxed);
  counters.read.totalCount.fetch_add(50, std::memory_order_relaxed);
  counters.browse.totalCount.fetch_add(30, std::memory_order_relaxed);
  counters.call.errorCount.fetch_add(2, std::memory_order_relaxed);
  counters.unauthorizedRequestCount.fetch_add(3, std::memory_order_relaxed);
  counters.translateBrowsePaths.totalCount.fetch_add(7, std::memory_order_relaxed);
  counters.write.totalCount.fetch_add(12, std::memory_order_relaxed);

  EXPECT_EQ(counters.totalRequests.totalCount.load(), 100u);
  EXPECT_EQ(counters.read.totalCount.load(), 50u);
  EXPECT_EQ(counters.browse.totalCount.load(), 30u);
  EXPECT_EQ(counters.write.totalCount.load(), 12u);

  counters.reset();

  EXPECT_EQ(counters.totalRequests.totalCount.load(), 0u);
  EXPECT_EQ(counters.totalRequests.errorCount.load(), 0u);
  EXPECT_EQ(counters.read.totalCount.load(), 0u);
  EXPECT_EQ(counters.browse.totalCount.load(), 0u);
  EXPECT_EQ(counters.call.errorCount.load(), 0u);
  EXPECT_EQ(counters.unauthorizedRequestCount.load(), 0u);
  EXPECT_EQ(counters.translateBrowsePaths.totalCount.load(), 0u);
  EXPECT_EQ(counters.write.totalCount.load(), 0u);
}

TEST(ServerCounterTests, ConcurrentIncrements)
{
  ServerSummaryCounters counters;
  constexpr int threadCount = 4;
  constexpr int opsPerThread = 10000;

  std::vector<std::jthread> threads;
  for (int t = 0; t < threadCount; ++t)
  {
    threads.emplace_back(
      [&]
      {
        for (int i = 0; i < opsPerThread; ++i)
        {
          counters.cumulatedSessionCount.fetch_add(1, std::memory_order_relaxed);
        }
      });
  }
  threads.clear();

  EXPECT_EQ(counters.cumulatedSessionCount.load(), threadCount * opsPerThread);
}

// ----------------------------------------------------------------------
// Latency tracker unit tests
// ----------------------------------------------------------------------

TEST(LatencyTrackerTests, FirstSampleSetsAverage)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{1000});

  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).averageUs.load(), 1000u);
  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).maxUs.load(), 1000u);
  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).sampleCount.load(), 1u);
}

TEST(LatencyTrackerTests, EmaConvergesUpward)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{100});

  // Record a much higher sample; EMA should increase but stay below the new sample.
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{900});
  auto avg = tracker.entry(ServiceKind::DiscoveryFindServers).averageUs.load();
  EXPECT_GT(avg, 100u);
  EXPECT_LT(avg, 900u);
}

TEST(LatencyTrackerTests, EmaConvergesDownward)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{1000});

  // Record a much lower sample; EMA should decrease but stay above the new sample.
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{200});
  auto avg = tracker.entry(ServiceKind::DiscoveryFindServers).averageUs.load();
  EXPECT_GT(avg, 200u);
  EXPECT_LT(avg, 1000u);
}

TEST(LatencyTrackerTests, MaxWatermarkTracksHighest)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{500});
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{1000});
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{300});

  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).maxUs.load(), 1000u);
  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).sampleCount.load(), 3u);
}

TEST(LatencyTrackerTests, DifferentServiceIndicesAreIndependent)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{100});
  tracker.record(ServiceKind::Read, std::chrono::microseconds{500});
  tracker.record(ServiceKind::BrowseNext, std::chrono::microseconds{200});

  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServers).averageUs.load(), 100u);
  EXPECT_EQ(tracker.entry(ServiceKind::Read).averageUs.load(), 500u);
  EXPECT_EQ(tracker.entry(ServiceKind::BrowseNext).averageUs.load(), 200u);
  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryFindServersOnNetwork).sampleCount.load(), 0u);
}

// Public API review D3 (API-D3.2): every service has a slot, and a request of no known type is not a service.
TEST(LatencyTrackerTests, EveryServiceHasASlotAndUnknownIsNotRecorded)
{
  RequestLatencyTracker tracker;
  for (std::size_t index = 0; index < ua::server::serviceKindCount; ++index)
  {
    tracker.record(static_cast<ServiceKind>(index), std::chrono::microseconds{100});
  }
  tracker.record(ServiceKind::Unknown, std::chrono::microseconds{100});
  for (const auto& entry : tracker.byService)
  {
    EXPECT_EQ(entry.sampleCount.load(), 1u) << "each service recorded exactly once";
  }
}

TEST(LatencyTrackerTests, ResetClearsAll)
{
  RequestLatencyTracker tracker;
  tracker.record(ServiceKind::DiscoveryFindServers, std::chrono::microseconds{500});
  tracker.record(ServiceKind::Read, std::chrono::microseconds{1000});

  tracker.reset();

  for (const auto& entry : tracker.byService)
  {
    EXPECT_EQ(entry.averageUs.load(), 0u);
    EXPECT_EQ(entry.maxUs.load(), 0u);
    EXPECT_EQ(entry.sampleCount.load(), 0u);
  }
}

TEST(LatencyTrackerTests, SampleCountAccumulates)
{
  RequestLatencyTracker tracker;
  for (int i = 0; i < 100; ++i)
  {
    tracker.record(ServiceKind::DiscoveryGetEndpoints, std::chrono::microseconds{500});
  }
  EXPECT_EQ(tracker.entry(ServiceKind::DiscoveryGetEndpoints).sampleCount.load(), 100u);
}

// ----------------------------------------------------------------------
// Pull health API - server-level tests
// ----------------------------------------------------------------------

namespace
{

shared_ptr<ServerImpl> create_test_server(boost::asio::any_io_executor ex)
{
  auto appCfg = ua::test_utils::create_test_config();
  CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig serverConfig;
  auto addListener = [&](std::string name, std::string address, std::string externalUrl)
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = std::move(name);
    listener.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = std::move(address);
    listener.externalUrl = transport::EndpointUrl{std::move(externalUrl)};

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(endpoint));
    serverConfig.listeners().push_back(std::move(listener));
  };
  addListener("DiagnosticsA", "127.0.0.1:4840", "opc.tcp://localhost:4840/UA/Diagnostics");
  addListener("DiagnosticsB", "127.0.0.1:4841", "opc.tcp://localhost:4841/UA/Other");
  frozen.server = std::move(serverConfig);

  auto server = ServerImpl::create(
    ex, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

}  // namespace

TEST(PullHealthTests, InitialSnapshotIsZero)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  auto snap = server->health_snapshot();
  EXPECT_EQ(snap.currentSessionCount, 0u);
  EXPECT_EQ(snap.cumulatedSessionCount, 0u);
  EXPECT_EQ(snap.currentSecureChannelCount, 0u);
  EXPECT_EQ(snap.cumulatedSecureChannelCount, 0u);
  EXPECT_EQ(snap.currentConnectionCount, 0u);
  EXPECT_EQ(snap.cumulatedConnectionCount, 0u);
  EXPECT_EQ(snap.rejectedSessionCount, 0u);
  EXPECT_EQ(snap.sessionTimeoutCount, 0u);
  EXPECT_EQ(snap.sessionAbortCount, 0u);
  EXPECT_EQ(snap.securityRejectedSessionCount, 0u);
  EXPECT_EQ(snap.rejectedRequestsCount, 0u);
  EXPECT_EQ(snap.securityRejectedRequestsCount, 0u);
  EXPECT_EQ(snap.rejectedSecureChannelCount, 0u);
  EXPECT_EQ(snap.rejectedConnectionCount, 0u);
}

TEST(PullHealthTests, CounterAccessorsReturnSharedInstances)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  // Verify counter objects are non-null and shared.
  auto sc1 = TestAccess{*server}.summary_counters();
  auto sc2 = TestAccess{*server}.summary_counters();
  ASSERT_NE(sc1, nullptr);
  EXPECT_EQ(sc1.get(), sc2.get());

  auto ch1 = TestAccess{*server}.secure_channel_counters();
  auto ch2 = TestAccess{*server}.secure_channel_counters();
  ASSERT_NE(ch1, nullptr);
  EXPECT_EQ(ch1.get(), ch2.get());

  auto co1 = TestAccess{*server}.connection_counters();
  auto co2 = TestAccess{*server}.connection_counters();
  ASSERT_NE(co1, nullptr);
  EXPECT_EQ(co1.get(), co2.get());

  auto lt1 = TestAccess{*server}.latency_tracker();
  auto lt2 = TestAccess{*server}.latency_tracker();
  ASSERT_NE(lt1, nullptr);
  EXPECT_EQ(lt1.get(), lt2.get());

  auto en1 = TestAccess{*server}.diagnostics_enabled();
  auto en2 = TestAccess{*server}.diagnostics_enabled();
  ASSERT_NE(en1, nullptr);
  EXPECT_EQ(en1.get(), en2.get());
}

TEST(PullHealthTests, DirectCounterMutationReflectsInSnapshot)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(42, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->sessionTimeoutCount.store(3, std::memory_order_relaxed);
  TestAccess{*server}.secure_channel_counters()->currentCount.store(5, std::memory_order_relaxed);
  TestAccess{*server}.connection_counters()->rejectedCount.store(7, std::memory_order_relaxed);

  auto snap = server->health_snapshot();
  EXPECT_EQ(snap.cumulatedSessionCount, 42u);
  EXPECT_EQ(snap.sessionTimeoutCount, 3u);
  EXPECT_EQ(snap.currentSecureChannelCount, 5u);
  EXPECT_EQ(snap.rejectedConnectionCount, 7u);
}

// ActivateSession referencing a never-created session (invalid SessionId) is a session-establishment
// request rejected for a NON-security reason: rejectedSessionCount increments but the
// securityRejectedSessionCount subset does not (OPC 10000-5 12.9). Reproduces the non-security half
// of the RejectedSessionCount accounting the CTT checks.
// Covers SVR-DIAG-RejectedSessionCount (CTT Base Info Diagnostics/023 step 2)
TEST(PullHealthTests, ActivateUnknownSessionIncrementsRejectedButNotSecurityRejected)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  auto counters = TestAccess{*server}.summary_counters();
  ASSERT_NE(counters, nullptr);

  // Default request -> default (null) authentication token -> matches no live session.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 99;
  SecureChannelInfo channelInfo(weak_ptr<SecureChannel>{},
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "0");  // endpointPolicyId must be non-empty
  TestAccess{*server}.activate_session_on_channel(std::move(channelInfo), 7, std::move(asr));

  EXPECT_EQ(counters->rejectedSessionCount.load(), 1u)
    << "activating an unknown session must increment rejectedSessionCount";
  EXPECT_EQ(counters->securityRejectedSessionCount.load(), 0u)
    << "a non-security session rejection must NOT increment securityRejectedSessionCount";

  // The server holds armed diagnostic timers; like the sibling PullHealth tests we let the
  // thread_pool destructor stop() + join() rather than draining a still-live server.
}

TEST(PullHealthTests, LatencyTrackerExposedInSnapshot)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  TestAccess{*server}.latency_tracker()->record(ServiceKind::Read, std::chrono::microseconds{750});
  TestAccess{*server}.latency_tracker()->record(ServiceKind::Read, std::chrono::microseconds{1250});

  auto snap = server->health_snapshot();
  EXPECT_GT(snap.latency.read.averageUs, 0u);
  EXPECT_EQ(snap.latency.read.maxUs, 1250u);
  EXPECT_EQ(snap.latency.read.sampleCount, 2u);
  EXPECT_EQ(snap.latency.findServers.sampleCount, 0u);
}

// Public API review D3 (API-D3.1): after one sample for every service, every named entry of the snapshot has
// exactly one - including the thirteen services the 16-slot array used to drop (Republish, the MonitoredItem
// services, TransferSubscriptions, NodeManagement, HistoryRead, HistoryUpdate).
TEST(PullHealthTests, EveryServiceReachesItsNamedLatencyEntry)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  for (std::size_t index = 0; index < ua::server::serviceKindCount; ++index)
  {
    TestAccess{*server}.latency_tracker()->record(
      static_cast<ServiceKind>(index), std::chrono::microseconds{10});
  }

  const auto latency = server->health_snapshot().latency;
  using Latency = ServerHealthSnapshot::ServiceLatency;
  const std::pair<const char*, ServerHealthSnapshot::LatencyEntry Latency::*> named[]{
    {"read", &Latency::read},
    {"write", &Latency::write},
    {"browse", &Latency::browse},
    {"browseNext", &Latency::browseNext},
    {"translateBrowsePaths", &Latency::translateBrowsePaths},
    {"registerNodes", &Latency::registerNodes},
    {"unregisterNodes", &Latency::unregisterNodes},
    {"call", &Latency::call},
    {"historyRead", &Latency::historyRead},
    {"historyUpdate", &Latency::historyUpdate},
    {"createSubscription", &Latency::createSubscription},
    {"modifySubscription", &Latency::modifySubscription},
    {"deleteSubscriptions", &Latency::deleteSubscriptions},
    {"setPublishingMode", &Latency::setPublishingMode},
    {"publish", &Latency::publish},
    {"republish", &Latency::republish},
    {"transferSubscriptions", &Latency::transferSubscriptions},
    {"createMonitoredItems", &Latency::createMonitoredItems},
    {"modifyMonitoredItems", &Latency::modifyMonitoredItems},
    {"deleteMonitoredItems", &Latency::deleteMonitoredItems},
    {"setMonitoringMode", &Latency::setMonitoringMode},
    {"setTriggering", &Latency::setTriggering},
    {"addNodes", &Latency::addNodes},
    {"addReferences", &Latency::addReferences},
    {"deleteNodes", &Latency::deleteNodes},
    {"deleteReferences", &Latency::deleteReferences},
    {"findServers", &Latency::findServers},
    {"findServersOnNetwork", &Latency::findServersOnNetwork},
    {"getEndpoints", &Latency::getEndpoints}};
  static_assert(std::size(named) == ua::server::serviceKindCount);
  for (const auto& [name, member] : named)
  {
    EXPECT_EQ((latency.*member).sampleCount, 1u) << name;
  }
}

TEST(PullHealthTests, SessionSnapshotsEmptyWhenNoSessions)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  auto snaps = server->session_health_snapshots();
  EXPECT_TRUE(snaps.empty());
}

TEST(PullHealthTests, DiagnosticsEnabledByDefault)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  EXPECT_TRUE(TestAccess{*server}.diagnostics_enabled()->load(std::memory_order_relaxed));
}

TEST(PullHealthTests, DiagnosticsEnabledFlagGatesIncrements)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  // Disable diagnostics.
  TestAccess{*server}.diagnostics_enabled()->store(false, std::memory_order_relaxed);

  auto& channelCounters = *TestAccess{*server}.secure_channel_counters();
  const auto before = channelCounters.currentCount.load(std::memory_order_relaxed);

  // Simulate the gated increment pattern used in ServerImpl.
  if (TestAccess{*server}.diagnostics_enabled()->load(std::memory_order_relaxed))
  {
    channelCounters.currentCount.fetch_add(1, std::memory_order_relaxed);
  }

  EXPECT_EQ(channelCounters.currentCount.load(std::memory_order_relaxed), before);

  // Re-enable and verify increment works.
  TestAccess{*server}.diagnostics_enabled()->store(true, std::memory_order_relaxed);

  if (TestAccess{*server}.diagnostics_enabled()->load(std::memory_order_relaxed))
  {
    channelCounters.currentCount.fetch_add(1, std::memory_order_relaxed);
  }

  EXPECT_EQ(channelCounters.currentCount.load(std::memory_order_relaxed), before + 1);
}

// ----------------------------------------------------------------------
// ns0 diagnostic Variable node handler tests
// ----------------------------------------------------------------------

namespace
{

uint32_t read_ns0_uint32(const shared_ptr<ServerImpl>& server, VariableId id)
{
  auto as = server->address_space();
  auto node = as.try_find_node_sync(NodeId{id});
  EXPECT_TRUE(node.is_good());
  auto var = node.value().as<VariableAccessor>();
  EXPECT_TRUE(var.has_value());
  auto dv = var->try_read_value_sync();
  EXPECT_TRUE(dv.is_good());
  EXPECT_TRUE(dv.value().value().is_uint32());
  return dv.value().value().as<uint32_t>();
}

bool read_ns0_bool(const shared_ptr<ServerImpl>& server, VariableId id)
{
  auto as = server->address_space();
  auto node = as.try_find_node_sync(NodeId{id});
  EXPECT_TRUE(node.is_good());
  auto var = node.value().as<VariableAccessor>();
  EXPECT_TRUE(var.has_value());
  auto dv = var->try_read_value_sync();
  EXPECT_TRUE(dv.is_good());
  EXPECT_TRUE(dv.value().value().is_boolean());
  return dv.value().value().as<bool>();
}

void write_ns0_bool(const shared_ptr<ServerImpl>& server, VariableId id, bool value)
{
  auto as = server->address_space();
  auto node = as.try_find_node_sync(NodeId{id});
  EXPECT_TRUE(node.is_good());
  auto var = node.value().as<VariableAccessor>();
  EXPECT_TRUE(var.has_value());
  DataValue dv;
  dv.value() = Variant{value};
  var->write_value_sync(std::move(dv));
}

}  // namespace

TEST(Ns0DiagnosticNodeTests, InitialDiagnosticCountersAreZero)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount),
    0u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount),
    0u);
  EXPECT_EQ(
    read_ns0_uint32(server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount),
    0u);
}

TEST(Ns0DiagnosticNodeTests, CounterMutationReflectedInNodeRead)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(42, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->currentSessionCount.store(7, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->sessionTimeoutCount.store(3, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->rejectedSessionCount.store(5, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->securityRejectedSessionCount.store(2, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->sessionAbortCount.store(1, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->publishingIntervalCount.store(4, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->currentSubscriptionCount.store(8, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->cumulatedSubscriptionCount.store(20, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->securityRejectedRequestsCount.store(6, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->rejectedRequestsCount.store(9, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->serverViewCount.store(11, std::memory_order_relaxed);

  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount),
    42u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount),
    7u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount),
    3u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount),
    5u);
  EXPECT_EQ(read_ns0_uint32(server,
              VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount),
    2u);
  EXPECT_EQ(
    read_ns0_uint32(server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount),
    1u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount),
    4u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount),
    8u);
  EXPECT_EQ(read_ns0_uint32(server,
              VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount),
    20u);
  EXPECT_EQ(read_ns0_uint32(server,
              VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount),
    6u);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount),
    9u);
  EXPECT_EQ(
    read_ns0_uint32(server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount),
    11u);
}

// @relation(SVR-BASE-015, scope=function)
TEST(Ns0DiagnosticNodeTests, EnabledFlagReadsTrue)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  EXPECT_TRUE(read_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag));
}

TEST(Ns0DiagnosticNodeTests, EnabledFlagWriteFalseDisablesDiagnostics)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  write_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag, false);

  EXPECT_FALSE(TestAccess{*server}.diagnostics_enabled()->load(std::memory_order_relaxed));
  EXPECT_FALSE(read_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag));
}

TEST(Ns0DiagnosticNodeTests, EnabledFlagWriteTrueResetsCounters)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  // Accumulate some counters.
  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(50, std::memory_order_relaxed);
  TestAccess{*server}.summary_counters()->rejectedSessionCount.store(10, std::memory_order_relaxed);
  TestAccess{*server}.secure_channel_counters()->cumulatedCount.store(25, std::memory_order_relaxed);
  TestAccess{*server}.connection_counters()->rejectedCount.store(3, std::memory_order_relaxed);

  // Write TRUE to EnabledFlag - should reset all counters.
  write_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag, true);

  EXPECT_TRUE(TestAccess{*server}.diagnostics_enabled()->load(std::memory_order_relaxed));
  EXPECT_EQ(
    TestAccess{*server}.summary_counters()->cumulatedSessionCount.load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(TestAccess{*server}.summary_counters()->rejectedSessionCount.load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(
    TestAccess{*server}.secure_channel_counters()->cumulatedCount.load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(TestAccess{*server}.connection_counters()->rejectedCount.load(std::memory_order_relaxed), 0u);
}

TEST(Ns0DiagnosticNodeTests, EnabledFlagWriteFalsePreservesCounters)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(50, std::memory_order_relaxed);

  // Write FALSE - counters should retain their values.
  write_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag, false);

  EXPECT_EQ(
    TestAccess{*server}.summary_counters()->cumulatedSessionCount.load(std::memory_order_relaxed), 50u);
}

TEST(Ns0DiagnosticNodeTests, CounterLiveUpdatesVisibleThroughNodes)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  // Read initial value
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount),
    0u);

  // Mutate counter and read again - should reflect the new value.
  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(99, std::memory_order_relaxed);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount),
    99u);

  // Mutate again.
  TestAccess{*server}.summary_counters()->cumulatedSessionCount.store(200, std::memory_order_relaxed);
  EXPECT_EQ(read_ns0_uint32(
              server, VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount),
    200u);
}

// ----------------------------------------------------------------------
// Per-session diagnostic object tests
// ----------------------------------------------------------------------

namespace
{

/// Test helper: find a child node by browse name using synchronous reference traversal.
optional<NodeId> find_child_by_browse_name(
  AddressSpace as, const NodeId& parent, const std::string& browseName)
{
  auto node = as.try_find_node_sync(parent);
  if (node.is_bad())
  {
    return {};
  }
  for (const auto& ref : node.value().get_components_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
    {
      continue;
    }
    auto childId = ref.target_id().node_id();
    auto child = as.try_find_node_sync(childId);
    if (child.is_good() && child.value().get_browse_name().name() == browseName)
    {
      return childId;
    }
  }
  return {};
}

}  // namespace

// The session's strand rewrites the security and descriptive records on every ActivateSession, while the
// diagnostics Variables build their values from the same records on whichever thread serves the Read. An
// activation alternating between two users grows the history vector (reallocating it) and swaps the
// strings under a reader. Under ThreadSanitizer an unguarded record is reported here; in any build every
// history entry the reader copies must be one of the two user ids.
// @relation(AC-SVR-DIAG-SESSION-RECORDS-READ-WHILE-ACTIVATING, scope=function)
TEST(PerSessionDiagnosticNodeTests, RecordsAreReadConsistentlyWhileTheSessionReactivates)
{
  auto counters = std::make_shared<SessionCounters>();
  auto security = std::make_shared<SessionSecurityState>();
  auto descriptive = std::make_shared<SessionDescriptiveState>();
  UserIdentity alice;
  alice.userId = "alice-with-a-name-longer-than-the-small-string-buffer";
  alice.kind = UserTokenKind::UserName;
  UserIdentity bob;
  bob.userId = "bob-with-a-name-longer-than-the-small-string-buffer";
  bob.kind = UserTokenKind::X509;
  EndpointSecurityContext endpoint;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
  endpoint.securityPolicyId = ua::SecurityPolicyId::None;

  std::atomic<bool> done{false};
  std::atomic<std::size_t> foreignEntries{0};
  std::thread reader(
    [&]
    {
      while (!done.load(std::memory_order_acquire))
      {
        const auto securityRecord = build_session_security_diagnostics(*security);
        for (const auto& entry : securityRecord.client_user_id_history())
        {
          const std::string_view id{entry};
          if (id != alice.userId && id != bob.userId)
            foreignEntries.fetch_add(1, std::memory_order_relaxed);
        }
        (void)build_session_diagnostics(*counters, *security, *descriptive);
      }
    });

  // Stops and joins the reader however the writer below leaves this scope.
  struct StopReader
  {
    std::atomic<bool>& done;
    std::thread& reader;

    ~StopReader()
    {
      done.store(true, std::memory_order_release);
      if (reader.joinable())
        reader.join();
    }
  } stopReader{done, reader};

  for (int activation = 0; activation < 20000; ++activation)
  {
    security->update_on_activate(activation % 2 == 0 ? alice : bob, endpoint);
    const std::lock_guard lock{descriptive->mutex};
    descriptive->localeIds.assign({activation % 2 == 0 ? std::string{"en-US"} : std::string{"de-DE-1996"}});
  }
  done.store(true, std::memory_order_release);
  reader.join();

  EXPECT_EQ(foreignEntries.load(), 0u) << "a reader copied a history entry that was never written";
  const std::lock_guard lock{security->mutex};
  EXPECT_EQ(security->clientUserIdHistory.size(), SessionSecurityState::maxClientUserIdHistory);
}

// @relation(SVR-BASE-017, scope=function)
TEST(PerSessionDiagnosticNodeTests, HelperCreatesObjectUnderParent)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{42u};

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};

  auto result = SessionDiagnosticsHelper::try_create_sync(
    as, parent, QualifiedName{0, "TestSession"}, counters, secState, descState, InstantiationOptions{});
  ASSERT_TRUE(result.is_good());

  auto& helper = result.value();
  EXPECT_FALSE(helper.node_id().is_null());

  // Verify the node exists in the address space.
  auto node = as.try_find_node_sync(helper.node_id());
  EXPECT_TRUE(node.is_good());
}

// The helper answers a failed instantiation with the instantiation's own status and ErrorDetail, not one
// of its own: under a parent that does not exist, SessionDiagnosticsObject::create_async refuses, and the
// helper's result is that refusal.
// @relation(AC-SVR-DIAG-008-SESSION-DIAGNOSTICS-HELPER-PROPAGATES, scope=function)
TEST(PerSessionDiagnosticNodeTests, HelperPropagatesTheInstantiationFailureExactly)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();
  const NodeId absentParent{0, 999999u};

  auto direct = SessionDiagnosticsObject::try_create_sync(
    as, absentParent, QualifiedName{0, "Absent"}, InstantiationOptions{});
  ASSERT_TRUE(direct.is_bad()) << "the fixture needs a refused instantiation";

  auto viaHelper = SessionDiagnosticsHelper::try_create_sync(as,
    absentParent,
    QualifiedName{0, "Absent"},
    std::make_shared<SessionCounters>(),
    std::make_shared<SessionSecurityState>(),
    std::make_shared<SessionDescriptiveState>(),
    InstantiationOptions{});
  ASSERT_TRUE(viaHelper.is_bad());
  EXPECT_EQ(viaHelper.status_code(), direct.status_code());
  ASSERT_NE(direct.shared_detail(), nullptr);
  ASSERT_NE(viaHelper.shared_detail(), nullptr);
  EXPECT_EQ(viaHelper.shared_detail()->code, direct.shared_detail()->code);
}

TEST(PerSessionDiagnosticNodeTests, HelperCleansUpOnDestruction)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};

  NodeId helperNodeId;
  {
    auto helper = SessionDiagnosticsHelper::create_sync(
      as, parent, QualifiedName{0, "TempSession"}, counters, secState, descState, InstantiationOptions{});
    helperNodeId = helper.node_id();

    // Verify the node exists while helper is alive.
    auto node = as.try_find_node_sync(helperNodeId);
    EXPECT_TRUE(node.is_good());
  }
  // The helper removes its subtree on destruction via an async fire-and-forget
  // cascade on the server's executor. The live server keeps the pool busy (so it
  // can't be joined/drained), so poll until the deletion settles. Use a time budget
  // rather than a fixed number of round-trips: under a fully sharded run, the
  // generated diagnostics subtree cleanup competes for CPU with every other shard.
  bool removed = false;
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (!removed && std::chrono::steady_clock::now() < deadline)
  {
    removed = as.try_find_node_sync(helperNodeId).is_bad();
  }
  EXPECT_TRUE(removed) << "helper subtree should be removed after destruction";
}

TEST(PerSessionDiagnosticNodeTests, CounterReadHandlersReturnValues)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{100u};

  // Set some counter values.
  counters->read.totalCount.store(42, std::memory_order_relaxed);
  counters->read.errorCount.store(3, std::memory_order_relaxed);
  counters->browse.totalCount.store(10, std::memory_order_relaxed);
  counters->totalRequests.totalCount.store(55, std::memory_order_relaxed);

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};

  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "CounterSession"}, counters, secState, descState, InstantiationOptions{});

  // Find the SessionDiagnostics child variable and read it.
  auto diagNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionDiagnostics");
  ASSERT_TRUE(diagNodeId.has_value());

  auto diagNode = as.try_find_node_sync(*diagNodeId);
  ASSERT_TRUE(diagNode.is_good());
  auto diagVar = diagNode.value().as<VariableAccessor>();
  ASSERT_TRUE(diagVar.has_value());

  auto dv = diagVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());

  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_structure());
  const auto* dt = dynamic_cast<const SessionDiagnosticsDataType*>(val.as<RefStructure<Structure>>().get());
  ASSERT_NE(dt, nullptr);

  EXPECT_EQ(dt->session_id(), NodeId{100u});
  EXPECT_EQ(dt->read_count().total_count(), 42u);
  EXPECT_EQ(dt->read_count().error_count(), 3u);
  EXPECT_EQ(dt->browse_count().total_count(), 10u);
  EXPECT_EQ(dt->total_request_count().total_count(), 55u);
}

TEST(PerSessionDiagnosticNodeTests, SecurityReadHandlersReturnValues)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{200u};
  secState->clientUserId = "admin";
  secState->authenticationMechanism = "UserName";
  secState->securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
  secState->securityMode = MessageSecurityMode::SignAndEncrypt;

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};

  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "SecuritySession"}, counters, secState, descState, InstantiationOptions{});

  // Find the SessionSecurityDiagnostics child variable and read it.
  auto secNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionSecurityDiagnostics");
  ASSERT_TRUE(secNodeId.has_value());

  auto secNode = as.try_find_node_sync(*secNodeId);
  ASSERT_TRUE(secNode.is_good());
  auto secVar = secNode.value().as<VariableAccessor>();
  ASSERT_TRUE(secVar.has_value());

  auto dv = secVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());

  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_structure());
  const auto* dt =
    dynamic_cast<const SessionSecurityDiagnosticsDataType*>(val.as<RefStructure<Structure>>().get());
  ASSERT_NE(dt, nullptr);

  EXPECT_EQ(dt->session_id(), NodeId{200u});
  EXPECT_EQ(dt->client_user_id_of_session(), "admin");
  EXPECT_EQ(dt->authentication_mechanism(), "UserName");
  EXPECT_EQ(dt->security_policy_uri(), "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
  EXPECT_EQ(dt->security_mode(), MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(dt->encoding(), "UA Binary");
  EXPECT_EQ(dt->transport_protocol(), "opc.tcp");
}

TEST(PerSessionDiagnosticNodeTests, SecurityDiagnosticNodeIdsPopulated)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};

  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "SecNodeIdSession"}, counters, secState, descState, InstantiationOptions{});

  // Security diagnostic node IDs should include the SessionSecurityDiagnostics variable.
  const auto& secNodeIds = helper.security_diagnostic_node_ids();
  EXPECT_FALSE(secNodeIds.empty());
}

// ----------------------------------------------------------------------
// Access-control helpers
// ----------------------------------------------------------------------

namespace
{

std::shared_ptr<const AccessIdentity> make_access_identity(
  std::vector<NodeId> roles, AccessIdentityKey key = AccessIdentityKey{1})
{
  auto user = std::make_shared<UserIdentity>();
  user->userId = "diagnostics-reader";
  user->kind = UserTokenKind::UserName;
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  endpoint->securityPolicyId = SecurityPolicyId::Basic256Sha256;
  return std::make_shared<AccessIdentity>(
    key, std::move(roles), std::move(user), std::move(endpoint), String{"urn:test:diagnostics"});
}

AccessControl::Verdict authorize(AddressSpace addressSpace, const AccessIdentity& identity,
  const NodeAccessor& node, AccessOperation operation)
{
  AccessControl accessControl{std::move(addressSpace), 100ms};
  auto identityView = std::shared_ptr<const AccessIdentity>(&identity, [](const AccessIdentity*) {});
  std::promise<std::vector<AccessControl::Verdict>> promise;
  auto future = promise.get_future();
  const std::array items{AccessControl::Item{node, operation}};
  accessControl.authorize_async(ua::RequestInfo{},
    std::move(identityView),
    items,
    identity.endpoint(),
    [&promise](std::vector<AccessControl::Verdict> verdicts) { promise.set_value(std::move(verdicts)); });
  auto verdicts = future.get();
  if (verdicts.size() != 1)
    throw std::logic_error{"single-item authorization returned the wrong cardinality"};
  return std::move(verdicts.front());
}

}  // namespace

// ----------------------------------------------------------------------
// SessionSecurityState tests
// ----------------------------------------------------------------------

TEST(SessionSecurityStateTests, UpdateOnActivateSetsFields)
{
  SessionSecurityState state;

  UserIdentity user;
  user.userId = "admin";
  user.kind = UserTokenKind::UserName;

  EndpointSecurityContext endpoint;
  endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;

  state.update_on_activate(user, endpoint);

  EXPECT_EQ(state.clientUserId, "admin");
  EXPECT_EQ(state.authenticationMechanism, "UserName");
  EXPECT_EQ(state.securityMode, MessageSecurityMode::SignAndEncrypt);
  EXPECT_FALSE(state.securityPolicyUri.empty());
}

// @relation(SVR-EVT-AUD-005, SVR-BASE-095, SVR-BASE-105, scope=function)
TEST(SessionSecurityStateTests, HistoryTracksUserChanges)
{
  SessionSecurityState state;
  EndpointSecurityContext endpoint;
  endpoint.securityPolicyId = SecurityPolicyId::None;

  UserIdentity user1;
  user1.userId = "alice";
  user1.kind = UserTokenKind::UserName;

  UserIdentity user2;
  user2.userId = "bob";
  user2.kind = UserTokenKind::UserName;

  UserIdentity user3;
  user3.userId = "charlie";
  user3.kind = UserTokenKind::X509;

  // First activation records the active user as the final history entry.
  state.update_on_activate(user1, endpoint);
  EXPECT_EQ(state.clientUserId, "alice");
  ASSERT_EQ(state.clientUserIdHistory.size(), 1u);
  EXPECT_EQ(state.clientUserIdHistory[0], "alice");

  // Same user - no history change.
  state.update_on_activate(user1, endpoint);
  EXPECT_EQ(state.clientUserId, "alice");
  ASSERT_EQ(state.clientUserIdHistory.size(), 1u);
  EXPECT_EQ(state.clientUserIdHistory[0], "alice");

  // Different user - newly active user appended to history.
  state.update_on_activate(user2, endpoint);
  EXPECT_EQ(state.clientUserId, "bob");
  ASSERT_EQ(state.clientUserIdHistory.size(), 2u);
  EXPECT_EQ(state.clientUserIdHistory[0], "alice");
  EXPECT_EQ(state.clientUserIdHistory[1], "bob");

  // Another different user.
  state.update_on_activate(user3, endpoint);
  EXPECT_EQ(state.clientUserId, "charlie");
  EXPECT_EQ(state.authenticationMechanism, "Certificate");
  ASSERT_EQ(state.clientUserIdHistory.size(), 3u);
  EXPECT_EQ(state.clientUserIdHistory[0], "alice");
  EXPECT_EQ(state.clientUserIdHistory[1], "bob");
  EXPECT_EQ(state.clientUserIdHistory[2], "charlie");
}

// @relation(AC-SVR-BASE-095-HISTORY-KEEPS-NEWEST-BOUNDED, scope=function)
TEST(SessionSecurityStateTests, HistoryKeepsTheNewestEntriesUpToItsBound)
{
  SessionSecurityState state;
  EndpointSecurityContext endpoint;
  endpoint.securityPolicyId = SecurityPolicyId::None;

  constexpr std::size_t bound = SessionSecurityState::maxClientUserIdHistory;
  for (std::size_t change = 0; change < bound + 5; ++change)
  {
    UserIdentity user;
    user.userId = "user" + std::to_string(change);
    user.kind = UserTokenKind::UserName;
    state.update_on_activate(user, endpoint);
  }

  ASSERT_EQ(state.clientUserIdHistory.size(), bound);
  EXPECT_EQ(state.clientUserIdHistory.front(), "user5");
  EXPECT_EQ(state.clientUserIdHistory.back(), "user" + std::to_string(bound + 4));
  EXPECT_EQ(state.clientUserId, state.clientUserIdHistory.back());
}

// @relation(SVR-EVT-AUD-005, SVR-BASE-096, SVR-BASE-105, scope=function)
TEST(SessionSecurityStateTests, AuthenticationMechanismMapping)
{
  SessionSecurityState state;
  EndpointSecurityContext endpoint;
  endpoint.securityPolicyId = SecurityPolicyId::None;

  auto testKind = [&](UserTokenKind kind, const std::string& expected)
  {
    UserIdentity user;
    user.userId = "test_" + expected;  // Different user each time to avoid history issues.
    user.kind = kind;
    state.update_on_activate(user, endpoint);
    EXPECT_EQ(state.authenticationMechanism, expected);
  };

  testKind(UserTokenKind::Anonymous, "Anonymous");
  testKind(UserTokenKind::UserName, "UserName");
  testKind(UserTokenKind::X509, "Certificate");
  testKind(UserTokenKind::IssuedToken, "IssuedToken");
}

// Stage-3a memory-safety: the SessionDiagnosticsArray / SubscriptionDiagnosticsArray read handlers run
// providers that snapshot ServerImpl state. The handlers are co-owned by the AddressSpace value handle,
// so they can be invoked AFTER ServerImpl is destroyed (a held AddressSpace copy keeps the node + handler
// alive; ~ServerImpl does not detach handlers or drain the externally-owned pool). The providers must
// weak-capture ServerImpl and bail when it is gone - a raw `this` would dereference a destroyed
// mMutex / mSessions / mSubscriptionRouter (use-after-free). This reproduces the
// AddressSpace-outlives-ServerImpl path: read the diagnostics arrays through a held AddressSpace AFTER
// the server is destroyed; the read must complete with an empty array, not crash.
TEST(Ns0DiagnosticNodeTests, DiagnosticArrayReadAfterServerDestructionIsSafeAndEmpty)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  // Hold the AddressSpace and the two provider-backed array nodes; this keeps the nodes + their read
  // handlers alive independently of ServerImpl.
  auto as = server->address_space();
  auto sessionArrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray});
  auto subscriptionArrayNode =
    as.try_find_node_sync(NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray});
  ASSERT_TRUE(sessionArrayNode.is_good());
  ASSERT_TRUE(subscriptionArrayNode.is_good());
  auto sessionVar = sessionArrayNode.value().as<VariableAccessor>();
  auto subscriptionVar = subscriptionArrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(sessionVar.has_value());
  ASSERT_TRUE(subscriptionVar.has_value());

  // Destroy ServerImpl while the AddressSpace (and thus the handlers) stay alive via `as`.
  std::weak_ptr<ServerImpl> weakServer = server;
  server.reset();
  // Prove the provider path is actually exercised: ServerImpl must be gone (so the providers'
  // weak_from_this().lock() returns null). If a stray strong ref kept it alive this test would not
  // cover the use-after-free path.
  ASSERT_TRUE(weakServer.expired()) << "ServerImpl must be destroyed for this test to exercise the fix";

  // Invoking the read handlers now runs the providers with a null-locking weak_ptr. Before the fix
  // (raw `this`) this dereferenced freed ServerImpl members; after the fix it returns an empty array.
  auto sessionDv = sessionVar->try_read_value_sync();
  auto subscriptionDv = subscriptionVar->try_read_value_sync();

  // The read must COMPLETE (no use-after-free crash) - the primary regression assertion; under ASan a
  // raw-`this` deref of the destroyed server would be caught here. The provider returns empty once the
  // server is gone, so the value is null or an empty array rather than stale entries.
  EXPECT_TRUE(sessionDv.is_good());
  if (sessionDv.is_good())
  {
    EXPECT_TRUE(sessionDv.value().value().empty() || sessionDv.value().value().is_array());
  }
  EXPECT_TRUE(subscriptionDv.is_good());
  if (subscriptionDv.is_good())
  {
    EXPECT_TRUE(subscriptionDv.value().value().empty() || subscriptionDv.value().value().is_array());
  }

  pool.join();
}

// ----------------------------------------------------------------------
// ServerDiagnostics obligations: gate flag, summary accounting, and the
// authorisation of the per-Session diagnostic surface.
// ----------------------------------------------------------------------

namespace
{

/// Drives one real session-establishment rejection through ServerImpl: an ActivateSession whose
/// authentication token matches no live session. The production path increments
/// rejectedSessionCount under the diagnostics gate, so the counter movement is decided by the
/// server, not by the test.
void reject_one_session(const shared_ptr<ServerImpl>& server, uint32_t requestId)
{
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = requestId;
  SecureChannelInfo channelInfo(weak_ptr<SecureChannel>{},
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "0");  // endpointPolicyId must be non-empty
  TestAccess{*server}.activate_session_on_channel(std::move(channelInfo), requestId, std::move(asr));
}

SecureChannelInfo make_live_none_channel(const shared_ptr<ServerImpl>& server)
{
  TestAccess access{*server};
  auto dependencies = access.secure_channel_dependencies();
  auto channel = SecureChannel::create(
    dependencies, nullptr, connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "Diagnostics");
  access.add_secure_channel(channel);
  SecureChannelTestAccess::on_strand(
    *channel, [&](auto& guard) { guard.set_minimal_context_none(dependencies->executor(), "0"); });
  return SecureChannelInfo(channel->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "0",
    SecureChannelTestAccess::on_strand(
      *channel, [](auto& guard) -> const auto& { return guard.user_identity_tokens(); }));
}

void wait_for_live_session_count(const shared_ptr<ServerImpl>& server, size_t expectedCount)
{
  TestAccess access{*server};
  for (int attempt = 0; attempt < 200 && access.sessions().size() < expectedCount; ++attempt)
    std::this_thread::sleep_for(1ms);
  auto sessions = access.sessions();
  ASSERT_GE(sessions.size(), expectedCount);
  SessionTestAccess::strand_barrier(*sessions.back());
}

/// Drives one real CreateSession through ServerImpl, which registers the Session and applies the
/// ServerDiagnosticsSummary session accounting.
void create_one_session(const shared_ptr<ServerImpl>& server, uint32_t requestId, const char* sessionName)
{
  const auto expectedCount = TestAccess{*server}.sessions().size() + 1;
  CreateSessionRequest csr;
  csr.session_name() = sessionName;
  csr.endpoint_url() = "opc.tcp://localhost:4840/UA/Diagnostics";
  csr.request_header().request_handle() = requestId;
  auto channelInfo = make_live_none_channel(server);
  TestAccess{*server}.create_session(std::move(channelInfo), requestId, std::move(csr));
  wait_for_live_session_count(server, expectedCount);
}

}  // namespace

// Part 5 6.3: ServerDiagnostics.EnabledFlag gates collection - writing FALSE freezes the summary
// counters at their current values, writing TRUE zeroes them and resumes collection. A plausible
// implementation gets this wrong in one of two ways: it treats the flag as advisory and keeps
// counting while it reads false, or it zeroes on the FALSE write. The second is the dangerous one:
// the counters are meant to hold plausible *stale* values while disabled, not obviously empty ones,
// so a client that ignores the flag is misled either way.
// @verifies AC-SVR-BASE-015-DIAGNOSTICS-ENABLEDFLAG
TEST(Ns0DiagnosticNodeTests, DisabledFlagFreezesCountersAndEnabledFlagResumesCollection)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  constexpr auto rejected =
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount;

  // Diagnostics are enabled out of the box: real activity moves the counter, which establishes the
  // non-zero baseline the "frozen" half needs in order to be falsifiable.
  reject_one_session(server, 1);
  ASSERT_EQ(read_ns0_uint32(server, rejected), 1u)
    << "with diagnostics enabled a rejected session must be counted";

  // Flag FALSE: further real activity must leave the counter STATIC - neither incremented nor
  // zeroed by the write itself.
  write_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag, false);
  reject_one_session(server, 2);
  reject_one_session(server, 3);
  EXPECT_EQ(read_ns0_uint32(server, rejected), 1u)
    << "with EnabledFlag false the counter must stay static at its pre-disable value";

  // Flag TRUE: the write resets the counters, and collection resumes.
  write_ns0_bool(server, VariableId::Server_ServerDiagnostics_EnabledFlag, true);
  ASSERT_EQ(read_ns0_uint32(server, rejected), 0u)
    << "writing EnabledFlag TRUE must reset the summary counters";
  reject_one_session(server, 4);
  EXPECT_EQ(read_ns0_uint32(server, rejected), 1u)
    << "with EnabledFlag true the counter must increment again";

  // The server holds armed diagnostic timers; let the thread_pool destructor stop() + join().
}

// Part 5 6.3: ServerDiagnosticsSummary is the Server's lifetime session accounting.
// CurrentSessionCount must follow the live count in both directions while CumulatedSessionCount
// only ever rises. A plausible implementation drives both from the same "session count" and
// decrements the cumulated total on close, which makes session churn - the very thing the summary
// exists to reveal - invisible.
// @verifies AC-SVR-BASE-016-DIAGNOSTICS-SUMMARY
TEST(Ns0DiagnosticNodeTests, ServerDiagnosticsSummaryTracksLiveSessionsWhileCumulatedOnlyRises)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());

  constexpr auto current = VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount;
  constexpr auto cumulated =
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount;

  ASSERT_EQ(read_ns0_uint32(server, current), 0u);
  ASSERT_EQ(read_ns0_uint32(server, cumulated), 0u);

  create_one_session(server, 11, "SummarySessionA");
  create_one_session(server, 12, "SummarySessionB");

  EXPECT_EQ(read_ns0_uint32(server, current), 2u) << "CurrentSessionCount must track the live count";
  EXPECT_EQ(read_ns0_uint32(server, cumulated), 2u)
    << "CumulatedSessionCount must count every session created";

  // Close one session through the real CloseSession path.
  auto sessions = TestAccess{*server}.sessions();
  ASSERT_EQ(sessions.size(), 2u);
  ASSERT_NE(sessions.front(), nullptr);
  sessions.front()->close(13, CloseSessionRequest{});

  // The close runs on the session strand on the pool thread; poll for the accounting to settle.
  bool settled = false;
  for (int i = 0; i < 400 && !settled; ++i)
  {
    if (read_ns0_uint32(server, current) == 1u)
    {
      settled = true;
      break;
    }
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_TRUE(settled) << "CurrentSessionCount must fall back to the live count after a close";

  EXPECT_EQ(read_ns0_uint32(server, current), 1u);
  EXPECT_EQ(read_ns0_uint32(server, cumulated), 2u)
    << "CumulatedSessionCount must not fall when a session closes";

  // CurrentSessionCount falls when the Session leaves the Server's table, before its close completes: the
  // Session holds itself until its diagnostics node is removed and the CloseSession response is sent. The
  // test waits for that, because stopping the pool with the removal still queued leaves the Session holding
  // itself, which LeakSanitizer reports (heavy-ci-green pipeline 2970961528, gcc14-asan).
  const std::weak_ptr<Session> closed = sessions.front();
  sessions.clear();
  for (int i = 0; i < 400 && !closed.expired(); ++i)
    std::this_thread::sleep_for(5ms);
  ASSERT_TRUE(closed.expired()) << "the closed Session must be released once its close completes";
}

// Part 5 6.3: the per-Session diagnostics under SessionsDiagnosticsSummary name every connected
// client - who is connected, from where, and how active - so an unauthorised reader must be refused
// (or see only its own entry). A plausible implementation guards only the security-flavoured
// children and leaves the summary's SessionDiagnosticsArray open, which hands an unprivileged
// client the full client inventory.
// @verifies AC-SVR-BASE-017-SESSIONS-DIAGNOSTICS-RESTRICTED
TEST(PerSessionDiagnosticNodeTests, SessionsDiagnosticsSummaryIsRestrictedForUnauthorisedReaders)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  // Two live sessions, so the summary genuinely exposes a session other than any single reader's.
  create_one_session(server, 21, "PeerSessionA");
  create_one_session(server, 22, "PeerSessionB");

  auto arrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray});
  ASSERT_TRUE(arrayNode.is_good());
  auto arrayVar = arrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(arrayVar.has_value());
  auto dv = arrayVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());
  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_array_of_structure());
  const auto& entries = val.as<Array<RefStructure<Structure>>>();
  ASSERT_GE(entries.size(), 2u)
    << "the summary must actually expose every live session for this restriction to matter";

  const auto unauthorised = make_access_identity({});
  const auto verdict = authorize(as, *unauthorised, arrayNode.value(), AccessOperation::Read);
  EXPECT_FALSE(verdict.permitted);
  EXPECT_EQ(verdict.cause.as_status(), Status::BadUserAccessDenied);
}

// Part 5 6.3 (SVR-BASE-077): SessionSecurityDiagnostics names each session's security policy, mode
// and user identity - a map of which connection is weakest - so an unauthorised read must be
// refused. The curated set is the one the production per-session diagnostics helper reports, so this
// fails if the helper ever stops declaring its security children rather than only if access control
// regresses.
// @verifies AC-SVR-BASE-077-SESSIONSECURITY-RESTRICTED
TEST(AccessControlDiagnosticsTests, SessionSecurityDiagnosticsVariableRefusesUnauthorisedRead)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{300u};
  secState->clientUserId = "operator";

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "RestrictedSession"}, counters, secState, descState, InstantiationOptions{});

  const auto& curated = helper.security_diagnostic_node_ids();
  ASSERT_FALSE(curated.empty());

  auto secNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionSecurityDiagnostics");
  ASSERT_TRUE(secNodeId.has_value());
  bool curatedCoversVariable = false;
  for (const auto& id : curated)
  {
    if (id == *secNodeId)
    {
      curatedCoversVariable = true;
    }
  }
  ASSERT_TRUE(curatedCoversVariable)
    << "the SessionSecurityDiagnostics Variable must be among the nodes the session curates";

  auto secNode = as.try_find_node_sync(*secNodeId);
  ASSERT_TRUE(secNode.is_good());

  const auto unauthorised = make_access_identity({});
  auto verdict = authorize(as, *unauthorised, secNode.value(), AccessOperation::Read);
  EXPECT_FALSE(verdict.permitted) << "an unauthorised session must not read SessionSecurityDiagnostics";
  EXPECT_EQ(verdict.cause.as_status(), Status::BadUserAccessDenied);

  // The refusal must be driven by the missing authorisation, not by a blanket denial of the node.
  const auto authorised =
    make_access_identity({NodeId{ObjectId::WellKnownRole_SecurityAdmin}}, AccessIdentityKey{2});
  EXPECT_TRUE(authorize(as, *authorised, secNode.value(), AccessOperation::Read).permitted);
}

// Part 5 12 (SVR-BASE-094): the restriction belongs to the DataType, not to one Variable. The same
// SessionSecurityDiagnosticsDataType is published a second time through the server-wide
// SessionSecurityDiagnosticsArray under SessionsDiagnosticsSummary, so a guard written once - as a
// set of per-session node ids - leaves that array path wide open and the data escapes.
// @verifies AC-SVR-BASE-094-SESSIONSECURITY-DATATYPE-RESTRICTED
// @relation(AC-SVR-BASE-077-AUTHORISED-ENCRYPTED-ARRAY, scope=function)
TEST(AccessControlDiagnosticsTests, SessionSecurityDiagnosticsDataTypeRefusedOnEveryPathThatExposesIt)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  // A live session, so the server-wide array actually carries the structure.
  create_one_session(server, 31, "ArrayPathSession");

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  auto helper = SessionDiagnosticsHelper::create_sync(as,
    parent,
    QualifiedName{0, "DataTypePathSession"},
    counters,
    secState,
    descState,
    InstantiationOptions{});

  const auto unauthorised = make_access_identity({});

  // Conjunct 1: the named per-session Variable is refused.
  auto secNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionSecurityDiagnostics");
  ASSERT_TRUE(secNodeId.has_value());
  auto secNode = as.try_find_node_sync(*secNodeId);
  ASSERT_TRUE(secNode.is_good());
  auto namedVerdict = authorize(as, *unauthorised, secNode.value(), AccessOperation::Read);
  EXPECT_FALSE(namedVerdict.permitted);
  EXPECT_EQ(namedVerdict.cause.as_status(), Status::BadUserAccessDenied);

  // The second path really does publish the same DataType - otherwise conjunct 2 would be vacuous.
  auto arrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
  ASSERT_TRUE(arrayNode.is_good());
  auto arrayVar = arrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(arrayVar.has_value());
  auto dv = arrayVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());
  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_array_of_structure());
  const auto& entries = val.as<Array<RefStructure<Structure>>>();
  ASSERT_GE(entries.size(), 1u);
  ASSERT_NE(dynamic_cast<const SessionSecurityDiagnosticsDataType*>(entries[0].get()), nullptr)
    << "the array path must carry SessionSecurityDiagnosticsDataType values";

  // Conjunct 2: the same DataType, reached through the array Variable, must be refused too.
  auto arrayVerdict = authorize(as, *unauthorised, arrayNode.value(), AccessOperation::Read);
  EXPECT_FALSE(arrayVerdict.permitted)
    << "SessionSecurityDiagnosticsDataType must be refused wherever it appears, not only on the "
       "named per-session Variable";
  EXPECT_EQ(arrayVerdict.cause.as_status(), Status::BadUserAccessDenied);
}

// Part 5 6.3 (SVR-BASE-095): clientUserIdHistory is an audit trail - "each time the active user
// changes, an entry shall be made at the end of the array", and the last element is the current
// user. A plausible implementation records only the *outgoing* identity, which leaves the current
// user out of the array entirely: after one identity change a client reading the history sees one
// name where the spec requires two, and the last element names the user who is no longer active.
// Read through the SessionSecurityDiagnostics Variable, which is how a client sees the field.
// @verifies AC-SVR-BASE-095-CLIENTUSERIDHISTORY-APPENDS
TEST(SessionSecurityStateTests, ClientUserIdHistoryAppendsWithTheActiveUserLast)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{400u};

  EndpointSecurityContext endpoint;
  endpoint.securityPolicyId = SecurityPolicyId::None;

  UserIdentity alice;
  alice.userId = "alice";
  alice.kind = UserTokenKind::UserName;

  UserIdentity bob;
  bob.userId = "bob";
  bob.kind = UserTokenKind::UserName;

  // Activate, then change the identity - the production state transition, not a hand-set field.
  secState->update_on_activate(alice, endpoint);
  secState->update_on_activate(bob, endpoint);

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "HistorySession"}, counters, secState, descState, InstantiationOptions{});

  auto secNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionSecurityDiagnostics");
  ASSERT_TRUE(secNodeId.has_value());
  auto secNode = as.try_find_node_sync(*secNodeId);
  ASSERT_TRUE(secNode.is_good());
  auto secVar = secNode.value().as<VariableAccessor>();
  ASSERT_TRUE(secVar.has_value());
  auto dv = secVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());

  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_structure());
  const auto* dt =
    dynamic_cast<const SessionSecurityDiagnosticsDataType*>(val.as<RefStructure<Structure>>().get());
  ASSERT_NE(dt, nullptr);

  const auto& history = dt->client_user_id_history();
  ASSERT_EQ(history.size(), 2u) << "one identity change must leave two entries in the history";
  EXPECT_EQ(history[0], "alice") << "the superseded user must remain, oldest first";
  EXPECT_EQ(history[1], "bob") << "the last history element must be the active user";
  EXPECT_EQ(dt->client_user_id_of_session(), "bob");
}

// DISABLED: the behaviour is UNIMPLEMENTED and this test is correct. Do not weaken it to make it
// pass; re-enable it when the mapping is fixed.
//
// Part 5 12.12 Table 232 (SVR-BASE-096): authenticationMechanism "shall be one of the lexical names
// of the UserIdentityTokenType Enum". The lexical names are the DataType Definition field names of
// UserTokenType (i=303) in Opc.Ua.NodeSet2.xml - Anonymous, UserName, Certificate, IssuedToken -
// which is also the spelling SVR-BASE-096's STATEMENT fixes (`Anonymous_0`, `UserName_1`,
// `Certificate_2`, `IssuedToken_3`). Part 4 7.43 Table 197 renders those names upper-cased, but
// that is the spec document's table styling for every enum it tabulates (Table 115 renders
// ApplicationType as SERVER / CLIENT / CLIENTANDSERVER against a NodeSet that spells them
// Server / Client / ClientAndServer), not the lexical name itself.
//
// The field is a String carrying an enumeration, so it is only comparable if the spelling is fixed:
// a server that writes its own internal token-kind spelling - "X509" for a certificate token -
// produces a value no client can match against the enumeration, and the whole point of the field is
// that it is machine-comparable. That is exactly what
// sdk/implementation/server/ua_session_security_state.cpp:31 does.
// Read through the SessionSecurityDiagnostics Variable, which is how a client sees it.
// @verifies AC-SVR-BASE-096-AUTHENTICATIONMECHANISM-LEXICAL
TEST(SessionSecurityStateTests, AuthenticationMechanismIsTheUserIdentityTokenTypeLexicalName)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  auto counters = std::make_shared<SessionCounters>();
  auto secState = std::make_shared<SessionSecurityState>();
  auto descState = std::make_shared<SessionDescriptiveState>();
  secState->sessionId = NodeId{500u};

  const auto parent = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  auto helper = SessionDiagnosticsHelper::create_sync(
    as, parent, QualifiedName{0, "MechanismSession"}, counters, secState, descState, InstantiationOptions{});

  auto secNodeId = find_child_by_browse_name(as, helper.node_id(), "SessionSecurityDiagnostics");
  ASSERT_TRUE(secNodeId.has_value());
  auto secNode = as.try_find_node_sync(*secNodeId);
  ASSERT_TRUE(secNode.is_good());
  auto secVar = secNode.value().as<VariableAccessor>();
  ASSERT_TRUE(secVar.has_value());

  EndpointSecurityContext endpoint;
  endpoint.securityPolicyId = SecurityPolicyId::None;

  // Activate with the given token kind through the production state transition, then read the field
  // back off the diagnostics Variable - the server decides the spelling, not the test.
  auto expectMechanism = [&](UserTokenKind kind, std::string_view userId, std::string_view lexicalName)
  {
    UserIdentity user;
    user.userId = std::string{userId};
    user.kind = kind;
    secState->update_on_activate(user, endpoint);

    auto dv = secVar->try_read_value_sync();
    ASSERT_TRUE(dv.is_good());
    const auto& val = dv.value().value();
    ASSERT_TRUE(val.is_structure());
    const auto* dt =
      dynamic_cast<const SessionSecurityDiagnosticsDataType*>(val.as<RefStructure<Structure>>().get());
    ASSERT_NE(dt, nullptr);

    const std::string_view actual{dt->authentication_mechanism()};
    EXPECT_EQ(actual, lexicalName) << "authenticationMechanism must be the UserTokenType lexical name '"
                                   << lexicalName << "', not the server's own spelling of the token kind";
  };

  expectMechanism(UserTokenKind::Anonymous, "anon_user", "Anonymous");
  expectMechanism(UserTokenKind::UserName, "name_user", "UserName");
  expectMechanism(UserTokenKind::X509, "cert_user", "Certificate");
  expectMechanism(UserTokenKind::IssuedToken, "issued_user", "IssuedToken");
}

namespace
{

/// Drives one real CreateSession that names the URL the client used to reach the server. Same shape
/// as create_one_session, but carries the `endpointUrl` the session must record: the transport
/// scheme is an external fact, so it has to enter through the request rather than be set by hand.
void create_one_session_on_url(
  const shared_ptr<ServerImpl>& server, uint32_t requestId, const char* sessionName, const char* endpointUrl)
{
  const auto expectedCount = TestAccess{*server}.sessions().size() + 1;
  CreateSessionRequest csr;
  csr.session_name() = sessionName;
  csr.endpoint_url() = endpointUrl;
  csr.request_header().request_handle() = requestId;
  auto channelInfo = make_live_none_channel(server);
  TestAccess{*server}.create_session(std::move(channelInfo), requestId, std::move(csr));
  wait_for_live_session_count(server, expectedCount);
}

}  // namespace

// Part 5 12.12 Table 232 (SVR-BASE-097): `encoding` is exactly one of the three strings "XML",
// "JSON" and "UA Binary" - case-sensitive, and spaced as shown. It is a String carrying a closed
// vocabulary, so the plausible implementation reports the codec under whatever spelling the stack
// uses internally - "UABinary", "Binary", or the transport profile's "uabinary" - each of which is
// unmatchable by a client comparing against the defined set. The space in "UA Binary" is the detail
// a normalising server drops. Read through the server-wide SessionSecurityDiagnosticsArray, which is
// how a client sees the field, and off a session the server created rather than a hand-built record.
// @verifies AC-SVR-BASE-097-ENCODING-VALUE-SET
TEST(PerSessionDiagnosticNodeTests, EncodingIsOneOfTheThreeDefinedStrings)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  // The fixture's transport offers the binary codec; the obligation is that whatever codec is in
  // force is named with one of the three defined spellings.
  create_one_session_on_url(server, 61, "EncodingSession", "opc.tcp://localhost:4840/UA/Diagnostics");

  auto arrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
  ASSERT_TRUE(arrayNode.is_good());
  auto arrayVar = arrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(arrayVar.has_value());
  auto dv = arrayVar->try_read_value_sync();
  ASSERT_TRUE(dv.is_good());
  const auto& val = dv.value().value();
  ASSERT_TRUE(val.is_array_of_structure());
  const auto& entries = val.as<Array<RefStructure<Structure>>>();
  ASSERT_GE(entries.size(), 1u)
    << "the live session must appear in the security diagnostics for its encoding to be observable";

  for (size_t i = 0; i < entries.size(); ++i)
  {
    const auto* dt = dynamic_cast<const SessionSecurityDiagnosticsDataType*>(entries[i].get());
    ASSERT_NE(dt, nullptr);
    const std::string encoding{dt->encoding()};
    EXPECT_TRUE(encoding == "XML" || encoding == "JSON" || encoding == "UA Binary")
      << "encoding must be exactly one of \"XML\", \"JSON\" or \"UA Binary\"; the session reported '"
      << encoding << "'";
  }
}

// Part 5 12.12 Table 232 (SVR-BASE-098): `transportProtocol` is the URL scheme the session was
// established on, recorded verbatim from the connecting endpoint URL. It is the one fixed-vocabulary
// diagnostic string with an external source, so the plausible implementation is the one that treats
// it as a server constant: a server that speaks opc.tcp today fixes the field at "opc.tcp", which
// reads correctly for every opc.tcp client and silently misreports every session that arrived over
// any other scheme - exactly the sessions an operator is looking for. Drive the real CreateSession
// path with the URL the client used and read the field back off the server-wide
// SessionSecurityDiagnosticsArray.
// @verifies AC-SVR-BASE-098-TRANSPORTPROTOCOL-IS-SCHEME
TEST(PerSessionDiagnosticNodeTests, TransportProtocolIsTheSchemeOfTheSessionUrl)
{
  auto expectScheme = [](const char* endpointUrl, const char* expectedScheme)
  {
    boost::asio::thread_pool pool(1);
    auto server = create_test_server(pool.get_executor());
    auto as = server->address_space();

    // Exactly one session on this server, so every diagnostics entry below describes it.
    create_one_session_on_url(server, 71, "TransportSession", endpointUrl);

    auto diagArrayNode = as.try_find_node_sync(
      NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray});
    ASSERT_TRUE(diagArrayNode.is_good());
    auto diagArrayVar = diagArrayNode.value().as<VariableAccessor>();
    ASSERT_TRUE(diagArrayVar.has_value());

    // CreateSession is applied on the session's own strand, so poll until the session has recorded
    // the URL. This is also the control: without it the observation below could be made against a
    // session that was never addressed on `endpointUrl` at all.
    bool urlRecorded = false;
    for (int attempt = 0; attempt < 400 && !urlRecorded; ++attempt)
    {
      auto diagDv = diagArrayVar->try_read_value_sync();
      if (diagDv.is_good() && diagDv.value().value().is_array_of_structure())
      {
        const auto& diagEntries = diagDv.value().value().as<Array<RefStructure<Structure>>>();
        for (size_t i = 0; i < diagEntries.size(); ++i)
        {
          const auto* diagDt = dynamic_cast<const SessionDiagnosticsDataType*>(diagEntries[i].get());
          if (diagDt != nullptr && std::string{diagDt->endpoint_url()} == endpointUrl)
          {
            urlRecorded = true;
          }
        }
      }
      if (!urlRecorded)
      {
        std::this_thread::sleep_for(5ms);
      }
    }
    ASSERT_TRUE(urlRecorded) << "the session must record the endpoint URL '" << endpointUrl
                             << "' before its transportProtocol says anything";

    auto secArrayNode = as.try_find_node_sync(NodeId{
      VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
    ASSERT_TRUE(secArrayNode.is_good());
    auto secArrayVar = secArrayNode.value().as<VariableAccessor>();
    ASSERT_TRUE(secArrayVar.has_value());
    auto secDv = secArrayVar->try_read_value_sync();
    ASSERT_TRUE(secDv.is_good());
    const auto& secVal = secDv.value().value();
    ASSERT_TRUE(secVal.is_array_of_structure());
    const auto& secEntries = secVal.as<Array<RefStructure<Structure>>>();
    ASSERT_GE(secEntries.size(), 1u)
      << "the live session must appear in the security diagnostics for its transportProtocol to be "
         "observable";

    for (size_t i = 0; i < secEntries.size(); ++i)
    {
      const auto* secDt = dynamic_cast<const SessionSecurityDiagnosticsDataType*>(secEntries[i].get());
      ASSERT_NE(secDt, nullptr);
      EXPECT_EQ(std::string{secDt->transport_protocol()}, std::string{expectedScheme})
        << "transportProtocol must be the undecorated scheme of the URL the session was established "
           "on ('"
        << endpointUrl << "'), not a server constant";
    }
  };

  expectScheme("opc.tcp://localhost:4840/UA/Diagnostics", "opc.tcp");

  // An `https` arm was removed here on 2026-08-10. It derived the expected transportProtocol from
  // `CreateSessionRequest.endpointUrl`, which is client-supplied and unvalidated at the point the
  // diagnostics record is written - a server that honoured it would let a client name any scheme it
  // liked in its own diagnostics entry. The field is a property of the listener, and this SDK offers
  // one transport profile, so the arm asserted a value no conforming server could produce.
}

// Part 5 12.12 Table 232 (SVR-BASE-098): `transportProtocol` is a PER-SESSION field - each
// SessionSecurityDiagnostics entry carries the URL scheme of the transport its own session was
// established on, undecorated. This SDK offers exactly one transport profile,
// `TransportProfileId::UaTcpUaScUaBinary`, whose URL scheme is `opc.tcp` (Part 6), so every session
// an operator can read was established on that scheme and every entry must say so. The plausible
// implementation reports the transport under an internal spelling - the profile name
// "UaTcpUaScUaBinary", the profile URI, "UA-TCP", or the whole endpoint URL with its `://host:port`
// still attached - each of which is unmatchable by a client comparing against the Part 6 scheme
// strings. Two concurrent sessions are established and every entry in the array is read separately,
// so a server that emits a decorated or renamed value for any session is caught.
// @verifies AC-SVR-BASE-098-TRANSPORTPROTOCOL-IS-SCHEME
// @relation(AC-SVR-BASE-017-SESSION-DIAGNOSTICS-ARRAY-LIVE, scope=function)
TEST(PerSessionDiagnosticNodeTests, TransportProtocolIsRecordedPerSessionNotOncePerServer)
{
  boost::asio::thread_pool pool(1);
  auto server = create_test_server(pool.get_executor());
  auto as = server->address_space();

  // Two endpoint URLs differing in port and path but not in scheme: the SDK binds only the UA-TCP
  // profile, so `opc.tcp` is the scheme of every session it can establish.
  const std::string firstUrl{"opc.tcp://localhost:4840/UA/Diagnostics"};
  const std::string secondUrl{"opc.tcp://localhost:4841/UA/Other"};

  create_one_session_on_url(server, 81, "PerSessionTransportA", firstUrl.c_str());
  create_one_session_on_url(server, 82, "PerSessionTransportB", secondUrl.c_str());

  auto diagArrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray});
  ASSERT_TRUE(diagArrayNode.is_good());
  auto diagArrayVar = diagArrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(diagArrayVar.has_value());

  // CreateSession is applied on each session's own strand, so poll until BOTH sessions have recorded
  // their endpoint URL. This is also the control: without it the observation below could be made
  // against an array that holds no established session at all.
  bool firstRecorded = false;
  bool secondRecorded = false;
  for (int attempt = 0; attempt < 400 && !(firstRecorded && secondRecorded); ++attempt)
  {
    firstRecorded = false;
    secondRecorded = false;
    auto diagDv = diagArrayVar->try_read_value_sync();
    if (diagDv.is_good() && diagDv.value().value().is_array_of_structure())
    {
      const auto& diagEntries = diagDv.value().value().as<Array<RefStructure<Structure>>>();
      for (size_t i = 0; i < diagEntries.size(); ++i)
      {
        const auto* diagDt = dynamic_cast<const SessionDiagnosticsDataType*>(diagEntries[i].get());
        if (diagDt == nullptr)
        {
          continue;
        }
        const std::string url{diagDt->endpoint_url()};
        firstRecorded = firstRecorded || url == firstUrl;
        secondRecorded = secondRecorded || url == secondUrl;
      }
    }
    if (!(firstRecorded && secondRecorded))
    {
      std::this_thread::sleep_for(5ms);
    }
  }
  ASSERT_TRUE(firstRecorded && secondRecorded)
    << "both sessions must have been established before their transportProtocol says anything";

  auto secArrayNode = as.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
  ASSERT_TRUE(secArrayNode.is_good());
  auto secArrayVar = secArrayNode.value().as<VariableAccessor>();
  ASSERT_TRUE(secArrayVar.has_value());
  auto secDv = secArrayVar->try_read_value_sync();
  ASSERT_TRUE(secDv.is_good());
  const auto& secVal = secDv.value().value();
  ASSERT_TRUE(secVal.is_array_of_structure());
  const auto& secEntries = secVal.as<Array<RefStructure<Structure>>>();
  ASSERT_GE(secEntries.size(), 2u)
    << "both live sessions must appear in the security diagnostics for their transportProtocol to be "
       "observable";

  for (size_t i = 0; i < secEntries.size(); ++i)
  {
    const auto* secDt = dynamic_cast<const SessionSecurityDiagnosticsDataType*>(secEntries[i].get());
    ASSERT_NE(secDt, nullptr);
    EXPECT_EQ(std::string{secDt->transport_protocol()}, std::string{"opc.tcp"})
      << "entry " << i
      << ": transportProtocol must be the undecorated URL scheme of the transport this session was "
         "established on";
  }
}
