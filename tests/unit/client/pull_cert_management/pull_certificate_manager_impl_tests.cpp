// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Tests for the tier-2 ua::client::detail::PullCertificateManagerImpl (client design section 8.1A, Phase F):
// the own-strand Pull-Model certificate + trust-list refresh engine. Drives the strand-bearing Impl against a
// FakePullCertificateManagerHost (no GDS, certificate store, or wire stack - the mockable host interface is
// the whole point) and asserts its OWN section 8.1A.4 cycle FSM: the transition table, the GDS bootstrap
// overlay, the TrustList LastUpdateTime short-circuit, the Start/Finish poll loop + persistence, the atomic
// apply + revalidation broadcast, the renew/retry-backoff timers, the mGeneration stale-callback guard, and
// the CL-PULLCRT-001..006 / CL-SECADMIN-004 behavioural contracts. Every test is FALSIFIABLE: it asserts the
// host calls issued (which primitive, with what args) AND the resulting state / snapshot / observer fire.
//
// Anchor reconciliation: section 8.1A.5 anchors this component to CL-PULLCRT-001..006 (+ CL-MULTI-001,
// CL-RECONN-006, CL-SECADMIN-004 cross-ref). CL-SECADMIN-001..007 proper are tier-0 CertificateStore
// obligations (client requirements doc 13); only CL-SECADMIN-004 (continuous revalidation) cross-refs the
// pull manager, verified below. Tests are anchored to the CL-PULLCRT names actually used in section 8.1A.5.
//
// Deferred anchors (not covered here - they need the Client-wiring slice, not the strand-core):
//   - CL-MULTI-001 second-start `Bad_AlreadyExists` (`CoreClientImpl::start_pull_cert_management` guard) -
//   lives
//     in the Client slice; the strand-core has no static/second-start notion.
//   - section 8.1A.3 block-join destructor (needs the Client-owned runtime) - the strand-core only drops
//   in-flight
//     work by generation and closes the GDS; the residual-ack fire on destruction IS covered (M5c).
//
// The io_context is single-threaded; state is read via PullCertificateManagerTestAccess only AFTER draining,
// so there is no cross-strand race. A per-fixture injectable clock makes the persisted-at / commit timestamps
// deterministic. The cycle timer (seconds-typed) and poll timer (armed above the drain window) never fire a
// real wall delay in-test - cycles/polls are driven by force_cycle_async / the trigger_* strand-post hooks
// (testing.md "poll, don't sleep"; NEVER a 0ms/0s real timer under sharded load).

#include "ua_pull_certificate_manager_impl.h"

#include "fake_certificate_store.h"
#include "fake_pull_cert_manager_host.h"
#include "stub_x509_certificate.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_pull_certificate_manager.h"
#include "ua_pull_certificate_manager_test_access.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::PullCertLifecycleEvent;
using ua::client::PullCertManagementState;
using ua::client::detail::PersistedRequest;
using ua::client::detail::PullCertificateManagerFactory;
using ua::client::detail::PullCertificateManagerImpl;
using ua::client::detail::PullCertificateManagerTestAccess;
using ua::testing::FakePullCertificateManagerHost;
using Access = ua::client::detail::PullCertificateManagerTestAccess;

/// The group a default CertificateGroupConfig names: null, so the GDS chooses its DefaultApplicationGroup
/// (OPC 10000-12 7.9.3).
ua::NodeId default_group_id()
{
  return ua::NodeId{};
}

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakePullCertificateManagerHost> host = std::make_shared<FakePullCertificateManagerHost>();
  ua::client::PullCertManagementConfig config;
  std::shared_ptr<ua::DateTime> clock = std::make_shared<ua::DateTime>(ua::DateTime::now());

  Fixture()
  {
    // Keep every timer well above the drain / settle windows so no real wall delay ever fires in-test; the
    // seconds-typed cycle timer and the poll timer are driven through the trigger_* / force_cycle hooks.
    config.gdsEndpointUrl = "opc.tcp://gds";
    config.updateFrequency = std::chrono::seconds{3600};
    config.minCycleBackoff = std::chrono::seconds{60};
    config.maxCycleBackoff = std::chrono::seconds{3600};
    config.cycleBackoffJitterPct = 0.0;  // deterministic backoff-delay assertions.
    config.pollInitialDelay = std::chrono::milliseconds{5000};  // above the drain window.
    config.pollBackoffMultiplier = 2.0;
    config.pollJitterPct = 0.0;
    config.pollMaxRepeat = 4;
    // Default to a SKIP of the trust-list download (missing LastUpdateTime, not forced) so cycles are
    // cert-focused unless a test opts into a download by scripting a LastUpdateTime.
    config.checkLastUpdateTimeBeforeDownload = true;
    config.treatLastUpdateTimeMissingAsForceDownload = false;
    // H4(a): a valid manager MUST have a bootstrap trust store (a null store = accept-any = MITM). The
    // default gives every test a real anchor; the null-store case opts out explicitly.
    config.bootstrapTrustStore = ua::test_helpers::FakeCertificateStore::create();
  }

  std::shared_ptr<PullCertificateManagerImpl> make()
  {
    host->injectedExecutor = ctx.get_executor();
    auto impl = PullCertificateManagerImpl::create(ctx.get_executor(), host, ua::Logger{}, config);
    Access::set_now_fn(*impl, [clock = clock] { return *clock; });
    return impl;
  }

  // Poll-based draining: runs every ready handler to a fixed point but never blocks on a still-pending timer
  // (the poll timer is armed above 5s; the cycle timer above 60s) - so a manager sitting with an armed long
  // timer never hangs the test thread.
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

  // Bounded blocking run that services a freshly-armed already-expired timer, then a trailing poll-drain.
  // Provided for parity with the sibling fixtures; the pull-cert tests drive timers via the trigger hooks so
  // no real timer is expected to fire here.
  void settle_timers()
  {
    ctx.restart();
    ctx.run_for(std::chrono::milliseconds{200});
    for (;;)
    {
      ctx.restart();
      if (ctx.poll() == 0)
      {
        break;
      }
    }
  }
};

// Brings a manager from ctor through the GDS bootstrap to Idle.
std::shared_ptr<PullCertificateManagerImpl> boot(Fixture& fixture)
{
  auto impl = fixture.make();
  fixture.drain();
  return impl;
}

PersistedRequest make_pending(const std::string& thumbprint)
{
  PersistedRequest request;
  request.certificateGroupId = default_group_id();
  request.certificateTypeId = ua::NodeId{ua::ObjectTypeId::RsaSha256ApplicationCertificateType};
  request.requestId = ua::NodeId{2, 0xA1U};
  request.certThumbprintSha1 = thumbprint;
  request.persistedAt = ua::DateTime::now();
  return request;
}

// ============================================================================
// Bootstrap / GDS overlay - CL-PULLCRT-001 / CL-PULLCRT-002 / section 8.1A.4
// ============================================================================

// @verifies CL-PULLCRT-001
// @verifies CL-PULLCRT-002
// transition: (ctor) --construction--> BootstrappingGds --conn good--> Idle
// @relation(CL-PULLCRT-001, CL-PULLCRT-002, scope=function)
TEST(ClientPullCertBootstrap, OpensGdsWithSignAndEncryptAndAnonymousThenIdle)
{
  Fixture f;
  auto impl = boot(f);

  ASSERT_EQ(f.host->openGdsCalls.size(), 1u);
  EXPECT_EQ(f.host->openGdsCalls[0].securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_TRUE(f.host->openGdsCalls[0].anonymousIdentity);
  EXPECT_EQ(f.host->openGdsCalls[0].endpointUrl, "opc.tcp://gds");
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_TRUE(Access::gds_connected(*impl));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::Started));
}

// @verifies CL-PULLCRT-001
// The GDS channel is forced to SignAndEncrypt even when the config attempts to weaken it to None.
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientPullCertBootstrap, RejectsSecurityModeNoneConfig)
{
  Fixture f;
  f.config.requestedGdsSecurityMode = ua::MessageSecurityMode::None;
  auto impl = boot(f);

  ASSERT_EQ(f.host->openGdsCalls.size(), 1u);
  EXPECT_EQ(f.host->openGdsCalls[0].securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.security_mode_forced");
}

// @verifies CL-PULLCRT-001
// section 3.1: SignAndEncrypt with a None SecurityPolicy is contradictory and would yield an UNENCRYPTED,
// server-cert-UNVALIDATED channel. A None gdsSecurityPolicyId is forced to a secure policy (Basic256Sha256),
// with a source-tagged advisory. Falsifiable: threading None through verbatim would fail both assertions.
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientPullCertBootstrap, ForcesSecurityPolicyWhenConfigIsNone)
{
  Fixture f;
  f.config.gdsSecurityPolicyId = ua::SecurityPolicyId::None;
  auto impl = boot(f);

  ASSERT_EQ(f.host->openGdsCalls.size(), 1u);
  EXPECT_EQ(f.host->openGdsCalls[0].securityPolicyId, ua::SecurityPolicyId::Basic256Sha256)
    << "a None GDS SecurityPolicy must be forced to a secure policy (CL-PULLCRT-001)";
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(
    impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.security_policy_forced");
}

// @verifies CL-PULLCRT-001
// The bootstrap trust store (distinct from the runtime store) is what validates the GDS server cert; the
// runtime store is never handed to the OPN handshake.
// @relation(CL-PULLCRT-001, scope=function)
TEST(ClientPullCertBootstrap, UsesBootstrapTrustStoreDistinctFromRuntimeStore)
{
  Fixture f;
  auto bootstrapStore = ua::test_helpers::FakeCertificateStore::create();
  auto runtimeStore = ua::test_helpers::FakeCertificateStore::create();
  f.config.bootstrapTrustStore = bootstrapStore;
  f.config.runtimeCertStore = runtimeStore;
  auto impl = boot(f);

  ASSERT_EQ(f.host->openGdsCalls.size(), 1u);
  EXPECT_EQ(f.host->openGdsCalls[0].bootstrapTrustStore.get(), bootstrapStore.get());
  EXPECT_NE(f.host->openGdsCalls[0].bootstrapTrustStore.get(), runtimeStore.get());
}

// @verifies CL-DISC-017
// Part 12 section 6.3: cyclic PullManagement adds a random 1%-10% start delay before the second cycle.
// @relation(CL-DISC-017, scope=function)
TEST(ClientPullCertBootstrap, RegularCycleAddsRequiredRandomizedStartDelay)
{
  Fixture f;
  f.config.updateFrequency = std::chrono::seconds{60};

  auto impl = boot(f);

  ASSERT_TRUE(Access::last_armed_cycle_delay(*impl).has_value());
  EXPECT_GE(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{60'600});
  EXPECT_LE(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{66'000});

  Access::seed_jitter_rng(*impl, 0xC1C1'017u);
  std::set<std::chrono::milliseconds> observed;
  for (std::size_t sample = 0; sample < 16; ++sample)
  {
    const auto delay = Access::regular_cycle_delay(*impl);
    EXPECT_GE(delay, std::chrono::milliseconds{60'600});
    EXPECT_LE(delay, std::chrono::milliseconds{66'000});
    observed.insert(delay);
  }
  EXPECT_GT(observed.size(), 1u) << "the cycle delay must actually vary, not use a fixed 1% offset";
}

// transition: BootstrappingGds --conn bad--> Failed
TEST(ClientPullCertBootstrap, GdsOpenFailureEntersFailedAndArmsRetry)
{
  Fixture f;
  f.host->fail_open_gds(Status::BadConnectionRejected);
  auto impl = boot(f);

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  EXPECT_FALSE(Access::gds_connected(*impl));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::CycleFailed));
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->source, "client.tier1.pull_cert_manager.bootstrap");
  ASSERT_TRUE(Access::last_armed_cycle_delay(*impl).has_value());
  EXPECT_EQ(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{60000});
}

// @design(section 8.1A.6)
// A corrupt persisted-requests file is cleared and the advisory is carried on the Started event, then a fresh
// cycle proceeds.
TEST(ClientPullCertBootstrap, CorruptPersistenceClearsAndAdvisesOnStarted)
{
  Fixture f;
  f.host->fail_persisted_load(Status::BadDecodingError);
  auto impl = boot(f);

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_EQ(Access::pending_request_count(*impl), 0u);
  ASSERT_FALSE(f.host->persistedWrites.empty());  // the cleared file was written back.
  EXPECT_TRUE(f.host->persistedWrites.front().empty());
  auto started = f.host->last_lifecycle_detail(PullCertLifecycleEvent::Started);
  ASSERT_NE(started, nullptr);
  EXPECT_EQ(started->source, "client.tier1.pull_cert_manager.persisted_requests_load");
}

// ============================================================================
// Cycle entry / TrustList refresh - CL-PULLCRT-005 / section 8.1A.4
// ============================================================================

// @verifies CL-PULLCRT-005
// transition: RefreshingTrustList --LastUpdate advanced--> (download) --Read good--> commit
// RATIFIED EXPECTATION CHANGE (2026-10-03, decision D3): the last assertion was Polling ("proceeded to cert
// renewal"), the TrustList-before-certificate order. Figure 16 of OPC 10000-12 7.6 takes the group's
// certificate first and its TrustList after, so with no certificate update required the cycle refreshes the
// TrustList, commits it and ends Idle.
// @relation(CL-PULLCRT-005, scope=function)
TEST(ClientPullCertTrustList, DownloadsTrustListWhenLastUpdateAdvances)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusFallback =
    ua::Result<bool>{false};  // no certificate update: the cycle reaches the TrustList.
  f.host->set_last_update_time(*f.clock);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(f.host->lastUpdateReads.size(), 1u);
  EXPECT_EQ(f.host->trustListReads.size(), 1u);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);  // committed; no certificate was needed.
}

// @verifies CL-PULLCRT-006
// A TrustList-only production policy commits a changed list and immediately
// broadcasts connection revalidation without entering the certificate RPC path.
// @relation(CL-PULLCRT-006, scope=function)
TEST(ClientPullCertTrustList, TrustListOnlyCycleCommitsAndRevalidates)
{
  Fixture f;
  f.config.renewApplicationCertificate = false;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_TRUE(f.host->applyCalls.front().newTrustList.has_value());
  EXPECT_EQ(f.host->startCalls.size(), 0u);
  EXPECT_EQ(f.host->revalidateCalls, 1u);
  ASSERT_EQ(f.host->revalidateOwnCertificateChanges.size(), 1U);
  EXPECT_FALSE(f.host->revalidateOwnCertificateChanges[0])
    << "a trust-list-only commit must not force every Connection onto the new-Session path";
  ASSERT_EQ(f.host->revalidateServerCertificateRequests.size(), 1U);
  EXPECT_TRUE(f.host->revalidateServerCertificateRequests[0]);
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::TrustListCommitted));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::RevalidationCompleted));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-PULLCRT-006
// An unchanged TrustList-only cycle has nothing to commit, so it neither applies
// storage nor broadcasts a spurious revalidation.
// @relation(CL-PULLCRT-006, scope=function)
TEST(ClientPullCertTrustList, UnchangedTrustListOnlyCycleSkipsApplyAndRevalidation)
{
  Fixture f;
  f.config.renewApplicationCertificate = false;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  ASSERT_TRUE(Access::last_trust_list_update(*impl).has_value());
  ASSERT_EQ(f.host->revalidateCalls, 1u);

  Access::trigger_cycle(impl);
  f.drain();

  EXPECT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_EQ(f.host->revalidateCalls, 1u);
  EXPECT_EQ(f.host->startCalls.size(), 0u);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-PULLCRT-005
// transition: RefreshingTrustList --LastUpdate unchanged + cache--> RequestingCert (skip download)
// @relation(CL-PULLCRT-005, scope=function)
TEST(ClientPullCertTrustList, SkipsDownloadWhenLastUpdateUnchanged)
{
  Fixture f;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);

  // Cycle 1: download + commit the trust list (a cert is delivered so the pending request is fully retired -
  // otherwise a retained requestId would make the next cycle resume polling instead of refreshing).
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);
  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();
  ASSERT_TRUE(Access::last_trust_list_update(*impl).has_value());
  ASSERT_EQ(Access::pending_request_count(*impl), 0u);
  EXPECT_EQ(f.host->trustListReads.size(), 1u);

  // Cycle 2: same LastUpdateTime -> skip the download. The certificate is current, so the cycle goes
  // straight to the TrustList (Figure 16: the certificate comes first).
  f.host->statusFallback =
    ua::Result<bool>{false};  // no certificate update: the cycle reaches the TrustList.
  Access::trigger_cycle(impl);
  f.drain();
  EXPECT_EQ(f.host->lastUpdateReads.size(), 2u);
  EXPECT_EQ(f.host->trustListReads.size(), 1u);  // NOT re-downloaded.
}

// @verifies CL-PULLCRT-005
// transition: RefreshingTrustList --LastUpdate missing && force--> (download)
// @relation(CL-PULLCRT-005, scope=function)
TEST(ClientPullCertTrustList, LastUpdateTimeMissingForcesDownload)
{
  Fixture f;
  f.config.treatLastUpdateTimeMissingAsForceDownload = true;
  auto impl = boot(f);
  f.host->statusFallback =
    ua::Result<bool>{false};  // no certificate update: the cycle reaches the TrustList.
  f.host->set_last_update_time_missing();

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(f.host->lastUpdateReads.size(), 1u);
  EXPECT_EQ(f.host->trustListReads.size(), 1u);
}

// transition: RefreshingTrustList --LastUpdate read bad--> Failed
TEST(ClientPullCertTrustList, LastUpdateReadFailureEntersFailed)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusFallback =
    ua::Result<bool>{false};  // no certificate update: the cycle reaches the TrustList.
  f.host->fail_last_update_time(Status::BadInternalError);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.trust_list_last_update");
}

// transition: RefreshingTrustList --Open(Read) bad--> Failed (cache preserved)
TEST(ClientPullCertTrustList, DownloadFailureEntersFailedAndPreservesCache)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusFallback =
    ua::Result<bool>{false};  // no certificate update: the cycle reaches the TrustList.
  f.host->set_last_update_time(*f.clock);
  f.host->fail_trust_list(Status::BadInternalError);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  EXPECT_FALSE(Access::last_trust_list_update(*impl).has_value());  // cache untouched.
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.trust_list_download");
}

// ============================================================================
// Cert renewal + poll loop - CL-PULLCRT-003 / section 8.1A.4
// ============================================================================

// transition: RefreshingTrustList --(skip)--> RequestingCert --StartRequest good--> Polling
TEST(ClientPullCertRequest, StartRequestGoodEntersPolling)
{
  Fixture f;
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  EXPECT_EQ(f.host->startCalls.size(), 1u);
  EXPECT_EQ(Access::pending_request_count(*impl), 1u);
}

// transition: RequestingCert --StartRequest bad--> Failed
TEST(ClientPullCertRequest, StartRequestBadEntersFailed)
{
  Fixture f;
  auto impl = boot(f);
  f.host->fail_start_request(Status::BadUserAccessDenied);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.start_request");
}

// @verifies CL-PULLCRT-004
// The on-channel own-cert thumbprint is stamped onto each persisted request at issuance.
// @relation(CL-PULLCRT-004, scope=function)
TEST(ClientPullCertRequest, RecordsCertThumbprintPerRequest)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-XYZ";
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(Access::pending_requests(*impl).size(), 1u);
  EXPECT_EQ(Access::pending_requests(*impl).front().certThumbprintSha1, "thumb-XYZ");
}

// @verifies CL-PULLCRT-003
// transition: Polling --Finish Bad_NothingToDo (< max)--> Polling (re-arm) --Finish good--> Persisting
// @relation(CL-PULLCRT-003, scope=function)
TEST(ClientPullCertPoll, PollsFinishRequestUntilGood)
{
  Fixture f;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_nothing_to_do();
  f.host->push_finish_nothing_to_do();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // NothingToDo -> re-arm
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  Access::trigger_poll(impl);
  f.drain();  // NothingToDo -> re-arm
  Access::trigger_poll(impl);
  f.drain();  // cert -> Persisting -> Revalidating -> Idle

  EXPECT_EQ(f.host->finishCalls.size(), 3u);
  EXPECT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-PULLCRT-003
// transition: Polling --Finish Bad_NothingToDo (>= max)--> Idle (persist requestId; resume next cycle)
// @relation(CL-PULLCRT-003, scope=function)
TEST(ClientPullCertPoll, PersistsRequestIdWhenRepeatExhausted)
{
  Fixture f;
  f.config.pollMaxRepeat = 2;
  auto impl = boot(f);  // finishFallback is Bad_NothingToDo - every poll is "still pending".

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling (requestId persisted at issuance)
  Access::trigger_poll(impl);
  f.drain();  // attempt 1
  Access::trigger_poll(impl);
  f.drain();  // exhausted -> Idle

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_EQ(Access::pending_request_count(*impl), 1u);  // requestId retained for the next cycle.
  EXPECT_TRUE(f.host->applyCalls.empty());  // nothing committed.
  auto succeeded = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleSucceeded);
  ASSERT_NE(succeeded, nullptr);  // succeeded WITH the "still pending approval" advisory.
  EXPECT_EQ(succeeded->source, "client.tier1.pull_cert_manager.finish_request");
}

// @verifies CL-PULLCRT-003
// Resume from disk: a persisted request drives Polling immediately with the persisted requestId - no new
// StartRequest is issued.
// @relation(CL-PULLCRT-003, scope=function)
TEST(ClientPullCertPoll, ResumesPollingWithPersistedRequestId)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  f.host->set_persisted({make_pending("thumb-A")});
  auto impl = boot(f);

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  EXPECT_TRUE(f.host->startCalls.empty());  // resumed, not re-issued.
  EXPECT_EQ(Access::pending_request_count(*impl), 1u);

  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);
  Access::trigger_poll(impl);
  f.drain();

  ASSERT_EQ(f.host->finishCalls.size(), 1u);
  EXPECT_EQ(f.host->finishCalls.front().requestId, (ua::NodeId{2, 0xA1U}));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-PULLCRT-003
// transition: Polling --Finish other Bad--> Failed (drop requestId)
// @relation(CL-PULLCRT-003, scope=function)
TEST(ClientPullCertPoll, OtherBadFinishRequestTriggersFailed)
{
  Fixture f;
  auto impl = boot(f);
  f.host->push_finish_bad(Status::BadCertificateInvalid);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // other bad -> Failed

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  EXPECT_EQ(Access::pending_request_count(*impl), 0u);  // requestId dropped (server-side invalid).
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.finish_request");
}

// @verifies CL-PULLCRT-003
// The poll delay grows by pollBackoffMultiplier on each re-arm (asserted via the armed delay, no real wait).
// @relation(CL-PULLCRT-003, scope=function)
TEST(ClientPullCertPoll, PollDelayGrowsByBackoffMultiplier)
{
  Fixture f;
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // enter_polling armed the first poll at pollInitialDelay.
  ASSERT_TRUE(Access::last_armed_poll_delay(*impl).has_value());
  EXPECT_EQ(*Access::last_armed_poll_delay(*impl), std::chrono::milliseconds{5000});
  Access::trigger_poll(impl);
  f.drain();  // NothingToDo -> attempt 1 -> 5000 * 2
  EXPECT_EQ(*Access::last_armed_poll_delay(*impl), std::chrono::milliseconds{10000});
  Access::trigger_poll(impl);
  f.drain();  // NothingToDo -> attempt 2 -> 5000 * 4
  EXPECT_EQ(*Access::last_armed_poll_delay(*impl), std::chrono::milliseconds{20000});
}

// ============================================================================
// Own-cert rotation mid-poll - CL-PULLCRT-004 / section 8.1A.4
// ============================================================================

// @verifies CL-PULLCRT-004
// transition: Polling --mid-cycle own-cert rotation--> RequestingCert (drop stale request; restart)
// @relation(CL-PULLCRT-004, scope=function)
TEST(ClientPullCertRotation, DoesNotPollFinishAfterOwnCertRotation)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling (Start #1, thumbprint "thumb-A")
  const std::uint64_t generationBefore = Access::generation(*impl);

  f.host->ownCertThumbprint = "thumb-B";
  impl->notify_own_cert_rotated_async("thumb-B", [](VoidResult) {});
  f.drain();

  EXPECT_TRUE(f.host->finishCalls.empty());  // never polled the stale request.
  EXPECT_EQ(f.host->startCalls.size(), 2u);  // restarted with the new cert.
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  EXPECT_GT(Access::generation(*impl), generationBefore);
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(
    impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.cert_changed_mid_poll");
}

// @verifies CL-PULLCRT-004
// On entry to Polling from disk, a thumbprint mismatch drops the persisted request and re-requests.
// @relation(CL-PULLCRT-004, scope=function)
TEST(ClientPullCertRotation, DropsPersistedRequestWhenThumbprintMismatches)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  f.host->set_persisted({make_pending("thumb-OLD")});
  auto impl = boot(f);

  EXPECT_EQ(f.host->startCalls.size(), 1u);  // re-requested with the current cert.
  ASSERT_EQ(Access::pending_requests(*impl).size(), 1u);
  EXPECT_EQ(Access::pending_requests(*impl).front().certThumbprintSha1, "thumb-A");
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(
    impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.cert_changed_mid_poll");
}

// @design(section 8.1A.4)
// A tier-1 callback captured at a superseded generation is dropped by the is_current() guard.
TEST(ClientPullCertRotation, StaleGenerationFinishCallbackDropped)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  f.host->captureFinish = true;
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling (Start #1)
  Access::trigger_poll(impl);
  f.drain();  // do_poll -> finish captured (held), gen G
  ASSERT_EQ(f.host->finishCalls.size(), 1u);

  f.host->ownCertThumbprint = "thumb-B";
  impl->notify_own_cert_rotated_async("thumb-B", [](VoidResult) {});
  f.drain();  // gen bumped past G; restart -> Polling (Start #2, not polled)

  auto cert = ua::testing::make_stub_certificate();
  FakePullCertificateManagerHost::FinishResult good{
    FakePullCertificateManagerHost::Host::FinishCertificateResult{}};
  good.value().certificate = cert;
  f.host->complete_finish(std::move(good));  // answer the STALE (gen-G) callback
  f.drain();

  EXPECT_TRUE(f.host->applyCalls.empty());  // the stale cert was NOT committed.
  EXPECT_TRUE(f.host->certRotatedFires.empty());
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
}

// ============================================================================
// Persist + revalidate - CL-PULLCRT-005 / CL-PULLCRT-006 / CL-RECONN-006 / section 8.1A.4
// ============================================================================

// @verifies CL-PULLCRT-005
// @verifies CL-PULLCRT-006
// transition: Polling --Finish good--> Persisting --apply good--> Revalidating --callback--> Idle
// Cert AND trust list are committed in ONE apply (atomicity), then the revalidation broadcast fires.
// @relation(CL-PULLCRT-005, CL-PULLCRT-006, scope=function)
TEST(ClientPullCertCommit, PersistsCertAndTrustListAtomicallyThenRevalidates)
{
  Fixture f;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);  // force a trust-list download this cycle.
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert, ua::ByteString{0xBE, 0xEF});

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // cert -> Persisting -> apply -> Revalidating -> Idle

  ASSERT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_NE(f.host->applyCalls[0].newOwnCert, nullptr);
  EXPECT_TRUE(f.host->applyCalls[0].newTrustList.has_value());
  EXPECT_TRUE(f.host->applyCalls[0].newPrivateKey.has_value());
  EXPECT_EQ(f.host->revalidateCalls, 1u);
  ASSERT_EQ(f.host->revalidateOwnCertificateChanges.size(), 1U);
  EXPECT_TRUE(f.host->revalidateOwnCertificateChanges[0])
    << "the host must distinguish an own-certificate commit from a trust-list-only revalidation";
  ASSERT_EQ(f.host->revalidateServerCertificateRequests.size(), 1U);
  EXPECT_TRUE(f.host->revalidateServerCertificateRequests[0]);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::TrustListCommitted));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::CertificateCommitted));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::RevalidationCompleted));
  EXPECT_TRUE(impl->pull_cert_info()->lastSuccessfulCycleAt.has_value());
}

// @verifies CL-PULLCRT-006
// @verifies CL-RECONN-006
// A committed own-cert rotation fires the certificate-rotated observer (the FSM's pre-reconnect hook).
// @relation(CL-PULLCRT-006, CL-RECONN-006, scope=function)
TEST(ClientPullCertCommit, TriggersReconnectObserverWhenOwnCertRotates)
{
  Fixture f;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();

  ASSERT_EQ(f.host->certRotatedFires.size(), 1u);
  EXPECT_EQ(f.host->certRotatedFires.front().get(), cert.get());
}

// @verifies CL-PULLCRT-006
// A cycle that commits nothing (poll still pending, no trust-list change) runs NO revalidation broadcast.
// @relation(CL-PULLCRT-006, scope=function)
TEST(ClientPullCertCommit, NoRevalidationWhenCommitChangesNothing)
{
  Fixture f;
  f.config.pollMaxRepeat = 1;
  auto impl = boot(f);  // trust-list skipped by default; finishFallback is NothingToDo.

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // NothingToDo exhausted, nothing to commit -> Idle

  EXPECT_TRUE(f.host->applyCalls.empty());
  EXPECT_EQ(f.host->revalidateCalls, 0);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::CycleSucceeded));
}

// @verifies CL-RECONN-006
// Disabling immediate server-certificate revalidation cannot suppress Part 4 section 6.7: an own-certificate
// rotation still broadcasts the mandatory new-Session request, without asking Connections to revalidate the
// server certificate.
// @relation(CL-RECONN-006, scope=function)
TEST(ClientPullCertCommit, RevalidateImmediatelyDisabledStillBroadcastsOwnCertificateRotation)
{
  Fixture f;
  f.config.revalidateImmediatelyOnCommit = false;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();

  EXPECT_EQ(f.host->revalidateCalls, 1);
  ASSERT_EQ(f.host->revalidateOwnCertificateChanges.size(), 1U);
  EXPECT_TRUE(f.host->revalidateOwnCertificateChanges[0]);
  ASSERT_EQ(f.host->revalidateServerCertificateRequests.size(), 1U);
  EXPECT_FALSE(f.host->revalidateServerCertificateRequests[0]);
  EXPECT_EQ(f.host->certRotatedFires.size(), 1u);  // rotation still announced.
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::CertificateCommitted));
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::RevalidationCompleted));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-SECADMIN-004
// A trust-list-only commit retains the deferred policy: no broadcast occurs when immediate server-certificate
// revalidation is disabled and no own-certificate rotation requires a new Session.
// @relation(CL-SECADMIN-004, scope=function)
TEST(ClientPullCertCommit, RevalidateImmediatelyDisabledSkipsTrustListOnlyBroadcast)
{
  Fixture f;
  f.config.renewApplicationCertificate = false;
  f.config.revalidateImmediatelyOnCommit = false;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_TRUE(f.host->applyCalls.front().newTrustList.has_value());
  EXPECT_EQ(f.host->revalidateCalls, 0);
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::TrustListCommitted));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @verifies CL-PULLCRT-005
// transition: Persisting --apply bad--> Failed (staging discarded; runtime store untouched -> cache
// preserved)
// @relation(CL-PULLCRT-005, scope=function)
TEST(ClientPullCertCommit, ApplyFailureEntersFailedAndRollsBack)
{
  Fixture f;
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);
  f.host->fail_apply(Status::BadUserAccessDenied);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();  // finish good -> Persisting -> apply bad -> Failed

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  EXPECT_FALSE(Access::last_trust_list_update(*impl).has_value());  // rollback: cache not advanced.
  EXPECT_EQ(f.host->revalidateCalls, 0);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "host.persistence");
}

// ============================================================================
// Backoff / failure accounting - section 8.1A.4
// ============================================================================

// transition: Failed --retry--> next cycle; the backoff grows but is capped at maxCycleBackoff.
TEST(ClientPullCertBackoff, CycleFailureBackoffCappedAtMax)
{
  Fixture f;
  f.config.minCycleBackoff = std::chrono::seconds{60};
  f.config.maxCycleBackoff = std::chrono::seconds{90};
  f.config.cycleBackoffJitterPct = 0.0;
  f.host->fail_start_request(Status::BadInternalError);
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // failure 1 -> armed 60s
  EXPECT_EQ(Access::failure_count(*impl), 1u);
  ASSERT_TRUE(Access::last_armed_cycle_delay(*impl).has_value());
  EXPECT_EQ(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{60000});

  Access::trigger_cycle(impl);
  f.drain();  // failure 2 -> base 120s, capped to 90s
  EXPECT_EQ(Access::failure_count(*impl), 2u);
  EXPECT_EQ(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{90000});
}

// transition: Revalidating --callback--> Idle sets mFailureCount = 0 after a run of failures.
TEST(ClientPullCertBackoff, FailureCountResetsOnSuccess)
{
  Fixture f;
  f.host->fail_start_request(Status::BadInternalError);
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // fail
  EXPECT_EQ(Access::failure_count(*impl), 1u);

  f.host->startResponse.reset();  // StartRequest now succeeds (default Good).
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);
  Access::trigger_cycle(impl);
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // cert -> commit -> Idle

  EXPECT_EQ(Access::failure_count(*impl), 0u);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// @design(section 8.1A.5)
// The terminal cycle-failure chain is rooted at the pull-cert cycle source and carries the step StatusCode as
// its inner cause.
TEST(ClientPullCertChain, TerminalChainSourceIsCycleAndCarriesStepStatus)
{
  Fixture f;
  f.host->fail_start_request(Status::BadUserAccessDenied);
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  auto chain = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(chain, nullptr);
  EXPECT_EQ(chain->source, "client.tier1.pull_cert_manager.cycle");
  EXPECT_EQ(chain->code, "PULL_CERT_CYCLE_FAILED");
  EXPECT_EQ(chain->innerStatus, StatusCode{Status::BadUserAccessDenied}.value());
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->source, "client.tier1.pull_cert_manager.start_request");
}

// ============================================================================
// force_cycle / stop / lifecycle - section 8.1A.1 / section 8.1A.3 / section 8.1A.6
// ============================================================================

// @design(section 8.1A.1)
// force_cycle resolves Good when the cycle succeeds.
TEST(ClientPullCertForceCycle, ResolvesGoodOnSuccess)
{
  Fixture f;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  bool resolved = false;
  bool good = false;
  impl->force_cycle_async(
    [&](VoidResult result)
    {
      resolved = true;
      good = result.is_good();
    });
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // commit -> Idle -> ack fires

  EXPECT_TRUE(resolved);
  EXPECT_TRUE(good);
}

// @design(section 8.1A.1)
// force_cycle resolves Good even when the cycle fails (the failure is in pull_cert_info().lastError).
TEST(ClientPullCertForceCycle, ResolvesGoodOnFailure)
{
  Fixture f;
  f.host->fail_start_request(Status::BadInternalError);
  auto impl = boot(f);

  bool resolved = false;
  bool good = false;
  impl->force_cycle_async(
    [&](VoidResult result)
    {
      resolved = true;
      good = result.is_good();
    });
  f.drain();

  EXPECT_TRUE(resolved);
  EXPECT_TRUE(good);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
}

// transition: any (not Revalidating) --stop_async--> Closed
TEST(ClientPullCertStop, StopEntersClosedCancelsTimersAndClosesGds)
{
  Fixture f;
  auto impl = boot(f);

  bool stopped = false;
  impl->stop_async([&](VoidResult result) { stopped = result.is_good(); });
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Closed);
  EXPECT_EQ(f.host->closeGdsCalls, 1);
  EXPECT_TRUE(f.host->has_lifecycle(PullCertLifecycleEvent::Stopped));
  EXPECT_TRUE(stopped);
}

// stop cancels a pending force_cycle callback with Bad_Cancelled.
TEST(ClientPullCertStop, StopCancelsPendingForceCycle)
{
  Fixture f;
  auto impl = boot(f);

  bool forceResolved = false;
  StatusCode forceStatus;
  impl->force_cycle_async(
    [&](VoidResult result)
    {
      forceResolved = true;
      forceStatus = result.status_code();
    });
  f.drain();  // cycle running (Polling); ack still pending.
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Polling);

  impl->stop_async([](VoidResult) {});
  f.drain();

  EXPECT_TRUE(forceResolved);
  EXPECT_EQ(forceStatus.as_status(), Status::BadRequestCancelledByClient);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Closed);
}

// transition: Revalidating --stop_async--> (queued) --revalidation callback--> Closed
TEST(ClientPullCertStop, StopDuringRevalidationAwaitsCompletion)
{
  Fixture f;
  f.host->captureRevalidate = true;  // hold the broadcast open.
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // cert -> Persisting -> apply -> Revalidating (broadcast held)
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Revalidating);

  bool stopped = false;
  impl->stop_async([&](VoidResult) { stopped = true; });
  f.drain();
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Revalidating);  // stop is queued.
  EXPECT_FALSE(stopped);

  f.host->complete_revalidate();  // broadcast returns -> close proceeds.
  f.drain();

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Closed);
  EXPECT_TRUE(stopped);
  EXPECT_EQ(f.host->closeGdsCalls, 1);
}

// ============================================================================
// section 3.1 panel fixes - C1 / H2..H6 / M1..M9
// ============================================================================

// Finds a structured-context value by key on an ErrorDetail layer.
std::optional<std::string> find_context(
  const std::shared_ptr<const ua::ErrorDetail>& detail, std::string_view key)
{
  if (!detail)
  {
    return std::nullopt;
  }
  for (const auto& entry : detail->context)
  {
    if (entry.key == key)
    {
      return entry.value;
    }
  }
  return std::nullopt;
}

// C1 (CRITICAL): a cert-rotation notify while Idle must NOT brick renewal. The armed cycle timer is
// generation-guarded, so the generation bump has to be paired with a re-arm at the NEW generation, and a real
// armed timer must then actually drive a fresh cycle. Uses a REAL armed timer + settle (NOT trigger_cycle,
// which would use the current generation and hide the bug).
TEST(ClientPullCertRotation, NotifyWhileIdleRearmsCycleAtNewGeneration)
{
  Fixture f;
  f.config.minCycleBackoff = std::chrono::seconds{1};  // distinct re-arm delay, observed via last_armed_*.
  auto impl = boot(f);
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  const std::uint64_t genBefore = Access::generation(*impl);
  const std::size_t startsBefore = f.host->startCalls.size();
  const std::size_t lastUpdateReadsBefore = f.host->lastUpdateReads.size();

  f.host->ownCertThumbprint = "thumb-B";
  impl->notify_own_cert_rotated_async("thumb-B", [](VoidResult) {});
  f.drain();

  // Deterministic C1 proof (no wall-clock timer wait): notify-while-Idle bumped the generation AND re-armed
  // the cycle timer at the NEW generation with the short delay. Before the fix the timer was never re-armed,
  // so its captured generation stayed stale (!= the bumped current generation) and the armed timer silently
  // no-op'd forever - bricking renewal + trust-list refresh.
  EXPECT_GT(Access::generation(*impl), genBefore);
  ASSERT_TRUE(Access::last_armed_cycle_delay(*impl).has_value());
  EXPECT_EQ(*Access::last_armed_cycle_delay(*impl), std::chrono::milliseconds{1000});
  ASSERT_TRUE(Access::last_armed_cycle_generation(*impl).has_value());
  EXPECT_EQ(*Access::last_armed_cycle_generation(*impl), Access::generation(*impl));  // fresh gen, not stale

  // And the re-armed cycle drives a fresh renewal (not bricked) - driven through the same start_cycle path
  // the armed timer would invoke, at the current generation. Deterministic, no real-timer wait.
  Access::trigger_cycle(impl);
  f.drain();
  // The renewal completes; the group's TrustList follows its certificate (Figure 16).
  f.host->push_finish_certificate(ua::testing::make_stub_certificate());
  Access::trigger_poll(impl);
  f.drain();
  EXPECT_GT(f.host->lastUpdateReads.size(), lastUpdateReadsBefore);
  EXPECT_GT(f.host->startCalls.size(), startsBefore);
}

// C1 (CRITICAL): a cert-rotation notify during Revalidating must not strand a queued stop.
TEST(ClientPullCertRotation, NotifyDuringRevalidationDoesNotStrandQueuedStop)
{
  Fixture f;
  f.host->captureRevalidate = true;  // hold the broadcast open.
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // cert -> Persisting -> apply -> Revalidating (broadcast held)
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Revalidating);

  bool stopped = false;
  impl->stop_async([&](VoidResult) { stopped = true; });
  f.drain();  // stop queued (awaiting the broadcast).
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Revalidating);

  impl->notify_own_cert_rotated_async("thumb-B", [](VoidResult) {});
  f.drain();  // rotation arrives while the stop is queued and the broadcast is in flight.

  f.host->complete_revalidate();  // broadcast returns.
  f.drain();

  EXPECT_TRUE(stopped);  // the queued stop is honored, not stranded.
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Closed);
}

// H2: a failed GDS bootstrap must RE-OPEN the connection on the retry cycle (not run RPCs against a dead
// conn) and must trip the diagnostics failure count. spec-gap: section 8.1A.4 has no Failed->BootstrappingGds
// edge; the re-open is added here.
TEST(ClientPullCertBootstrap, FailedBootstrapReopensGdsOnRetry)
{
  Fixture f;
  f.host->fail_open_gds(Status::BadConnectionRejected);
  auto impl = boot(f);
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  ASSERT_FALSE(Access::gds_connected(*impl));
  ASSERT_EQ(f.host->openGdsCalls.size(), 1u);
  EXPECT_GE(Access::failure_count(*impl), 1u);  // diagnostics count tripped.

  f.host->openGdsResponse.reset();  // GDS now reachable.
  Access::trigger_cycle(impl);  // the retry cycle fires.
  f.drain();

  EXPECT_EQ(f.host->openGdsCalls.size(), 2u);  // re-opened, not run against a dead connection.
  EXPECT_TRUE(Access::gds_connected(*impl));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// H3 (ErrorDetail-drop): a failed revalidation broadcast must surface an advisory on the cycle outcome - the
// cert/trust-list commit still stands (cycle succeeds) but the drop must not be silent.
TEST(ClientPullCertCommit, RevalidateFailureSurfacesAdvisoryOnCycleOutcome)
{
  Fixture f;
  auto impl = boot(f);
  f.host->fail_revalidate(Status::BadInternalError);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();  // commit -> revalidate (bad) -> Idle

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);  // cycle still considered successful.
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.revalidate");
  EXPECT_EQ(impl->pull_cert_info()->lastError->innerStatus, StatusCode{Status::BadInternalError}.value());
  auto succeeded = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleSucceeded);
  ASSERT_NE(succeeded, nullptr);
  EXPECT_EQ(succeeded->source, "client.tier1.pull_cert_manager.revalidate");
}

// H4(a) (trust gap): a null bootstrap trust store = accept-any = MITM; the manager must refuse to open the
// GDS and enter Failed with an advisory.
TEST(ClientPullCertBootstrap, NullBootstrapTrustStoreRefusesToOpenGds)
{
  Fixture f;
  f.config.bootstrapTrustStore = nullptr;  // explicit MITM-risk config.
  auto impl = boot(f);

  EXPECT_TRUE(f.host->openGdsCalls.empty());  // never opened.
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(impl->pull_cert_info()->lastError->code, "PULL_CERT_BOOTSTRAP_TRUST_STORE_MISSING");
  EXPECT_EQ(impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.bootstrap");
}

// H4(b) (trust gap): a Good FinishRequest with no certificate is malformed - the cert<=>request binding
// cannot be established, so the manager drops it rather than commit a null cert.
TEST(ClientPullCertPoll, GoodFinishWithNullCertificateIsRejected)
{
  Fixture f;
  auto impl = boot(f);
  f.host->push_finish_certificate(nullptr);  // malformed Good: no certificate.

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();

  EXPECT_TRUE(f.host->applyCalls.empty());  // a null cert was never committed.
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.cert_binding");
}

// RATIFIED EXPECTATION CHANGE (2026-10-03, decision D3): this arm asserted the H6 advisory that only the
// first configured group was serviced. Figure 16 of OPC 10000-12 7.6 processes every CertificateGroup each
// cycle ("All CertificateGroups processed"), and the cycle now does: each configured group is asked for its
// status, a certificate is requested where one is required, and each group's TrustList is refreshed once.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST(ClientPullCertBootstrap, EveryConfiguredGroupIsProcessedInOneCycle)
{
  Fixture f;
  ua::client::CertificateGroupConfig groupOne;
  groupOne.certificateGroupId = default_group_id();
  ua::client::CertificateGroupConfig groupTwo;
  groupTwo.certificateGroupId = ua::NodeId{12345};
  f.config.certificateGroups = {groupOne, groupTwo};
  auto impl = boot(f);
  EXPECT_EQ(impl->pull_cert_info()->lastError, nullptr) << "no multi-group advisory: both groups are served";

  // Neither group needs a certificate: the cycle asks both, then refreshes both TrustLists.
  f.host->statusScript = {ua::Result<bool>{false}, ua::Result<bool>{false}};
  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->statusCalls.size(), 2u) << "GetCertificateStatus for every configured group";
  EXPECT_EQ(f.host->statusCalls[0].certificateGroupId, default_group_id());
  EXPECT_EQ(f.host->statusCalls[1].certificateGroupId, (ua::NodeId{12345}));
  EXPECT_TRUE(f.host->startCalls.empty());
  ASSERT_EQ(f.host->lastUpdateReads.size(), 2u) << "each group's TrustList is checked";
  EXPECT_EQ(f.host->lastUpdateReads[0], default_group_id());
  EXPECT_EQ(f.host->lastUpdateReads[1], (ua::NodeId{12345}));
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// Two certificate types of one CertificateGroup: each type is asked about and requested on its own, and the
// group's one TrustList is refreshed once.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST(ClientPullCertBootstrap, TwoTypesOfOneGroupShareItsTrustListRefresh)
{
  Fixture f;
  ua::client::CertificateGroupConfig rsa;
  rsa.certificateTypeId = ua::NodeId{ua::ObjectTypeId::RsaSha256ApplicationCertificateType};
  ua::client::CertificateGroupConfig ecc;
  ecc.certificateTypeId = ua::NodeId{ua::ObjectTypeId::EccNistP256ApplicationCertificateType};
  f.config.certificateGroups = {rsa, ecc};
  auto impl = boot(f);

  f.host->statusScript = {ua::Result<bool>{false}, ua::Result<bool>{false}};
  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->statusCalls.size(), 2u);
  EXPECT_EQ(f.host->statusCalls[0].certificateTypeId, rsa.certificateTypeId);
  EXPECT_EQ(f.host->statusCalls[1].certificateTypeId, ecc.certificateTypeId);
  EXPECT_EQ(f.host->lastUpdateReads.size(), 1u) << "one TrustList per group, not per type";
}

// OPC 10000-12 7.6 Table 21: GetCertificateStatus decides whether a certificate is requested. FALSE: no
// request is made, and the TrustList is still refreshed. Falsifiable: a cycle that renews unconditionally
// issues a StartSigningRequest every cycle.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(ClientPullCertStatus, NoUpdateRequiredMakesNoRequestAndStillRefreshesTheTrustList)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusScript = {ua::Result<bool>{false}};
  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->statusCalls.size(), 1u);
  EXPECT_EQ(f.host->statusCalls[0].applicationId, f.config.applicationId);
  EXPECT_TRUE(f.host->startCalls.empty()) << "no certificate is requested when none is required";
  EXPECT_EQ(f.host->lastUpdateReads.size(), 1u) << "the TrustList is still checked";
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// Control: TRUE starts a request for the group and type that were asked about.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(ClientPullCertStatus, UpdateRequiredStartsARequest)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusScript = {ua::Result<bool>{true}};
  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->statusCalls.size(), 1u);
  ASSERT_EQ(f.host->startCalls.size(), 1u);
  EXPECT_EQ(f.host->startCalls[0].certificateGroupId, f.host->statusCalls[0].certificateGroupId);
  EXPECT_EQ(f.host->startCalls[0].certificateTypeId, f.host->statusCalls[0].certificateTypeId);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
}

// A failed GetCertificateStatus fails the cycle with its status; it is not read as "no update required", and
// the group's TrustList is still checked.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(ClientPullCertStatus, AFailedStatusCallFailsTheCycle)
{
  Fixture f;
  auto impl = boot(f);
  f.host->statusScript = {ua::Result<bool>{ua::StatusCode{Status::BadNotFound}}};
  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_TRUE(f.host->startCalls.empty());
  EXPECT_EQ(f.host->lastUpdateReads.size(), 1u)
    << "the group's TrustList is still checked: a status failure must not stop revocation updates";
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  EXPECT_NE(detail->summary.find("BadNotFound"), std::string::npos)
    << "the CertificateManager's status reaches the failure chain: " << detail->summary;
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.certificate_status");
}

// A status failure in an earlier group does not stop a later group's TrustList (and CRL) refresh; the cycle
// still ends Failed with that status. Falsifiable: ending the cycle at the failure skips the second group.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST(ClientPullCertStatus, AnEarlierStatusFailureStillRefreshesALaterGroup)
{
  Fixture f;
  ua::client::CertificateGroupConfig groupOne;
  groupOne.certificateGroupId = default_group_id();
  ua::client::CertificateGroupConfig groupTwo;
  groupTwo.certificateGroupId = ua::NodeId{12345};
  f.config.certificateGroups = {groupOne, groupTwo};
  auto impl = boot(f);
  f.host->statusScript = {ua::Result<bool>{ua::StatusCode{Status::BadNotFound}}, ua::Result<bool>{false}};

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->statusCalls.size(), 2u) << "the second group is still asked";
  ASSERT_EQ(f.host->lastUpdateReads.size(), 2u) << "both groups' TrustLists are checked";
  EXPECT_EQ(f.host->lastUpdateReads[1], ua::NodeId{12345});
  EXPECT_TRUE(f.host->startCalls.empty());
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  EXPECT_NE(detail->summary.find("BadNotFound"), std::string::npos) << detail->summary;
}

// A group committed earlier in the cycle is revalidated although a later group fails (CL-PULLCRT-006):
// the commit stands and the next cycle does not make it again. Falsifiable: a failure that wipes the cycle's
// commit flags skips the broadcast for the committed TrustList.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST(ClientPullCertStatus, ALaterGroupFailureStillRevalidatesAnEarlierCommit)
{
  Fixture f;
  ua::client::CertificateGroupConfig groupOne;
  groupOne.certificateGroupId = default_group_id();
  ua::client::CertificateGroupConfig groupTwo;
  groupTwo.certificateGroupId = ua::NodeId{12345};
  f.config.certificateGroups = {groupOne, groupTwo};
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);  // group one downloads and commits its TrustList
  // Group two needs a certificate and its StartSigningRequest is refused, which ends the cycle at once.
  f.host->statusScript = {ua::Result<bool>{false}, ua::Result<bool>{true}};
  f.host->startResponse = ua::Result<ua::NodeId>{ua::StatusCode{Status::BadRequestNotAllowed}};

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.host->applyCalls.size(), 1u) << "group one committed";
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed) << "group two failed";
  EXPECT_EQ(f.host->revalidateCalls, 1) << "the committed TrustList is still revalidated";
}

// Control: two groups that both commit are revalidated once, after the last group.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST(ClientPullCertStatus, TwoCommittingGroupsRevalidateOnceAfterTheLast)
{
  Fixture f;
  ua::client::CertificateGroupConfig groupOne;
  groupOne.certificateGroupId = default_group_id();
  ua::client::CertificateGroupConfig groupTwo;
  groupTwo.certificateGroupId = ua::NodeId{12345};
  f.config.certificateGroups = {groupOne, groupTwo};
  auto impl = boot(f);
  f.host->set_last_update_time(*f.clock);
  f.host->statusScript = {ua::Result<bool>{false}, ua::Result<bool>{false}};

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(f.host->applyCalls.size(), 2u) << "each group commits its TrustList";
  EXPECT_EQ(f.host->revalidateCalls, 1) << "one broadcast for the cycle";
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Idle);
}

// A certificate rotation while GetCertificateStatus is in flight asks again; it does not request a
// certificate the CertificateManager has not asked for (Table 21). Falsifiable: restarting the renewal there
// issues StartSigningRequest without a status answer.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(ClientPullCertStatus, ARotationDuringTheStatusQueryAsksAgain)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  auto impl = boot(f);
  f.host->captureStatus = true;  // hold the GetCertificateStatus answer
  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  ASSERT_EQ(f.host->statusCalls.size(), 1u);
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::RequestingCert);

  f.host->ownCertThumbprint = "thumb-B";
  impl->notify_own_cert_rotated_async("thumb-B", [](VoidResult) {});
  f.drain();

  EXPECT_TRUE(f.host->startCalls.empty()) << "no certificate is requested without a status answer";
  EXPECT_EQ(f.host->statusCalls.size(), 2u) << "the status is asked again";
}

// A pending request is finished before anything else is asked (Figure 16 SigningRequestPending): no
// GetCertificateStatus for a group whose request is still open.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(ClientPullCertStatus, APendingRequestIsFinishedWithoutAskingForTheStatus)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  f.host->set_persisted({make_pending("thumb-A")});
  auto impl = boot(f);

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  EXPECT_TRUE(f.host->statusCalls.empty());
}

// M1: a perpetually-stuck pending request must not starve the trust-list / CRL refresh forever.
TEST(ClientPullCertTrustList, StuckPendingDoesNotStarveTrustListRefresh)
{
  Fixture f;
  f.config.pollMaxRepeat = 1;
  f.config.treatLastUpdateTimeMissingAsForceDownload = false;
  auto impl = boot(f);  // finishFallback = Bad_NothingToDo (perpetually stuck).

  // Cycle 0: LastUpdateTime missing -> no trust-list download; request issued, poll exhausts -> pending
  // persisted.
  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling
  Access::trigger_poll(impl);
  f.drain();  // exhausted -> Idle, pending retained
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  ASSERT_EQ(Access::pending_request_count(*impl), 1u);
  ASSERT_EQ(f.host->trustListReads.size(), 0u);

  // Now the server publishes an advancing LastUpdateTime; a stuck pending would otherwise skip the refresh.
  f.host->set_last_update_time(*f.clock);
  const std::size_t before = f.host->trustListReads.size();
  for (int cycle = 0; cycle < 3; ++cycle)
  {
    Access::trigger_cycle(impl);
    f.drain();
    Access::trigger_poll(impl);
    f.drain();
  }
  EXPECT_GE(f.host->trustListReads.size(), before + 1);  // refreshed despite the stuck pending.
}

// M2: the section 8.1A.5 terminal chain carries the structured context map (failed_state / failure_count /
// group_id).
TEST(ClientPullCertChain, TerminalChainCarriesContextMap)
{
  Fixture f;
  f.host->fail_start_request(Status::BadUserAccessDenied);
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();

  auto chain = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(chain, nullptr);
  auto failedState = find_context(chain, "pull_cert.failed_state");
  ASSERT_TRUE(failedState.has_value());
  EXPECT_EQ(*failedState, "RequestingCert");
  auto failureCount = find_context(chain, "pull_cert.failure_count");
  ASSERT_TRUE(failureCount.has_value());
  EXPECT_EQ(*failureCount, "1");
  EXPECT_TRUE(find_context(chain, "pull_cert.group_id").has_value());
}

// M3 (CL-PULLCRT-004): the on-channel thumbprint is re-checked on EVERY poll, not just on Polling entry - a
// cert that rotates between polls (without a notify) must drop the stale request.
TEST(ClientPullCertRotation, PollRechecksThumbprintAndDropsStaleRequest)
{
  Fixture f;
  f.host->ownCertThumbprint = "thumb-A";
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // -> Polling (Start #1, thumbprint thumb-A)
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Polling);

  f.host->ownCertThumbprint = "thumb-B";  // cert rotates WITHOUT a notify.
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert);  // a cert is queued for the now-stale poll.
  Access::trigger_poll(impl);
  f.drain();

  EXPECT_TRUE(f.host->applyCalls.empty());  // the stale cert was never committed.
  EXPECT_EQ(f.host->startCalls.size(), 2u);  // re-requested with the new cert.
  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(
    impl->pull_cert_info()->lastError->source, "client.tier1.pull_cert_manager.cert_changed_mid_poll");
}

// M4: the poll delay applies the configured jitter band (mirrors the cycle backoff).
TEST(ClientPullCertPoll, PollDelayAppliesJitterBand)
{
  Fixture f;
  f.config.pollJitterPct = 0.20;  // +/-20%.
  f.config.pollInitialDelay = std::chrono::milliseconds{5000};
  f.config.pollBackoffMultiplier = 1.0;  // isolate jitter: base is constant across attempts.
  f.config.pollMaxRepeat = 60;
  auto impl = boot(f);  // finishFallback = NothingToDo -> each poll re-arms.

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // first poll armed.
  bool anyDiffersFromBase = false;
  for (int sample = 0; sample < 30; ++sample)
  {
    ASSERT_TRUE(Access::last_armed_poll_delay(*impl).has_value());
    const auto delay = *Access::last_armed_poll_delay(*impl);
    EXPECT_GE(delay, std::chrono::milliseconds{4000});  // 5000 * 0.8
    EXPECT_LE(delay, std::chrono::milliseconds{6000});  // 5000 * 1.2
    if (delay != std::chrono::milliseconds{5000})
    {
      anyDiffersFromBase = true;
    }
    Access::trigger_poll(impl);
    f.drain();
  }
  EXPECT_TRUE(anyDiffersFromBase);  // jitter actually perturbs the delay (unjittered code leaves it at base).
}

// M5(a): a stop after a FAILED bootstrap must still close the GDS connection (an open was requested).
TEST(ClientPullCertStop, StopAfterFailedBootstrapStillClosesGds)
{
  Fixture f;
  f.host->fail_open_gds(Status::BadConnectionRejected);
  auto impl = boot(f);
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  ASSERT_FALSE(Access::gds_connected(*impl));

  impl->stop_async([](VoidResult) {});
  f.drain();

  EXPECT_EQ(f.host->closeGdsCalls, 1);  // closed despite never fully connecting.
}

// M5(c): destroying the manager with a pending force_cycle ack fires it Cancelled rather than dropping it.
TEST(ClientPullCertLifecycle, DestructorCancelsPendingForceCycle)
{
  Fixture f;
  auto impl = boot(f);

  bool resolved = false;
  StatusCode status;
  impl->force_cycle_async(
    [&](VoidResult result)
    {
      resolved = true;
      status = result.status_code();
    });
  f.drain();  // cycle running (Polling); ack pending.
  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Polling);
  ASSERT_FALSE(resolved);

  impl.reset();  // drop the last strong ref -> dtor fires the pending ack.

  EXPECT_TRUE(resolved);
  EXPECT_EQ(status.as_status(), Status::BadRequestCancelledByClient);
}

// M6: the per-cycle private-key scratch is wiped at the cycle terminus (secrets hygiene).
TEST(ClientPullCertCommit, ClearsCertScratchAfterCommit)
{
  Fixture f;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate(cert, ua::ByteString{0xBE, 0xEF});  // carries a private key.

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();  // commit -> Idle

  ASSERT_EQ(Access::state(*impl), PullCertManagementState::Idle);
  EXPECT_FALSE(Access::cycle_new_key_present(*impl));  // key scratch wiped at the cycle terminus.
}

// M7: a corrupt persisted-load advisory must not be lost when the GDS bootstrap ALSO fails - surface both.
TEST(ClientPullCertBootstrap, CorruptPersistenceAndBootstrapFailureSurfaceBoth)
{
  Fixture f;
  f.host->fail_persisted_load(Status::BadDecodingError);
  f.host->fail_open_gds(Status::BadConnectionRejected);
  auto impl = boot(f);

  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Failed);
  auto detail = f.host->last_lifecycle_detail(PullCertLifecycleEvent::CycleFailed);
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "PULL_CERT_GDS_BOOTSTRAP_FAILED");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadConnectionRejected}.value());
  ASSERT_NE(detail->cause, nullptr);  // the corrupt-persistence advisory survives in the cause chain.
  EXPECT_EQ(detail->cause->source, "client.tier1.pull_cert_manager.persisted_requests_load");
}

// M8: a failed persist write must not be silently dropped - it raises an advisory.
TEST(ClientPullCertPoll, PersistWriteFailureRaisesAdvisory)
{
  Fixture f;
  f.host->fail_persisted_write(Status::BadUserAccessDenied);
  auto impl = boot(f);

  impl->force_cycle_async([](VoidResult) {});
  f.drain();  // StartRequest good -> persist (fails) -> advisory

  ASSERT_NE(impl->pull_cert_info()->lastError, nullptr);
  EXPECT_EQ(impl->pull_cert_info()->lastError->code, "PULL_CERT_PERSIST_WRITE_FAILED");
}

// M9: the issuer chain delivered with a renewed cert is threaded into the atomic commit.
TEST(ClientPullCertCommit, ThreadsIssuerChainIntoApply)
{
  Fixture f;
  auto impl = boot(f);
  auto cert = ua::testing::make_stub_certificate();
  auto issuer = ua::testing::make_stub_certificate();
  f.host->push_finish_certificate_with_issuers(cert, {issuer});

  impl->force_cycle_async([](VoidResult) {});
  f.drain();
  Access::trigger_poll(impl);
  f.drain();

  ASSERT_EQ(f.host->applyCalls.size(), 1u);
  EXPECT_EQ(f.host->applyCalls[0].newIssuerChain.size(), 1u);
}

// The public shared-handle facade forwards to the strand-core Impl.
TEST(ClientPullCertFacade, ForwardsToImpl)
{
  Fixture f;
  auto impl = boot(f);
  auto facade = PullCertificateManagerFactory::wrap(impl);

  ASSERT_NE(facade->pull_cert_info(), nullptr);
  EXPECT_EQ(facade->pull_cert_info()->state, PullCertManagementState::Idle);

  bool stopped = false;
  facade->stop_async([&](VoidResult result) { stopped = result.is_good(); });
  f.drain();

  EXPECT_TRUE(stopped);
  EXPECT_EQ(Access::state(*impl), PullCertManagementState::Closed);
}

}  // namespace
