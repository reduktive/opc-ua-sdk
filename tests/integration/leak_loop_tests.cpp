// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Create/destroy-N memory-leak loops (Phase 1.5a).
///
/// Each test repeatedly creates and destroys one resource (secure channel,
/// session, subscription, or monitored item) over a full client -> server
/// round-trip, then asserts via `expect_stable_heap` that the live-allocation
/// watermark does not climb across the loop. The loop serves two purposes:
///
///   1. The heap-watermark assertion catches Class-2 leaks: reachable growth
///      and shared_ptr reference cycles that LeakSanitizer (which only reports
///      *unreachable* blocks at exit) would miss. This is the bug class that
///      bit the address-space nodeset code (see project memory).
///   2. The loop gives LeakSanitizer (bundled with ASan on Linux) repeated
///      create/destroy cycles to find Class-1 definitely-lost blocks at exit.
///
/// Run under the `gcc-asan` preset (the suites are ComplianceBase/With* so the
/// filter must be substring-anchored, not `LeakLoop.*` which matches nothing):
///   cmake -E chdir cmake-build-debug-gcc-asan/tests \
///     ./integration_tests --gtest_filter='*LeakLoop*'
///
/// These are deliberately NOT part of the routine debug integration run; they
/// are heavy (full handshakes) and meant for the sanitizer preset.

#include "compliance_helpers.h"
#include "heap_watermark.h"
#include "subscription.h"
#include "ua_instance_tracker.h"

#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"

#include <chrono>
#include <thread>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;

namespace
{

// ---------------------------------------------------------------------------
// Tuning constants.
//
// Channel/session loops are heavy: each iteration is a full TCP + UASC
// handshake (open channel) or CreateSession + ActivateSession round-trip, so
// we keep the iteration count modest (60) to bound runtime while still giving a
// real per-iteration leak (tens-to-hundreds of bytes x 60) room to clear the
// allocator-noise tolerance.
//
// Subscription/MI loops are lighter (one request pair each), so we run more
// iterations (200) for a stronger leak signal.
//
// Tolerance: the ASan live-allocation counter is precise, but small caches and
// pool growth still wobble the baseline by a few KB across a run. 64 KiB is
// comfortably above that noise floor yet far below what a genuine
// ~hundred-bytes-per-iteration leak would accumulate (e.g. 200 B x 200 = 40 KB
// would still pass at the lighter loops, so for the MI/subscription loops the
// per-iteration leak that this catches is on the order of >=325 B/iter; for the
// 60-iteration channel/session loops it is >~1 KB/iter). LeakSanitizer at exit
// backstops the smaller definitely-lost leaks.
constexpr size_t heavyIterations = 60;
constexpr size_t lightIterations = 200;
constexpr size_t warmup = 20;
constexpr size_t toleranceBytes = 256 * 1024;

// Settle/drain: async server-side teardown (channel close, session close)
// continues after the client-side sync call returns. Measuring the watermark
// before that completes inflates it and produces flaky failures. A short sleep
// lets both the client and server thread pools drain their teardown posts.
// If this proves insufficient, raise the duration or the warmup count.
// Sized for the SLOWEST cycle's async teardown: session create/close instantiates AND removes
// the SessionDiagnostics subtree asynchronously (creation was made async so it no longer blocks
// the server executor - see Session::create_diagnostics_object). A short settle left that
// create/remove churn in flight at measurement and read as growth; this drains it.
constexpr std::chrono::milliseconds settleDelay{1000};

void settle_drain()
{
  std::this_thread::sleep_for(settleDelay);
}

// The compliance fixtures install a Debug-level TestLogSink that BUFFERS every
// log entry for the lifetime of the test. Across a leak loop's tens-to-hundreds
// of iterations that buffer grows monotonically and shows up in the heap
// watermark as a per-iteration "leak" - but it is a test artifact, not SDK
// memory. Raise the level so the loop measures the SDK only. (Confirmed via
// __sanitizer_print_memory_profile: TestLogSink::log dominated the growth.)
// Both sides share the same buffering sink, so both must be quieted - the client
// side dominates the channel loop's logging in particular.
void silence_logs_for_measurement(TestServer& server, CoreClient& client)
{
  // Raise the level (not the sink - there is no runtime sink setter): the logger drops sub-Critical
  // entries before they reach the buffering TestLogSink, so nothing accumulates during the loop.
  server.server().set_log_level(LogLevel::Critical);
  client.set_log_level(LogLevel::Critical);
}

uint32_t create_loop_subscription(Session& session)
{
  CreateSubscriptionRequest req;
  req.requested_publishing_interval() = 100.0;
  req.requested_lifetime_count() = 100;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  req.publishing_enabled() = true;
  req.priority() = 0;

  auto resp = session.subscriptions().create_subscription_sync(std::move(req));
  return resp.subscription_id();
}

MonitoredItemCreateResult create_loop_mi(
  Session& session, uint32_t subscriptionId, const NodeId& nodeId, uint32_t clientHandle)
{
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = clientHandle;
  params.sampling_interval() = 100.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subscriptionId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = session.monitored_items().create_monitored_items_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

void delete_loop_mi(Session& session, uint32_t subscriptionId, uint32_t monitoredItemId)
{
  DeleteMonitoredItemsRequest req;
  req.subscription_id() = subscriptionId;
  req.monitored_item_ids().push_back(monitoredItemId);
  auto resp = session.monitored_items().delete_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].is_good());
}

}  // namespace

// ---------------------------------------------------------------------------
// LeakLoop.ChannelOpenClose - open and gracefully close a secure channel N
// times. Exercises client SecureChannelImpl + server SecureChannel +
// ConnectionProtocol + the full TCP transport on each iteration.
// ---------------------------------------------------------------------------
// The channel leak loop churns channels far faster than the default per-IP
// connection rate limit (30/min) allows; left enabled, it trips the throttle
// (the server correctly rejects, the client sees BadTcpInternalError) around
// iteration ~30 instead of measuring memory. Disable throttling for this loop -
// it exercises the channel lifecycle, not the rate limiter (tested elsewhere).
class LeakLoopChannelChurn : public ComplianceBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.connectionThrottling.enabled = false;
  }
};

TEST_F(LeakLoopChannelChurn, LeakLoop_ChannelOpenClose)
{
  silence_logs_for_measurement(mServer, mClient->core());

  auto cycle = [this]()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    (void)channel.try_close_sync();
  };

  expect_stable_heap(cycle, heavyIterations, warmup, toleranceBytes, settle_drain);

  // Exact counts, asserted on EVERY build rather than only under the ASan byte gate. A heap slope
  // says how many bytes; these say which type, which is the difference between a lead and a number.
  settle_drain();
  using namespace ua::diagnostics;
  EXPECT_EQ(InstanceTracker<ServerSecureChannelTag>::live(), 0u)
    << "server SecureChannel objects leaked across the loop";
  EXPECT_EQ(InstanceTracker<ClientSecureChannelTag>::live(), 0u)
    << "client SecureChannelImpl objects leaked across the loop";
}

// ---------------------------------------------------------------------------
// LeakLoop.SessionCreateActivateClose - on one shared channel, create +
// activate + close a session N times. Exercises the server-side Session
// lifecycle and the client SessionImpl.
// ---------------------------------------------------------------------------
TEST_F(ComplianceBase, LeakLoop_SessionCreateActivateClose)
{
  silence_logs_for_measurement(mServer, mClient->core());
  mServer.server().set_log_level(LogLevel::Warning);

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  auto cycle = [&channel]()
  {
    auto session = channel.create_session_sync({.sessionName = "LeakLoopSession"});
    session.activate_sync();
    (void)session.try_close_sync();
  };

  expect_stable_heap(cycle, heavyIterations, warmup, toleranceBytes, settle_drain);

  // Regression pin: every created session object must be destroyed by close +
  // settle. A non-zero count means a reachable reference cycle keeps closed
  // sessions alive (a Class-2 leak LeakSanitizer cannot see). Triage during the
  // investigation showed 0 here - the residual growth is elsewhere, not the
  // session object itself.
  settle_drain();
  using namespace ua::diagnostics;
  EXPECT_EQ(InstanceTracker<ServerSessionTag>::live(), 0u) << "server Session objects leaked across the loop";
  EXPECT_EQ(InstanceTracker<ClientSessionTag>::live(), 0u)
    << "client SessionImpl objects leaked across the loop";

  (void)channel.try_close_sync();
}

// ---------------------------------------------------------------------------
// LeakLoop.SubscriptionCreateDelete - on one activated session, create +
// delete a subscription N times. Exercises the server-side Subscription
// lifecycle.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithSession, LeakLoop_SubscriptionCreateDelete)
{
  silence_logs_for_measurement(mServer, mClient->core());

  auto cycle = [this]()
  {
    auto subscriptionId = create_loop_subscription(*mSession);
    delete_subscription(*mSession, subscriptionId);
  };

  expect_stable_heap(cycle, lightIterations, warmup, toleranceBytes, settle_drain);

  // As above: the type, not the byte count.
  settle_drain();
  EXPECT_EQ(ua::diagnostics::InstanceTracker<ua::diagnostics::ServerMonitoredItemTag>::live(), 0u)
    << "server MonitoredItem objects leaked across the loop";
}

// ---------------------------------------------------------------------------
// LeakLoop.MonitoredItemCreateDelete - on one subscription, create + delete a
// monitored item N times. Exercises the server-side MonitoredItem lifecycle and
// its sampling-group attach/detach.
// ---------------------------------------------------------------------------
TEST_F(ComplianceWithNodes, LeakLoop_MonitoredItemCreateDelete)
{
  silence_logs_for_measurement(mServer, mClient->core());

  auto subscriptionId = create_loop_subscription(*mSession);

  uint32_t clientHandle = 1;
  auto cycle = [this, subscriptionId, &clientHandle]()
  {
    auto result = create_loop_mi(*mSession, subscriptionId, mWritableVariableId, clientHandle++);
    ASSERT_TRUE(result.status_code().is_good()) << "0x" << std::hex << result.status_code().as_uint32();
    delete_loop_mi(*mSession, subscriptionId, static_cast<uint32_t>(result.monitored_item_id()));
  };

  expect_stable_heap(cycle, lightIterations, warmup, toleranceBytes, settle_drain);

  delete_subscription(*mSession, subscriptionId);
}
