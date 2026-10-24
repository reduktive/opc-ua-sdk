// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Client tier-1 ConnectionImpl reconnect integration test (slice R1: reconnect via manual trigger).
///
/// Drives the internal `ua::client::detail::ConnectionImpl` orchestrator with reconnect wiring against
/// a real TestServer over ephemeral TCP. The tier-0 connect (open_channel / create_session / activate)
/// produces an activated Session that is handed to a `ConnectionImpl` built with a `ReconnectWiring`
/// whose channel-reopen interface re-opens a fresh SecureChannel to the same endpoint. A manual
/// `trigger_reconnect_async` exercises the whole reconnect substrate end-to-end (FSM -> host ->
/// tier-0 primitives): the session is rebound onto a fresh channel (Part 4 5.6.2) and wire ops flow
/// again once the connection returns to Active.

#include "compliance_helpers.h"
#include "sanitizer_budget.h"

#include "ua_connection_impl.h"

#include "ua_client_observers.h"
#include "ua_test_server.h"

#include "ua_attribute_id.h"
#include "ua_core_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reconnect_policy.h"
#include "ua_result.h"
#include "ua_server_state.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_session_attribute_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_array.h"
#include "ua_read_response.h"

#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <future>
#include <thread>
#include <utility>

using namespace ua;
using namespace ua::client;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionState;
using ua::client::detail::ReconnectWiring;

using ConnectionImplReconnect = ComplianceBase;

namespace
{

/// Builds a ReadRequest for one node's Value attribute.
ReadRequest make_value_read(const NodeId& node)
{
  ReadRequest request;
  ReadValueId nodeToRead;
  nodeToRead.node_id() = node;
  nodeToRead.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
  request.nodes_to_read().push_back(std::move(nodeToRead));
  request.timestamps_to_return() = TimestampsToReturn::Both;
  return request;
}

/// Runs the bootstrap and blocks until it completes, returning the outcome.
VoidResult start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Issues a Read through the orchestrator and blocks until it completes.
Result<ReadResponse> read_and_wait(ConnectionImpl& connection, ReadRequest request)
{
  std::promise<Result<ReadResponse>> promise;
  auto future = promise.get_future();
  connection.read_async(
    std::move(request), [&promise](Result<ReadResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Closes the orchestrator and blocks until it completes.
VoidResult close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// A reopen interface that PARKS the reconnect's open-channel step (captures its callback without opening) so
/// a test can hold the Connection in `Reconnecting` and exercise the queue-during-reconnect window.
struct ReopenGate
{
  std::mutex mutex;
  std::function<void(Result<SecureChannel>)> heldCallback;  // the parked open-channel completion
  bool hold = true;  // park while true
  std::atomic<int> calls{0};
};

/// A near-zero backoff policy so a retry (if any) fires promptly and the test stays fast.
ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

}  // namespace

// ---------------------------------------------------------------------------
// A manually-triggered reconnect reopens a fresh channel, rebinds the existing
// session onto it, returns the Connection to Active, and wire ops flow again
// (section 8.2A.3 / section 8.3, CL-RECONN happy path).
// ---------------------------------------------------------------------------
// @verifies CL-RECONN-001
// @relation(CL-RECONN-001, scope=function)
TEST_F(ConnectionImplReconnect, ReconnectRestoresActiveAndReadWorks)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_RECONNECT"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // The channel-reopen interface opens a fresh SecureChannel to the same endpoint. The counter proves the
  // reconnect actually ran (reopenChannel is invoked only during a reconnect's open-channel step). It
  // is declared before `connection` so it outlives every reopen callback.
  std::atomic<int> reopenCount{0};

  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, &reopenCount](auto callback)
  {
    ++reopenCount;
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  // Near-zero backoff so a retry (if any) fires promptly and the test stays fast.
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));

  auto startResult = start_and_wait(*connection);
  ASSERT_TRUE(startResult.is_good()) << "bootstrap failed: 0x" << std::hex
                                     << startResult.status_code().as_uint32();
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  // A Read succeeds before the reconnect (baseline).
  {
    auto readResult =
      read_and_wait(*connection, make_value_read(NodeId{VariableId::Server_ServerStatus_State}));
    ASSERT_TRUE(readResult.is_good())
      << "pre-reconnect read failed: 0x" << std::hex << readResult.status_code().as_uint32();
  }

  // Drive a reconnect manually (no real transport drop in R1).
  connection->trigger_reconnect_async();

  // Poll until the reconnect has both reopened a channel (reopenCount >= 1, so a reconnect definitely
  // ran) and returned the Connection to Active. Bounded at ~5s; the thread pool auto-runs the work.
  ConnectionState finalState = ConnectionState::Connecting;
  for (int iteration = 0; iteration < 100; ++iteration)
  {
    finalState = connection->info()->state;
    if (reopenCount.load() >= 1 && finalState == ConnectionState::Active)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  EXPECT_GE(reopenCount.load(), 1) << "a reconnect should have reopened a fresh channel";
  EXPECT_EQ(finalState, ConnectionState::Active) << "the Connection should return to Active";

  // After the reconnect the rebound session serves wire ops again: Read Server_ServerStatus_State and
  // confirm it is Running -> the session was rebound onto the fresh channel and the gate flushed.
  auto readResult =
    read_and_wait(*connection, make_value_read(NodeId{VariableId::Server_ServerStatus_State}));
  ASSERT_TRUE(readResult.is_good()) << "post-reconnect read failed: 0x" << std::hex
                                    << readResult.status_code().as_uint32();
  ASSERT_EQ(readResult.value().results().size(), 1u);
  EXPECT_EQ(readResult.value().results()[0].value().as<std::int32_t>(),
    static_cast<std::int32_t>(ServerState::Running));

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  ASSERT_NE(connection->info(), nullptr);
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// ---------------------------------------------------------------------------
// section 3.1 finding #1: a wire op submitted while the Connection is Reconnecting must be QUEUED in the
// dispatch gate (not fast-failed), and flushed when the reconnect reaches Active (CL-SESS-019/021).
// ---------------------------------------------------------------------------
// Wave F: ReconnectPolicy::perStepTimeout. A reopen interface that is PARKED (never calls back) stalls the
// FSM inside a step, which is precisely what the per-step deadline exists to escape. With the deadline
// short the FSM abandons the step and exhausts its attempt budget quickly; with it long, the same
// scenario takes materially longer. Two distinct values, so a hardcoded deadline cannot pass.
TEST_F(ConnectionImplReconnect, PerStepTimeoutBoundsAStalledReconnectStep)
{
  const auto runWith = [this](std::chrono::milliseconds perStep)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_PERSTEP"});
    session.activate_sync();

    // Park every attempt: capture the callback and never invoke it.
    auto held = std::make_shared<std::vector<std::function<void(Result<SecureChannel>)>>>();
    auto mutex = std::make_shared<std::mutex>();
    ReconnectWiring wiring;
    wiring.reopenChannel = [held, mutex](auto callback)
    {
      std::lock_guard<std::mutex> lock(*mutex);
      held->push_back(std::move(callback));
    };
    wiring.activateConfig = Session::ActivateConfig{};
    auto policy = fast_policy();
    policy.maxAttempts = 2;
    policy.perStepTimeout = perStep;
    wiring.policy = policy;

    auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
      std::move(session),
      ua::client::detail::ConnectionConfig{},
      Logger{},
      std::move(wiring));
    EXPECT_TRUE(start_and_wait(*connection).is_good());

    const auto start = std::chrono::steady_clock::now();
    connection->trigger_reconnect_async();
    for (int i = 0; i < 400 && connection->info()->state != ConnectionState::Failed; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
    }
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    EXPECT_EQ(connection->info()->state, ConnectionState::Failed)
      << "a stalled step must be abandoned by the deadline, not waited on forever";
    (void)close_and_wait(*connection);
    return elapsed;
  };

  const std::int64_t quick = runWith(std::chrono::milliseconds{300});
  const std::int64_t slow = runWith(std::chrono::milliseconds{1500});

  EXPECT_GT(slow, quick) << "a longer per-step deadline must take longer to exhaust the same attempt budget ("
                         << slow << " ms vs " << quick
                         << " ms); equal times would mean the deadline is not what bounds the step";
}

// Wave F: ReconnectPolicy::maxAttempts. A reopen interface that always FAILS lets the FSM run its attempt
// budget to exhaustion, and the interface itself counts the attempts - so the oracle is the observed attempt
// count plus the terminal state, exactly as the matrix row asks.
TEST_F(ConnectionImplReconnect, MaxAttemptsBoundsTheReconnectAttemptCount)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_MAXATT"});
  session.activate_sync();

  auto attempts = std::make_shared<std::atomic<int>>(0);
  ReconnectWiring wiring;
  wiring.reopenChannel = [attempts](auto callback)
  {
    ++*attempts;
    callback(ua::Result<SecureChannel>{ua::StatusCode{ua::Status::BadNotConnected}});  // never recovers
  };
  wiring.activateConfig = Session::ActivateConfig{};
  auto policy = fast_policy();
  policy.maxAttempts = 2;  // default: unset (unbounded paced retries)
  wiring.policy = policy;

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  connection->trigger_reconnect_async();
  for (int i = 0; i < 200 && connection->info()->state != ConnectionState::Failed; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }

  EXPECT_EQ(connection->info()->state, ConnectionState::Failed)
    << "a bounded attempt budget must end in Failed rather than retrying forever";
  EXPECT_LE(attempts->load(), 3)
    << "with maxAttempts=2 the interface must be called a bounded number of times (" << attempts->load()
    << "); unbounded retries against a server that never returns is precisely what the field prevents";
  EXPECT_GE(attempts->load(), 1) << "and at least one attempt must actually have been made";

  (void)close_and_wait(*connection);
}

// Wave F: ConnectionConfig::maxQueueAge - the third of the three queue statuses (`Bad_Timeout`).
// The age is evaluated ON FLUSH, not on a timer: nothing fails for age WHILE the link is still down, then
// the stale op fails on recovery. Boundary values make the stale and fresh arms deterministic without
// racing a fixed sleep against reconnect/authentication latency. Queueing is ON and the limit is high, so
// neither of the other two refusal statuses can occur here. Both arms still traverse a real reconnect and
// flush end to end.
TEST_F(ConnectionImplReconnect, MaxQueueAgeFailsStaleOpsOnFlushOnly)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_QAGE"});
  session.activate_sync();
  auto gate = std::make_shared<ReopenGate>();
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, gate](auto callback)
  {
    ++gate->calls;
    std::lock_guard<std::mutex> lock(gate->mutex);
    if (gate->hold)
    {
      gate->heldCallback = std::move(callback);
      return;
    }
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  ua::client::detail::ConnectionConfig config;
  config.queueOnReconnect = true;
  config.pendingQueueLimit = 64;  // high: eviction cannot be what fails anything here
  config.maxQueueAge = std::chrono::milliseconds{0};  // default 30s; any positive age is stale

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), std::move(config), Logger{}, std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  connection->trigger_reconnect_async();
  for (int i = 0; i < 100 && connection->info()->state != ConnectionState::Reconnecting; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  ASSERT_EQ(connection->info()->state, ConnectionState::Reconnecting);

  // Stale op: once queued, any later flush is past the explicit zero-duration budget.
  std::promise<Result<ReadResponse>> stalePromise;
  auto staleFuture = stalePromise.get_future();
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&stalePromise](Result<ReadResponse> result) { stalePromise.set_value(std::move(result)); });

  EXPECT_EQ(staleFuture.wait_for(std::chrono::milliseconds{200}), std::future_status::timeout)
    << "nothing may fail for AGE while the link is still down - the budget is applied on flush, and an "
       "op failed early would be indistinguishable from a timer-based expiry";

  // Prepare the fresh-entry control; it is submitted on a separately budgeted connection below.
  std::promise<Result<ReadResponse>> freshPromise;
  auto freshFuture = freshPromise.get_future();

  std::function<void(Result<SecureChannel>)> parked;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->hold = false;
    parked = std::move(gate->heldCallback);
  }
  ASSERT_TRUE(parked) << "the reconnect must have been parked for this row to mean anything";
  parked(mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl}));

  ASSERT_EQ(staleFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_EQ(staleFuture.get().status_code().as_status(), Status::BadTimeout)
    << "the stale op must fail on flush with the AGE status, distinct from eviction and fail-fast";
  ASSERT_TRUE(close_and_wait(*connection).is_good());

  auto freshChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto freshSession = freshChannel.create_session_sync({.sessionName = "CONN_IMPL_QAGE_FRESH"});
  freshSession.activate_sync();

  gate = std::make_shared<ReopenGate>();
  wiring = ReconnectWiring{};
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, gate](auto callback)
  {
    ++gate->calls;
    std::lock_guard<std::mutex> lock(gate->mutex);
    if (gate->hold)
    {
      gate->heldCallback = std::move(callback);
      return;
    }
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  config = ua::client::detail::ConnectionConfig{};
  config.queueOnReconnect = true;
  config.pendingQueueLimit = 64;
  config.maxQueueAge = std::chrono::hours{1};

  connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(freshSession), std::move(config), Logger{}, std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  connection->trigger_reconnect_async();
  for (int i = 0; i < 100 && connection->info()->state != ConnectionState::Reconnecting; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  ASSERT_EQ(connection->info()->state, ConnectionState::Reconnecting);

  // One hour exceeds the five-second completion bound below, so a ready result cannot be stale.
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&freshPromise](Result<ReadResponse> result) { freshPromise.set_value(std::move(result)); });
  EXPECT_EQ(freshFuture.wait_for(std::chrono::milliseconds{200}), std::future_status::timeout)
    << "the fresh control must actually queue while the reconnect is parked";

  parked = {};
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->hold = false;
    parked = std::move(gate->heldCallback);
  }
  ASSERT_TRUE(parked) << "the fresh control's reconnect must also be parked";
  parked(mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl}));

  ASSERT_EQ(freshFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  auto freshResult = freshFuture.get();
  EXPECT_TRUE(freshResult.is_good()) << "the fresh op must replay successfully, got status 0x" << std::hex
                                     << freshResult.status_code().as_uint32();
  EXPECT_NE(freshResult.status_code().as_status(), Status::BadTimeout)
    << "the fresh op must replay normally - without this half, a queue that failed EVERYTHING on flush "
       "would satisfy the assertion above";

  (void)close_and_wait(*connection);
}

// Wave F: ConnectionConfig::pendingQueueLimit. With queueing ON and the limit set to 1, a second op
// submitted during the same outage evicts the FIRST - which completes `Bad_ResourceUnavailable` rather
// than being dropped silently. The three statuses in this area are the contract and must stay
// distinguishable: `Bad_ResourceUnavailable` = evicted by the limit, `Bad_SessionNotActivated` = queueing
// disabled, `Bad_Timeout` = aged out. This row asserts the first AND that the survivor is not failed.
TEST_F(ConnectionImplReconnect, PendingQueueLimitEvictsTheOldestQueuedOp)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_QLIMIT"});
  session.activate_sync();
  auto gate = std::make_shared<ReopenGate>();
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, gate](auto callback)
  {
    ++gate->calls;
    std::lock_guard<std::mutex> lock(gate->mutex);
    if (gate->hold)
    {
      gate->heldCallback = std::move(callback);
      return;
    }
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  ua::client::detail::ConnectionConfig config;
  config.queueOnReconnect = true;  // the default: this row is about the LIMIT, not the gate
  config.pendingQueueLimit = 1;  // default 1024

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), std::move(config), Logger{}, std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  connection->trigger_reconnect_async();
  for (int i = 0; i < 100 && connection->info()->state != ConnectionState::Reconnecting; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  ASSERT_EQ(connection->info()->state, ConnectionState::Reconnecting);

  std::promise<Result<ReadResponse>> firstPromise;
  auto firstFuture = firstPromise.get_future();
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&firstPromise](Result<ReadResponse> result) { firstPromise.set_value(std::move(result)); });

  std::promise<Result<ReadResponse>> secondPromise;
  auto secondFuture = secondPromise.get_future();
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&secondPromise](Result<ReadResponse> result) { secondPromise.set_value(std::move(result)); });

  ASSERT_EQ(firstFuture.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "the FIRST op must be evicted by the second and completed now, not held to recovery";
  EXPECT_EQ(firstFuture.get().status_code().as_status(), Status::BadResourceUnavailable)
    << "eviction by the queue limit has its own status, distinct from the fail-fast and aged-out cases";

  EXPECT_EQ(secondFuture.wait_for(std::chrono::milliseconds{300}), std::future_status::timeout)
    << "the SURVIVOR must still be queued - a limit that failed both ops would satisfy the assertion "
       "above while breaking the queue entirely";

  std::function<void(Result<SecureChannel>)> parked;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->hold = false;
    parked = std::move(gate->heldCallback);
  }
  if (parked)
    parked(mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl}));
  (void)secondFuture.wait_for(std::chrono::seconds{5});
  (void)close_and_wait(*connection);
}

// Wave F of the configuration coverage matrix (section 9): ConnectionConfig::queueOnReconnect - the OFF half.
// The test below proves the ON half (default true: the op queues and flushes on recovery). Per section 1 rule
// 5 a gate needs both, and the difference here is not cosmetic: with the flag cleared an op submitted during
// an outage FAILS FAST rather than waiting, which is the behaviour an application opts into when it would
// rather handle the error itself than have latency absorbed invisibly.
//
// Identical setup to the ON test, with the single flag flipped, so the flag is the only variable.
TEST_F(ConnectionImplReconnect, WireOpDuringReconnectFailsFastWhenQueueingDisabled)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_NOQUEUE"});
  session.activate_sync();
  auto gate = std::make_shared<ReopenGate>();
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, gate](auto callback)
  {
    ++gate->calls;
    std::lock_guard<std::mutex> lock(gate->mutex);
    if (gate->hold)
    {
      gate->heldCallback = std::move(callback);
      return;
    }
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  ua::client::detail::ConnectionConfig config;
  config.queueOnReconnect = false;  // default true

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), std::move(config), Logger{}, std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  connection->trigger_reconnect_async();
  for (int i = 0; i < 100 && connection->info()->state != ConnectionState::Reconnecting; ++i)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  ASSERT_EQ(connection->info()->state, ConnectionState::Reconnecting);

  std::promise<Result<ReadResponse>> promise;
  auto future = promise.get_future();
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&promise](Result<ReadResponse> result) { promise.set_value(std::move(result)); });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "with queueing disabled the op must complete immediately rather than waiting for recovery - the "
       "ON test asserts the opposite for the identical scenario";
  auto result = future.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadSessionNotActivated)
    << "and it must fail with the fail-fast status, not some other error";

  // Release the parked reconnect so teardown is clean.
  std::function<void(Result<SecureChannel>)> parked;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->hold = false;
    parked = std::move(gate->heldCallback);
  }
  if (parked)
    parked(mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl}));
  (void)close_and_wait(*connection);
}

TEST_F(ConnectionImplReconnect, WireOpDuringReconnectQueuesAndFlushesOnRecovery)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_QUEUE"});
  session.activate_sync();

  auto gate = std::make_shared<ReopenGate>();
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, gate](auto callback)
  {
    ++gate->calls;
    std::lock_guard<std::mutex> lock(gate->mutex);
    if (gate->hold)
    {
      gate->heldCallback = std::move(callback);  // park the reconnect in the open-channel step
      return;
    }
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  // Reconnecting is published before the reopen wiring runs; wait until it holds the callback.
  connection->trigger_reconnect_async();
  bool reconnectParked = false;
  for (int i = 0; i < 100 && !reconnectParked; ++i)
  {
    if (connection->info()->state == ConnectionState::Reconnecting)
    {
      const std::lock_guard<std::mutex> lock(gate->mutex);
      reconnectParked = static_cast<bool>(gate->heldCallback);
    }
    if (!reconnectParked)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
  }
  ASSERT_EQ(connection->info()->state, ConnectionState::Reconnecting);
  ASSERT_TRUE(reconnectParked);
  ASSERT_GE(gate->calls.load(), 1);

  // A Read submitted during the outage must QUEUE: its future stays not-ready while parked.
  std::promise<Result<ReadResponse>> promise;
  auto future = promise.get_future();
  connection->read_async(make_value_read(NodeId{VariableId::Server_ServerStatus_State}),
    [&promise](Result<ReadResponse> result) { promise.set_value(std::move(result)); });
  EXPECT_EQ(future.wait_for(std::chrono::milliseconds{300}), std::future_status::timeout)
    << "a wire op submitted during reconnect must queue in the gate, not fast-fail";

  // Release: open a real channel and hand it to the parked callback, completing the reconnect.
  std::function<void(Result<SecureChannel>)> parked;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->hold = false;
    parked = std::move(gate->heldCallback);
  }
  ASSERT_TRUE(parked);
  mClient->core().open_channel_async({.endpointUrl = mEndpointUrl}, std::move(parked));

  // The reconnect reaches Active -> the queued Read flushes and completes Good.
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the queued Read should flush once the reconnect reaches Active";
  auto readResult = future.get();
  EXPECT_TRUE(readResult.is_good()) << "flushed Read failed: 0x" << std::hex
                                    << readResult.status_code().as_uint32();

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// section 3.1 finding #5: triggering a reconnect after close has begun must NOT open a fresh channel to the
// server (a late/racing trigger cannot resurrect a closed Connection).
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplReconnect, TriggerReconnectAfterCloseDoesNotReopen)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_TRIGGER_CLOSED"});
  session.activate_sync();

  std::atomic<int> reopenCount{0};
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, &reopenCount](auto callback)
  {
    ++reopenCount;
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  EXPECT_TRUE(close_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Closed);

  connection->trigger_reconnect_async();
  std::this_thread::sleep_for(std::chrono::milliseconds{300});
  EXPECT_EQ(reopenCount.load(), 0) << "a reconnect triggered after close must not reopen a channel";
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// ---------------------------------------------------------------------------
// The NamespaceArray remap notification, fired from the reconnect re-read.
//
// A NodeId encodes a namespace INDEX, not a URI. A client that persisted NodeIds and reconnects to a
// server whose array changed will read and write the WRONG NODES, silently, unless it is told - which is
// what `on_namespace_remap` exists for. `compare_namespace_tables` has unit rows for every case it must
// distinguish, but the one-line call that FIRES it sits on the reconnect re-read path, and nothing drove
// that path with a changed array: these two rows do, over real TCP.
// ---------------------------------------------------------------------------

/// Records every `on_namespace_remap` the Connection fires. The observer runs on the connection strand
/// while the test thread reads it, so it carries its own lock.
class RemapRecorder : public ua::client::ConnectionObserver
{
public:
  void on_namespace_remap(const ua::client::Connection& /*connection*/, std::size_t generation,
    bool sizeChanged, bool indexShifted) override
  {
    const std::lock_guard lock(mMutex);
    mRemaps.push_back(Remap{generation, sizeChanged, indexShifted});
  }

  struct Remap
  {
    std::size_t generation = 0;
    bool sizeChanged = false;
    bool indexShifted = false;
  };

  [[nodiscard]] std::vector<Remap> remaps() const
  {
    const std::lock_guard lock(mMutex);
    return mRemaps;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Remap> mRemaps;
};

/// Polls until @p predicate holds or the bound passes. The reconnect runs on the pool, so every wait here
/// is bounded polling on a thread-safe observable.
template<class Predicate>
bool wait_for(Predicate predicate, std::chrono::milliseconds bound = std::chrono::seconds{10})
{
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }
  return predicate();
}

// @relation(AC-SVR-BASE-047-NAMESPACEARRAY-APPEND-ONLY, scope=function)

// A server that gained a namespace between the bootstrap read and the reconnect re-read must produce a
// remap notification reporting a size change - and NOT an index shift, because an append moves nothing.
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionImplReconnect, ReconnectToAGrownNamespaceArrayFiresRemapWithoutIndexShift)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_NS_APPEND"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  std::atomic<int> reopenCount{0};
  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, &reopenCount](auto callback)
  {
    ++reopenCount;
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));

  auto recorder = std::make_shared<RemapRecorder>();
  connection->set_connection_observer_async(recorder);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);
  ASSERT_TRUE(recorder->remaps().empty())
    << "the bootstrap snapshot is not a remap - there was no previous array to differ from";

  // The server grows its NamespaceArray while the client holds a snapshot of the old one.
  {
    auto addressSpace = mServer.server().address_space();
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:reconnect:appended", {}));
  }

  connection->trigger_reconnect_async();
  ASSERT_TRUE(wait_for([&] { return reopenCount.load() >= 1; })) << "the reconnect must reopen a channel";
  ASSERT_TRUE(wait_for([&] { return connection->info()->state == ConnectionState::Active; }))
    << "the reconnect must return the Connection to Active";

  ASSERT_TRUE(wait_for([&] { return !recorder->remaps().empty(); }))
    << "a NamespaceArray that changed across a reconnect must be reported to the observer";
  const auto remap = recorder->remaps().back();
  EXPECT_TRUE(remap.sizeChanged) << "the array gained an entry";
  EXPECT_FALSE(remap.indexShifted) << "an append moves no existing URI, so no persisted NodeId is stale";
  EXPECT_GT(remap.generation, 0u) << "the re-read publishes a bumped generation";

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// The case that silently corrupts: reconnecting to a server whose array holds the SAME URIs at DIFFERENT
// indices. Every NodeId the application persisted now addresses a different namespace. One server cannot
// produce this - `add_namespace` only appends - so the reconnect targets a SECOND server provisioned with
// the URIs in the opposite order, which is exactly the real case (a peer restarted, or a redundant peer
// that loaded its namespaces in another order).
// @verifies CL-ADDRSP-004
// @relation(CL-ADDRSP-004, scope=function)
TEST_F(ConnectionImplReconnect, ReconnectToAShuffledNamespaceArrayReportsAnIndexShift)
{
  // The first server's own namespaces, in this order.
  {
    auto addressSpace = mServer.server().address_space();
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:reconnect:one", {}));
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:reconnect:two", {}));
  }

  // The second server publishes the same two URIs with their indices SWAPPED.
  ua::test_helpers::TestServer shuffled;
  shuffled.create();
  {
    auto addressSpace = shuffled.server().address_space();
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:reconnect:two", {}));
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:reconnect:one", {}));
  }
  ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  endpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  const auto shuffledListener = shuffled.listen_ephemeral();
  shuffled.add_endpoint(shuffledListener, endpoint);
  shuffled.start();
  const auto shuffledUrls = shuffled.server().advertised_urls(shuffledListener);
  ASSERT_FALSE(shuffledUrls.empty());
  const std::string shuffledUrl = shuffledUrls.front().str();

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_NS_SHUFFLE"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  std::atomic<int> reopenCount{0};
  ReconnectWiring wiring;
  // The reconnect reopens against the OTHER server: the session cannot be rebound there, so the FSM
  // takes its create-session path and re-reads that server's NamespaceArray.
  wiring.reopenChannel = [client = &*mClient, url = shuffledUrl, &reopenCount](auto callback)
  {
    ++reopenCount;
    client->core().open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  wiring.policy = fast_policy();

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));

  auto recorder = std::make_shared<RemapRecorder>();
  connection->set_connection_observer_async(recorder);
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  connection->trigger_reconnect_async();
  ASSERT_TRUE(wait_for([&] { return reopenCount.load() >= 1; }));
  ASSERT_TRUE(wait_for([&] { return connection->info()->state == ConnectionState::Active; }))
    << "the reconnect must reach Active against the second server";

  ASSERT_TRUE(wait_for([&] { return !recorder->remaps().empty(); }))
    << "the array the client holds no longer matches the server it is talking to";
  const auto remap = recorder->remaps().back();
  EXPECT_TRUE(remap.indexShifted)
    << "a URI that moved index is what invalidates every persisted NodeId - this is the flag that "
       "must fire";

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ReconnectPolicy::subscriptionRecovery is NOT covered here. The branch
// (`ua_connection_impl.cpp:6707`) needs BOTH a subscription registered with the managed Connection's
// pipeline (a tier-0 `session.subscriptions().create_subscription_sync` leaves `descriptors` empty, so the
// function early-returns under either policy) AND a reconnect that produces a FRESH session - this
// harness rebinds the existing one, which keeps its subscriptions and needs no transfer. Verified: the
// server counts zero TransferSubscriptions under BOTH policies. See the matrix row.

// Row: BackoffPolicy::factor (configuration coverage matrix section 9).
//
// The growth rate of the retry interval. An interface that always fails lets the FSM run several paced
// retries, and the interface records WHEN each was attempted, so the gaps between attempts are directly
// observable.
//
// ASSERTED AS A RATIO, NEVER AS ABSOLUTE TIMES. Backoff carries jitter and the pool schedules on real
// threads, so absolute deadlines flake; what the field controls is the SHAPE of the sequence. Jitter is
// pinned to 0 and `max` is set high enough not to clamp the growth, otherwise the ceiling - not the factor
// - would decide the third gap.
TEST_F(ConnectionImplReconnect, BackoffFactorGrowsTheRetryInterval)
{
  const auto gapsFor = [this](double factor)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_BACKOFF"});
    session.activate_sync();

    auto stamps = std::make_shared<std::vector<std::chrono::steady_clock::time_point>>();
    auto guard = std::make_shared<std::mutex>();
    ReconnectWiring wiring;
    wiring.reopenChannel = [stamps, guard](auto callback)
    {
      {
        const std::lock_guard<std::mutex> lock(*guard);
        stamps->push_back(std::chrono::steady_clock::now());
      }
      callback(ua::Result<SecureChannel>{ua::StatusCode{ua::Status::BadNotConnected}});  // never recovers
    };
    wiring.activateConfig = Session::ActivateConfig{};

    ReconnectPolicy policy;
    policy.backoff.base = std::chrono::milliseconds{60};
    policy.backoff.max = std::chrono::seconds{10};  // high enough that the factor, not the ceiling, decides
    policy.backoff.jitterPct = 0.0;  // a ratio oracle cannot tolerate jitter
    policy.backoff.factor = factor;
    policy.maxAttempts = 4;
    wiring.policy = policy;

    auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
      std::move(session),
      ua::client::detail::ConnectionConfig{},
      Logger{},
      std::move(wiring));
    EXPECT_TRUE(start_and_wait(*connection).is_good());

    connection->trigger_reconnect_async();
    for (int i = 0; i < 400 && connection->info()->state != ConnectionState::Failed; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
    (void)close_and_wait(*connection);

    const std::lock_guard<std::mutex> lock(*guard);
    std::vector<std::chrono::milliseconds> gaps;
    for (size_t i = 1; i < stamps->size(); ++i)
    {
      gaps.push_back(std::chrono::duration_cast<std::chrono::milliseconds>((*stamps)[i] - (*stamps)[i - 1]));
    }
    return gaps;
  };

  const auto flat = gapsFor(1.0);  // non-default: a constant retry interval
  const auto growing = gapsFor(3.0);  // non-default: aggressive growth

  ASSERT_GE(flat.size(), 2u) << "the interface must be retried enough times to measure a gap sequence";
  ASSERT_GE(growing.size(), 2u);

  // factor 1.0 keeps every gap at `base`; factor 3.0 triples it each time. Comparing the LAST gap to the
  // FIRST is what distinguishes them - both start at `base`, so a first-gap comparison would show nothing.
  EXPECT_LT(flat.back().count(), flat.front().count() * 2)
    << "with factor 1.0 the interval must not grow (first=" << flat.front().count()
    << "ms last=" << flat.back().count() << "ms)";
  // The ratio must match the CONFIGURED factor, not merely be greater than one. Three attempts under
  // factor 3.0 give 60/180/540 - a last:first ratio of 9 - where the compiled-in default of 2.0 gives
  // 60/120/240, a ratio of 4. Asserting only "it grows" cannot tell those apart, and a mutation replacing
  // the configured factor with the default passes such a test unchanged.
  EXPECT_GE(growing.back().count(), growing.front().count() * 6)
    << "with factor 3.0 the interval must grow by roughly factor^2 across three attempts (first="
    << growing.front().count() << "ms last=" << growing.back().count()
    << "ms); the compiled-in default of 2.0 would yield only ~4x";
}

// Row: ReconnectPolicy::shutdownBackoffMultiplier (configuration coverage matrix section 9).
//
// When the reconnect was caused by a server-announced SHUTDOWN, the retry spacing is widened by this
// multiplier - a client should not hammer a server that has told it to go away. The multiplier applies
// ONLY to that cause (`ua_reconnection_fsm.cpp:536`), so the row must produce a genuine ServerShutdown
// cause rather than the synthetic TransportDropped that `trigger_reconnect_async` hardcodes. It is driven
// the way a real client meets it: the server shuts down, and the keep-alive poll observes
// `ServerStatus.State == Shutdown`.
//
// SPLIT ACROSS TWO TESTS ON PURPOSE. Each probe shuts its server down, so a second probe in the same test
// has nothing left to connect to; gtest builds a fresh fixture - and a fresh server - per test.
class ConnectionImplShutdownBackoff : public ConnectionImplReconnect
{
protected:
  // Gaps between paced retries after a server-announced shutdown, under @p multiplier.
  std::vector<std::chrono::milliseconds> shutdown_retry_gaps(std::size_t multiplier)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_SHUTBACKOFF"});
    session.activate_sync();

    auto stamps = std::make_shared<std::vector<std::chrono::steady_clock::time_point>>();
    auto guard = std::make_shared<std::mutex>();
    ReconnectWiring wiring;
    wiring.reopenChannel = [stamps, guard](auto callback)
    {
      {
        const std::lock_guard<std::mutex> lock(*guard);
        stamps->push_back(std::chrono::steady_clock::now());
      }
      callback(ua::Result<SecureChannel>{ua::StatusCode{ua::Status::BadNotConnected}});
    };
    wiring.activateConfig = Session::ActivateConfig{};

    ReconnectPolicy policy;
    policy.backoff.base = std::chrono::milliseconds{40};
    policy.backoff.max = std::chrono::seconds{10};
    policy.backoff.jitterPct = 0.0;
    policy.backoff.factor = 1.0;  // flat, so the multiplier is the ONLY thing shaping the gaps
    policy.maxAttempts = 4;
    policy.shutdownBackoffMultiplier = multiplier;
    wiring.policy = policy;
    wiring.keepAlive =
      KeepAlivePolicy{.interval = std::chrono::milliseconds{200}, .missedBeforeReconnect = 1};

    auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
      std::move(session),
      ua::client::detail::ConnectionConfig{},
      Logger{},
      std::move(wiring));
    EXPECT_TRUE(start_and_wait(*connection).is_good());

    // A real server-announced shutdown: ServerStatus.State reads Shutdown while the session is still
    // usable, which is what lets the keep-alive poll classify the cause.
    mServer.server().shutdown_async({}, [](ua::VoidResult) {});

    for (int i = 0; i < 400 && connection->info()->state != ConnectionState::Failed; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
    (void)close_and_wait(*connection);

    const std::lock_guard<std::mutex> lock(*guard);
    std::vector<std::chrono::milliseconds> gaps;
    for (size_t i = 1; i < stamps->size(); ++i)
    {
      gaps.push_back(std::chrono::duration_cast<std::chrono::milliseconds>((*stamps)[i] - (*stamps)[i - 1]));
    }
    return gaps;
  }
};

// The control half: a multiplier of 1 disables the widening, so pacing stays at `base`.
TEST_F(ConnectionImplShutdownBackoff, MultiplierOfOneLeavesThePacingAtTheBaseInterval)
{
  const auto gaps = shutdown_retry_gaps(1);
  ASSERT_FALSE(gaps.empty()) << "the interface must be retried at least twice to measure a gap";
  EXPECT_LT(gaps.front().count(), 120)
    << "multiplier 1 must not widen the pacing (" << gaps.front().count() << "ms)";
}

// DEFAULT (4): the same shutdown paces at roughly 160 ms, so the threshold below is what makes the row
// falsifiable against the compiled-in value rather than merely asserting "it got slower".
TEST_F(ConnectionImplShutdownBackoff, MultiplierWidensThePacingBeyondTheDefault)
{
  const auto gaps = shutdown_retry_gaps(8);
  ASSERT_FALSE(gaps.empty()) << "the interface must be retried at least twice to measure a gap";
  EXPECT_GT(gaps.front().count(), 220)
    << "multiplier 8 must widen pacing well past the default of 4 (" << gaps.front().count()
    << "ms); a client using the compiled-in 4 would pace at roughly 160 ms";
}

// ---------------------------------------------------------------------------
// Row: ReconnectPolicy::subscriptionRecovery - unblocked by the session-recreating reconnect interface below.
//
// TWO PRECONDITIONS defeated the first attempt at this row, and the interface exists to satisfy both:
//
//  1. The subscription must be registered with the MANAGED Connection's pipeline. A tier-0
//     `session.subscriptions().create_subscription_sync` leaves `descriptors` empty at
//     `ua_connection_impl.cpp:6694`, so recovery early-returns under either policy. The row therefore
//     creates its subscription through `ConnectionImpl::create_subscription_managed_async`.
//  2. The reconnect must produce a FRESH session. Recovery is the session-CHANGED path; a reconnect that
//     rebinds the existing session keeps its subscriptions and transfers nothing.
//     `ua_reconnection_fsm.cpp:375` recreates only when re-activation returns Bad_SessionIdInvalid /
//     Bad_SessionClosed / Bad_InvalidState.
//
// The interface drives (2) the way a real outage does rather than by injecting a status: the server is given
// a short session timeout, and the reopen is PARKED for longer than that, so the server reaps the session
// while the client is disconnected. Re-activation then legitimately fails and the FSM creates a new one.
class ConnectionImplSessionRecreatingReconnect : public ComplianceSecured
{
protected:
  void SetUp() override
  {
    ComplianceSecured::SetUp();
    set_authentication_claims({{"diagnostics:full", "1"}});
  }

  // A server that reaps idle sessions quickly, so a parked reconnect outlives its own session.
  //
  // Every duration in this fixture is scaled together - these two, the session the subject requests,
  // and the outage that has to outlive it - so the relationship the test depends on holds in an
  // instrumented build, where connecting at all can take longer than an unscaled 2 s timeout.
  void configure_secured_server(ua::ApplicationConfig& appCfg) override
  {
    appCfg.stack_limits().sessionMinimumTimeout = ua::test_utils::scaled(std::chrono::milliseconds{1000});
    appCfg.stack_limits().sessionMaximumTimeout = ua::test_utils::scaled(std::chrono::milliseconds{2000});
  }

  CoreClient::OpenChannelConfig secured_channel_config() const
  {
    CoreClient::OpenChannelConfig config;
    config.endpointUrl = mEndpointUrl;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerCert;
    return config;
  }

  // Server-side count of TransferSubscriptions calls, summed across live sessions.
  //
  // Opens a FRESH session per read. A long-lived reader cannot be used here: this fixture deliberately
  // gives the server a 2 s session timeout so the subject can be reaped during the parked reconnect, and
  // that timeout reaps an idle reader too - its next read then throws BadSessionClosed and the row fails
  // for a reason that has nothing to do with the field.
  std::uint32_t server_transfer_count()
  {
    auto channel = mClient->core().open_channel_sync(secured_channel_config());
    auto session = channel.create_session_sync({.sessionName = "RECOVERY_READER"});
    session.activate_sync();
    auto read = session.attributes().try_read_sync(make_value_read(
      NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray}));

    const auto closeReader = [&]
    {
      (void)session.try_close_sync();
      (void)channel.try_close_sync();
    };

    if (read.is_bad())
    {
      ADD_FAILURE() << "SessionDiagnosticsArray service read failed: " << to_string(read.status_code());
      closeReader();
      return 0;
    }
    if (read.value().results().size() != 1U)
    {
      ADD_FAILURE() << "SessionDiagnosticsArray read returned " << read.value().results().size()
                    << " results instead of one";
      closeReader();
      return 0;
    }

    const auto& dataValue = read.value().results()[0];
    if (dataValue.status().has_value() && dataValue.status()->is_bad())
    {
      ADD_FAILURE() << "SessionDiagnosticsArray item read failed: " << to_string(*dataValue.status());
      closeReader();
      return 0;
    }
    if (!dataValue.value().is_array_of_structure())
    {
      ADD_FAILURE() << "SessionDiagnosticsArray did not contain an array of structures";
      closeReader();
      return 0;
    }

    std::uint32_t total = 0;
    for (const auto& entry : dataValue.value().as<Array<RefStructure<Structure>>>().payload())
    {
      if (const auto* diag = dynamic_cast<const SessionDiagnosticsDataType*>(entry.get()))
        total += diag->transfer_subscriptions_count().total_count();
    }
    closeReader();
    return total;
  }

  // Drives one SESSION-RECREATING reconnect under @p recovery; returns how many TransferSubscriptions the
  // SERVER saw during it.
  std::uint32_t transfers_during_session_recreate(
    ua::client::SubscriptionRecovery recovery, ua::client::detail::ObserverSlots observers = {})
  {
    auto channel = mClient->core().open_channel_sync(secured_channel_config());
    auto session = channel.create_session_sync(
      {.requestedSessionTimeout = ua::test_utils::scaled(std::chrono::milliseconds{2000}),
        .sessionName = "RECOVERY_SUBJECT"});
    session.activate_sync();

    auto gate = std::make_shared<ReopenGate>();
    ReconnectWiring wiring;
    wiring.reopenChannel = [client = &*mClient, url = mEndpointUrl, serverCertificate = mServerCert, gate](
                             auto callback)
    {
      ++gate->calls;
      const std::lock_guard<std::mutex> lock(gate->mutex);
      if (gate->hold)
      {
        gate->heldCallback = std::move(callback);  // park: the client stays disconnected
        return;
      }
      CoreClient::OpenChannelConfig config;
      config.endpointUrl = url;
      config.securityMode = MessageSecurityMode::SignAndEncrypt;
      config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      config.serverCertificate = serverCertificate;
      client->core().open_channel_async(std::move(config), std::move(callback));
    };
    wiring.activateConfig = Session::ActivateConfig{};
    auto policy = fast_policy();
    policy.subscriptionRecovery = recovery;
    wiring.policy = policy;

    ua::client::detail::ConnectionConfig connectionConfig;
    connectionConfig.observers = std::move(observers);
    auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
      std::move(session),
      std::move(connectionConfig),
      Logger{},
      std::move(wiring));
    EXPECT_TRUE(start_and_wait(*connection).is_good());

    // Precondition 1: a subscription the PIPELINE knows about.
    std::promise<bool> created;
    auto createdFuture = created.get_future();
    // Scaled with the outage below, not left at 500ms. The server grants lifetime = interval x
    // lifetimeCount = 500ms x 30 = 15s, and the outage has to outlive the SESSION timeout without
    // outliving the SUBSCRIPTION - otherwise the Subscription is gone before the transfer reaches
    // it, the transfer rightly fails, and the client rightly recreates instead. Scaling the outage
    // alone broke that relationship under a sanitizer; scaling this with it keeps the same ratio.
    connection->create_subscription_managed_async(ua::test_utils::scaled_ms(500.0),
      /*publishingEnabled=*/true,
      [&created](ua::Result<ua::client::detail::SubscriptionCreated> result)
      { created.set_value(result.is_good()); });
    EXPECT_EQ(createdFuture.wait_for(ua::test_utils::scaled(std::chrono::milliseconds{10000})),
      std::future_status::ready);
    EXPECT_TRUE(createdFuture.get()) << "the managed subscription is the precondition for recovery";

    const auto before = server_transfer_count();

    // Precondition 2: park the reopen for longer than the session timeout, so the server reaps the
    // session while the client is away and re-activation must fail.
    connection->trigger_reconnect_async();
    for (int i = 0; i < 100 * ua::test_utils::sanitizer_slowdown() && gate->calls.load() == 0; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // Outlive the session timeout so the SUBJECT session is reaped - while keeping the READER alive.
    // The short timeout applies to every session on this server, so an idle reader is reaped alongside the
    // subject and its diagnostics read then throws BadSessionClosed. Polling it is the point: the outage
    // must be selective, affecting only the connection under test.
    std::this_thread::sleep_for(ua::test_utils::scaled(std::chrono::milliseconds{3000}));

    {
      const std::lock_guard<std::mutex> lock(gate->mutex);
      gate->hold = false;
    }
    // Release the parked attempt; subsequent attempts open for real.
    std::function<void(Result<SecureChannel>)> held;
    {
      const std::lock_guard<std::mutex> lock(gate->mutex);
      held.swap(gate->heldCallback);
    }
    if (held)
    {
      held(ua::Result<SecureChannel>{ua::StatusCode{ua::Status::BadNotConnected}});
    }

    for (int i = 0; i < 200 * ua::test_utils::sanitizer_slowdown() &&
                    connection->info()->state != ConnectionState::Active;
         ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{50});

    const auto after = server_transfer_count();
    (void)close_and_wait(*connection);
    return after - before;
  }
};

// DEFAULT (TransferThenRecreate): the client attempts a transfer onto the fresh session first.
TEST_F(ConnectionImplSessionRecreatingReconnect, RecreateOnlySkipsTheTransferAttempt)
{
  EXPECT_GT(transfers_during_session_recreate(ua::client::SubscriptionRecovery::TransferThenRecreate), 0u)
    << "the default policy must attempt a TransferSubscriptions onto the recreated session - without this "
       "half the zero below would pass against a reconnect that never recovered subscriptions at all";

  EXPECT_EQ(transfers_during_session_recreate(ua::client::SubscriptionRecovery::RecreateOnly), 0u)
    << "RecreateOnly must skip the transfer and recreate directly";
}

namespace
{

// Records the reconnect-lifecycle notifications an application can only learn from the SDK.
struct RecoveryObserverCapture
{
  std::atomic<int> sessionCreated{0};
  std::atomic<int> sessionRecreated{0};
  std::atomic<int> subscriptionRecreated{0};
  std::atomic<int> subscriptionTransferred{0};
  std::atomic<ua::IntegerId> recreatedOldId{0};
  std::atomic<ua::IntegerId> recreatedNewId{0};
};

class CapturingConnectionObserver : public ua::client::ConnectionObserver
{
public:
  explicit CapturingConnectionObserver(std::shared_ptr<RecoveryObserverCapture> capture)
    : mCapture(std::move(capture))
  {}

  void on_session_created(const ua::client::Connection&, ua::NodeId) override
  {
    ++mCapture->sessionCreated;
  }

  void on_session_recreated(const ua::client::Connection&, ua::NodeId, ua::NodeId) override
  {
    ++mCapture->sessionRecreated;
  }

private:
  std::shared_ptr<RecoveryObserverCapture> mCapture;
};

class CapturingSubscriptionObserver : public ua::client::SubscriptionObserver
{
public:
  explicit CapturingSubscriptionObserver(std::shared_ptr<RecoveryObserverCapture> capture)
    : mCapture(std::move(capture))
  {}

  void on_subscription_recreated(ua::IntegerId oldId, ua::IntegerId newId) override
  {
    mCapture->recreatedOldId.store(oldId);
    mCapture->recreatedNewId.store(newId);
    ++mCapture->subscriptionRecreated;
  }

  void on_subscription_transferred(ua::IntegerId) override
  {
    ++mCapture->subscriptionTransferred;
  }

private:
  std::shared_ptr<RecoveryObserverCapture> mCapture;
};

}  // namespace

// The reconnect-lifecycle observers report facts an application has no other way to learn: that its
// Session was replaced, and that its Subscription came back under a new id. Both were documented and
// unfireable - the sink fanned them out correctly and no production code ever called it.
//
// RecreateOnly is used so the outcome is unambiguous: the transfer is skipped, so a recovered
// subscription can only have been recreated.
TEST_F(ConnectionImplSessionRecreatingReconnect, SessionAndSubscriptionRecreationAreReportedToObservers)
{
  auto capture = std::make_shared<RecoveryObserverCapture>();
  auto connectionObserver = std::make_shared<CapturingConnectionObserver>(capture);
  auto subscriptionObserver = std::make_shared<CapturingSubscriptionObserver>(capture);

  ua::client::detail::ObserverSlots slots;
  slots.connection = connectionObserver;
  slots.subscription = subscriptionObserver;

  EXPECT_EQ(transfers_during_session_recreate(ua::client::SubscriptionRecovery::RecreateOnly, slots), 0u)
    << "RecreateOnly must skip the transfer, so recovery can only be a recreate";

  EXPECT_GE(capture->sessionCreated.load(), 1)
    << "the Session the Connection was handed must be reported once the observers are resolved";
  EXPECT_GE(capture->sessionRecreated.load(), 1)
    << "a reconnect that created a FRESH Session must report it - the whole point of the callback";
  EXPECT_GE(capture->subscriptionRecreated.load(), 1)
    << "the subscription came back under a new id and the application must be told";
  EXPECT_NE(capture->recreatedOldId.load(), capture->recreatedNewId.load())
    << "a recreate yields a DIFFERENT server-side id; equal ids would mean the pair is not real";
  EXPECT_EQ(capture->subscriptionTransferred.load(), 0)
    << "RecreateOnly must not report a transfer that never happened";
}

// The transfer arm of the same barrier. A Subscription is not tied to its Session's lifetime
// (OPC 10000-4 5.13), so one whose Session was reaped can still be adopted by the fresh Session -
// and when TransferSubscriptions succeeds the Subscription keeps its id and its sequence counter,
// which is materially different from being recreated. The application is told which happened.
TEST_F(ConnectionImplSessionRecreatingReconnect, SubscriptionTransferIsReportedWhenTheTransferSucceeds)
{
  auto capture = std::make_shared<RecoveryObserverCapture>();
  ua::client::detail::ObserverSlots slots;
  slots.connection = std::make_shared<CapturingConnectionObserver>(capture);
  slots.subscription = std::make_shared<CapturingSubscriptionObserver>(capture);

  EXPECT_GT(
    transfers_during_session_recreate(ua::client::SubscriptionRecovery::TransferThenRecreate, slots), 0u)
    << "the default policy must attempt the transfer";

  // The authenticated requesting channel satisfies Part 4 5.13.7.1, so this arm must transfer rather
  // than fall back to recreation. The barrier still settles the Subscription exactly once.
  const int transferred = capture->subscriptionTransferred.load();
  const int recreated = capture->subscriptionRecreated.load();
  EXPECT_EQ(transferred, 1) << "the secured same-client transfer must be reported exactly once";
  EXPECT_EQ(recreated, 0) << "a successful transfer must not be reported as a recreation";
}
