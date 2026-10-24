// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the ConnectionImpl <-> RedundancyManager wiring (client design section 8.11, Slice
// W4/10e-wire phases P0-P4): the eager-construct/write-once ownership (F3/J44), the null-safe single-shot
// handle, the REAL failover-reconnect trigger (P3: stash the completion, fire it from the terminal drives),
// the P4 close-order oracle (section 8.11.3: manager closed BEFORE the FSM is cancelled), and the ONE
// intentional manager->host strong-cycle exception broken by an explicit manager close even after the
// orchestrator is gone.
//
// Driven over a REAL ConnectionImpl built with the injecting create_with_ops factory (which is always
// reconnect-wired, so the manager is eagerly constructed) over the fake tier-0 interface. The single-shot /
// no-manager path is reached through the public Connection facade with a null pimpl (the moved-from handle
// the design points to), which returns the same null-wrapped RedundancyManager. Delivery is driven on a
// plain io_context (pump()); there are NO real timers.
//
// P3/P4 primary observable: the STASHED failover-reconnect completion. `trigger_reconnect_async` (via the
// host) parks the completion in the orchestrator's strand-only mRedundancyReconnectPending (in this fixture
// the FSM is never started, so its trigger() is an inert no-op) and it is fired ONLY from the terminal
// drives - reconnect-Active (Good), reconnect-failed (Bad + trigger.failed), a second trigger (prior fired
// Good), and begin_close (Bad + trigger.closing). The close-order probe records "manager_close" strictly
// before "fsm_cancel" (F5, the falsifiable section 8.11.3 ordering oracle).
//
// Falsifiability: each test asserts a concrete observable - the eagerly-constructed manager/host are
// non-null and Dormant, the null handle degrades to empty info / Bad_ConnectionClosed / Good-close, the
// stashed completion is NOT fired inline yet fires exactly once (Good / Bad with the exact source tag) from
// each terminal drive, close closes the manager before the FSM, first-reach-Active drives the manager out
// of Dormant into Discovering, and the manager close completes Good with the orchestrator already destroyed.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_reconnect_policy.h"
#include "ua_reconnect_types.h"
#include "ua_redundancy_manager.h"
#include "ua_redundancy_manager_connection_host.h"
#include "ua_redundancy_manager_impl.h"
#include "ua_status.h"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::ReconnectCause;
using ua::client::RedundancyManager;
using ua::client::RedundancyManagerState;
using ua::client::Session;
using ua::client::TransportDropped;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::KeepAlivePolicy;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

class ConnectionRedundancyWiringTest : public ::testing::Test
{
protected:
  boost::asio::io_context mCtx;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();

  void pump()
  {
    mCtx.run();
    mCtx.restart();
  }

  std::shared_ptr<ConnectionImpl> make_connection()
  {
    return TA::create_with_ops(mCtx.get_executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      KeepAlivePolicy{std::chrono::milliseconds{0}},
      /*clientObserverDefaults=*/{},
      /*enableRedundancy=*/true);
  }

  // Kicks the host failover-reconnect trigger so a completion is STASHED in the orchestrator's strand-only
  // mRedundancyReconnectPending, awaiting a terminal drive. In this fixture the FSM is never started (no
  // start_async), so the trigger's mReconnectFsm->trigger() call is an inert no-op that leaves the stashed
  // completion parked; pump() therefore settles without firing it. `captured` receives the completion when a
  // later terminal drive fires it. The connection is Connecting (non-terminal) + reconnect-wired, so the
  // trigger takes the stash path (not the single-shot / terminal unavailable path).
  void stash_pending_via_trigger(ConnectionImpl& connection, std::optional<VoidResult>& captured)
  {
    auto host = TA::redundancy_host(connection);
    ASSERT_NE(host, nullptr);
    host->trigger_reconnect_async(ReconnectCause{TransportDropped{}},
      StatusCode{Status::BadNoCommunication},
      nullptr,
      [&captured](VoidResult result) { captured = std::move(result); });
    pump();
  }
};

// A reconnect-wired Connection eagerly constructs BOTH the tier-1 host shim and the own-strand manager
// (write-once, before `self` is published), and the manager starts Dormant until the first session-active.
TEST_F(ConnectionRedundancyWiringTest, ReconnectWiredEagerlyConstructsManager)
{
  auto connection = make_connection();

  EXPECT_NE(TA::redundancy_manager(*connection), nullptr)
    << "manager eagerly constructed on a wired Connection";
  EXPECT_NE(TA::redundancy_host(*connection), nullptr) << "host eagerly constructed on a wired Connection";

  // Through ConnectionImpl, not Connection: the public `Connection::redundancy()` accessor was
  // withdrawn with the rest of the client redundancy surface (client_design.md section 8.11.10). The facade
  // itself is unchanged and still reached internally, so this arm keeps its coverage.
  const auto info = connection->redundancy().redundancy_info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, RedundancyManagerState::Dormant)
    << "the eagerly-constructed manager starts Dormant (on_first_session_active drives it later)";
}

// The J49 opt-in DEFAULT (enableRedundancy=false): a reconnect-wired Connection builds NO redundancy engine,
// pays no per-connection discovery/monitor overhead, and Connection::redundancy() hands back the null-safe
// handle. This is the production default until an application explicitly asks for failover.
TEST_F(ConnectionRedundancyWiringTest, ReconnectWiredWithRedundancyDisabledHasNoManager)
{
  auto connection = TA::create_with_ops(mCtx.get_executor(),
    mSession,
    ConnectionConfig{},
    ua::Logger{},
    mReopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    KeepAlivePolicy{std::chrono::milliseconds{0}});
  // enableRedundancy defaults false -> no engine is constructed even though the Connection is
  // reconnect-wired.

  EXPECT_EQ(TA::redundancy_manager(*connection), nullptr)
    << "redundancy disabled: no own-strand manager is constructed (J49 opt-in default)";
  EXPECT_EQ(TA::redundancy_host(*connection), nullptr) << "redundancy disabled: no host shim is constructed";

  const auto info = connection->redundancy().redundancy_info();
  ASSERT_NE(info, nullptr) << "the null-wrapped facade still hands back a default RedundancyInfo";
  EXPECT_EQ(info->state, RedundancyManagerState::Dormant);
  EXPECT_TRUE(info->candidates.empty());
}

// A handle with no ConnectionImpl (the moved-from / single-shot path: no manager) returns a null-wrapped
// RedundancyManager whose facade is already null-safe - empty info, Bad_ConnectionClosed on force_switch,
// Good on close.
TEST_F(ConnectionRedundancyWiringTest, SingleShotRedundancyReturnsNullSafeHandle)
{
  // `Connection::redundancy()` wrapped a null impl for the moved-from case; with that accessor
  // withdrawn, the null-safety it relied on is pinned directly on the factory it called.
  RedundancyManager manager = ua::client::detail::RedundancyManagerFactory::wrap(nullptr);

  const auto info = manager.redundancy_info();
  ASSERT_NE(info, nullptr) << "the null facade hands back a default (non-null) RedundancyInfo, not nullptr";
  EXPECT_EQ(info->state, RedundancyManagerState::Dormant);
  EXPECT_TRUE(info->candidates.empty());

  std::optional<VoidResult> forceResult;
  manager.force_switch_async("urn:server:x", [&forceResult](VoidResult result) { forceResult = result; });
  ASSERT_TRUE(forceResult.has_value()) << "the null facade fires inline (no live strand)";
  EXPECT_EQ(forceResult->status_code().as_status(), Status::BadConnectionClosed);

  std::optional<VoidResult> closeResult;
  manager.close_async([&closeResult](VoidResult result) { closeResult = result; });
  ASSERT_TRUE(closeResult.has_value());
  EXPECT_TRUE(closeResult->is_good()) << "closing a null handle is a Good idempotent no-op";
}

// P3: the host's trigger_reconnect_async forwards to ConnectionImpl::trigger_redundancy_reconnect_async,
// which (non-terminal, reconnect-wired) STASHES the completion in mRedundancyReconnectPending and kicks the
// FSM - it does NOT complete inline. The stashed completion is fired only from a terminal drive, so after a
// pump it is still empty. Falsifiable: the deleted P2 stub would have fired Bad_NotImplemented here.
TEST_F(ConnectionRedundancyWiringTest, TriggerRedundancyReconnectStashesCompletionNotFiredInline)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  std::optional<VoidResult> captured;
  host->trigger_reconnect_async(ReconnectCause{TransportDropped{}},
    StatusCode{Status::BadNoCommunication},
    nullptr,
    [&captured](VoidResult result) { captured = std::move(result); });
  pump();

  EXPECT_FALSE(captured.has_value())
    << "the failover-reconnect completion is STASHED awaiting the FSM outcome, not fired inline";
}

// P3: the FSM reached Active again -> reconnect_notify_active fires the stashed completion Good (the manager
// reads this as its own failover succeeding) AND drives the manager's on_reconnect_completed hook. The latter
// is asserted observably: a Dormant manager re-runs discovery on reconnect-completed, so with the discovery
// Read parked at the held session interface it leaves Dormant and sits in Discovering - proving the F6 drive
// actually ran (not merely that the stashed completion fired).
TEST_F(ConnectionRedundancyWiringTest, ReconnectActiveFiresStashedCompletionGood)
{
  auto connection = make_connection();
  std::optional<VoidResult> captured;
  stash_pending_via_trigger(*connection, captured);
  ASSERT_FALSE(captured.has_value()) << "still parked before the terminal drive";

  auto manager = TA::redundancy_manager(*connection);
  ASSERT_NE(manager, nullptr);
  ASSERT_EQ(manager->redundancy_info()->state, RedundancyManagerState::Dormant)
    << "the manager is Dormant before the reconnect-completed drive";

  // Park every Read at the session interface so the manager's reconnect-completed-driven discovery Read stays
  // pending, leaving the manager in a stable, observable Discovering state.
  mSession->read.set_hold(true);

  TA::reconnect_notify_active(*connection);
  pump();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good()) << "reach-Active fires the pending failover-reconnect completion Good";

  // F6: reconnect_notify_active drove on_reconnect_completed_async on the manager -> a Dormant manager
  // re-runs discovery, so it transitioned out of Dormant into Discovering (its RedundancySupport Read is
  // parked).
  const auto info = manager->redundancy_info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, RedundancyManagerState::Discovering)
    << "reconnect_notify_active drove the manager's on_reconnect_completed hook (Dormant -> Discovering)";
}

// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST_F(ConnectionRedundancyWiringTest, ReconnectActiveColdCauseRoutesConditionRefreshToAlarmTracker)
{
  auto connection = make_connection();
  // Script the backbone's server-assigned id to a value the fake would never hand back on its own, so the
  // assertion below cannot pass on a default that happens to coincide with the right answer.
  constexpr std::uint32_t backboneSubscriptionId = 71;
  ua::CreateSubscriptionResponse createResponse;
  createResponse.subscription_id() = backboneSubscriptionId;
  mSession->createSubscription.set_result(
    ua::Result<ua::CreateSubscriptionResponse>{std::move(createResponse)});

  // Park Publish. A live subscription keeps a Publish outstanding at all times, so an unheld fake would
  // answer and re-issue forever and pump() (which runs until the io_context has no work) would never return.
  mSession->publish.set_hold(true);

  // Drive the connection Active BEFORE attaching the tracker, so its event backbone is really created and
  // the tracker really holds the backbone's SubscriptionId. Without that this test can only observe a
  // refresh issued with no subscription behind it - which is the shape a conforming server rejects, so it
  // would prove the routing by asserting a request that cannot work.
  TA::reconnect_notify_active(*connection);
  pump();

  Connection handle = ConnectionHandleFactory::make_connection(connection);
  auto alarms = handle.alarms();
  pump();
  ASSERT_GE(mSession->createSubscription.call_count(), 1U)
    << "the tracker's event backbone must exist before a ConditionRefresh can name it";
  ASSERT_EQ(mSession->call.call_count(), 0U);

  ua::client::ReconnectOutcome outcome;
  outcome.cause = ua::client::ReconnectCause{
    ua::client::RedundancySwitchInfo{ua::RedundancySupport::Cold, "opc.tcp://former", "opc.tcp://active"}};
  TA::reconnect_notify_active(*connection, std::move(outcome));
  pump();

  ASSERT_EQ(mSession->call.call_count(), 1U)
    << "the Connection recovered-cause boundary must reach the tier-2 tracker";
  const auto requests = mSession->call.requests();
  ASSERT_EQ(requests.size(), 1U);
  ASSERT_EQ(requests.front().methods_to_call().size(), 1U);
  const auto& method = requests.front().methods_to_call()[0];
  EXPECT_EQ(
    method.method_id(), ua::NodeId{static_cast<std::uint32_t>(ua::MethodId::ConditionType_ConditionRefresh)});
  // OPC 10000-9 Table 20: the one Mandatory input argument, and it must be the id of the subscription the
  // tracker's own backbone is monitored on - a refresh delivered anywhere else replays past the tracker.
  ASSERT_EQ(method.input_arguments().size(), 1U)
    << "ConditionRefresh([in] IntegerId SubscriptionId) takes one Mandatory argument";
  const auto argument = method.input_arguments()[0].to<std::uint32_t>();
  ASSERT_TRUE(argument.is_good()) << "the argument is an IntegerId";
  EXPECT_EQ(argument.value(), backboneSubscriptionId)
    << "ConditionRefresh must identify the recovered event backbone Subscription";
}

// P3: the reconnect gave up -> reconnect_notify_failed drives on_transport_fatal FIRST, then fires the
// stashed completion Bad with the terminal status and the trigger.failed source tag.
TEST_F(ConnectionRedundancyWiringTest, ReconnectFailedFiresStashedCompletionBad)
{
  auto connection = make_connection();
  std::optional<VoidResult> captured;
  stash_pending_via_trigger(*connection, captured);
  ASSERT_FALSE(captured.has_value()) << "still parked before the terminal drive";

  const std::shared_ptr<const ua::ErrorDetail> someChain =
    ua::make_error_detail("TransportFatal", "the transport dropped fatally", "test.transport.fatal");
  TA::reconnect_notify_failed(*connection, StatusCode{Status::BadConnectionClosed}, someChain);
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadConnectionClosed)
    << "the completion carries the terminal reconnect status";
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.redundancy.trigger.failed");
}

// P4: begin_close never drops the stashed completion (error_handling.md) - it fires it Bad_ConnectionClosed
// with the trigger.closing source tag before the FSM is cancelled.
TEST_F(ConnectionRedundancyWiringTest, CloseFiresStashedCompletionBad)
{
  auto connection = make_connection();
  std::optional<VoidResult> captured;
  stash_pending_via_trigger(*connection, captured);
  ASSERT_FALSE(captured.has_value()) << "still parked before close";

  connection->close_async([](VoidResult) {});
  pump();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.redundancy.trigger.closing");
}

// P3: a second trigger supersedes a still-pending first - the prior stashed completion is fired Good before
// the new one is stashed, so it is never dropped. Guards the "fire any prior pending Good first" branch.
TEST_F(ConnectionRedundancyWiringTest, SecondTriggerFiresPriorStashedCompletionGoodFirst)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  ASSERT_NE(host, nullptr);

  std::optional<VoidResult> first;
  host->trigger_reconnect_async(ReconnectCause{TransportDropped{}},
    StatusCode{Status::BadNoCommunication},
    nullptr,
    [&first](VoidResult result) { first = std::move(result); });
  pump();
  ASSERT_FALSE(first.has_value()) << "the first completion is parked";

  std::optional<VoidResult> second;
  host->trigger_reconnect_async(ReconnectCause{TransportDropped{}},
    StatusCode{Status::BadNoCommunication},
    nullptr,
    [&second](VoidResult result) { second = std::move(result); });
  pump();

  ASSERT_TRUE(first.has_value()) << "the superseded first completion is fired, never dropped";
  EXPECT_TRUE(first->is_good()) << "a superseded pending completion is released Good";
  EXPECT_FALSE(second.has_value())
    << "the second completion is now the parked one, awaiting a terminal drive";
}

// P4 / F5 - the falsifiable section 8.11.3 close-order oracle: begin_close closes the RedundancyManager
// BEFORE it cancels the reconnect FSM. Swapping the two production blocks flips this recorded order and fails
// the test.
//
// set_close_step_probe installs the probe via a BLOCKING strand round-trip, so (unlike the rest of this
// suite) the io_context must be draining concurrently while it runs - a plain pump() would deadlock (the
// install task can never run on the strand while the sole thread blocks on its future). So this one test
// drains mCtx on a background thread for its duration; the probe records the source-level order on the
// strand and the close-completion promise barriers the read (runner.join() publishes every write).
TEST_F(ConnectionRedundancyWiringTest, CloseClosesManagerBeforeFsmCancel)
{
  auto connection = make_connection();
  std::vector<std::string> order;

  auto guard = boost::asio::make_work_guard(mCtx);
  std::thread runner([this] { mCtx.run(); });

  TA::set_close_step_probe(*connection, [&order](std::string_view step) { order.emplace_back(step); });

  std::promise<void> closed;
  auto closedFuture = closed.get_future();
  connection->close_async([&closed](VoidResult) { closed.set_value(); });
  closedFuture.get();  // close finished -> begin_close's probe calls have all run on the strand

  guard.reset();
  runner.join();  // synchronizes every runner-thread write of `order` into this thread

  EXPECT_EQ(order, (std::vector<std::string>{"manager_close", "fsm_cancel"}))
    << "the redundancy manager is closed strictly before the reconnect FSM is cancelled (section 8.11.3)";
}

// P3: the FIRST reach-Active drives the manager's on_session_active hook, kicking discovery. With the Read
// held at the session interface the RedundancySupport read parks, so the manager leaves Dormant and sits in
// Discovering - a stable, observable proof the drive ran. (The bootstrap NamespaceArray Read is fired by
// hand so the connection reaches Active; the subsequent discovery Read then parks at the same held interface.)
TEST_F(ConnectionRedundancyWiringTest, FirstActiveDrivesOnSessionActive)
{
  auto connection = make_connection();
  mSession->read.set_hold(true);  // park every Read at the interface so the discovery Read stays pending

  std::optional<VoidResult> startResult;
  connection->start_async([&startResult](VoidResult result) { startResult = std::move(result); });
  pump();  // the bootstrap NamespaceArray Read parks; mState is still Connecting
  ASSERT_EQ(mSession->read.pending_count(), 1u) << "the bootstrap Read is parked at the interface";

  mSession->read.fire_next(ua::Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response()});
  pump();  // finish bootstrap -> Active -> on_first_session_active -> manager discovery Read parks

  ASSERT_TRUE(startResult.has_value());
  ASSERT_TRUE(startResult->is_good()) << "the bootstrap reached Active";

  auto manager = TA::redundancy_manager(*connection);
  ASSERT_NE(manager, nullptr);
  const auto info = manager->redundancy_info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, RedundancyManagerState::Discovering)
    << "on_first_session_active drove on_session_active -> the manager left Dormant and kicked discovery";
}

// The manager holds the host STRONG (the one intentional cycle-exception) and the host holds ConnectionImpl
// WEAK. When the orchestrator is destroyed, the host's forwards fail with source-tagged boundary failures,
// yet the manager's own close_async still completes Good - the latent cycle is breakable independently of
// the (already gone) orchestrator (section 8.11.3).
class ConnectionRedundancyCycleTest : public ConnectionRedundancyWiringTest
{};

TEST_F(ConnectionRedundancyCycleTest, DroppedConnectionHostLockFailsManagerCloseStillCompletes)
{
  auto connection = make_connection();
  auto host = TA::redundancy_host(*connection);
  auto manager = TA::redundancy_manager(*connection);
  ASSERT_NE(host, nullptr);
  ASSERT_NE(manager, nullptr);

  connection.reset();  // destroy the orchestrator; host's weak ConnectionImpl now expires.

  EXPECT_EQ(host->connection_id(), ua::NodeId{})
    << "identity read degrades to default when the Connection is gone";

  std::optional<ua::Result<std::vector<ua::DataValue>>> readResult;
  host->read_attributes_async(
    {}, [&readResult](ua::Result<std::vector<ua::DataValue>> result) { readResult = std::move(result); });

  std::optional<VoidResult> triggerResult;
  host->trigger_reconnect_async(ReconnectCause{TransportDropped{}},
    StatusCode{Status::BadNoCommunication},
    nullptr,
    [&triggerResult](VoidResult result) { triggerResult = result; });

  std::optional<VoidResult> closeResult;
  manager->close_async([&closeResult](VoidResult result) { closeResult = result; });
  pump();

  ASSERT_TRUE(readResult.has_value());
  ASSERT_TRUE(readResult->is_bad());
  EXPECT_EQ(readResult->status_code().as_status(), Status::BadConnectionClosed);
  ASSERT_NE(readResult->shared_detail(), nullptr);
  EXPECT_EQ(readResult->shared_detail()->source, "client.tier1.redundancy.read.connection_gone");

  ASSERT_TRUE(triggerResult.has_value());
  ASSERT_TRUE(triggerResult->is_bad());
  EXPECT_EQ(triggerResult->status_code().as_status(), Status::BadConnectionClosed);
  ASSERT_NE(triggerResult->shared_detail(), nullptr);
  EXPECT_EQ(triggerResult->shared_detail()->source, "client.tier1.redundancy.trigger.connection_gone");

  ASSERT_TRUE(closeResult.has_value());
  EXPECT_TRUE(closeResult->is_good())
    << "the manager close completes Good even with the orchestrator destroyed - the cycle is broken";
}

}  // namespace
