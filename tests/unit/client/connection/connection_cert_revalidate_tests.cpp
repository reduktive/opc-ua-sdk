// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::ConnectionImpl::revalidate_server_cert_async (section 722/section 727,
// W5 / CL-SECADMIN-004 / CL-RECONN-006) - the per-Connection server-cert re-validation the Client-level walk
// (CoreClientImpl::revalidate_connections_async) fans out to after a renewed cert / new trust list is
// committed.
//
// The Connection re-checks its CURRENT server cert against the store via the injected ServerCertValidator
// interface and ACTS on the verdict: still-trusted (Good) -> acknowledge Good, do nothing; now-untrusted/revoked
// (Bad) -> trigger its own ReconnectionFSM with a CertRotated cause AND acknowledge Good (J53: the ack is
// advisory - the Connection owns its reconnect, so a triggered reconnect is still a Good acknowledgement).
// A terminal/closing Connection, or one with no validator interface wired (the W5 production default), is a Good
// no-op. If the Connection is destroyed mid-flight (after the interface is invoked, before its async verdict
// lands) the OWED completion is STILL delivered Good - it is the walk-barrier decrement and must never be
// dropped, else the Client aggregate can never reach zero and hangs.
//
// Driven over the fake tier-0 interface (FakeSessionOps / FakeReopen) on a live AsyncTestRuntime (mirroring the
// reconnect suite): a Bad verdict kicks a real FSM whose open-channel step drives the fake reopen - observed
// via reopen->pending_count() (exactly the TransportDropTriggersReconnect pattern). No real timers are
// waited on; the reopen is held so the parked open-channel step is the observable.
//
// Falsifiability: each test asserts a concrete observable - the exact ack status, the interface invocation count,
// whether the fake reopen was driven (FSM kicked) or not, and (the key regression oracle) that the owed
// completion still fires Good after the Connection is provably destroyed mid-flight.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen

#include "async_test_runtime.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_logger.h"
#include "ua_reconnect_policy.h"
#include "ua_result.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <variant>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::Status;
using ua::VoidResult;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::ServerCertValidator;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

/// A near-zero backoff so any incidental FSM timer fires promptly (the suite drives the trigger directly).
ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// A ServerCertValidator that fires the verdict Bad inline (now untrusted / revoked).
ServerCertValidator untrusted_wire_ops()
{
  return [](std::function<void(VoidResult)> verdict)
  {
    verdict(VoidResult{ua::StatusCode{Status::BadCertificateUntrusted}});
  };
}

/// A ServerCertValidator that counts its invocations then fires the verdict @p verdictResult inline. The
/// counter is shared so the test can assert exactly-once invocation.
ServerCertValidator counting_wire_ops(std::shared_ptr<std::atomic<int>> count, VoidResult verdictResult = {})
{
  return [count = std::move(count), verdictResult](std::function<void(VoidResult)> verdict) mutable
  {
    count->fetch_add(1, std::memory_order_relaxed);
    verdict(verdictResult);
  };
}

/// Thread-safe ConnectionObserver that captures the cause of the FIRST on_reconnecting (fired on the delivery
/// strand of the async runtime). Lets a test assert the reconnect CAUSE, not merely that a reconnect started
/// (reopen->pending_count() fires identically for EVERY non-SecurityFailure cause, so it cannot distinguish
/// CertRotated - the CL-RECONN-006 required label - from a generic drop).
class CauseCapturingObserver : public ua::client::ConnectionObserver
{
public:
  std::mutex mutex;
  std::condition_variable cv;
  std::optional<ua::client::ReconnectCause> cause;

  void on_reconnecting(
    const ua::client::Connection&, std::size_t, ua::client::ReconnectCause reconnectCause) override
  {
    const std::lock_guard lk{mutex};
    if (!cause)
    {
      cause = std::move(reconnectCause);
    }
    cv.notify_all();
  }

  [[nodiscard]] bool wait_for_cause(std::chrono::milliseconds timeout)
  {
    std::unique_lock lk{mutex};
    return cv.wait_for(lk, timeout, [this] { return cause.has_value(); });
  }
};

class ConnectionCertRevalidate : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;

  std::shared_ptr<ConnectionImpl> make_connection(const std::shared_ptr<FakeSessionOps>& session,
    const std::shared_ptr<FakeReopen>& reopen, ServerCertValidator validator = {},
    std::shared_ptr<ua::client::ConnectionObserver> observer = {})
  {
    ConnectionConfig config;
    config.observers.connection = std::move(observer);
    return TA::create_with_ops(mRuntime.executor(),
      session,
      std::move(config),
      Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      KeepAlivePolicy{0ms},
      /*clientObserverDefaults=*/{},
      /*enableRedundancy=*/false,
      /*redundancyPolicy=*/{},
      /*redundancyDiscovery=*/{},
      std::move(validator));
  }

  static VoidResult start_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  /// Drives revalidate and blocks (bounded) on the ack. A barrier bug that never acknowledges must FAIL the
  /// test promptly rather than hang CI, so a timeout is a hard failure (never an unbounded wait).
  static VoidResult revalidate_and_wait(
    ConnectionImpl& connection, bool ownCertificateChanged = false, bool revalidateServerCertificate = true)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.revalidate_server_cert_async(ownCertificateChanged,
      revalidateServerCertificate,
      [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "revalidate_server_cert_async never acknowledged within 5s (owed-completion drop?)";
      return VoidResult{ua::StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }

  /// Polls until the fake reopen has parked at least @p n completions (bounded), proving the FSM reached
  /// its open-channel step.
  static void wait_for_reopen_pending(FakeReopen& reopen, std::size_t n)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (reopen.pending_count() < n && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    ASSERT_GE(reopen.pending_count(), n);
  }
};

// No validator interface wired (the W5 production default: no retained secured channel to revalidate) -> the
// revalidate is a Good no-op that neither invokes an interface nor kicks the FSM.
TEST_F(ConnectionCertRevalidate, NoValidatorAcknowledgesGoodNoReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // an erroneous reconnect would park here (observable), so 0 proves none started
  auto connection = make_connection(session, reopen, /*validator=*/{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result = revalidate_and_wait(*connection);
  EXPECT_TRUE(result.is_good()) << "no interface: nothing to revalidate -> Good no-op";

  TA::snapshot(*connection);  // connection-strand FIFO barrier: the revalidate handler has fully run
  EXPECT_EQ(reopen->call_count(), 0u) << "no interface: the FSM must not be kicked";
  EXPECT_EQ(connection->info()->state, ConnectionState::Active) << "still Active - no reconnect";
}

// @verifies CL-RECONN-006
// The no-validator production path must not turn an own-certificate update into the trust-list no-op above.
// Part 4 section 6.7 requires a new Session based solely on the client's certificate having changed.
// @relation(CL-RECONN-006, scope=function)
TEST_F(ConnectionCertRevalidate, OwnCertificateChangeReconnectsWithoutServerValidator)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto observer = std::make_shared<CauseCapturingObserver>();
  auto connection = make_connection(session, reopen, /*validator=*/{}, observer);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result = revalidate_and_wait(*connection, true);
  EXPECT_TRUE(result.is_good());
  wait_for_reopen_pending(*reopen, 1);
  ASSERT_TRUE(observer->wait_for_cause(5s));
  {
    const std::lock_guard lock{observer->mutex};
    ASSERT_TRUE(observer->cause.has_value());
    EXPECT_TRUE(std::holds_alternative<ua::client::CertRotated>(*observer->cause));
  }

  close_and_wait(*connection);
}

// @verifies CL-RECONN-006
// The immediate-server-revalidation policy is independent of the mandatory own-certificate reconnect: the
// latter starts even when the former is disabled, and the server validator is not consulted.
// @relation(CL-RECONN-006, scope=function)
TEST_F(ConnectionCertRevalidate, OwnCertificateChangeCanSkipIndependentServerValidation)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto observer = std::make_shared<CauseCapturingObserver>();
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls, VoidResult{}), observer);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result =
    revalidate_and_wait(*connection, /*ownCertificateChanged=*/true, /*revalidateServerCertificate=*/false);
  EXPECT_TRUE(result.is_good());
  wait_for_reopen_pending(*reopen, 1);
  EXPECT_EQ(wireOpCalls->load(), 0);
  ASSERT_TRUE(observer->wait_for_cause(5s));
  {
    const std::lock_guard lock{observer->mutex};
    ASSERT_TRUE(observer->cause.has_value());
    EXPECT_TRUE(std::holds_alternative<ua::client::CertRotated>(*observer->cause));
  }

  close_and_wait(*connection);
}

// A still-trusted (Good) verdict acknowledges Good and does NOT kick a reconnect.
TEST_F(ConnectionCertRevalidate, TrustedVerdictAcknowledgesGoodNoReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls, VoidResult{}));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result = revalidate_and_wait(*connection);
  EXPECT_TRUE(result.is_good()) << "still trusted -> Good";

  EXPECT_EQ(wireOpCalls->load(), 1) << "the validator interface was consulted";
  TA::snapshot(*connection);  // barrier
  EXPECT_EQ(reopen->call_count(), 0u) << "a trusted verdict must not kick a reconnect";
  EXPECT_EQ(connection->info()->state, ConnectionState::Active);
}

// A now-untrusted (Bad) verdict triggers a CertRotated reconnect (the FSM's open-channel step drives the
// fake reopen) AND still acknowledges Good (J53: the ack is advisory).
// @verifies CL-RECONN-006
// @verifies CL-PULLCRT-006
// @relation(CL-PULLCRT-006, CL-RECONN-006, scope=function)
TEST_F(ConnectionCertRevalidate, UntrustedVerdictTriggersCertRotatedReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the reopen so the FSM's open-channel step is observable without completing
  auto observer = std::make_shared<CauseCapturingObserver>();
  auto connection = make_connection(session, reopen, untrusted_wire_ops(), observer);
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result = revalidate_and_wait(*connection);
  EXPECT_TRUE(result.is_good()) << "acknowledged Good even though it ACTED on the untrusted verdict (J53)";

  wait_for_reopen_pending(*reopen, 1);  // the reconnect reached the open-channel step

  // The required assertion (CL-RECONN-006): the reconnect cause is CertRotated SPECIFICALLY - not just
  // that *a* reconnect started. reopen->pending_count() is identical for every non-SecurityFailure cause, so
  // a regression to TransportDropped would pass on the reopen oracle alone; on_reconnecting carries the true
  // cause, which selects new-Session + TransferSubscriptions and is the label reported to the observer.
  ASSERT_TRUE(observer->wait_for_cause(5s)) << "the reconnect must fire on_reconnecting with a cause";
  {
    const std::lock_guard lk{observer->mutex};
    ASSERT_TRUE(observer->cause.has_value());
    EXPECT_TRUE(std::holds_alternative<ua::client::CertRotated>(*observer->cause))
      << "an untrusted server cert must trigger the CertRotated reconnect cause, not a generic drop";
  }

  close_and_wait(*connection);  // cancel the parked reconnect + its armed step deadline before teardown
}

// A terminal (closed) Connection is a Good no-op: the terminal guard short-circuits BEFORE the interface is
// invoked and no reconnect is kicked.
TEST_F(ConnectionCertRevalidate, TerminalConnectionAcknowledgesGoodNoReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls, VoidResult{}));
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_TRUE(close_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Closed);

  const auto result = revalidate_and_wait(*connection);
  EXPECT_TRUE(result.is_good()) << "terminal -> Good no-op";

  EXPECT_EQ(wireOpCalls->load(), 0) << "the terminal guard runs before the interface - it must not be consulted";
  EXPECT_EQ(reopen->call_count(), 0u) << "terminal: no reconnect";
}

// The validator interface is invoked exactly once per revalidate call.
TEST_F(ConnectionCertRevalidate, ValidatorInvokedExactlyOncePerRevalidate)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls, VoidResult{}));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const auto result = revalidate_and_wait(*connection);
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(wireOpCalls->load(), 1) << "exactly one interface invocation per revalidate";
}

// THE key regression oracle: if the Connection is destroyed after the validator interface is invoked but before
// its async verdict lands, the OWED revalidate completion must STILL be delivered Good. It is the Client
// walk-barrier decrement and must never be dropped - dropping it on the connection-gone path would leave the
// aggregate barrier one short forever (a hang). Falsifiable: were the completion dropped when the weak
// self-lock fails, `ackCalls` would stay 0 and the has_value()/wait_for assertions below would FAIL.
TEST_F(ConnectionCertRevalidate, CompletionDeliveredEvenIfConnectionGoneMidFlight)
{
  // A HELD interface: capture the verdict callback and park it (do NOT fire), so the revalidate flow is stalled
  // exactly at the async-validate step while the test destroys the Connection. Thread-safe: the interface runs on
  // the runtime thread; the test thread reads `captured` and later moves the parked verdict out.
  struct HeldWireOps
  {
    std::mutex mutex;
    std::function<void(VoidResult)> verdict;
    std::atomic<bool> captured{false};
  };

  auto held = std::make_shared<HeldWireOps>();
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session,
    reopen,
    [held](std::function<void(VoidResult)> verdict)
    {
      {
        const std::lock_guard<std::mutex> lock(held->mutex);
        held->verdict = std::move(verdict);
      }
      held->captured.store(true, std::memory_order_release);
    });

  // Reach Active (so the FSM is Active and a live verdict COULD kick it - proving the drop path, not a
  // trivially-inert one, still delivers the completion).
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // Revalidate: the interface is invoked and parks the verdict. The completion is now OWED (not yet delivered).
  std::atomic<int> ackCalls{0};
  std::promise<VoidResult> ackPromise;
  auto ackFuture = ackPromise.get_future();
  connection->revalidate_server_cert_async(false,
    true,
    [&ackCalls, &ackPromise](VoidResult result)
    {
      if (ackCalls.fetch_add(1, std::memory_order_relaxed) == 0)
      {
        ackPromise.set_value(std::move(result));
      }
    });

  // Wait (bounded) until the interface has parked the verdict, then a strand barrier so the outer handler has
  // fully returned and the runtime is idle before the Connection is dropped.
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!held->captured.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(1ms);
  }
  ASSERT_TRUE(held->captured.load(std::memory_order_acquire))
    << "the interface was invoked and parked the verdict";
  TA::snapshot(*connection);  // barrier: the revalidate outer handler has fully run on the strand
  ASSERT_EQ(ackFuture.wait_for(0s), std::future_status::timeout) << "the completion is owed, not delivered";

  // Destroy the Connection mid-flight (after the interface parked, before the verdict lands). The parked verdict
  // holds only a weak self-ref, so dropping this sole strong ref truly destroys it.
  std::weak_ptr<ConnectionImpl> weakConnection = connection;
  connection.reset();
  ASSERT_TRUE(weakConnection.expired()) << "the Connection is provably gone (no lingering strong ref)";

  // Now fire the parked verdict Bad: the weak self-lock fails, so the impl must deliver the owed completion
  // Good DIRECTLY (never dropping it) - the walk-barrier decrement that keeps the aggregate from hanging.
  std::function<void(VoidResult)> verdict;
  {
    const std::lock_guard<std::mutex> lock(held->mutex);
    verdict = std::move(held->verdict);
  }
  ASSERT_TRUE(static_cast<bool>(verdict));
  verdict(VoidResult{ua::StatusCode{Status::BadCertificateUntrusted}});

  ASSERT_EQ(ackFuture.wait_for(5s), std::future_status::ready)
    << "the owed completion must be delivered even though the Connection is gone (else the aggregate hangs)";
  EXPECT_TRUE(ackFuture.get().is_good()) << "delivered Good (advisory ack, J53)";
  EXPECT_EQ(ackCalls.load(), 1) << "delivered exactly once";
}

/// AC-COMP-CL-CONNIMPL-21-C. CO6 requires each collaborator mode, and "completes twice" is one the header
/// names explicitly: the interface contract says fire exactly once, and `revalidate_server_cert_async` carries a
/// fire-once guard against an interface that breaks it. `ValidatorInvokedExactlyOncePerRevalidate` asserts the
/// opposite direction - that the component invokes the interface once - so the defensive guard itself was
/// unexercised. Both consequences of a lost guard are observed here: a second completion for a caller that
/// owes one, and a second reconnect against a Connection already recovering.
// @relation(AC-COMP-CL-CONNIMPL-21-C, scope=function)
TEST_F(ConnectionCertRevalidate, DoubleFiringValidatorYieldsOneCompletionAndOneReconnect)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  reopen->set_hold(true);  // park the FSM's open-channel step so the reconnect count is observable

  // An interface that violates its contract by firing the same Bad verdict twice.
  ServerCertValidator doubleFiring = [](std::function<void(VoidResult)> verdict)
  {
    verdict(VoidResult{ua::StatusCode{Status::BadCertificateUntrusted}});
    verdict(VoidResult{ua::StatusCode{Status::BadCertificateUntrusted}});
  };

  auto connection = make_connection(session, reopen, std::move(doubleFiring));
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  std::atomic<int> ackCalls{0};
  std::promise<VoidResult> ack;
  auto ackFuture = ack.get_future();
  TA::revalidate_server_cert_async(
    *connection,
    [&ackCalls, &ack](VoidResult result)
    {
      if (ackCalls.fetch_add(1) == 0)
      {
        ack.set_value(std::move(result));
      }
    },
    /*ownCertificateChanged=*/false,
    /*revalidateServerCertificate=*/true);

  ASSERT_EQ(ackFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(ackFuture.get().is_good());
  std::this_thread::sleep_for(50ms);  // let an erroneous second delivery land before asserting

  EXPECT_EQ(ackCalls.load(), 1) << "the fire-once guard must de-duplicate a interface that fires twice";
  EXPECT_EQ(reopen->pending_count(), 1u)
    << "one verdict, one CertRotated reconnect - a second trigger would re-drive a recovering connection";
}

}  // namespace
