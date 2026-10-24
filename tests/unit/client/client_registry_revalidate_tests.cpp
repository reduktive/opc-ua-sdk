// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the W5 Connection registry + server-cert revalidation walk on ua::client::CoreClientImpl:
// register_connection / unregister_connection and revalidate_connections_async (section 722/section 727, W6
// PullCert consumer). The walk snapshots the weak Connection registry to strong refs (releasing the registry
// mutex first - callback_safety), dispatches ConnectionImpl::revalidate_server_cert_async to each LIVE
// Connection, and fires the aggregate callback EXACTLY ONCE on the executor after every Connection has
// acknowledged. An empty registry completes Good immediately; expired weak entries are skipped; each
// Connection that finds its server cert now-untrusted routes ITSELF to its ReconnectionFSM (CertRotated)
// while the aggregate stays Good (advisory, J53).
//
// Reached via CoreClientTestAccess::impl (the impl-level surface is not on the move-only Client facade). Real
// ConnectionImpls are built on the SAME single-thread executor as the Client, over the fake tier-0 interface, and
// registered directly (the auto-registration connect path is a later slice). A single-thread pool serialises
// the async work so the aggregate barrier is observable deterministically; the aggregate is awaited with a
// bounded wait_for + hard-FAIL on timeout so a barrier hang fails fast rather than hanging CI.
//
// Falsifiability: each test asserts a concrete observable - which per-Connection interfaces were invoked (the
// walk reached them), that the aggregate fired exactly once (a shared counter, never twice), that a dead
// weak entry is skipped without crashing, and that one untrusted Connection kicks ONLY its own FSM (its fake
// reopen is driven) while the trusted siblings' reopens stay untouched.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen (../connection, via CMake)

#include "ua_core_client.h"
#include "ua_core_client_impl.h"
#include "ua_client_test_hooks.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_logger.h"
#include "ua_reconnect_policy.h"
#include "ua_result.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include "dev_factories.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Logger;
using ua::Status;
using ua::VoidResult;
using ua::client::CoreClient;
using ua::client::CoreClientImpl;
using ua::client::CoreClientTestAccess;
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

ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// A ServerCertValidator that counts its invocations then fires the verdict @p verdictResult inline.
ServerCertValidator counting_wire_ops(std::shared_ptr<std::atomic<int>> count, VoidResult verdictResult = {})
{
  return [count = std::move(count), verdictResult](std::function<void(VoidResult)> verdict) mutable
  {
    count->fetch_add(1, std::memory_order_relaxed);
    verdict(verdictResult);
  };
}

class ClientConnectionRegistry : public ::testing::Test
{
protected:
  // One worker thread: the async work is serialised, so a fence posted after the aggregate fires is a true
  // barrier (deterministic exactly-once observation) and the blocking bridges below never deadlock (the test
  // thread is separate from the pool worker).
  boost::asio::thread_pool mPool{1};
  CoreClient mClient = ua::test_helpers::make_dev_core_client(mPool.get_executor());
  std::shared_ptr<CoreClientImpl> mClientImpl = CoreClientTestAccess::impl(mClient);

  std::shared_ptr<ConnectionImpl> make_connection(const std::shared_ptr<FakeSessionOps>& session,
    const std::shared_ptr<FakeReopen>& reopen, ServerCertValidator validator = {})
  {
    return TA::create_with_ops(mPool.get_executor(),
      session,
      ConnectionConfig{},
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

  /// Aggregate-callback capture: an atomic invocation count plus a one-shot promise (set on the first fire),
  /// so a double-fire regression is caught by the count while the future still unblocks the test.
  struct Aggregate
  {
    std::atomic<int> calls{0};
    std::promise<VoidResult> promise;
    std::future<VoidResult> future{promise.get_future()};
  };

  /// Runs the walk and blocks (bounded) on the FIRST aggregate fire. A barrier bug that never fires must
  /// FAIL promptly rather than hang CI, so a timeout is a hard failure (never an unbounded wait).
  std::shared_ptr<Aggregate> revalidate_and_wait(bool ownCertificateChanged = false)
  {
    auto aggregate = std::make_shared<Aggregate>();
    mClientImpl->revalidate_connections_async(ownCertificateChanged,
      true,
      [aggregate](VoidResult result)
      {
        if (aggregate->calls.fetch_add(1, std::memory_order_relaxed) == 0)
        {
          aggregate->promise.set_value(std::move(result));
        }
      });
    if (aggregate->future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "revalidate_connections_async aggregate never fired within 5s (barrier hang?)";
    }
    return aggregate;
  }

  /// A round-trip fence on the (single-thread) pool executor: after it returns, every task queued on the
  /// pool before it - including an erroneous SECOND aggregate fire - has already run. A true barrier.
  void drain_pool()
  {
    std::promise<void> fenced;
    auto future = fenced.get_future();
    boost::asio::post(mPool.get_executor(), [&fenced] { fenced.set_value(); });
    future.get();
  }

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

// An empty registry completes the aggregate Good immediately (on the executor) - no per-Connection dispatch.
TEST_F(ClientConnectionRegistry, EmptyRegistryRevalidateCompletesGood)
{
  auto aggregate = revalidate_and_wait();

  ASSERT_EQ(aggregate->future.wait_for(0s), std::future_status::ready);
  EXPECT_TRUE(aggregate->future.get().is_good()) << "empty registry -> Good";
  drain_pool();
  EXPECT_EQ(aggregate->calls.load(), 1) << "the aggregate fired exactly once";
}

// The walk dispatches revalidate to EVERY registered Connection: three counting interfaces are each invoked once
// and the aggregate fires once.
TEST_F(ClientConnectionRegistry, RegisterThenRevalidateDispatchesToEach)
{
  std::vector<std::shared_ptr<FakeSessionOps>> sessions;
  std::vector<std::shared_ptr<FakeReopen>> reopens;
  std::vector<std::shared_ptr<ConnectionImpl>> connections;
  std::vector<std::shared_ptr<std::atomic<int>>> wireOpCalls;
  for (int i = 0; i < 3; ++i)
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    auto calls = std::make_shared<std::atomic<int>>(0);
    auto connection = make_connection(session, reopen, counting_wire_ops(calls));
    mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));
    sessions.push_back(std::move(session));
    reopens.push_back(std::move(reopen));
    wireOpCalls.push_back(std::move(calls));
    connections.push_back(std::move(connection));
  }

  auto aggregate = revalidate_and_wait();
  EXPECT_TRUE(aggregate->future.get().is_good());
  drain_pool();

  for (std::size_t i = 0; i < wireOpCalls.size(); ++i)
  {
    EXPECT_EQ(wireOpCalls[i]->load(), 1) << "connection " << i << "'s server-cert validator was consulted once";
  }
  EXPECT_EQ(aggregate->calls.load(), 1) << "the aggregate fired exactly once for the three-way walk";
}

// A registered Connection whose weak entry has expired (the ConnectionImpl was destroyed) is silently
// skipped by the snapshot - no crash, and with no live Connections left the aggregate is Good.
TEST_F(ClientConnectionRegistry, ExpiredWeakEntrySkipped)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto connection = make_connection(session, reopen, counting_wire_ops(std::make_shared<std::atomic<int>>(0)));
  std::weak_ptr<ConnectionImpl> weakConnection = connection;
  mClientImpl->register_connection(weakConnection);

  connection.reset();  // destroy the ConnectionImpl; the registry's weak entry now dangles
  ASSERT_TRUE(weakConnection.expired());

  auto aggregate = revalidate_and_wait();
  EXPECT_TRUE(aggregate->future.get().is_good()) << "the dead entry is skipped; no live Connection -> Good";
  drain_pool();
  EXPECT_EQ(aggregate->calls.load(), 1);
}

// Unregistering a Connection removes it from the walk: its interface is never consulted afterwards.
TEST_F(ClientConnectionRegistry, UnregisterRemovesFromWalk)
{
  auto session = std::make_shared<FakeSessionOps>();
  auto reopen = std::make_shared<FakeReopen>();
  auto wireOpCalls = std::make_shared<std::atomic<int>>(0);
  auto connection = make_connection(session, reopen, counting_wire_ops(wireOpCalls));
  mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));

  mClientImpl->unregister_connection(connection.get());

  auto aggregate = revalidate_and_wait();
  EXPECT_TRUE(aggregate->future.get().is_good());
  drain_pool();

  EXPECT_EQ(wireOpCalls->load(), 0) << "an unregistered Connection is not walked";
  EXPECT_EQ(aggregate->calls.load(), 1) << "an empty (post-unregister) walk still fires the aggregate once";
}

// One Connection's verdict is untrusted (kicks ONLY its own CertRotated reconnect); the other two are
// trusted. All three acknowledge, the aggregate fires once, and only the untrusted Connection's FSM is
// kicked (its fake reopen is driven; the trusted siblings' reopens stay untouched). This is the real
// walk -> per-Connection revalidate -> CertRotated mechanic (the pull_cert tests only assert the manager
// CALLS the host via a fake counter; this exercises the genuine registry walk).
// @verifies CL-PULLCRT-006
// @verifies CL-RECONN-006
// @relation(CL-PULLCRT-006, CL-RECONN-006, scope=function)
TEST_F(ClientConnectionRegistry, OneUntrustedConnectionTriggersItsReconnectOthersStillRevalidate)
{
  std::vector<std::shared_ptr<FakeSessionOps>> sessions;
  std::vector<std::shared_ptr<FakeReopen>> reopens;
  std::vector<std::shared_ptr<ConnectionImpl>> connections;
  std::vector<std::shared_ptr<std::atomic<int>>> wireOpCalls;
  for (int i = 0; i < 3; ++i)
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    reopen->set_hold(true);  // park an (untrusted) reconnect at its open-channel step, observably
    auto calls = std::make_shared<std::atomic<int>>(0);
    // Connection 0 is now-untrusted (Bad verdict -> CertRotated); 1 and 2 are still-trusted (Good).
    const VoidResult verdict =
      (i == 0) ? VoidResult{ua::StatusCode{Status::BadCertificateUntrusted}} : VoidResult{};
    auto connection = make_connection(session, reopen, counting_wire_ops(calls, verdict));
    // All three must be Active with their FSM Active so a CertRotated trigger actually drives a reconnect
    // (and so the trusted siblings' non-kick is falsifiable - a stray kick would drive their reopen too).
    ASSERT_TRUE(start_and_wait(*connection).is_good());
    mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));
    sessions.push_back(std::move(session));
    reopens.push_back(std::move(reopen));
    wireOpCalls.push_back(std::move(calls));
    connections.push_back(std::move(connection));
  }

  auto aggregate = revalidate_and_wait();
  EXPECT_TRUE(aggregate->future.get().is_good()) << "the aggregate stays Good - the untrusted verdict is "
                                                    "acted on locally, not surfaced (advisory, J53)";

  // The untrusted Connection kicked its own FSM: its open-channel step parked at the fake reopen.
  wait_for_reopen_pending(*reopens[0], 1);
  drain_pool();

  for (std::size_t i = 0; i < wireOpCalls.size(); ++i)
  {
    EXPECT_EQ(wireOpCalls[i]->load(), 1) << "connection " << i << " was revalidated exactly once";
  }
  EXPECT_EQ(reopens[1]->call_count(), 0u) << "a trusted Connection must not be kicked";
  EXPECT_EQ(reopens[2]->call_count(), 0u) << "a trusted Connection must not be kicked";
  EXPECT_EQ(aggregate->calls.load(), 1) << "the aggregate fired exactly once across the mixed walk";

  // Cancel the untrusted Connection's parked reconnect (and its armed step deadline) before teardown so the
  // pool drains cleanly.
  for (auto& connection : connections)
  {
    close_and_wait(*connection);
  }
}

// @verifies CL-RECONN-006
// An own-certificate commit is categorically different from a trust-list-only update: Part 4 section 6.7
// requires every live Connection to create a new Session even when its pinned server certificate remains
// trusted. The Client registry broadcast therefore has to drive CertRotated on every live reconnect-capable
// Connection; a server-cert-only implementation would leave both reopens at zero.
// @relation(CL-RECONN-006, scope=function)
TEST_F(ClientConnectionRegistry, OwnCertificateChangeTriggersEveryTrustedConnectionReconnect)
{
  std::vector<std::shared_ptr<FakeSessionOps>> sessions;
  std::vector<std::shared_ptr<FakeReopen>> reopens;
  std::vector<std::shared_ptr<ConnectionImpl>> connections;
  for (int i = 0; i < 2; ++i)
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    reopen->set_hold(true);
    auto connection =
      make_connection(session, reopen, counting_wire_ops(std::make_shared<std::atomic<int>>(0), VoidResult{}));
    ASSERT_TRUE(start_and_wait(*connection).is_good());
    mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));
    sessions.push_back(std::move(session));
    reopens.push_back(std::move(reopen));
    connections.push_back(std::move(connection));
  }

  auto aggregate = revalidate_and_wait(true);
  ASSERT_EQ(aggregate->future.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(aggregate->future.get().is_good());
  for (auto& reopen : reopens)
  {
    wait_for_reopen_pending(*reopen, 1);
    EXPECT_EQ(reopen->call_count(), 1U)
      << "own-certificate rotation must reconnect even when server-certificate validation is Good";
  }

  for (auto& connection : connections)
    close_and_wait(*connection);
}

// The aggregate callback is invoked EXACTLY ONCE - never twice - even across a multi-Connection walk.
TEST_F(ClientConnectionRegistry, AggregateFiresExactlyOnce)
{
  std::vector<std::shared_ptr<FakeSessionOps>> sessions;
  std::vector<std::shared_ptr<FakeReopen>> reopens;
  std::vector<std::shared_ptr<ConnectionImpl>> connections;
  for (int i = 0; i < 3; ++i)
  {
    auto session = std::make_shared<FakeSessionOps>();
    auto reopen = std::make_shared<FakeReopen>();
    auto connection = make_connection(session, reopen, counting_wire_ops(std::make_shared<std::atomic<int>>(0)));
    mClientImpl->register_connection(std::weak_ptr<ConnectionImpl>(connection));
    sessions.push_back(std::move(session));
    reopens.push_back(std::move(reopen));
    connections.push_back(std::move(connection));
  }

  auto aggregate = revalidate_and_wait();
  EXPECT_TRUE(aggregate->future.get().is_good());

  // Fence the pool: any erroneous second fire queued during the barrier decrement has now run.
  drain_pool();
  EXPECT_EQ(aggregate->calls.load(), 1) << "the aggregate barrier must fire the callback exactly once";
}

}  // namespace
