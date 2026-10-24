// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::CoreClientImpl::connect_async, driven through the PRODUCTION public entry point
// Client::connect_async / try_connect_sync with a fake ConnectionEstablisher injected (no real server). These
// exercise connect_async's OWN orchestration: plan-reject short-circuit, establish-failure mapping, RAII
// registration + unregister-on-destruct, strong-hold across bootstrap, bootstrap-failure mapping, the
// establish double-fire guard, on-executor + fire-once delivery, and Client-level observer-default threading.
//
// Falsifiability: each test scripts one stage (invalid plan / establish bad / bootstrap read bad / double
// fire) and asserts the exact delivered status, the registry size (registered / unregistered), the number of
// establish invocations, and the threaded observer defaults - so an orchestrator that mis-mapped an error,
// leaked a registry entry, double-registered, or dropped the observer defaults fails a concrete assertion.

#include "fake_session_ops.h"  // ua::test_helpers::FakeSessionOps / FakeReopen (../connection, via CMake)

#include "ua_client.h"
#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_client_test_hooks.h"
#include "ua_connect_plan.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_connection_establisher.h"
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
#include <optional>
#include <stdexcept>
#include <utility>

#include "test_components.h"

namespace
{
using namespace std::chrono_literals;

using ua::client::Client;
using ua::client::Connection;
using ua::client::ConnectionConfig;  // the PUBLIC config
using ua::client::CoreClientImpl;
using ua::client::CoreClientTestAccess;
using ua::client::EndpointSelection;
using ua::client::Session;
using ua::client::detail::ConnectionEstablisher;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::client::detail::ConnectPlan;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::ObserverSlots;
using ua::client::detail::ServerCertValidator;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;
using EstablishResult = ua::Result<std::shared_ptr<ConnectionImpl>>;

ua::client::ReconnectPolicy fast_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = 1ms;
  policy.backoff.max = 1ms;
  policy.backoff.jitterPct = 0.0;
  return policy;
}

ServerCertValidator counting_wire_ops(std::shared_ptr<std::atomic<int>> count)
{
  return [count = std::move(count)](std::function<void(ua::VoidResult)> verdict)
  {
    count->fetch_add(1, std::memory_order_relaxed);
    verdict(ua::VoidResult{});
  };
}

// A ConnectionEstablisher test double: scripts a Good outcome (building a REAL fake-backed ConnectionImpl so
// connect_async's register/start/wrap runs against real code) or a Bad status, records the observer defaults
// it was handed, and can fire its callback more than once (the double-fire guard test).
class FakeConnectionEstablisher : public ConnectionEstablisher
{
public:
  explicit FakeConnectionEstablisher(boost::asio::any_io_executor executor) : mExecutor(std::move(executor))
  {}

  // --- scripting ---
  bool yieldBad = false;
  ua::StatusCode badStatus{ua::Status::BadConnectionRejected};
  int fireCount = 1;  // fire the callback this many times (double-fire regression)
  ua::VoidResult bootstrapRead{};  // Bad => the built ConnectionImpl's NamespaceArray bootstrap fails
  bool throwOnEstablish = false;  // throw synchronously (exercises connect_async's noexcept guard)
  bool stall = false;  // never fire the callback (exercises the connectTimeout deadline)

  // --- records / handles for the test ---
  std::shared_ptr<FakeSessionOps> session = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> reopen = std::make_shared<FakeReopen>();
  std::shared_ptr<std::atomic<int>> wireOpCalls = std::make_shared<std::atomic<int>>(0);
  std::atomic<int> establishCalls{0};
  std::optional<ObserverSlots> lastDefaults;

  void establish_async(
    ConnectPlan plan, ObserverSlots defaults, std::function<void(EstablishResult)> callback) override
  {
    establishCalls.fetch_add(1, std::memory_order_relaxed);
    lastDefaults = defaults;
    if (throwOnEstablish)
    {
      throw std::runtime_error("establish blew up");
    }
    if (stall)
    {
      return;  // never fire the callback -> only the connectTimeout deadline can complete the connect
    }
    if (yieldBad)
    {
      for (int i = 0; i < fireCount; ++i)
      {
        callback(EstablishResult{badStatus});
      }
      return;
    }
    if (bootstrapRead.is_bad())
    {
      session->read.set_result(ua::Result<ua::ReadResponse>{bootstrapRead.status_code()});
    }
    auto connection = TA::create_with_ops(mExecutor,
      session,
      std::move(plan.implConfig),
      ua::Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      KeepAlivePolicy{0ms},
      defaults,
      /*enableRedundancy=*/false,
      /*redundancyPolicy=*/{},
      /*redundancyDiscovery=*/{},
      counting_wire_ops(wireOpCalls));
    for (int i = 0; i < fireCount; ++i)
    {
      callback(EstablishResult{connection});
    }
  }

private:
  boost::asio::any_io_executor mExecutor;
};

class ClientConnect : public ::testing::Test
{
protected:
  boost::asio::thread_pool mPool{1};
  Client mClient = ua::test_helpers::make_dev_client(mPool.get_executor());
  std::shared_ptr<CoreClientImpl> mClientImpl = CoreClientTestAccess::impl(mClient.core());
  std::shared_ptr<FakeConnectionEstablisher> mEstablisher =
    std::make_shared<FakeConnectionEstablisher>(mPool.get_executor());

  ClientConnect()
  {
    CoreClientTestAccess::set_connection_establisher(*mClientImpl, mEstablisher);
  }

  static ConnectionConfig valid_config()
  {
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    return config;
  }

  // A round-trip fence on the single-thread pool: after it returns, every task queued before it has run
  // (including a Connection destruction + teardown-hook unregister posted by connect_async's chain).
  void drain_pool()
  {
    std::promise<void> fenced;
    auto future = fenced.get_future();
    boost::asio::post(mPool.get_executor(), [&fenced] { fenced.set_value(); });
    future.get();
  }
};

TEST_F(ClientConnect, SuccessfulConnectDeliversActiveConnectionAndRegisters)
{
  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  Connection connection = std::move(result).value();
  EXPECT_EQ(connection.state(), ConnectionState::Active);
  EXPECT_EQ(mEstablisher->establishCalls.load(), 1);
  EXPECT_EQ(CoreClientTestAccess::connection_registry_size(*mClientImpl), 1u)
    << "a successful connect registers the Connection in the W5 registry";
}

TEST_F(ClientConnect, EstablishFailureDeliversBadWithoutRegistering)
{
  mEstablisher->yieldBad = true;
  mEstablisher->badStatus = ua::StatusCode{ua::Status::BadConnectionRejected};

  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadConnectionRejected}.value());
  drain_pool();
  EXPECT_EQ(CoreClientTestAccess::connection_registry_size(*mClientImpl), 0u)
    << "a failed establish registers nothing";
}

TEST_F(ClientConnect, BootstrapFailureDeliversBadAndUnregisters)
{
  mEstablisher->bootstrapRead = ua::VoidResult{ua::Status::BadConnectionRejected};

  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());

  EXPECT_TRUE(result.is_bad()) << "a bootstrap-read failure fails the connect";
  drain_pool();
  EXPECT_EQ(CoreClientTestAccess::connection_registry_size(*mClientImpl), 0u)
    << "the teardown hook must unregister the Connection when bootstrap fails and the impl is dropped";
}

TEST_F(ClientConnect, InvalidPlanDeliversBadWithoutEstablishing)
{
  ConnectionConfig config = valid_config();
  config.endpointUrl.clear();

  ua::Result<Connection> result = mClient.try_connect_sync(config);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadInvalidArgument}.value());
  EXPECT_EQ(mEstablisher->establishCalls.load(), 0) << "an invalid plan must not reach the establisher";
}

// The public managed-connect boundary rejects a deprecated policy from the frozen default application
// configuration before the establisher can emit HEL/OPN traffic.
// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST_F(ClientConnect, DeprecatedPolicyRejectedBeforeEstablisherByDefault)
{
  ConnectionConfig config = valid_config();
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic128Rsa15;

  ua::Result<Connection> result = mClient.try_connect_sync(config);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
  ASSERT_TRUE(result.shared_detail());
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_NE(detail.find("Basic128Rsa15"), std::string::npos);
  EXPECT_NE(detail.find("AllowDeprecatedSecurityPolicies"), std::string::npos);
  EXPECT_EQ(mEstablisher->establishCalls.load(), 0)
    << "policy rejection must happen before any wire interface";
}

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientConnectPolicyOptIn, DeprecatedPolicyReachesEstablisherWhenExplicitlyAllowed)
{
  boost::asio::thread_pool pool{1};
  ua::client::CreateConfig createConfig{.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::ApplicationConfig::load_default(),
    .client = {}};
  createConfig.application.allowDeprecatedSecurityPolicies = true;
  Client client = Client::create(pool.get_executor(),
    std::move(createConfig),
    ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
  auto clientImpl = CoreClientTestAccess::impl(client.core());
  auto establisher = std::make_shared<FakeConnectionEstablisher>(pool.get_executor());
  CoreClientTestAccess::set_connection_establisher(*clientImpl, establisher);

  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://legacy.example:4840";
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic128Rsa15;
  auto result = client.try_connect_sync(config);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(establisher->establishCalls.load(), 1);
}

TEST_F(ClientConnect, SuccessfulConnectAppearsInTheRevalidationWalk)
{
  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());
  ASSERT_TRUE(result.is_good());
  Connection connection = std::move(result).value();

  // The registered Connection is reached by the W5 server-cert revalidation walk: its counting interface
  // fires.
  std::promise<ua::VoidResult> walked;
  mClientImpl->revalidate_connections_async(
    false, true, [&walked](ua::VoidResult r) { walked.set_value(std::move(r)); });
  ASSERT_EQ(walked.get_future().wait_for(5s), std::future_status::ready);
  drain_pool();
  EXPECT_EQ(mEstablisher->wireOpCalls->load(), 1)
    << "revalidate reached the registered Connection exactly once";
}

TEST_F(ClientConnect, DoubleEstablishFireRegistersAndDeliversOnce)
{
  mEstablisher->fireCount = 2;  // a misbehaving establisher fires its callback twice

  std::atomic<int> callbackCount{0};
  std::promise<void> firstDelivered;
  auto firstFuture = firstDelivered.get_future();
  std::optional<Connection> captured;  // hold the Connection alive so it stays registered
  mClient.connect_async(valid_config(),
    [&](ua::Result<Connection> result)
    {
      if (callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
      {
        captured.emplace(std::move(result).value());
        firstDelivered.set_value();
      }
    });
  ASSERT_EQ(firstFuture.wait_for(5s), std::future_status::ready);
  drain_pool();

  EXPECT_EQ(callbackCount.load(), 1) << "the fire-once guard delivers the user callback exactly once";
  EXPECT_EQ(CoreClientTestAccess::connection_registry_size(*mClientImpl), 1u)
    << "the establish double-fire guard must not double-register";
}

TEST_F(ClientConnect, ClientObserverDefaultsThreadedToEstablisher)
{
  struct DummyConnectionObserver : ua::client::ConnectionObserver
  {};

  auto observer = std::make_shared<DummyConnectionObserver>();
  mClient.set_connection_observer(observer);

  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());
  ASSERT_TRUE(result.is_good());

  ASSERT_TRUE(mEstablisher->lastDefaults.has_value());
  EXPECT_EQ(mEstablisher->lastDefaults->connection, observer)
    << "connect_async must thread the Client-level observer defaults into the establisher";
}

// --- section 3.1 regression tests
// ------------------------------------------------------------------------------

// section 3.1 finding: connect_async is noexcept; an internal throw must not std::terminate + drop the owed
// callback. It must be caught and delivered as a bad Result. (Falsifiability: without the try/catch the
// noexcept throw terminates the whole test process before the callback fires.)
TEST_F(ClientConnect, InternalThrowIsCaughtAndDeliveredAsBad)
{
  mEstablisher->throwOnEstablish = true;

  ua::Result<Connection> result = mClient.try_connect_sync(valid_config());

  EXPECT_TRUE(result.is_bad())
    << "an internal throw must be delivered as a bad connect result, not terminate";
}

// section 3.1 finding: the user callback is invoked inside an Asio post; a throwing user callback must be
// swallowed by ua::async::guarded, not escape into the io_context worker and std::terminate. Proof: a second
// connect still completes after the first callback throws (the worker survived).
TEST_F(ClientConnect, ThrowingUserCallbackIsSwallowedAndClientSurvives)
{
  std::promise<void> firstReached;
  mClient.connect_async(valid_config(),
    [&firstReached](ua::Result<Connection>)
    {
      firstReached.set_value();
      throw std::runtime_error("user connect callback throws");
    });
  ASSERT_EQ(firstReached.get_future().wait_for(5s), std::future_status::ready);
  drain_pool();

  ua::Result<Connection> second = mClient.try_connect_sync(valid_config());
  EXPECT_TRUE(second.is_good())
    << "the executor worker must survive a throwing user callback (guarded), so a later connect still works";
}

// section 3.1 finding: connectTimeout was a silent no-op. An overall connect deadline must fire Bad_Timeout
// when the tier-0 connect never completes. (Falsifiability: without the deadline timer, a stalled establisher
// hangs try_connect_sync forever.)
TEST_F(ClientConnect, ConnectTimeoutDeliversBadTimeoutWhenEstablishStalls)
{
  mEstablisher->stall = true;
  ConnectionConfig config = valid_config();
  config.connectTimeout = 50ms;

  ua::Result<Connection> result = mClient.try_connect_sync(config);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadTimeout}.value())
    << "an exceeded connectTimeout must deliver Bad_Timeout";
}

// section 3.1 re-review: the deadline timer's cancel() and expiry-completion must be serialised (they run on
// a private strand over the executor), so the connect is safe on a MULTI-threaded io_context. This runs the
// timeout path under a 2-thread pool and asserts exactly-one delivery (a TSan build would additionally
// surface any residual timer data race the strand is meant to prevent).
TEST(ClientConnectMultiThread, ConnectTimeoutIsThreadSafeUnderMultiThreadExecutor)
{
  boost::asio::thread_pool pool{2};
  Client client = ua::test_helpers::make_dev_client(pool.get_executor());
  auto establisher = std::make_shared<FakeConnectionEstablisher>(pool.get_executor());
  establisher->stall = true;
  CoreClientTestAccess::set_connection_establisher(*CoreClientTestAccess::impl(client.core()), establisher);

  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.connectTimeout = 50ms;

  std::atomic<int> callbackCount{0};
  std::promise<ua::Result<Connection>> done;
  client.connect_async(config,
    [&](ua::Result<Connection> result)
    {
      callbackCount.fetch_add(1, std::memory_order_relaxed);
      done.set_value(std::move(result));
    });

  auto result = done.get_future().get();
  std::promise<void> fenced;
  boost::asio::post(pool.get_executor(), [&fenced] { fenced.set_value(); });
  fenced.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadTimeout}.value());
  EXPECT_EQ(callbackCount.load(), 1) << "exactly one delivery even under a multi-threaded executor";
}
}  // namespace
