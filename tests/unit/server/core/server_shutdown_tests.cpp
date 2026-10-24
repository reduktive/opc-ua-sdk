// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <limits>
#include <gtest/gtest.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "ua_application_configuration.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_on_strand.h"
#include "ua_reverse_hello.h"
#include "ua_conditions.h"
#include "ua_server_impl.h"
#include "ua_server_session.h"
#include "ua_to_string.h"

#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_namespace_registration_coordinator.h"

#include "namespace_registration_coordinator_test_access.h"
#include "server_impl_test_access.h"
#include "test_utilities.h"

#include "async_test_runtime.h"
#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"

#include "test_components.h"
// These tests drive a live server over a background-threaded io_context via
// AsyncTestRuntime, declared as the first local in each test so it is destroyed
// LAST and drains all posted teardown work (including ~ServerImpl's close work)
// before ~io_context. See async_test_runtime.h for why this replaced the old
// workGuard/ioc.stop()/runner.join() teardown that caused the intermittent
// server-shutdown SIGSEGV.

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

shared_ptr<ServerImpl> create_test_server_impl(
  boost::asio::any_io_executor ex, std::shared_ptr<LogSink> logSink = nullptr)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.maxConnections = 100;
  sc.defaultShutdownGracePeriodSeconds = 2;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  auto server = ua::server::ServerImpl::create(ex,
    std::move(frozen),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto(), .logSink = std::move(logSink)});
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

/// Buffers every entry a logger emits, so a test can assert on logging that happens after the
/// component that issued the logger is gone.
///
/// Owned by the TEST, not by the server: that is the whole point. A `Logger` holds shared ownership
/// of its sink and its level, so a completion that COPIED the logger can still emit here with the
/// server destroyed, and one that reached the logger through a raw `this` cannot.
class RecordingLogSink final : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    const std::lock_guard lock(mMutex);
    mMessages.emplace_back(entry.message);
  }

  [[nodiscard]] bool saw(std::string_view fragment) const
  {
    const std::lock_guard lock(mMutex);
    return std::any_of(mMessages.begin(),
      mMessages.end(),
      [fragment](const std::string& message) { return message.find(fragment) != std::string::npos; });
  }

  /// Everything buffered, newline-separated, for a failure message that says what DID arrive.
  ///
  /// A test that only reports the absence of one line leaves the reader unable to tell "the
  /// completion ran and said something else" from "nothing was logged at all", and those are
  /// different defects.
  [[nodiscard]] std::string transcript() const
  {
    const std::lock_guard lock(mMutex);
    std::string joined;
    for (const auto& message : mMessages)
    {
      joined += "\n  ";
      joined += message;
    }
    return joined.empty() ? std::string{"<nothing was logged at all>"} : joined;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mMessages;
};

/// A registration participant that never answers until the test lets it.
///
/// Parking the preparation is what keeps a request outstanding in the coordinator's queue, which is
/// what makes the coordinator's DESTRUCTOR the thing that answers it.
class ParkingRegistrationParticipant final : public ua::detail::NamespaceRegistrationParticipant
{
public:
  void prepare_async(ua::detail::NamespaceRegistrationCandidate,
    ua::detail::NamespaceRegistrationPreparationCallback callback) noexcept override
  {
    {
      const std::lock_guard lock(mMutex);
      mParked.push_back(std::move(callback));
    }
    mCalled.notify_all();
  }

  bool wait_until_called()
  {
    std::unique_lock lock(mMutex);
    return mCalled.wait_for(lock, std::chrono::seconds{10}, [this] { return !mParked.empty(); });
  }

  void release_all()
  {
    std::vector<ua::detail::NamespaceRegistrationPreparationCallback> parked;
    {
      const std::lock_guard lock(mMutex);
      parked.swap(mParked);
    }
    for (auto& callback : parked)
    {
      // Answered as a FAILURE, because by the time a test releases these the server it was
      // preparing for is gone. What matters to the subject is that the request is answered at all -
      // that is what lets the coordinator reach the shutdown request queued behind it.
      callback(ua::detail::NamespaceRegistrationPreparationResult{ua::StatusCode{ua::Status::BadShutdown}});
    }
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCalled;
  std::vector<ua::detail::NamespaceRegistrationPreparationCallback> mParked;
};

struct ConnectionBundle
{
  shared_ptr<FakeConnectionProtocolDeps> deps;
  shared_ptr<FakeTransportConnection> transport;
  shared_ptr<ConnectionProtocol> protocol;
};

ConnectionBundle create_connection(boost::asio::any_io_executor ex)
{
  ConnectionBundle bundle;
  bundle.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
  bundle.transport = std::make_shared<FakeTransportConnection>();
  bundle.transport->stall_reads();

  bundle.protocol = ua::ConnectionProtocol::create(
    ua::ConnectionProtocolRole::Server,
    bundle.deps,
    bundle.transport,
    false,
    // Realistic handshake deadline (production config rejects a non-positive timeout). A 0s
    // timeout would arm a zero-delay deadline timer that fires on the io thread mid-construction.
    /*timeout*/ std::chrono::seconds{30},
    /*connectionCompleteCallback*/
    [](StatusCode,
      shared_ptr<ua::ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    /*errorCallback*/ [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  return bundle;
}

class ShutdownTestObserver : public ServerObserver
{
public:
  std::atomic<bool> shutdownInitiated{false};
  std::atomic<bool> shutdownComplete{false};
  std::atomic<uint32_t> secondsTillShutdown{0};
  LocalizedText shutdownReason;

  void on_shutdown_initiated(uint32_t seconds, const LocalizedText& reason) override
  {
    secondsTillShutdown = seconds;
    shutdownReason = reason;
    shutdownInitiated = true;
  }

  void on_shutdown_complete() override
  {
    shutdownComplete = true;
  }
};

class ReverseConnectTestObserver final : public ServerObserver
{
public:
  void on_reverse_connect_opened(const std::string& targetName, const std::string& remoteAddress) override
  {
    opened.emplace_back(targetName, remoteAddress);
  }

  void on_reverse_connect_closed(
    const std::string& targetName, const std::string& remoteAddress, StatusCode reason) override
  {
    closed.emplace_back(targetName, remoteAddress);
    closedReason = std::move(reason);
  }

  void on_reverse_connect_channel_established(
    const std::string& targetName, uint32_t secureChannelId) override
  {
    established.emplace_back(targetName, secureChannelId);
  }

  std::vector<std::pair<std::string, std::string>> opened;
  std::vector<std::pair<std::string, std::string>> closed;
  std::vector<std::pair<std::string, uint32_t>> established;
  StatusCode closedReason;
};

class ReverseConnectFailureObserver final : public ServerObserver
{
public:
  void on_reverse_connect_closed(
    const std::string& targetName, const std::string& remoteAddress, StatusCode reason) override
  {
    {
      const std::lock_guard lock{mMutex};
      mTargetName = targetName;
      mRemoteAddress = remoteAddress;
      mReason = std::move(reason);
    }
    mClosed.notify_all();
  }

  bool wait_for_target(std::string_view targetName, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mClosed.wait_for(lock, timeout, [&] { return mTargetName == targetName; });
  }

  std::string remote_address() const
  {
    const std::lock_guard lock{mMutex};
    return mRemoteAddress;
  }

  StatusCode reason() const
  {
    const std::lock_guard lock{mMutex};
    return mReason;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mClosed;
  std::string mTargetName;
  std::string mRemoteAddress;
  StatusCode mReason;
};

}  // namespace

// @relation(AC-SVR-RC-017-MULTIPLE-TARGETS, scope=function)
TEST(ServerObserverTests, CompositeObserverForwardsEveryReverseConnectEventToEveryDelegate)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto server = create_test_server_impl(runtime.executor());
  auto applicationObserver = std::make_shared<ReverseConnectTestObserver>();
  auto internalObserver = std::make_shared<ReverseConnectTestObserver>();
  server->set_observer(applicationObserver);
  TestAccess{*server}.add_internal_observer(internalObserver);

  auto composite = TestAccess{*server}.observer();
  ASSERT_NE(composite, nullptr);
  ASSERT_NE(composite, applicationObserver);
  ASSERT_NE(composite, internalObserver);

  const auto detail = std::shared_ptr<const ErrorDetail>{
    make_error_detail("ReverseConnectClosed", "Reverse connection closed", "ServerObserverTests")};
  const StatusCode closeReason{Status::BadConnectionClosed, detail};
  composite->on_reverse_connect_opened("Target-A", "127.0.0.1:4841");
  composite->on_reverse_connect_closed("Target-B", "127.0.0.1:4842", closeReason);
  composite->on_reverse_connect_channel_established("Target-C", 42);

  for (const auto& observer : {applicationObserver, internalObserver})
  {
    EXPECT_EQ(
      observer->opened, (std::vector<std::pair<std::string, std::string>>{{"Target-A", "127.0.0.1:4841"}}));
    EXPECT_EQ(
      observer->closed, (std::vector<std::pair<std::string, std::string>>{{"Target-B", "127.0.0.1:4842"}}));
    EXPECT_EQ(observer->closedReason, Status::BadConnectionClosed);
    EXPECT_EQ(observer->closedReason.shared_detail(), detail);
    EXPECT_EQ(observer->established, (std::vector<std::pair<std::string, uint32_t>>{{"Target-C", 42}}));
  }
}

// @relation(AC-SVR-RC-021-LIFECYCLE-OBSERVABLE, scope=function)
TEST(ServerObserverTests, FailedReverseConnectDialReachesApplicationWithItsRichCause)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto server = create_test_server_impl(runtime.executor());
  auto observer = std::make_shared<ReverseConnectFailureObserver>();
  server->set_observer(observer);

  boost::asio::io_context portContext;
  boost::asio::ip::tcp::acceptor reservation{portContext, {boost::asio::ip::tcp::v4(), 0}};
  const auto unusedPort = reservation.local_endpoint().port();
  reservation.close();

  ServerConfig::ReverseConnectTarget target;
  target.name = "UnreachableTarget";
  target.clientApplicationUri = "urn:test:unreachable-client";
  target.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", unusedPort);
  target.serverEndpointUrl = "opc.tcp://127.0.0.1:4840";
  target.periodicConnectInterval = std::chrono::hours{1};
  target.maxPendingSockets = 1;

  std::promise<ReverseConnectHandleResult> started;
  auto startedFuture = started.get_future();
  server->start_reverse_connect_async(std::move(target),
    [&started](ReverseConnectHandleResult result) { started.set_value(std::move(result)); });
  auto startResult = startedFuture.get();
  ASSERT_TRUE(startResult) << ua::to_string(startResult.status_code());

  ASSERT_TRUE(observer->wait_for_target("UnreachableTarget", std::chrono::seconds{5}));
  const auto reason = observer->reason();
  EXPECT_EQ(reason, Status::BadConnectionRejected);
  ASSERT_NE(reason.shared_detail(), nullptr);
  EXPECT_EQ(reason.shared_detail()->code, "TcpConnectFailed");
  EXPECT_TRUE(observer->remote_address().empty()) << "a refused dial has no connected peer address to report";

  std::promise<VoidResult> stopped;
  auto stoppedFuture = stopped.get_future();
  server->stop_reverse_connect_async(
    startResult.value(), [&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stoppedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(stoppedFuture.get());
  server->set_observer(nullptr);
}

TEST(ServerShutdownTests, ShutdownTransitionsState)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto dynamicState = TestAccess{*server}.dynamic_state();

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};
  params.reason = LocalizedText{"en", "Test shutdown"};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_EQ(dynamicState->serverState.load(), ServerState::Shutdown);

  auto result = p.get_future().wait_for(std::chrono::seconds{5});
  EXPECT_EQ(result, std::future_status::ready);
}

// A condition instance arms timers on the server's executor - shelving, re-alarm, branch
// upkeep - and the registry serialises its state on a strand. If shutdown leaves them
// running they are work the executor never finishes, and the Runtime's drain expires with
// BadTimeout naming nothing. Closing the registry is therefore part of shutting the server
// down, not something an application is expected to do.
//
// A registry that is still open answers a lookup for an absent condition with BadNotFound;
// a closed one answers BadShutdown. Probing after shutdown distinguishes the two without
// needing a live instance. The probe posts to the registry strand, which the close was
// posted to first, so strand ordering makes the observation deterministic.
TEST(ServerShutdownTests, ShutdownClosesTheConditionsRegistry)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{0};
  params.reason = LocalizedText{"en", "Test shutdown"};
  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });
  ASSERT_EQ(p.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  EXPECT_EQ(server->conditions().try_find_condition_sync(NodeId{1, 1000u}).status_code(),
    StatusCode{Status::BadShutdown})
    << "server shutdown must close the conditions registry; an open registry keeps its "
       "instances' timers on the executor and the drain expires with BadTimeout";
}

// Covers SVR-PULLCRT-019 (coverage-audit retag).
TEST(ServerShutdownTests, ShutdownSetsSecondsTillShutdown)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto dynamicState = TestAccess{*server}.dynamic_state();

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{3};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_EQ(dynamicState->secondsTillShutdown.load(), 3u);

  auto result = p.get_future().wait_for(std::chrono::seconds{5});
  EXPECT_EQ(result, std::future_status::ready);
}

// ShutdownOptions::grace is a duration (API-5.5); ServerStatus.SecondsTillShutdown is a UInt32. A negative
// grace is an immediate shutdown, and one longer than a UInt32 holds advertises the longest it can.
TEST(ServerShutdownTests, ANegativeGraceAdvertisesAnImmediateShutdown)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto server = create_test_server_impl(runtime.executor());
  auto dynamicState = TestAccess{*server}.dynamic_state();

  std::promise<VoidResult> p;
  server->shutdown_async(ShutdownOptions{.grace = std::chrono::seconds{-5}},
    [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_EQ(dynamicState->secondsTillShutdown.load(), 0u);
  EXPECT_EQ(p.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

TEST(ServerShutdownTests, AGraceLongerThanAUInt32AdvertisesTheLongestOne)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto server = create_test_server_impl(runtime.executor());
  auto dynamicState = TestAccess{*server}.dynamic_state();

  std::promise<VoidResult> p;
  const auto longest = std::chrono::seconds{std::numeric_limits<uint32_t>::max()};
  server->shutdown_async(ShutdownOptions{.grace = longest + std::chrono::seconds{10}},
    [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_EQ(dynamicState->secondsTillShutdown.load(), std::numeric_limits<uint32_t>::max());
  EXPECT_EQ(p.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "with no clients connected nothing waits out the grace period";
}

TEST(ServerShutdownTests, ShutdownSetsServiceLevelToZero)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto dynamicState = TestAccess{*server}.dynamic_state();

  // Verify initial service level is non-zero.
  EXPECT_EQ(dynamicState->serviceLevel.load(), 255u);

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_EQ(dynamicState->serviceLevel.load(), 0u);

  auto result = p.get_future().wait_for(std::chrono::seconds{5});
  EXPECT_EQ(result, std::future_status::ready);
}

TEST(ServerShutdownTests, ShutdownSetsShutdownReason)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto dynamicState = TestAccess{*server}.dynamic_state();

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};
  params.reason = LocalizedText{"en", "Maintenance window"};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  {
    std::shared_lock lk(dynamicState->mutex);
    EXPECT_EQ(dynamicState->shutdownReason.text(), "Maintenance window");
  }

  auto result = p.get_future().wait_for(std::chrono::seconds{5});
  EXPECT_EQ(result, std::future_status::ready);
}

TEST(ServerShutdownTests, ShutdownUsesConfigDefaultGracePeriod)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto dynamicState = TestAccess{*server}.dynamic_state();

  // Inject a connection so the grace period timer path is taken (not immediate shutdown).
  auto conn = create_connection(ex);
  TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn.protocol, {}, {});

  std::promise<VoidResult> p;
  ShutdownOptions params;
  // Leave params.seconds_till_shutdown as nullopt - that selects the config default per
  // ShutdownOptions docs. An explicit 0 would mean "immediate", not "use default".

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  // The config default is 2 seconds.
  EXPECT_EQ(dynamicState->secondsTillShutdown.load(), 2u);

  // Wait for the shutdown timer to complete.
  auto result = p.get_future().wait_for(std::chrono::seconds{10});
  EXPECT_EQ(result, std::future_status::ready);
}

TEST(ServerShutdownTests, ShutdownNotifiesObserver)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto observer = std::make_shared<ShutdownTestObserver>();
  server->set_observer(observer);

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};
  params.reason = LocalizedText{"en", "Observer test"};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  EXPECT_TRUE(observer->shutdownInitiated.load());
  EXPECT_EQ(observer->secondsTillShutdown.load(), 1u);

  auto result = p.get_future().wait_for(std::chrono::seconds{5});
  EXPECT_EQ(result, std::future_status::ready);
}

TEST(ServerShutdownTests, ShutdownCompletionCallbackFires)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  auto future = p.get_future();
  auto status = future.wait_for(std::chrono::seconds{5});
  ASSERT_EQ(status, std::future_status::ready);

  auto result = future.get();
  EXPECT_TRUE(result.is_good());
}

TEST(ServerShutdownTests, DoubleShutdownReturnsBadInvalidState)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);

  // First shutdown.
  std::promise<VoidResult> p1;
  ShutdownOptions params1;
  params1.grace = std::chrono::seconds{1};
  server->shutdown_async(std::move(params1), [&p1](VoidResult result) { p1.set_value(std::move(result)); });

  auto f1 = p1.get_future();
  auto s1 = f1.wait_for(std::chrono::seconds{5});
  ASSERT_EQ(s1, std::future_status::ready);
  EXPECT_TRUE(f1.get().is_good());

  // Second shutdown should fail with BadInvalidState.
  std::promise<VoidResult> p2;
  ShutdownOptions params2;
  params2.grace = std::chrono::seconds{1};
  server->shutdown_async(std::move(params2), [&p2](VoidResult result) { p2.set_value(std::move(result)); });

  auto f2 = p2.get_future();
  auto s2 = f2.wait_for(std::chrono::seconds{5});
  ASSERT_EQ(s2, std::future_status::ready);

  auto result2 = f2.get();
  EXPECT_TRUE(result2.is_bad());
  EXPECT_EQ(result2.status_code(), StatusCode{Status::BadInvalidState});
}

TEST(ServerShutdownTests, NewConnectionRejectedDuringShutdown)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);

  // Shutdown first (no clients, completes immediately).
  std::promise<VoidResult> shutdownPromise;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};
  server->shutdown_async(std::move(params),
    [&shutdownPromise](VoidResult result) { shutdownPromise.set_value(std::move(result)); });

  auto shutdownFuture = shutdownPromise.get_future();
  ASSERT_EQ(shutdownFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);

  // Now try to inject a new connection - should be rejected.
  auto conn = create_connection(ex);
  TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn.protocol, {}, {});

  // The transport should receive an ERR message and be closed.
  ASSERT_TRUE(conn.transport->wait_for_write_count(1, std::chrono::milliseconds{2000}));

  auto allWrites = conn.transport->writes();
  ASSERT_FALSE(allWrites.empty());

  // Verify ERRF message header.
  const auto& err = allWrites.front();
  ASSERT_GE(err.size(), ua::connection_protocol::headerSize);
  EXPECT_EQ(static_cast<char>(err[0]), 'E');
  EXPECT_EQ(static_cast<char>(err[1]), 'R');
  EXPECT_EQ(static_cast<char>(err[2]), 'R');
  EXPECT_EQ(static_cast<char>(err[3]), 'F');

  EXPECT_TRUE(conn.transport->wait_for_close(std::chrono::milliseconds{2000}));
}

// Deterministic replacement for the intermittent 8-shard shutdown-teardown
// std::terminate (ComplianceSecuredWithSession.RequestServerStateChange_...).
//
// ServerDependencies holds weak_ptr<ServerImpl> and its immutable accessors
// throw when the server has been destroyed - which legitimately happens when an
// in-flight async continuation resumes during shutdown drain, after ~ServerImpl.
// The fix keeps the throw (callers consume it via ua::async::guarded) but changes
// the dead-server StatusCode from BadInternalError to BadInvalidState. This test
// pins that contract: a dependency accessor invoked after the server is gone
// throws a UaException carrying Bad_InvalidState, not BadInternalError.
//
// Falsifiability: before the fix this asserted-against status was BadInternalError;
// if an accessor silently returned (made total) instead of throwing, the
// EXPECT_TRUE(threw) guards would fail.
TEST(ServerShutdownTests, DeadServerDependencyAccessorsThrowBadInvalidState)
{
  std::weak_ptr<ServerImpl> weakServer;
  shared_ptr<SessionDependencies> deps;

  {
    ua::test_helpers::AsyncTestRuntime runtime;
    auto ex = runtime.executor();

    auto server = create_test_server_impl(ex);
    weakServer = server;
    deps = TestAccess{*server}.session_dependencies();
    ASSERT_TRUE(deps);

    // Shut down and wait so complete_shutdown() drops the server's strong
    // self-references, then drop our own; the runtime drains ~ServerImpl on
    // destruction at the end of this block.
    std::promise<VoidResult> p;
    ShutdownOptions params;
    params.grace = std::chrono::seconds{1};
    server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });
    ASSERT_EQ(p.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

    server.reset();
  }

  ASSERT_TRUE(weakServer.expired())
    << "the ServerImpl must be destroyed so its dependency weak_ptr expires (the drain condition)";

  // Every immutable accessor must throw Bad_InvalidState now that the server is gone.
  auto expectThrowsInvalidState = [&](auto&& accessor, const char* name)
  {
    bool threw = false;
    try
    {
      accessor();
    }
    catch (const ua::UaException& ex)
    {
      threw = true;
      EXPECT_EQ(ex.status(), Status::BadInvalidState) << name << " threw the wrong status";
    }
    EXPECT_TRUE(threw) << name << " must throw once the server is destroyed";
  };

  expectThrowsInvalidState([&] { (void)deps->server_configuration(); }, "server_configuration()");
  expectThrowsInvalidState([&] { (void)deps->configuration(); }, "configuration()");
  expectThrowsInvalidState([&] { (void)deps->crypto(); }, "crypto()");

  // And consuming that throw through ua::async::guarded must NOT propagate - the
  // exact mechanism that protects the noexcept Asio drain boundary.
  EXPECT_NO_THROW(ua::async::guarded(ua::Logger{}, [&] { (void)deps->server_configuration(); })());
}

TEST(ServerShutdownTests, ImmediateShutdownWithNoClients)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto server = create_test_server_impl(ex);
  auto observer = std::make_shared<ShutdownTestObserver>();
  server->set_observer(observer);

  std::promise<VoidResult> p;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{1};

  server->shutdown_async(std::move(params), [&p](VoidResult result) { p.set_value(std::move(result)); });

  auto future = p.get_future();
  auto status = future.wait_for(std::chrono::seconds{5});
  ASSERT_EQ(status, std::future_status::ready);

  auto result = future.get();
  EXPECT_TRUE(result.is_good());

  // Observer should have received both initiated and complete notifications.
  EXPECT_TRUE(observer->shutdownInitiated.load());
  EXPECT_TRUE(observer->shutdownComplete.load());
}

// A caller that passes no callback still has the server started: the start reaches namespace preparation,
// and its failure is logged rather than dropped.
// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST(ServerShutdownTests, AStartWithoutACallbackStillStartsAndLogsItsFailure)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto sink = std::make_shared<RecordingLogSink>();
  auto participant = std::make_shared<ParkingRegistrationParticipant>();
  auto server = create_test_server_impl(runtime.executor(), sink);
  ua::test_helpers::NamespaceRegistrationCoordinatorTestAccess::install_participant(
    server->address_space(), participant);

  server->start_async(nullptr);
  ASSERT_TRUE(participant->wait_until_called()) << "a start without a callback never began";
  participant->release_all();

  const auto deadline = std::chrono::steady_clock::now() + ua::test_utils::default_poll_budget();
  while (!sink->saw("Call made without a completion callback failed") &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  }
  EXPECT_TRUE(sink->saw("Call made without a completion callback failed"))
    << "the failed start was not logged. What the sink did receive:" << sink->transcript();

  std::promise<VoidResult> stopped;
  ShutdownOptions params;
  params.grace = std::chrono::seconds{0};
  server->shutdown_async(std::move(params), [&stopped](VoidResult result) { stopped.set_value(result); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{10}), std::future_status::ready);
}

// The namespace-stop completion runs after the server that handed it out is gone.
//
// `complete_shutdown` asks every namespace to stop and hands out ONE completion for the answer. That
// completion is also queued inside `NamespaceRegistrationCoordinator`, whose destructor drains its
// queue - the shutdown request included - when the last POSTED handler holding the coordinator drops
// it, on a strand turn AFTER `~ServerImpl` has returned. This test pins that reachability: a parked
// registration participant keeps the coordinator's queue outstanding, the server is destroyed, and
// only then is the preparation released, so the completion is answered with nothing of the server
// left. If a later change makes the completion unreachable after `~ServerImpl`, this goes red.
//
// WHAT THIS TEST DOES NOT DO, stated because the name would otherwise overclaim. It does not detect
// the use-after-free that reachability allows. The completion used to capture raw `this` and reach
// `mLogger` through it; after `~ServerImpl` that is freed memory, but freed memory under an ordinary
// allocator is still mapped and still holds the old bytes, so the log line is emitted either way and
// the assertion below passes on the broken code. Verified, not assumed: with the fix reverted this
// test passed twice.
//
// The defect is only observable under an allocator that poisons what it frees:
//
//     MALLOC_CHECK_=3 MALLOC_PERTURB_=165 ./tests --gtest_filter='ServerPart18WiringTest.*'
//     broken: exit 139, SIGSEGV, core dumped, on the first iteration - the faulting read is
//             `Logger::is_enabled` on 0xa5a5a5a5a5a5a5a5, and 0xa5 is the poison byte
//     fixed:  exit 0, 19 tests passed, three iterations
//
// That command is the falsification for the fix. This test is the falsification for the ORDERING the
// fix has to survive, which is the part a reader can otherwise only get from a commit message.
TEST(ServerShutdownTests, TheNamespaceStopCompletionIsAnsweredAfterTheServerIsDestroyed)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  auto sink = std::make_shared<RecordingLogSink>();
  auto participant = std::make_shared<ParkingRegistrationParticipant>();

  std::promise<VoidResult> shutdownPromise;
  auto shutdownFuture = shutdownPromise.get_future();
  {
    auto server = create_test_server_impl(ex, sink);
    ua::test_helpers::NamespaceRegistrationCoordinatorTestAccess::install_participant(
      server->address_space(), participant);

    // Starting asks every installed participant to prepare the namespaces that already exist. This
    // one never answers, so the coordinator has a request outstanding from here on.
    server->start_async([](VoidResult) {});
    ASSERT_TRUE(participant->wait_until_called())
      << "the registration participant was never asked to prepare, so nothing was ever outstanding";

    ShutdownOptions params;
    params.grace = std::chrono::seconds{0};
    server->shutdown_async(
      std::move(params), [&shutdownPromise](VoidResult result) { shutdownPromise.set_value(result); });

    // Waited for, and this is the whole reason the test works. `complete_shutdown` reaches the
    // namespaces THROUGH the conditions close, and that continuation holds a weak self-reference -
    // so a server destroyed before the close completes never hands the completion out at all, and
    // the defect is never reached. A closed registry answers a lookup with BadShutdown where an
    // open one answers BadNotFound, which makes "the close has completed" observable.
    const auto closedBy = std::chrono::steady_clock::now() + ua::test_utils::default_poll_budget();
    while (server->conditions().try_find_condition_sync(NodeId{1, 1000u}).status_code() !=
             StatusCode{Status::BadShutdown} &&
           std::chrono::steady_clock::now() < closedBy)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_EQ(server->conditions().try_find_condition_sync(NodeId{1, 1000u}).status_code(),
      StatusCode{Status::BadShutdown})
      << "the conditions registry never closed, so the namespace-stop completion was never handed "
         "out and the subject of this test was never reached";
  }
  // The server is gone. Its namespace-stop completion is not: it is still sitting in the
  // coordinator's queue, and releasing the parked preparation is what finally answers it.
  participant->release_all();

  ASSERT_EQ(shutdownFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "the shutdown caller was never answered at all";

  // Polled rather than asserted outright: the completion logs and then answers its caller, but
  // nothing in the contract orders the two against THIS thread, and a budget that bounds a hang
  // asserts no latency. A run that needs the whole budget still passes.
  const auto deadline = std::chrono::steady_clock::now() + ua::test_utils::default_poll_budget();
  while (!sink->saw("did not stop its background work") && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  }

  EXPECT_TRUE(sink->saw("did not stop its background work"))
    << "the namespace-stop completion never ran after the server was destroyed, so the ordering this "
       "test exists to pin no longer happens and the lifetime rule it protects is untested. What the "
       "sink did receive:"
    << sink->transcript();
}
