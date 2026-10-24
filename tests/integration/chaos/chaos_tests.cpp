// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Network-fault-injection (chaos) integration tests.
///
/// These tests put a real toxiproxy proxy (running in Docker) in front of the server so the
/// client connects through a controllable, degradable TCP link. They prove that the server
/// recovers from a mid-session link break AND leaks no resources: after recovery and a clean
/// disconnect the server's live session / subscription / secure-channel counts return to their
/// pre-chaos baseline.
///
/// The leak baseline is read directly from the public `Server::health_snapshot()` accessor
/// (sdk/interface/server/ua_server_health.h), which samples the live atomic gauges
/// (`current_session_count`, `current_subscription_count`, `current_secure_channel_count`).
/// Reading through this accessor - rather than via the address space - keeps the assertion
/// valid even while the proxy link is broken or torn down.
///
/// If toxiproxy is not reachable (no Docker), each test FAILS naming the missing toxiproxy admin API.
/// Local runs default to host networking. CI supplies separate listen, endpoint, bind, and
/// upstream addresses so toxiproxy can forward between service and build containers. Locally:
///   docker run -d --rm --name toxiproxy --network host ghcr.io/shopify/toxiproxy
///   cmake -E chdir cmake-build-debug-gcc/tests ./integration_tests --gtest_filter='Chaos.*'

#include "environment_variable.h"
#include "toxiproxy_control.h"

#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <unistd.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>

#include "ua_test_server.h"

#include "ua_built_in_authenticators.h"
#include "ua_core_client.h"
#include "ua_connection_impl.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_reconnect_policy.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_session_attribute_services.h"
#include "ua_session_subscription_services.h"

#include "subscription.h"  // create_subscription_with_monitored_item, try_publish_once

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_server_state.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// Reads a single Int32/Server-state value via try_read_sync. Returns nullopt if the service
/// call itself failed (e.g. the channel broke), so the caller can detect the link break without
/// an exception.
std::optional<int32_t> try_read_server_state(Session& session)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;

  auto resp = session.attributes().try_read_sync(std::move(req));
  if (!resp.is_good())
    return std::nullopt;
  const auto& response = resp.value();
  if (response.response_header().service_result().is_bad())
    return std::nullopt;
  if (response.results().empty() || response.results()[0].status().has_value())
    return std::nullopt;
  auto value = response.results()[0].value().try_as<int32_t>();
  if (!value)
    return std::nullopt;
  return *value;
}

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionState;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::ReconnectWiring;

/// Thread-safe counter of DataChange notifications delivered to a monitored-item callback (the callback
/// runs on the client executor, the test asserts from its own thread).
class DataChangeSink
{
public:
  void push()
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mCount;
  }

  std::size_t count() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mCount;
  }

private:
  mutable std::mutex mMutex;
  std::size_t mCount = 0;
};

/// Thread-safe capture of the LATEST Int32 value delivered to a monitored-item callback, plus a count.
/// Used to prove subscription delivery deterministically by writing a known value and awaiting it.
class Int32Sink
{
public:
  void push(const DataValue& value)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDelivered;
    mLastStatus = value.status().value_or(StatusCode{Status::Good});
    if (auto asInt = value.value().try_as<int32_t>())
    {
      mLast = *asInt;
      ++mCount;
    }
  }

  /// What was delivered, for a failure message: every DataChange counts, Int32 or not.
  std::string describe() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return "delivered " + std::to_string(mDelivered) + " DataChange(s), " + std::to_string(mCount) +
           " Int32, last status 0x" + fmt::format("{:08X}", mLastStatus.as_uint32()) +
           (mLast ? ", last value " + std::to_string(*mLast) : std::string{", no value"});
  }

  std::optional<int32_t> last() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLast;
  }

private:
  mutable std::mutex mMutex;
  std::optional<int32_t> mLast;
  std::size_t mCount = 0;
  std::size_t mDelivered = 0;
  StatusCode mLastStatus{Status::Good};
};

/// Polls @p predicate until true or @p timeout elapses; returns whether it became true (never throws).
template<typename Predicate>
bool wait_until(Predicate predicate, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(20ms);
  }
  return predicate();
}

/// Blocking bridges over the ConnectionImpl async surface (the pool auto-runs the work).
VoidResult conn_start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

VoidResult conn_close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

Result<std::uint32_t> conn_create_subscription_and_wait(ConnectionImpl& connection, double publishingInterval)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_subscription_async(
    publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

Result<std::uint32_t> conn_create_monitored_item_and_wait(ConnectionImpl& connection,
  std::uint32_t subscriptionId, const NodeId& node, std::uint32_t clientHandle,
  std::function<void(DataValue)> onData)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_monitored_item_async(subscriptionId,
    node,
    clientHandle,
    std::move(onData),
    [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Writes an Int32 to a node's Value attribute through the orchestrator and blocks until complete.
Result<WriteResponse> conn_write_int32_and_wait(ConnectionImpl& connection, const NodeId& node, int32_t value)
{
  WriteRequest request;
  WriteValue writeValue;
  writeValue.node_id() = node;
  writeValue.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
  writeValue.value() = DataValue{Variant{value}};
  request.nodes_to_write().push_back(std::move(writeValue));
  std::promise<Result<WriteResponse>> promise;
  auto future = promise.get_future();
  connection.write_async(
    std::move(request), [&promise](Result<WriteResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

// ---------------------------------------------------------------------------
// Chaos: server with a SHORT session-minimum-timeout so an orphaned
// session (left behind when the link is severed before a graceful close) is
// reaped quickly enough for a bounded zero-leak assertion. The OPC UA spec
// (10000-4 section 5.6.2) keeps a session alive across a channel break until its
// revised timeout elapses, so the timeout must be small for the test to settle.
// ---------------------------------------------------------------------------
/// A loopback port free at the time of the call: the kernel picks it for a socket bound to port 0. Each test
/// process (one per shard) therefore uses its own ports, where fixed ports made parallel runs collide.
std::uint16_t free_loopback_port()
{
  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor acceptor{
    io, boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address("127.0.0.1"), 0}};
  return acceptor.local_endpoint().port();
}

/// A toxiproxy proxy name of this process and test, so concurrent test processes never reuse one.
std::string chaos_proxy_name()
{
  static std::atomic<int> counter{0};
  return "ua_chaos_" + std::to_string(::getpid()) + "_" + std::to_string(++counter);
}

class Chaos : public ::testing::Test
{
protected:
  static constexpr auto sSessionTimeout = 2000ms;

  void SetUp() override
  {
    // The client connects to the proxy URL, so the HEL it sends carries the proxy's
    // host:port. The server validates the HEL EndpointUrl by port+path against the
    // listener's advertised URL (Part 6 section 7.1.2.3), so the listener must advertise the
    // proxy URL - exactly the NAT/load-balancer case `externalUrl` exists for. The server
    // binds a fixed local port (the proxy's upstream) so we know it without a listener handle.
    mProxyListen = read_environment_variable("UA_CHAOS_TOXIPROXY_LISTEN")
                     .value_or("127.0.0.1:" + std::to_string(free_loopback_port()));
    mProxyEndpoint = read_environment_variable("UA_CHAOS_TOXIPROXY_ENDPOINT").value_or(mProxyListen);
    mServerBind = read_environment_variable("UA_CHAOS_SERVER_BIND")
                    .value_or("127.0.0.1:" + std::to_string(free_loopback_port()));
    mProxyUpstream = read_environment_variable("UA_CHAOS_TOXIPROXY_UPSTREAM").value_or(mServerBind);
    mProxyEndpointUrl = std::string{"opc.tcp://"} + mProxyEndpoint;

    mServer.create(
      [](ua::ApplicationConfig& app)
      {
        // Allow a 2s session timeout so a severed session is reaped within the test window.
        app.stack_limits().sessionMinimumTimeout = sSessionTimeout;
        app.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{3'600'000};
      },
      [this](ua::server::ServerConfig& server)
      {
        ServerEndpointConfig endpoint;
        endpoint.name = "None";
        endpoint.messageSecurityMode = MessageSecurityMode::None;
        endpoint.securityPolicyId = SecurityPolicyId::None;
        endpoint.userIdentityTokens.push_back(
          create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

        ua::server::ServerConfig::ListenerConfig listener;
        listener.name = "chaos";
        listener.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
        listener.bind.address = mServerBind;
        // Advertise the proxy URL so the HEL EndpointUrl (which carries the proxy port) is
        // accepted by the server's port+path validator.
        listener.externalUrl = ua::transport::EndpointUrl{mProxyEndpointUrl};
        listener.endpoints.push_back(std::move(endpoint));
        server.listeners().push_back(std::move(listener));
      });

    // A bind failure throws out of start() and fails the test: the chaos suite needs its port.
    mServer.start();

    // The server's sink is installed by TestServer::create (test_log_sink()); wire the client here.
    mClient.emplace(CoreClient::create(mClientThreadPool.executor(),
      ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
        .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "chaos-client");
  }

  // Polls health_snapshot() until the three live gauges match `expected`, or the timeout
  // elapses. Returns the final snapshot either way.
  ServerHealthSnapshot wait_for_health(
    const ServerHealthSnapshot& expected, std::chrono::milliseconds timeout)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    ServerHealthSnapshot snap = mServer.server().health_snapshot();
    while (std::chrono::steady_clock::now() < deadline)
    {
      snap = mServer.server().health_snapshot();
      if (snap.currentSessionCount == expected.currentSessionCount &&
          snap.currentSubscriptionCount == expected.currentSubscriptionCount &&
          snap.currentSecureChannelCount == expected.currentSecureChannelCount)
        return snap;
      std::this_thread::sleep_for(50ms);
    }
    return snap;
  }

  // Creates the toxiproxy proxy using independently configurable listen and upstream addresses.
  // This matters in CI, where the service container and build container do not share loopback.
  // nullopt if the proxy could not be created (the caller fails the test).
  std::optional<ToxiproxyControl::Proxy> make_proxy(ToxiproxyControl& toxiproxy)
  {
    return toxiproxy.create_proxy(chaos_proxy_name(), mProxyListen, mProxyUpstream);
  }

  // Opens a channel + session through the proxy and reads ServerState. Returns the value on
  // a fully successful round-trip, nullopt otherwise. The channel/session are closed before
  // returning, so this is a self-contained probe of link health.
  std::optional<int32_t> probe_through_proxy(const std::string& proxyUrl)
  {
    auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyUrl});
    if (!channelResult.is_good())
      return std::nullopt;
    auto channel = std::move(channelResult).value();
    auto sessionResult = channel.try_create_session_sync(
      {.requestedSessionTimeout = sSessionTimeout, .sessionName = "ChaosProbe"});
    std::optional<int32_t> state;
    if (sessionResult.is_good())
    {
      auto session = std::move(sessionResult).value();
      if (session.try_activate_sync().is_good())
        state = try_read_server_state(session);
      (void)session.try_close_sync();
    }
    (void)channel.try_close_sync();
    return state;
  }

  // After a fault is removed, prove a fresh channel+session+read succeeds within the window.
  void expect_recovers(const std::string& proxyUrl)
  {
    std::optional<int32_t> recovered;
    for (int attempt = 0; attempt < 40 && !recovered.has_value(); ++attempt)
    {
      recovered = probe_through_proxy(proxyUrl);
      if (!recovered.has_value())
        std::this_thread::sleep_for(100ms);
    }
    ASSERT_TRUE(recovered.has_value()) << "Client could not reconnect and read after recovery";
    EXPECT_EQ(*recovered, static_cast<int32_t>(ServerState::Running));
  }

  // Asserts the live gauges return to `baseline` (no leaked session/subscription/channel).
  void expect_no_leak(const ServerHealthSnapshot& baseline)
  {
    const ServerHealthSnapshot snap = wait_for_health(baseline, sSessionTimeout + 8000ms);
    EXPECT_EQ(snap.currentSessionCount, baseline.currentSessionCount)
      << "Leaked sessions: " << snap.currentSessionCount << " vs baseline " << baseline.currentSessionCount;
    EXPECT_EQ(snap.currentSubscriptionCount, baseline.currentSubscriptionCount)
      << "Leaked subscriptions: " << snap.currentSubscriptionCount << " vs baseline "
      << baseline.currentSubscriptionCount;
    EXPECT_EQ(snap.currentSecureChannelCount, baseline.currentSecureChannelCount)
      << "Leaked secure channels: " << snap.currentSecureChannelCount << " vs baseline "
      << baseline.currentSecureChannelCount;
  }

  TestServer mServer;
  boost::asio::thread_pool mClientThreadPool;
  std::string mProxyListen;
  std::string mProxyEndpoint;
  std::string mServerBind;
  std::string mProxyUpstream;
  std::string mProxyEndpointUrl;  // advertised via the listener's externalUrl
  std::optional<CoreClient> mClient;
};

}  // namespace

// ---------------------------------------------------------------------------
// Chaos.ResetPeerMidSession_RecoversAndLeaksNothing
//
//  1. Baseline = health_snapshot() before any chaos.
//  2. Create a toxiproxy proxy: listen on a published local port, upstream = server.
//  3. Connect the client THROUGH the proxy; open a session, create a subscription, read.
//  4. Inject a deterministic `reset_peer` toxic; drive a request and observe the break.
//  5. Remove the toxic; open a FRESH channel + session and read - recovery succeeds.
//  6. Clean disconnect; assert the live session/subscription/secure-channel gauges return
//     to baseline (the severed session/channel were reaped, not leaked).
// ---------------------------------------------------------------------------
TEST_F(Chaos, ResetPeerMidSession_RecoversAndLeaksNothing)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable())
    << "missing precondition: " << "toxiproxy admin API not reachable at "
    << ToxiproxyControl::default_admin_url()
    << " - start it with: docker run -d --rm --name toxiproxy "
       "--network host ghcr.io/shopify/toxiproxy  (host networking is required so "
       "the container can forward to the in-process server's loopback port)";

  // --- 1. Zero-leak baseline -------------------------------------------------
  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  ASSERT_EQ(baseline.currentSessionCount, 0u) << "Server should start with no sessions";
  ASSERT_EQ(baseline.currentSubscriptionCount, 0u) << "Server should start with no subscriptions";

  // --- 2. Create the proxy in front of the server ---------------------------
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value())
    << "missing precondition: " << "Could not create toxiproxy proxy on " << mProxyListen
    << " (toxiproxy must share this process's network, e.g. docker run "
       "--network host, or UA_CHAOS_TOXIPROXY_LISTEN / UA_CHAOS_TOXIPROXY_ENDPOINT / "
       "UA_CHAOS_SERVER_BIND must name reachable addresses).";

  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // --- 3. Connect THROUGH the proxy and drive normal traffic ----------------
  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "Could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  ASSERT_TRUE(channel.is_open());

  auto session = channel.create_session_sync(
    {.requestedSessionTimeout = sSessionTimeout, .sessionName = "ChaosResetPeer"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // A subscription bumps current_subscription_count - part of the leak invariant.
  CreateSubscriptionRequest subReq;
  subReq.requested_publishing_interval() = 200.0;
  subReq.requested_lifetime_count() = 100;
  subReq.requested_max_keep_alive_count() = 10;
  subReq.max_notifications_per_publish() = 0;
  subReq.publishing_enabled() = true;
  subReq.priority() = 0;
  auto subResp = session.subscriptions().create_subscription_sync(std::move(subReq));
  ASSERT_NE(subResp.subscription_id(), 0u);

  // Normal read succeeds through the healthy proxy.
  auto preChaosState = try_read_server_state(session);
  ASSERT_TRUE(preChaosState.has_value()) << "Read failed before chaos was injected";
  EXPECT_EQ(*preChaosState, static_cast<int32_t>(ServerState::Running));

  // Confirm the server now holds exactly the resources we created.
  {
    ServerHealthSnapshot active = mServer.server().health_snapshot();
    EXPECT_EQ(active.currentSessionCount, 1u);
    EXPECT_EQ(active.currentSubscriptionCount, 1u);
    EXPECT_GE(active.currentSecureChannelCount, 1u);
  }

  // --- 4. Inject the fault: RST the connection on the next byte -------------
  ASSERT_TRUE(proxy->add_toxic("rst",
    ToxiproxyControl::ToxicType::ResetPeer,
    ToxiproxyControl::Stream::Downstream,
    "timeout",
    0,
    /*toxicity=*/1.0))
    << "Failed to add reset_peer toxic";

  // Drive requests until the client observes the break. reset_peer with timeout=0 tears down
  // the connection on the next forwarded byte; the in-flight or next read must fail.
  bool brokeUnderChaos = false;
  for (int attempt = 0; attempt < 40; ++attempt)
  {
    if (!try_read_server_state(session).has_value())
    {
      brokeUnderChaos = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(brokeUnderChaos) << "Client did not detect the severed link under reset_peer";

  // --- 5. Remove the toxic and prove recovery with a FRESH session ----------
  ASSERT_TRUE(proxy->remove_toxic("rst")) << "Failed to remove reset_peer toxic";

  // The old channel/session are dead; drop them so the client tears down its side.
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  // A fresh channel+session+read must succeed now that the link is healthy again.
  expect_recovers(proxyEndpointUrl);

  // --- 6. Zero-leak invariant: the severed session/channel were reaped, not leaked --------
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.LatencyInjected_SessionSurvives
//
// A latency toxic delays every byte in both directions. The session must keep
// working (reads succeed, just slower) rather than spuriously dropping, and no
// resources leak once the degraded link is removed.
// ---------------------------------------------------------------------------
TEST_F(Chaos, LatencyInjected_SessionSurvives)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // 120 ms each way (~240 ms round-trip) - degraded but within client timeouts.
  ASSERT_TRUE(proxy->add_toxic(
    "lat_down", ToxiproxyControl::ToxicType::Latency, ToxiproxyControl::Stream::Downstream, "latency", 120));
  ASSERT_TRUE(proxy->add_toxic(
    "lat_up", ToxiproxyControl::ToxicType::Latency, ToxiproxyControl::Stream::Upstream, "latency", 120));

  // Every round-trip over the slow link must still succeed.
  for (int i = 0; i < 3; ++i)
  {
    auto state = probe_through_proxy(proxyEndpointUrl);
    ASSERT_TRUE(state.has_value()) << "read " << i << " failed under injected latency";
    EXPECT_EQ(*state, static_cast<int32_t>(ServerState::Running));
  }

  proxy->remove_toxic("lat_down");
  proxy->remove_toxic("lat_up");
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.SlicedStream_ReassemblesAndDoesNotLeak
//
// The slicer fragments every TCP segment into small pieces WITH a per-piece delay,
// so the SDK's transport reader sees partial messages on each read() and must
// reassemble them (TCP carries no message boundaries). A successful round-trip proves
// the framing/reassembly is robust to pathological segmentation - the OPC UA
// chunk-boundary case.
// ---------------------------------------------------------------------------
TEST_F(Chaos, SlicedStream_ReassemblesAndDoesNotLeak)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // ~32-byte fragments, 2 ms (2000 us) between them: the delay defeats kernel coalescing so
  // each app-level read returns a partial message.
  const std::vector<std::pair<std::string, int64_t>> slice = {{"average_size", 32}, {"delay", 2000}};
  ASSERT_TRUE(proxy->add_toxic(
    "slice_down", ToxiproxyControl::ToxicType::Slicer, ToxiproxyControl::Stream::Downstream, slice));
  ASSERT_TRUE(proxy->add_toxic(
    "slice_up", ToxiproxyControl::ToxicType::Slicer, ToxiproxyControl::Stream::Upstream, slice));

  // The full handshake + read must complete despite per-read fragmentation.
  auto state = probe_through_proxy(proxyEndpointUrl);
  ASSERT_TRUE(state.has_value()) << "read failed under TCP slicing - message reassembly is broken";
  EXPECT_EQ(*state, static_cast<int32_t>(ServerState::Running));

  proxy->remove_toxic("slice_down");
  proxy->remove_toxic("slice_up");
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.TimeoutStall_DropsAndRecovers
//
// A timeout toxic stalls the downstream (server->client) data and then closes the
// connection after 600 ms. This is a distinct failure mode from a RST: the link goes
// silent, then drops. The client must detect the dead link, and after the toxic is
// removed a fresh session must recover with the stalled session reaped, not leaked.
// ---------------------------------------------------------------------------
TEST_F(Chaos, TimeoutStall_DropsAndRecovers)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = sSessionTimeout, .sessionName = "ChaosTimeout"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());
  ASSERT_TRUE(try_read_server_state(session).has_value()) << "read failed before the stall";

  // Stall, then drop: data stops and the connection is closed after 600 ms (bounded detection).
  ASSERT_TRUE(proxy->add_toxic(
    "stall", ToxiproxyControl::ToxicType::Timeout, ToxiproxyControl::Stream::Downstream, "timeout", 600));

  bool broke = false;
  for (int attempt = 0; attempt < 60; ++attempt)
  {
    if (!try_read_server_state(session).has_value())
    {
      broke = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(broke) << "client did not detect the stalled-then-closed link";

  ASSERT_TRUE(proxy->remove_toxic("stall"));
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
  expect_recovers(proxyEndpointUrl);
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.BandwidthThrottled_HandshakeStillCompletes
//
// A bandwidth toxic caps throughput in both directions. The handshake + read is only
// a few KB, so it must still complete - just slowly - proving the SDK tolerates a
// low-bandwidth pipe (distinct from latency: a rate cap, not a per-byte delay).
// ---------------------------------------------------------------------------
TEST_F(Chaos, BandwidthThrottled_HandshakeStillCompletes)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // 32 KB/s each way - clearly throttled but within client connect/request timeouts.
  ASSERT_TRUE(proxy->add_toxic(
    "bw_down", ToxiproxyControl::ToxicType::Bandwidth, ToxiproxyControl::Stream::Downstream, "rate", 32));
  ASSERT_TRUE(proxy->add_toxic(
    "bw_up", ToxiproxyControl::ToxicType::Bandwidth, ToxiproxyControl::Stream::Upstream, "rate", 32));

  auto state = probe_through_proxy(proxyEndpointUrl);
  ASSERT_TRUE(state.has_value()) << "session/read did not complete under bandwidth throttling";
  EXPECT_EQ(*state, static_cast<int32_t>(ServerState::Running));

  proxy->remove_toxic("bw_down");
  proxy->remove_toxic("bw_up");
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.SlowClose_TeardownDoesNotHangOrLeak
//
// A slow_close toxic delays the TCP FIN on every connection close. A round-trip that
// opens + closes a session must still complete promptly (the SDK must not block on the
// lingering FIN) and leak nothing.
// ---------------------------------------------------------------------------
TEST_F(Chaos, SlowClose_TeardownDoesNotHangOrLeak)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  ASSERT_TRUE(proxy->add_toxic("slow_close",
    ToxiproxyControl::ToxicType::SlowClose,
    ToxiproxyControl::Stream::Downstream,
    "delay",
    300));

  auto state = probe_through_proxy(proxyEndpointUrl);
  ASSERT_TRUE(state.has_value()) << "session round-trip failed under slow_close";
  EXPECT_EQ(*state, static_cast<int32_t>(ServerState::Running));

  proxy->remove_toxic("slow_close");
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.SubscriptionUnderReset_ReapsSubscriptionAndItems
//
// Scenario test (not just an idle session): a subscription with a monitored item on a
// value that changes every cycle is actively publishing when the link is severed. The
// stalled session - and the subscription + monitored item it owns - must be reaped, not
// leaked. current_subscription_count returning to baseline proves the MI under it is gone.
// ---------------------------------------------------------------------------
TEST_F(Chaos, SubscriptionUnderReset_ReapsSubscriptionAndItems)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  ASSERT_EQ(baseline.currentSubscriptionCount, 0u) << "server should start with no subscriptions";
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session = channel.create_session_sync(
    {.requestedSessionTimeout = sSessionTimeout, .sessionName = "ChaosSubscription"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Monitor a value that changes every publish cycle, so notifications are in flight.
  auto sub = create_subscription_with_monitored_item(
    session, NodeId{VariableId::Server_ServerStatus_CurrentTime}, {.publishingInterval = 100.0});
  ASSERT_NE(sub.subscriptionId, 0u);
  ASSERT_NE(sub.monitoredItemId, 0u);

  // Drive the notification path, then confirm the server holds the subscription.
  (void)try_publish_once(session);
  {
    const ServerHealthSnapshot active = mServer.server().health_snapshot();
    EXPECT_EQ(active.currentSessionCount, 1u);
    EXPECT_EQ(active.currentSubscriptionCount, 1u);
  }

  // Sever the link while the subscription is actively publishing.
  ASSERT_TRUE(proxy->add_toxic(
    "rst", ToxiproxyControl::ToxicType::ResetPeer, ToxiproxyControl::Stream::Downstream, "timeout", 0));
  bool broke = false;
  for (int attempt = 0; attempt < 40; ++attempt)
  {
    if (!try_read_server_state(session).has_value())
    {
      broke = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(broke) << "client did not detect the severed link";

  ASSERT_TRUE(proxy->remove_toxic("rst"));
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
  expect_recovers(proxyEndpointUrl);

  // The subscription + its monitored item are reaped with the timed-out session.
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.ChannelRenewalUnderLatency_SurvivesAndDoesNotLeak
//
// A short channel lifetime forces frequent renewal OPNs (the SDK renews before expiry).
// With the link degraded by latency, reading for far longer than the lifetime requires
// repeated successful renewals over the slow path - and the retired channel epochs must
// not leak. (Relies on the server honouring the short requested lifetime.)
// ---------------------------------------------------------------------------
TEST_F(Chaos, ChannelRenewalUnderLatency_SurvivesAndDoesNotLeak)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable()) << "missing precondition: " << "toxiproxy admin API not reachable at "
                                     << ToxiproxyControl::default_admin_url();

  const ServerHealthSnapshot baseline = mServer.server().health_snapshot();
  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  auto channelResult = mClient->try_open_channel_sync(
    {.endpointUrl = proxyEndpointUrl, .requestedLifetime = std::chrono::milliseconds{1500}});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session = channel.create_session_sync(
    {.requestedSessionTimeout = std::chrono::milliseconds{30'000}, .sessionName = "ChaosRenew"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Degrade the link so each renewal OPN traverses a slow path.
  ASSERT_TRUE(proxy->add_toxic(
    "lat_down", ToxiproxyControl::ToxicType::Latency, ToxiproxyControl::Stream::Downstream, "latency", 80));
  ASSERT_TRUE(proxy->add_toxic(
    "lat_up", ToxiproxyControl::ToxicType::Latency, ToxiproxyControl::Stream::Upstream, "latency", 80));

  // Read for ~6 s - well past the 1.5 s lifetime, so the channel must renew several times
  // under the degraded link for every read to keep succeeding.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{6000};
  int successfulReads = 0;
  while (std::chrono::steady_clock::now() < deadline)
  {
    auto state = try_read_server_state(session);
    ASSERT_TRUE(state.has_value()) << "read " << successfulReads
                                   << " failed - channel renewal did not survive the degraded link";
    EXPECT_EQ(*state, static_cast<int32_t>(ServerState::Running));
    ++successfulReads;
    std::this_thread::sleep_for(300ms);
  }
  EXPECT_GE(successfulReads, 10) << "too few reads to have spanned a renewal";

  proxy->remove_toxic("lat_down");
  proxy->remove_toxic("lat_up");
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
  // The repeated renewals must not leave stale secure-channel epochs behind.
  expect_no_leak(baseline);
}

// ---------------------------------------------------------------------------
// Chaos.ConnectionImplAutoDetectsRealDropAndReconnects  (task R2 / CL-RECONN-001)
//
// The tier-1 ConnectionImpl orchestrator, driving a live subscription through the proxy, must
// AUTOMATICALLY detect a real transport drop (its Publish pump is the keep-alive channel) and drive the
// reconnect FSM WITHOUT any manual trigger - the behaviour ua_connection_impl's publish-result drop
// detection adds. When the link heals the reconnect must rebind the session onto the fresh channel and
// wire ops must flow again (section 8.3, CL-RECONN-001..003).
//
// SCOPE: this validates AUTOMATIC DROP DETECTION + connection recovery. It deliberately does NOT assert
// that the subscription resumes delivering notifications: reconnect_recover_subscriptions is currently a
// documented no-op stub (subscription transfer/republish/recreate after reconnect is unimplemented - see
// CL-RECONN-004), so a monitored item does not survive the rebind yet. The subscription here exists only
// to keep the Publish pump active so the drop rides the Publish path. Subscription survival is tracked
// separately; wiring it will let this test add a "notifications resume" assertion.
// ---------------------------------------------------------------------------
TEST_F(Chaos, ConnectionImplAutoDetectsRealDropAndReconnects)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable())
    << "missing precondition: " << "toxiproxy admin API not reachable at "
    << ToxiproxyControl::default_admin_url()
    << " - start it with: docker run -d --rm --name toxiproxy --network host "
       "ghcr.io/shopify/toxiproxy";

  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // Connect THROUGH the proxy and hand the activated session to a ConnectionImpl whose reconnect wiring
  // also reopens THROUGH the proxy (so a healed proxy lets the reconnect succeed).
  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  // Request a generous session timeout: this test asserts survival + recovery (not leak reaping), so the
  // session must outlive the short reconnect outage and be TRANSFERRED onto the fresh channel rather than
  // timing out server-side and forcing a recreate. (The fixture's 2s minimum is for the leak tests.)
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = 30s, .sessionName = "ChaosConnImplReconnect"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = proxyEndpointUrl](auto callback)
  {
    client->open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  ReconnectPolicy policy;
  // A realistic backoff: the server enforces a per-IP connection rate limit (30/min), so a hot retry
  // loop would exhaust it during the outage and the reconnect would then be REJECTED even after the link
  // heals. Spacing attempts keeps the handful of reopens during the short toxic window under that limit.
  policy.backoff.base = 250ms;
  policy.backoff.max = 500ms;
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(conn_start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  // Monitor Server_ServerStatus_CurrentTime (changes every cycle), so DataChange notifications flow on
  // their own and the pump is genuinely active (the drop signal rides the Publish path).
  DataChangeSink sink;
  auto subId = conn_create_subscription_and_wait(*connection, /*publishingInterval=*/100.0);
  ASSERT_TRUE(subId.is_good()) << "create_subscription failed: 0x" << std::hex
                               << subId.status_code().as_uint32();
  auto miResult = conn_create_monitored_item_and_wait(*connection,
    subId.value(),
    NodeId{VariableId::Server_ServerStatus_CurrentTime},
    /*clientHandle=*/1,
    [&sink](DataValue) { sink.push(); });
  ASSERT_TRUE(miResult.is_good()) << "create_monitored_item failed: 0x" << std::hex
                                  << miResult.status_code().as_uint32();

  // Notifications flow through the healthy proxy.
  ASSERT_TRUE(wait_until([&] { return sink.count() >= 1; }, 8s)) << "no notifications before the drop";

  // Inject a real transport drop: RST the connection on the next forwarded byte.
  ASSERT_TRUE(proxy->add_toxic(
    "rst", ToxiproxyControl::ToxicType::ResetPeer, ToxiproxyControl::Stream::Downstream, "timeout", 0, 1.0))
    << "failed to add reset_peer toxic";

  // KEY ASSERTION 1 (automatic drop detection): the failing Publish must move the connection out of Active
  // and into Reconnecting WITHOUT any manual trigger_reconnect call.
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto state = connection->info()->state;
      return state == ConnectionState::Reconnecting || state == ConnectionState::Failed;
    },
    10s))
    << "automatic drop detection did not move the connection out of Active";
  EXPECT_EQ(connection->info()->state, ConnectionState::Reconnecting)
    << "the auto-detected drop must drive Reconnecting (retrying through the down proxy), not Failed";

  // Heal the link; the reconnect (retrying through the proxy) must now succeed and return to Active.
  ASSERT_TRUE(proxy->remove_toxic("rst")) << "failed to remove reset_peer toxic";
  ASSERT_TRUE(wait_until([&] { return connection->info()->state == ConnectionState::Active; }, 20s))
    << "the connection did not recover to Active after the link healed";

  // KEY ASSERTION 2 (the session was rebound onto the fresh channel): a wire op flows again.
  {
    ReadRequest request;
    ReadValueId nodeToRead;
    nodeToRead.node_id() = NodeId{VariableId::Server_ServerStatus_State};
    nodeToRead.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
    request.nodes_to_read().push_back(std::move(nodeToRead));
    request.timestamps_to_return() = TimestampsToReturn::Both;
    std::promise<Result<ReadResponse>> promise;
    auto future = promise.get_future();
    connection->read_async(
      std::move(request), [&promise](Result<ReadResponse> result) { promise.set_value(std::move(result)); });
    auto readResult = future.get();
    EXPECT_TRUE(readResult.is_good())
      << "post-reconnect read failed: 0x" << std::hex << readResult.status_code().as_uint32();
  }

  EXPECT_TRUE(conn_close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// Chaos.ConnectionImplSubscriptionSurvivesRealDrop  (task R2 / CL-RECONN-001..004)
//
// The DEFINITIVE subscription-survival test, using a WRITABLE node whose value the test controls (rather
// than a self-changing node like CurrentTime, which only delivers an initial value here and confounds the
// signal). A monitored item watches the node; the test writes a known value BEFORE the drop (proving the
// subscription delivers) and a second known value AFTER the auto-detected reconnect. If the subscription
// survived the same-session channel rebind, the post-reconnect write's DataChange must be delivered.
// ---------------------------------------------------------------------------
TEST_F(Chaos, ConnectionImplSubscriptionSurvivesRealDrop)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable())
    << "missing precondition: " << "toxiproxy admin API not reachable at "
    << ToxiproxyControl::default_admin_url()
    << " - start it with: docker run -d --rm --name toxiproxy --network host "
       "ghcr.io/shopify/toxiproxy";

  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  // Create a writable Int32 node BEFORE connecting so it is in the NamespaceArray the client bootstraps.
  auto addressSpace = mServer.server().address_space();
  auto testNamespace = default_ns::Namespace::create("urn:test:chaos", mServer.thread_pool().executor());
  // A namespace that declares no RolePermissions grants nobody access to its nodes; give it the well-known
  // role defaults, as an application namespace does, so the anonymous session may read and monitor the node.
  testNamespace->set_namespace_defaults(
    ua::server::well_known_role_default_permissions(ua::server::well_known_roles()), std::nullopt);
  const auto nsIndex = addressSpace.add_namespace_sync(testNamespace);
  const NodeId writableNode{nsIndex, std::uint32_t{1000}};
  {
    auto node = addressSpace.create_node_sync(writableNode, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{nsIndex, "ChaosWritableInt32"});
    variable->set_display_name(LocalizedText{"", "ChaosWritableInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(std::int32_t{0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, writableNode);
  }

  // Connect THROUGH the proxy; hand the activated session to a ConnectionImpl that reopens through it.
  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = 30s, .sessionName = "ChaosSubSurvive"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = proxyEndpointUrl](auto callback)
  {
    client->open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  ReconnectPolicy policy;
  policy.backoff.base = 250ms;  // stay under the server's per-IP connection rate limit during the outage
  policy.backoff.max = 500ms;
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(conn_start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  Int32Sink sink;
  auto subId = conn_create_subscription_and_wait(*connection, /*publishingInterval=*/100.0);
  ASSERT_TRUE(subId.is_good()) << "create_subscription failed: 0x" << std::hex
                               << subId.status_code().as_uint32();
  auto miResult = conn_create_monitored_item_and_wait(
    *connection, subId.value(), writableNode, /*clientHandle=*/1, [&sink](DataValue v) { sink.push(v); });
  ASSERT_TRUE(miResult.is_good()) << "create_monitored_item failed: 0x" << std::hex
                                  << miResult.status_code().as_uint32();

  // PRE-DROP: write a known value and require its DataChange - proves the subscription genuinely delivers
  // (this is the check the CurrentTime probe silently failed).
  ASSERT_TRUE(conn_write_int32_and_wait(*connection, writableNode, 100).is_good()) << "pre-drop write failed";
  ASSERT_TRUE(wait_until([&] { return sink.last() == 100; }, 8s))
    << "no pre-drop DataChange for the written value - the subscription is not delivering even before the "
       "drop; "
    << sink.describe();

  // Sever the link: the failing Publish must auto-drive Reconnecting (no manual trigger).
  ASSERT_TRUE(proxy->add_toxic(
    "rst", ToxiproxyControl::ToxicType::ResetPeer, ToxiproxyControl::Stream::Downstream, "timeout", 0, 1.0))
    << "failed to add reset_peer toxic";
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto state = connection->info()->state;
      return state == ConnectionState::Reconnecting || state == ConnectionState::Failed;
    },
    10s))
    << "automatic drop detection did not move the connection out of Active";

  // Heal the link and require recovery to Active.
  ASSERT_TRUE(proxy->remove_toxic("rst")) << "failed to remove reset_peer toxic";
  ASSERT_TRUE(wait_until([&] { return connection->info()->state == ConnectionState::Active; }, 20s))
    << "the connection did not recover to Active after the link healed";

  // POST-RECONNECT: write a second known value. If the subscription SURVIVED the rebind, its DataChange
  // must be delivered. This is the definitive survival assertion.
  ASSERT_TRUE(conn_write_int32_and_wait(*connection, writableNode, 200).is_good())
    << "post-reconnect write failed";
  const bool survived = wait_until([&] { return sink.last() == 200; }, 10s);
  EXPECT_TRUE(survived) << "the subscription did NOT survive the reconnect: no DataChange delivered for the "
                           "post-reconnect write (last delivered value = "
                        << (sink.last() ? std::to_string(*sink.last()) : std::string{"<none>"}) << ")";

  EXPECT_TRUE(conn_close_and_wait(*connection).is_good());
}

// End-to-end proof of the section 6.7 Republish-on-reconnect drain (#23): a value written to the monitored
// node WHILE THE CLIENT IS DISCONNECTED is queued in the server's retransmission queue and must be RECOVERED
// via Republish on reconnect - delivered to the monitored item BEFORE any post-reconnect live write. This
// exercises the whole recovery path (recover_subscriptions_async -> pipeline_republish -> deliver), not just
// post-reconnect live publishing (which ConnectionImplSubscriptionSurvivesRealDrop covers).
TEST_F(Chaos, ConnectionImplRepublishRecoversDuringOutageWrite)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable())
    << "missing precondition: " << "toxiproxy admin API not reachable at "
    << ToxiproxyControl::default_admin_url()
    << " - start it with: docker run -d --rm --name toxiproxy --network host "
       "ghcr.io/shopify/toxiproxy";

  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  auto addressSpace = mServer.server().address_space();
  auto testNamespace =
    default_ns::Namespace::create("urn:test:chaos-republish", mServer.thread_pool().executor());
  // A namespace that declares no RolePermissions grants nobody access to its nodes (see the first test).
  testNamespace->set_namespace_defaults(
    ua::server::well_known_role_default_permissions(ua::server::well_known_roles()), std::nullopt);
  const auto nsIndex = addressSpace.add_namespace_sync(testNamespace);
  const NodeId writableNode{nsIndex, std::uint32_t{1001}};
  {
    auto node = addressSpace.create_node_sync(writableNode, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{nsIndex, "ChaosRepublishInt32"});
    variable->set_display_name(LocalizedText{"", "ChaosRepublishInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(std::int32_t{0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, writableNode);
  }

  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = 30s, .sessionName = "ChaosRepublish"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = proxyEndpointUrl](auto callback)
  {
    client->open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  ReconnectPolicy policy;
  policy.backoff.base = 250ms;
  policy.backoff.max = 500ms;
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(conn_start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  Int32Sink sink;
  auto subId = conn_create_subscription_and_wait(*connection, /*publishingInterval=*/100.0);
  ASSERT_TRUE(subId.is_good()) << "create_subscription failed: 0x" << std::hex
                               << subId.status_code().as_uint32();
  auto miResult = conn_create_monitored_item_and_wait(
    *connection, subId.value(), writableNode, /*clientHandle=*/1, [&sink](DataValue v) { sink.push(v); });
  ASSERT_TRUE(miResult.is_good()) << "create_monitored_item failed: 0x" << std::hex
                                  << miResult.status_code().as_uint32();

  // PRE-DROP: write 100 via the client and require its DataChange - proves the subscription delivers.
  ASSERT_TRUE(conn_write_int32_and_wait(*connection, writableNode, 100).is_good()) << "pre-drop write failed";
  ASSERT_TRUE(wait_until([&] { return sink.last() == 100; }, 8s)) << "no pre-drop DataChange for value 100";

  // Sever the link: the failing Publish auto-drives Reconnecting.
  ASSERT_TRUE(proxy->add_toxic(
    "rst", ToxiproxyControl::ToxicType::ResetPeer, ToxiproxyControl::Stream::Downstream, "timeout", 0, 1.0))
    << "failed to add reset_peer toxic";
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto state = connection->info()->state;
      return state == ConnectionState::Reconnecting || state == ConnectionState::Failed;
    },
    10s))
    << "automatic drop detection did not move the connection out of Active";

  // DURING THE OUTAGE: write 300 DIRECTLY on the server (the client is disconnected). The server's
  // subscription samples the change and queues its NotificationMessage in the retransmission queue (there is
  // no live Publish to carry it). It CANNOT be delivered while the client is severed.
  {
    auto serverVariable = addressSpace.find_node_sync(writableNode).as<VariableAccessor>();
    ASSERT_TRUE(serverVariable.has_value());
    serverVariable->write_value_sync(std::int32_t{300});
  }
  // Let the server sample + queue it (several 100ms publishing intervals), still severed.
  std::this_thread::sleep_for(700ms);
  EXPECT_EQ(sink.last(), 100) << "the during-outage value must NOT reach the client while it is disconnected";

  // Heal the link -> reconnect -> the recover step Republishes the queued NotificationMessage.
  ASSERT_TRUE(proxy->remove_toxic("rst")) << "failed to remove reset_peer toxic";
  ASSERT_TRUE(wait_until([&] { return connection->info()->state == ConnectionState::Active; }, 20s))
    << "the connection did not recover to Active after the link healed";

  // DEFINITIVE: the during-outage value (300) is delivered via Republish on reconnect, with NO
  // post-reconnect write. Without the Republish-on-reconnect drain the client would never see it.
  const bool recovered = wait_until([&] { return sink.last() == 300; }, 10s);
  EXPECT_TRUE(recovered)
    << "the during-outage write (300) was NOT recovered via Republish on reconnect (last delivered value = "
    << (sink.last() ? std::to_string(*sink.last()) : std::string{"<none>"}) << ")";

  EXPECT_TRUE(conn_close_and_wait(*connection).is_good());
}

// End-to-end proof of the KEEP-ALIVE (section 8.2A.6, CL-RECONN-009): a SUBSCRIPTION-LESS Connection issues
// no Publishes, so a SILENT link stall (the downstream freezes with NO RST - no channel error) is invisible
// to the Publish-fatal drop path. ONLY the keep-alive poll (a periodic Server.ServerStatus.State read that
// times out at the poll cadence) can detect it. This drives the Connection out of Active on a silent stall
// with zero subscriptions, then recovers when the stall heals.
TEST_F(Chaos, KeepAliveDetectsSilentStallOnSubscriptionlessConnection)
{
  ToxiproxyControl toxiproxy;
  ASSERT_TRUE(toxiproxy.reachable())
    << "missing precondition: " << "toxiproxy admin API not reachable at "
    << ToxiproxyControl::default_admin_url()
    << " - start it with: docker run -d --rm --name toxiproxy --network host "
       "ghcr.io/shopify/toxiproxy";

  auto proxy = make_proxy(toxiproxy);
  ASSERT_TRUE(proxy.has_value()) << "missing precondition: " << "could not create toxiproxy proxy on "
                                 << mProxyListen;
  const std::string& proxyEndpointUrl = mProxyEndpointUrl;

  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = proxyEndpointUrl});
  ASSERT_TRUE(channelResult.is_good())
    << "could not open channel through the proxy: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = 30s, .sessionName = "ChaosKeepAlive"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  ReconnectWiring wiring;
  wiring.reopenChannel = [client = &*mClient, url = proxyEndpointUrl](auto callback)
  {
    client->open_channel_async({.endpointUrl = url}, std::move(callback));
  };
  wiring.activateConfig = Session::ActivateConfig{};
  ReconnectPolicy policy;
  policy.backoff.base = 250ms;
  policy.backoff.max = 500ms;
  policy.backoff.jitterPct = 0.0;
  wiring.policy = policy;
  // A SHORT keep-alive so a silent stall is detected well inside the test window: 2 missed 300ms polls.
  wiring.keepAlive = KeepAlivePolicy{/*interval=*/300ms, /*missedBeforeReconnect=*/2};

  auto connection = ConnectionImpl::create(mClientThreadPool.executor(),
    std::move(session),
    ua::client::detail::ConnectionConfig{},
    Logger{},
    std::move(wiring));
  ASSERT_TRUE(conn_start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);
  // Deliberately NO subscription / monitored item: the keep-alive is the ONLY liveness signal.

  // Inject a SILENT stall: the downstream (server -> client) freezes and never closes (timeout 0), so there
  // is no RST and no channel error. The Publish-fatal path cannot see it; only the keep-alive read (which
  // never gets its response) times out and, after two misses, drives the reconnect.
  ASSERT_TRUE(proxy->add_toxic(
    "stall", ToxiproxyControl::ToxicType::Timeout, ToxiproxyControl::Stream::Downstream, "timeout", 0))
    << "failed to add timeout (silent-stall) toxic";
  const bool detected = wait_until(
    [&]
    {
      const auto state = connection->info()->state;
      return state == ConnectionState::Reconnecting || state == ConnectionState::Failed;
    },
    15s);
  EXPECT_TRUE(detected)
    << "the keep-alive must detect a SILENT stall on a subscription-less connection - nothing else can";

  // Heal the stall -> the reconnect (already in flight) reaches the server and recovers to Active.
  ASSERT_TRUE(proxy->remove_toxic("stall")) << "failed to remove the timeout toxic";
  EXPECT_TRUE(wait_until([&] { return connection->info()->state == ConnectionState::Active; }, 25s))
    << "the connection did not recover to Active after the silent stall healed";

  EXPECT_TRUE(conn_close_and_wait(*connection).is_good());
}
