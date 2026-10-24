// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Reverse Connect End-to-End Integration Tests
///
/// Verifies the full reverse connect pipeline with real Server and Client:
/// 1. Client starts a reverse connect listener on an ephemeral port
/// 2. Server starts a ReverseConnectListener targeting that listener
/// 3. Server connects outbound, sends ReverseHello
/// 4. Client's open_channel with ConnectMode::Reverse consumes the connection
/// 5. OPN handshake completes, session/service operations work normally

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <functional>
#include <future>
#include <string>
#include <vector>

#include "compliance_helpers.h"

#include "ua_attribute_id.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reverse_connect_config.h"
#include "ua_server_configuration.h"
#include "ua_server_health.h"
#include "ua_server_state.h"
#include "ua_session_attribute_services.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

/// The Client's ApplicationUri. Part 6 section 7.1.3 (SVR-RC-012) makes this administrator-supplied
/// data the server requires per target, and `ReverseConnectListener::start()` refuses a target that is
/// missing it - it reports `BadInvalidArgument` through `on_reverse_connect_error` and never dials.
/// Every target in this suite therefore carries one; a target without it never reaches the socket
/// the obligations below are stated over.
constexpr const char* clientApplicationUri = "urn:test:reverse-connect:client";

/// Find a free TCP port by binding to port 0 and immediately closing.
uint16_t find_free_port()
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(
    ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
  auto port = acceptor.local_endpoint().port();
  acceptor.close();
  return port;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture: sets up Server with an ephemeral listener plus Client, but does
// NOT start reverse connect - individual tests configure their own targets.
// ---------------------------------------------------------------------------
class ReverseConnectIntegration : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer = std::make_unique<TestServer>();
    mServer->create();

    // Server needs at least one normal listener so it has configured endpoints.
    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    mListener = mServer->listen_ephemeral();
    mServer->add_endpoint(mListener, endpoint);
    mServer->start();

    auto urls = mServer->server().advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mServerEndpointUrl = urls.front().str();

    mServerApplicationUri =
      mServer->server().config().application->application_description_part().applicationUri;

    auto logSink = test_log_sink();
    mLogSink = logSink;
    // The server's sink is installed by TestServer::create (test_log_sink()); wire the client here.
    // The long form, not Client::create(executor, sink, level): this suite reverse-connects over a
    // None endpoint and then creates Sessions on it, which the client refuses unless the
    // application opts in. create_test_config() carries that opt-in.
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = ua::test_utils::create_test_config()};
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    // Stop the client's reverse connect listener before destroying anything, so it
    // stops accepting new inbound connections from the server.
    if (mClientReverseConnectHandle != client::ReverseConnectHandle{})
    {
      (void)mClient->core().try_stop_reverse_connect_sync(mClientReverseConnectHandle);
      mClientReverseConnectHandle = {};
    }

    // Destroy the server first (stops its reverse connect managers and closes all
    // connections) before stopping the client thread pool. Otherwise the server
    // keeps hammering TCP connections to the now-dead listener, creating leaked
    // ConnectionProtocol instances that never complete their handshake.
    mServer.reset();

    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  /// Start a reverse connect listener on the client side and return the port it should bind to.
  /// Uses find_free_port() to allocate an ephemeral port.
  /// Blocks until the listener is fully bound and ready to accept connections.
  uint16_t start_client_listener()
  {
    auto port = find_free_port();

    ReverseConnectListenerConfig listenerConfig;
    listenerConfig.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    listenerConfig.bind.address = fmt::format("127.0.0.1:{}", port);
    listenerConfig.expectedServers.push_back(ExpectedServer{
      .serverUri = mServerApplicationUri,
      .endpointUrls = {mServerEndpointUrl},
    });
    listenerConfig.maxQueuedConnections = 5;
    listenerConfig.initialMessageTimeout = std::chrono::seconds{10};

    mClientReverseConnectHandle = mClient->core().start_reverse_connect_sync(std::move(listenerConfig));

    // The listener's start() posts acceptor bind to its strand asynchronously.
    // The Client API does not yet expose a bind-readiness signal end-to-end,
    // so we use a brief sleep as a transitional measure.
    // TODO: plumb ReverseConnectListener::start() callback through CoreClientImpl
    // to eliminate this sleep.
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    return port;
  }

  /// Start a reverse connect target on the server side, pointing at the given client port.
  server::ReverseConnectHandle start_server_reverse_connect(uint16_t clientPort)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = "TestTarget";
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", clientPort);
    target.serverEndpointUrl = mServerEndpointUrl;

    // Copy endpoints from the normal listener.
    target.endpoints = mServer->server().endpoints(mListener);

    target.periodicConnectInterval = std::chrono::seconds{2};
    target.maxPendingSockets = 5;

    return mServer->server().start_reverse_connect_sync(std::move(target));
  }

  std::unique_ptr<TestServer> mServer;
  boost::asio::thread_pool mClientThreadPool;
  ListenerHandle mListener{0};
  std::string mServerEndpointUrl;
  std::string mServerApplicationUri;
  std::shared_ptr<LogSink> mLogSink;
  std::optional<Client> mClient;
  client::ReverseConnectHandle mClientReverseConnectHandle{};
};

// ---------------------------------------------------------------------------
// RC-001: Basic reverse connect - open channel, create session, read ServerState
// ---------------------------------------------------------------------------
// @relation(SVR-RC-010, SVR-RC-011, SVR-RC-019, SVR-RC-024, SVR-RC-025, scope=function)
TEST_F(ReverseConnectIntegration, BasicReverseConnectAndRead)
{
  auto clientPort = start_client_listener();
  auto serverRcHandle = start_server_reverse_connect(clientPort);

  // Open channel via reverse connect. The server should have connected to our listener.
  auto channel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel.is_open()) << "Channel should be open after reverse connect";

  // Create and activate a session.
  auto session = channel.create_session_sync({.sessionName = "RC-001"});
  ASSERT_TRUE(session.is_created());
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Read Server_ServerStatus_State to verify the session works.
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;

  auto resp = session.attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_FALSE(resp.results()[0].status().has_value())
    << "Read failed: 0x" << std::hex << resp.results()[0].status().value().as_uint32();

  auto val = resp.results()[0].value().as<int32_t>();
  EXPECT_EQ(val, static_cast<int32_t>(ServerState::Running));

  // Clean up.
  session.close_sync();
  channel.close_sync();
  mServer->server().stop_reverse_connect_sync(serverRcHandle);
}

// ---------------------------------------------------------------------------
// RC-002: Stop reverse connect target dynamically
// ---------------------------------------------------------------------------
// @relation(SVR-RC-018, SVR-RC-025, scope=function)
TEST_F(ReverseConnectIntegration, StopReverseConnectTarget)
{
  auto clientPort = start_client_listener();
  auto serverRcHandle = start_server_reverse_connect(clientPort);

  // Verify the reverse connect target can be stopped without error.
  auto stopResult = mServer->server().try_stop_reverse_connect_sync(serverRcHandle);
  EXPECT_TRUE(stopResult.is_good()) << "Stopping reverse connect should succeed";

  // Stopping again should fail (handle no longer valid).
  auto stopAgainResult = mServer->server().try_stop_reverse_connect_sync(serverRcHandle);
  EXPECT_TRUE(stopAgainResult.is_bad()) << "Stopping an already-stopped target should fail";
}

// ---------------------------------------------------------------------------
// RC-003: Reverse connect open_channel times out when no server connects
// ---------------------------------------------------------------------------
// @relation(SVR-RC-009, SVR-RC-025, scope=function)
TEST_F(ReverseConnectIntegration, ReverseConnectTimesOutWhenNoServerConnects)
{
  auto clientPort = start_client_listener();

  // Do NOT start a server reverse connect target - the client will wait and timeout.
  auto result = mClient->core().try_open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{2000},
  });

  EXPECT_TRUE(result.is_bad()) << "open_channel should fail when no server reverse-connects";
}

// ---------------------------------------------------------------------------
// RC-004: Multiple sessions over reverse connect
// ---------------------------------------------------------------------------
// @relation(SVR-RC-017, SVR-RC-025, scope=function)
TEST_F(ReverseConnectIntegration, MultipleSessionsOverReverseConnect)
{
  auto clientPort = start_client_listener();
  auto serverRcHandle = start_server_reverse_connect(clientPort);

  // Open first channel and session.
  auto channel1 = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel1.is_open());

  auto session1 = channel1.create_session_sync({.sessionName = "RC-004-A"});
  session1.activate_sync();
  ASSERT_TRUE(session1.is_active());

  // The server periodically re-connects, so a second reverse connection should
  // become available after a short wait. Open a second channel.
  auto channel2Result = mClient->core().try_open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel2Result.is_good()) << "Second reverse connect should succeed";

  auto& channel2 = channel2Result.value();
  ASSERT_TRUE(channel2.is_open());

  auto session2 = channel2.create_session_sync({.sessionName = "RC-004-B"});
  session2.activate_sync();
  ASSERT_TRUE(session2.is_active());

  // Both sessions should be able to read independently and return correct values.
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;

  auto resp1 = session1.attributes().read_sync(ReadRequest{req});
  ASSERT_TRUE(resp1.response_header().service_result().is_good());
  ASSERT_EQ(resp1.results().size(), 1u);
  EXPECT_FALSE(resp1.results()[0].status().has_value());
  EXPECT_EQ(resp1.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  auto resp2 = session2.attributes().read_sync(ReadRequest{req});
  ASSERT_TRUE(resp2.response_header().service_result().is_good());
  ASSERT_EQ(resp2.results().size(), 1u);
  EXPECT_FALSE(resp2.results()[0].status().has_value());
  EXPECT_EQ(resp2.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  // Clean up.
  session2.close_sync();
  channel2.close_sync();
  session1.close_sync();
  channel1.close_sync();
  mServer->server().stop_reverse_connect_sync(serverRcHandle);
}

// ---------------------------------------------------------------------------
// RC-005: Stop all reverse connects
// ---------------------------------------------------------------------------
// @relation(SVR-RC-018, SVR-RC-020, SVR-RC-025, scope=function)
TEST_F(ReverseConnectIntegration, StopAllReverseConnects)
{
  auto clientPort = start_client_listener();

  // Start two reverse connect targets (both pointing to same listener).
  auto handle1 = start_server_reverse_connect(clientPort);

  // Second target needs a unique name.
  ServerConfig::ReverseConnectTarget target2;
  target2.name = "TestTarget2";
  target2.clientApplicationUri = clientApplicationUri;
  target2.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", clientPort);
  target2.serverEndpointUrl = mServerEndpointUrl;
  target2.endpoints = mServer->server().endpoints(mListener);
  target2.periodicConnectInterval = std::chrono::seconds{2};
  target2.maxPendingSockets = 5;
  auto handle2 = mServer->server().start_reverse_connect_sync(std::move(target2));

  // Stop all at once.
  auto result = mServer->server().try_stop_all_reverse_connects_sync();
  EXPECT_TRUE(result.is_good()) << "stop_all_reverse_connects should succeed";

  // Both handles should now be invalid.
  auto stop1 = mServer->server().try_stop_reverse_connect_sync(handle1);
  EXPECT_TRUE(stop1.is_bad()) << "Handle 1 should be invalid after stop_all";
  auto stop2 = mServer->server().try_stop_reverse_connect_sync(handle2);
  EXPECT_TRUE(stop2.is_bad()) << "Handle 2 should be invalid after stop_all";
}

// ---------------------------------------------------------------------------
// RC-006: Client listener rejects unknown server URIs
// (Start listener expecting a different server URI, verify open_channel reports the rejected handshake)
// ---------------------------------------------------------------------------
// @relation(SVR-RC-022, SVR-RC-025, SVR-TCP-016, SVR-TCP-032, scope=function)
TEST_F(ReverseConnectIntegration, ListenerRejectsUnknownServerUri)
{
  auto port = find_free_port();

  // Configure the client listener to expect a DIFFERENT server URI.
  ReverseConnectListenerConfig listenerConfig;
  listenerConfig.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  listenerConfig.bind.address = fmt::format("127.0.0.1:{}", port);
  listenerConfig.expectedServers.push_back(ExpectedServer{
    .serverUri = "urn:completely:different:server",
    .endpointUrls = {mServerEndpointUrl},
  });
  listenerConfig.maxQueuedConnections = 5;
  listenerConfig.initialMessageTimeout = std::chrono::seconds{5};

  mClientReverseConnectHandle = mClient->core().start_reverse_connect_sync(std::move(listenerConfig));

  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Start the server reverse connect (which has the REAL server URI).
  auto serverRcHandle = start_server_reverse_connect(port);

  // The listener rejects the ReverseHello because the server URI doesn't match and reports that handshake
  // failure to the matching waiter immediately.
  auto result = mClient->core().try_open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{3000},
  });

  EXPECT_TRUE(result.is_bad()) << "open_channel should fail when server URI is rejected";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTcpEndpointUrlInvalid})
    << "the rejected ReverseHello must surface as an immediate handshake failure";
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "ReverseConnectListener");

  mServer->server().stop_reverse_connect_sync(serverRcHandle);
}

// ===========================================================================
// Helpers for the obligations below.
//
// Three of them are about what the SERVER does to its outbound socket before any client-side
// handshake completes (it must close a socket nobody answers, close a pending socket on stop, and
// dial every configured target). A real Client cannot observe those: it answers the ReverseHello,
// which is exactly the condition being excluded. A bare TCP acceptor can - it accepts the socket,
// reads the ReverseHello, and stays silent.
// ===========================================================================

namespace
{

/// A bare TCP acceptor standing in for a reverse-connect client: it accepts the socket the server
/// dials out and reads whatever the server writes, but never answers with a Hello. All work runs
/// on the calling thread via `io_context::run_for`, so every wait is bounded and there is no
/// background thread to join.
class RawReverseConnectPeer
{
public:
  RawReverseConnectPeer()
    : mAcceptor(mIo, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0))
  {}

  /// Binds a specific port (one previously reserved by find_free_port()).
  explicit RawReverseConnectPeer(uint16_t port)
    : mAcceptor(mIo, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), port))
  {}

  uint16_t port()
  {
    return mAcceptor.local_endpoint().port();
  }

  std::string url()
  {
    return fmt::format("opc.tcp://127.0.0.1:{}", port());
  }

  /// Waits up to @p timeout for one outbound connection from the server, keeping the socket.
  /// @return true when a connection was accepted inside the window.
  bool accept_one(std::chrono::milliseconds timeout)
  {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(mIo);
    bool accepted = false;
    mAcceptor.async_accept(*socket, [&accepted](const boost::system::error_code& ec) { accepted = !ec; });

    mIo.restart();
    mIo.run_for(timeout);

    if (!accepted)
    {
      // Drain the still-armed accept before returning: its handler writes to `accepted`.
      boost::system::error_code ignored;
      mAcceptor.cancel(ignored);
      mIo.restart();
      mIo.run();
      return false;
    }

    mSockets.push_back(std::move(socket));
    return true;
  }

  /// Reads from the socket accepted at @p index until the server closes it or @p window elapses.
  /// Everything read is APPENDED to @p received, so the ReverseHello stays observable whichever
  /// way the call ends - the close must remain falsifiable against a socket that carried one.
  /// @return true when the server closed the connection inside the window.
  bool read_until_closed(size_t index, std::chrono::milliseconds window, std::string& received)
  {
    auto& socket = *mSockets.at(index);
    bool closed = false;
    std::array<char, 512> buffer{};

    boost::asio::steady_timer deadline(mIo);
    deadline.expires_after(window);
    deadline.async_wait(
      [&socket](const boost::system::error_code& ec)
      {
        if (!ec)
        {
          boost::system::error_code ignored;
          socket.cancel(ignored);
        }
      });

    std::function<void()> readMore = [&]()
    {
      socket.async_read_some(boost::asio::buffer(buffer),
        [&](const boost::system::error_code& ec, size_t bytes)
        {
          if (ec)
          {
            closed = (ec == boost::asio::error::eof) || (ec == boost::asio::error::connection_reset);
            deadline.cancel();
            return;
          }
          received.append(buffer.data(), bytes);
          readMore();
        });
    };
    readMore();

    mIo.restart();
    mIo.run();
    return closed;
  }

  size_t connection_count() const
  {
    return mSockets.size();
  }

private:
  boost::asio::io_context mIo;
  boost::asio::ip::tcp::acceptor mAcceptor;
  std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> mSockets;
};

/// Polls @p predicate until it holds or @p timeout elapses. The server-side observer fires on
/// internal strands, so a notification is not visible the instant the client-side call returns.
bool wait_until(std::chrono::milliseconds timeout, const std::function<bool()>& predicate)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  return predicate();
}

/// Records the application-facing server observer callbacks the reverse-connect obligations are
/// stated over. Hooks fire on internal strands, so every field is mutex-guarded.
class ReverseConnectRecorder : public server::ServerObserver
{
public:
  struct ReverseChannel
  {
    std::string targetName;
    uint32_t secureChannelId{};
  };

  void on_secure_channel_opened(const server::SecureChannelEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    mOpenedChannelIds.push_back(info.secureChannelId);
  }

  void on_reverse_connect_opened(const std::string& targetName, const std::string&) override
  {
    const std::lock_guard lock{mMutex};
    mOpenedTargets.push_back(targetName);
  }

  void on_reverse_connect_channel_established(
    const std::string& targetName, uint32_t secureChannelId) override
  {
    const std::lock_guard lock{mMutex};
    mReverseChannels.push_back(ReverseChannel{targetName, secureChannelId});
  }

  std::vector<uint32_t> opened_channel_ids() const
  {
    const std::lock_guard lock{mMutex};
    return mOpenedChannelIds;
  }

  std::vector<ReverseChannel> reverse_channels() const
  {
    const std::lock_guard lock{mMutex};
    return mReverseChannels;
  }

  bool has_opened_target(const std::string& targetName) const
  {
    const std::lock_guard lock{mMutex};
    return std::find(mOpenedTargets.begin(), mOpenedTargets.end(), targetName) != mOpenedTargets.end();
  }

private:
  mutable std::mutex mMutex;
  std::vector<uint32_t> mOpenedChannelIds;
  std::vector<std::string> mOpenedTargets;
  std::vector<ReverseChannel> mReverseChannels;
};

/// A Read of Server_ServerStatus_State carrying a caller-chosen RequestHandle, so a response can
/// be matched back to the request that produced it.
ReadRequest make_state_read(uint32_t requestHandle)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  req.request_header().request_handle() = requestHandle;
  return req;
}

/// The None endpoint every server in this suite offers.
ServerEndpointConfig none_endpoint()
{
  ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  endpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  return endpoint;
}

}  // namespace

// ---------------------------------------------------------------------------
// RC-007: A reverse connection the peer never answers with a Hello is closed
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3: a connection that receives no Hello must be closed after a configurable
// period. On the reverse path the SERVER dialled the socket, so an implementation that arms the
// Hello deadline on accept (the inbound path) never arms it here at all, and every client that
// answers the ReverseHello with silence keeps a server socket forever. The timeout is set to two
// seconds so the assertion is about the CONFIGURED period, not about the default expiring.
// @verifies AC-SVR-RC-009-NO-HELLO-CLOSES
// @relation(SVR-RC-009, scope=function)
TEST_F(ReverseConnectIntegration, ReverseConnectionWithoutHelloIsClosedAfterConfiguredTimeout)
{
  // Declared first so it outlives the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer peer;

  TestServer server;
  server.create([](ua::ApplicationConfig& appCfg)
    { appCfg.stack_limits().connectionProtocolTimeout = std::chrono::seconds{2}; },
    nullptr,
    nullptr);

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, none_endpoint());
  server.start();

  auto urls = server.server().advertised_urls(listener);
  ASSERT_FALSE(urls.empty());

  ServerConfig::ReverseConnectTarget target;
  target.name = "NoHelloTarget";
  target.clientApplicationUri = clientApplicationUri;
  target.clientEndpointUrl = peer.url();
  target.serverEndpointUrl = urls.front().str();
  target.endpoints = server.server().endpoints(listener);
  // Long, so the socket under observation is the one dialled at start and nothing else muddies it.
  target.periodicConnectInterval = std::chrono::seconds{60};
  target.maxPendingSockets = 5;
  auto handle = server.server().start_reverse_connect_sync(std::move(target));

  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "the server must dial the configured client endpoint";

  std::string received;
  const auto start = std::chrono::steady_clock::now();
  const bool closed = peer.read_until_closed(0, std::chrono::milliseconds{9000}, received);
  const auto elapsedMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

  // The socket really was a reverse connection awaiting a Hello - otherwise "closed" proves nothing.
  ASSERT_GE(received.size(), 3u) << "nothing was received on the dialled connection";
  EXPECT_EQ(received.substr(0, 3), "RHE") << "the dialled connection must carry a ReverseHello";

  EXPECT_TRUE(closed) << "a reverse connection that never receives a Hello must be closed by the "
                         "server; it was still open "
                      << elapsedMs
                      << " ms after the ReverseHello, "
                         "with a 2 s configured wait";
  EXPECT_GE(elapsedMs, 1000) << "the close must follow the configured wait, not pre-empt it";
}

// ---------------------------------------------------------------------------
// RC-008: Concurrent reverse channels are each bound to their own connection
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3: on accepting a channel the server binds the TransportConnection to the
// SecureChannelId. The server dialled BOTH connections here, so it cannot tell them apart by who
// connected; an implementation that keys the association off the target (one binding per
// configured client) rather than off the connection object collapses the two onto one transport,
// and closing one channel then takes the other down with it.
//
// The binding is read off the wire, not off a server-side hook: each SecureChannelId arrives in the
// OPN response that travelled the very connection it was allocated for, so two distinct ids in the
// client's hands are two distinct bindings. The application-notification hooks belong to
// SVR-RC-011 and are verified there.
// @verifies AC-SVR-RC-010-ASSOCIATE-CONNECTION-WITH-CHANNEL
// @relation(SVR-RC-010, scope=function)
TEST_F(ReverseConnectIntegration, ConcurrentReverseChannelsAreBoundToTheirOwnConnections)
{
  auto clientPort = start_client_listener();
  auto serverRcHandle = start_server_reverse_connect(clientPort);

  auto channel1 = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel1.is_open());
  auto session1 = channel1.create_session_sync({.sessionName = "RC-008-A"});
  session1.activate_sync();
  ASSERT_TRUE(session1.is_active());

  auto channel2Result = mClient->core().try_open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel2Result.is_good()) << "a second reverse connection is needed for this test";
  auto& channel2 = channel2Result.value();
  ASSERT_TRUE(channel2.is_open());
  auto session2 = channel2.create_session_sync({.sessionName = "RC-008-B"});
  session2.activate_sync();
  ASSERT_TRUE(session2.is_active());

  // Two channels, each carrying the id the server allocated on its own transport.
  ASSERT_NE(channel1.secure_channel_id(), 0u) << "the first reverse channel was never assigned an id";
  ASSERT_NE(channel2.secure_channel_id(), 0u) << "the second reverse channel was never assigned an id";
  EXPECT_NE(channel1.secure_channel_id(), channel2.secure_channel_id())
    << "two concurrent reverse connections must not share one SecureChannelId";

  // Messages do not cross: interleaved requests come back on the channel that carried them, each
  // response echoing its own RequestHandle (Part 4 section 7.28).
  auto resp1 = session1.attributes().read_sync(make_state_read(1001));
  ASSERT_TRUE(resp1.response_header().service_result().is_good());
  EXPECT_EQ(resp1.response_header().request_handle(), 1001u);
  ASSERT_EQ(resp1.results().size(), 1u);
  EXPECT_EQ(resp1.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  auto resp2 = session2.attributes().read_sync(make_state_read(2002));
  ASSERT_TRUE(resp2.response_header().service_result().is_good());
  EXPECT_EQ(resp2.response_header().request_handle(), 2002u);
  ASSERT_EQ(resp2.results().size(), 1u);
  EXPECT_EQ(resp2.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  auto resp3 = session1.attributes().read_sync(make_state_read(3003));
  ASSERT_TRUE(resp3.response_header().service_result().is_good());
  EXPECT_EQ(resp3.response_header().request_handle(), 3003u);

  // Closing one channel tears down ITS transport only.
  session1.close_sync();
  channel1.close_sync();

  EXPECT_TRUE(channel2.is_open()) << "closing one reverse channel must not close the other";
  auto resp4 = session2.attributes().read_sync(make_state_read(4004));
  ASSERT_TRUE(resp4.response_header().service_result().is_good())
    << "the surviving channel's session must still be served";
  EXPECT_EQ(resp4.response_header().request_handle(), 4004u);
  ASSERT_EQ(resp4.results().size(), 1u);
  EXPECT_FALSE(resp4.results()[0].status().has_value());

  session2.close_sync();
  channel2.close_sync();
  mServer->server().stop_reverse_connect_sync(serverRcHandle);
}

// ---------------------------------------------------------------------------
// RC-009: The application is notified of channels opened in either direction
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3: the stack notifies the server application of each OpenSecureChannel,
// including the response returned. The application does no work during negotiation, so the
// notification is its only evidence the channel exists - and for a reverse connection there is no
// inbound accept to hang the notification off. An implementation that raises the hook from the
// acceptor path leaves reverse channels silent, which is invisible until an operator asks why a
// configured target reports nothing.
// @verifies AC-SVR-RC-011-CHANNEL-NOTIFICATION
// @relation(SVR-RC-011, scope=function)
TEST_F(ReverseConnectIntegration, ApplicationIsNotifiedOfChannelsOpenedInBothDirections)
{
  auto observer = std::make_shared<ReverseConnectRecorder>();
  mServer->server().set_observer(observer);

  // Direction 1: the client dials the server's listener.
  auto inboundChannel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(inboundChannel.is_open());

  // Direction 2: the server dials the client's reverse-connect listener.
  auto clientPort = start_client_listener();
  auto serverRcHandle = start_server_reverse_connect(clientPort);
  auto reverseChannel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(reverseChannel.is_open());

  // Each direction is identified by the id the server allocated for it, taken from the client's own
  // handle rather than from a server-side hook - so "notified of each" is checked against the two
  // channels that actually exist, not against a count that two notifications of the same channel
  // would satisfy.
  const auto reverseId = reverseChannel.secure_channel_id();
  const auto inboundId = inboundChannel.secure_channel_id();
  ASSERT_NE(reverseId, 0u);
  ASSERT_NE(inboundId, 0u);
  ASSERT_NE(reverseId, inboundId) << "the two directions must be distinct channels";

  ASSERT_TRUE(wait_until(
    std::chrono::milliseconds{5000}, [&observer] { return observer->opened_channel_ids().size() >= 2; }))
    << "the application must be notified of both channels";

  const auto openedIds = observer->opened_channel_ids();
  EXPECT_TRUE(std::find(openedIds.begin(), openedIds.end(), reverseId) != openedIds.end())
    << "the channel established over the reverse connection must reach the application observer";
  EXPECT_TRUE(std::find(openedIds.begin(), openedIds.end(), inboundId) != openedIds.end())
    << "the inbound channel must reach the same observer, whichever direction it was initiated from";

  reverseChannel.close_sync();
  inboundChannel.close_sync();
  mServer->server().stop_reverse_connect_sync(serverRcHandle);
  mServer->server().set_observer(nullptr);
}

// ---------------------------------------------------------------------------
// RC-010: An unreachable target retries without affecting its siblings
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3 / SVR-RC-017: each configured target owns its state. A shared retry loop
// would stall every target behind the slowest - which is precisely the unreachable one, whose
// backoff grows to tens of seconds. The unreachable target is proved to be retrying by binding its
// endpoint LATE: nothing can accept there until it does, so a later connection can only come from
// a repeated attempt.
//
// Regression identity: ServerImpl returns a CompositeObserver whenever application and internal
// observers coexist. Every per-target opened/closed/channel-established event must therefore cross
// that composite without losing the target name. Do not weaken this to infer target state from the
// client side: the named observer stream is the obligation. Scope-bound cleanup remains independent
// of assertions so any future regression cannot strand reverse-connect work and hang the suite.
// @relation(AC-SVR-RC-017-MULTIPLE-TARGETS, scope=function)
// @relation(SVR-RC-017, scope=function)
TEST_F(ReverseConnectIntegration, UnreachableTargetRetriesWithoutAffectingOtherTargets)
{
  auto observer = std::make_shared<ReverseConnectRecorder>();
  mServer->server().set_observer(observer);

  auto clientPort = start_client_listener();
  const auto unreachablePort = find_free_port();  // reserved, deliberately left unbound

  auto startTarget = [this](const std::string& name, uint16_t port, std::chrono::seconds periodic)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", port);
    target.serverEndpointUrl = mServerEndpointUrl;
    target.endpoints = mServer->server().endpoints(mListener);
    target.periodicConnectInterval = periodic;
    target.maxPendingSockets = 5;
    return mServer->server().start_reverse_connect_sync(std::move(target));
  };

  auto handleA = startTarget("TargetA", clientPort, std::chrono::seconds{2});
  auto handleB = startTarget("TargetB", clientPort, std::chrono::seconds{2});
  // A long periodic interval, so any connection this target ever makes came from its own
  // failure-driven retry and not from the periodic timer.
  auto handleC = startTarget("TargetC", unreachablePort, std::chrono::seconds{60});

  struct TargetCleanup
  {
    std::function<void()> action;

    ~TargetCleanup() noexcept
    {
      try
      {
        action();
      }
      catch (const std::exception& error)
      {
        ADD_FAILURE() << "RC-017 target cleanup threw: " << error.what();
      }
      catch (...)
      {
        ADD_FAILURE() << "RC-017 target cleanup threw an unknown exception";
      }
    }
  } cleanup{[this, handleA, handleB, handleC]
    {
      (void)mServer->server().try_stop_reverse_connect_sync(handleC);
      (void)mServer->server().try_stop_reverse_connect_sync(handleB);
      (void)mServer->server().try_stop_reverse_connect_sync(handleA);
      mServer->server().set_observer(nullptr);
    }};

  // Let the unreachable target fail at least once before anything can accept there.
  std::this_thread::sleep_for(std::chrono::milliseconds{1200});
  ASSERT_FALSE(observer->has_opened_target("TargetC"))
    << "the third target must be unreachable for this test to mean anything";

  // The two reachable targets connect and are usable.
  ASSERT_TRUE(wait_until(std::chrono::milliseconds{15000},
    [&observer] { return observer->has_opened_target("TargetA") && observer->has_opened_target("TargetB"); }))
    << "an unreachable sibling must not stop the reachable targets from connecting";

  auto channel1 = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel1.is_open());
  auto session1 = channel1.create_session_sync({.sessionName = "RC-010-A"});
  session1.activate_sync();
  ASSERT_TRUE(session1.is_active());

  auto channel2Result = mClient->core().try_open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel2Result.is_good()) << "the second reachable target must also deliver a connection";
  auto& channel2 = channel2Result.value();
  ASSERT_TRUE(channel2.is_open());
  auto session2 = channel2.create_session_sync({.sessionName = "RC-010-B"});
  session2.activate_sync();
  ASSERT_TRUE(session2.is_active());

  // Now let the unreachable endpoint answer: only a retry can reach it.
  std::optional<RawReverseConnectPeer> latePeer;
  latePeer.emplace(unreachablePort);
  EXPECT_TRUE(wait_until(
    std::chrono::milliseconds{25000}, [&observer] { return observer->has_opened_target("TargetC"); }))
    << "the unreachable target must keep retrying on its own schedule";

  // And the siblings are untouched by any of it.
  EXPECT_TRUE(channel1.is_open()) << "the first target's channel must stay connected";
  EXPECT_TRUE(channel2.is_open()) << "the second target's channel must stay connected";

  auto resp1 = session1.attributes().read_sync(make_state_read(11));
  ASSERT_TRUE(resp1.response_header().service_result().is_good());
  ASSERT_EQ(resp1.results().size(), 1u);
  EXPECT_FALSE(resp1.results()[0].status().has_value());
  EXPECT_EQ(resp1.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  auto resp2 = session2.attributes().read_sync(make_state_read(22));
  ASSERT_TRUE(resp2.response_header().service_result().is_good());
  ASSERT_EQ(resp2.results().size(), 1u);
  EXPECT_FALSE(resp2.results()[0].status().has_value());
  EXPECT_EQ(resp2.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  session2.close_sync();
  channel2.close_sync();
  session1.close_sync();
  channel1.close_sync();
}

// ---------------------------------------------------------------------------
// RC-011: Stopping a target closes its pending socket; restarting dials a new one
// ---------------------------------------------------------------------------
// SVR-RC-018: a target holds an outbound socket open waiting for the client, so a stop that only
// clears a running flag leaves that socket alive until the Hello deadline expires and the next
// start adds a second one - a server that accumulates connections across restarts. The window used
// here is shorter than the Hello deadline (10 s by default), so a socket left to time out fails.
// @verifies AC-SVR-RC-018-REVERSE-CONNECT-LIFECYCLE
// @relation(SVR-RC-018, scope=function)
TEST_F(ReverseConnectIntegration, StoppingTargetClosesPendingSocketAndRestartDialsANewOne)
{
  // Never answers the ReverseHello, so the socket the server dials stays PENDING: not yet a
  // SecureChannel, which is exactly the socket a stop must close.
  RawReverseConnectPeer peer;

  auto makeTarget = [this, &peer]()
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = "LifecycleTarget";
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = peer.url();
    target.serverEndpointUrl = mServerEndpointUrl;
    target.endpoints = mServer->server().endpoints(mListener);
    // Long, so every connection observed here is one the start dialled, not a periodic extra.
    target.periodicConnectInterval = std::chrono::seconds{60};
    target.maxPendingSockets = 5;
    return target;
  };

  auto handle = mServer->server().start_reverse_connect_sync(makeTarget());
  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "the target must dial the client endpoint on start";

  // Before the stop the socket is open and carries a ReverseHello - the antecedent of the close.
  std::string firstSocketBytes;
  const bool closedBeforeStop = peer.read_until_closed(0, std::chrono::milliseconds{500}, firstSocketBytes);
  ASSERT_FALSE(closedBeforeStop) << "the pending socket must be held open while the target runs";
  ASSERT_GE(firstSocketBytes.size(), 3u);
  ASSERT_EQ(firstSocketBytes.substr(0, 3), "RHE") << "the pending socket must carry a ReverseHello";

  auto stopResult = mServer->server().try_stop_reverse_connect_sync(handle);
  EXPECT_TRUE(stopResult.is_good()) << "stopping a running target must succeed";

  const bool closedByStop = peer.read_until_closed(0, std::chrono::milliseconds{5000}, firstSocketBytes);
  EXPECT_TRUE(closedByStop) << "stopping the target must CLOSE its pending socket, not leave it to "
                               "expire on the Hello deadline";

  // Restart: a new socket, and the closed one does not come back.
  auto handle2 = mServer->server().start_reverse_connect_sync(makeTarget());
  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "restarting the target must establish a new connection";
  EXPECT_EQ(peer.connection_count(), 2u)
    << "the restart must dial a NEW socket; no socket from the stopped period survives into it";

  std::string secondSocketBytes;
  (void)peer.read_until_closed(1, std::chrono::milliseconds{1000}, secondSocketBytes);
  ASSERT_GE(secondSocketBytes.size(), 3u);
  EXPECT_EQ(secondSocketBytes.substr(0, 3), "RHE")
    << "the restarted target's socket must carry its own ReverseHello";

  mServer->server().stop_reverse_connect_sync(handle2);
}

// ---------------------------------------------------------------------------
// RC-012: Server::start_sync() launches every configured reverse-connect target
// ---------------------------------------------------------------------------
// SVR-RC-019: targets declared in ServerConfig are activated by the same start() that opens
// listeners. Requiring a second call would make a configured-but-silent server the default outcome
// of forgetting it, with nothing reporting the omission. Two targets are configured and each
// announces its OWN ServerEndpointUrl in its ReverseHello, so a server that launches only the
// first (or dials once and reconnects) cannot satisfy this.
// @verifies AC-SVR-RC-019-START-LAUNCHES-TARGETS
// @relation(SVR-RC-019, scope=function)
TEST_F(ReverseConnectIntegration, StartLaunchesEveryConfiguredReverseConnectTarget)
{
  // Declared first so it outlives the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer peer;

  const std::string urlA = "opc.tcp://127.0.0.1:14841";
  const std::string urlB = "opc.tcp://127.0.0.1:14842";
  const auto clientUrl = peer.url();

  TestServer server;
  server.create(
    [&clientUrl, &urlA, &urlB](ua::server::ServerConfig& serverCfg)
    {
      ServerConfig::ReverseConnectTarget targetA;
      targetA.name = "ConfiguredA";
      targetA.clientApplicationUri = clientApplicationUri;
      targetA.clientEndpointUrl = clientUrl;
      targetA.serverEndpointUrl = urlA;
      targetA.endpoints.push_back(none_endpoint());
      targetA.periodicConnectInterval = std::chrono::seconds{60};
      targetA.maxPendingSockets = 5;

      auto targetB = targetA;
      targetB.name = "ConfiguredB";
      targetB.serverEndpointUrl = urlB;

      serverCfg.reverseConnectTargets.push_back(std::move(targetA));
      serverCfg.reverseConnectTargets.push_back(std::move(targetB));
    });

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, none_endpoint());

  // The only call made. No start_reverse_connect_* anywhere in this test.
  server.start();

  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "a configured reverse-connect target must be dialled by start()";
  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "EVERY configured target must be dialled by start(), not just the first";
  ASSERT_EQ(peer.connection_count(), 2u);

  std::string first;
  std::string second;
  (void)peer.read_until_closed(0, std::chrono::milliseconds{1000}, first);
  (void)peer.read_until_closed(1, std::chrono::milliseconds{1000}, second);

  ASSERT_GE(first.size(), 3u) << "the first dialled connection sent nothing";
  ASSERT_GE(second.size(), 3u) << "the second dialled connection sent nothing";
  EXPECT_EQ(first.substr(0, 3), "RHE");
  EXPECT_EQ(second.substr(0, 3), "RHE");

  // Each connection announced a different target's endpoint URL, so both targets ran.
  const bool aThenB = (first.find(urlA) != std::string::npos) && (second.find(urlB) != std::string::npos);
  const bool bThenA = (first.find(urlB) != std::string::npos) && (second.find(urlA) != std::string::npos);

  auto carried = [&urlA, &urlB](const std::string& bytes)
  {
    if (bytes.find(urlA) != std::string::npos)
      return std::string{"target A's endpoint URL"};
    if (bytes.find(urlB) != std::string::npos)
      return std::string{"target B's endpoint URL"};
    return std::string{"neither target's endpoint URL"};
  };

  EXPECT_TRUE(aThenB || bThenA)
    << "both configured targets must dial out with their own ServerEndpointUrl; connection 1 carried "
    << carried(first) << " and connection 2 carried " << carried(second);
}

// ===========================================================================
// Helpers for the obligations below.
//
// One of them is stated over the CLIENT side of a reverse connection - the listening party - and
// over a ReverseHello no conforming server would ever emit. A real server cannot produce it, so the
// stimulus is a bare TCP dialler that hand-builds the message and writes it at the listener.
// ===========================================================================

namespace
{

/// Builds the raw bytes of a ReverseHello: "RHE" + 'F' + uint32 messageSize + String serverUri +
/// String endpointUrl (Part 6 section 7.1.2.6; the SDK's own `encode_reverse_hello` lays it out the
/// same way). Hand-built because the obligation below is about a field length the SDK's encoder
/// would never emit.
std::string encode_reverse_hello_bytes(const std::string& serverUri, const std::string& endpointUrl)
{
  auto appendUInt32 = [](std::string& out, uint32_t value)
  {
    out.push_back(static_cast<char>(value & 0xFFu));
    out.push_back(static_cast<char>((value >> 8) & 0xFFu));
    out.push_back(static_cast<char>((value >> 16) & 0xFFu));
    out.push_back(static_cast<char>((value >> 24) & 0xFFu));
  };

  std::string body;
  appendUInt32(body, static_cast<uint32_t>(serverUri.size()));
  body.append(serverUri);
  appendUInt32(body, static_cast<uint32_t>(endpointUrl.size()));
  body.append(endpointUrl);

  // 8-byte header: 3-byte message type + 1 reserved byte + the 4-byte size field.
  std::string message = "RHEF";
  appendUInt32(message, static_cast<uint32_t>(8 + body.size()));
  message.append(body);
  return message;
}

/// A bare TCP dialler standing in for a reverse-connecting server: it connects to the client's
/// reverse-connect listener, writes a caller-built ReverseHello, and then reads whatever the
/// listener answers until it closes. All work runs on the calling thread, so every wait is bounded
/// and there is no background thread to join.
class RawReverseHelloSender
{
public:
  explicit RawReverseHelloSender(uint16_t port) : mSocket(mIo), mPort(port)
  {}

  /// Connects to the loopback port given at construction.
  bool connect()
  {
    boost::system::error_code errorCode;
    mSocket.connect(
      boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), mPort), errorCode);
    return !errorCode;
  }

  /// Writes @p bytes in full, looping until the socket has taken all of them.
  bool write_all(const std::string& bytes)
  {
    boost::system::error_code errorCode;
    size_t sent = 0;
    while (sent < bytes.size())
    {
      const auto written =
        mSocket.write_some(boost::asio::buffer(bytes.data() + sent, bytes.size() - sent), errorCode);
      if (errorCode)
        return false;
      sent += written;
    }
    return true;
  }

  /// Reads until the listener closes the connection or @p window elapses. Everything read is
  /// APPENDED to @p received, so whatever the listener answered stays observable whichever way the
  /// call ends - the refusal must remain falsifiable against a listener that answered with a Hello.
  /// @return true when the listener closed the connection inside the window.
  bool read_until_closed(std::chrono::milliseconds window, std::string& received)
  {
    bool closed = false;
    std::array<char, 512> buffer{};

    boost::asio::steady_timer deadline(mIo);
    deadline.expires_after(window);
    deadline.async_wait(
      [this](const boost::system::error_code& errorCode)
      {
        if (!errorCode)
        {
          boost::system::error_code ignored;
          mSocket.cancel(ignored);
        }
      });

    std::function<void()> readMore = [&]()
    {
      mSocket.async_read_some(boost::asio::buffer(buffer),
        [&](const boost::system::error_code& errorCode, size_t bytes)
        {
          if (errorCode)
          {
            closed =
              (errorCode == boost::asio::error::eof) || (errorCode == boost::asio::error::connection_reset);
            deadline.cancel();
            return;
          }
          received.append(buffer.data(), bytes);
          readMore();
        });
    };
    readMore();

    mIo.restart();
    mIo.run();
    return closed;
  }

private:
  boost::asio::io_context mIo;
  boost::asio::ip::tcp::socket mSocket;
  uint16_t mPort;
};

/// Everything an EndpointDescription advertises about security, flattened into one line so two
/// GetEndpoints answers can be compared field-for-field rather than by object identity.
std::string describe_endpoint(const EndpointDescription& endpoint)
{
  const std::string url = endpoint.endpoint_url();
  const std::string policyUri = endpoint.security_policy_uri();
  const std::string transportProfileUri = endpoint.transport_profile_uri();
  return fmt::format("{}|{}|{}|{}|{}|{}",
    url,
    static_cast<int>(endpoint.security_mode()),
    policyUri,
    transportProfileUri,
    static_cast<unsigned>(endpoint.security_level()),
    endpoint.user_identity_tokens().size());
}

/// The endpoint summaries a GetEndpoints answer carries, sorted so the comparison is over the SET
/// the server advertises and not over the order it happened to enumerate its listeners in.
std::vector<std::string> endpoint_summaries(const GetEndpointsResponse& response)
{
  std::vector<std::string> summaries;
  for (size_t i = 0; i < response.endpoints().size(); ++i)
  {
    summaries.push_back(describe_endpoint(response.endpoints()[i]));
  }
  std::sort(summaries.begin(), summaries.end());
  return summaries;
}

}  // namespace

// ---------------------------------------------------------------------------
// RC-013: Several targets run independently; an unreachable one does not hold the others back
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3 / SVR-RC-017: every target owns its strand, pending-socket list and timers.
// A shared retry loop would stall every target behind the slowest, and the slowest is exactly the
// unreachable one whose backoff doubles to tens of seconds. The observation is per target and taken
// off the wire: each reachable target dials its OWN acceptor, so no connection can be credited to
// the wrong target, and the third target's port is bound only AFTER the other two are up - nothing
// could answer there before, so a connection arriving afterwards can only be a repeated attempt.
// @verifies AC-SVR-RC-017-MULTIPLE-TARGETS
// @relation(SVR-RC-017, scope=function)
TEST_F(ReverseConnectIntegration, ReachableTargetsStayConnectedWhileAnUnreachableSiblingRetries)
{
  // Declared first so they outlive the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer peerA;
  RawReverseConnectPeer peerB;
  const auto unreachablePort = find_free_port();  // reserved, deliberately left unbound
  std::optional<RawReverseConnectPeer> latePeerC;

  TestServer server;
  // Long, so no pending socket can be closed by the no-Hello deadline inside the test window: every
  // close observed below would then be a sibling's doing, which is what this test excludes.
  server.create([](ua::ApplicationConfig& appCfg)
    { appCfg.stack_limits().connectionProtocolTimeout = std::chrono::seconds{120}; },
    nullptr,
    nullptr);

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, none_endpoint());
  server.start();

  auto urls = server.server().advertised_urls(listener);
  ASSERT_FALSE(urls.empty());
  const auto serverEndpointUrl = urls.front().str();

  auto startTarget = [&](const std::string& name, const std::string& clientUrl, std::chrono::seconds periodic)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = clientUrl;
    target.serverEndpointUrl = serverEndpointUrl;
    target.endpoints = server.server().endpoints(listener);
    target.periodicConnectInterval = periodic;
    target.maxPendingSockets = 5;
    return server.server().start_reverse_connect_sync(std::move(target));
  };

  // The two reachable targets dial once and hold; only the unreachable one keeps trying.
  auto handleA = startTarget("TargetA", peerA.url(), std::chrono::seconds{120});
  auto handleB = startTarget("TargetB", peerB.url(), std::chrono::seconds{120});
  auto handleC =
    startTarget("TargetC", fmt::format("opc.tcp://127.0.0.1:{}", unreachablePort), std::chrono::seconds{2});

  ASSERT_TRUE(peerA.accept_one(std::chrono::milliseconds{15000}))
    << "the first target must dial its own client endpoint";
  ASSERT_TRUE(peerB.accept_one(std::chrono::milliseconds{15000}))
    << "an unreachable sibling must not stop the second target from connecting";

  std::string bytesA;
  std::string bytesB;
  ASSERT_FALSE(peerA.read_until_closed(0, std::chrono::milliseconds{500}, bytesA))
    << "the first target's connection must be held open";
  ASSERT_FALSE(peerB.read_until_closed(0, std::chrono::milliseconds{500}, bytesB))
    << "the second target's connection must be held open";
  ASSERT_GE(bytesA.size(), 3u) << "the first target's connection sent nothing";
  ASSERT_GE(bytesB.size(), 3u) << "the second target's connection sent nothing";
  EXPECT_EQ(bytesA.substr(0, 3), "RHE") << "the first target's connection must carry a ReverseHello";
  EXPECT_EQ(bytesB.substr(0, 3), "RHE") << "the second target's connection must carry a ReverseHello";

  // Nothing could accept on the third target's port until this line, so a connection arriving there
  // now can only come from a repeated attempt by that target.
  latePeerC.emplace(unreachablePort);
  ASSERT_TRUE(latePeerC->accept_one(std::chrono::milliseconds{25000}))
    << "the unreachable target must keep retrying on its own schedule";

  std::string bytesC;
  (void)latePeerC->read_until_closed(0, std::chrono::milliseconds{1000}, bytesC);
  ASSERT_GE(bytesC.size(), 3u) << "the retried connection sent nothing";
  EXPECT_EQ(bytesC.substr(0, 3), "RHE") << "the retry must be a real reverse connect, not a bare socket";

  // ... and the two reachable targets are untouched by any of it.
  EXPECT_FALSE(peerA.read_until_closed(0, std::chrono::milliseconds{500}, bytesA))
    << "the first target's connection must survive a sibling's retry loop";
  EXPECT_FALSE(peerB.read_until_closed(0, std::chrono::milliseconds{500}, bytesB))
    << "the second target's connection must survive a sibling's retry loop";

  // Per-target lifecycle: each handle addresses its own target, and none of the three is a no-op.
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(handleC).is_good())
    << "the unreachable target must still be individually stoppable";
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(handleB).is_good());
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(handleA).is_good());
}

// ---------------------------------------------------------------------------
// RC-014: Shutdown stops the reverse-connect targets before anything else is torn down
// ---------------------------------------------------------------------------
// SVR-RC-020: the manager stop happens FIRST, so nothing dials out while listeners, channels and
// sessions are closing. A shutdown that closed those first would trip each target's own reconnect
// logic - it cannot tell a shutdown from a dropped link (SVR-RC-013) - and the server would spend
// its teardown opening fresh sockets nobody will ever answer. The target dials on a two-second
// period here and two dials are observed BEFORE the shutdown, so the absence of a third afterwards
// is a real absence and not a target that never dialled twice in the first place.
// @verifies AC-SVR-RC-020-SHUTDOWN-STOPS-TARGETS-FIRST
// @relation(SVR-RC-020, scope=function)
TEST_F(ReverseConnectIntegration, ShutdownStopsReverseConnectTargetsBeforeListenersAndChannelsClose)
{
  // Declared first so it outlives the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer peer;

  TestServer server;
  // Long, so a pending socket cannot expire on the no-Hello deadline during the test: the close
  // asserted below must be the shutdown's doing.
  server.create([](ua::ApplicationConfig& appCfg)
    { appCfg.stack_limits().connectionProtocolTimeout = std::chrono::seconds{120}; },
    nullptr,
    nullptr);

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, none_endpoint());
  server.start();

  auto urls = server.server().advertised_urls(listener);
  ASSERT_FALSE(urls.empty());

  ServerConfig::ReverseConnectTarget target;
  target.name = "ShutdownTarget";
  target.clientApplicationUri = clientApplicationUri;
  target.clientEndpointUrl = peer.url();
  target.serverEndpointUrl = urls.front().str();
  target.endpoints = server.server().endpoints(listener);
  target.periodicConnectInterval = std::chrono::seconds{2};
  // Far above the number of sockets this test lets accumulate, so a missing dial after the shutdown
  // is the target having been stopped and not the pending-socket limit declining to dial.
  target.maxPendingSockets = 20;
  auto handle = server.server().start_reverse_connect_sync(std::move(target));
  (void)handle;

  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "the target must dial the configured client endpoint on start";
  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "the target must keep dialling on its periodic schedule while the server runs";
  ASSERT_EQ(peer.connection_count(), 2u);

  // Both sockets are open and carry a ReverseHello - the antecedent of the closes asserted below.
  std::string firstBytes;
  std::string secondBytes;
  ASSERT_FALSE(peer.read_until_closed(0, std::chrono::milliseconds{500}, firstBytes))
    << "the first pending socket must still be open when the shutdown begins";
  ASSERT_FALSE(peer.read_until_closed(1, std::chrono::milliseconds{500}, secondBytes))
    << "the second pending socket must still be open when the shutdown begins";
  ASSERT_GE(firstBytes.size(), 3u);
  ASSERT_GE(secondBytes.size(), 3u);
  ASSERT_EQ(firstBytes.substr(0, 3), "RHE") << "the first pending socket must carry a ReverseHello";
  ASSERT_EQ(secondBytes.substr(0, 3), "RHE") << "the second pending socket must carry a ReverseHello";

  auto shutdownResult = server.server().try_shutdown_sync(ShutdownOptions{.grace = std::chrono::seconds{0}});
  EXPECT_TRUE(shutdownResult.is_good()) << "the graceful shutdown itself must succeed";

  EXPECT_TRUE(peer.read_until_closed(0, std::chrono::milliseconds{5000}, firstBytes))
    << "shutdown must close every pending reverse-connect socket the target holds";
  EXPECT_TRUE(peer.read_until_closed(1, std::chrono::milliseconds{5000}, secondBytes))
    << "shutdown must close every pending reverse-connect socket the target holds";

  // Two whole periodic intervals with no dial: the target was stopped before the rest of the
  // teardown, rather than left running to reconnect into a server that is closing everything else.
  EXPECT_FALSE(peer.accept_one(std::chrono::milliseconds{5000}))
    << "no target may dial out during or after shutdown";
  EXPECT_EQ(peer.connection_count(), 2u) << "the connection count must not have grown across the shutdown";
}

// ---------------------------------------------------------------------------
// RC-015: A reverse-arrived channel is indistinguishable from an inbound one
// ---------------------------------------------------------------------------
// SVR-RC-022: the reverse path registers a synthetic ListenerHandle and hands its socket to the same
// `new_connection_complete` an accept would have called. A parallel path would duplicate endpoint
// advertising, session handling and the diagnostics counters, and duplicated logic diverges - the
// reverse channel would advertise a different endpoint set, or go uncounted, and no connectivity
// test would notice because the channel still works. Both channels here are opened against the SAME
// server with the SAME listener set already registered, so any difference below is the direction the
// socket was dialled in and nothing else.
// @verifies AC-SVR-RC-022-REUSE-INBOUND-PATH
// @relation(SVR-RC-022, scope=function)
TEST_F(ReverseConnectIntegration, ReverseArrivedChannelBehavesIdenticallyToAnInboundChannel)
{
  auto clientPort = start_client_listener();

  // A long periodic interval, so the connection consumed below is the one the start dialled.
  ServerConfig::ReverseConnectTarget target;
  target.name = "ParityTarget";
  target.clientApplicationUri = clientApplicationUri;
  target.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", clientPort);
  target.serverEndpointUrl = mServerEndpointUrl;
  target.endpoints = mServer->server().endpoints(mListener);
  target.periodicConnectInterval = std::chrono::seconds{60};
  target.maxPendingSockets = 5;
  auto serverRcHandle = mServer->server().start_reverse_connect_sync(std::move(target));

  // --- Direction 1: the client dials the server's listener. ---
  const auto beforeInbound = mServer->server().health_snapshot();

  auto inboundChannel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(inboundChannel.is_open());
  auto inboundSession = inboundChannel.create_session_sync({.sessionName = "RC-015-inbound"});
  inboundSession.activate_sync();
  ASSERT_TRUE(inboundSession.is_active());

  ASSERT_TRUE(wait_until(std::chrono::milliseconds{5000},
    [this, &beforeInbound] {
      return mServer->server().health_snapshot().cumulatedSessionCount > beforeInbound.cumulatedSessionCount;
    }))
    << "the inbound session must reach the server's diagnostics";
  const auto afterInbound = mServer->server().health_snapshot();

  // --- Direction 2: the server dials the client's reverse-connect listener. ---
  auto reverseChannel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(reverseChannel.is_open());
  auto reverseSession = reverseChannel.create_session_sync({.sessionName = "RC-015-reverse"});
  reverseSession.activate_sync();
  ASSERT_TRUE(reverseSession.is_active());

  ASSERT_TRUE(wait_until(std::chrono::milliseconds{5000},
    [this, &afterInbound] {
      return mServer->server().health_snapshot().cumulatedSessionCount > afterInbound.cumulatedSessionCount;
    }))
    << "the reverse session must reach the same diagnostics";
  const auto afterReverse = mServer->server().health_snapshot();

  // Same diagnostics: each direction moved the same counters by the same amount. The inbound delta
  // is asserted to be exactly one first, so a server that counts nothing at all cannot pass by
  // symmetry. Only the session counters are compared: a running target keeps dialling spare sockets
  // (Part 6 section 7.1.3 S4), so the connection and channel counters carry traffic this test did
  // not cause, while sessions are created only here.
  ASSERT_EQ(afterInbound.cumulatedSessionCount - beforeInbound.cumulatedSessionCount, 1u)
    << "the inbound session was not counted, so this comparison would prove nothing";
  ASSERT_EQ(afterInbound.currentSessionCount - beforeInbound.currentSessionCount, 1u)
    << "the inbound session did not reach the live session count";

  EXPECT_EQ(afterReverse.cumulatedSessionCount - afterInbound.cumulatedSessionCount,
    afterInbound.cumulatedSessionCount - beforeInbound.cumulatedSessionCount)
    << "a session created over a reverse channel must be counted as any other session is";
  EXPECT_EQ(afterReverse.currentSessionCount - afterInbound.currentSessionCount,
    afterInbound.currentSessionCount - beforeInbound.currentSessionCount)
    << "a session created over a reverse channel must appear in the live session count";

  // ... and both are visible in the per-session diagnostics under their own names.
  const auto sessionSnapshots = mServer->server().session_health_snapshots();
  ASSERT_FALSE(sessionSnapshots.empty()) << "the server reported no session diagnostics at all";
  const bool inboundDiagnosed = std::any_of(sessionSnapshots.begin(),
    sessionSnapshots.end(),
    [](const SessionHealthSnapshot& snapshot) { return snapshot.sessionName == "RC-015-inbound"; });
  const bool reverseDiagnosed = std::any_of(sessionSnapshots.begin(),
    sessionSnapshots.end(),
    [](const SessionHealthSnapshot& snapshot) { return snapshot.sessionName == "RC-015-reverse"; });
  EXPECT_TRUE(inboundDiagnosed) << "the inbound session must appear in the per-session diagnostics";
  EXPECT_TRUE(reverseDiagnosed)
    << "a session created over a reverse channel must appear in the same per-session diagnostics";

  // Same security processing: the endpoints, security modes and policies advertised over the two
  // channels are the same set. A parallel reverse path is what would make them diverge.
  GetEndpointsRequest inboundRequest;
  inboundRequest.endpoint_url() = mServerEndpointUrl;
  auto inboundEndpoints = inboundChannel.get_endpoints_sync(std::move(inboundRequest));
  ASSERT_TRUE(inboundEndpoints.response_header().service_result().is_good());

  GetEndpointsRequest reverseRequest;
  reverseRequest.endpoint_url() = mServerEndpointUrl;
  auto reverseEndpoints = reverseChannel.get_endpoints_sync(std::move(reverseRequest));
  ASSERT_TRUE(reverseEndpoints.response_header().service_result().is_good())
    << "GetEndpoints must be served on a reverse-arrived channel exactly as on an inbound one";

  const auto inboundSummaries = endpoint_summaries(inboundEndpoints);
  const auto reverseSummaries = endpoint_summaries(reverseEndpoints);
  ASSERT_FALSE(inboundSummaries.empty()) << "the server advertised no endpoints at all";
  EXPECT_EQ(reverseSummaries, inboundSummaries)
    << "a reverse-arrived channel must see the same advertised endpoints, security modes and "
       "policies as an inbound channel";

  // Same session handling: both sessions serve the same request, each echoing its own handle.
  auto inboundRead = inboundSession.attributes().read_sync(make_state_read(5101));
  ASSERT_TRUE(inboundRead.response_header().service_result().is_good());
  EXPECT_EQ(inboundRead.response_header().request_handle(), 5101u);
  ASSERT_EQ(inboundRead.results().size(), 1u);
  EXPECT_FALSE(inboundRead.results()[0].status().has_value());

  auto reverseRead = reverseSession.attributes().read_sync(make_state_read(5202));
  ASSERT_TRUE(reverseRead.response_header().service_result().is_good())
    << "a reverse-arrived channel must serve the same session services";
  EXPECT_EQ(reverseRead.response_header().request_handle(), 5202u);
  ASSERT_EQ(reverseRead.results().size(), 1u);
  EXPECT_FALSE(reverseRead.results()[0].status().has_value());
  EXPECT_EQ(reverseRead.results()[0].value().as<int32_t>(), inboundRead.results()[0].value().as<int32_t>())
    << "the same read must return the same value whichever direction the channel arrived from";

  reverseSession.close_sync();
  reverseChannel.close_sync();
  inboundSession.close_sync();
  inboundChannel.close_sync();
  mServer->server().stop_reverse_connect_sync(serverRcHandle);
}

// ---------------------------------------------------------------------------
// RC-016: A ReverseHello ServerUri of 4096 bytes or more is refused before it is matched
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.6: the RHE ServerUri's encoded value shall be less than 4 096 bytes, and a
// Client shall answer Bad_TcpEndpointUrlInvalid and close. The bound is a PARSE-TIME guard, so
// checking it after matching the URI against the configured set defeats its purpose - the listener
// would have read and compared an arbitrarily long attacker-supplied string first. The oversized URI
// used here IS the one the listener is configured to expect, so a listener that matched first would
// accept the connection and answer with a Hello: only the length bound can refuse it.
// @verifies AC-SVR-TCP-016-LEN
// @relation(SVR-TCP-016, scope=function)
TEST_F(ReverseConnectIntegration, ReverseHelloWithAnOversizedServerUriIsRefusedBeforeItIsMatched)
{
  const auto port = find_free_port();

  // Well past the 4 096-byte bound, and still inside the stack's maximum ReverseHello size, so the
  // refusal is the URI-length rule and not a whole-message size guard standing in front of it.
  const std::string oversizedServerUri(5000, 'u');

  ReverseConnectListenerConfig listenerConfig;
  listenerConfig.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  listenerConfig.bind.address = fmt::format("127.0.0.1:{}", port);
  listenerConfig.expectedServers.push_back(ExpectedServer{
    .serverUri = oversizedServerUri,
    .endpointUrls = {mServerEndpointUrl},
  });
  listenerConfig.maxQueuedConnections = 5;
  listenerConfig.initialMessageTimeout = std::chrono::seconds{10};

  mClientReverseConnectHandle = mClient->core().start_reverse_connect_sync(std::move(listenerConfig));

  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // The waiter must exist before the ReverseHello arrives: a handshake failure is reported to the
  // waiters registered at the moment it happens.
  auto opened = std::async(std::launch::async,
    [this]
    {
      return mClient->core().try_open_channel_sync({
        .endpointUrl = mServerEndpointUrl,
        .connectMode = ConnectMode::Reverse,
        .timeout = std::chrono::milliseconds{8000},
      });
    });
  std::this_thread::sleep_for(std::chrono::milliseconds{300});

  RawReverseHelloSender sender(port);
  ASSERT_TRUE(sender.connect()) << "the client's reverse-connect listener must accept the connection";
  ASSERT_TRUE(sender.write_all(encode_reverse_hello_bytes(oversizedServerUri, mServerEndpointUrl)))
    << "the oversized ReverseHello must reach the listener";

  std::string received;
  const bool closed = sender.read_until_closed(std::chrono::milliseconds{5000}, received);

  EXPECT_TRUE(closed)
    << "the listener must close a connection whose ReverseHello carries an oversized ServerUri";
  EXPECT_EQ(received.find("HEL"), std::string::npos)
    << "the listener must not answer with a Hello: the length bound precedes matching the URI "
       "against the configured set, and this URI is in that set";

  auto result = opened.get();
  ASSERT_TRUE(result.is_bad()) << "an oversized ServerUri must not produce a channel";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTcpEndpointUrlInvalid})
    << "the refusal must be reported as Bad_TcpEndpointUrlInvalid";
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "ReverseConnectListener")
    << "the refusal must come from the listener's own validation, not from the open timing out";
}

// ---------------------------------------------------------------------------
// RC-017: An unreachable target's retry loop leaves an established sibling channel serving
// ---------------------------------------------------------------------------
// Part 6 section 7.1.3 / SVR-RC-017: each target owns its strand, pending-socket list and timers, so
// a failing target's retry loop is invisible to its siblings. "Connected" for a reverse-connect
// target does not stop at the socket: the sibling that matters is the one carrying a live
// SecureChannel and a Session. An implementation whose per-target isolation reaches only as far as
// the dial - separate sockets, but the connect/retry work still funnelled through one shared strand
// or one shared executor slot - keeps every pending socket open while the unreachable target backs
// off, and is caught only where a sibling has to SERVE something during that window.
//
// Every observation is attributed to exactly one target, because each target has its own peer: the
// established channel can only be the target pointed at the client's listener, the held-open socket
// can only be the target pointed at the raw acceptor, and the unreachable target's port carries no
// acceptor at all until the other two are up - so a connection arriving there afterwards can only be
// a repeated attempt by that target.
// @verifies AC-SVR-RC-017-MULTIPLE-TARGETS
// @relation(SVR-RC-017, scope=function)
TEST_F(ReverseConnectIntegration, ReachableTargetsKeepServingWhileAnUnreachableSiblingRetries)
{
  // Declared first so they outlive the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer pendingPeer;
  const auto unreachablePort = find_free_port();  // reserved, deliberately left unbound
  std::optional<RawReverseConnectPeer> latePeer;

  TestServer server;
  // Long, so no pending socket can be closed by the no-Hello deadline inside the test window: a
  // socket that dies here must be the unreachable sibling's doing, which is what this test excludes.
  server.create([](ua::ApplicationConfig& appCfg)
    { appCfg.stack_limits().connectionProtocolTimeout = std::chrono::seconds{120}; },
    nullptr,
    nullptr);

  auto listener = server.listen_ephemeral();
  server.add_endpoint(listener, none_endpoint());
  server.start();

  auto urls = server.server().advertised_urls(listener);
  ASSERT_FALSE(urls.empty());
  const std::string serverEndpointUrl = urls.front().str();
  const std::string serverApplicationUri =
    server.server().config().application->application_description_part().applicationUri;

  // A real client listener, so one of the reachable targets gets all the way to a SecureChannel.
  const auto clientPort = find_free_port();
  ReverseConnectListenerConfig listenerConfig;
  listenerConfig.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  listenerConfig.bind.address = fmt::format("127.0.0.1:{}", clientPort);
  listenerConfig.expectedServers.push_back(ExpectedServer{
    .serverUri = serverApplicationUri,
    .endpointUrls = {serverEndpointUrl},
  });
  listenerConfig.maxQueuedConnections = 5;
  listenerConfig.initialMessageTimeout = std::chrono::seconds{10};
  mClientReverseConnectHandle = mClient->core().start_reverse_connect_sync(std::move(listenerConfig));
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  auto startTarget = [&](const std::string& name, const std::string& clientUrl, std::chrono::seconds periodic)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = clientUrl;
    target.serverEndpointUrl = serverEndpointUrl;
    target.endpoints = server.server().endpoints(listener);
    target.periodicConnectInterval = periodic;
    target.maxPendingSockets = 5;
    return server.server().start_reverse_connect_sync(std::move(target));
  };

  // The two reachable targets dial and hold; only the unreachable one keeps trying.
  auto servingHandle = startTarget(
    "ServingTarget", fmt::format("opc.tcp://127.0.0.1:{}", clientPort), std::chrono::seconds{120});
  auto pendingHandle = startTarget("PendingTarget", pendingPeer.url(), std::chrono::seconds{120});
  auto unreachableHandle = startTarget(
    "UnreachableTarget", fmt::format("opc.tcp://127.0.0.1:{}", unreachablePort), std::chrono::seconds{2});

  // Sibling 1: dialled its own acceptor and is being held open awaiting a Hello.
  ASSERT_TRUE(pendingPeer.accept_one(std::chrono::milliseconds{15000}))
    << "an unreachable sibling must not stop a second target from dialling its own client endpoint";
  std::string pendingBytes;
  ASSERT_FALSE(pendingPeer.read_until_closed(0, std::chrono::milliseconds{500}, pendingBytes))
    << "the second target's connection must be held open";
  ASSERT_GE(pendingBytes.size(), 3u) << "the second target's connection sent nothing";
  EXPECT_EQ(pendingBytes.substr(0, 3), "RHE") << "the second target's connection must carry a ReverseHello";

  // Sibling 2: all the way to a SecureChannel and an activated Session.
  auto channel = mClient->core().open_channel_sync({
    .endpointUrl = serverEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel.is_open())
    << "an unreachable sibling must not stop a target from establishing its channel";
  auto session = channel.create_session_sync({.sessionName = "RC-017-serving"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  auto before = session.attributes().read_sync(make_state_read(7101));
  ASSERT_TRUE(before.response_header().service_result().is_good());
  EXPECT_EQ(before.response_header().request_handle(), 7101u);
  ASSERT_EQ(before.results().size(), 1u);
  ASSERT_FALSE(before.results()[0].status().has_value());
  ASSERT_EQ(before.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  // Nothing could accept on the third target's port until this line, so a connection arriving there
  // now can only come from a repeated attempt by that target.
  latePeer.emplace(unreachablePort);
  ASSERT_TRUE(latePeer->accept_one(std::chrono::milliseconds{25000}))
    << "the unreachable target must keep retrying on its own schedule";
  std::string lateBytes;
  (void)latePeer->read_until_closed(0, std::chrono::milliseconds{1000}, lateBytes);
  ASSERT_GE(lateBytes.size(), 3u) << "the retried connection sent nothing";
  EXPECT_EQ(lateBytes.substr(0, 3), "RHE") << "the retry must be a real reverse connect, not a bare socket";

  // ... and neither sibling was touched by any of it: the established one still serves, and the
  // pending one is still open.
  EXPECT_TRUE(channel.is_open())
    << "an established sibling channel must survive an unreachable target's retry loop";
  EXPECT_TRUE(session.is_active())
    << "an established sibling session must survive an unreachable target's retry loop";

  auto after = session.attributes().read_sync(make_state_read(7202));
  EXPECT_TRUE(after.response_header().service_result().is_good())
    << "the established sibling must still be served while an unreachable target retries";
  EXPECT_EQ(after.response_header().request_handle(), 7202u);
  ASSERT_EQ(after.results().size(), 1u);
  EXPECT_FALSE(after.results()[0].status().has_value());
  EXPECT_EQ(after.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  EXPECT_FALSE(pendingPeer.read_until_closed(0, std::chrono::milliseconds{500}, pendingBytes))
    << "the pending sibling's connection must survive an unreachable target's retry loop";

  session.close_sync();
  channel.close_sync();

  // Per-target lifecycle: each handle addresses its own target, and none of the three is a no-op.
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(unreachableHandle).is_good())
    << "the unreachable target must still be individually stoppable";
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(pendingHandle).is_good());
  EXPECT_TRUE(server.server().try_stop_reverse_connect_sync(servingHandle).is_good());
}

// ===========================================================================
// Helpers for the obligations below.
//
// These are stated over the BYTES the server writes: the header slots of the ReverseHello and the
// lengths of its two String fields. Nothing above the transport can see them, so the observation is
// taken from a bare TCP acceptor and decoded here.
// ===========================================================================

namespace
{

/// Reads the little-endian UInt32 at @p offset out of raw wire bytes (Part 6 section 5.2.2.1 encodes
/// every integer least-significant byte first). The caller must have checked the length first.
uint32_t read_uint32_le(const std::string& bytes, size_t offset)
{
  const auto byteAt = [&bytes](size_t index)
  {
    return static_cast<uint32_t>(static_cast<unsigned char>(bytes[index]));
  };
  return byteAt(offset) | (byteAt(offset + 1) << 8) | (byteAt(offset + 2) << 16) | (byteAt(offset + 3) << 24);
}

/// A URL of exactly @p length bytes that still parses as an endpoint URL, so a length rule is the
/// only thing that can refuse it.
std::string endpoint_url_of_length(size_t length)
{
  const std::string prefix = "opc.tcp://127.0.0.1:4840/";
  return prefix + std::string(length - prefix.size(), 'p');
}

void override_outgoing_reverse_hello_server_uri(Server& server, std::string serverUri)
{
  // The effective application configuration is otherwise immutable. This test owns the idle server and
  // overrides it only after startup, so namespace metadata is built from the valid URI while the
  // ServerReverseConnectDeps snapshot receives the injected outgoing RHE value.
  auto& application = const_cast<ApplicationConfig&>(*server.config().application);
  application.application_description_part().applicationUri = std::move(serverUri);
}

}  // namespace

// ---------------------------------------------------------------------------
// RC-018: The ReverseHello header carries the RHE message type and the reserved byte
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.2 Table 65: the 8-byte header puts the ASCII bytes `R`, `H`, `E` in the
// MessageType slot, the ASCII `F` in the Reserved slot, and a MessageSize that counts the header
// itself. The Reserved byte is the one a plausible implementation gets wrong: Table 65 documents it
// as ignored on receipt, so a header struct left zero-initialised ships 0x00 and is accepted by every
// peer that follows the specification and refused only by the ones that check it - a defect no
// connectivity test can surface. The bytes are read off the socket rather than from the encoder, so
// what is asserted is what the peer actually receives.
// @verifies AC-SVR-RC-002-RHE-MESSAGETYPE
TEST_F(ReverseConnectIntegration, ReverseHelloHeaderCarriesTheRheMessageTypeAndReservedByte)
{
  RawReverseConnectPeer peer;

  ServerConfig::ReverseConnectTarget target;
  target.name = "HeaderTarget";
  target.clientApplicationUri = clientApplicationUri;
  target.clientEndpointUrl = peer.url();
  target.serverEndpointUrl = mServerEndpointUrl;
  target.endpoints = mServer->server().endpoints(mListener);
  // Long, so the bytes read below are the ones the start dialled and no periodic extra muddies them.
  target.periodicConnectInterval = std::chrono::seconds{60};
  target.maxPendingSockets = 5;
  auto handle = mServer->server().start_reverse_connect_sync(std::move(target));

  ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{10000}))
    << "the target must dial the configured client endpoint";

  std::string bytes;
  const bool closed = peer.read_until_closed(0, std::chrono::milliseconds{1500}, bytes);
  ASSERT_FALSE(closed) << "the server must hold the dialled connection open awaiting the client's Hello";
  ASSERT_GE(bytes.size(), 8u) << "the dialled connection carried no complete message header";

  EXPECT_EQ(bytes.substr(0, 3), "RHE")
    << "the first three bytes must be the ASCII MessageType of a ReverseHello";

  const auto reservedByte = static_cast<unsigned>(static_cast<unsigned char>(bytes[3]));
  EXPECT_EQ(reservedByte, static_cast<unsigned>('F'))
    << "the Reserved byte must carry ASCII 'F' (0x46), not the 0x00 a zero-initialised header leaves "
       "behind; receivers are told to ignore it, which is exactly why a wrong value survives testing";

  const uint32_t messageSize = read_uint32_le(bytes, 4);
  EXPECT_EQ(static_cast<size_t>(messageSize), bytes.size())
    << "MessageSize must be the length of the whole message including its own 8-byte header; the "
       "ReverseHello is the only thing the server writes before the Hello arrives";

  mServer->server().stop_reverse_connect_sync(handle);
}

// ---------------------------------------------------------------------------
// RC-019: A ReverseHello is never sent carrying an over-bound ServerUri
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.6 Table 69: the RHE `ServerUri` is the server's ApplicationUri and its encoded
// value shall be less than 4 096 bytes. The test starts a valid server, then injects the outgoing-only
// value after namespace metadata startup so the stimulus reaches ReverseHello validation without weakening
// the independent DisplayName limit. A manager that encodes whatever it is handed puts a wire-malformed
// message on a connection it dialled itself; the control target proves this peer sees a ReverseHello when
// one is sent, so the negative cannot pass by observing nothing at all.
// @relation(AC-SVR-RC-005-RHE-SERVERURI-LENGTH, scope=function)
TEST_F(ReverseConnectIntegration, ReverseHelloIsNotSentWithAnOversizedServerUri)
{
  // Declared first so they outlive the servers, whose shutdown closes the sockets dialled here.
  RawReverseConnectPeer oversizedPeer;
  RawReverseConnectPeer controlPeer;

  // Well past the 4 096-byte bound, and still leaving the whole message inside the stack's maximum
  // ReverseHello size, so any refusal is the field-length rule and not a whole-message size guard.
  const std::string oversizedApplicationUri = "uri://reduktive.com/TestServer/" + std::string(5000, 'u');

  TestServer oversizedServer;
  oversizedServer.create();

  auto oversizedListener = oversizedServer.listen_ephemeral();
  oversizedServer.add_endpoint(oversizedListener, none_endpoint());
  oversizedServer.start();

  override_outgoing_reverse_hello_server_uri(oversizedServer.server(), oversizedApplicationUri);

  auto oversizedUrls = oversizedServer.server().advertised_urls(oversizedListener);
  ASSERT_FALSE(oversizedUrls.empty());

  ServerConfig::ReverseConnectTarget oversizedTarget;
  oversizedTarget.name = "OversizedUriTarget";
  oversizedTarget.clientApplicationUri = clientApplicationUri;
  oversizedTarget.clientEndpointUrl = oversizedPeer.url();
  oversizedTarget.serverEndpointUrl = oversizedUrls.front().str();
  oversizedTarget.endpoints = oversizedServer.server().endpoints(oversizedListener);
  oversizedTarget.periodicConnectInterval = std::chrono::seconds{60};
  oversizedTarget.maxPendingSockets = 5;
  auto oversizedHandle = oversizedServer.server().start_reverse_connect_sync(std::move(oversizedTarget));

  // The control: the fixture's server, whose ApplicationUri is well inside the bound.
  ServerConfig::ReverseConnectTarget controlTarget;
  controlTarget.name = "ControlUriTarget";
  controlTarget.clientApplicationUri = clientApplicationUri;
  controlTarget.clientEndpointUrl = controlPeer.url();
  controlTarget.serverEndpointUrl = mServerEndpointUrl;
  controlTarget.endpoints = mServer->server().endpoints(mListener);
  controlTarget.periodicConnectInterval = std::chrono::seconds{60};
  controlTarget.maxPendingSockets = 5;
  auto controlHandle = mServer->server().start_reverse_connect_sync(std::move(controlTarget));

  ASSERT_TRUE(controlPeer.accept_one(std::chrono::milliseconds{10000}))
    << "the control target must dial its own client endpoint";
  std::string controlBytes;
  ASSERT_FALSE(controlPeer.read_until_closed(0, std::chrono::milliseconds{1500}, controlBytes))
    << "the control connection must be held open awaiting the Hello";
  ASSERT_GE(controlBytes.size(), 12u) << "the control connection carried no ReverseHello body";
  ASSERT_EQ(controlBytes.substr(0, 3), "RHE") << "the control connection must carry a ReverseHello";

  // The ServerUri is the first body String: a 4-byte length at offset 8, then its bytes. Reading it
  // back off the control connection is what makes the assertion over the oversized one meaningful.
  const uint32_t controlServerUriLength = read_uint32_le(controlBytes, 8);
  ASSERT_EQ(static_cast<size_t>(controlServerUriLength), mServerApplicationUri.size())
    << "the ReverseHello's first body String must be the server's own ApplicationUri";
  ASSERT_NE(controlBytes.find(mServerApplicationUri), std::string::npos)
    << "the control ReverseHello must carry the ApplicationUri itself";
  ASSERT_LT(controlServerUriLength, 4096u) << "the control server's own URI must be inside the bound";

  // The oversized server: the connection is dialled, and then nothing that carries the URI may be
  // written to it.
  ASSERT_TRUE(oversizedPeer.accept_one(std::chrono::milliseconds{10000}))
    << "the target must dial before the encoding of its ServerUri can be judged";
  std::string oversizedBytes;
  const bool closed = oversizedPeer.read_until_closed(0, std::chrono::milliseconds{6000}, oversizedBytes);

  const bool sentReverseHello = (oversizedBytes.size() >= 3) && (oversizedBytes.compare(0, 3, "RHE") == 0);
  EXPECT_FALSE(sentReverseHello)
    << "a ReverseHello whose ServerUri exceeds 4 096 bytes must not be sent at all: the manager has to "
       "refuse the message rather than ship one the client will reject";
  EXPECT_EQ(oversizedBytes.find(oversizedApplicationUri), std::string::npos)
    << "the over-bound ApplicationUri must never reach the wire";
  EXPECT_TRUE(closed) << "the server must close a connection whose ReverseHello fields are invalid";

  mServer->server().stop_reverse_connect_sync(controlHandle);
  oversizedServer.server().stop_reverse_connect_sync(oversizedHandle);
}

// ---------------------------------------------------------------------------
// RC-020: A ReverseHello EndpointUrl of 4 096 bytes or more is refused and the connection closed
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.6 Table 69: the RHE `EndpointUrl`'s encoded value shall be LESS THAN 4 096
// bytes. Since 2026-09-30 the SDK applies the same encoded-length rule (the four-byte prefix plus the
// bytes, less than 4 096) to the Hello EndpointUrl of section 7.1.2.3 as well, on both sides; an
// implementation with a looser `> 4096` check would emit a 4 096-byte EndpointUrl that every
// conforming client refuses while the server that wrote it reports nothing wrong. Both an over-bound
// and an at-bound configuration are driven, and each must produce the whole observation - no
// ReverseHello on the wire AND the connection closed. The control target proves this peer sees a
// ReverseHello when one is sent, so neither negative can pass by observing nothing at all.
// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST_F(ReverseConnectIntegration, ReverseHelloWithAnOversizedEndpointUrlIsRefusedAndTheConnectionClosed)
{
  RawReverseConnectPeer controlPeer;
  RawReverseConnectPeer overBoundPeer;
  RawReverseConnectPeer atBoundPeer;

  const std::string overBoundUrl = endpoint_url_of_length(5000);
  const std::string atBoundUrl = endpoint_url_of_length(4096);
  ASSERT_EQ(overBoundUrl.size(), 5000u);
  ASSERT_EQ(atBoundUrl.size(), 4096u);

  auto startTarget =
    [this](const std::string& name, const std::string& clientUrl, const std::string& serverEndpointUrl)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = clientUrl;
    target.serverEndpointUrl = serverEndpointUrl;
    target.endpoints = mServer->server().endpoints(mListener);
    // Long, so the sockets observed below are the ones the start dialled.
    target.periodicConnectInterval = std::chrono::seconds{60};
    target.maxPendingSockets = 5;
    return mServer->server().start_reverse_connect_sync(std::move(target));
  };

  auto controlHandle = startTarget("ControlUrlTarget", controlPeer.url(), mServerEndpointUrl);
  auto overBoundHandle = startTarget("OverBoundUrlTarget", overBoundPeer.url(), overBoundUrl);
  auto atBoundHandle = startTarget("AtBoundUrlTarget", atBoundPeer.url(), atBoundUrl);

  // The control: a ReverseHello inside the bound is written and the connection held open. Everything
  // asserted below is the absence of exactly this, so it has to be shown to be observable first.
  ASSERT_TRUE(controlPeer.accept_one(std::chrono::milliseconds{15000}))
    << "the control target must dial its own client endpoint";
  std::string controlBytes;
  ASSERT_FALSE(controlPeer.read_until_closed(0, std::chrono::milliseconds{1500}, controlBytes))
    << "the control connection must be held open awaiting the Hello";
  ASSERT_GE(controlBytes.size(), 3u) << "the control connection sent nothing";
  ASSERT_EQ(controlBytes.substr(0, 3), "RHE")
    << "an EndpointUrl inside the bound must produce a ReverseHello on the wire";

  auto expectRefusedAndClosed =
    [](RawReverseConnectPeer& peer, const std::string& endpointUrl, const std::string& label)
  {
    ASSERT_TRUE(peer.accept_one(std::chrono::milliseconds{15000}))
      << label << ": the target must dial before the encoding of its EndpointUrl can be judged";

    std::string bytes;
    const bool closed = peer.read_until_closed(0, std::chrono::milliseconds{6000}, bytes);

    const bool sentReverseHello = (bytes.size() >= 3) && (bytes.compare(0, 3, "RHE") == 0);
    EXPECT_FALSE(sentReverseHello)
      << label
      << ": a ReverseHello whose EndpointUrl reaches 4 096 bytes must be refused, not written to the "
         "connection";
    EXPECT_EQ(bytes.find(endpointUrl), std::string::npos)
      << label << ": the EndpointUrl at or beyond the bound must never reach the wire";
    EXPECT_TRUE(closed)
      << label
      << ": the connection must be closed once the ReverseHello is refused, not left open carrying "
         "nothing the client can act on";
  };

  expectRefusedAndClosed(overBoundPeer, overBoundUrl, "EndpointUrl of 5 000 bytes");
  expectRefusedAndClosed(atBoundPeer, atBoundUrl, "EndpointUrl of exactly 4 096 bytes");

  mServer->server().stop_reverse_connect_sync(atBoundHandle);
  mServer->server().stop_reverse_connect_sync(overBoundHandle);
  mServer->server().stop_reverse_connect_sync(controlHandle);
}

// ---------------------------------------------------------------------------
// RC-021: A ReverseHello whose EndpointUrl ENCODING reaches 4 096 bytes is refused and closed
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.6 Table 69 bounds the RHE `EndpointUrl`'s ENCODED value, and a Part-6 String
// is encoded as a four-byte length prefix followed by its characters (section 5.2.2.4). SVR-RC-006
// therefore bites at a raw URL of 4 092 characters: its encoding is exactly 4 096 bytes, which is not
// less than 4 096. A plausible implementation bounds the raw `size()` instead - the field and its
// encoding differ by four bytes, and every URL an administrator ever types is three orders of
// magnitude below either - so the length prefix goes uncounted and a message the specification calls
// malformed is written to a connection the server dialled itself: the client refuses it, the target's
// own retry loop re-sends it, and nothing on the server reports a fault. Both conjuncts of the
// observation are asserted, the refusal (no ReverseHello, and the URL nowhere on the wire) and the
// close. The control target proves this peer sees a ReverseHello when one is sent, and its own
// EndpointUrl field is decoded back off the wire, so the negative cannot pass by observing nothing at
// all nor by the second body String being something other than the URL under test.
// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST_F(ReverseConnectIntegration, ReverseHelloWithAnEndpointUrlEncodingAtTheBoundIsRefusedAndClosed)
{
  // Declared first so they outlive the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer controlPeer;
  RawReverseConnectPeer boundPeer;

  // 4 092 raw characters, so the Part-6 String encoding is exactly 4 096 bytes - the shortest URL the
  // bound excludes, and the one a raw-size check lets through.
  const std::string atEncodedBoundUrl = endpoint_url_of_length(4092);
  ASSERT_EQ(atEncodedBoundUrl.size(), 4092u);
  ASSERT_EQ(sizeof(uint32_t) + atEncodedBoundUrl.size(), 4096u)
    << "this URL must encode to exactly the bound for the test to be about the bound";

  auto startTarget =
    [this](const std::string& name, const std::string& clientUrl, const std::string& serverEndpointUrl)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = clientUrl;
    target.serverEndpointUrl = serverEndpointUrl;
    target.endpoints = mServer->server().endpoints(mListener);
    // Long, so the socket observed below is the one the start dialled and no periodic extra muddies it.
    target.periodicConnectInterval = std::chrono::seconds{60};
    target.maxPendingSockets = 5;
    return mServer->server().start_reverse_connect_sync(std::move(target));
  };

  auto controlHandle = startTarget("EncodedControlTarget", controlPeer.url(), mServerEndpointUrl);
  auto boundHandle = startTarget("EncodedBoundTarget", boundPeer.url(), atEncodedBoundUrl);

  // The control: a ReverseHello whose EndpointUrl encodes to less than the bound is written and the
  // connection held open. Everything asserted afterwards is the absence of exactly this.
  ASSERT_TRUE(controlPeer.accept_one(std::chrono::milliseconds{15000}))
    << "the control target must dial its own client endpoint";
  std::string controlBytes;
  ASSERT_FALSE(controlPeer.read_until_closed(0, std::chrono::milliseconds{1500}, controlBytes))
    << "the control connection must be held open awaiting the Hello";
  ASSERT_GE(controlBytes.size(), 12u) << "the control connection carried no ReverseHello body";
  ASSERT_EQ(controlBytes.substr(0, 3), "RHE")
    << "an EndpointUrl inside the bound must produce a ReverseHello on the wire";

  // The body is ServerUri then EndpointUrl, each a 4-byte length followed by its bytes. Decoding the
  // second one back proves the field this obligation is stated over is the field being observed.
  const uint32_t controlServerUriLength = read_uint32_le(controlBytes, 8);
  const size_t endpointUrlLengthOffset = 12u + static_cast<size_t>(controlServerUriLength);
  ASSERT_GE(controlBytes.size(), endpointUrlLengthOffset + 4u)
    << "the control ReverseHello carried no EndpointUrl field";
  const uint32_t controlEndpointUrlLength = read_uint32_le(controlBytes, endpointUrlLengthOffset);
  ASSERT_EQ(static_cast<size_t>(controlEndpointUrlLength), mServerEndpointUrl.size())
    << "the ReverseHello's second body String must be the target's own ServerEndpointUrl";
  ASSERT_NE(controlBytes.find(mServerEndpointUrl), std::string::npos)
    << "the control ReverseHello must carry the ServerEndpointUrl itself";
  ASSERT_LT(sizeof(uint32_t) + static_cast<size_t>(controlEndpointUrlLength), 4096u)
    << "the control target's URL must encode to less than the bound";

  // The target at the bound: the connection is dialled, and then nothing carrying that URL may be
  // written to it, and it must not be left open.
  ASSERT_TRUE(boundPeer.accept_one(std::chrono::milliseconds{15000}))
    << "the target must dial before the encoding of its EndpointUrl can be judged";
  std::string boundBytes;
  const bool closed = boundPeer.read_until_closed(0, std::chrono::milliseconds{6000}, boundBytes);

  const bool sentReverseHello = (boundBytes.size() >= 3) && (boundBytes.compare(0, 3, "RHE") == 0);
  EXPECT_FALSE(sentReverseHello)
    << "an EndpointUrl whose Part-6 String encoding reaches 4 096 bytes must be refused rather than "
       "encoded and written: the four bytes of the length prefix count towards the bound";
  EXPECT_EQ(boundBytes.find(atEncodedBoundUrl), std::string::npos)
    << "an EndpointUrl at or beyond the encoded bound must never reach the wire";
  EXPECT_TRUE(closed)
    << "the connection must be closed once the ReverseHello is refused, not left open awaiting a "
       "Hello no conforming client will send";

  mServer->server().stop_reverse_connect_sync(boundHandle);
  mServer->server().stop_reverse_connect_sync(controlHandle);
}

// ---------------------------------------------------------------------------
// RC-022: The EndpointUrl refusal begins exactly where Part 6 puts it, and not before
// ---------------------------------------------------------------------------
// Part 6 section 7.1.2.6 Table 69 bounds the RHE `EndpointUrl`'s ENCODED value below 4 096 bytes, and
// a Part-6 String encodes as a four-byte length prefix plus its characters (section 5.2.2.4). The
// bound therefore falls between two adjacent URLs: 4 091 raw characters encode to 4 095 bytes and are
// the longest the specification permits, while 4 092 encode to 4 096 and are the shortest it forbids.
// A negative stated only over a grossly oversized URL is satisfied by an implementation that refuses
// on any threshold at all - a shared HEL guard, a stricter house limit, a truncating encoder - so
// nothing pins the refusal to the quantity the specification names. Driving the adjacent pair pins
// it: the last legal URL must be encoded, written and its length decoded back off the wire with the
// connection held open, and the first illegal one must produce no ReverseHello, must not appear on
// the wire, and must have its connection closed.
// @relation(AC-SVR-RC-006-RHE-URL-LENGTH, scope=function)
TEST_F(ReverseConnectIntegration, ReverseHelloEndpointUrlRefusalBeginsAtTheEncodedFourKilobyteBound)
{
  // Declared first so they outlive the server, whose shutdown closes the sockets it dialled here.
  RawReverseConnectPeer lastLegalPeer;
  RawReverseConnectPeer firstRefusedPeer;

  // The adjacent pair either side of the bound: 4 091 raw characters encode to 4 095 bytes, 4 092 to
  // exactly 4 096. Nothing but the encoded-length rule distinguishes them.
  const std::string lastLegalUrl = endpoint_url_of_length(4091);
  const std::string firstRefusedUrl = endpoint_url_of_length(4092);
  ASSERT_EQ(lastLegalUrl.size(), 4091u);
  ASSERT_EQ(firstRefusedUrl.size(), 4092u);
  ASSERT_EQ(sizeof(uint32_t) + lastLegalUrl.size(), 4095u)
    << "the accepted side of the pair must encode to one byte inside the bound";
  ASSERT_EQ(sizeof(uint32_t) + firstRefusedUrl.size(), 4096u)
    << "the refused side of the pair must encode to exactly the bound";

  auto startTarget =
    [this](const std::string& name, const std::string& clientUrl, const std::string& serverEndpointUrl)
  {
    ServerConfig::ReverseConnectTarget target;
    target.name = name;
    target.clientApplicationUri = clientApplicationUri;
    target.clientEndpointUrl = clientUrl;
    target.serverEndpointUrl = serverEndpointUrl;
    target.endpoints = mServer->server().endpoints(mListener);
    // Long, so the sockets observed below are the ones the start dialled and no periodic extra
    // muddies them.
    target.periodicConnectInterval = std::chrono::seconds{60};
    target.maxPendingSockets = 5;
    return mServer->server().start_reverse_connect_sync(std::move(target));
  };

  auto lastLegalHandle = startTarget("LastLegalUrlTarget", lastLegalPeer.url(), lastLegalUrl);
  auto firstRefusedHandle = startTarget("FirstRefusedUrlTarget", firstRefusedPeer.url(), firstRefusedUrl);

  // The URL one byte inside the bound: a ReverseHello carrying it must be written in full and the
  // connection held open. This is the side that makes the refusal below a statement about the bound
  // rather than about long URLs in general, so it is decoded back off the wire and not merely
  // presumed.
  ASSERT_TRUE(lastLegalPeer.accept_one(std::chrono::milliseconds{15000}))
    << "the last-legal target must dial its own client endpoint";
  std::string lastLegalBytes;
  ASSERT_FALSE(lastLegalPeer.read_until_closed(0, std::chrono::milliseconds{2500}, lastLegalBytes))
    << "an EndpointUrl whose encoding is inside the bound must leave the connection open awaiting the "
       "Hello, not be treated as a misconfiguration";
  ASSERT_GE(lastLegalBytes.size(), 12u) << "the last-legal connection carried no ReverseHello body";
  ASSERT_EQ(lastLegalBytes.substr(0, 3), "RHE")
    << "the longest EndpointUrl the specification permits must still produce a ReverseHello";

  // The body is ServerUri then EndpointUrl, each a 4-byte length followed by its bytes. Decoding the
  // second one proves the field carried on the wire is the field this obligation is stated over.
  const uint32_t legalServerUriLength = read_uint32_le(lastLegalBytes, 8);
  const size_t legalEndpointUrlLengthOffset = 12u + static_cast<size_t>(legalServerUriLength);
  ASSERT_GE(lastLegalBytes.size(), legalEndpointUrlLengthOffset + 4u)
    << "the last-legal ReverseHello carried no EndpointUrl field";
  const uint32_t legalEndpointUrlLength = read_uint32_le(lastLegalBytes, legalEndpointUrlLengthOffset);
  EXPECT_EQ(static_cast<size_t>(legalEndpointUrlLength), lastLegalUrl.size())
    << "the ReverseHello's second body String must be the target's own 4 091-byte ServerEndpointUrl, "
       "carried whole and not truncated to fit some narrower house limit";
  EXPECT_NE(lastLegalBytes.find(lastLegalUrl), std::string::npos)
    << "the last-legal EndpointUrl must reach the wire in full";

  // The URL one byte over: no ReverseHello, the URL nowhere on the wire, and the connection closed.
  ASSERT_TRUE(firstRefusedPeer.accept_one(std::chrono::milliseconds{15000}))
    << "the first-refused target must dial before the encoding of its EndpointUrl can be judged";
  std::string refusedBytes;
  const bool refusedClosed =
    firstRefusedPeer.read_until_closed(0, std::chrono::milliseconds{6000}, refusedBytes);

  const bool sentReverseHello = (refusedBytes.size() >= 3) && (refusedBytes.compare(0, 3, "RHE") == 0);
  EXPECT_FALSE(sentReverseHello)
    << "one byte past the last legal EndpointUrl the encoding reaches 4 096 bytes, and the ReverseHello "
       "must be refused rather than written";
  EXPECT_EQ(refusedBytes.find(firstRefusedUrl), std::string::npos)
    << "the first EndpointUrl the bound excludes must never reach the wire";
  EXPECT_TRUE(refusedClosed)
    << "the connection must be closed once the ReverseHello is refused, not left open awaiting a Hello "
       "no conforming client will send";

  mServer->server().stop_reverse_connect_sync(firstRefusedHandle);
  mServer->server().stop_reverse_connect_sync(lastLegalHandle);
}

// ---------------------------------------------------------------------------
// RC-021: every reverse-connect lifecycle transition reaches the application
// ---------------------------------------------------------------------------

namespace
{

/// Records every reverse-connect transition the `ServerObserver` family carries, keyed by the target
/// name the hooks identify it with.
class ReverseConnectLifecycleRecorder : public server::ServerObserver
{
public:
  struct Transition
  {
    std::string kind;  // "opened" | "channel-established" | "closed"
    std::string targetName;
    uint32_t secureChannelId{};
    StatusCode reason{};
  };

  void on_reverse_connect_opened(const std::string& targetName, const std::string&) override
  {
    record(Transition{"opened", targetName, 0u, StatusCode{}});
  }

  void on_reverse_connect_channel_established(
    const std::string& targetName, uint32_t secureChannelId) override
  {
    record(Transition{"channel-established", targetName, secureChannelId, StatusCode{}});
  }

  void on_reverse_connect_closed(
    const std::string& targetName, const std::string&, StatusCode reason) override
  {
    record(Transition{"closed", targetName, 0u, reason});
  }

  std::vector<Transition> transitions() const
  {
    const std::lock_guard lock{mMutex};
    return mTransitions;
  }

  bool has(const std::string& kind, const std::string& targetName) const
  {
    const std::lock_guard lock{mMutex};
    return std::any_of(mTransitions.begin(),
      mTransitions.end(),
      [&kind, &targetName](const Transition& t) { return t.kind == kind && t.targetName == targetName; });
  }

  bool has_any_for(const std::string& targetName) const
  {
    const std::lock_guard lock{mMutex};
    return std::any_of(mTransitions.begin(),
      mTransitions.end(),
      [&targetName](const Transition& t) { return t.targetName == targetName; });
  }

  std::string describe() const
  {
    const std::lock_guard lock{mMutex};
    std::string out;
    for (const auto& t : mTransitions)
    {
      out += t.kind + "(" + t.targetName + ") ";
    }
    return out.empty() ? std::string{"(nothing)"} : out;
  }

private:
  void record(Transition transition)
  {
    const std::lock_guard lock{mMutex};
    mTransitions.push_back(std::move(transition));
  }

  mutable std::mutex mMutex;
  std::vector<Transition> mTransitions;
};

}  // namespace

// SVR-RC-021 records this as a DESIGN obligation rather than a specification clause, and states it as
// "operators can observe the reverse-connect machine from outside without polling - TCP socket open,
// TCP socket close (with reason StatusCode), and channel-established events are emitted via the
// existing ServerEventHandler family". A reverse connection is dialled BY the server, so there is no
// inbound accept for an application to hang its own instrumentation off; the observer stream is the
// only outside view of the machine there is.
//
// The failure case is the one that decides this. Opening and closing are the transitions an
// implementation notices it needs, because they happen on the path that works - but a target whose
// dial keeps failing is, to an application that is told nothing, indistinguishable from one that
// connected and is quietly idle. That is the state an operator most needs pushed to them, and it is
// exactly the one that an implementation which raises its hooks from the connection object cannot
// raise: there is no connection. `AC-SVR-RC-025-HEALTH-OBSERVABLE` makes that state queryable; this
// makes it pushed, and asking a poll to stand in for the push would discharge the wrong criterion.
//
// The failure arm asserts the weakest thing that still discharges it: SOME transition naming the
// unreachable target reaches the observer, so an application can tell that target apart from a
// connected one. It does not dictate which hook carries it.
// @relation(AC-SVR-RC-021-LIFECYCLE-OBSERVABLE, scope=function)
TEST_F(ReverseConnectIntegration, EveryReverseConnectLifecycleTransitionReachesTheApplicationObserver)
{
  auto observer = std::make_shared<ReverseConnectLifecycleRecorder>();
  mServer->server().set_observer(observer);

  // ---- Opening: a reachable target dials the client's listener and a channel is established on it.
  auto clientPort = start_client_listener();
  auto reachableHandle = start_server_reverse_connect(clientPort);  // named "TestTarget"
  const std::string reachableTarget{"TestTarget"};

  auto channel = mClient->core().open_channel_sync({
    .endpointUrl = mServerEndpointUrl,
    .connectMode = ConnectMode::Reverse,
    .timeout = std::chrono::milliseconds{15000},
  });
  ASSERT_TRUE(channel.is_open()) << "the reverse connection must come up, or none of the transitions "
                                    "below have a subject";
  const auto reverseChannelId = channel.secure_channel_id();
  ASSERT_NE(reverseChannelId, 0u);

  EXPECT_TRUE(wait_until(std::chrono::milliseconds{10000},
    [&observer, &reachableTarget] { return observer->has("opened", reachableTarget); }))
    << "the outbound TCP socket coming up was not delivered to the observer; seen: " << observer->describe();
  EXPECT_TRUE(wait_until(std::chrono::milliseconds{10000},
    [&observer, &reachableTarget] { return observer->has("channel-established", reachableTarget); }))
    << "the SecureChannel established over the reverse connection was not delivered to the observer; "
       "seen: "
    << observer->describe();

  // The established notification names the channel that actually exists, not merely "a" channel.
  {
    bool matchedId = false;
    for (const auto& transition : observer->transitions())
    {
      if (transition.kind == "channel-established" && transition.secureChannelId == reverseChannelId)
        matchedId = true;
    }
    EXPECT_TRUE(matchedId) << "the channel-established transition carried no SecureChannelId matching the "
                              "channel the client holds ("
                           << reverseChannelId << "); seen: " << observer->describe();
  }

  // ---- Closing: the same channel goes away, and that is delivered too.
  channel.close_sync();
  EXPECT_TRUE(wait_until(std::chrono::milliseconds{10000},
    [&observer, &reachableTarget] { return observer->has("closed", reachableTarget); }))
    << "the reverse connection closing was not delivered to the observer, so an application that was "
       "told the target came up is never told it went away; seen: "
    << observer->describe();

  // ---- Failing: a target whose client endpoint nothing is listening on. The port is reserved and
  // deliberately left unbound, so every dial fails and the target retries forever.
  const auto unreachablePort = find_free_port();
  const std::string failingTarget{"UnreachableTarget"};
  ServerConfig::ReverseConnectTarget failing;
  failing.name = failingTarget;
  failing.clientApplicationUri = clientApplicationUri;
  failing.clientEndpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", unreachablePort);
  failing.serverEndpointUrl = mServerEndpointUrl;
  failing.endpoints = mServer->server().endpoints(mListener);
  // Short, so several dials are attempted inside the window below rather than one.
  failing.periodicConnectInterval = std::chrono::seconds{1};
  failing.maxPendingSockets = 5;
  auto failingHandle = mServer->server().start_reverse_connect_sync(std::move(failing));

  // Non-vacuity: the target really is unreachable, so nothing here can be satisfied by it connecting.
  EXPECT_FALSE(observer->has("opened", failingTarget))
    << "the target chosen as unreachable connected, so the failure transition was never provoked";

  const bool failureDelivered = wait_until(std::chrono::milliseconds{12000},
    [&observer, &failingTarget] { return observer->has_any_for(failingTarget); });

  GTEST_LOG_(INFO) << "reverse-connect transitions delivered to the application: " << observer->describe();

  EXPECT_TRUE(failureDelivered)
    << "a reverse-connect target whose dial keeps failing delivered NO transition at all to the "
       "application observer, so a target retrying forever is indistinguishable from one that "
       "connected and is idle. Transitions seen across all targets: "
    << observer->describe();

  mServer->server().stop_reverse_connect_sync(failingHandle);
  mServer->server().stop_reverse_connect_sync(reachableHandle);
  mServer->server().set_observer(nullptr);
}
