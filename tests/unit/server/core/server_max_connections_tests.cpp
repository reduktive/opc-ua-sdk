// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <thread>

#include "ua_application_configuration.h"
#include "ua_get_endpoints_request.h"
#include "ua_message_security_mode.h"
#include "ua_open_secure_channel_request.h"
#include "ua_reverse_hello.h"
#include "ua_security_token_request_type.h"
#include "ua_server_impl.h"

#include <chrono>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel.h"
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include "async_test_runtime.h"
#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"

#include "ua_status.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

shared_ptr<ServerImpl> create_test_server_impl_with_max_connections(boost::asio::any_io_executor ex,
  uint32_t maxConnections, std::optional<uint32_t> maxSecureChannels = std::nullopt)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  sc.maxConnections = maxConnections;
  sc.maxSecureChannels = maxSecureChannels;
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

  auto server = ua::server::ServerImpl::create(
    ex, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

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
    /*timeout*/ std::chrono::seconds{0},
    /*connectionCompleteCallback*/
    [](StatusCode,
      shared_ptr<ua::ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    /*errorCallback*/ [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  return bundle;
}

}  // namespace

// @relation(AC-SVR-UASC-050-A-CONNECTION-ARRIVING-AT-SECURECHANNEL-CAPACITY, scope=function)

// Covers SVR-TCP-012 (coverage-audit retag).
TEST(ServerMaxConnectionsTests, MaxConnectionsLimitSendsErrAndCloses)
{
  // Drains its io_context on destruction (after ~server), per the teardown
  // contract documented in async_test_runtime.h - replaces the old
  // workGuard/stop()/join() teardown that abandoned parked async work and
  // caused the intermittent server-teardown SIGSEGV.
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex, 1));

  auto conn1 = create_connection(ex);
  auto conn2 = create_connection(ex);

  // 1st established connection should be accepted.
  ASSERT_NO_THROW(TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn1.protocol, {}, {}));

  // 2nd established connection should be rejected.
  ASSERT_NO_THROW(TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn2.protocol, {}, {}));

  ASSERT_TRUE(conn2.transport->wait_for_write_count(1, std::chrono::milliseconds{500}));

  auto allWrites = conn2.transport->writes();
  ASSERT_FALSE(allWrites.empty());

  // ERRF
  const auto& err = allWrites.front();
  ASSERT_GE(err.size(), ua::connection_protocol::headerSize);
  EXPECT_EQ(static_cast<char>(err[0]), 'E');
  EXPECT_EQ(static_cast<char>(err[1]), 'R');
  EXPECT_EQ(static_cast<char>(err[2]), 'R');
  EXPECT_EQ(static_cast<char>(err[3]), 'F');

  EXPECT_TRUE(conn2.transport->wait_for_close(std::chrono::milliseconds{500}));
}

namespace
{

// Decode the 32-bit status code carried in an ERRF error message body.
// Wire layout (OPC 10000-6 v1.05 section 7.1.2.3): bytes 0..3 = 'E','R','R','F',
// bytes 4..7 = message size (uint32 LE), bytes 8..11 = error code (uint32 LE),
// followed by the reason String. The error code starts at headerSize (8).
uint32_t decode_errf_status(const std::vector<byte>& message)
{
  const size_t statusOffset = ua::connection_protocol::headerSize;
  uint32_t status = 0;
  for (size_t i = 0; i < sizeof(uint32_t); ++i)
  {
    status |= static_cast<uint32_t>(static_cast<uint8_t>(message[statusOffset + i])) << (8 * i);
  }
  return status;
}

}  // namespace

// @relation(AC-SVR-UASC-050-A-CONNECTION-ARRIVING-AT-SECURECHANNEL-CAPACITY, scope=function)

// OPC 10000-6 v1.05 section 7.1.2.3: when the Server lacks resources to establish a new
// SecureChannel it SHALL immediately return a Bad_TcpNotEnoughResources Error Message
// and gracefully close the socket. This pins the transport-layer status for the
// secure-channel-exhaustion reject (all existing channels carry sessions, so none can be
// evicted) - it must be the transport-level Bad_TcpNotEnoughResources, NOT the
// session-level Bad_TooManySessions.
TEST(ServerMaxConnectionsTests, SecureChannelExhaustionSendsBadTcpNotEnoughResources)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  // MaxConnections high enough that the connection-level admission ceiling does not fire;
  // MaxSecureChannels = 1 so the secure-channel layer is the binding limit.
  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex,
                    /*maxConnections*/ 16,
                    /*maxSecureChannels*/ 1));

  // Seed one SecureChannel that carries a session, so it is NOT evictable.
  auto deps = TestAccess{*server}.secure_channel_dependencies();
  auto seededChannel = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  ua::server::SecureChannelTestAccess::on_strand(
    *seededChannel, [&](auto& g) { g.set_minimal_context_none(ex, "TestListener/None"); });

  // Register a session on the channel so session_count() > 0 (non-evictable).
  seededChannel->register_session(
    NodeId{1, uint32_t{777}}, [](Request) {}, [](StatusCode, shared_ptr<const ErrorDetail>) {});
  ua::server::SecureChannelTestAccess::strand_barrier(*seededChannel);
  ASSERT_EQ(seededChannel->session_count(), 1u) << "Seeded channel must host a session to be non-evictable";

  TestAccess{*server}.add_secure_channel(seededChannel);

  // Drive a fresh connection: the MaxSecureChannels limit (1) is reached and the only
  // channel has a session, so the connection must be rejected at the transport layer.
  auto conn = create_connection(ex);
  ASSERT_NO_THROW(TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn.protocol, {}, {}));

  ASSERT_TRUE(conn.transport->wait_for_write_count(1, std::chrono::milliseconds{500}));

  auto allWrites = conn.transport->writes();
  ASSERT_FALSE(allWrites.empty());

  const auto& err = allWrites.front();
  ASSERT_GE(err.size(), ua::connection_protocol::headerSize + sizeof(uint32_t));
  EXPECT_EQ(static_cast<char>(err[0]), 'E');
  EXPECT_EQ(static_cast<char>(err[1]), 'R');
  EXPECT_EQ(static_cast<char>(err[2]), 'R');
  EXPECT_EQ(static_cast<char>(err[3]), 'F');

  // The wire status code MUST be Bad_TcpNotEnoughResources, NOT Bad_TooManySessions.
  EXPECT_EQ(decode_errf_status(err), static_cast<uint32_t>(Status::BadTcpNotEnoughResources))
    << "Secure-channel exhaustion must reject with the transport-level Bad_TcpNotEnoughResources "
       "(OPC 10000-6 v1.05 section 7.1.2.3), not the session-level Bad_TooManySessions";
  EXPECT_NE(decode_errf_status(err), static_cast<uint32_t>(Status::BadTooManySessions));

  EXPECT_TRUE(conn.transport->wait_for_close(std::chrono::milliseconds{500}));

  // Drop our reference before the runtime drains, so teardown is clean.
  seededChannel.reset();
}

// ---------------------------------------------------------------------------
// Group I (B1-4): the session-less reclaim order puts never-opened channels first.
// ---------------------------------------------------------------------------

// Part 4 5.5.2.1 reclaims the oldest UNUSED session-less channel. A channel whose OPN has not been
// accepted (HEL/ACK only) has never been used, whatever its age: it reports the clock's minimum and
// so goes before every opened channel, however idle.
// @verifies AC-SVR-SC-002-NEVER-OPENED-CHANNELS-ARE-RECLAIMED-BEFORE-OPENED-ONES
TEST(ServerMaxConnectionsTests, AChannelWhoseOpnHasNotBeenAcceptedReportsTheClocksMinimumAsItsLastUse)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();
  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex, 16, 4));
  auto deps = TestAccess{*server}.secure_channel_dependencies();

  auto channel = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  EXPECT_EQ(channel->last_used_time(), std::chrono::steady_clock::time_point::min());
  channel.reset();
}

// An OPN is not use until it is accepted: a dispatched OPN that the channel refuses leaves the last use at
// the clock's minimum, so the channel still goes before every opened one. (The common dispatch point stamps
// every other decoded request; stamping the OPN there would count a refused or still-validating OPN as use.)
// @verifies AC-SVR-SC-002-NEVER-OPENED-CHANNELS-ARE-RECLAIMED-BEFORE-OPENED-ONES
TEST(ServerMaxConnectionsTests, ARefusedOpnLeavesTheChannelAtTheClocksMinimum)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();
  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex, 16, /*maxSecureChannels*/ 2));
  auto deps = TestAccess{*server}.secure_channel_dependencies();

  auto channel = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  std::atomic<bool> answered{false};
  ua::server::SecureChannelTestAccess::on_strand(*channel,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "TestListener/None");
      g.set_response_sink([&](const auto&) { answered.store(true); });
    });
  auto opn = std::make_shared<OpenSecureChannelRequest>();
  opn->client_protocol_version() = 1;  // only version 0 is supported: refused inline
  opn->request_type() = SecurityTokenRequestType::Issue;
  opn->security_mode() = MessageSecurityMode::None;
  opn->requested_lifetime() = 60000;
  ua::server::SecureChannelTestAccess::on_strand(
    *channel, [&](auto& g) { g.inject_decoded_request(1, opn, NodeId{}); });

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!answered.load() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  ASSERT_TRUE(answered.load()) << "the refused OPN must be answered";
  EXPECT_EQ(channel->last_used_time(), std::chrono::steady_clock::time_point::min())
    << "a refused OPN is not use";

  channel->close();
  channel.reset();
}

// A service body before the OPN (an OPN-typed chunk carrying some other request) is refused on a channel
// that never opened, and it is not use either: the last use stays at the clock's minimum.
// @verifies AC-SVR-SC-002-NEVER-OPENED-CHANNELS-ARE-RECLAIMED-BEFORE-OPENED-ONES
TEST(ServerMaxConnectionsTests, ARequestBeforeTheOpnLeavesTheChannelAtTheClocksMinimum)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();
  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex, 16, /*maxSecureChannels*/ 2));
  auto deps = TestAccess{*server}.secure_channel_dependencies();

  auto channel = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  std::atomic<bool> answered{false};
  ua::server::SecureChannelTestAccess::on_strand(*channel,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "TestListener/None");
      g.set_response_sink([&](const auto&) { answered.store(true); });
    });
  ua::server::SecureChannelTestAccess::on_strand(*channel,
    [&](auto& g) { g.inject_decoded_request(1, std::make_shared<GetEndpointsRequest>(), NodeId{}); });

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (!answered.load() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  ASSERT_TRUE(answered.load()) << "the premature request must be refused";
  EXPECT_EQ(channel->last_used_time(), std::chrono::steady_clock::time_point::min())
    << "a request refused before the OPN is not use";

  channel->close();
  channel.reset();
}

// Channel A is created FIRST and its OPN is accepted (the accepted OPN stamps its last use); channel B is
// created afterwards and never opened. Creation order names A; use order names B. At the ceiling the
// reclaim must take B - the accepted OPN is what makes A the used one.
// @verifies AC-SVR-SC-002-NEVER-OPENED-CHANNELS-ARE-RECLAIMED-BEFORE-OPENED-ONES
TEST(ServerMaxConnectionsTests, TheReclaimTakesTheNeverOpenedChannelBeforeAnOlderOpenedOne)
{
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();
  shared_ptr<ServerImpl> server;
  ASSERT_NO_THROW(server = create_test_server_impl_with_max_connections(ex, 16, /*maxSecureChannels*/ 2));
  auto deps = TestAccess{*server}.secure_channel_dependencies();

  auto channelA = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  ua::server::SecureChannelTestAccess::on_strand(*channelA,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "TestListener/None");
      g.set_response_sink([](const auto&) {});  // the OPN response goes nowhere (no transport)
    });
  {
    auto opn = std::make_shared<OpenSecureChannelRequest>();
    opn->client_protocol_version() = 0;
    opn->request_type() = SecurityTokenRequestType::Issue;
    opn->security_mode() = MessageSecurityMode::None;
    opn->requested_lifetime() = 60000;
    ua::server::SecureChannelTestAccess::on_strand(
      *channelA, [&](auto& g) { g.inject_decoded_request(1, opn, NodeId{}); });
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (channelA->last_used_time() == std::chrono::steady_clock::time_point::min() &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  ASSERT_NE(channelA->last_used_time(), std::chrono::steady_clock::time_point::min())
    << "the accepted OPN must stamp channel A's last use";
  TestAccess{*server}.add_secure_channel(channelA);

  auto channelB = SecureChannel::create(
    deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  ua::server::SecureChannelTestAccess::on_strand(
    *channelB, [&](auto& g) { g.set_minimal_context_none(ex, "TestListener/None"); });
  TestAccess{*server}.add_secure_channel(channelB);
  ASSERT_EQ(channelA->session_count(), 0u);
  ASSERT_EQ(channelB->session_count(), 0u);

  auto conn = create_connection(ex);
  ASSERT_NO_THROW(TestAccess{*server}.new_connection_complete(
    ListenerHandle{1}, "TestListener", Status::Good, conn.protocol, {}, {}));

  EXPECT_TRUE(TestAccess{*server}.holds_secure_channel(channelA)) << "the older, opened channel stays";
  EXPECT_FALSE(TestAccess{*server}.holds_secure_channel(channelB)) << "the never-opened channel is reclaimed";
  EXPECT_EQ(TestAccess{*server}.secure_channel_count(), 2u);

  channelA->close();
  channelB->close();
  channelA.reset();
  channelB.reset();
}
