// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientTransport cluster of the client integration-test matrix (the 22 `ClientTransport.*` rows).
///
/// These are TCP-stub-level integration tests of the client-side tier-0 connection protocol (section 10.14):
/// the HEL/ACK/MSG/ERR framing, buffer/size negotiation, and the size/chunk limits that defend the
/// client against decode-bomb / DoS traffic. They exercise `ua::ConnectionProtocol` (Client role) as
/// reached through the public `CoreClient::open_channel_async` entry point (normal connect direction) and,
/// for the reverse row, `CoreClient::start_reverse_connect_sync`.
///
/// HARNESS. Most rows use a raw TCP `StubServer` that plays the role of an OPC UA server the client
/// dials into: it binds an ephemeral port, accepts the client's connection, reads the HEL the client
/// emits, and writes crafted ACK/ERR/MSG bytes. Every connection-protocol frame is HAND-ROLLED here
/// (an oracle INDEPENDENT of the product encoder), so a framing bug in the product cannot mask itself.
/// Observation is BOUNDED-poll on the socket (read with a deadline / wait for EOF), never a fixed
/// sleep. The client's own reaction is observed two ways: (a) the exact bytes it puts on the wire (its
/// HEL fields, a CLO on fatal error), and (b) the `CoreClient::SecureChannelResult` its `open_channel`
/// callback receives (the surfaced StatusCode + ErrorDetail).
///
/// A client fatal transport error is observed as: the client closes the socket, AND the open-channel
/// callback completes Bad carrying the terminal status. The CloseSecureChannel Part 6 section 7.1.5 asks
/// for is a secured message of an open SecureChannel, which a StubServer never reaches, so on these rows
/// the client writes nothing before it closes (the CLO on an open channel is covered by the unit tests).
///
/// The final cluster (large-outbound-request rows) cannot be driven by a StubServer - they need a fully
/// open SecureChannel + Session so the client's outbound chunk encoder runs against negotiated limits.
/// Those use a real in-tree `TestServer` configured with deliberately small connection-protocol limits.
///
/// REPORTED DIVERGENCES (matrix oracle vs built behaviour - asserted against the real observable and
/// batched, per the ClientReverseListener/ClientTypeResolver precedent):
///   - The matrix expects `Bad_RequestTooLarge` for an oversized outbound request; the built encoder
///     surfaces `Bad_ResponseTooLarge` for BOTH directions (a single shared code path - see the comment
///     in ua_security_policy.cpp encode_*_message_async). The rows assert the real status.
///   - CL-TCP-011 (OversizedRequestAlreadyChunkedEmitsAbortChunk) needs a wire capture of the outbound
///     Abort ('A') chunk to distinguish it from the pre-send reject (CL-TCP-010). See that row.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ua_core_client.h"
#include "ua_client_config_bundle.h"
#include "ua_client_session.h"
#include "ua_session_attribute_services.h"
#include "ua_application_configuration.h"
#include "ua_defines.h"
#include "ua_error_detail.h"
#include "ua_reverse_connect_config.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include "compliance_helpers.h"
#include "requests.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/write.hpp>

#include "fmt/format.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Wire-frame builders - an independent, hand-rolled oracle for UA Connection
// Protocol messages (Part 6 section 7.1.2). Deliberately NOT the product encoder.
// ---------------------------------------------------------------------------

void append_u32_le(std::vector<std::byte>& out, uint32_t value)
{
  out.push_back(static_cast<std::byte>(value & 0xFF));
  out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
  out.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
  out.push_back(static_cast<std::byte>((value >> 24) & 0xFF));
}

void append_i32_le(std::vector<std::byte>& out, int32_t value)
{
  append_u32_le(out, static_cast<uint32_t>(value));
}

/// UA String: int32 length prefix (-1 = null) followed by the raw bytes.
void append_ua_string(std::vector<std::byte>& out, std::string_view value)
{
  append_i32_le(out, static_cast<int32_t>(value.size()));
  for (char character : value)
  {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
}

/// Prepend an 8-byte header (3 type chars + 'F' + u32 total size) then splice in the actual size.
std::vector<std::byte> frame_with_header(const char (&type)[4], std::vector<std::byte> body)
{
  std::vector<std::byte> out;
  out.push_back(static_cast<std::byte>(type[0]));
  out.push_back(static_cast<std::byte>(type[1]));
  out.push_back(static_cast<std::byte>(type[2]));
  out.push_back(static_cast<std::byte>('F'));
  const uint32_t total = static_cast<uint32_t>(8 + body.size());
  append_u32_le(out, total);
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<std::byte> make_acknowledge(uint32_t protocolVersion, uint32_t receiveBuffer, uint32_t sendBuffer,
  uint32_t maxMessage, uint32_t maxChunk)
{
  std::vector<std::byte> body;
  append_u32_le(body, protocolVersion);
  append_u32_le(body, receiveBuffer);
  append_u32_le(body, sendBuffer);
  append_u32_le(body, maxMessage);
  append_u32_le(body, maxChunk);
  return frame_with_header("ACK", std::move(body));
}

std::vector<std::byte> make_error(uint32_t statusCode, std::string_view reason)
{
  std::vector<std::byte> body;
  append_u32_le(body, statusCode);
  append_ua_string(body, reason);
  return frame_with_header("ERR", std::move(body));
}

std::vector<std::byte> make_reverse_hello(std::string_view serverUri, std::string_view endpointUrl)
{
  std::vector<std::byte> body;
  append_ua_string(body, serverUri);
  append_ua_string(body, endpointUrl);
  return frame_with_header("RHE", std::move(body));
}

/// A bare 8-byte header carrying @p type as the message-type tag and @p declaredSize as the MessageSize.
/// No body bytes follow: the CP rejects both an unknown tag and an oversized MessageSize from the header
/// alone, before it ever reads a body.
std::vector<std::byte> make_header_only(const char (&type)[4], uint32_t declaredSize)
{
  std::vector<std::byte> out;
  out.push_back(static_cast<std::byte>(type[0]));
  out.push_back(static_cast<std::byte>(type[1]));
  out.push_back(static_cast<std::byte>(type[2]));
  out.push_back(static_cast<std::byte>('F'));
  append_u32_le(out, declaredSize);
  return out;
}

// ---------------------------------------------------------------------------
// Decoded HEL (client-emitted) - hand-rolled decoder, independent of product.
// ---------------------------------------------------------------------------

struct DecodedHello
{
  uint32_t protocolVersion{};
  uint32_t receiveBufferSize{};
  uint32_t sendBufferSize{};
  uint32_t maxMessageSize{};
  uint32_t maxChunkCount{};
  std::string endpointUrl;
};

uint32_t read_u32_le(const std::byte* data)
{
  return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
}

/// Decode a full HEL frame (header + body). Pre-condition: bytes.size() >= 28 and type == "HEL".
DecodedHello decode_hello(const std::vector<std::byte>& bytes)
{
  DecodedHello hello;
  const std::byte* body = bytes.data() + 8;  // skip header
  hello.protocolVersion = read_u32_le(body + 0);
  hello.receiveBufferSize = read_u32_le(body + 4);
  hello.sendBufferSize = read_u32_le(body + 8);
  hello.maxMessageSize = read_u32_le(body + 12);
  hello.maxChunkCount = read_u32_le(body + 16);
  const auto urlLength = static_cast<int32_t>(read_u32_le(body + 20));
  if (urlLength > 0 && bytes.size() >= 28 + static_cast<size_t>(urlLength))
  {
    hello.endpointUrl.assign(reinterpret_cast<const char*>(body + 24), static_cast<size_t>(urlLength));
  }
  return hello;
}

// ---------------------------------------------------------------------------
// StubServer - a raw TCP acceptor that plays the OPC UA server the client dials
// into. Bounded reads/EOF-wait via async ops on a private io_context.
// ---------------------------------------------------------------------------

class StubServer
{
public:
  StubServer()
    : mAcceptor(mIoContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0))
  {}

  uint16_t port() const
  {
    return mAcceptor.local_endpoint().port();
  }

  /// Dial OUT to @p port (used to play the reverse-connecting server against a client reverse listener).
  void dial(uint16_t port)
  {
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(), port);
    mSocket.connect(endpoint);
  }

  /// Accept the client's inbound TCP connection (bounded by @p timeout). Returns true if accepted.
  bool accept(std::chrono::milliseconds timeout)
  {
    boost::asio::steady_timer timer(mIoContext);
    timer.expires_after(timeout);
    bool accepted = false;

    timer.async_wait(
      [this](const boost::system::error_code& error)
      {
        if (!error)
        {
          boost::system::error_code ignore;
          mAcceptor.cancel(ignore);
        }
      });

    mAcceptor.async_accept(mSocket,
      [&](const boost::system::error_code& error)
      {
        if (!error)
        {
          accepted = true;
        }
        timer.cancel();
      });

    mIoContext.restart();
    mIoContext.run();
    return accepted;
  }

  void send(const std::vector<std::byte>& bytes)
  {
    boost::asio::write(mSocket, boost::asio::buffer(bytes.data(), bytes.size()));
  }

  struct ReadResult
  {
    std::vector<std::byte> data;
    bool eof{false};  ///< Peer closed (FIN / reset) before/while reading.
    bool timedOut{false};  ///< Deadline elapsed before the requested bytes arrived.
  };

  /// Read exactly @p count bytes, or stop early on EOF/deadline.
  ReadResult read_exact(size_t count, std::chrono::milliseconds timeout)
  {
    ReadResult result;
    result.data.resize(count);

    boost::asio::steady_timer timer(mIoContext);
    timer.expires_after(timeout);

    bool timerFired = false;
    boost::system::error_code readError;
    size_t bytesRead = 0;

    timer.async_wait(
      [&](const boost::system::error_code& error)
      {
        if (!error)
        {
          timerFired = true;
          boost::system::error_code ignore;
          mSocket.cancel(ignore);
        }
      });

    boost::asio::async_read(mSocket,
      boost::asio::buffer(result.data.data(), count),
      [&](const boost::system::error_code& error, size_t transferred)
      {
        readError = error;
        bytesRead = transferred;
        timer.cancel();
      });

    mIoContext.restart();
    mIoContext.run();

    result.data.resize(bytesRead);
    if (readError == boost::asio::error::eof || readError == boost::asio::error::connection_reset)
    {
      result.eof = true;
    }
    if (timerFired && bytesRead < count)
    {
      result.timedOut = true;
    }
    return result;
  }

  struct MessageResult
  {
    std::string type;  ///< 3-char message-type tag ("HEL", "CLO", "ERR", "ACK", "OPN", "MSG", ...).
    std::vector<std::byte> bytes;  ///< Full frame bytes (header + body) actually read.
    bool eof{false};
    bool timedOut{false};
  };

  /// Read one UA Connection Protocol message (8-byte header, then body up to the declared size).
  MessageResult read_message(std::chrono::milliseconds timeout)
  {
    MessageResult message;

    auto header = read_exact(8, timeout);
    message.bytes = header.data;
    if (header.data.size() < 8)
    {
      message.eof = header.eof;
      message.timedOut = header.timedOut;
      return message;
    }

    message.type.assign(reinterpret_cast<const char*>(header.data.data()), 3);
    const uint32_t declaredSize = read_u32_le(header.data.data() + 4);
    if (declaredSize > 8)
    {
      auto body = read_exact(declaredSize - 8, timeout);
      message.bytes.insert(message.bytes.end(), body.data.begin(), body.data.end());
      message.eof = body.eof;
      message.timedOut = body.timedOut;
    }
    return message;
  }

  /// Bounded-poll until the peer closes the socket (EOF); true if the close was observed.
  bool wait_for_close(std::chrono::milliseconds timeout)
  {
    auto result = read_exact(1, timeout);
    return result.eof;
  }

private:
  boost::asio::io_context mIoContext;
  boost::asio::ip::tcp::acceptor mAcceptor;
  boost::asio::ip::tcp::socket mSocket{mIoContext};
};

// ---------------------------------------------------------------------------
// Latched open-channel outcome - captured from the client's callback thread and
// read by the test thread once the callback (or a timeout) has settled.
//
// The callback delivers a move-only `SecureChannelResult`; the latch keeps only the copyable facts a
// test needs (the terminal StatusCode and the rendered error-chain text), so it can be read safely from
// the test thread after the fact.
// ---------------------------------------------------------------------------
struct OpenResult
{
  StatusCode status;  ///< Terminal status the open-channel callback reported.
  std::string errorText;  ///< Rendered ErrorDetail chain (empty if the result carried no detail).

  bool is_bad() const
  {
    return status.is_bad();
  }

  bool is_good() const
  {
    return status.is_good();
  }
};

class OpenOutcome
{
public:
  void set(const CoreClient::SecureChannelResult& result)
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      OpenResult latched;
      latched.status = result.status_code();
      if (auto detail = result.shared_detail())
      {
        latched.errorText = ua::to_string(*detail);
      }
      mResult.emplace(std::move(latched));
    }
    mCondition.notify_all();
  }

  /// Wait up to @p timeout for the callback to fire. Returns the latched facts if it fired, else nullopt.
  std::optional<OpenResult> wait(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    if (mCondition.wait_for(lock, timeout, [this] { return mResult.has_value(); }))
    {
      return mResult;
    }
    return std::nullopt;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::optional<OpenResult> mResult;
};

constexpr std::string_view reservedByteAsciiF = "F";

/// Find a free TCP port by binding to port 0 and immediately closing (for the reverse-listener bind).
uint16_t find_free_port()
{
  boost::asio::io_context ioContext;
  boost::asio::ip::tcp::acceptor acceptor(
    ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
  auto port = acceptor.local_endpoint().port();
  acceptor.close();
  return port;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture: a Client (default config) dialing into a raw TCP StubServer.
// ---------------------------------------------------------------------------
class ClientTransport : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
        .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mRealSession)
    {
      (void)mRealSession->try_close_sync();
      mRealSession.reset();
    }
    if (mRealChannel)
    {
      (void)mRealChannel->try_close_sync();
      mRealChannel.reset();
    }
    if (mReverseHandle != client::ReverseConnectHandle{})
    {
      (void)mClient->core().try_stop_reverse_connect_sync(mReverseHandle);
      mReverseHandle = {};
    }
    mClient.reset();
    mRealServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  /// Start a real in-tree server with the given connection-protocol limits (buffer / MaxMessageSize /
  /// MaxChunkCount) on an anonymous None endpoint, then open a channel + activated session over it. The
  /// small-limit variants drive the client's outbound sizing/chunking against the negotiated (small)
  /// limits. Returns a reference to the activated session.
  Session& open_real_session(ua::connection_protocol::Limits limits)
  {
    mRealServer.emplace();
    mRealServer->create([limits](ua::ApplicationConfig& appCfg)
      { appCfg.stack_limits().connectionProtocolLimits = limits; },
      [](ua::server::ServerConfig&) {});

    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    auto listener = mRealServer->listen_ephemeral();
    mRealServer->add_endpoint(listener, endpoint);
    mRealServer->start();

    auto urls = mRealServer->server().advertised_urls(listener);
    EXPECT_FALSE(urls.empty());
    const std::string endpointUrl = urls.front().str();

    mRealChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = endpointUrl}));
    mRealSession.emplace(mRealChannel->create_session_sync({.sessionName = "ClientTransport"}));
    mRealSession->activate_sync();
    return *mRealSession;
  }

  /// Kick off a normal-connect open_channel to the stub's port. The outcome latch outlives the client
  /// so the callback (which may fire during teardown) is always safe.
  std::shared_ptr<OpenOutcome> begin_open(StubServer& stub, SecurityPolicyId policy = SecurityPolicyId::None,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{4000})
  {
    auto outcome = std::make_shared<OpenOutcome>();
    CoreClient::OpenChannelConfig config;
    config.endpointUrl = fmt::format("opc.tcp://127.0.0.1:{}", stub.port());
    config.securityPolicyId = policy;
    config.securityMode =
      policy == SecurityPolicyId::None ? MessageSecurityMode::None : MessageSecurityMode::SignAndEncrypt;
    config.timeout = timeout;
    mClient->core().open_channel_async(
      std::move(config), [outcome](CoreClient::SecureChannelResult result) { outcome->set(result); });
    return outcome;
  }

  /// Read the client's HEL after accepting its connection. Returns the decoded HEL (asserts type == HEL).
  DecodedHello accept_and_read_hello(StubServer& stub)
  {
    EXPECT_TRUE(stub.accept(5s)) << "client did not connect to the stub server";
    auto message = stub.read_message(5s);
    EXPECT_EQ(message.type, "HEL") << "first client message must be HEL; got '" << message.type << "'";
    if (message.type != "HEL" || message.bytes.size() < 28)
    {
      return DecodedHello{};
    }
    return decode_hello(message.bytes);
  }

  /// Drive an in-flight open (HEL sent, awaiting ACK - or post-handshake, awaiting the OPN response) to a
  /// deterministic terminal state so no armed handshake timer / pending read survives into teardown:
  /// inject an ERR that fails the flow, then wait for the open-channel callback to settle. Both the
  /// handshake ERR path (on_acknowledge_received) and the post-handshake ERR path (check_header) close.
  void terminate_open(StubServer& stub, OpenOutcome& outcome)
  {
    stub.send(make_error(StatusCode{Status::BadServerHalted}.as_uint32(), "stub server terminating"));
    (void)outcome.wait(3s);
  }

  /// Accept the client, read its HEL, then send a valid ACK (protocolVersion 0) that echoes the client's
  /// proposed buffer/message/chunk limits so ACK validation passes and the handshake completes. Returns
  /// the decoded HEL; after this the client proceeds to send its OPN.
  DecodedHello accept_hello_and_ack(StubServer& stub)
  {
    auto hello = accept_and_read_hello(stub);
    stub.send(make_acknowledge(
      0, hello.receiveBufferSize, hello.sendBufferSize, hello.maxMessageSize, hello.maxChunkCount));
    return hello;
  }

  /// Replace the default client with one whose configured connection-protocol max buffer size is
  /// @p maxBufferSize, so the HEL it emits carries that proposal (the client sends mMaxBufferSize as both
  /// its Receive- and SendBufferSize; there is no per-policy clamp in send_hello).
  void reset_client_with_buffer(uint32_t maxBufferSize)
  {
    mClient.reset();
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.stack_limits().connectionProtocolLimits.maxBufferSize = maxBufferSize;
    ua::client::CreateConfig cfg{
      .identity = ua::ApplicationIdentity::load_default(), .application = std::move(appCfg), .client = {}};
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  boost::asio::thread_pool mClientThreadPool;
  std::optional<Client> mClient;
  std::optional<TestServer> mRealServer;
  std::optional<SecureChannel> mRealChannel;
  std::optional<Session> mRealSession;
  client::ReverseConnectHandle mReverseHandle{};
};

// ---------------------------------------------------------------------------
// HelloIsFirstMessageOnNewConnection - CL-TCP-001; Minimum Client Functionality
// @verifies CL-TCP-001
// The very first bytes a fresh client puts on the wire are the 'HEL' message-type tag; a mis-ordered
// handshake that emitted OPN first would show 'OPN' at byte[0..2] and fail.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-001, scope=function)
TEST_F(ClientTransport, HelloIsFirstMessageOnNewConnection)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  ASSERT_TRUE(stub.accept(5s));
  auto message = stub.read_message(5s);

  EXPECT_EQ(message.type, "HEL") << "first message on a new connection must be HEL";
  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// HelloReservedByteIsAsciiF - CL-TCP-008
// @verifies CL-TCP-008
// The reserved 4th header byte of the HEL is ASCII 'F' (0x46); any other value falsifies.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-008, scope=function)
TEST_F(ClientTransport, HelloReservedByteIsAsciiF)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  ASSERT_TRUE(stub.accept(5s));
  auto message = stub.read_message(5s);
  ASSERT_EQ(message.type, "HEL");
  ASSERT_GE(message.bytes.size(), 4u);

  const auto reserved = static_cast<unsigned char>(message.bytes[3]);
  EXPECT_EQ(std::string(1, static_cast<char>(reserved)), reservedByteAsciiF)
    << "HEL reserved byte must be ASCII 'F' (0x46); got 0x" << fmt::format("{:02x}", reserved);
  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// HelloReceiveBufferMeetsNonEccMinimum - CL-TCP-002
// @verifies CL-TCP-002
// A non-ECC (Basic256Sha256/None) HEL proposes a ReceiveBufferSize >= 8192; a sub-floor 4096 would fail.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-002, scope=function)
TEST_F(ClientTransport, HelloReceiveBufferMeetsNonEccMinimum)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_and_read_hello(stub);
  EXPECT_GE(hello.receiveBufferSize, 8192u) << "non-ECC HEL ReceiveBufferSize must meet the 8192-byte floor";
  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// HelloSendBufferMeetsNonEccMinimum - CL-TCP-003
// @verifies CL-TCP-003
// A non-ECC HEL proposes a SendBufferSize >= 8192; a sub-floor proposal would fail.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-003, scope=function)
TEST_F(ClientTransport, HelloSendBufferMeetsNonEccMinimum)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_and_read_hello(stub);
  EXPECT_GE(hello.sendBufferSize, 8192u) << "non-ECC HEL SendBufferSize must meet the 8192-byte floor";
  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// NoNonHelloMessageEmittedBeforeHello - CL-TCP-001
// @verifies CL-TCP-001
// After the socket opens the client emits EXACTLY ONE frame (HEL) and then blocks awaiting ACK - it does
// not optimistically pipeline an OPN before the ACK arrives. Asserted by reading the HEL, then confirming
// no second frame arrives while the stub withholds the ACK. [neg: pipelined-OPN-before-ACK]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-001, scope=function)
TEST_F(ClientTransport, NoNonHelloMessageEmittedBeforeHello)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_and_read_hello(stub);
  ASSERT_GT(hello.receiveBufferSize, 0u) << "the single emitted frame must be a well-formed HEL";

  // The stub deliberately sends NO ACK. A correct client blocks; a broken one would pipeline an OPN.
  auto next = stub.read_message(600ms);
  EXPECT_TRUE(next.timedOut) << "client must not send a second frame before the ACK; got '" << next.type
                             << "'";
  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// HelloEndpointUrlBoundedTo4096 - CL-TCP-004
// @verifies CL-TCP-004
// Connecting with an endpoint URL longer than 4096 bytes must not put a >4096-byte EndpointUrl on the
// wire: the client either rejects locally (open completes Bad) or emits a HEL whose EndpointUrl is
// <= 4096 bytes. [neg: EndpointUrl > 4096 bytes]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-004, scope=function)
TEST_F(ClientTransport, HelloEndpointUrlBoundedTo4096)
{
  StubServer stub;

  // A syntactically valid opc.tcp URL whose path pushes the whole URL past 4096 bytes.
  const std::string prefix = fmt::format("opc.tcp://127.0.0.1:{}/", stub.port());
  std::string overlongUrl = prefix + std::string(5000, 'a');
  ASSERT_GT(overlongUrl.size(), 4096u);

  auto outcome = std::make_shared<OpenOutcome>();
  CoreClient::OpenChannelConfig config;
  config.endpointUrl = overlongUrl;
  config.securityPolicyId = SecurityPolicyId::None;
  config.timeout = std::chrono::milliseconds{3000};
  mClient->core().open_channel_async(
    std::move(config), [outcome](CoreClient::SecureChannelResult result) { outcome->set(result); });

  // Either the client never dials / rejects the URL (no HEL ever accepted), or it dials and the HEL it
  // emits carries a bounded EndpointUrl. Both satisfy the requirement; a >4096 EndpointUrl falsifies.
  if (stub.accept(3s))
  {
    auto message = stub.read_message(3s);
    if (message.type == "HEL" && message.bytes.size() >= 28)
    {
      auto hello = decode_hello(message.bytes);
      EXPECT_LE(hello.endpointUrl.size(), 4096u)
        << "HEL EndpointUrl must be bounded to 4096 bytes on the wire";
    }
    // A non-HEL / short frame means the client refused to emit an over-long HEL - also acceptable.
    terminate_open(stub, *outcome);
  }
  else
  {
    // Client rejected the over-long URL before dialing: the open must complete Bad.
    auto result = outcome->wait(3s);
    ASSERT_TRUE(result.has_value()) << "over-long URL: client neither dialed nor reported an outcome";
    EXPECT_TRUE(result->is_bad()) << "an over-long endpoint URL rejected locally must complete Bad";
  }
}

// ---------------------------------------------------------------------------
// ClientUsesNegotiatedProtocolVersionFromAck - CL-TCP-005
// @verifies CL-TCP-005
// After a valid ACK carrying ProtocolVersion 0 the client proceeds to the SecureChannel open (it emits
// its OPN). Only version 0 exists in Part 6, so this pins the positive half of CL-TCP-005 (the
// reject-higher-version sibling carries the falsifiable weight). [neg: client stalls after a valid ACK]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-005, scope=function)
// @relation(AC-CL-TCP-005-01, scope=function)
TEST_F(ClientTransport, ClientUsesNegotiatedProtocolVersionFromAck)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  accept_hello_and_ack(stub);

  auto opn = stub.read_message(5s);
  EXPECT_EQ(opn.type, "OPN")
    << "after accepting a valid (version 0) ACK the client must proceed to OPN; got '" << opn.type << "'";

  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// UnsupportedAckProtocolVersionReportedAndClosed - CL-TCP-005
// @verifies CL-TCP-005
// An ACK advertising a ProtocolVersion the client does not support (1) is rejected: the open completes
// Bad (BadProtocolVersionUnsupported), the client closes, and no OPN follows.
// [neg: unsupported protocol version in ACK]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-005, scope=function)
// @relation(AC-CL-TCP-005-01, scope=function)
TEST_F(ClientTransport, UnsupportedAckProtocolVersionReportedAndClosed)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_and_read_hello(stub);
  stub.send(make_acknowledge(1 /* unsupported */,
    hello.receiveBufferSize,
    hello.sendBufferSize,
    hello.maxMessageSize,
    hello.maxChunkCount));

  auto response = stub.read_message(5s);
  EXPECT_TRUE(response.type == "CLO" || response.eof)
    << "client must close on an unsupported ACK protocol version; got '" << response.type << "'";
  EXPECT_NE(response.type, "OPN") << "client must not proceed to OPN on an unsupported ACK version";

  auto result = outcome->wait(3s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status, StatusCode{Status::BadProtocolVersionUnsupported})
    << "open must complete BadProtocolVersionUnsupported";
}

// ---------------------------------------------------------------------------
// DuplicateAcknowledgeClosesConnection - CL-TCP-007
// @verifies CL-TCP-007
// After a successful HEL/ACK exchange (client has emitted its OPN), a SECOND ACK frame injected where the
// OPN response is expected is an invalid message type post-handshake: the client reports a protocol error
// and closes. [neg: duplicate Acknowledge]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-007, scope=function)
TEST_F(ClientTransport, DuplicateAcknowledgeClosesConnection)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_hello_and_ack(stub);

  auto opn = stub.read_message(5s);
  ASSERT_EQ(opn.type, "OPN") << "handshake must reach OPN before the duplicate ACK";

  // Inject a second ACK where the OPN response belongs.
  stub.send(make_acknowledge(
    0, hello.receiveBufferSize, hello.sendBufferSize, hello.maxMessageSize, hello.maxChunkCount));

  auto response = stub.read_message(5s);
  EXPECT_TRUE(response.type == "CLO" || response.eof)
    << "a duplicate ACK must be rejected and the connection closed; got '" << response.type << "'";
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error. That frame is not a CloseSecureChannel (Part 6 6.7.2.2-6.7.2.4 need the
  // SecureChannelId, TokenId and sequence header, Part 4 5.5.3.1 the current token's signature), and here
  // the OpenSecureChannel is still unanswered, so no conformant one exists. Still asserted: the client closes
  // the connection; now also that it writes nothing before doing so. The CLO a fatal error on an OPEN channel
  // owes is verified by FatalErrorOnOpenChannelSendsCloSignedWithCurrentToken (AC-CL-TCP-014-01).
  EXPECT_TRUE(response.type.empty() && response.eof)
    << "client must close on a duplicate ACK without writing; got '" << response.type << "'";

  auto result = outcome->wait(3s);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad()) << "open must complete Bad after a duplicate ACK";
}

// ---------------------------------------------------------------------------
// ErrorReasonWithinLimitParsedAndSurfaced - CL-TCP-013
// @verifies CL-TCP-013
// An ERR frame whose Reason is within the 4096-byte limit, carrying a specific StatusCode, surfaces that
// exact StatusCode and Reason text to the application. [neg: reason dropped/truncated when within limit]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-013, scope=function)
TEST_F(ClientTransport, ErrorReasonWithinLimitParsedAndSurfaced)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  accept_and_read_hello(stub);

  const std::string reason = "stub-refused-because-server-is-too-busy-right-now";
  stub.send(make_error(StatusCode{Status::BadTcpServerTooBusy}.as_uint32(), reason));

  auto result = outcome->wait(4s);
  ASSERT_TRUE(result.has_value()) << "an ERR during handshake must complete the open";
  EXPECT_EQ(result->status, StatusCode{Status::BadTcpServerTooBusy})
    << "the ERR StatusCode must be surfaced verbatim";
  EXPECT_THAT(result->errorText, ::testing::HasSubstr(reason))
    << "the within-limit ERR Reason must be surfaced; got: " << result->errorText;
}

// ---------------------------------------------------------------------------
// ErrorReasonExceedingLimitIgnoredNoCrash - CL-TCP-013
// @verifies CL-TCP-013
// An ERR frame whose Reason exceeds 4096 bytes: the client discards the over-long reason (does not echo
// it) and completes cleanly without crash or unbounded read; the StatusCode is still surfaced.
// [neg: reason string > 4096 bytes read into memory / echoed]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-013, scope=function)
TEST_F(ClientTransport, ErrorReasonExceedingLimitIgnoredNoCrash)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  accept_and_read_hello(stub);

  // A distinctive sentinel repeated past the 4096-byte cap; a client that echoed the reason would leak it.
  const std::string overlongReason(5000, 'Z');
  stub.send(make_error(StatusCode{Status::BadTcpServerTooBusy}.as_uint32(), overlongReason));

  auto result = outcome->wait(4s);
  ASSERT_TRUE(result.has_value()) << "an over-long ERR must still complete the open (no crash/hang)";
  EXPECT_TRUE(result->is_bad()) << "a status must still be surfaced for an over-long ERR";
  EXPECT_THAT(result->errorText, ::testing::Not(::testing::HasSubstr(std::string(4097, 'Z'))))
    << "the over-long ERR Reason must be dropped, not echoed";
}

// ---------------------------------------------------------------------------
// FatalErrorReportedToApplicationAndCloSent - CL-TCP-014
// @verifies CL-TCP-014
// On a fatal transport error the client both notifies the application (the open-channel callback fires
// Bad) AND writes a CLO frame before closing the socket (Part 6 section 7.1.5 - the client sends CLO, not
// ERR). Driven here via a fatal ERR during the handshake (a StubServer cannot open a real SecureChannel, so
// the matrix's "post-open SC decode fault" is realised as the equivalent fatal-transport path; the observable
// - app-notified + CLO-before-close - is identical). [neg: socket torn down without CLO / error swallowed]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-014, scope=function)
TEST_F(ClientTransport, FatalErrorReportedToApplicationAndCloSent)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  accept_and_read_hello(stub);
  stub.send(make_error(StatusCode{Status::BadCommunicationError}.as_uint32(), "fatal"));

  auto response = stub.read_message(5s);
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error. That frame is not a CloseSecureChannel (Part 6 6.7.2.2-6.7.2.4 need the
  // SecureChannelId, TokenId and sequence header, Part 4 5.5.3.1 the current token's signature), and here
  // no SecureChannel is open, so no conformant one exists. Still asserted: the client closes the
  // connection; now also that it writes nothing before doing so. The CLO a fatal error on an OPEN channel
  // owes is verified by FatalErrorOnOpenChannelSendsCloSignedWithCurrentToken (AC-CL-TCP-014-01).
  EXPECT_TRUE(response.type.empty() && response.eof)
    << "client must close without writing on a fatal error during the handshake; got '" << response.type
    << "'";
  EXPECT_TRUE(response.eof || stub.wait_for_close(5s)) << "socket must reach EOF";

  auto result = outcome->wait(4s);
  ASSERT_TRUE(result.has_value()) << "the application must be notified of the fatal error";
  EXPECT_TRUE(result->is_bad()) << "the fatal error must be reported to the application as Bad";
}

// ---------------------------------------------------------------------------
// InboundMessageSizeExceedingReceiveBufferRejected - CL-TCP-009
// @verifies CL-TCP-009
// A post-handshake MSG whose declared MessageSize exceeds the negotiated ReceiveBufferSize is rejected by
// the CP layer BEFORE its body is read/decoded: the client errors and closes rather than reading the
// oversized body. Asserted from the header alone (the stub sends no body). [neg: MessageSize > ReceiveBuffer]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-009, scope=function)
TEST_F(ClientTransport, InboundMessageSizeExceedingReceiveBufferRejected)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  auto hello = accept_hello_and_ack(stub);

  auto opn = stub.read_message(5s);
  ASSERT_EQ(opn.type, "OPN") << "handshake must complete before the oversized MSG";

  // The negotiated ReceiveBufferSize equals the ACK SendBufferSize we echoed (the client's proposal).
  // Declare a MessageSize one byte past it; the client must reject from the header without reading a body.
  const uint32_t oversized = hello.sendBufferSize + 1;
  stub.send(make_header_only("MSG", oversized));

  auto response = stub.read_message(5s);
  EXPECT_TRUE(response.type == "CLO" || response.eof)
    << "client must reject/close on a MSG larger than the negotiated ReceiveBufferSize; got '"
    << response.type << "'";

  auto result = outcome->wait(3s);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad()) << "the oversized inbound MSG must fail the open";
}

// ---------------------------------------------------------------------------
// UnknownMessageTypeTagRejectedAndClosed - CL-TCP-009
// @verifies CL-TCP-009
// A post-handshake frame whose 3-byte type tag is not any valid UA tag ('XYZ') is rejected: the client
// reports an error and closes; the malformed bytes are NOT handed to the SC decoder.
// [neg: unknown MessageType tag]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-009, scope=function)
TEST_F(ClientTransport, UnknownMessageTypeTagRejectedAndClosed)
{
  StubServer stub;
  auto outcome = begin_open(stub);

  accept_hello_and_ack(stub);

  auto opn = stub.read_message(5s);
  ASSERT_EQ(opn.type, "OPN") << "handshake must complete before the bad-tag frame";

  stub.send(make_header_only("XYZ", 8));

  auto response = stub.read_message(5s);
  EXPECT_TRUE(response.type == "CLO" || response.eof)
    << "client must reject/close on an unknown message-type tag; got '" << response.type << "'";

  auto result = outcome->wait(3s);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad()) << "an unknown message-type tag must fail the open";
}

// ---------------------------------------------------------------------------
// HelloReceiveBufferMeetsEccMinimum - CL-TCP-002
// @verifies CL-TCP-002
// An ECC-policy channel's HEL meets the 1024-byte ECC floor (the HEL precedes any crypto, so it is
// emitted even without an ECC application certificate). [neg: ECC channel below the 1024 floor]
//
// DIVERGENCE (batched): the matrix frames the ECC floor as 1024 (below the 8192 non-ECC floor). The SDK
// conservatively floors EVERY client proposal at 8192 (always valid for ECC and non-ECC servers alike;
// see send_hello), so the observed value is >= 8192, which trivially satisfies the >= 1024 the row
// requires. The client never proposes a sub-8192 buffer even for ECC.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-002, scope=function)
TEST_F(ClientTransport, HelloReceiveBufferMeetsEccMinimum)
{
  StubServer stub;
  auto outcome = begin_open(stub, SecurityPolicyId::EccNistP256AesGcm);

  ASSERT_TRUE(stub.accept(5s)) << "client must dial the stub for an ECC channel (HEL precedes any crypto)";
  auto message = stub.read_message(5s);
  ASSERT_EQ(message.type, "HEL") << "an ECC channel still emits a HEL first; got '" << message.type << "'";
  ASSERT_GE(message.bytes.size(), 28u);

  auto hello = decode_hello(message.bytes);
  EXPECT_GE(hello.receiveBufferSize, 1024u) << "ECC HEL ReceiveBufferSize must meet the 1024-byte ECC floor";

  terminate_open(stub, *outcome);
}

// ---------------------------------------------------------------------------
// ReceiveBufferBelowMinimumClampedOrRejected - CL-TCP-002
// @verifies CL-TCP-002
// Configuring a sub-minimum ReceiveBufferSize (512, below even the 1024 ECC floor) for a non-ECC channel
// must NOT put 512 on the wire: the client either clamps up to the non-ECC 8192 floor or fails the open
// with a configuration error. [neg: sub-minimum 512 proposed on the wire]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-002, scope=function)
TEST_F(ClientTransport, ReceiveBufferBelowMinimumClampedOrRejected)
{
  reset_client_with_buffer(512);

  StubServer stub;
  auto outcome = begin_open(stub, SecurityPolicyId::None);

  if (stub.accept(3s))
  {
    auto message = stub.read_message(3s);
    if (message.type == "HEL" && message.bytes.size() >= 28)
    {
      auto hello = decode_hello(message.bytes);
      EXPECT_GE(hello.receiveBufferSize, 8192u)
        << "a sub-minimum configured buffer must be clamped up to the 8192-byte non-ECC floor, "
           "never proposed as 512 on the wire";
    }
    else
    {
      // Client refused to emit a HEL for the sub-minimum buffer - acceptable (reject path).
      SUCCEED() << "client did not emit a HEL for a sub-minimum buffer";
    }
    terminate_open(stub, *outcome);
  }
  else
  {
    auto result = outcome->wait(3s);
    ASSERT_TRUE(result.has_value()) << "sub-minimum buffer: client neither dialed nor reported an outcome";
    EXPECT_TRUE(result->is_bad()) << "a sub-minimum buffer rejected locally must complete Bad";
  }
}

// ---------------------------------------------------------------------------
// ValidMsgChunkForwardedToSecureChannel - CL-TCP-009
// @verifies CL-TCP-009
// A well-formed MSG response is forwarded by the CP layer to the SecureChannel layer and decoded. Driven
// end-to-end against a real server: a normal Read returns Good, which is only possible if the server's
// MSG (ReadResponse) chunk was accepted by the CP layer (MessageType/MessageSize validated) and handed to
// the SC decoder. [neg: a valid MSG chunk dropped/rejected by the CP layer]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-009, scope=function)
TEST_F(ClientTransport, ValidMsgChunkForwardedToSecureChannel)
{
  auto& session = open_real_session(ua::connection_protocol::Limits{});

  auto result = session.attributes().try_read_sync(
    ReadRequestBuilder().read(NodeId{ObjectId::Server}).attribute(AttributeId::BrowseName));

  ASSERT_TRUE(result.is_good()) << "a valid MSG (ReadResponse) chunk must be forwarded to the SC and decoded";
  ASSERT_EQ(result.value().results().size(), 1u);
  const auto status = result.value().results()[0].status();
  EXPECT_TRUE(!status.has_value() || status->is_good())
    << "the forwarded-and-decoded Read must carry the server's Good value";
}

// ---------------------------------------------------------------------------
// NegotiatedBufferSizesReportedToSecureChannelLayer - CL-TCP-006
// @verifies CL-TCP-006
// The buffer size negotiated in the HEL/ACK exchange is the one the SecureChannel layer uses to chunk
// outbound messages. Driven against a real server whose ReceiveBufferSize is negotiated down to 8192: a
// Write whose encoded body far exceeds 8192 forces the client to split it into multiple <=8192 chunks. If
// the SC layer had not been given the negotiated 8192 (and used the client's proposed 65536 instead), the
// server would frame-reject the oversized chunk and the service call would fail at the transport layer.
// The service round-trip (a WriteResponse comes back) proves the client chunked at the negotiated size.
// [neg: client ignores the ACK-negotiated buffer and emits one oversized chunk]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-006, scope=function)
TEST_F(ClientTransport, NegotiatedBufferSizesReportedToSecureChannelLayer)
{
  // Server negotiates an 8192-byte buffer (below the client's proposed 65536); message/chunk limits stay
  // generous so only the buffer forces chunking.
  auto& session = open_real_session(ua::connection_protocol::Limits{
    .maxBufferSize = 8192, .maxMessageSize = 16 * 1024 * 1024, .maxChunkCount = 5000});

  // A ~32 KB body: at an 8192-byte send buffer this needs several chunks; a single 32 KB chunk (or a
  // 65536 proposal) would exceed the negotiated buffer and be frame-rejected by the server.
  ua::Variant largeValue{ua::ByteString(size_t{32768}, uint8_t{0x41})};
  auto result = session.attributes().try_write_sync(
    WriteRequestBuilder().write(NodeId{ObjectId::Server}, std::move(largeValue)).build());

  ASSERT_TRUE(result.is_good())
    << "a multi-chunk Write over an 8192-buffer channel must round-trip (proving chunking at the "
       "negotiated buffer), not fail at the transport layer";
  EXPECT_EQ(result.value().results().size(), 1u)
    << "the server processed the reassembled multi-chunk request and returned a per-item result";
}

// ---------------------------------------------------------------------------
// OutboundRequestExceedingMaxMessageSizeReportsRequestTooLarge - CL-TCP-010
// @verifies CL-TCP-010
// A single outbound request whose encoded size exceeds the peer's negotiated MaxMessageSize is rejected
// locally before any bytes for it reach the wire.
//
// The status is direction-correct: OPC 10000-4 section 5.3 gives the client stack Bad_RequestTooLarge before
// it sends an oversized request. The encode path is shared with the server, which returns
// Bad_ResponseTooLarge for an oversized response; the SecureChannelContext's role selects between them.
// This row previously recorded a DIVERGENCE - both directions reported Bad_ResponseTooLarge, so a caller
// whose request was too large was told "response too large". [neg: request > MaxMessageSize]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-010, scope=function)
TEST_F(ClientTransport, OutboundRequestExceedingMaxMessageSizeReportsRequestTooLarge)
{
  // MaxMessageSize small (20000) but the buffer generous so the size limit - not the chunk count - is the
  // binding constraint. Session setup (< 8 KB for None) fits comfortably under 20000.
  auto& session = open_real_session(
    ua::connection_protocol::Limits{.maxBufferSize = 65536, .maxMessageSize = 20000, .maxChunkCount = 5000});

  // A ~64 KB body far exceeds the negotiated 20000-byte MaxMessageSize.
  ua::Variant hugeValue{ua::ByteString(size_t{65536}, uint8_t{0x42})};
  auto result = session.attributes().try_write_sync(
    WriteRequestBuilder().write(NodeId{ObjectId::Server}, std::move(hugeValue)).build());

  ASSERT_TRUE(result.is_bad())
    << "an outbound request exceeding the negotiated MaxMessageSize must be rejected locally";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadRequestTooLarge})
    << "an oversized OUTBOUND REQUEST must report Bad_RequestTooLarge (OPC 10000-4 section 5.3); "
       "Bad_ResponseTooLarge means the shared encode path stopped consulting the channel role";
}

// ---------------------------------------------------------------------------
// RequestExceedingMaxChunkCountAborted - CL-TCP-012
// @verifies CL-TCP-012
// A request that would require more chunks than the negotiated MaxChunkCount is aborted locally before it
// is sent (the encoder computes the required chunk count up front and rejects).
//
// As with CL-TCP-010 the status is Bad_RequestTooLarge for this (client) direction, and the rejection is
// UP-FRONT (before chunk 1), so no partial chunks reach the wire.
// [neg: required chunk count > negotiated MaxChunkCount]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-012, scope=function)
TEST_F(ClientTransport, RequestExceedingMaxChunkCountAborted)
{
  // MaxChunkCount=2 with an 8192 buffer: session setup fits in one chunk (<= 2), but a large Write needs
  // many chunks. MaxMessageSize stays generous so the chunk-count limit - not the size limit - binds.
  auto& session = open_real_session(ua::connection_protocol::Limits{
    .maxBufferSize = 8192, .maxMessageSize = 16 * 1024 * 1024, .maxChunkCount = 2});

  // A ~40 KB body needs ~5 chunks at 8192, exceeding the negotiated MaxChunkCount of 2.
  ua::Variant largeValue{ua::ByteString(size_t{40960}, uint8_t{0x43})};
  auto result = session.attributes().try_write_sync(
    WriteRequestBuilder().write(NodeId{ObjectId::Server}, std::move(largeValue)).build());

  ASSERT_TRUE(result.is_bad())
    << "a request requiring more chunks than the negotiated MaxChunkCount must be aborted locally";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadRequestTooLarge})
    << "an outbound request needing too many chunks must report Bad_RequestTooLarge for the client "
       "direction; Bad_ResponseTooLarge means the channel role is no longer consulted";
}

// ---------------------------------------------------------------------------
// OversizedRequestAlreadyChunkedEmitsAbortChunk - CL-TCP-011  [BLOCKED - reported]
// @verifies CL-TCP-011
// The matrix premise ("a request begins multi-chunk encoding then CROSSES the size limit mid-stream, so
// the server observes an Abort ('A') chunk for that RequestId") does not match the built architecture: the
// SDK validates both MaxMessageSize and MaxChunkCount UP FRONT in encode_symmetric_message_async (before
// chunk 1 is emitted), so a size/chunk overflow is rejected pre-send with Bad_ResponseTooLarge and NO
// chunk - let alone an Abort chunk - ever reaches the wire (this is exactly what CL-TCP-010/012 assert).
//
// The outbound Abort ('A') chunk path IS built (EncodeSymmetricAbortFlow), but it is triggered only by a
// deferred SIGN/ENCRYPT/SEND failure that occurs AFTER chunksSent > 0
// (handle_encode_symmetric_deferred_error) - a mid-stream crypto/transport fault, not a size-limit crossing.
// Driving that observable requires a fault-injecting SecurityPolicy or transport decorator that fails a
// specific chunk mid-stream AND a wire-capturing server to observe the 'A' chunk; neither the StubServer nor
// the real-server harness here can inject a mid-stream crypto failure. This row is BLOCKED on that
// fault-injection interface and REPORTED; its size-limit sibling behaviour is covered up-front by CL-TCP-010
// (RequestTooLarge) and CL-TCP-012.
//
// Skipping would silently hide the gap; per policy this is reported in the slice write-up instead. To
// keep the suite honest without inventing behaviour, the one thing this test CAN pin is the real,
// observable half of the requirement: an oversized already-would-be-multi-chunk request fails locally
// (Bad_ResponseTooLarge) and NO bytes reach the server - i.e. the up-front rejection, not a mid-stream
// abort. The mid-stream Abort-chunk emission remains unverified and is called out in the report.
// ---------------------------------------------------------------------------
// @relation(CL-TCP-011, scope=function)
TEST_F(ClientTransport, OversizedRequestAlreadyChunkedEmitsAbortChunk)
{
  // Force the MULTI-CHUNK regime (small buffer so the message would be many chunks) AND cross the size
  // limit, to exercise the code path closest to the matrix premise. The built SDK still rejects up front.
  auto& session = open_real_session(
    ua::connection_protocol::Limits{.maxBufferSize = 8192, .maxMessageSize = 24000, .maxChunkCount = 5000});

  ua::Variant hugeValue{ua::ByteString(size_t{65536}, uint8_t{0x44})};
  auto result = session.attributes().try_write_sync(
    WriteRequestBuilder().write(NodeId{ObjectId::Server}, std::move(hugeValue)).build());

  // Real observable: up-front local rejection (no mid-stream Abort chunk is emitted - see the block
  // comment; the true Abort-chunk path needs a mid-stream fault-injection interface that is unbuilt).
  //
  // The status is Bad_RequestTooLarge, not Bad_ResponseTooLarge. Part 4 Table 15 (maxRequestMessageSize)
  // says "The Client Communication Stack should return a Bad_RequestTooLarge error to the application if
  // a request message exceeds this limit", and OPC 10000-6 makes it a shall: "The Client shall abort the
  // Message with a Bad_RequestTooLarge StatusCode". Bad_ResponseTooLarge is the mirror case - a RESPONSE
  // exceeding limits set by the Client - and is not what an outbound Write reports.
  ASSERT_TRUE(result.is_bad()) << "an oversized multi-chunk request must fail locally";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadRequestTooLarge})
    << "the SDK rejects the oversized request up front, not via a mid-stream Abort: "
    << to_string(result.status_code());
}

// @relation(AC-SVR-TCP-017-ECHO, scope=function)

// ---------------------------------------------------------------------------
// ReverseHelloEndpointUrlEchoedInHello - CL-TCP-016
// @verifies CL-TCP-016
// On the reverse-connect path the client's HEL echoes the EndpointUrl carried by the server's ReverseHello
// verbatim (the reverse-connect Hello builder takes the EndpointUrl from the RHE, not from any local
// connect URL). In reverse mode there is no local connect URL, so the echoed value is the only source -
// a HEL carrying any other EndpointUrl falsifies. [neg: HEL rewrites/omits the RHE EndpointUrl]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-016, scope=function)
TEST_F(ClientTransport, ReverseHelloEndpointUrlEchoedInHello)
{
  constexpr std::string_view serverUri = "urn:test:client-transport:reverse-server";
  constexpr std::string_view endpointUrl = "opc.tcp://reverse.example.com:4840/echo-me-verbatim";

  auto port = find_free_port();

  ReverseConnectListenerConfig config;
  config.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  config.bind.address = fmt::format("127.0.0.1:{}", port);
  config.expectedServers.push_back(ExpectedServer{
    .serverUri = std::string{serverUri},
    .endpointUrls = {std::string{endpointUrl}},
  });
  config.maxQueuedConnections = 5;
  config.initialMessageTimeout = std::chrono::seconds{10};

  mReverseHandle = mClient->core().start_reverse_connect_sync(std::move(config));
  // The acceptor bind is posted to the listener strand; the Client API exposes no bind-readiness signal
  // end-to-end (same transitional settle as the ClientReverseListener slice).
  std::this_thread::sleep_for(200ms);

  StubServer stub;
  stub.dial(port);
  stub.send(make_reverse_hello(serverUri, endpointUrl));

  auto response = stub.read_message(5s);
  ASSERT_EQ(response.type, "HEL") << "a valid ReverseHello must start negotiation with a client HEL; got '"
                                  << response.type << "'";
  ASSERT_GE(response.bytes.size(), 28u);

  auto hello = decode_hello(response.bytes);
  EXPECT_EQ(hello.endpointUrl, endpointUrl)
    << "the reverse-connect HEL must echo the ReverseHello EndpointUrl verbatim";
}
