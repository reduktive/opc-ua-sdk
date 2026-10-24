// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientReverseListener cluster of the client integration-test matrix (the 12
/// `ClientReverseListener.*`
///        rows).
///
/// These are TCP-stub-level integration tests of the client-side reverse-connect LISTENER
/// (section 10.14): `ua::client::ReverseConnectListener` reached through the public
/// `CoreClient::start_reverse_connect_sync` entry point, plus the reverse-connect handshake state machine
/// in `ua::ConnectionProtocol` (Client role, `reverseConnect=true`). The client LISTENS on an ephemeral
/// TCP port; a Server is expected to dial IN, send a ReverseHello (RHE), receive the client's Hello
/// (HEL), reply Acknowledge (ACK), and hand off the negotiated connection.
///
/// HARNESS. Each test starts a client reverse listener via `start_reverse_connect_sync` and then plays
/// the role of the reverse-connecting Server with a raw TCP stub (`StubServer`): it connects to the
/// listener port and writes crafted first-message bytes (a valid RHE, a HEL, an ERR, garbage, or
/// nothing), then reads back the exact bytes the client emits. All UA connection-protocol frames are
/// HAND-ROLLED here (an oracle INDEPENDENT of the product encoder), so a decode/echo bug in the product
/// cannot mask itself. Observation is BOUNDED-poll on the socket (read with a deadline / wait for EOF),
/// never a fixed sleep, so the two timer rows are not shard-flaky.
///
/// OBSERVABLES. On a client-role fatal handshake error the client closes the socket without writing
/// (no SecureChannel exists, so there is no CloseSecureChannel to send, Part 6 section 7.1.5), so a
/// rejection is observed as "the client sends nothing (never HEL), then EOF". A valid RHE is observed as "the
/// client emits a HEL echoing the RHE EndpointUrl and carrying negotiated buffer sizes". A completed
/// RHE->HEL->ACK negotiation queues the connection; a consumer (`open_channel_async` in ConnectMode::Reverse,
/// keyed on the EndpointUrl) then drives an OPN over the same socket - the stub observes that OPN as the
/// hand-off.
///
/// REPORTED DIVERGENCES (matrix oracle vs built architecture - asserted against the real observable and
/// batched, per the ClientSubscription/ClientRepublish precedent):
///   - There is no `on_reverse_connection` callback surface. The built hand-off is the queue consumed by
///     `open_channel(ConnectMode::Reverse)`. Rows CallbackInvokedOnce... and NoCallbackRegistered... assert
///     the built hand-off (OPN keyed on EndpointUrl / the queued socket is owned and released on stop,
///     never orphaned) rather than a callback invocation.
///   - `ClientObserver::on_error_chain` is NOT wired to reverse-listener handshake failures (the
///     listener's on_handshake_error only logs). FatalErrReportedToApplicationBeforeClose asserts the
///     WIRE observable (client closes promptly after the injected ERR); the observer fan-out is unbuilt.
///   - The listener idle timeout is not exposed as a millisecond config; a silent (no-RHE) socket is
///     governed by the configurable, seconds-granularity `initialMessageTimeout` (the C4 pre-RHE
///     window), and a QUEUED connection has a hard-coded 60s idle timer - both <= 120s. The two idle
///     rows target `initialMessageTimeout`.
///   - ReverseHelloServerUriTooLongRejected: the client DECODES the RHE body before field-validating, so
///     "no allocation of the over-long URI" is not literally satisfied; the asserted observable is "no
///     HEL echoed, connection closed".

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"

#include "ua_core_client.h"
#include "ua_defines.h"  // TransportProfileId
#include "ua_reverse_connect_config.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include "fmt/format.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
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

/// Prepend an 8-byte header (3 type chars + 'F' + u32 size) then splice in the actual size.
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

std::vector<std::byte> make_reverse_hello(std::string_view serverUri, std::string_view endpointUrl)
{
  std::vector<std::byte> body;
  append_ua_string(body, serverUri);
  append_ua_string(body, endpointUrl);
  return frame_with_header("RHE", std::move(body));
}

std::vector<std::byte> make_hello(std::string_view endpointUrl)
{
  std::vector<std::byte> body;
  append_u32_le(body, 0);  // protocolVersion
  append_u32_le(body, 65536);  // ReceiveBufferSize
  append_u32_le(body, 65536);  // SendBufferSize
  append_u32_le(body, 0);  // MaxMessageSize (0 = unlimited)
  append_u32_le(body, 0);  // MaxChunkCount (0 = unlimited)
  append_ua_string(body, endpointUrl);
  return frame_with_header("HEL", std::move(body));
}

std::vector<std::byte> make_acknowledge(
  uint32_t receiveBuffer, uint32_t sendBuffer, uint32_t maxMessage, uint32_t maxChunk)
{
  std::vector<std::byte> body;
  append_u32_le(body, 0);  // protocolVersion
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

/// A raw 8-byte header with an arbitrary (garbage) message-type tag.
std::vector<std::byte> make_garbage_header(const char (&type)[4])
{
  return frame_with_header(type, {});
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

/// Decode a full HEL frame (header + body). Pre-condition: bytes.size() >= 8 and type == "HEL".
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
  if (urlLength > 0)
  {
    hello.endpointUrl.assign(reinterpret_cast<const char*>(body + 24), static_cast<size_t>(urlLength));
  }
  return hello;
}

// ---------------------------------------------------------------------------
// StubServer - a synchronous TCP client that plays the reverse-connecting
// Server. Bounded reads/EOF-wait via async ops driven on a private io_context.
// ---------------------------------------------------------------------------

class StubServer
{
public:
  void connect(uint16_t port)
  {
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(), port);
    mSocket.connect(endpoint);
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

  /// Read exactly `count` bytes, or stop early on EOF/deadline.
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
    std::string type;  ///< 3-char message-type tag ("HEL", "CLO", "ERR", "ACK", "OPN", ...).
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
  boost::asio::ip::tcp::socket mSocket{mIoContext};
};

/// Find a free TCP port by binding to port 0 and immediately closing.
uint16_t find_free_port()
{
  boost::asio::io_context ioContext;
  boost::asio::ip::tcp::acceptor acceptor(
    ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
  auto port = acceptor.local_endpoint().port();
  acceptor.close();
  return port;
}

constexpr std::string_view reverseServerUri = "urn:test:reverse-listener:server";
constexpr std::string_view reverseEndpointUrl = "opc.tcp://reverse.example.com:4840/negotiation-echo";

/// Drive the client through a full RHE -> HEL -> ACK negotiation. Sends a valid ReverseHello, reads
/// the client's HEL (asserting the type), then replies with an ACK that echoes the client's advertised
/// buffer sizes so ACK validation passes. Returns the decoded HEL (empty EndpointUrl on failure).
DecodedHello negotiate_to_ack(StubServer& stub, std::chrono::milliseconds timeout)
{
  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));
  auto hello = stub.read_message(timeout);
  EXPECT_EQ(hello.type, "HEL") << "negotiation must reach the client HEL";

  DecodedHello decoded;
  if (hello.type == "HEL" && hello.bytes.size() >= 8)
  {
    decoded = decode_hello(hello.bytes);
    stub.send(make_acknowledge(
      decoded.receiveBufferSize, decoded.sendBufferSize, decoded.maxMessageSize, decoded.maxChunkCount));
  }
  return decoded;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture: a Client with a reverse listener, driven by a raw TCP stub server.
// ---------------------------------------------------------------------------
class ClientReverseListener : public ::testing::Test
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
    if (mHandle != client::ReverseConnectHandle{})
    {
      (void)mClient->core().try_stop_reverse_connect_sync(mHandle);
      mHandle = {};
    }
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  /// Start a client reverse listener that expects `reverseServerUri` advertising `reverseEndpointUrl`.
  /// Returns the bound port. A brief bind-readiness settle mirrors reverse_connect_tests.cpp.
  uint16_t start_listener(std::chrono::seconds initialMessageTimeout = std::chrono::seconds{10},
    uint32_t maxQueuedConnections = 5, std::optional<uint32_t> maxPendingHandshakes = std::nullopt,
    std::optional<uint32_t> maxPendingHandshakesPerAddress = std::nullopt)
  {
    auto port = find_free_port();

    ReverseConnectListenerConfig config;
    if (maxPendingHandshakes)
      config.maxPendingHandshakes = *maxPendingHandshakes;
    if (maxPendingHandshakesPerAddress)
      config.maxPendingHandshakesPerAddress = *maxPendingHandshakesPerAddress;
    config.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    config.bind.address = fmt::format("127.0.0.1:{}", port);
    config.expectedServers.push_back(ExpectedServer{
      .serverUri = std::string{reverseServerUri},
      .endpointUrls = {std::string{reverseEndpointUrl}},
    });
    config.maxQueuedConnections = maxQueuedConnections;
    config.initialMessageTimeout = initialMessageTimeout;

    mHandle = mClient->core().start_reverse_connect_sync(std::move(config));

    // The acceptor bind is posted to the listener strand; the Client API does not yet expose a
    // bind-readiness signal end-to-end (same transitional settle as reverse_connect_tests.cpp).
    std::this_thread::sleep_for(200ms);
    return port;
  }

  boost::asio::thread_pool mClientThreadPool;
  std::optional<Client> mClient;
  client::ReverseConnectHandle mHandle{};
};

// ---------------------------------------------------------------------------
// AThirdSilentServerBeyondThePendingHandshakeBoundIsClosedAtAccept - CL-RC-007
// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-IN-TOTAL
// Three stub servers connect and send nothing. With maxPendingHandshakes = 2 (per-address 8, so the
// total is the bound that fires) the third socket is closed at accept while the first two stay open
// inside their initial-message window. This is also the non-default-value proof for the new field.
// ---------------------------------------------------------------------------
TEST_F(ClientReverseListener, AThirdSilentServerBeyondThePendingHandshakeBoundIsClosedAtAccept)
{
  auto port = start_listener(std::chrono::seconds{10},
    /*maxQueuedConnections=*/5,
    /*maxPendingHandshakes=*/2,
    /*maxPendingHandshakesPerAddress=*/8);

  StubServer first;
  first.connect(port);
  StubServer second;
  second.connect(port);
  std::this_thread::sleep_for(200ms);  // both are pending before the third arrives
  StubServer third;
  third.connect(port);

  EXPECT_TRUE(third.wait_for_close(3s)) << "the third silent server must be closed at accept";
  EXPECT_FALSE(first.wait_for_close(500ms)) << "the first server stays pending inside its window";
  EXPECT_FALSE(second.wait_for_close(500ms)) << "the second server stays pending inside its window";
}

// ---------------------------------------------------------------------------
// FirstMessageReverseHelloStartsNegotiation - CL-RC-001
// @verifies CL-RC-001
// A valid RHE (recognized ServerUri + advertised EndpointUrl) makes the client begin buffer
// negotiation by emitting a HEL. [neg: client ignores the RHE / sends no HEL]
// ---------------------------------------------------------------------------
// @relation(CL-RC-001, scope=function)
TEST_F(ClientReverseListener, FirstMessageReverseHelloStartsNegotiation)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));

  auto response = stub.read_message(5s);
  EXPECT_EQ(response.type, "HEL")
    << "A valid ReverseHello must start negotiation with a client HEL; got type '" << response.type << "'";
}

// ---------------------------------------------------------------------------
// DefaultIdleTimeoutAtMost120Seconds - CL-RC-003
// @verifies CL-RC-003
// The default listener idle timeout must not exceed two minutes. The public-config surface for the
// pre-RHE idle window is initialMessageTimeout; its default (30s) is read WITHOUT waiting.
// [neg: default must not exceed 2 minutes]
// ---------------------------------------------------------------------------
// @relation(CL-RC-003, scope=function)
TEST_F(ClientReverseListener, DefaultIdleTimeoutAtMost120Seconds)
{
  const ReverseConnectListenerConfig defaults;
  EXPECT_LE(defaults.initialMessageTimeout, std::chrono::seconds{120})
    << "Default reverse-listener idle timeout exceeds 120s";
}

// @relation(AC-SVR-TCP-017-ECHO, scope=function)

// ---------------------------------------------------------------------------
// EmitsHelloWithEchoedEndpointUrlAfterValidReverseHello - CL-RC-002; CL-TCP-016
// @verifies CL-RC-002
// @verifies CL-TCP-016
// A valid RHE carrying EndpointUrl X makes the client emit a HEL that echoes X verbatim and carries
// negotiated buffer sizes. [neg: HEL omits or rewrites the RHE EndpointUrl]
// ---------------------------------------------------------------------------
// @relation(CL-RC-002, CL-TCP-016, scope=function)
TEST_F(ClientReverseListener, EmitsHelloWithEchoedEndpointUrlAfterValidReverseHello)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));

  auto response = stub.read_message(5s);
  ASSERT_EQ(response.type, "HEL");

  auto hello = decode_hello(response.bytes);
  EXPECT_EQ(hello.endpointUrl, reverseEndpointUrl)
    << "Client HEL must echo the ReverseHello EndpointUrl verbatim";
  EXPECT_GT(hello.receiveBufferSize, 0u) << "HEL must carry a negotiated ReceiveBufferSize";
  EXPECT_GT(hello.sendBufferSize, 0u) << "HEL must carry a negotiated SendBufferSize";
}

// ---------------------------------------------------------------------------
// FirstMessageGarbageTagRejected - CL-RC-001
// @verifies CL-RC-001
// A first frame whose message-type tag is not any valid OPC UA tag is rejected: the client closes
// without writing and never emits a HEL. [neg: garbage first-message tag]
// ---------------------------------------------------------------------------
// @relation(CL-RC-001, scope=function)
TEST_F(ClientReverseListener, FirstMessageGarbageTagRejected)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_garbage_header("XYZ"));

  auto response = stub.read_message(5s);
  EXPECT_NE(response.type, "HEL") << "A garbage first-message tag must not yield a HEL";
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof) << "Client must close on a garbage first-message tag";
}

// ---------------------------------------------------------------------------
// FirstMessageHelloRejectedWithMessageTypeInvalid - CL-RC-001
// @verifies CL-RC-001
// A HEL (rather than an RHE) as the first frame on the listener path is rejected: the client closes
// without writing and emits no HEL of its own. [neg: first message is HEL not RHE]
// ---------------------------------------------------------------------------
// @relation(CL-RC-001, scope=function)
TEST_F(ClientReverseListener, FirstMessageHelloRejectedWithMessageTypeInvalid)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_hello(reverseEndpointUrl));

  auto response = stub.read_message(5s);
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof)
    << "Client must reject a HEL-first on the reverse-listener path";
}

// ---------------------------------------------------------------------------
// NoHelloWhenReverseHelloServerUriUnknown - CL-RC-002; CL-TCP-015
// @verifies CL-RC-002
// @verifies CL-TCP-015
// An RHE whose ServerUri is not in the listener's expected-server allow-list is rejected: the client
// emits NO HEL and closes. [neg: unrecognized ServerUri]
// ---------------------------------------------------------------------------
// @relation(CL-RC-002, CL-TCP-015, scope=function)
TEST_F(ClientReverseListener, NoHelloWhenReverseHelloServerUriUnknown)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_reverse_hello("urn:completely:unexpected:server", reverseEndpointUrl));

  auto response = stub.read_message(5s);
  EXPECT_NE(response.type, "HEL") << "Client must not HEL against an unrecognized ServerUri";
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof) << "Client must close on an unrecognized ServerUri";
}

// ---------------------------------------------------------------------------
// ReverseHelloServerUriTooLongRejected - CL-TCP-015
// @verifies CL-TCP-015
// An RHE whose ServerUri exceeds 4096 bytes is rejected: the client emits no HEL and closes. (The
// client decodes the body before field-validating, so the "no allocation" clause is not literally
// satisfied - the asserted observable is "no HEL echoed, connection closed".)
// [neg: ServerUri > 4096 bytes]
// ---------------------------------------------------------------------------
// @relation(CL-TCP-015, scope=function)
TEST_F(ClientReverseListener, ReverseHelloServerUriTooLongRejected)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  // 4097 bytes: one over the Part 6 section 7.1.2.3 limit (maxUrlSize == 4096), still within
  // maxReverseHelloSize so the frame is read and field-validated (not size-rejected).
  const std::string overlongUri(4097, 'a');
  stub.send(make_reverse_hello(overlongUri, reverseEndpointUrl));

  auto response = stub.read_message(5s);
  EXPECT_NE(response.type, "HEL") << "Client must not echo an over-long ServerUri into a HEL";
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof) << "Client must close on an over-long ServerUri";
}

// ---------------------------------------------------------------------------
// SecondReverseHelloAfterHelloRejected - CL-RC-004
// @verifies CL-RC-004
// After a valid RHE and the client's HEL (awaiting ACK), a second RHE on the same socket is rejected:
// the client closes rather than continuing. [neg: duplicate ReverseHello]
// ---------------------------------------------------------------------------
// @relation(CL-RC-004, scope=function)
TEST_F(ClientReverseListener, SecondReverseHelloAfterHelloRejected)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));

  auto hello = stub.read_message(5s);
  ASSERT_EQ(hello.type, "HEL");

  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));  // duplicate RHE where ACK is expected

  auto response = stub.read_message(5s);
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof)
    << "A duplicate ReverseHello must be rejected, not accepted";
}

// ---------------------------------------------------------------------------
// FatalErrReportedToApplicationBeforeClose - CL-RC-005; CL-TCP-014
// @verifies CL-RC-005
// @verifies CL-TCP-014
// After a valid RHE and the client's HEL, the server replies with a fatal ERR (Bad_TcpServerTooBusy).
// APPLICATION observable: the pending public open_channel callback receives the server's exact status
// and rich reason before its timeout. WIRE observable: the client also tears down the reverse socket
// promptly (it closes without writing: no SecureChannel is open, so no CloseSecureChannel exists).
// [neg: server ERR on reverse socket replaced by BadTimeout or dropped silently]
// ---------------------------------------------------------------------------
// @relation(CL-RC-005, CL-TCP-014, scope=function)
TEST_F(ClientReverseListener, FatalErrReportedToApplicationBeforeClose)
{
  auto port = start_listener();

  auto openPromise = std::make_shared<std::promise<CoreClient::SecureChannelResult>>();
  auto openFuture = openPromise->get_future();
  mClient->core().open_channel_async(
    CoreClient::OpenChannelConfig{
      .endpointUrl = std::string{reverseEndpointUrl},
      .connectMode = ConnectMode::Reverse,
      .timeout = 8s,
    },
    [openPromise](CoreClient::SecureChannelResult result) { openPromise->set_value(std::move(result)); });

  StubServer stub;
  stub.connect(port);
  stub.send(make_reverse_hello(reverseServerUri, reverseEndpointUrl));

  auto hello = stub.read_message(5s);
  ASSERT_EQ(hello.type, "HEL");

  stub.send(make_error(StatusCode{Status::BadTcpServerTooBusy}.as_uint32(), "server too busy"));

  ASSERT_EQ(openFuture.wait_for(5s), std::future_status::ready)
    << "fatal reverse-listener ERR must reach the application before the open timeout";
  auto openResult = openFuture.get();
  ASSERT_TRUE(openResult.is_bad());
  EXPECT_EQ(openResult.status_code(), StatusCode{Status::BadTcpServerTooBusy});
  ASSERT_NE(openResult.shared_detail(), nullptr);
  ASSERT_GE(openResult.shared_detail()->context.size(), 2u);
  EXPECT_EQ(openResult.shared_detail()->context.back().value, "server too busy");

  auto response = stub.read_message(5s);
  // RATIFIED TEST ADAPTATION (group L, L-D6): this asserted the bare 8-byte "CLOF" frame the client used
  // to write on any fatal error; before a SecureChannel is open no conformant CloseSecureChannel exists
  // (Part 6 6.7.2.2-6.7.2.4, Part 4 5.5.3.1). Still asserted: the client closes; now also that it writes
  // nothing first.
  EXPECT_TRUE(response.type.empty() && response.eof)
    << "Client must close the reverse socket after a fatal ERR; got '" << response.type << "'";
  EXPECT_TRUE(response.eof || stub.wait_for_close(5s)) << "Socket must reach EOF after the client closes";
}

// ---------------------------------------------------------------------------
// SilentSocketClosedAtIdleTimeout - CL-RC-003
// @verifies CL-RC-003
// A socket that connects but sends no RHE is closed at the (configurable, seconds-granularity)
// initial-message timeout - the pre-RHE idle window (C4). Observed by bounded polling for the close,
// not a fixed sleep. [neg: half-open socket left open indefinitely]
// ---------------------------------------------------------------------------
// @relation(CL-RC-003, scope=function)
TEST_F(ClientReverseListener, SilentSocketClosedAtIdleTimeout)
{
  auto port = start_listener(std::chrono::seconds{1});  // shortest configurable pre-RHE window

  StubServer stub;
  stub.connect(port);
  // Send nothing: the client's 1s initial-message deadline elapses -> BadTimeout -> close.

  auto response = stub.read_message(8s);
  EXPECT_TRUE(response.type == "CLO" || response.eof)
    << "Silent reverse socket must be closed at the initial-message timeout; got type '" << response.type
    << "' (timedOut=" << response.timedOut << ")";
}

// ---------------------------------------------------------------------------
// CallbackInvokedOnceWithConfiguredConnectionAfterNegotiation - CL-RC-006
// @verifies CL-RC-006
// After a full RHE -> HEL -> ACK negotiation, the negotiated connection is handed off to the consumer
// keyed on the EndpointUrl. Built architecture note: there is no on_reverse_connection callback; the
// hand-off is the queue consumed by open_channel(ConnectMode::Reverse). The stub observes the hand-off
// as the OPN the consumer drives over the same socket (a HEL/CLO would falsify the hand-off).
// [neg: callback fires zero/multiple times or yields the wrong endpoint]
// ---------------------------------------------------------------------------
// @relation(CL-RC-006, scope=function)
TEST_F(ClientReverseListener, CallbackInvokedOnceWithConfiguredConnectionAfterNegotiation)
{
  auto port = start_listener();

  // Register the consumer first (waiter keyed on reverseEndpointUrl). Its callback captures only a shared
  // flag, so it is safe if it fires after the socket drops during teardown.
  auto opened = std::make_shared<std::atomic<bool>>(false);
  mClient->core().open_channel_async(
    CoreClient::OpenChannelConfig{
      .endpointUrl = std::string{reverseEndpointUrl},
      .connectMode = ConnectMode::Reverse,
      .timeout = std::chrono::milliseconds{8000},
    },
    [opened](CoreClient::SecureChannelResult) { opened->store(true); });

  StubServer stub;
  stub.connect(port);
  auto hello = negotiate_to_ack(stub, 5s);
  ASSERT_EQ(hello.endpointUrl, reverseEndpointUrl) << "negotiation must complete before hand-off";

  // The consumer, having received the negotiated connection keyed on reverseEndpointUrl, drives an OPN.
  auto handoff = stub.read_message(5s);
  EXPECT_EQ(handoff.type, "OPN")
    << "Negotiated reverse connection must be handed off to the endpoint-keyed consumer (OPN); got '"
    << handoff.type << "'";
}

// ---------------------------------------------------------------------------
// NoCallbackRegisteredDropsAcceptedConnection - CL-RC-006
// @verifies CL-RC-006
// With no consumer, a fully negotiated connection is QUEUED (owned by the listener, not orphaned).
// Built architecture note: the built model queues (bounded; 60s idle-evicted) rather than dropping
// immediately; the accepted connection is owned by the listener and RELEASED on stop - stopping the
// listener closes it, which the stub observes as FIN. An orphaned/leaked socket would not close.
// [neg: accepted socket left open with no owner]
// ---------------------------------------------------------------------------
// @relation(CL-RC-006, scope=function)
TEST_F(ClientReverseListener, NoCallbackRegisteredDropsAcceptedConnection)
{
  auto port = start_listener();

  StubServer stub;
  stub.connect(port);
  auto hello = negotiate_to_ack(stub, 5s);
  EXPECT_EQ(hello.endpointUrl, reverseEndpointUrl) << "negotiation must complete (no consumer registered)";

  // The negotiated connection must be QUEUED and idle (open, no data, no close) with no consumer -
  // this pins the close to the stop below, not to an earlier ACK rejection.
  auto idle = stub.read_message(500ms);
  EXPECT_TRUE(idle.timedOut) << "queued connection must stay open before the listener stops";
  EXPECT_FALSE(idle.eof) << "queued connection must not close before the listener stops";

  // Stop the listener: a well-owned queued connection is closed; an orphan would linger.
  ASSERT_TRUE(mClient->core().try_stop_reverse_connect_sync(mHandle).is_good());
  mHandle = {};

  EXPECT_TRUE(stub.wait_for_close(5s))
    << "Queued reverse connection with no consumer must be closed when the listener stops "
       "(never orphaned)";
}

// ---------------------------------------------------------------------------
// Row: ReverseConnectListenerConfig::maxQueuedConnections
//      (configuration coverage matrix section 11 - audited WEAK: every fixture left it at 5 and no test
//      varied it).
//
// Inbound reverse connections that no waiter has claimed are parked in a queue. The queue is attacker-
// facing - a rogue server can dial in repeatedly - so it is bounded, and at capacity the NEW connection is
// refused, as the option's documentation states ("rejected until the queue drains"). RATIFIED CHANGE
// (group L, security review B1-10): this row pinned drop-oldest, which let any peer whose ReverseHello
// passes the validator (its strings are public) displace a legitimate server's parked connection.
//
// The close is what the dialing peer sees, and it is the oracle: the newcomer's socket goes away while the
// parked one survives. Asserting only "the newcomer is closed" would pass against an implementation that
// closed both, so the survivor is asserted too.
// ---------------------------------------------------------------------------
// @verifies AC-CL-RC-007-A-FULL-REVERSE-CONNECT-QUEUE-REFUSES-THE-NEWCOMER
TEST_F(ClientReverseListener, QueueAtCapacityRefusesTheNewcomer)
{
  auto port = start_listener(std::chrono::seconds{10}, /*maxQueuedConnections=*/1);

  // A connection is parked only once negotiation COMPLETES - RHE, the client's HEL, then our ACK. A stub
  // that stops at the RHE is still mid-negotiation and never enters the queue at all.
  StubServer first;
  first.connect(port);
  ASSERT_FALSE(negotiate_to_ack(first, 5s).endpointUrl.empty()) << "first server must reach the queue";
  std::this_thread::sleep_for(300ms);

  // Second server dials in and negotiates. With capacity 1 it is refused.
  StubServer second;
  second.connect(port);
  ASSERT_FALSE(negotiate_to_ack(second, 5s).endpointUrl.empty()) << "second server completes negotiation";

  EXPECT_TRUE(second.wait_for_close(3s)) << "at capacity the NEW connection must be refused (closed)";
  EXPECT_FALSE(first.wait_for_close(500ms))
    << "the parked connection must survive (reject-newest, not drop-oldest)";
}
