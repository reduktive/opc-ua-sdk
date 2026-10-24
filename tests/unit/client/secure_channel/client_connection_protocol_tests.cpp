// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_connection_protocol.h"
#include "ua_reverse_hello.h"
#include <boost/asio/thread_pool.hpp>

#include <condition_variable>
#include <future>
#include <thread>
#include <mutex>
#include <optional>

#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// Parsed Hello message from client writes.
struct Hello
{
  uint32_t protocolVersion{0};
  uint32_t receiveBufferSize{0};
  uint32_t sendBufferSize{0};
  uint32_t maxMessageSize{0};
  uint32_t maxChunkCount{0};
  std::string endpointUrl;
};

static Hello parse_hello(span<const byte> bytes)
{
  memory_stream_device::ExternalReadOnly streamDevice{bytes};
  MemoryStream stream{streamDevice};
  StructureFactory structureFactory;
  EncodingLimits limits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(structureFactory.resolver(), stream, limits);
  auto depth = limits.stack_depth();

  uint8_t h{0}, e{0}, l{0}, f{0};
  dec.decode(depth, h);
  dec.decode(depth, e);
  dec.decode(depth, l);
  dec.decode(depth, f);
  if (h != 'H' || e != 'E' || l != 'L' || f != 'F')
  {
    throw UaException{Status::BadDecodingError, make_error_detail("TestError", "Not a HELF message", "Test")};
  }

  Hello hel;
  uint32_t messageSize{0};
  dec.decode(depth, messageSize);
  dec.decode(depth, hel.protocolVersion);
  dec.decode(depth, hel.receiveBufferSize);
  dec.decode(depth, hel.sendBufferSize);
  dec.decode(depth, hel.maxMessageSize);
  dec.decode(depth, hel.maxChunkCount);

  String url;
  dec.decode(depth, url);
  hel.endpointUrl = std::string{std::string_view{url}};
  return hel;
}

/// Build an ACK frame with configurable server limits.
static std::vector<byte> build_ack(
  uint32_t protocolVersion, uint32_t recvBuf, uint32_t sendBuf, uint32_t maxMsg, uint32_t maxChunks)
{
  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::acknowledgeSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'A'});
  enc.encode(limit, uint8_t{'C'});
  enc.encode(limit, uint8_t{'K'});
  enc.encode(limit, uint8_t{'F'});
  enc.encode(limit, uint32_t{ua::connection_protocol::acknowledgeSize});
  enc.encode(limit, protocolVersion);
  enc.encode(limit, recvBuf);
  enc.encode(limit, sendBuf);
  enc.encode(limit, maxMsg);
  enc.encode(limit, maxChunks);

  auto out = streamDevice.move_storage_out();
  out.resize(ua::connection_protocol::acknowledgeSize);
  return out;
}

/// Build an ACK frame with invalid reserved byte.
static std::vector<byte> build_ack_bad_reserved(
  uint32_t recvBuf, uint32_t sendBuf, uint32_t maxMsg, uint32_t maxChunks)
{
  auto ack = build_ack(0, recvBuf, sendBuf, maxMsg, maxChunks);
  ack[3] = static_cast<byte>('X');  // Bad reserved byte.
  return ack;
}

/// Build an ERR frame with a status code and reason string.
static std::vector<byte> build_err(uint32_t errorCode, std::string reason)
{
  memory_stream_device::Dynamic streamDevice{256, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'F'});

  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});  // placeholder

  enc.encode(limit, errorCode);

  String reasonStr{reason};
  enc.encode(limit, reasonStr);

  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);

  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

/// Build a ReverseHello (RHE) frame carrying the given ServerUri and EndpointUrl. Uses the production
/// encoder directly, so the wire bytes are exactly what a conforming reverse-connect server would send.
/// The encoder does not validate field lengths (validation is a separate step performed by the client on
/// decode), so an oversized ServerUri can be produced here to drive the client's CL-TCP-015 length check.
static std::vector<byte> build_rhe(std::string serverUri, std::string endpointUrl)
{
  detail::ReverseHelloMessage msg;
  msg.serverUri = std::move(serverUri);
  msg.endpointUrl = std::move(endpointUrl);
  return detail::encode_reverse_hello(msg);
}

/// Build a message header (8 bytes) with given type, reserved byte, and size.
static std::vector<byte> build_header(std::array<char, 3> type, char reserved, uint32_t messageSize)
{
  std::vector<byte> out;
  out.resize(ua::connection_protocol::headerSize);
  out[0] = static_cast<byte>(type[0]);
  out[1] = static_cast<byte>(type[1]);
  out[2] = static_cast<byte>(type[2]);
  out[3] = static_cast<byte>(reserved);

  out[4] = static_cast<byte>(messageSize & 0xFF);
  out[5] = static_cast<byte>((messageSize >> 8) & 0xFF);
  out[6] = static_cast<byte>((messageSize >> 16) & 0xFF);
  out[7] = static_cast<byte>((messageSize >> 24) & 0xFF);
  return out;
}

/// Synchronization state for connection protocol callbacks.
struct ConnSync
{
  std::mutex mx;
  std::condition_variable cv;

  bool complete{false};
  StatusCode completeStatus{Status::Good};
  ua::connection_protocol::NegotiatedLimits negotiatedLimits;

  bool errorOccurred{false};
  StatusCode errorStatus{Status::Good};
  std::string errorReason;

  bool chunkReceived{false};
  StatusCode chunkStatus{Status::Good};
  std::vector<byte> chunkData;

  /// The ReverseHello surfaced to the completion callback (reverse-connect only).
  std::optional<ua::detail::ReverseHelloMessage> reverseHello;

  bool wait_complete(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return complete; });
  }

  bool wait_error(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return errorOccurred; });
  }

  bool wait_chunk(std::chrono::milliseconds timeout = 500ms)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return chunkReceived; });
  }
};

/// Create a client-role ConnectionProtocol with given endpoint URL and ACK pre-queued.
struct ClientSetup
{
  std::shared_ptr<FakeConnectionProtocolDeps> deps;
  std::shared_ptr<FakeTransportConnection> transport;
  std::shared_ptr<ConnSync> sync;
  std::shared_ptr<ConnectionProtocol> cp;

  /// Drop every executor-pinned shared_ptr so that a subsequent pool.join()
  /// can drain - any_io_executor is work-tracking; cp/transport/deps keep
  /// strands and timers alive otherwise.
  void release()
  {
    cp.reset();
    transport.reset();
    deps.reset();
    sync.reset();
  }

  /// Create with ACK pre-queued for a successful handshake.
  static ClientSetup create_with_ack(boost::asio::any_io_executor ex,
    std::string endpointUrl = "opc.tcp://localhost:4840", uint32_t ackRecv = 65536, uint32_t ackSend = 65536,
    uint32_t ackMaxMsg = 0, uint32_t ackMaxChunks = 0)
  {
    ClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<ConnSync>();

    // Queue ACK response before creating ConnectionProtocol (client sends HEL immediately).
    s.transport->enqueue_hello_message(build_ack(0, ackRecv, ackSend, ackMaxMsg, ackMaxChunks));

    auto syncPtr = s.sync;
    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      false,
      60s,
      [syncPtr](StatusCode st,
        std::shared_ptr<ConnectionProtocol>
          cp,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
          syncPtr->negotiatedLimits = negotiatedLimits;
        }
        syncPtr->cv.notify_one();

        // Register message callbacks so post-handshake messages can be tested.
        cp->set_callbacks(
          [syncPtr](StatusCode chunkSt, std::vector<byte>&& data)
          {
            {
              std::lock_guard<std::mutex> lk(syncPtr->mx);
              syncPtr->chunkReceived = true;
              syncPtr->chunkStatus = chunkSt;
              syncPtr->chunkData = std::move(data);
            }
            syncPtr->cv.notify_one();
          },
          [syncPtr](StatusCode errSt, string_view reason, ua::FatalCloseDisposition)
          {
            {
              std::lock_guard<std::mutex> lk(syncPtr->mx);
              syncPtr->errorOccurred = true;
              syncPtr->errorStatus = errSt;
              syncPtr->errorReason = std::string{reason};
            }
            syncPtr->cv.notify_one();
          });
      },
      [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
          syncPtr->errorReason = std::string{reason};
        }
        syncPtr->cv.notify_one();
      },
      endpointUrl);

    return s;
  }

  /// Create a reverse-connect Client (reverseConnect=true). The client waits for a ReverseHello (RHE)
  /// before sending its Hello. The reverse-connect client issues its first read synchronously during
  /// construction, so the frames the server will send (the RHE, and any following ACK) must be queued on
  /// the transport BEFORE the protocol is created - exactly as the forward-connect factories pre-queue the
  /// ACK. `prequeuedReads` is delivered in order (empty for the never-sends-anything timeout case). The
  /// completion callback records the RHE that was surfaced. `reverseHelloValidator` gates ServerUri
  /// recognition (CL-TCP-015); `timeout` is the connection-establishment deadline (CL-RC-003).
  static ClientSetup create_reverse(boost::asio::any_io_executor ex,
    std::vector<std::vector<byte>> prequeuedReads,
    ConnectionProtocol::ReverseHelloValidator reverseHelloValidator = {}, std::chrono::seconds timeout = 60s,
    std::string serverUri = "urn:test:server",
    ConnectionProtocol::EndpointUrlValidator endpointUrlValidator = {})
  {
    ClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<ConnSync>();

    for (auto& frame : prequeuedReads)
    {
      s.transport->enqueue_hello_message(std::move(frame));
    }

    auto syncPtr = s.sync;
    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      true,
      timeout,
      [syncPtr](StatusCode st,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>
          rhe)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
          syncPtr->negotiatedLimits = negotiatedLimits;
          syncPtr->reverseHello = std::move(rhe);
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
          syncPtr->errorReason = std::string{reason};
        }
        syncPtr->cv.notify_one();
      },
      std::string{},  // endpointUrl is taken from the RHE, not configured up front.
      std::move(endpointUrlValidator),
      10'000ms,
      std::move(serverUri),
      std::move(reverseHelloValidator));

    return s;
  }

  /// Create without any ACK queued (for error/stall tests).
  static ClientSetup create_no_ack(
    boost::asio::any_io_executor ex, std::string endpointUrl = "opc.tcp://localhost:4840")
  {
    ClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<ConnSync>();

    auto syncPtr = s.sync;
    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      false,
      60s,
      [syncPtr](StatusCode st,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
          syncPtr->negotiatedLimits = negotiatedLimits;
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
          syncPtr->errorReason = std::string{reason};
        }
        syncPtr->cv.notify_one();
      },
      endpointUrl);

    return s;
  }

  /// Create with ERR pre-queued instead of ACK.
  static ClientSetup create_with_err(boost::asio::any_io_executor ex, uint32_t errorCode, std::string reason,
    std::string endpointUrl = "opc.tcp://localhost:4840")
  {
    ClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<ConnSync>();

    s.transport->enqueue_hello_message(build_err(errorCode, reason));

    auto syncPtr = s.sync;
    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      false,
      60s,
      [syncPtr](StatusCode st,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
          syncPtr->negotiatedLimits = negotiatedLimits;
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
          syncPtr->errorReason = std::string{reason};
        }
        syncPtr->cv.notify_one();
      },
      endpointUrl);

    return s;
  }

  /// Create with a raw pre-queued response (for invalid message type tests).
  static ClientSetup create_with_raw_response(boost::asio::any_io_executor ex, std::vector<byte> response,
    std::string endpointUrl = "opc.tcp://localhost:4840")
  {
    ClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<ConnSync>();

    s.transport->enqueue_hello_message(std::move(response));

    auto syncPtr = s.sync;
    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      false,
      60s,
      [syncPtr](StatusCode st,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
          syncPtr->completeStatus = st;
        }
        syncPtr->cv.notify_one();
      },
      [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->errorOccurred = true;
          syncPtr->errorStatus = st;
          syncPtr->errorReason = std::string{reason};
        }
        syncPtr->cv.notify_one();
      },
      endpointUrl);

    return s;
  }
};

}  // namespace

// =============================================================================
// CL-TCP-001: First message on new connection must be Hello
// =============================================================================

// @verifies CL-TCP-001
// @relation(CL-TCP-001, scope=function)
TEST(ClientConnectionProtocolTests, HelloIsSentAsFirstMessage)
{
  // Spec: Part 6, 7.1.3 - First message sent shall be a Hello.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());

  // Wait for client to write HEL + connection to complete.
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  // First write must be a HELF message.
  auto& hel = writes[0];
  ASSERT_GE(hel.size(), ua::connection_protocol::headerSize);
  EXPECT_EQ(static_cast<char>(hel[0]), 'H');
  EXPECT_EQ(static_cast<char>(hel[1]), 'E');
  EXPECT_EQ(static_cast<char>(hel[2]), 'L');
  EXPECT_EQ(static_cast<char>(hel[3]), 'F');
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-008: Reserved byte set to 'F' for connection protocol messages
// =============================================================================

// @verifies CL-TCP-008
// @relation(CL-TCP-008, scope=function)
TEST(ClientConnectionProtocolTests, HelloMessageHasReservedByteF)
{
  // Spec: Part 6, 7.1.2.2 - Reserved byte shall be 'F'.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-002: Hello ReceiveBufferSize meets minimum (8192 for non-ECC)
// =============================================================================

// @verifies CL-TCP-002
// @relation(CL-TCP-002, scope=function)
TEST(ClientConnectionProtocolTests, HelloReceiveBufferMeetsNonEccMinimum)
{
  // Spec: Part 6, 7.1.2.3 - ReceiveBufferSize shall be at least 8192 bytes.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  auto hel = parse_hello(writes[0]);
  EXPECT_GE(hel.receiveBufferSize, 8192u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-003: Hello SendBufferSize meets minimum (8192 for non-ECC)
// =============================================================================

// @verifies CL-TCP-003
// @relation(CL-TCP-003, scope=function)
TEST(ClientConnectionProtocolTests, HelloSendBufferMeetsNonEccMinimum)
{
  // Spec: Part 6, 7.1.2.3 - SendBufferSize shall be at least 8192 bytes.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  auto hel = parse_hello(writes[0]);
  EXPECT_GE(hel.sendBufferSize, 8192u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-002
// @relation(CL-TCP-002, scope=function)
TEST(ClientConnectionProtocolTests, HelloBufferBelowMinimumClampedToNonEccFloor)
{
  // Spec: Part 6, 7.1.2.3 - a client shall not propose a Receive/SendBufferSize below the protocol
  // minimum. A client configured with a sub-minimum buffer (512, below even the 1024 ECC floor) must NOT
  // put 512 on the wire; send_hello clamps the proposal up to the non-ECC minimum (8192), which is valid
  // for every server. Regression guard for the client proposing an out-of-spec sub-minimum buffer.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(
    ua::connection_protocol::Limits{.maxBufferSize = 512, .maxMessageSize = 0, .maxChunkCount = 0});

  auto transport = std::make_shared<FakeTransportConnection>();
  auto sync = std::make_shared<ConnSync>();
  // The ACK echoes the clamped proposal (8192) so ACK validation (peer buffers must be <= the client's
  // effective, clamped mMaxBufferSize) passes and the handshake completes.
  transport->enqueue_hello_message(build_ack(0, 8192, 8192, 0, 0));

  auto syncPtr = sync;
  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    deps,
    transport,
    false,
    60s,
    [syncPtr](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->complete = true;
        syncPtr->completeStatus = st;
      }
      syncPtr->cv.notify_one();
    },
    [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->errorOccurred = true;
        syncPtr->errorStatus = st;
        syncPtr->errorReason = std::string{reason};
      }
      syncPtr->cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  ASSERT_TRUE(sync->wait_complete());

  auto writes = transport->writes();
  ASSERT_GE(writes.size(), 1u);
  auto hel = parse_hello(writes[0]);
  EXPECT_GE(hel.receiveBufferSize, 8192u)
    << "a sub-minimum configured buffer must be clamped up to the 8192 floor, never proposed as 512";
  EXPECT_GE(hel.sendBufferSize, 8192u)
    << "a sub-minimum configured buffer must be clamped up to the 8192 floor, never proposed as 512";

  cp.reset();
  transport.reset();
  deps.reset();
  sync.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-004: Hello EndpointUrl encoded correctly
// =============================================================================

TEST(ClientConnectionProtocolTests, HelloEndpointUrlWithinLimit)
{
  // Spec: Part 6, 7.1.2.3 - EndpointUrl encoded length shall be less than 4096 bytes.
  boost::asio::thread_pool tp;
  const std::string url = "opc.tcp://localhost:4840/test";
  auto setup = ClientSetup::create_with_ack(tp.get_executor(), url);
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  auto hel = parse_hello(writes[0]);
  EXPECT_EQ(hel.endpointUrl, url);
  EXPECT_LE(hel.endpointUrl.size(), 4096u) << "EndpointUrl encoded length shall be less than 4096 bytes";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-005: Client uses negotiated protocol version from ACK
// =============================================================================

// @relation(AC-CL-TCP-005-01, scope=function)
TEST(ClientConnectionProtocolTests, ClientUsesNegotiatedProtocolVersion)
{
  // Spec: Part 6, 7.1.2.4 - Client accepts protocol version from ACK.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  // Verify HEL used protocol version 0.
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);
  auto hel = parse_hello(writes[0]);
  EXPECT_EQ(hel.protocolVersion, 0u);

  // Connection completed successfully with version 0.
  // Note: the negotiated protocol version is not separately exposed in the Limits
  // callback - the test verifies the HEL sends version 0 and the ACK (also version 0)
  // is accepted without error. A test with a non-zero ACK version is covered by
  // ClientRejectsUnsupportedProtocolVersion.
  EXPECT_TRUE(setup.sync->completeStatus.is_good());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-006: Report negotiated buffer sizes to SecureChannel layer
// =============================================================================

// @verifies CL-TCP-006
// @relation(CL-TCP-006, scope=function)
TEST(ClientConnectionProtocolTests, NegotiatedBufferSizesPassedToCallback)
{
  // Spec: Part 6, 7.1.3 - Negotiated buffer sizes shall be reported.
  boost::asio::thread_pool tp;
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 32768, 16384, 1048576, 100);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Server sent: recv=32768, send=16384.
  // Client defaults: recv=65536, send=65536.
  // Negotiated: recv = min(65536, server_send=16384) = 16384.
  //             send = min(65536, server_recv=32768) = 32768.
  EXPECT_EQ(setup.sync->negotiatedLimits.receiveBufferSize, 16384u);
  EXPECT_EQ(setup.sync->negotiatedLimits.sendBufferSize, 32768u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The control arm of AC-CL-TCP-006. NegotiatedBufferSizesPassedToCallback drives one asymmetric ACK;
// on its own it cannot tell "each direction is taken from the opposite field of the ACK" apart from
// "the pair happens to be those two constants". This run differs from it in exactly one variable -
// which of the ACK's two buffers is the larger - and the reported pair must swap with it.
TEST(ClientConnectionProtocolTests, NegotiatedBufferSizesFollowTheAckWhenItsBuffersAreReversed)
{
  boost::asio::thread_pool tp;
  // Mirror image of NegotiatedBufferSizesPassedToCallback: ACK recv=16384, send=32768.
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 16384, 32768, 1048576, 100);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Negotiated: recv = min(client 65536, server_send=32768) = 32768.
  //             send = min(client 65536, server_recv=16384) = 16384.
  EXPECT_EQ(setup.sync->negotiatedLimits.receiveBufferSize, 32768u)
    << "the receive direction must follow the ACK's SendBufferSize, not a fixed value";
  EXPECT_EQ(setup.sync->negotiatedLimits.sendBufferSize, 16384u)
    << "the send direction must follow the ACK's ReceiveBufferSize, not a fixed value";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientConnectionProtocolTests, AckBuffersExceedingHelloRejected)
{
  // Spec: Part 6, 7.1.2.4 - ACK buffer sizes shall not exceed Hello values.
  // Server advertises larger buffers than client sent in Hello - client rejects.
  boost::asio::thread_pool tp;
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 131072, 131072, 0, 0);
  EXPECT_FALSE(setup.sync->wait_complete()) << "Connection should not complete when ACK exceeds Hello";
  ASSERT_TRUE(setup.sync->wait_error());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-013: Error message reason string handling - Server sends ERR
// =============================================================================

TEST(ClientConnectionProtocolTests, ServerSendsErrInsteadOfAckClosesConnection)
{
  // Spec: Part 6, 7.1.2.5 - Client shall extract reason string from ERR.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_err(
    tp.get_executor(), static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid), "Unknown endpoint");

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-CL-TCP-013-ERR-WITH-GOOD-STATUS-IS-REPORTED-AS-BAD, scope=function)  // control arm
TEST(ClientConnectionProtocolTests, ServerErrStatusCodePropagated)
{
  // Verify the specific error code from server ERR frame is propagated.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_err(
    tp.get_executor(), static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid), "Bad endpoint");

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpEndpointUrlInvalid);
  // Test #23: Verify the reason string from the ERR frame is extracted (not just the status code).
  EXPECT_FALSE(setup.sync->errorReason.empty()) << "ERR reason string should be parsed and propagated";
  EXPECT_NE(setup.sync->errorReason.find("Bad endpoint"), std::string::npos)
    << "Reason text should contain the string sent in the ERR frame";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// An ERR frame is by definition a failure. Its Error field is peer-supplied, so a value with Good
// severity must still be surfaced as a Bad status: the error sink feeds Result<T> error constructors,
// whose invariant is a non-Good status.
// @relation(AC-CL-TCP-013-ERR-WITH-GOOD-STATUS-IS-REPORTED-AS-BAD, scope=function)
TEST(ClientConnectionProtocolTests, ServerErrCarryingAGoodStatusIsReportedAsABadStatus)
{
  boost::asio::thread_pool tp;
  auto setup =
    ClientSetup::create_with_err(tp.get_executor(), static_cast<uint32_t>(Status::Good), "not an error");

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadCommunicationError)
    << "an ERR frame whose Error field is Good must be reported as Bad_CommunicationError, got 0x" << std::hex
    << setup.sync->errorStatus.as_uint32();
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The same sanitisation applies to an ERR received after the handshake (the message-phase decode site).
// @relation(AC-CL-TCP-013-ERR-WITH-GOOD-STATUS-IS-REPORTED-AS-BAD, scope=function)
TEST(ClientConnectionProtocolTests, ServerErrAfterAckCarryingAGoodStatusIsReportedAsABadStatus)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  // The message-phase ERR path reads the header asynchronously and the body synchronously (the same
  // split the fake serves for a first frame). Queue the frame that way, then complete the header
  // read the client may already have armed after the handshake: enqueue_read_exact serves a deferred
  // read at once, which enqueue_hello_message alone does not.
  const auto errFrame = build_err(static_cast<uint32_t>(Status::Good), "not an error");
  setup.transport->enqueue_hello_message(errFrame);
  setup.transport->enqueue_read_exact(
    std::vector<byte>{errFrame.begin(), errFrame.begin() + ua::connection_protocol::headerSize});

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadCommunicationError)
    << "an ERR frame whose Error field is Good must be reported as Bad_CommunicationError, got 0x" << std::hex
    << setup.sync->errorStatus.as_uint32();
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

/// An ERR frame whose Reason length prefix claims more bytes than the frame holds.
static std::vector<byte> build_err_with_reason_cut_short(uint32_t errorCode)
{
  memory_stream_device::Dynamic streamDevice{64, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, errorCode);
  enc.encode(limit, int32_t{100});  // Reason length prefix ...
  enc.encode(limit, uint8_t{'x'});  // ... one byte follows
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

// The Error field is decoded before the Reason; a Reason cut short does not hide the peer's status.
// @relation(AC-CL-TCP-013-ERR-WITH-GOOD-STATUS-IS-REPORTED-AS-BAD, scope=function)  // reason-cut-short arm
TEST(ClientConnectionProtocolTests, ServerErrWithReasonCutShortStillReportsThePeersStatus)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  const auto errFrame =
    build_err_with_reason_cut_short(static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid));
  setup.transport->enqueue_hello_message(errFrame);
  setup.transport->enqueue_read_exact(
    std::vector<byte>{errFrame.begin(), errFrame.begin() + ua::connection_protocol::headerSize});

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpEndpointUrlInvalid)
    << "the peer's Error status must be reported although its Reason was cut short, got 0x" << std::hex
    << setup.sync->errorStatus.as_uint32();
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// ACK validation - Invalid message type
// =============================================================================

TEST(ClientConnectionProtocolTests, AckWithInvalidMessageTypeRejected)
{
  // Receive a non-ACK/non-ERR response; verify client reports error and closes.
  boost::asio::thread_pool tp;
  // Build a response with message type "XYZ" instead of "ACK".
  auto response = build_ack(0, 65536, 65536, 0, 0);
  response[0] = static_cast<byte>('X');
  response[1] = static_cast<byte>('Y');
  response[2] = static_cast<byte>('Z');

  auto setup = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(response));

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpMessageTypeInvalid);
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// ACK validation - Invalid reserved byte
// =============================================================================

TEST(ClientConnectionProtocolTests, AckWithInvalidReservedByteRejected)
{
  // Spec: Part 6, 6.7.6 - Reserved byte must be 'F' in ACK.
  boost::asio::thread_pool tp;
  auto response = build_ack_bad_reserved(65536, 65536, 0, 0);
  auto setup = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(response));

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpMessageTypeInvalid);
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// ACK validation - Invalid message size
// =============================================================================

TEST(ClientConnectionProtocolTests, AckWithMessageSizeTooSmallRejected)
{
  // ACK with messageSize <= headerSize should be rejected.
  boost::asio::thread_pool tp;
  auto response = build_ack(0, 65536, 65536, 0, 0);
  // Overwrite message size to be equal to header size (8) - invalid.
  response[4] = static_cast<byte>(8);
  response[5] = static_cast<byte>(0);
  response[6] = static_cast<byte>(0);
  response[7] = static_cast<byte>(0);

  auto setup = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(response));

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_TRUE(setup.sync->errorStatus.is_bad());
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// ACK validation - Server buffers too small
// =============================================================================

TEST(ClientConnectionProtocolTests, AckWithTooSmallBuffersRejected)
{
  // Spec: buffers must be >= 1024 (eccMinBufferSize).
  boost::asio::thread_pool tp;
  // Server advertises recv=512, send=512 - below minimum.
  auto setup = ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 512, 512, 0, 0);

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpMessageTypeInvalid);
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Successful handshake - connection completes
// =============================================================================

TEST(ClientConnectionProtocolTests, SuccessfulHandshakeCompletesConnection)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  EXPECT_TRUE(setup.sync->completeStatus.is_good());
  EXPECT_FALSE(setup.transport->closed());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-009: Post-handshake message forwarding
// =============================================================================

TEST(ClientConnectionProtocolTests, ValidMessageForwardedToSecureChannelCallback)
{
  // Spec: Part 6, 7.1.2.2 - Valid MSG forwarded to SecureChannel layer.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  // Build a valid MSG frame and queue it for the client to read.
  const uint32_t bodySize = 16;
  const uint32_t totalSize = ua::connection_protocol::headerSize + bodySize;
  auto header = build_header({'M', 'S', 'G'}, 'F', totalSize);

  std::vector<byte> body(bodySize, static_cast<byte>(0xAB));

  // Queue header (for async_read) then body (for the next async_read).
  setup.transport->enqueue_read_exact(header);
  setup.transport->enqueue_read_exact(body);

  ASSERT_TRUE(setup.sync->wait_chunk());
  EXPECT_TRUE(setup.sync->chunkStatus.is_good());
  // The chunk data should be header + body combined.
  EXPECT_EQ(setup.sync->chunkData.size(), totalSize);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-009
// @relation(CL-TCP-009, scope=function)
TEST(ClientConnectionProtocolTests, MessageSizeExceedingReceiveBufferRejected)
{
  // Spec: Part 6, 7.1.2.2 - MessageSize exceeding negotiated ReceiveBufferSize rejected.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  // Set client's local limits to 8192 so negotiation produces a small buffer.
  deps->set_server_limits(
    ua::connection_protocol::Limits{.maxBufferSize = 8192, .maxMessageSize = 0, .maxChunkCount = 0});

  auto transport = std::make_shared<FakeTransportConnection>();
  auto sync = std::make_shared<ConnSync>();

  // Queue ACK with server limits of 8192.
  transport->enqueue_hello_message(build_ack(0, 8192, 8192, 0, 0));
  // Queue the oversized message header immediately so it's ready when async_read fires.
  auto header = build_header({'M', 'S', 'G'}, 'F', 16384);
  transport->enqueue_read_exact(header);

  auto syncPtr = sync;
  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    deps,
    transport,
    false,
    60s,
    [syncPtr](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        cp,
      ua::connection_protocol::NegotiatedLimits negotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->complete = true;
        syncPtr->completeStatus = st;
        syncPtr->negotiatedLimits = negotiatedLimits;
      }
      syncPtr->cv.notify_one();

      cp->set_callbacks([](StatusCode, std::vector<byte>&&) {},
        [syncPtr](StatusCode errSt, string_view reason, ua::FatalCloseDisposition)
        {
          {
            std::lock_guard<std::mutex> lk(syncPtr->mx);
            syncPtr->errorOccurred = true;
            syncPtr->errorStatus = errSt;
            syncPtr->errorReason = std::string{reason};
          }
          syncPtr->cv.notify_one();
        });
    },
    [syncPtr](StatusCode st, string_view reason, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        syncPtr->errorOccurred = true;
        syncPtr->errorStatus = st;
        syncPtr->errorReason = std::string{reason};
      }
      syncPtr->cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  ASSERT_TRUE(sync->wait_error());
  EXPECT_EQ(sync->errorStatus, Status::BadTcpMessageTooLarge);
  EXPECT_TRUE(transport->wait_for_close(500ms));

  cp.reset();
  transport.reset();
  deps.reset();
  sync.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientConnectionProtocolTests, MessageSizeEqualToReceiveBufferAccepted)
{
  // Boundary: message size exactly equals negotiated receive buffer size.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 8192, 8192, 0, 0);
  ASSERT_TRUE(setup.sync->wait_complete());

  const uint32_t bodySize = 8192 - ua::connection_protocol::headerSize;
  auto header = build_header({'M', 'S', 'G'}, 'F', 8192);
  std::vector<byte> body(bodySize, static_cast<byte>(0xCC));

  setup.transport->enqueue_read_exact(header);
  setup.transport->enqueue_read_exact(body);

  ASSERT_TRUE(setup.sync->wait_chunk());
  EXPECT_TRUE(setup.sync->chunkStatus.is_good());
  EXPECT_EQ(setup.sync->chunkData.size(), 8192u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientConnectionProtocolTests, MessageSizeOneGreaterThanReceiveBufferRejected)
{
  // Boundary: message size is one byte over negotiated buffer.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 8192, 8192, 0, 0);
  ASSERT_TRUE(setup.sync->wait_complete());

  auto header = build_header({'M', 'S', 'G'}, 'F', 8193);
  setup.transport->enqueue_read_exact(header);

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpMessageTooLarge);
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientConnectionProtocolTests, MessageSizeEqualToHeaderSizeIsRejected)
{
  // Message with size == header size (8) has no body - should be rejected.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto header = build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize);
  setup.transport->enqueue_read_exact(header);

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_TRUE(setup.sync->errorStatus.is_bad());
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-009: Unsupported message type after handshake
// =============================================================================

TEST(ClientConnectionProtocolTests, UnsupportedMessageTypeAfterHandshakeRejected)
{
  // Spec: Part 6, 7.1.2.2 - Unknown MessageType rejected.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto header = build_header({'X', 'Y', 'Z'}, 'F', 16);
  setup.transport->enqueue_read_exact(header);

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_TRUE(setup.sync->errorStatus.is_bad());
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Post-handshake OPN and CLO messages accepted
// =============================================================================

TEST(ClientConnectionProtocolTests, OpnMessageAfterHandshakeForwarded)
{
  // OPN (OpenSecureChannel) messages should be forwarded post-handshake.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  const uint32_t bodySize = 16;
  const uint32_t totalSize = ua::connection_protocol::headerSize + bodySize;
  auto header = build_header({'O', 'P', 'N'}, 'F', totalSize);
  std::vector<byte> body(bodySize, static_cast<byte>(0xDD));

  setup.transport->enqueue_read_exact(header);
  setup.transport->enqueue_read_exact(body);

  ASSERT_TRUE(setup.sync->wait_chunk());
  EXPECT_TRUE(setup.sync->chunkStatus.is_good());
  EXPECT_EQ(setup.sync->chunkData.size(), totalSize);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ClientConnectionProtocolTests, CloMessageAfterHandshakeForwarded)
{
  // CLO (CloseSecureChannel) messages should be forwarded post-handshake.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  const uint32_t bodySize = 16;
  const uint32_t totalSize = ua::connection_protocol::headerSize + bodySize;
  auto header = build_header({'C', 'L', 'O'}, 'F', totalSize);
  std::vector<byte> body(bodySize, static_cast<byte>(0xEE));

  setup.transport->enqueue_read_exact(header);
  setup.transport->enqueue_read_exact(body);

  ASSERT_TRUE(setup.sync->wait_chunk());
  EXPECT_TRUE(setup.sync->chunkStatus.is_good());
  EXPECT_EQ(setup.sync->chunkData.size(), totalSize);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Non-'F' reserved byte on post-handshake secure channel messages
// =============================================================================

TEST(ClientConnectionProtocolTests, ReservedByteNotFOnSecureChannelMessageIsForwarded)
{
  // Post-handshake MSG with reserved byte != 'F' should still be forwarded.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  const uint32_t bodySize = 16;
  const uint32_t totalSize = ua::connection_protocol::headerSize + bodySize;
  auto header = build_header({'M', 'S', 'G'}, 'C', totalSize);  // 'C' = intermediate chunk
  std::vector<byte> body(bodySize, static_cast<byte>(0xFF));

  setup.transport->enqueue_read_exact(header);
  setup.transport->enqueue_read_exact(body);

  ASSERT_TRUE(setup.sync->wait_chunk());
  EXPECT_TRUE(setup.sync->chunkStatus.is_good());
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Connection timeout during handshake
// =============================================================================

TEST(ClientConnectionProtocolTests, ConnectionTimeoutDuringHandshakeClosesConnection)
{
  // If ACK doesn't arrive within timeout, connection should be closed.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  auto transport = std::make_shared<FakeTransportConnection>();
  transport->stall_reads();

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Client,
    deps,
    transport,
    false,
    1s,  // Short timeout.
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [&](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        gotError = true;
        errorStatus = st;
      }
      cv.notify_one();
    },
    "opc.tcp://localhost:4840");

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 3s, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTimeout);
  EXPECT_TRUE(transport->wait_for_close(500ms));

  cp.reset();
  transport.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-001 #2: No other message sent before Hello
// =============================================================================

TEST(ClientConnectionProtocolTests, NoOtherMessageSentBeforeHello)
{
  // Spec: Part 6, 7.1.3 - First message sent shall be a Hello.
  // Verify no other message (e.g. OPN) is sent before the HEL.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_no_ack(tp.get_executor());

  // Wait for at least one write (the HEL).
  ASSERT_TRUE(setup.transport->wait_for_write_count(1, 500ms));

  auto writes = setup.transport->writes();
  // Only one write should exist at this point (the HEL). No OPN or other message before it.
  EXPECT_EQ(writes.size(), 1u);

  // That single write must be a HELF.
  ASSERT_GE(writes[0].size(), ua::connection_protocol::headerSize);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'H');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'L');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-004 #9: EndpointUrl exceeding 4096 bytes rejected
// =============================================================================

// @verifies CL-TCP-004
// @relation(CL-TCP-004, scope=function)
TEST(ClientConnectionProtocolTests, HelloEndpointUrlExceedingLimitRejected)
{
  // Spec: Part 6, 7.1.2.3 - EndpointUrl encoded length shall be less than 4096 bytes.
  // A URL exceeding this limit should be rejected or truncated by the client.
  boost::asio::thread_pool tp;
  std::string longUrl = "opc.tcp://localhost:4840/";
  longUrl.append(4100, 'x');  // Make URL well over 4096 bytes.

  auto setup = ClientSetup::create_with_ack(tp.get_executor(), longUrl);

  // The rejection is local: send_hello checks the length before it encodes anything, so the specific
  // status reaches the application and no HEL ever reaches the transport. Asserting both is what
  // separates this from a client that put the over-long URL on the wire and let the server object.
  ASSERT_TRUE(setup.sync->wait_error(500ms)) << "Client should reject EndpointUrl exceeding 4096 bytes";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
  EXPECT_FALSE(setup.sync->complete) << "the handshake must not complete on a rejected EndpointUrl";
  for (const auto& write : setup.transport->writes())
  {
    ASSERT_GE(write.size(), 4u);
    const bool isHello =
      write[0] == byte{'H'} && write[1] == byte{'E'} && write[2] == byte{'L'} && write[3] == byte{'F'};
    EXPECT_FALSE(isHello) << "the over-long EndpointUrl must be rejected locally, never sent";
  }
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The client keeps to the rule it sends under: the EndpointUrl's encoded value (its four-byte length plus
// its bytes) shall be less than 4096 bytes (Part 6 7.1.2.3). A 4092-byte URL (encoded 4096) is refused
// locally with no HEL written; the 4091-byte one is sent.
// @verifies AC-CL-TCP-004-02
TEST(ClientConnectionProtocolTests, AnEndpointUrlWhoseEncodedValueIs4096BytesIsRefusedLocally)
{
  const auto helloWritten = [](const std::shared_ptr<FakeTransportConnection>& transport)
  {
    for (const auto& write : transport->writes())
    {
      if (write.size() >= 4u && write[0] == byte{'H'} && write[1] == byte{'E'} && write[2] == byte{'L'} &&
          write[3] == byte{'F'})
        return true;
    }
    return false;
  };

  {
    boost::asio::thread_pool tp;
    std::string url = "opc.tcp://localhost:4840/";
    url.resize(4092, 'x');
    auto setup = ClientSetup::create_with_ack(tp.get_executor(), url);
    ASSERT_TRUE(setup.sync->wait_error(500ms)) << "a 4092-byte EndpointUrl (encoded 4096) must be refused";
    EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
    EXPECT_FALSE(helloWritten(setup.transport)) << "refused locally, never sent";
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
  {
    boost::asio::thread_pool tp;
    std::string url = "opc.tcp://localhost:4840/";
    url.resize(4091, 'x');
    auto setup = ClientSetup::create_with_ack(tp.get_executor(), url);
    ASSERT_TRUE(setup.transport->wait_for_write_count(1, 500ms));
    EXPECT_TRUE(helloWritten(setup.transport)) << "control: a 4091-byte EndpointUrl (encoded 4095) is sent";
    setup.release();
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

// =============================================================================
// CL-TCP-005 #11: Client rejects unsupported protocol version
// =============================================================================

// @verifies CL-TCP-005
// @relation(CL-TCP-005, scope=function)
// @relation(AC-CL-TCP-005-01, scope=function)
TEST(ClientConnectionProtocolTests, ClientRejectsUnsupportedProtocolVersion)
{
  // Spec: Part 6, 7.1.2.4 - If ACK protocol version is unsupported, client shall report error.
  // Currently the SDK accepts any version. This test documents expected behavior:
  // a high protocol version in ACK should either be accepted (downward compat) or rejected.
  boost::asio::thread_pool tp;
  // Use create_with_raw_response to send an ACK with a high protocol version.
  auto ack = build_ack(999, 65536, 65536, 0, 0);
  auto setup2 = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(ack));

  // The client should either reject (error) or accept (complete).
  bool completed = setup2.sync->wait_complete(500ms);
  bool errored = setup2.sync->wait_error(500ms);

  // Spec requires rejection of unsupported protocol versions.
  EXPECT_TRUE(errored) << "Client should reject unsupported protocol version 999";
  setup2.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-007 #13: Duplicate ACK received closes connection
// =============================================================================

// @verifies CL-TCP-007
// @relation(CL-TCP-007, scope=function)
TEST(ClientConnectionProtocolTests, DuplicateAckReceivedClosesConnection)
{
  // Spec: Part 6, 7.1.3 - Hello/Acknowledge may only be sent once.
  // If received again, the receiver shall report an error and close.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  // After successful handshake, inject a second ACK as if from the server.
  auto secondAck = build_ack(0, 65536, 65536, 0, 0);
  // ACK starts with 'A','C','K','F' - this is not a valid post-handshake message type.
  // The connection protocol should reject it as an unsupported message type.
  auto header = std::vector<byte>(secondAck.begin(), secondAck.begin() + ua::connection_protocol::headerSize);
  auto body = std::vector<byte>(secondAck.begin() + ua::connection_protocol::headerSize, secondAck.end());

  setup.transport->enqueue_read_exact(header);
  if (!body.empty())
  {
    setup.transport->enqueue_read_exact(body);
  }

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-013 #24: Error reason exceeding 4096 bytes ignored
// =============================================================================

// @verifies CL-TCP-013
// @relation(CL-TCP-013, scope=function)
TEST(ClientConnectionProtocolTests, ErrorReasonExceedingLimitIgnored)
{
  // Spec: Part 6, 7.1.2.5 - Reason string shall not be more than 4096 bytes.
  // Client shall IGNORE strings longer than this (not crash, and not surface the over-long reason).
  boost::asio::thread_pool tp;
  // Build an ERR frame with a 5000-char reason manually (build_err uses a small buffer).
  std::string longReason(5000, 'E');
  memory_stream_device::Dynamic streamDevice{8192, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid));
  String reasonStr{longReason};
  enc.encode(limit, reasonStr);
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto errBytes = streamDevice.move_storage_out();
  errBytes.resize(msgSize);

  auto setup = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(errBytes));

  // Client must not crash, must still surface the status code, and must IGNORE the over-long reason
  // (Part 6 section 7.1.2.5): a Reason exceeding 4096 bytes is dropped rather than echoed to the application.
  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpEndpointUrlInvalid);
  EXPECT_TRUE(setup.sync->errorReason.empty())
    << "an ERR Reason exceeding 4096 bytes must be ignored, not surfaced (got "
    << setup.sync->errorReason.size() << " bytes)";
  EXPECT_TRUE(setup.transport->wait_for_close(500ms));
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The ERR body is read synchronously, so the read is bounded by what an ERR can legally hold - the Error
// field, the Reason's length and 4096 Reason bytes - not by what the socket has buffered. A 20000-byte
// Reason is served from a 20008-byte body: at most 4104 bytes are read, the Reason is ignored and the
// Error kept. The client read the whole claimed body.
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-02-AN-ERR-BODY-READ-IS-BOUNDED
TEST(ClientConnectionProtocolTests, AnErrBodyReadIsBoundedByTheErrGrammar)
{
  boost::asio::thread_pool tp;
  std::string longReason(20000, 'E');
  memory_stream_device::Dynamic streamDevice{32768, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid));
  String reasonStr{longReason};
  enc.encode(limit, reasonStr);
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto errBytes = streamDevice.move_storage_out();
  errBytes.resize(msgSize);

  auto setup = ClientSetup::create_with_raw_response(tp.get_executor(), std::move(errBytes));
  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpEndpointUrlInvalid) << "the Error is kept";
  EXPECT_TRUE(setup.sync->errorReason.empty()) << "the over-long Reason is ignored";
  const auto reads = setup.transport->sync_read_sizes();
  ASSERT_FALSE(reads.empty());
  for (const auto size : reads)
  {
    EXPECT_LE(size, 4104u) << "the ERR body read must not exceed Error + Reason length + 4096 bytes";
  }
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

/// An ERR frame carrying `errorCode` and a Reason of `reasonLength` bytes.
static std::vector<byte> build_err_with_reason_length(uint32_t errorCode, size_t reasonLength)
{
  memory_stream_device::Dynamic streamDevice{reasonLength + 64, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'R'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, errorCode);
  enc.encode(limit, String{std::string(reasonLength, 'E')});
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto bytes = streamDevice.move_storage_out();
  bytes.resize(msgSize);
  return std::vector<byte>(bytes.begin(), bytes.end());
}

// The same bound on the ERR read after the handshake (the message phase reads the header asynchronously
// and the body synchronously): a 20000-byte Reason is read at most 4104 bytes at a time, the Reason is
// ignored and the Error kept.
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-02-AN-ERR-BODY-READ-IS-BOUNDED
TEST(ClientConnectionProtocolTests, AnErrBodyReadAfterTheHandshakeIsBoundedByTheErrGrammar)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  const auto errFrame =
    build_err_with_reason_length(static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid), 20000);
  setup.transport->enqueue_hello_message(errFrame);
  setup.transport->enqueue_read_exact(
    std::vector<byte>{errFrame.begin(), errFrame.begin() + ua::connection_protocol::headerSize});

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpEndpointUrlInvalid) << "the Error is kept";
  const auto reads = setup.transport->sync_read_sizes();
  ASSERT_FALSE(reads.empty());
  for (const auto size : reads)
  {
    EXPECT_LE(size, 4104u) << "the ERR body read must not exceed Error + Reason length + 4096 bytes";
  }
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-010: MaxMessageSize enforcement (send direction)
// =============================================================================

TEST(ClientConnectionProtocolTests, RequestWithinMaxMessageSizeSent)
{
  // Spec: Part 6, 7.1.2.4 - Requests within MaxMessageSize should be sent.
  boost::asio::thread_pool tp;
  // Server ACK with MaxMessageSize=65536.
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 65536, 65536, 65536, 0);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Send a small message chunk through the connection protocol.
  const uint32_t chunkSize = 100;
  std::vector<byte> chunk(chunkSize, static_cast<byte>(0x42));
  setup.cp->send_message_chunk(std::move(chunk));

  // Should succeed - wait for the write to appear.
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 500ms));  // 1=HEL, 2=our chunk
  auto writes = setup.transport->writes();
  EXPECT_EQ(writes.size(), 2u);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-010
// @relation(CL-TCP-010, scope=function)
TEST(ClientConnectionProtocolTests, RequestExceedingMaxMessageSizeReported)
{
  // Spec: Part 6, 7.1.2.4 - If a request Message exceeds MaxMessageSize,
  // client shall report an error to the application.
  // Assert the required behavior - the error callback should fire when enforcement
  // is implemented. This test will fail until MaxMessageSize send-path enforcement exists.
  boost::asio::thread_pool tp;
  // Server ACK with MaxMessageSize=100 (very small).
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 65536, 65536, 100, 0);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Send a chunk larger than MaxMessageSize.
  const uint32_t chunkSize = 200;
  std::vector<byte> chunk(chunkSize, static_cast<byte>(0x42));
  setup.cp->send_message_chunk(std::move(chunk));

  // The spec requires the client to report an error. Assert the error callback fires.
  EXPECT_TRUE(setup.sync->wait_error(500ms))
    << "Error callback should fire when message exceeds MaxMessageSize";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-014 #25: Fatal error handling - report and send CLO
// =============================================================================

namespace
{

/// What a SecureChannel that delegated its close (set_callbacks, delegateFatalClose) observed.
struct DelegatedCloseSync
{
  std::mutex mx;
  std::condition_variable cv;
  bool complete{false};
  int errorCount{0};
  StatusCode errorStatus{Status::Good};
  std::optional<FatalCloseDisposition> disposition;
  std::vector<StatusCode> closeObserved;  ///< every status the close observer received.

  bool wait_complete(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return complete; });
  }

  bool wait_error(std::chrono::milliseconds timeout = 2s)
  {
    std::unique_lock<std::mutex> lk(mx);
    return cv.wait_for(lk, timeout, [this]() { return errorCount > 0; });
  }

  int error_count()
  {
    std::lock_guard<std::mutex> lk(mx);
    return errorCount;
  }
};

/// A stand-in for the client SecureChannel's CloseSecureChannel chunk: the connection protocol forwards
/// chunks without looking inside them, so only its identity matters to these tests.
std::vector<byte> canned_close_chunk()
{
  auto chunk = build_header({'C', 'L', 'O'}, 'F', 24);
  chunk.resize(24, static_cast<byte>(0x5A));
  return chunk;
}

/// A client-role protocol whose error sink delegates the close (set_callbacks, delegateFatalClose), wired
/// after the handshake the way the SecureChannel wires it. On AwaitingClose, if @p answerWithClose, the sink
/// does what the SecureChannel does: submits its CloseSecureChannel chunk, then asks for the close.
struct DelegatingClientSetup
{
  std::shared_ptr<FakeConnectionProtocolDeps> deps;
  std::shared_ptr<FakeTransportConnection> transport;
  std::shared_ptr<DelegatedCloseSync> sync;
  std::shared_ptr<ConnectionProtocol> cp;

  void release()
  {
    cp.reset();
    transport.reset();
    deps.reset();
    sync.reset();
  }

  static DelegatingClientSetup create(boost::asio::any_io_executor ex, bool answerWithClose,
    std::chrono::milliseconds fatalCloseTimeout = ConnectionProtocol::defaultFatalCloseTimeout)
  {
    DelegatingClientSetup s;
    s.deps = std::make_shared<FakeConnectionProtocolDeps>(ex);
    s.transport = std::make_shared<FakeTransportConnection>();
    s.sync = std::make_shared<DelegatedCloseSync>();
    s.transport->enqueue_hello_message(build_ack(0, 65536, 65536, 0, 0));

    auto syncPtr = s.sync;
    auto record = [syncPtr](StatusCode status, std::optional<FatalCloseDisposition> disposition)
    {
      {
        std::lock_guard<std::mutex> lk(syncPtr->mx);
        ++syncPtr->errorCount;
        syncPtr->errorStatus = status;
        syncPtr->disposition = disposition;
      }
      syncPtr->cv.notify_all();
    };

    s.cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Client,
      s.deps,
      s.transport,
      false,
      60s,
      [syncPtr, record, answerWithClose](StatusCode,
        std::shared_ptr<ConnectionProtocol>
          cp,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        std::weak_ptr<ConnectionProtocol> weakCp = cp;
        cp->set_callbacks([](StatusCode, std::vector<byte>&&) {},
          [record, weakCp, answerWithClose](StatusCode status, string_view, FatalCloseDisposition disposition)
          {
            record(status, disposition);
            if (disposition != FatalCloseDisposition::AwaitingClose || !answerWithClose)
            {
              return;
            }
            if (auto locked = weakCp.lock())
            {
              locked->send_message_chunk(canned_close_chunk());
              locked->close_after_pending_writes();
            }
          },
          /*delegateFatalClose=*/true);
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->complete = true;
        }
        syncPtr->cv.notify_all();
      },
      [record](StatusCode status, string_view, ua::FatalCloseDisposition) { record(status, std::nullopt); },
      "opc.tcp://localhost:4840",
      /*endpointUrlValidator=*/{},
      /*messageReadTimeout=*/std::chrono::milliseconds{10'000},
      /*serverUri=*/{},
      /*reverseHelloValidator=*/{},
      /*closeObserver=*/
      [syncPtr](StatusCode status, string_view)
      {
        {
          std::lock_guard<std::mutex> lk(syncPtr->mx);
          syncPtr->closeObserved.push_back(status);
        }
        syncPtr->cv.notify_all();
      },
      fatalCloseTimeout);
    return s;
  }
};

}  // namespace

// @verifies CL-TCP-014
// @verifies AC-CL-TCP-014-01
// @relation(CL-TCP-014, scope=function)
// @relation(AC-CL-TCP-014-01, scope=function)
TEST(ClientConnectionProtocolTests, FatalErrorReportsToApplicationAndSendsCLO)
{
  // Spec: Part 6, 7.1.5 - Fatal error reports to application and sends CLO.
  // RATIFIED TEST ADAPTATION (group L, L-D6): the stimulus was a transport read error, a dead socket on
  // which no CloseSecureChannel can be sent; it asserted the bare 8-byte "CLOF" frame the protocol then
  // wrote, which is not a conformant CloseSecureChannel (Part 6 6.7.2.2-6.7.2.4 need the SecureChannelId,
  // TokenId and sequence header; Part 4 5.5.3.1 needs the current token's signature). The fatal error is
  // now one after which the socket is still writable (an invalid message type after the handshake), and
  // the CLO is the SecureChannel's, sent through the delegated sink. Still asserted: the error reaches the
  // application with its status, and a CLO is written before the socket closes - now also the order
  // (close only after the CLO's write completes) and that the error is reported exactly once. The dead
  // socket arm moved to DeadSocketAfterHandshakeWritesNoClo (AC-CL-TCP-014-02).
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ true);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Hold write completions so the CLO stays pending until the test releases it.
  setup.transport->hold_writes();
  setup.transport->enqueue_read_exact(build_header({'X', 'Y', 'Z'}, 'F', 16));

  ASSERT_TRUE(setup.sync->wait_error());
  // The error should be reported to the application.
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpMessageTypeInvalid);
  EXPECT_EQ(setup.sync->disposition, FatalCloseDisposition::AwaitingClose)
    << "a writable transport must be left for the SecureChannel's CloseSecureChannel";

  // Writes: [0]=HEL, [1]=CLO.
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s)) << "the CLO must be the next write";
  auto writes = setup.transport->writes();
  ASSERT_EQ(writes.size(), 2u);
  EXPECT_EQ(writes[1], canned_close_chunk()) << "the SecureChannel's CLO chunk is written unchanged";

  EXPECT_FALSE(setup.transport->wait_for_close(200ms))
    << "the socket must not close while the CLO is still being written";
  setup.transport->complete_held_writes();
  ASSERT_TRUE(setup.transport->wait_for_close(2s)) << "the socket must close once the CLO is written";
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{2u})
    << "the CLO is written before the socket closes";
  EXPECT_EQ(setup.transport->writes().size(), 2u) << "nothing follows the CLO";
  EXPECT_EQ(setup.sync->error_count(), 1) << "the fatal error is reported exactly once";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 7.1.4 / 7.1.5: a dead socket (a read error after the handshake) cannot carry a CloseSecureChannel.
// The error is reported once, as TransportClosed, the socket is closed and nothing follows the HEL, even
// though the sink would send a CLO if the protocol offered it. Falsifiable: a protocol that wrote a CLO
// (bare or delegated) on a dead socket leaves a second write.
// @verifies AC-CL-TCP-014-02
// @relation(AC-CL-TCP-014-02, scope=function)
TEST(ClientConnectionProtocolTests, DeadSocketAfterHandshakeWritesNoClo)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ true);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->enqueue_read_error(Status::BadCommunicationError, "connection reset");

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadCommunicationError);
  EXPECT_EQ(setup.sync->disposition, FatalCloseDisposition::TransportClosed);
  ASSERT_TRUE(setup.transport->wait_for_close(2s));
  EXPECT_FALSE(setup.transport->wait_for_write_count(2, 200ms)) << "no CLO may follow a dead socket";
  EXPECT_EQ(setup.transport->writes().size(), 1u) << "only the HEL was written";
  EXPECT_EQ(setup.sync->error_count(), 1);

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 7.1.5 / 6.7.2: before an OpenSecureChannel has succeeded there is no SecureChannelId or token,
// so no conformant CloseSecureChannel exists. A failure during the handshake (the server answers the HEL
// with ERR) is reported and closes the socket with nothing written after the HEL. Falsifiable: the bare
// "CLOF" frame the protocol used to write here is a second write.
// @verifies AC-CL-TCP-014-02
// @relation(AC-CL-TCP-014-02, scope=function)
TEST(ClientConnectionProtocolTests, HandshakeFailureWritesNothingAfterHello)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_err(
    tp.get_executor(), StatusCode{Status::BadTcpServerTooBusy}.as_uint32(), "busy");

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->errorStatus, Status::BadTcpServerTooBusy);
  ASSERT_TRUE(setup.transport->wait_for_close(2s));
  EXPECT_FALSE(setup.transport->wait_for_write_count(2, 200ms))
    << "no CLO exists before a SecureChannel is open";
  EXPECT_EQ(setup.transport->writes().size(), 1u) << "only the HEL was written";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The fallback timer: a SecureChannel that never answers AwaitingClose (destroyed before its CLO is
// encoded, or failing to encode it) does not keep the socket open. The protocol closes the transport
// itself once fatalCloseTimeout has elapsed, writing nothing. Falsifiable: without the timer the socket
// stays open indefinitely.
// @verifies AC-CL-TCP-014-01
// @relation(AC-CL-TCP-014-01, scope=function)
TEST(ClientConnectionProtocolTests, FatalCloseFallbackTimerClosesWhenTheChannelNeverAnswers)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false, 500ms);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->enqueue_read_exact(build_header({'X', 'Y', 'Z'}, 'F', 16));

  ASSERT_TRUE(setup.sync->wait_error());
  EXPECT_EQ(setup.sync->disposition, FatalCloseDisposition::AwaitingClose);
  EXPECT_FALSE(setup.transport->closed()) << "the socket stays open for the channel's CLO at first";
  ASSERT_TRUE(setup.transport->wait_for_close(3s)) << "the fallback timer must close the socket";
  EXPECT_EQ(setup.transport->writes().size(), 1u) << "the protocol writes no CLO of its own";
  EXPECT_EQ(setup.sync->error_count(), 1) << "the timer closes without reporting again";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The fallback timer also bounds a CloseSecureChannel whose write never completes (a peer that stopped
// reading): the channel answered and asked for the close after its writes, but the write stays pending,
// so the timer closes the transport. Falsifiable: without the timer the close waits for the write forever.
// @verifies AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED
TEST(ClientConnectionProtocolTests, FatalCloseFallbackTimerClosesWhenTheCloseRequestIsNeverWritten)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ true, 500ms);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->hold_writes();
  setup.transport->enqueue_read_exact(build_header({'X', 'Y', 'Z'}, 'F', 16));

  ASSERT_TRUE(setup.sync->wait_error());
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s)) << "the CLO is queued";
  ASSERT_TRUE(setup.transport->wait_for_close(3s)) << "the fallback timer must close the socket";
  EXPECT_EQ(setup.sync->error_count(), 1) << "the fatal error is reported once";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The same bound for an error the SecureChannel detects itself (review finding on owner decision 2): the
// channel begins the fatal close before it encodes its CloseSecureChannel; if the encode never completes
// (a crypto provider that does not answer), the fallback timer closes the transport. Falsifiable: without
// begin_close_after_channel_error the transport stays open and reading.
// @verifies AC-CL-TCP-014-04-A-CHANNEL-DETECTED-ERROR-IS-BOUNDED
TEST(ClientConnectionProtocolTests, AChannelDetectedErrorIsBoundedByTheFallbackTimer)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false, 500ms);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.cp->begin_close_after_channel_error();

  ASSERT_TRUE(setup.transport->wait_for_close(3s)) << "the fallback timer must close the socket";
  EXPECT_EQ(setup.transport->writes().size(), 1u) << "the protocol writes nothing of its own";
  EXPECT_EQ(setup.sync->error_count(), 0) << "the channel reported the error; the protocol does not";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// close_async(CloseMode::AfterPendingWrites): the transport closes only once every chunk already
// submitted has been written, so a final message is not cut off - the server's ApplyChanges response on
// the channel the change closes (OPC 10000-12 7.10.6). The mode is role-independent; the client setup is
// the harness with a completed handshake. Falsifiable: an Immediate close (BR-14) closes while the chunk's
// write is still pending.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ConnectionProtocolCloseAfterWrites, TheTransportClosesOnlyAfterTheSubmittedChunkIsWritten)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->hold_writes();
  setup.cp->send_message_chunk(canned_close_chunk());
  setup.cp->close_async({}, TransportConnection::CloseMode::AfterPendingWrites);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s)) << "the chunk is written";
  EXPECT_FALSE(setup.transport->wait_for_close(200ms)) << "the close waits for the chunk's write";
  EXPECT_EQ(setup.transport->close_after_writes_count(), 1u);
  setup.transport->complete_held_writes();
  ASSERT_TRUE(setup.transport->wait_for_close(2s)) << "the transport closes once the chunk is written";
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{2u})
    << "the chunk is written before the transport closes";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The wait is bounded: a chunk whose write never completes (a peer that stopped reading) does not keep the
// transport open - the fallback timer closes it. Falsifiable: without the timer the close waits forever.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ConnectionProtocolCloseAfterWrites, TheFallbackTimerBoundsTheWaitForAWriteThatNeverCompletes)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false, 500ms);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->hold_writes();
  setup.cp->send_message_chunk(canned_close_chunk());
  setup.cp->close_async({}, TransportConnection::CloseMode::AfterPendingWrites);

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s));
  ASSERT_TRUE(setup.transport->wait_for_close(3s)) << "the fallback timer must close the transport";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The read a close after pending writes aborts (a real socket completes it with operation_aborted) is that
// close, not a connection failure: no fatal error is reported and no Error message is written while the
// response is still being written. Falsifiable: treating it as a failure tears the channel down and closes
// at once, cutting off the response (found end to end by GdsPushScenarios).
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ConnectionProtocolCloseAfterWrites, TheReadItsCloseAbortsIsNotAFailure)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->hold_writes();
  setup.cp->send_message_chunk(canned_close_chunk());
  setup.cp->close_async({}, TransportConnection::CloseMode::AfterPendingWrites);
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s));
  setup.transport->enqueue_read_error(StatusCode{Status::BadTcpInternalError}, "Operation canceled");

  std::this_thread::sleep_for(200ms);
  EXPECT_EQ(setup.sync->error_count(), 0) << "the aborted read is not reported as a failure";
  EXPECT_EQ(setup.transport->writes().size(), 2u) << "no Error message follows the response";
  setup.transport->complete_held_writes();
  ASSERT_TRUE(setup.transport->wait_for_close(2s)) << "the close completes after the response is written";
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{2u});
  ASSERT_TRUE(setup.sync->wait_error()) << "the close completion reports the close";
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(setup.sync->error_count(), 1) << "reported once, by the close completion";
  {
    const std::lock_guard<std::mutex> lk(setup.sync->mx);
    EXPECT_EQ(
      setup.sync->disposition, std::optional<FatalCloseDisposition>{FatalCloseDisposition::TransportClosed});
  }

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A close after writes that meets a fatal close already in progress reports the fatal close's status, not
// an orderly BadShutdown: the observer learns why the connection really ended. Falsifiable: a report that
// always names BadShutdown.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ConnectionProtocolCloseAfterWrites, AFatalCloseInProgressKeepsItsStatusForTheCloseObserver)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false, 10s);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.cp->begin_close_after_channel_error();  // BadSecureChannelClosed; the transport is still open
  setup.cp->close_async({}, TransportConnection::CloseMode::AfterPendingWrites);

  ASSERT_TRUE(setup.transport->wait_for_close(2s)) << "nothing is pending, so the transport closes at once";
  {
    std::unique_lock<std::mutex> lk(setup.sync->mx);
    ASSERT_TRUE(setup.sync->cv.wait_for(lk, 2s, [&] { return !setup.sync->closeObserved.empty(); }));
    EXPECT_EQ(setup.sync->closeObserved.front(), StatusCode{Status::BadSecureChannelClosed});
  }
  std::this_thread::sleep_for(200ms);
  {
    const std::lock_guard<std::mutex> lk(setup.sync->mx);
    EXPECT_EQ(setup.sync->closeObserved.size(), 1u) << "the close is reported once";
  }

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The protocol owns the transport, and a transport's write handlers do not own it: the caller may drop
// its reference straight after asking for the close, and the close still completes after the write.
// Falsifiable: a protocol that does not keep itself alive is destroyed with its transport before the
// pending write completes, so the transport never reports the close after it.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST(ConnectionProtocolCloseAfterWrites, TheProtocolOutlivesItsCallerUntilTheTransportHasClosed)
{
  boost::asio::thread_pool tp;
  auto setup = DelegatingClientSetup::create(tp.get_executor(), /*answerWithClose*/ false);
  ASSERT_TRUE(setup.sync->wait_complete());

  setup.transport->hold_writes();
  auto closed = std::make_shared<std::promise<VoidResult>>();
  setup.cp->send_message_chunk(canned_close_chunk());
  setup.cp->close_async([closed](VoidResult result) { closed->set_value(std::move(result)); },
    TransportConnection::CloseMode::AfterPendingWrites);
  std::weak_ptr<ConnectionProtocol> weakCp = setup.cp;
  setup.cp.reset();

  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 2s));
  EXPECT_FALSE(weakCp.expired()) << "the protocol keeps itself alive while the write is pending";
  setup.transport->complete_held_writes();
  auto future = closed->get_future();
  ASSERT_EQ(future.wait_for(2s), std::future_status::ready) << "the close completes after the write";
  EXPECT_TRUE(future.get().is_good());
  EXPECT_EQ(setup.transport->writes_at_first_close(), std::optional<size_t>{2u});

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-002 #ECC: Hello ReceiveBufferSize meets ECC minimum (1024)
// =============================================================================

TEST(ClientConnectionProtocolTests, HelloReceiveBufferMeetsEccMinimum)
{
  // Spec: Part 6, 7.1.2.3 - ReceiveBufferSize shall be at least 1024 bytes
  // "if the sender intends to use an ECC SecurityPolicy."
  // The ECC minimum is unconditionally satisfied by the default buffer size.
  // The security policy is not yet known at Hello time - the client advertises
  // buffers that satisfy both ECC (>= 1024) and non-ECC (>= 8192) minimums.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  auto hel = parse_hello(writes[0]);
  EXPECT_GE(hel.receiveBufferSize, ua::connection_protocol::eccMinBufferSize);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-003 #ECC: Hello SendBufferSize meets ECC minimum (1024)
// =============================================================================

TEST(ClientConnectionProtocolTests, HelloSendBufferMeetsEccMinimum)
{
  // Spec: Part 6, 7.1.2.3 - SendBufferSize shall be at least 1024 bytes
  // "if the sender intends to use an ECC SecurityPolicy."
  // The ECC minimum is unconditionally satisfied by the default buffer size.
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_with_ack(tp.get_executor());
  ASSERT_TRUE(setup.sync->wait_complete());

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);

  auto hel = parse_hello(writes[0]);
  EXPECT_GE(hel.sendBufferSize, ua::connection_protocol::eccMinBufferSize);
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-010 #abort: Oversized request aborts after partial chunks
// =============================================================================

TEST(ClientConnectionProtocolTests, OversizedRequestAbortsAfterPartialChunks)
{
  // Spec: Part 6, 6.7.3 - If a request exceeds MaxMessageSize during chunking,
  // client shall send an abort chunk after already-sent intermediate chunks.
  // Assert the required behavior - the error callback should fire when enforcement
  // is implemented. This test will fail until abort-on-oversize is implemented.
  boost::asio::thread_pool tp;
  // Server ACK with very small MaxMessageSize (200 bytes).
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 65536, 65536, 200, 0);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Send a chunk larger than MaxMessageSize to trigger abort behavior.
  const uint32_t chunkSize = 300;
  std::vector<byte> chunk(chunkSize, static_cast<byte>(0x42));
  setup.cp->send_message_chunk(std::move(chunk));

  // The spec requires an abort chunk and error report. Assert the error callback fires.
  EXPECT_TRUE(setup.sync->wait_error(500ms))
    << "Error callback should fire when request exceeds MaxMessageSize during chunking";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-011: Request within MaxChunkCount sent successfully
// =============================================================================

TEST(ClientConnectionProtocolTests, RequestWithinMaxChunkCountSent)
{
  // Spec: Part 6, 7.1.2.4 - Requests within MaxChunkCount should be sent.
  boost::asio::thread_pool tp;
  // Server ACK with MaxChunkCount=10 - plenty of room for a small message.
  auto setup =
    ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 65536, 65536, 0, 10);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Send a small message chunk.
  const uint32_t chunkSize = 100;
  std::vector<byte> chunk(chunkSize, static_cast<byte>(0x42));
  setup.cp->send_message_chunk(std::move(chunk));

  // Wait for the write to appear (1=HEL, 2=our chunk).
  ASSERT_TRUE(setup.transport->wait_for_write_count(2, 500ms));
  auto writes = setup.transport->writes();
  EXPECT_GE(writes.size(), 2u) << "Small message within MaxChunkCount should be sent";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-TCP-011 #exceed: Request exceeding MaxChunkCount aborted
// =============================================================================

TEST(ClientConnectionProtocolTests, RequestExceedingMaxChunkCountAborted)
{
  // Spec: Part 6, 7.1.2.4 - Requests exceeding MaxChunkCount should be aborted.
  boost::asio::thread_pool tp;
  // Server ACK with MaxChunkCount=1 and small recv buffer to force multi-chunk.
  // Server recv=8192 (minimum valid), client send clamped to min(65536, 8192) = 8192.
  auto setup = ClientSetup::create_with_ack(tp.get_executor(), "opc.tcp://localhost:4840", 8192, 8192, 0, 1);
  ASSERT_TRUE(setup.sync->wait_complete());

  // Send a message that would require more than 1 chunk at the negotiated buffer size.
  // Negotiated send buffer = min(client=65536, server_recv=8192) = 8192.
  // A 20000-byte message would need >1 chunk at 8192-byte chunk size.
  const uint32_t chunkSize = 20000;
  std::vector<byte> chunk(chunkSize, static_cast<byte>(0x42));
  setup.cp->send_message_chunk(std::move(chunk));

  // Wait for either an abort or a timeout. If enforcement works, writes appear.
  setup.transport->wait_for_write_count(2, 500ms);

  auto writes = setup.transport->writes();
  // The request should be blocked or aborted - not fully sent as multiple chunks.
  // Count writes after HEL. If MaxChunkCount enforcement works, there should be
  // at most 1 data chunk (possibly an abort), not 2+ full chunks.
  size_t dataChunks = 0;
  for (size_t i = 1; i < writes.size(); ++i)
  {
    if (writes[i].size() >= 4 && static_cast<char>(writes[i][3]) != 'A')
    {
      ++dataChunks;
    }
  }
  EXPECT_LE(dataChunks, 1u) << "Request exceeding MaxChunkCount should be aborted, not fully sent";
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------------------------------
// Reverse-connect (server-initiated TCP) handshake - the ConnectionProtocol Client + reverseConnect path.
// The encode/decode of the RHE frame is unit-tested in tests/unit/transport/reverse_hello_tests.cpp and
// the listener lifecycle in tests/unit/client/reverse_connect_listener_tests.cpp; the tests below cover the
// distinct layer between them: how the ConnectionProtocol state machine reacts to the RHE on the wire.
// Part 6 section 7.1.3 / section 7.1.2.6.
// ---------------------------------------------------------------------------------------------------

// @verifies CL-RC-001
// Part 6 section 7.1.3: on a server-initiated (reverse-connect) socket the FIRST OPC UA message the client
// expects is a ReverseHello (RHE). Any other first-message type is a protocol violation and the client
// must close the connection. Drive a server that (incorrectly) begins with a Hello header.
// Falsifiable: a client that did not enforce RHE-first would not raise BadTcpMessageTypeInvalid.
// @relation(CL-RC-001, scope=function)
TEST(ClientConnectionProtocolReverseTests, FirstListenerMessageMustBeReverseHello)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_header({'H', 'E', 'L'}, 'F', ua::connection_protocol::headerSize)},
    [](const ua::detail::ReverseHelloMessage&) { return true; });

  ASSERT_TRUE(setup.sync->wait_error(1000ms)) << "a non-RHE first message must fire the error callback";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpMessageTypeInvalid});
  EXPECT_FALSE(setup.sync->complete) << "the connection must not complete on a bad first message";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-RC-002
// Part 6 section 7.1.3: "If the Client accepts the connection, it sends a Hello message back to the Server
// which starts the buffer negotiation." After a valid RHE the client must reply with a HEL and then complete
// the normal buffer negotiation on receipt of the ACK. Falsifiable: a client that did not answer with a Hello
// would produce no write and never complete.
// @relation(CL-RC-002, scope=function)
TEST(ClientConnectionProtocolReverseTests, ReverseHelloIsAnsweredWithHello)
{
  boost::asio::thread_pool tp;
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_rhe("urn:test:server", "opc.tcp://server:4840/path"), build_ack(0, 65536, 65536, 0, 0)},
    [](const ua::detail::ReverseHelloMessage&) { return true; });

  ASSERT_TRUE(setup.sync->wait_complete(1000ms))
    << "a valid RHE followed by an ACK must complete the handshake";
  EXPECT_EQ(setup.sync->completeStatus, StatusCode{Status::Good});

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u) << "the client must send a Hello in reply to the RHE";
  ASSERT_GE(writes[0].size(), 4u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'H');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'L');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F') << "the reply must be a HELF (Hello) message";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-016
// Part 6 section 7.1.2.6 line 4447: the EndpointUrl carried in the ReverseHello "shall be passed back to the
// Server in the Hello Message." Assert the HEL the client sends echoes the RHE's EndpointUrl verbatim.
// Falsifiable: a client that sent its own (empty/configured) EndpointUrl instead would mismatch.
// @relation(CL-TCP-016, scope=function)
TEST(ClientConnectionProtocolReverseTests, ReverseHelloEndpointUrlEchoedInHello)
{
  boost::asio::thread_pool tp;
  const std::string endpointUrl = "opc.tcp://server.example:4840/UA/echoed";
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_rhe("urn:test:server", endpointUrl), build_ack(0, 65536, 65536, 0, 0)},
    [](const ua::detail::ReverseHelloMessage&) { return true; });

  ASSERT_TRUE(setup.sync->wait_complete(1000ms));
  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);
  auto hel = parse_hello(writes[0]);
  EXPECT_EQ(hel.endpointUrl, endpointUrl)
    << "the Hello must carry the EndpointUrl received in the ReverseHello, not a locally-configured one";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-015
// Part 6 section 7.1.2.6 lines 4444-4445: the client "shall return a Bad_TcpEndpointUrlInvalid error and
// close the connection if the length [of the ServerUri] exceeds 4096". Deliver an RHE whose ServerUri exceeds
// maxUrlSize (4097 bytes, so the total frame at ~4134B still clears the maxReverseHelloSize=8208 cap and is
// not masked by the too-large guard). The length check inside decode_reverse_hello's validate step rejects
// BEFORE mReverseHelloValidator is consulted; the accepting validator here confirms the rejection is on
// length grounds, not recognition. (This exercises "exceeds 4096"; it does not probe the exact-4096
// boundary.) Falsifiable: a client without the length check would (validator accepting) proceed to send its
// Hello.
// @relation(CL-TCP-015, scope=function)
TEST(ClientConnectionProtocolReverseTests, ReverseHelloOversizedServerUriRejected)
{
  boost::asio::thread_pool tp;
  const std::string oversizedServerUri(ua::connection_protocol::maxUrlSize + 1, 'u');
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_rhe(oversizedServerUri, "opc.tcp://server:4840")},
    [](const ua::detail::ReverseHelloMessage&) { return true; });

  ASSERT_TRUE(setup.sync->wait_error(1000ms)) << "an oversized ServerUri must fire the error callback";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
  EXPECT_FALSE(setup.sync->complete);
  // The client may send a CLO frame before disconnecting (Part 6 7.1.5), but it must reject the RHE at
  // validation and never proceed to the Hello step - so no HELF may appear among the writes.
  for (const auto& write : setup.transport->writes())
  {
    ASSERT_GE(write.size(), 4u);
    const bool isHello =
      write[0] == byte{'H'} && write[1] == byte{'E'} && write[2] == byte{'L'} && write[3] == byte{'F'};
    EXPECT_FALSE(isHello) << "the client must not send a Hello for a ReverseHello it rejects on length";
  }

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-015
// Part 6 section 7.1.2.6 lines 4444-4445: the client "shall return a Bad_TcpEndpointUrlInvalid error and
// close the connection if ... it does not recognize the Server identified by the URI." A well-formed RHE
// whose ServerUri is not recognised (the validator returns false) must be rejected with
// Bad_TcpEndpointUrlInvalid. The validator is verified to have been consulted with the decoded ServerUri (not
// merely present). Falsifiable: a client that ignored the validator's verdict would proceed and complete.
// @relation(CL-TCP-015, scope=function)
TEST(ClientConnectionProtocolReverseTests, ReverseHelloUnrecognizedServerRejected)
{
  boost::asio::thread_pool tp;
  std::mutex seenMx;
  std::string seenServerUri;
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_rhe("urn:unknown:server", "opc.tcp://server:4840")},
    [&](const ua::detail::ReverseHelloMessage& msg)
    {
      std::lock_guard<std::mutex> lk(seenMx);
      seenServerUri = msg.serverUri;
      return false;
    });

  ASSERT_TRUE(setup.sync->wait_error(1000ms)) << "an unrecognised ServerUri must fire the error callback";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
  EXPECT_FALSE(setup.sync->complete);
  {
    std::lock_guard<std::mutex> lk(seenMx);
    EXPECT_EQ(seenServerUri, "urn:unknown:server")
      << "the client must consult the validator with the decoded RHE ServerUri";
  }

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-RC-003
// Part 6 section 7.1.3 lines 4478-4481: an application accepting incoming connections "shall close any
// TransportConnection after a period of time if it does not receive a Hello or ReverseHello Message." Drive
// a reverse-connect client with a 1s deadline and a server that never sends anything; the client must close
// with Bad_Timeout rather than wait forever.
// Falsifiable: a client without an establishment deadline would hang and the error wait would time out.
// @relation(CL-RC-003, scope=function)
TEST(ClientConnectionProtocolReverseTests, ListenerConnectionTimesOutAwaitingReverseHello)
{
  boost::asio::thread_pool tp;
  // Nothing enqueued: the server never sends a ReverseHello.
  auto setup = ClientSetup::create_reverse(
    tp.get_executor(),
    {},
    [](const ua::detail::ReverseHelloMessage&) { return true; },
    std::chrono::seconds{1});

  ASSERT_TRUE(setup.sync->wait_error(3000ms)) << "the client must close a socket that never sends an RHE";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTimeout});
  EXPECT_FALSE(setup.sync->complete);

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-RC-004
// Part 6 section 7.1.3 lines 4477-4478: the Hello/Acknowledge (and by symmetry ReverseHello) may only be sent
// once; a repeat "shall report an error and close the TransportConnection." Once the client has accepted a
// valid RHE it moves to the Hello/Acknowledge negotiation and now expects an ACK; the enforcement mechanism
// is that on_acknowledge_received rejects any non-ACK frame (a repeat RHE included) with
// BadTcpMessageTypeInvalid. The test asserts the first RHE WAS accepted (a Hello was sent) before the second
// is rejected, distinguishing this from the first-message-invalid case (CL-RC-001).
// Falsifiable: a client that tolerated a duplicate RHE would keep awaiting the ACK and never raise the error.
// @relation(CL-RC-004, scope=function)
TEST(ClientConnectionProtocolReverseTests, DuplicateReverseHelloRejected)
{
  boost::asio::thread_pool tp;
  // A second RHE arrives where the ACK is expected (Hello/Acknowledge negotiation already begun).
  auto setup = ClientSetup::create_reverse(tp.get_executor(),
    {build_rhe("urn:test:server", "opc.tcp://server:4840"),
      build_rhe("urn:test:server", "opc.tcp://server:4840")},
    [](const ua::detail::ReverseHelloMessage&) { return true; });

  ASSERT_TRUE(setup.sync->wait_error(1000ms)) << "a second RHE on the same connection must fire the error";
  EXPECT_EQ(setup.sync->errorStatus, StatusCode{Status::BadTcpMessageTypeInvalid});
  EXPECT_FALSE(setup.sync->complete);

  auto writes = setup.transport->writes();
  ASSERT_GE(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F')
    << "the first (valid) RHE must have been accepted: the client had already sent its Hello";

  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
