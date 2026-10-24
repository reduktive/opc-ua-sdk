// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <array>

#include "test_utilities.h"
#include <atomic>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>
#include "ua_error_detail.h"
#include "ua_connection_protocol.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_reverse_hello.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"
#include "ua_status_to_string.h"

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

struct Ack
{
  uint32_t messageSize{0};
  uint32_t protocolVersion{0};
  uint32_t receiveBufferSize{0};
  uint32_t sendBufferSize{0};
  uint32_t maxMessageSize{0};
  uint32_t maxChunkCount{0};
};

static std::vector<byte> build_hello(uint32_t protocolVersion, uint32_t recvBuf, uint32_t sendBuf,
  uint32_t maxMsg, uint32_t maxChunks, std::string endpointUrl)
{
  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::maxUrlSize + 128, true};
  MemoryStream stream{streamDevice};

  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};

  // HELF
  enc.encode(limit, uint8_t{'H'});
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'L'});
  enc.encode(limit, uint8_t{'F'});

  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});

  enc.encode(limit, protocolVersion);
  enc.encode(limit, recvBuf);
  enc.encode(limit, sendBuf);
  enc.encode(limit, maxMsg);
  enc.encode(limit, maxChunks);
  enc.encode(limit, endpointUrl);

  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);

  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

static Ack parse_ack(span<const byte> bytes)
{
  memory_stream_device::ExternalReadOnly streamDevice{bytes};
  MemoryStream stream{streamDevice};
  StructureFactory structureFactory;
  EncodingLimits limits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(structureFactory.resolver(), stream, limits);
  auto depth = limits.stack_depth();

  uint8_t a{0}, c{0}, k{0}, f{0};
  dec.decode(depth, a);
  dec.decode(depth, c);
  dec.decode(depth, k);
  dec.decode(depth, f);
  if (a != 'A' || c != 'C' || k != 'K' || f != 'F')
  {
    throw UaException{
      Status::BadDecodingError, make_error_detail("TestError", "Not an ACKF message", "Test")};
  }

  Ack ack;
  dec.decode(depth, ack.messageSize);
  dec.decode(depth, ack.protocolVersion);
  dec.decode(depth, ack.receiveBufferSize);
  dec.decode(depth, ack.sendBufferSize);
  dec.decode(depth, ack.maxMessageSize);
  dec.decode(depth, ack.maxChunkCount);
  return ack;
}

static std::vector<byte> build_header(std::array<char, 3> type, char reserved, uint32_t messageSize)
{
  std::vector<byte> out;
  out.resize(ua::connection_protocol::headerSize);
  out[0] = static_cast<byte>(type[0]);
  out[1] = static_cast<byte>(type[1]);
  out[2] = static_cast<byte>(type[2]);
  out[3] = static_cast<byte>(reserved);

  // MessageSize (UInt32 little-endian)
  out[4] = static_cast<byte>(messageSize & 0xFF);
  out[5] = static_cast<byte>((messageSize >> 8) & 0xFF);
  out[6] = static_cast<byte>((messageSize >> 16) & 0xFF);
  out[7] = static_cast<byte>((messageSize >> 24) & 0xFF);
  return out;
}

}  // namespace

// Part 6 7.1.2.3 Table 66: a Server that supports the requested version "or a lower version" returns the
// version it will use. Version 0 is lower than any requested version, so a Hello naming version 1 is
// acknowledged with version 0 rather than refused, and the requested version is kept for the
// OpenSecureChannel check of 6.7.4. RATIFIED CHANGE (group L): this arm asserted an ERR with
// Bad_TcpMessageTypeInvalid, the defect D-CAMPAIGN-TCP-PROTOCOLVERSION.
// @verifies AC-SVR-TCP-003-NEGOTIATES-DOWN
TEST(ConnectionProtocolTests, HelloNamingAHigherProtocolVersionIsAcknowledgedWithVersionZero)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(1, 8192, 8192, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  bool completed{false};
  StatusCode completionStatus{Status::Good};
  ua::connection_protocol::NegotiatedLimits negotiated;
  bool gotError{false};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits limits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        completed = true;
        completionStatus = st;
        negotiated = limits;
      }
      cv.notify_one();
    },
    [&](StatusCode, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        gotError = true;
      }
      cv.notify_one();
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return completed || gotError; }));
  }
  EXPECT_FALSE(gotError) << "a higher requested version is negotiated down, not refused";
  EXPECT_TRUE(completionStatus.is_good());
  EXPECT_EQ(negotiated.helloProtocolVersion, 1u) << "the requested version is kept for the OPN check";

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  const auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  const auto ack = parse_ack(writes.front());
  EXPECT_EQ(ack.protocolVersion, 0u) << "the Acknowledge names the version the server will use";
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_FALSE(transport->closed());

  cp.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, NonPositiveTimeoutDoesNotArmDeadlineTimerOrRaceConstruction)
{
  // Regression: a non-positive handshake timeout must NOT arm a zero-delay deadline timer.
  // Such a timer fires on the io thread the instant it is armed - while create()/initialise()
  // is still executing on *this* (the calling) thread - and its notifier touches the
  // half-constructed ConnectionProtocol, racing construction. On CI this surfaced as an
  // intermittent SIGSEGV under clang (null mHandshakeFlow deref in initialise). Production
  // config validation forbids a non-positive ConnectionProtocolTimeout, so the guard lives in
  // initialise(). The loop + already-running thread_pool exposes the race window deterministically;
  // without the guard this test crashes or trips the EXPECT_FALSE below.
  for (int i = 0; i < 100; ++i)
  {
    boost::asio::thread_pool tp;  // worker thread is already running the io_context
    auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
    deps->set_server_limits(ua::connection_protocol::Limits{});

    auto transport = std::make_shared<FakeTransportConnection>();
    transport->stall_reads();  // isolate the deadline-timer path: no progress via reads

    std::atomic<bool> gotError{false};

    auto cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      transport,
      false,
      /*timeout*/ std::chrono::seconds{0},
      [](StatusCode,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>) {},
      [&](StatusCode, string_view, ua::FatalCloseDisposition) { gotError.store(true); });

    // A disabled deadline timer must never fire BadTimeout into the error callback.
    std::this_thread::sleep_for(2ms);
    EXPECT_FALSE(gotError.load());

    (void)cp;
    ::ua::test_utils::drain_with_timeout(tp);
  }
}

namespace
{
/// Captures log entries (message + string field values) so a test can assert on what the
/// ConnectionProtocol logged - in particular a swallowed "guarded async continuation" exception, which
/// `guarded` logs but does not otherwise surface.
class CapturingLogSink : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    std::string combined{entry.message};
    for (const auto& field : entry.fields)
    {
      if (const auto* text = std::get_if<std::string_view>(&field.value))
      {
        combined += ' ';
        combined += *text;
      }
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    mEntries.push_back({entry.level, std::move(combined)});
  }

  [[nodiscard]] bool has_error_containing(std::string_view needle) const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& entry : mEntries)
    {
      if (entry.level == ua::LogLevel::Error && entry.text.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }

private:
  struct Entry
  {
    ua::LogLevel level;
    std::string text;
  };

  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};
}  // namespace

// Regression (#19): ConnectionProtocol::close_async() with no callback (the defaulted fire-and-forget
// close) must not throw std::bad_function_call on the completion-owning post_borrowing's GONE path. That
// path runs when self was destroyed before the strand turn - the common case during an RST teardown /
// reconnect - and delivers `completion(goneResult)` unconditionally. A default-constructed (empty)
// std::function there throws bad_function_call, which `guarded` catches and logs as a swallowed "guarded
// async continuation" error (the close completion silently lost). The fix normalizes an empty callback to
// a no-op. Here the gone path is driven deterministically: post the close, destroy the CP, THEN run the
// io_context so weak_from_this() has expired by the time the continuation runs.
TEST(ConnectionProtocolTests, CloseAsyncWithNoCallbackDoesNotThrowOnGonePath)
{
  boost::asio::io_context io;  // manually driven so we control when the posted close continuation runs
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(io.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto sink = std::make_shared<CapturingLogSink>();
  deps->set_logger(
    ua::Logger{sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->stall_reads();  // no read progress; isolate the close path

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    /*timeout*/ std::chrono::seconds{0},  // disable the deadline timer (no stray strand work to drain)
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  cp->close_async();  // no argument -> the empty std::function completion (fire-and-forget default)

  // Destroy the CP BEFORE running the io_context so the posted close continuation observes an expired
  // weak_from_this() and takes the GONE path - exactly the RST-teardown ordering that surfaced the bug.
  // (The CP holds no strong self-reference - every transport callback captures weak_from_this() - and the
  // FakeTransportConnection's registered read callback likewise holds only a weak ref, so cp.reset() truly
  // destroys it. If a fake ever regressed to a strong self-capture, this test would silently exercise the
  // alive path and pass vacuously.)
  cp.reset();

  io.run_for(2s);  // runs the posted close continuation against the now-dead CP (returns when drained)

  EXPECT_FALSE(sink->has_error_containing("guarded async continuation"))
    << "close_async() with no callback threw std::bad_function_call on the completion-owning gone path";
  EXPECT_FALSE(sink->has_error_containing("bad_function_call"));
}

// Positive control for the fix above: a NON-empty fire-and-forget callback must still be delivered exactly
// once on the same gone path (the completion-owning post_borrowing's contract). This pins that the
// normalization does not accidentally drop a real completion, and that the gone path fires it.
TEST(ConnectionProtocolTests, CloseAsyncDeliversRealCallbackOnceOnGonePath)
{
  boost::asio::io_context io;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(io.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->stall_reads();

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    /*timeout*/ std::chrono::seconds{0},
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  auto calls = std::make_shared<std::atomic<int>>(0);
  auto lastStatus = std::make_shared<std::atomic<uint32_t>>(0xFFFFFFFF);
  cp->close_async(
    [calls, lastStatus](VoidResult result)
    {
      lastStatus->store(result.status_code().as_uint32());
      calls->fetch_add(1);
    });

  cp.reset();  // gone path (self destroyed before the strand turn)
  io.run_for(2s);

  EXPECT_EQ(calls->load(), 1) << "the real close completion must fire exactly once on the gone path";
  EXPECT_EQ(lastStatus->load(), static_cast<uint32_t>(Status::Good))
    << "close on a dead CP is effectively closed -> Good";
}

// @relation(AC-SVR-TCP-010-URLLEN, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, HelloWithTooLongEndpointUrlErrorsAndCloses)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  // Queue the HEL bytes before creating `ConnectionProtocol` since it immediately starts reading.
  std::string url;
  url.resize(ua::connection_protocol::maxUrlSize + 1, 'a');
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, url));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  // Part 6 7.1.2.3 Table 66 names the status: Bad_TcpEndpointUrlInvalid (AC-SVR-TCP-010-URLLEN).
  EXPECT_EQ(errorStatus, Status::BadTcpEndpointUrlInvalid);

  // Server now sends an ERR frame before closing (Part 6 S7.1.5).
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-048-A-HEL-ENDPOINTURL-THE-SERVER-DOES, scope=function)

// @relation(AC-SVR-TCP-011-URLKNOWN, SVR-TCP-032, scope=function)
/// A HEL whose EndpointUrl length prefix claims more bytes than the frame holds: MessageSize is
/// consistent with the bytes sent, so the failure is discovered inside the body decode.
static std::vector<byte> build_hello_cut_short_inside_the_url()
{
  memory_stream_device::Dynamic streamDevice{256, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};
  enc.encode(limit, uint8_t{'H'});
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'L'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, uint32_t{0});  // ProtocolVersion
  enc.encode(limit, uint32_t{1024});  // ReceiveBufferSize
  enc.encode(limit, uint32_t{1024});  // SendBufferSize
  enc.encode(limit, uint32_t{0});  // MaxMessageSize
  enc.encode(limit, uint32_t{0});  // MaxChunkCount
  enc.encode(limit, int32_t{200});  // EndpointUrl length prefix ...
  for (char c : std::string_view{"opc.t"})  // ... but only five characters follow
  {
    enc.encode(limit, static_cast<uint8_t>(c));
  }
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

// A body that cannot be decoded is a protocol failure like any other: the error sink fires with a
// Bad status, the server answers with an ERR frame (Part 6 section 7.1.5) and closes.
// @relation(AC-SVR-UASC-064-TRUNCATED-HEL-BODY-IS-REPORTED, scope=function)
TEST(ConnectionProtocolTests, HelloCutShortInsideAFieldErrorsWithErrAndCloses)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});
  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello_cut_short_inside_the_url());

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }))
      << "a HEL cut short inside a field must reach the error sink, not only close the socket";
  }
  EXPECT_EQ(errorStatus, Status::BadDecodingError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms)) << "the server must answer with an ERR frame";
  auto writes = transport->writes();
  ASSERT_FALSE(writes.empty());
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(writes[0].data()), 4), "ERRF");
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, HelloWithUnrecognizedEndpointUrlErrorsAndCloses)
{
  // Requirement: P6-71-0009 (EndpointUrl recognition)

  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840/unknown"));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    {},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpEndpointUrlInvalid);

  // Server now sends an ERR frame before closing (Part 6 S7.1.5).
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-043-A-HEL-RECEIVEBUFFERSIZE-BELOW-THE-FLOOR, scope=function)
// @relation(AC-SVR-UASC-048-A-HEL-ENDPOINTURL-THE-SERVER-DOES, scope=function)

// @relation(AC-SVR-TCP-011-URLKNOWN, SVR-TCP-028, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, HelloWithRecognizedEndpointUrlWritesAck)
{
  // Requirement: P6-71-0009 (EndpointUrl recognition)

  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  bool gotComplete{false};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      EXPECT_TRUE(st.is_good());
      {
        std::lock_guard<std::mutex> lk(mx);
        gotComplete = true;
      }
      cv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) { FAIL() << "Unexpected error"; },
    {},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotComplete; }));
  }

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_NO_THROW((void)parse_ack(writes.front()));
  EXPECT_FALSE(transport->closed());

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-001-IGNORE, scope=function)
TEST(ConnectionProtocolTests, HelloWithReservedByteNotFIsAccepted)
{
  // The Connection Protocol layer does not validate the 4th byte (IsFinal/ChunkType)
  // for any message type, including HEL. The byte is passed through.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  // Build a HEL message but set the 4th byte to 'X' instead of 'F'.
  auto hel = build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840");
  ASSERT_GE(hel.size(), ua::connection_protocol::headerSize);
  hel[3] = static_cast<byte>('X');
  transport->enqueue_hello_message(std::move(hel));

  std::mutex mx;
  std::condition_variable cv;
  bool gotComplete{false};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      EXPECT_TRUE(st.is_good());
      {
        std::lock_guard<std::mutex> lk(mx);
        gotComplete = true;
      }
      cv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) { FAIL() << "Unexpected error"; });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotComplete; }));
  }

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_NO_THROW((void)parse_ack(writes.front()));
  EXPECT_FALSE(transport->closed());

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, HelloWithMessageSizeLessThanOrEqualToHeaderIsRejected)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  auto hel = build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840");
  ASSERT_GE(hel.size(), ua::connection_protocol::headerSize);

  // Set MessageSize to headerSize (invalid: no body).
  const uint32_t badSize = static_cast<uint32_t>(ua::connection_protocol::headerSize);
  hel[4] = static_cast<byte>(badSize & 0xFF);
  hel[5] = static_cast<byte>((badSize >> 8) & 0xFF);
  hel[6] = static_cast<byte>((badSize >> 16) & 0xFF);
  hel[7] = static_cast<byte>((badSize >> 24) & 0xFF);

  // HEL remainder must be empty to match the header's MessageSize.
  hel.resize(ua::connection_protocol::headerSize);
  transport->enqueue_hello_message(std::move(hel));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpInternalError);

  // Server now sends an ERR frame before closing (Part 6 S7.1.5).
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-043-A-HEL-RECEIVEBUFFERSIZE-BELOW-THE-FLOOR, scope=function)

// @relation(AC-SVR-TCP-005-MIN, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, HelloWithTooSmallReceiveBufferErrorsAndCloses)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  transport->enqueue_hello_message(build_hello(0, 1023, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);

  // Server now sends an ERR frame before closing (Part 6 S7.1.5).
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-043-A-HEL-RECEIVEBUFFERSIZE-BELOW-THE-FLOOR, scope=function)

// @relation(AC-SVR-TCP-006-MIN, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, HelloWithTooSmallSendBufferErrorsAndCloses)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  transport->enqueue_hello_message(build_hello(0, 1024, 1023, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);

  // Server now sends an ERR frame before closing (Part 6 S7.1.5).
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(static_cast<char>(writes[0][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[0][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[0][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-052-ACK-RECEIVEBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)
// @relation(AC-SVR-UASC-053-ACK-SENDBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)

// @relation(AC-SVR-TCP-004-ACK, SVR-TCP-013, SVR-TCP-028, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, HelloNegotiatesAckLimitsClampedToPeer)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = 60000;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();

  // Queue the HEL bytes before creating `ConnectionProtocol` since it immediately starts reading.
  // Client says it can send at most 20000 and receive at most 30000.
  transport->enqueue_hello_message(build_hello(0, 30000, 20000, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  bool gotComplete{false};
  ua::connection_protocol::NegotiatedLimits negotiated;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits nl,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      {
        std::lock_guard<std::mutex> lk(mx);
        gotComplete = true;
        negotiated = nl;
      }
      cv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  const auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);

  const auto ack = parse_ack(writes[0]);
  EXPECT_EQ(ack.protocolVersion, 0u);
  EXPECT_EQ(ack.receiveBufferSize, 20000u);
  EXPECT_EQ(ack.sendBufferSize, 30000u);

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotComplete; }));
  }

  EXPECT_EQ(negotiated.receiveBufferSize, 20000u);
  EXPECT_EQ(negotiated.sendBufferSize, 30000u);

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-052-ACK-RECEIVEBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)
// @relation(AC-SVR-UASC-053-ACK-SENDBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)
// @relation(AC-SVR-TCP-013-ACK-RECEIVE-BUFFER-FLOOR, scope=function)
// @relation(AC-SVR-TCP-014-ACK-SEND-BUFFER-FLOOR, scope=function)

// @relation(AC-SVR-TCP-013-CLAMP, scope=function)
TEST(ConnectionProtocolTests, AckAtAbsoluteMinimumRemainsWithinConfiguredAndPeerLimits)
{
  boost::asio::thread_pool tp;
  // The local limit already equals the absolute floor, so the ACK stays within both the configured
  // capacity and the peer's larger sub-8192 HEL fields.
  ua::connection_protocol::Limits server;
  server.maxBufferSize = ua::connection_protocol::eccMinBufferSize;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 2000, 2000, 0, 0, "opc.tcp://127.0.0.1:4840"));

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
  const auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);

  const auto ack = parse_ack(writes[0]);
  EXPECT_EQ(ack.receiveBufferSize, ua::connection_protocol::eccMinBufferSize);
  EXPECT_EQ(ack.sendBufferSize, ua::connection_protocol::eccMinBufferSize);

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 section 7.1.2.4 Table 67: each ACK buffer stays below the peer's opposite HEL field and is at
// least 8192 when that HEL field is at least 8192, or at least 1024 otherwise. The asymmetric
// refusal cases make each direction independently falsifiable.
// @relation(AC-SVR-TCP-013-ACK-RECEIVE-BUFFER-FLOOR, scope=function)
// @relation(AC-SVR-TCP-014-ACK-SEND-BUFFER-FLOOR, scope=function)
TEST(ConnectionProtocolTests, AckBufferMinimumsFollowPeerThresholdsAndNeverEmitNonConformingAck)
{
  struct Case
  {
    uint32_t serverMaxBuffer{0};
    uint32_t clientReceiveBuffer{0};
    uint32_t clientSendBuffer{0};
    bool expectAck{false};
    uint32_t expectedAckReceiveBuffer{0};
    uint32_t expectedAckSendBuffer{0};
  };

  const std::vector<Case> cases{
    {.serverMaxBuffer = ua::connection_protocol::eccMinBufferSize,
      .clientReceiveBuffer = 2000,
      .clientSendBuffer = 2000,
      .expectAck = true,
      .expectedAckReceiveBuffer = ua::connection_protocol::eccMinBufferSize,
      .expectedAckSendBuffer = ua::connection_protocol::eccMinBufferSize},
    {.serverMaxBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .clientReceiveBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .clientSendBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .expectAck = true,
      .expectedAckReceiveBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .expectedAckSendBuffer = ua::connection_protocol::nonEccMinBufferSize},
    {.serverMaxBuffer = 512, .clientReceiveBuffer = 2000, .clientSendBuffer = 2000, .expectAck = false},
    {.serverMaxBuffer = 4096,
      .clientReceiveBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .clientSendBuffer = ua::connection_protocol::eccMinBufferSize,
      .expectAck = false},
    {.serverMaxBuffer = 4096,
      .clientReceiveBuffer = ua::connection_protocol::eccMinBufferSize,
      .clientSendBuffer = ua::connection_protocol::nonEccMinBufferSize,
      .expectAck = false},
  };

  for (const auto& testCase : cases)
  {
    boost::asio::thread_pool threadPool;
    ua::connection_protocol::Limits server;
    server.maxBufferSize = testCase.serverMaxBuffer;

    auto deps = std::make_shared<FakeConnectionProtocolDeps>(threadPool.get_executor());
    deps->set_server_limits(server);
    auto transport = std::make_shared<FakeTransportConnection>();
    transport->enqueue_hello_message(build_hello(
      0, testCase.clientReceiveBuffer, testCase.clientSendBuffer, 0, 0, "opc.tcp://127.0.0.1:4840"));

    auto protocol = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      transport,
      false,
      60s,
      [](StatusCode,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>) {},
      [](StatusCode, string_view, ua::FatalCloseDisposition) {});

    ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
    const auto writes = transport->writes();
    ASSERT_EQ(writes.size(), 1u);
    ASSERT_GE(writes[0].size(), ua::connection_protocol::headerSize);

    const std::string_view messageType{reinterpret_cast<const char*>(writes[0].data()), 3};
    if (testCase.expectAck)
    {
      ASSERT_EQ(messageType, "ACK");
      const auto ack = parse_ack(writes[0]);
      EXPECT_EQ(ack.receiveBufferSize, testCase.expectedAckReceiveBuffer);
      EXPECT_EQ(ack.sendBufferSize, testCase.expectedAckSendBuffer);
      EXPECT_LE(ack.receiveBufferSize, testCase.clientSendBuffer);
      EXPECT_LE(ack.sendBufferSize, testCase.clientReceiveBuffer);
    }
    else
    {
      EXPECT_EQ(messageType, "ERR") << "the server emitted a non-conforming ACK";
      EXPECT_TRUE(transport->wait_for_close(500ms));
    }

    (void)protocol;
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
}

// @relation(AC-SVR-UASC-052-ACK-RECEIVEBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)
// @relation(AC-SVR-UASC-053-ACK-SENDBUFFERSIZE-IS-CLAMPED-DOWN, scope=function)

// @relation(AC-SVR-TCP-013-CLAMP, SVR-TCP-014, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, AckNegotiationClampsServerBuffersToClientHelloLimits)
{
  struct Case
  {
    uint32_t serverMaxBuffer{0};
    uint32_t clientRecv{0};
    uint32_t clientSend{0};
    uint32_t expectedAckRecv{0};
    uint32_t expectedAckSend{0};
  };

  // Expected behavior (current implementation):
  // - reject client buffers < 1024 (covered elsewhere)
  // - clamp: ack.Receive = min(server.mMaxBufferSize, client.Send)
  // - clamp: ack.Send    = min(server.mMaxBufferSize, client.Receive)
  const std::vector<Case> cases{
    // Clamp both directions.
    {.serverMaxBuffer = 60000,
      .clientRecv = 30000,
      .clientSend = 20000,
      .expectedAckRecv = 20000,
      .expectedAckSend = 30000},
    // No clamp (server already <= client limits).
    {.serverMaxBuffer = 2000,
      .clientRecv = 8000,
      .clientSend = 8000,
      .expectedAckRecv = 2000,
      .expectedAckSend = 2000},
    // Clamp only receive.
    {.serverMaxBuffer = 5000,
      .clientRecv = 8000,
      .clientSend = 1024,
      .expectedAckRecv = 1024,
      .expectedAckSend = 5000},
    // Clamp only send.
    {.serverMaxBuffer = 5000,
      .clientRecv = 1024,
      .clientSend = 8000,
      .expectedAckRecv = 5000,
      .expectedAckSend = 1024},
  };

  for (const auto& tc : cases)
  {
    boost::asio::thread_pool tp;
    ua::connection_protocol::Limits server;
    server.maxBufferSize = tc.serverMaxBuffer;

    auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
    deps->set_server_limits(server);

    auto transport = std::make_shared<FakeTransportConnection>();
    transport->enqueue_hello_message(
      build_hello(0, tc.clientRecv, tc.clientSend, 0, 0, "opc.tcp://127.0.0.1:4840"));

    auto cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      transport,
      false,
      60s,
      [](StatusCode,
        std::shared_ptr<ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>) {},
      [](StatusCode, string_view, ua::FatalCloseDisposition) {});

    ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));
    const auto writes = transport->writes();
    ASSERT_EQ(writes.size(), 1u);

    const auto ack = parse_ack(writes[0]);
    EXPECT_EQ(ack.receiveBufferSize, tc.expectedAckRecv);
    EXPECT_EQ(ack.sendBufferSize, tc.expectedAckSend);

    ::ua::test_utils::drain_with_timeout(tp);
    (void)cp;
  }
}

// @relation(AC-SVR-TCP-001-IGNORE, SVR-TCP-026, scope=function)
TEST(ConnectionProtocolTests, ReservedByteNotFOnSecureChannelMessagesIsForwarded)
{
  // The Connection Protocol layer does not validate the 4th byte for MSG/OPN/CLO.
  // Non-'F' values are accepted and the chunk is forwarded to the secure channel layer.
  for (const auto& type : {std::array<char, 3>{'M', 'S', 'G'},
         std::array<char, 3>{'O', 'P', 'N'},
         std::array<char, 3>{'C', 'L', 'O'}})
  {
    boost::asio::thread_pool tp;
    auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
    deps->set_server_limits(ua::connection_protocol::Limits{});

    auto transport = std::make_shared<FakeTransportConnection>();
    transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
    transport->enqueue_read_exact(build_header(type, 'X', 9));
    transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0xAB)});
    // Follow-up header to avoid fake-transport empty-queue assert.
    transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize));

    std::mutex mx;
    std::condition_variable cv;
    bool gotChunk{false};
    std::vector<byte> received;

    auto cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      transport,
      false,
      60s,
      [&](StatusCode st,
        std::shared_ptr<ConnectionProtocol>
          c,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        ASSERT_TRUE(st.is_good());
        c->set_callbacks(
          [&](StatusCode st2, std::vector<byte>&& buf)
          {
            ASSERT_TRUE(st2.is_good());
            {
              std::lock_guard<std::mutex> lk(mx);
              gotChunk = true;
              received = std::move(buf);
            }
            cv.notify_one();
          },
          [&](StatusCode, string_view, ua::FatalCloseDisposition) {});
      },
      [&](StatusCode, string_view, ua::FatalCloseDisposition) {});

    ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotChunk; }));
    }

    ASSERT_EQ(received.size(), 9u);
    EXPECT_EQ(received.back(), static_cast<byte>(0xAB));

    ::ua::test_utils::drain_with_timeout(tp);
    (void)cp;
  }
}

// NOTE: ReservedByteNotFOnMessageHeaderIsForwarded and ReservedByteNotFOnOpnAndCloHeadersIsForwarded
// were removed - they were subsets of ReservedByteNotFOnSecureChannelMessagesIsForwarded which already
// loops over MSG, OPN, and CLO message types.

// @relation(SVR-TCP-002, scope=function)
TEST(ConnectionProtocolTests, MessageSizeEqualToHeaderSizeIsRejected)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);

  // Server sends ACK (write 1) then ERR (write 2) before closing.
  ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
  auto allWrites = transport->writes();
  ASSERT_EQ(allWrites.size(), 2u);
  EXPECT_EQ(static_cast<char>(allWrites[1][0]), 'E');
  EXPECT_EQ(static_cast<char>(allWrites[1][1]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][2]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// An idle channel (handshake complete, no message in flight) must NOT be torn down by the
// per-message read timeout. A Client may legitimately leave a channel idle far longer than the
// message-read timeout - e.g. a Session deliberately stalled to exercise its own timeout
// (Part 4 section 5.6.2). The transport must keep the channel open; Session/SecurityToken lifetimes govern
// liveness, not the inter-message read timer.
TEST(ConnectionProtocolTests, IdleChannelSurvivesMessageReadTimeout)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
  // No further messages: after the handshake the channel goes idle (the header read is deferred).

  std::mutex mx;
  std::condition_variable cv;
  bool gotComplete{false};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks(
        [](StatusCode, std::vector<byte>&&) {}, [](StatusCode, string_view, ua::FatalCloseDisposition) {});
      {
        std::lock_guard<std::mutex> lk(mx);
        gotComplete = true;
      }
      cv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) {},
    std::string{},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; },
    200ms);  // short per-message read timeout

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotComplete; }));
  }

  // Idle for well over the 200ms message-read timeout. The channel must remain open.
  EXPECT_FALSE(transport->wait_for_close(600ms))
    << "Idle channel was torn down by the per-message read timeout";

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// Conversely, once a message is in flight (header received, body announced) the per-message read
// timeout MUST still fire if the body never arrives - partial-message / stalled-body protection.
TEST(ConnectionProtocolTests, InFlightMessageWithMissingBodyTimesOut)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
  // A MSG header announcing a 100-byte body, but the body is never enqueued: the body read stalls.
  transport->enqueue_read_exact(
    build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize + 100));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError,
    std::string{},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; },
    200ms);  // short per-message read timeout

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 1000ms, [&]() { return gotError; }));
  }
  EXPECT_EQ(errorStatus, Status::BadTimeout);
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, OpnAndCloMessageSizeEqualToHeaderSizeIsRejected)
{
  for (const auto& type : {std::array<char, 3>{'O', 'P', 'N'}, std::array<char, 3>{'C', 'L', 'O'}})
  {
    boost::asio::thread_pool tp;
    auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
    deps->set_server_limits(ua::connection_protocol::Limits{});

    auto transport = std::make_shared<FakeTransportConnection>();
    transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
    transport->enqueue_read_exact(build_header(type, 'F', ua::connection_protocol::headerSize));

    std::mutex mx;
    std::condition_variable cv;
    bool gotError{false};
    StatusCode errorStatus{Status::Good};

    auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        gotError = true;
        errorStatus = st;
      }
      cv.notify_one();
    };

    auto cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      transport,
      false,
      60s,
      [&](StatusCode st,
        std::shared_ptr<ConnectionProtocol>
          c,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>)
      {
        ASSERT_TRUE(st.is_good());
        c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
      },
      onError);

    ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

    {
      std::unique_lock<std::mutex> lk(mx);
      ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
    }

    EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);

    // Server sends ACK (write 1) then ERR (write 2) before closing.
    ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
    auto allWrites = transport->writes();
    ASSERT_EQ(allWrites.size(), 2u);
    EXPECT_EQ(static_cast<char>(allWrites[1][0]), 'E');
    EXPECT_EQ(static_cast<char>(allWrites[1][1]), 'R');
    EXPECT_EQ(static_cast<char>(allWrites[1][2]), 'R');
    EXPECT_EQ(static_cast<char>(allWrites[1][3]), 'F');
    EXPECT_TRUE(transport->wait_for_close(500ms));

    ::ua::test_utils::drain_with_timeout(tp);
    (void)cp;
  }
}

// Covers SVR-TCP-020 (coverage-audit retag).
// @relation(SVR-TCP-002, SVR-TCP-020, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, MessageSizeExceedingNegotiatedReceiveBufferErrorsAndCloses)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = 1024;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();

  // Client says it can send 1024-byte chunks, so negotiated server ReceiveBufferSize remains 1024.
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // Next header claims a chunk larger than negotiated receive buffer.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', 2048));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTooLarge);

  // Server sends ACK (write 1) then ERR (write 2) before closing.
  ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
  auto allWrites = transport->writes();
  ASSERT_EQ(allWrites.size(), 2u);
  EXPECT_EQ(static_cast<char>(allWrites[1][0]), 'E');
  EXPECT_EQ(static_cast<char>(allWrites[1][1]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][2]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-002-TYPE, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, UnsupportedMessageTypeAfterHelloErrorsAndCloses)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));
  transport->enqueue_read_exact(build_header({'R', 'H', 'E'}, 'F', 9));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);

  // Server sends ACK (write 1) then ERR (write 2) before closing.
  ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
  auto allWrites = transport->writes();
  ASSERT_EQ(allWrites.size(), 2u);
  EXPECT_EQ(static_cast<char>(allWrites[1][0]), 'E');
  EXPECT_EQ(static_cast<char>(allWrites[1][1]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][2]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-002-TYPE, SVR-TCP-026, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, MessageWithinLimitsIsForwardedToSecureChannelCallback)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = 1024;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // Minimal MSGF chunk of size 9.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', 9));
  transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0xAB)});

  std::mutex mx;
  std::condition_variable cv;
  bool gotChunk{false};
  std::vector<byte> received;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks(
        [&](StatusCode st2, std::vector<byte>&& buf)
        {
          ASSERT_TRUE(st2.is_good());
          {
            std::lock_guard<std::mutex> lk(mx);
            gotChunk = true;
            received = std::move(buf);
          }
          cv.notify_one();
        },
        [&](StatusCode, string_view, ua::FatalCloseDisposition) {});
    },
    [&](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotChunk; }));
  }

  ASSERT_EQ(received.size(), 9u);
  EXPECT_EQ(received.back(), static_cast<byte>(0xAB));
  EXPECT_FALSE(transport->closed());

  // Drop strand-pinned shared_ptrs before draining - the transport is still
  // open (test asserts no-close), so cp keeps the read loop posted to the
  // executor. Releasing the locals lets the pool's work counter reach zero.
  cp.reset();
  transport.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Read-pause backpressure (transport half of the incoming-chunk depth cap, P1.D #1).
// While reads are paused the protocol finishes any in-flight message but withholds the *next* header
// read; resume_reads() arms it again and the buffered message flows - no stall, no loss.
// Falsifiable: without the pause guard in configure_for_header_rx, message #2 would be delivered
// immediately after #1 (before resume), and the negative wait below would observe chunkCount == 2.
TEST(ConnectionProtocolTests, PauseReadsWithholdsNextHeaderReadUntilResume)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = 1024;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  std::mutex mx;
  std::condition_variable cv;
  int chunkCount{0};
  std::shared_ptr<ConnectionProtocol> channel;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks(
        [&](StatusCode st2, std::vector<byte>&& buf)
        {
          ASSERT_TRUE(st2.is_good());
          (void)buf;
          {
            std::lock_guard<std::mutex> lk(mx);
            ++chunkCount;
          }
          cv.notify_one();
        },
        [&](StatusCode, string_view, ua::FatalCloseDisposition) {});
      {
        std::lock_guard<std::mutex> lk(mx);
        channel = c;
      }
      cv.notify_one();
    },
    [&](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));  // ACK written -> handshake complete.

  std::shared_ptr<ConnectionProtocol> ch;
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return channel != nullptr; }));
    ch = channel;
  }
  ASSERT_TRUE(ch);

  // Pause up-front. The header read armed by the handshake is already in flight, so message #1 is still
  // delivered (in-flight messages always complete), but the re-arm after it must be withheld.
  ch->pause_reads();

  // Message #1: 8-byte header announcing a 9-byte message, then its 1-byte body.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', 9));
  transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0xAB)});
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return chunkCount == 1; }));
  }

  // Message #2 while paused: the protocol must not re-arm the header read, so these bytes sit in the
  // transport's queue and chunk #2 must NOT be delivered.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', 9));
  transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0xCD)});
  {
    std::unique_lock<std::mutex> lk(mx);
    EXPECT_FALSE(cv.wait_for(lk, 200ms, [&]() { return chunkCount >= 2; }))
      << "paused channel delivered the next message without resuming";
  }

  // Resume: the withheld header read is armed, the queued message #2 is consumed, and chunk #2 flows.
  ch->resume_reads();
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return chunkCount == 2; }))
      << "resume_reads did not re-arm the read; data stalled";
  }

  cp.reset();
  ch.reset();
  channel.reset();
  transport.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-002-SIZE, scope=function)
TEST(ConnectionProtocolTests, MessageSizeEqualToNegotiatedReceiveBufferSizeIsAccepted)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = ua::connection_protocol::eccMinBufferSize;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // MessageSize == the smallest conforming negotiated ReceiveBufferSize.
  transport->enqueue_read_exact(
    build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::eccMinBufferSize));
  std::vector<byte> body(ua::connection_protocol::eccMinBufferSize - ua::connection_protocol::headerSize);
  body.back() = static_cast<byte>(0x08);
  transport->enqueue_read_exact(std::move(body));

  // Ensure the follow-up header read has data so the fake transport doesn't assert.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize));

  std::mutex mx;
  std::condition_variable cv;
  bool gotChunk{false};
  std::vector<byte> received;

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks(
        [&](StatusCode st2, std::vector<byte>&& buf)
        {
          ASSERT_TRUE(st2.is_good());
          {
            std::lock_guard<std::mutex> lk(mx);
            gotChunk = true;
            received = std::move(buf);
          }
          cv.notify_one();
        },
        [&](StatusCode, string_view, ua::FatalCloseDisposition) {});
    },
    [&](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotChunk; }));
  }

  ASSERT_EQ(received.size(), ua::connection_protocol::eccMinBufferSize);
  EXPECT_EQ(received.back(), static_cast<byte>(0x08));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-024-FATAL, SVR-TCP-032, scope=function)
TEST(ConnectionProtocolTests, PostHelloBodyReadErrorClosesConnection)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // Header claims size 9 (needs 1 body byte), but the transport read fails for the body.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', 9));
  transport->enqueue_read_error(StatusCode{Status::BadTcpInternalError}, "simulated read failure");

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpInternalError);
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-002-SIZE, scope=function)
TEST(ConnectionProtocolTests, MessageSizeOneGreaterThanReceiveBufferIsRejected)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = ua::connection_protocol::eccMinBufferSize;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  transport->enqueue_read_exact(
    build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::eccMinBufferSize + 1));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpMessageTooLarge);

  // Server sends ACK (write 1) then ERR (write 2) before closing.
  ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
  auto allWrites = transport->writes();
  ASSERT_EQ(allWrites.size(), 2u);
  EXPECT_EQ(static_cast<char>(allWrites[1][0]), 'E');
  EXPECT_EQ(static_cast<char>(allWrites[1][1]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][2]), 'R');
  EXPECT_EQ(static_cast<char>(allWrites[1][3]), 'F');
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-TCP-026-FORWARD, scope=function)
TEST(ConnectionProtocolTests, MinimalLegalSizeIsForwardedForOpnAndClo)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // OPNF size 9 (header + 1 byte).
  transport->enqueue_read_exact(build_header({'O', 'P', 'N'}, 'F', 9));
  transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0x11)});

  // CLOF size 9 (header + 1 byte).
  transport->enqueue_read_exact(build_header({'C', 'L', 'O'}, 'F', 9));
  transport->enqueue_read_exact(std::vector<byte>{static_cast<byte>(0x22)});

  // Follow-up header to avoid fake-transport empty-queue assert.
  transport->enqueue_read_exact(build_header({'M', 'S', 'G'}, 'F', ua::connection_protocol::headerSize));

  std::mutex mx;
  std::condition_variable cv;
  int got{0};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks(
        [&](StatusCode st2, std::vector<byte>&& buf)
        {
          ASSERT_TRUE(st2.is_good());
          ASSERT_EQ(buf.size(), 9u);
          {
            std::lock_guard<std::mutex> lk(mx);
            ++got;
          }
          cv.notify_one();
        },
        [&](StatusCode, string_view, ua::FatalCloseDisposition) {});
    },
    [&](StatusCode, string_view, ua::FatalCloseDisposition) {});

  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return got >= 2; }));
  }

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- close_async terminal-callback semantics --------------------------------

// @relation(AC-SVR-TCP-024-FATAL, scope=function)
TEST(ConnectionProtocolTests, CloseAsyncSynthesisesTerminalErrorWhenIdle)
{
  // Create a CP that is mid-handshake (waiting for a HEL the test never delivers).
  // Calling close_async must synthesize a terminal mErrorCallback(BadShutdown)
  // exactly once so user-side teardown (e.g. the listener's cpHolder cycle
  // break) runs deterministically without relying on a wire-error to discover
  // the close.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  std::mutex mx;
  std::condition_variable cv;
  int errorFireCount{0};
  int observerFireCount{0};
  StatusCode errorStatus{Status::Good};
  StatusCode observerStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [&](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        ++errorFireCount;
        errorStatus = st;
      }
      cv.notify_all();
    },
    {},
    {},
    10'000ms,
    {},
    {},
    [&](StatusCode status, string_view)
    {
      {
        std::lock_guard<std::mutex> lock(mx);
        ++observerFireCount;
        observerStatus = status;
      }
      cv.notify_all();
    });

  // CP has begun reading the HEL header (deferred read on the fake). Fire close.
  std::promise<void> closeDone;
  auto closeFut = closeDone.get_future();
  cp->close_async([&closeDone](VoidResult) { closeDone.set_value(); });

  // Synthesised terminal error must fire with BadShutdown.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFireCount >= 1 && observerFireCount >= 1; }));
  }
  EXPECT_EQ(errorStatus, Status::BadShutdown);
  EXPECT_EQ(observerStatus, Status::BadShutdown);

  // close_async user callback fires after transport drain.
  EXPECT_EQ(closeFut.wait_for(500ms), std::future_status::ready);

  // Allow some time for any spurious second fire to have happened.
  std::this_thread::sleep_for(50ms);
  {
    std::lock_guard<std::mutex> lk(mx);
    EXPECT_EQ(errorFireCount, 1) << "terminal error callback fired more than once";
    EXPECT_EQ(observerFireCount, 1) << "additive close observer fired more than once";
  }

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, CloseAsyncDoesNotRefireAfterRealError)
{
  // After a real wire error has driven mErrorCallback (single-fire via
  // std::exchange), calling close_async must not synthesize a second
  // BadShutdown firing.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  // Deliver an invalid HEL (an EndpointUrl past the length gate) - drives the error path. RATIFIED
  // CHANGE (group L): the stimulus was a HEL naming ProtocolVersion 99, which the server now negotiates
  // down instead of refusing.
  std::string overLongUrl;
  overLongUrl.resize(ua::connection_protocol::maxUrlSize + 1, 'a');
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, overLongUrl));

  std::mutex mx;
  std::condition_variable cv;
  int errorFireCount{0};
  StatusCode firstErrorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [&](StatusCode st, string_view, ua::FatalCloseDisposition)
    {
      {
        std::lock_guard<std::mutex> lk(mx);
        ++errorFireCount;
        if (errorFireCount == 1)
          firstErrorStatus = st;
      }
      cv.notify_all();
    });

  // Wait for the real error to fire.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return errorFireCount >= 1; }));
  }
  EXPECT_EQ(firstErrorStatus, Status::BadTcpEndpointUrlInvalid);

  // Now call close_async. The synthesized terminal must NOT fire - mErrorCallback
  // was already exchanged to empty.
  std::promise<void> closeDone;
  auto closeFut = closeDone.get_future();
  cp->close_async([&closeDone](VoidResult) { closeDone.set_value(); });
  EXPECT_EQ(closeFut.wait_for(500ms), std::future_status::ready);

  // Allow some time for any spurious second fire to have happened.
  std::this_thread::sleep_for(50ms);
  {
    std::lock_guard<std::mutex> lk(mx);
    EXPECT_EQ(errorFireCount, 1) << "error callback double-fired after real error + close";
  }

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(ConnectionProtocolTests, CloseAsyncDoublyCalledFiresUserCallbackTwiceTerminalOnce)
{
  // Calling close_async twice should fire both user callbacks (each transport
  // drain delivers one) but the terminal error synthesis should fire only once.
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  std::mutex mx;
  int errorFireCount{0};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [](StatusCode,
      std::shared_ptr<ConnectionProtocol>,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>) {},
    [&](StatusCode, string_view, ua::FatalCloseDisposition)
    {
      std::lock_guard<std::mutex> lk(mx);
      ++errorFireCount;
    });

  std::promise<void> firstDone;
  std::promise<void> secondDone;
  auto firstFut = firstDone.get_future();
  auto secondFut = secondDone.get_future();
  cp->close_async([&firstDone](VoidResult) { firstDone.set_value(); });
  cp->close_async([&secondDone](VoidResult) { secondDone.set_value(); });

  EXPECT_EQ(firstFut.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(secondFut.wait_for(500ms), std::future_status::ready);

  std::this_thread::sleep_for(50ms);
  {
    std::lock_guard<std::mutex> lk(mx);
    EXPECT_EQ(errorFireCount, 1) << "terminal error fired more than once across double close";
  }

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// Decoded shape of an ERRF frame as it appears on the wire: "ERRF" + MessageSize + Error + Reason.
struct Err
{
  uint32_t messageSize{0};
  uint32_t error{0};
  String reason;
};

static Err parse_err(span<const byte> bytes)
{
  memory_stream_device::ExternalReadOnly streamDevice{bytes};
  MemoryStream stream{streamDevice};
  StructureFactory structureFactory;
  EncodingLimits limits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(structureFactory.resolver(), stream, limits);
  auto depth = limits.stack_depth();

  uint8_t e{0}, r1{0}, r2{0}, f{0};
  dec.decode(depth, e);
  dec.decode(depth, r1);
  dec.decode(depth, r2);
  dec.decode(depth, f);
  if (e != 'E' || r1 != 'R' || r2 != 'R' || f != 'F')
  {
    throw UaException{
      Status::BadDecodingError, make_error_detail("TestError", "Not an ERRF message", "Test")};
  }

  Err err;
  dec.decode(depth, err.messageSize);
  dec.decode(depth, err.error);
  dec.decode(depth, err.reason);
  return err;
}

}  // namespace

// Part 6 S7.1.2.5: the ERR `Reason` "shall not be more than 4 096 bytes". The cap binds the *sender*
// on emission; a plausible implementation enforces it only on the receiving side (this SDK caps an
// inbound Reason in `ignore_oversized_err_reason`) and then formats its outbound Reason from a
// description that embeds peer-supplied text. The rejected EndpointUrl is exactly such text and may
// itself be 4 096 bytes long, so the natural Reason overruns the bound and the emitted frame is
// either over-long or, if the encode buffer is sized for the bound, never written at all.
// @verifies AC-SVR-TCP-015-REASON
TEST(ConnectionProtocolTests, ServerSentErrReasonNeverExceedsFourThousandNinetySixBytes)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();

  // The longest EndpointUrl that passes the length gate (its encoded value, prefix included, is 4 095
  // bytes), so the rejection that follows is the unrecognised-URL one - the path whose description echoes
  // the whole URL back into the ERR Reason. That is the stimulus: an error whose natural description is
  // longer than 4 096 bytes, produced by the real code path rather than injected by the test.
  std::string url{"opc.tcp://127.0.0.1:4840/"};
  url.resize(ua::connection_protocol::maxUrlSize - sizeof(int32_t) - 1, 'a');
  ASSERT_EQ(url.size(), 4091u);
  transport->enqueue_hello_message(build_hello(0, 1024, 1024, 0, 0, url));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    {},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }

  EXPECT_EQ(errorStatus, Status::BadTcpEndpointUrlInvalid);

  // Part 6 S7.1.5: the server reports the fatal error with an ERR frame before closing. The Reason cap
  // is an obligation *about that frame*, so the frame has to exist for the obligation to be met.
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms))
    << "server wrote no ERR frame for the rejected EndpointUrl (an over-long Reason must be truncated, "
       "not turned into a dropped ERR)";
  const auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 1u);
  ASSERT_GE(writes[0].size(), ua::connection_protocol::headerSize + (2 * sizeof(uint32_t)));

  const auto err = parse_err(writes[0]);
  EXPECT_EQ(err.error, static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid));
  ASSERT_EQ(err.reason.size(), 4096u) << "ERR Reason was not truncated at the Part 6 byte boundary";
  std::string expectedReason{"EndpointUrl is not recognized: "};
  expectedReason += url;
  expectedReason.resize(4096);
  EXPECT_EQ(std::string_view{err.reason}, expectedReason)
    << "truncation must preserve the useful prefix of the natural Reason";

  // ...and the truncation must leave a well-formed frame: the declared MessageSize matches both the
  // bytes actually written and the header + Error + Reason layout.
  EXPECT_EQ(static_cast<size_t>(err.messageSize), writes[0].size());
  EXPECT_EQ(static_cast<size_t>(err.messageSize),
    ua::connection_protocol::headerSize + (2 * sizeof(uint32_t)) + err.reason.size());

  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 S7.1.3: "The Hello/Acknowledge Messages may only be sent once. If they are received again the
// receiver shall report an error and close the TransportConnection." A plausible implementation leaves
// the HEL handler reachable after the handshake and simply re-runs negotiation, which lets a peer
// resize the buffers underneath a SecureChannel already sized against the first ACK. The refusal is
// therefore asserted as a conjunction: an ERR and a close, AND no second ACK / no renegotiation.
// @verifies AC-SVR-TCP-018-ONCE
TEST(ConnectionProtocolTests, SecondHelloOnAnEstablishedConnectionIsRefusedAndClosesIt)
{
  boost::asio::thread_pool tp;
  ua::connection_protocol::Limits server;
  server.maxBufferSize = 60000;

  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(server);

  auto transport = std::make_shared<FakeTransportConnection>();

  // First HEL: negotiates ack.Receive = min(60000, 20000) and ack.Send = min(60000, 30000).
  transport->enqueue_hello_message(build_hello(0, 30000, 20000, 0, 0, "opc.tcp://127.0.0.1:4840"));

  // Second, well-formed HEL on the same connection, proposing *different* buffers so a server that
  // renegotiated would be caught by a differing second ACK rather than by frame counting alone. It is
  // framed the way the transport delivers a message - header read first, then the body - because the
  // header is where the refusal must happen; the body simply never gets read.
  const auto secondHello = build_hello(0, 9000, 9000, 0, 0, "opc.tcp://127.0.0.1:4840");
  ASSERT_GT(secondHello.size(), ua::connection_protocol::headerSize);
  std::vector<byte> secondHelloHeader{
    secondHello.begin(), secondHello.begin() + ua::connection_protocol::headerSize};
  std::vector<byte> secondHelloBody{
    secondHello.begin() + ua::connection_protocol::headerSize, secondHello.end()};
  transport->enqueue_read_exact(std::move(secondHelloHeader));
  transport->enqueue_read_exact(std::move(secondHelloBody));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  int completeCount{0};
  StatusCode errorStatus{Status::Good};
  ua::connection_protocol::NegotiatedLimits negotiated;

  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      errorStatus = st;
    }
    cv.notify_one();
  };

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits nl,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      ASSERT_TRUE(st.is_good());
      c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
      {
        std::lock_guard<std::mutex> lk(mx);
        ++completeCount;
        negotiated = nl;
      }
      cv.notify_one();
    },
    onError,
    {},
    [](string_view endpointUrl) { return endpointUrl == "opc.tcp://127.0.0.1:4840"; });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return completeCount >= 1; }));
  }
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms));

  // The duplicate HEL must be reported as an error and the connection closed.
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }))
      << "a second HEL on an established connection was accepted silently";
  }
  EXPECT_EQ(errorStatus, Status::BadTcpMessageTypeInvalid);
  EXPECT_TRUE(transport->wait_for_close(500ms));

  // ACK (write 1) then ERR (write 2) - and nothing else. A third frame, or an ACK in slot 2, would be
  // the second acknowledgement the spec forbids.
  ASSERT_TRUE(transport->wait_for_write_count(2, 500ms));
  const auto writes = transport->writes();
  ASSERT_EQ(writes.size(), 2u);
  ASSERT_GE(writes[1].size(), ua::connection_protocol::headerSize);
  EXPECT_EQ(static_cast<char>(writes[1][0]), 'E');
  EXPECT_EQ(static_cast<char>(writes[1][1]), 'R');
  EXPECT_EQ(static_cast<char>(writes[1][2]), 'R');
  EXPECT_EQ(static_cast<char>(writes[1][3]), 'F');

  // The buffers stay as the first (and only) negotiation left them: the first ACK still describes the
  // 30000/20000 exchange, and the application was told the channel's limits exactly once.
  const auto ack = parse_ack(writes[0]);
  EXPECT_EQ(ack.receiveBufferSize, 20000u);
  EXPECT_EQ(ack.sendBufferSize, 30000u);
  {
    std::lock_guard<std::mutex> lk(mx);
    EXPECT_EQ(completeCount, 1) << "the second HEL renegotiated the connection";
    EXPECT_EQ(negotiated.receiveBufferSize, 20000u);
    EXPECT_EQ(negotiated.sendBufferSize, 30000u);
  }

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Part 6 S7.1.4 - the Stack's application-facing notifications for SecureChannel lifecycle.
//
// These two obligations are about a surface one layer above the Connection Protocol: the Stack must
// tell the Server *application* what happened to a SecureChannel. The transport carries the bytes,
// the server SecureChannel raises the notification, so the drive below is a real
// `ua::server::SecureChannel` over the shared dependencies double, with the decoded-request
// injection interface standing in for the UASC decode the tests above already cover. Everything that
// decides an outcome - the OPN validation, the response returned to the client, the close reason -
// is production code; the double only supplies the observer and records what it is handed.
// ---------------------------------------------------------------------------

#include "fake_secure_channel_dependencies.h"

#include "ua_close_secure_channel_request.h"
#include "ua_message_security_mode.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_response_header.h"
#include "ua_security_policy.h"
#include "ua_security_token_request_type.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_observer.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_service_fault.h"

namespace
{

using ChannelAccess = ::ua::server::SecureChannelTestAccess;
using FakeChannelDeps = ::ua::test::behaviour_pins::phase_4_7::FakeSecureChannelDependencies;

/// Records the channel-lifecycle notifications the Stack delivers to the Server application, keeping
/// the payload fields a test needs to tie a notification back to the response it belongs with.
/// Every hook is invoked on an unspecified thread (a pool worker for the open/refuse arms, whichever
/// thread drops the last reference for the close arm), so the state is mutex-guarded throughout.
class ChannelEventRecorder final : public ::ua::server::ServerObserver
{
public:
  void on_secure_channel_opened(const ::ua::server::SecureChannelEventInfo& info) override
  {
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      ++mOpenedCount;
      mOpenedChannelId = info.secureChannelId;
      mOpenedRequestedLifetime = info.requestedLifetime;
    }
    mCv.notify_all();
  }

  void on_secure_channel_open_failed(
    const ::ua::server::SecureChannelEventInfo& info, ::ua::StatusCode reason) override
  {
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      ++mOpenFailedCount;
      mOpenFailedChannelId = info.secureChannelId;
      mOpenFailedStatus = reason;
    }
    mCv.notify_all();
  }

  void on_secure_channel_closed(
    const ::ua::server::SecureChannelEventInfo& info, ::ua::StatusCode reason) override
  {
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      ++mClosedCount;
      mClosedChannelId = info.secureChannelId;
      mClosedReason = reason;
    }
    mCv.notify_all();
  }

  void on_connection_closed(
    const std::string&, ::ua::server::ConnectionCloseReason reason, ::ua::StatusCode status) override
  {
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      ++mConnectionClosedCount;
      mConnectionCloseReason = reason;
      mConnectionCloseStatus = status;
    }
    mCv.notify_all();
  }

  bool wait_opened(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock{mMutex};
    return mCv.wait_for(lock, timeout, [this]() { return mOpenedCount > 0; });
  }

  bool wait_open_failed(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock{mMutex};
    return mCv.wait_for(lock, timeout, [this]() { return mOpenFailedCount > 0; });
  }

  int opened_count() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenedCount;
  }

  int open_failed_count() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenFailedCount;
  }

  int closed_count() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mClosedCount;
  }

  int connection_closed_count() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mConnectionClosedCount;
  }

  uint32_t opened_channel_id() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenedChannelId;
  }

  uint32_t opened_requested_lifetime() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenedRequestedLifetime;
  }

  ::ua::StatusCode open_failed_status() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenFailedStatus;
  }

  uint32_t open_failed_channel_id() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mOpenFailedChannelId;
  }

  uint32_t closed_channel_id() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mClosedChannelId;
  }

  ::ua::StatusCode closed_reason() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mClosedReason;
  }

  ::ua::server::ConnectionCloseReason connection_close_reason() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mConnectionCloseReason;
  }

  ::ua::StatusCode connection_close_status() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mConnectionCloseStatus;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  int mOpenedCount{0};
  int mOpenFailedCount{0};
  int mClosedCount{0};
  int mConnectionClosedCount{0};
  uint32_t mOpenedChannelId{0};
  uint32_t mOpenedRequestedLifetime{0};
  uint32_t mOpenFailedChannelId{0};
  uint32_t mClosedChannelId{0};
  ::ua::StatusCode mOpenFailedStatus{ua::Status::Good};
  ::ua::StatusCode mClosedReason{ua::Status::Good};
  ::ua::StatusCode mConnectionCloseStatus{ua::Status::Good};
  ::ua::server::ConnectionCloseReason mConnectionCloseReason{::ua::server::ConnectionCloseReason::Orderly};
};

/// The shared SecureChannel dependencies double, differing only in the observer it hands the
/// channel: the recorder above, so what the Stack notifies is visible to the test.
class RecordingObserverChannelDeps final : public FakeChannelDeps
{
public:
  RecordingObserverChannelDeps(
    boost::asio::any_io_executor executor, std::shared_ptr<ChannelEventRecorder> recorder)
    : FakeChannelDeps(std::move(executor)), mRecorder(std::move(recorder))
  {}

  std::shared_ptr<::ua::server::ServerObserver> observer() override
  {
    return mRecorder;
  }

private:
  std::shared_ptr<ChannelEventRecorder> mRecorder;
};

/// Captures the response the channel actually returned to the client, so a notification can be
/// checked against the response the spec says it must carry.
class ChannelResponseCapture
{
public:
  void install(::ua::server::SecureChannel& channel)
  {
    ChannelAccess::on_strand(channel,
      [this](auto& guard)
      {
        guard.set_response_sink(
          [this](const Response& response)
          {
            {
              const std::lock_guard<std::mutex> lock{mMutex};
              mResponse = response.second;
              if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
              {
                mIsServiceFault = true;
                mFaultStatus = fault->response_header().service_result();
              }
              mGotResponse = true;
            }
            mCv.notify_all();
          });
      });
  }

  bool wait(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock{mMutex};
    return mCv.wait_for(lock, timeout, [this]() { return mGotResponse; });
  }

  shared_ptr<Structure> response() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mResponse;
  }

  bool is_service_fault() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mIsServiceFault;
  }

  StatusCode fault_status() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mFaultStatus;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  bool mGotResponse{false};
  bool mIsServiceFault{false};
  StatusCode mFaultStatus{Status::Good};
  shared_ptr<Structure> mResponse;
};

/// A SecurityPolicy::None endpoint, so the OPN flow clears the server's security-mode selection.
static ::ua::server::ServerEndpointConfig build_none_endpoint()
{
  ::ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "None";
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  endpoint.transportProfile = TransportProfileId::UaTcpUaScUaBinary;
  return endpoint;
}

/// A well-formed OpenSecureChannel Issue request for SecurityPolicy::None.
static std::shared_ptr<OpenSecureChannelRequest> build_opn_issue_none(uint32_t requestedLifetime)
{
  auto request = std::make_shared<OpenSecureChannelRequest>();
  request->client_protocol_version() = 0;
  request->request_type() = SecurityTokenRequestType::Issue;
  request->security_mode() = MessageSecurityMode::None;
  request->requested_lifetime() = requestedLifetime;
  return request;
}

/// A server SecureChannel wired to its own recorder, in the state a first OPN really arrives in:
/// a context whose policy and mode are settled but which has not yet completed an open.
struct ObservedChannel
{
  std::shared_ptr<ChannelEventRecorder> recorder{std::make_shared<ChannelEventRecorder>()};
  std::shared_ptr<RecordingObserverChannelDeps> deps;
  std::shared_ptr<::ua::server::SecureChannel> channel;
  ChannelResponseCapture capture;

  ObservedChannel(boost::asio::any_io_executor executor, uint32_t channelId)
  {
    deps = std::make_shared<RecordingObserverChannelDeps>(executor, recorder);
    deps->set_endpoints({build_none_endpoint()});
    channel = ::ua::server::SecureChannel::create(
      deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");
    ChannelAccess::on_strand(*channel,
      [&](auto& guard)
      {
        guard.set_minimal_context_none(executor, "L/None");
        // The context the helper installs is fresh, which drops the id the channel was constructed
        // with; put a distinctive one back so a notification can be tied to the response it is
        // supposed to describe rather than matching on a shared default of zero.
        guard.context()->secureChannelId = channelId;
      });
    capture.install(*channel);
  }

  void inject(uint32_t requestId, std::shared_ptr<Structure> request)
  {
    ChannelAccess::on_strand(*channel,
      [&](auto& guard) { guard.inject_decoded_request(requestId, std::move(request), ua::NodeId{}); });
  }
};

}  // namespace

// Part 6 S7.1.4: "The Stack shall provide notifications to the Server application whenever it receives an
// OpenSecureChannel request. These notifications shall include the OpenSecureChannel or Error response
// returned to the Client." The plausible implementation notifies only where it already has a channel to
// describe - i.e. once the open has succeeded - which reads as satisfying "whenever it receives an
// OpenSecureChannel request" while silently dropping every refusal, exactly the events an auditor needs.
// Both arms are therefore driven: one OPN the server accepts and one it refuses, with the notification
// checked against the response the stack actually returned on the wire in each case.
// @verifies AC-SVR-TCP-029-NOTIFY-OPN
TEST(ConnectionProtocolTests, ApplicationIsNotifiedOfEveryOpenSecureChannelAndOfTheResponseReturned)
{
  boost::asio::thread_pool tp;
  const auto executor = tp.get_executor();

  // --- Arm 1: an OPN the server accepts. ---
  ObservedChannel accepted{executor, 0x0000A11Cu};
  accepted.inject(1, build_opn_issue_none(600'000));

  ASSERT_TRUE(accepted.capture.wait(500ms)) << "the accepted OPN produced no response at all";
  ASSERT_FALSE(accepted.capture.is_service_fault())
    << "expected the OPN to be accepted, got a fault: " << accepted.capture.fault_status().as_uint32();
  auto* openResponse = dynamic_cast<OpenSecureChannelResponse*>(accepted.capture.response().get());
  ASSERT_NE(openResponse, nullptr) << "the accepted OPN did not return an OpenSecureChannelResponse";

  EXPECT_TRUE(accepted.recorder->wait_opened(500ms))
    << "no application notification for an OpenSecureChannel the stack accepted";
  EXPECT_EQ(accepted.recorder->opened_count(), 1);
  // The notification must describe the exchange it reports: the channel of the OpenSecureChannelResponse
  // returned to the client, and the lifetime the OPN request asked for.
  EXPECT_EQ(accepted.recorder->opened_channel_id(), openResponse->security_token().channel_id());
  EXPECT_EQ(accepted.recorder->opened_channel_id(), 0x0000A11Cu);
  EXPECT_EQ(accepted.recorder->opened_requested_lifetime(), 600'000u);
  EXPECT_EQ(accepted.recorder->open_failed_count(), 0);

  // --- Arm 2: an OPN the server refuses, on a channel in the state a first OPN really arrives in. ---
  ObservedChannel refused{executor, 0x0000BADCu};
  auto refusedRequest = build_opn_issue_none(600'000);
  refusedRequest->client_protocol_version() = 1;  // the Hello named 0 (the channel's default)
  refused.inject(2, refusedRequest);

  ASSERT_TRUE(refused.capture.wait(500ms)) << "the refused OPN produced no response at all";
  ASSERT_TRUE(refused.capture.is_service_fault()) << "expected the OPN to be refused";
  // RATIFIED CHANGE (group L): a version differing from the Hello's is Bad_ProtocolVersionUnsupported
  // (Part 6 6.7.4); it was Bad_TcpMessageTypeInvalid for any non-zero version.
  EXPECT_EQ(refused.capture.fault_status(), Status::BadProtocolVersionUnsupported);

  EXPECT_TRUE(refused.recorder->wait_open_failed(500ms))
    << "no application notification for an OpenSecureChannel the stack refused - a refusal is invisible "
       "to the application, and to the audit record Part 4 builds on it";
  EXPECT_EQ(refused.recorder->open_failed_count(), 1);
  EXPECT_EQ(refused.recorder->open_failed_status(), refused.capture.fault_status())
    << "the notification must carry the Error response that was returned to the client";
  ASSERT_NE(refused.recorder->open_failed_status().shared_detail(), nullptr)
    << "the application callback lost the ErrorDetail attached to the refusal StatusCode";
  EXPECT_EQ(refused.recorder->open_failed_status().shared_detail()->code, "ProtocolVersionMismatch");
  EXPECT_EQ(refused.recorder->open_failed_channel_id(), 0x0000BADCu);
  EXPECT_EQ(refused.recorder->opened_count(), 0);

  accepted.channel.reset();
  refused.channel.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 6 S7.1.4: "the Stack shall provide notifications to the Server application whenever a
// CloseSecureChannel request is received **or** when the Stack cleans up an abandoned SecureChannel."
// The sentence names two triggers, and the cheap implementation collapses them into one undifferentiated
// "channel gone" callback: the application is notified either way, so the words are met, but an operator
// can no longer tell an orderly client close from a channel the server reclaimed - which is precisely the
// distinction an abandoned-channel investigation turns on. Both triggers are driven here on channels that
// were really opened first, and the two notifications are required to differ.
// @verifies AC-SVR-TCP-030-NOTIFY-CLO
TEST(ConnectionProtocolTests, ApplicationIsNotifiedOfAnExplicitCloseAndOfAnAbandonedChannelReclaim)
{
  boost::asio::thread_pool tp;
  const auto executor = tp.get_executor();

  // --- Trigger 1: a CloseSecureChannel request arrives on an open channel. ---
  ObservedChannel graceful{executor, 0x0000C10Eu};
  graceful.inject(1, build_opn_issue_none(600'000));
  ASSERT_TRUE(graceful.capture.wait(500ms));
  ASSERT_FALSE(graceful.capture.is_service_fault()) << "the channel under CLO must be open first";

  graceful.inject(2, std::make_shared<CloseSecureChannelRequest>());
  // The CLO reached the handler: it is the handler that unregisters the channel, so this pins that the
  // close state observed below was set by the CLO path and not left over as a default.
  ASSERT_TRUE(graceful.deps->wait_remove_called(500ms)) << "the CloseSecureChannel request was not handled";

  // --- Trigger 2: the stack reclaims a channel nobody renewed - the abandoned-channel cleanup. ---
  ObservedChannel reclaimed{executor, 0x0000DEADu};
  reclaimed.inject(1, build_opn_issue_none(600'000));
  ASSERT_TRUE(reclaimed.capture.wait(500ms));
  ASSERT_FALSE(reclaimed.capture.is_service_fault()) << "the reclaimed channel must be open first";
  auto* reclaimedResponse = dynamic_cast<OpenSecureChannelResponse*>(reclaimed.capture.response().get());
  ASSERT_NE(reclaimedResponse, nullptr);
  const auto activeTokenId = reclaimedResponse->security_token().token_id();

  // The channel's own security token elapses with nothing pending - the callback the server's token
  // timer fires when a peer walks away without renewing.
  ChannelAccess::on_strand(
    *reclaimed.channel, [&](auto& guard) { guard.handle_token_expired(activeTokenId); });
  ASSERT_TRUE(reclaimed.deps->wait_remove_called(500ms)) << "the expired token did not reclaim the channel";

  // Release both channels; the lifecycle notification is raised as the channel is torn down, and the
  // dependencies (which own the observer) deliberately outlive them.
  graceful.channel.reset();
  reclaimed.channel.reset();
  ::ua::test_utils::drain_with_timeout(tp);

  // Both triggers must reach the application...
  EXPECT_EQ(graceful.recorder->closed_count(), 1) << "no notification for a received CloseSecureChannel";
  EXPECT_EQ(reclaimed.recorder->closed_count(), 1) << "no notification for an abandoned-channel cleanup";
  EXPECT_EQ(graceful.recorder->closed_channel_id(), 0x0000C10Eu);
  EXPECT_EQ(reclaimed.recorder->closed_channel_id(), 0x0000DEADu);

  // ...and they must not be reported as the same event.
  EXPECT_EQ(graceful.recorder->closed_reason(), Status::Good);
  EXPECT_EQ(reclaimed.recorder->closed_reason(), Status::BadSecureChannelClosed);
  EXPECT_NE(graceful.recorder->closed_reason(), reclaimed.recorder->closed_reason())
    << "an explicit close and a stack-initiated reclaim are indistinguishable in the notification";
  EXPECT_EQ(graceful.recorder->connection_close_reason(), ::ua::server::ConnectionCloseReason::Orderly);
  EXPECT_EQ(
    reclaimed.recorder->connection_close_reason(), ::ua::server::ConnectionCloseReason::ProtocolError);
  EXPECT_EQ(graceful.recorder->connection_closed_count(), 1);
  EXPECT_EQ(reclaimed.recorder->connection_closed_count(), 1);
}

// ---------------------------------------------------------------------------
// Part 6 S7.1.1 - the TransportProfileUri the server publishes for its opc.tcp endpoints.
//
// The field is emitted by GetEndpoints, so the drive is the real GetEndpoints handler
// (`ua::server::DiscoveryServiceSet<GetEndpointsRequest>` and the endpoint builder behind it) - the
// same handler the SecureChannel's session-less discovery dispatch routes to. Only the dependency
// bundle is faked: the listeners, their advertised URLs and their endpoint configurations are
// ordinary server configuration, and every field of every EndpointDescription below is filled in by
// production code.
// ---------------------------------------------------------------------------

#include "fake_certificate_store.h"
#include "fake_discovery_dependencies.h"

#include "ua_application_configuration.h"
#include "ua_discovery_service_set.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_transport_address.h"

namespace
{

/// The URI OPC 10000-7 defines for the UA-TCP / UA-SC / UA-Binary transport - the only transport
/// profile an `opc.tcp:` endpoint may name, and the string a client matches on to pick its stack.
constexpr const char* partSevenUaTcpTransportProfileUri =
  "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

/// The Part 7 namespace every standard transport profile URI lives under. A vendor string would not
/// start here, which is what makes "not a vendor string" checkable rather than a matter of taste.
constexpr const char* partSevenTransportProfilePrefix = "http://opcfoundation.org/UA-Profile/Transport/";

/// A None-policy endpoint that deliberately leaves `transportProfile` at the value a configuration
/// which never mentions the field gets. That is the ordinary case, and the case where a wrong or
/// absent default would reach the wire unnoticed. None policy also keeps the endpoint in the
/// response even though the fake certificate store holds no application certificate.
static ::ua::server::ServerEndpointConfig build_endpoint_with_defaulted_transport(std::string name)
{
  ::ua::server::ServerEndpointConfig endpoint;
  endpoint.name = std::move(name);
  endpoint.messageSecurityMode = MessageSecurityMode::None;
  endpoint.securityPolicyId = SecurityPolicyId::None;
  endpoint.userIdentityTokens.push_back(
    ::ua::server::create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  return endpoint;
}

/// Runs one GetEndpoints call through the production handler and returns the response it produced.
static Response run_get_endpoints_against(
  const std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies>& dependencies,
  boost::asio::any_io_executor executor, GetEndpointsRequest&& request)
{
  std::promise<Response> promised;
  auto future = promised.get_future();
  auto service = ::ua::server::DiscoveryServiceSet<GetEndpointsRequest>::create(dependencies,
    LocaleId{"en"},
    /*requestId=*/0,
    std::move(request),
    std::move(executor),
    [&promised](Response response) { promised.set_value(std::move(response)); });
  if (future.wait_for(2s) != std::future_status::ready)
  {
    ADD_FAILURE() << "the GetEndpoints handler never completed";
    return Response{};
  }
  return future.get();
}

}  // namespace

// Part 6 S7.1.1: "The TransportProfileUri shall be a URI for the TCP transport defined in OPC
// 10000-7." Nothing in the request carries the value, so a plausible implementation leaves the field
// at its default (an empty String, which a client reads as "no transport declared") or fills it from
// a private/vendor string it also understands - either way the endpoint still looks well formed in
// every other field, and only a client that selects its stack on this URI notices. The observation is
// a conjunction, so all of it is asserted for every description in the published set: non-empty, in
// the Part 7 transport namespace, not an HTTPS profile, and exactly the UA-TCP URI. Both publication
// paths are driven - the unfiltered set and the host-rewritten set an endpointUrl hint produces -
// plus a profileUris filter, which is the client-side consumer of the same string.
// @verifies AC-SVR-TCP-031-PROFILE
TEST(ConnectionProtocolTests, EveryPublishedEndpointDescriptionNamesThePartSevenTcpTransportProfile)
{
  boost::asio::thread_pool tp;

  auto certificateStore = ::ua::test_helpers::FakeCertificateStore::create();
  auto deps = std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(tp.get_executor());
  deps->set_default_application_group_certificate_store(certificateStore);

  auto applicationConfiguration = ApplicationConfig::load_default();
  applicationConfiguration.application_description_part().applicationUri =
    "urn:reduktive:test:transport-profile-uri";
  deps->set_application_configuration(std::move(applicationConfiguration));

  // Two listeners, two endpoints each: one endpoint per listener states the transport profile the way
  // a configuration that sets it does (build_none_endpoint), the other leaves it defaulted.
  deps->add_listener(::ua::server::ListenerHandle{1},
    {build_none_endpoint(), build_endpoint_with_defaulted_transport("defaulted1")},
    {ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});
  deps->add_listener(::ua::server::ListenerHandle{2},
    {build_none_endpoint(), build_endpoint_with_defaulted_transport("defaulted2")},
    {ua::transport::EndpointUrl{"opc.tcp://localhost:4841/"}});

  const auto checkEveryDescription = [](const Response& response, const char* arm)
  {
    ASSERT_EQ(dynamic_cast<ServiceFault*>(response.second.get()), nullptr)
      << arm << ": GetEndpoints must be served";
    auto* getEndpoints = dynamic_cast<GetEndpointsResponse*>(response.second.get());
    ASSERT_NE(getEndpoints, nullptr) << arm << ": no GetEndpointsResponse";
    EXPECT_EQ(getEndpoints->response_header().service_result(), Status::Good) << arm;

    const auto& endpoints = getEndpoints->endpoints().payload();
    ASSERT_FALSE(endpoints.empty()) << arm << ": no endpoint published, so nothing to make the claim about";

    for (const auto& endpoint : endpoints)
    {
      const std::string profile{endpoint.transport_profile_uri()};
      EXPECT_FALSE(profile.empty())
        << arm << ": an empty transportProfileUri declares no transport at all, for endpoint "
        << std::string{endpoint.endpoint_url()};
      EXPECT_EQ(profile.rfind(partSevenTransportProfilePrefix, 0), 0u)
        << arm << ": transportProfileUri is not an OPC 10000-7 profile URI, got: " << profile;
      EXPECT_EQ(profile.find("https"), std::string::npos)
        << arm << ": an opc.tcp endpoint must not name an HTTPS transport profile, got: " << profile;
      EXPECT_EQ(profile, partSevenUaTcpTransportProfileUri)
        << arm << ": transportProfileUri is not the Part 7 UA-TCP transport URI, got: " << profile;
    }
  };

  // Arm 1: no endpointUrl hint - the whole published set, every listener and every endpoint.
  GetEndpointsRequest unfilteredRequest;
  const auto unfiltered = run_get_endpoints_against(deps, tp.get_executor(), std::move(unfilteredRequest));
  checkEveryDescription(unfiltered, "unfiltered");
  {
    auto* getEndpoints = dynamic_cast<GetEndpointsResponse*>(unfiltered.second.get());
    ASSERT_NE(getEndpoints, nullptr);
    EXPECT_EQ(getEndpoints->endpoints().payload().size(), 4u)
      << "every configured endpoint of every listener must be published";
  }

  // Arm 2: an endpointUrl hint - the descriptions are rebuilt with a rewritten host, and the claim
  // must survive that second construction path.
  GetEndpointsRequest hintedRequest;
  hintedRequest.endpoint_url() = String{"opc.tcp://nat-gateway.example.net:4840/"};
  const auto hinted = run_get_endpoints_against(deps, tp.get_executor(), std::move(hintedRequest));
  checkEveryDescription(hinted, "endpointUrl-hinted");

  // Arm 3: the client-side consumer of the same string. Filtering on the Part 7 UA-TCP URI must keep
  // the endpoints - a vendor string or an empty field would filter the whole set away, so this arm
  // fails loudly on exactly the substitution the first two arms are guarding against.
  GetEndpointsRequest filteredRequest;
  filteredRequest.profile_uris().payload().push_back(String{partSevenUaTcpTransportProfileUri});
  const auto filtered = run_get_endpoints_against(deps, tp.get_executor(), std::move(filteredRequest));
  checkEveryDescription(filtered, "profileUris-filtered");
  {
    auto* getEndpoints = dynamic_cast<GetEndpointsResponse*>(filtered.second.get());
    ASSERT_NE(getEndpoints, nullptr);
    EXPECT_EQ(getEndpoints->endpoints().payload().size(), 4u)
      << "a client filtering on the Part 7 UA-TCP profile URI must still be offered every endpoint";
  }

  deps.reset();
  certificateStore.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// A HEL whose EndpointUrl length prefix claims far more than the handshake grammar allows while
/// only a few bytes follow: what a peer sends to make the decoder reserve the claimed length.
static std::vector<byte> build_hello_claiming_a_huge_url_length(int32_t claimedLength)
{
  memory_stream_device::Dynamic streamDevice{256, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  StackDepth limit{64};
  enc.encode(limit, uint8_t{'H'});
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'L'});
  enc.encode(limit, uint8_t{'F'});
  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});
  enc.encode(limit, uint32_t{0});  // ProtocolVersion
  enc.encode(limit, uint32_t{8192});  // ReceiveBufferSize
  enc.encode(limit, uint32_t{8192});  // SendBufferSize
  enc.encode(limit, uint32_t{0});  // MaxMessageSize
  enc.encode(limit, uint32_t{0});  // MaxChunkCount
  enc.encode(limit, claimedLength);  // the String length prefix, forged
  for (int i = 0; i < 8; ++i)
    enc.encode(limit, uint8_t{'a'});  // ... over eight real bytes
  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);
  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

}  // namespace

// The HEL decoder runs under the handshake grammar's string bound (maxUrlSize, 4 KiB), not the
// process-wide 1 MiB limit: a forged length prefix is refused by that bound BEFORE the decoder reserves
// it, and the refusal is the one Part 6 7.1.2.3 names for an over-long EndpointUrl
// (Bad_TcpEndpointUrlInvalid), where reserving the claimed length and then running out of bytes reports
// Bad_DecodingError. The control is ServerSentErrReasonNeverExceedsFourThousandNinetySixBytes: the
// longest acceptable URL (4091 bytes) still decodes.
// @verifies AC-SVR-TCP-010-A-FORGED-HEL-STRING-LENGTH-IS-REFUSED-BEFORE-IT-IS-RESERVED
TEST(ConnectionProtocolTests, AHelloClaimingAMegabyteEndpointUrlIsRefusedByTheHandshakeBound)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello_claiming_a_huge_url_length(1024 * 1024));

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  StatusCode errorStatus{Status::Good};

  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
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
    });

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, 500ms, [&]() { return gotError; }));
  }
  // The handshake bound refuses the forged length before it is reserved, and the refusal is the one Part 6
  // 7.1.2.3 names for an over-long EndpointUrl; reserving it and running out of bytes would report
  // Bad_DecodingError instead.
  EXPECT_EQ(errorStatus, Status::BadTcpEndpointUrlInvalid)
    << "the forged length must be refused by the handshake bound, not after being reserved";
  ASSERT_TRUE(transport->wait_for_write_count(1, 500ms)) << "the refusal is answered with an ERR";
  const auto err = parse_err(transport->writes()[0]);
  EXPECT_EQ(err.error, static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid))
    << "the ERR on the wire carries the EndpointUrl status";
  EXPECT_TRUE(transport->wait_for_close(500ms));

  (void)cp;
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
struct ServerRun
{
  StatusCode errorStatus{Status::Good};
  std::vector<std::vector<byte>> writes;
  bool closed{false};
};

// Runs a server-role ConnectionProtocol over `transport` (already loaded with a HEL and what follows)
// until the error sink fires, and returns what it reported and wrote.
ServerRun run_server_until_error(const std::shared_ptr<FakeTransportConnection>& transport)
{
  boost::asio::thread_pool tp;
  auto deps = std::make_shared<FakeConnectionProtocolDeps>(tp.get_executor());
  deps->set_server_limits(ua::connection_protocol::Limits{});

  std::mutex mx;
  std::condition_variable cv;
  bool gotError{false};
  ServerRun run;
  auto onError = [&](StatusCode st, string_view, ua::FatalCloseDisposition)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      gotError = true;
      run.errorStatus = st;
    }
    cv.notify_one();
  };
  auto cp = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    deps,
    transport,
    false,
    60s,
    [&](StatusCode st,
      std::shared_ptr<ConnectionProtocol>
        c,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      if (st.is_good() && c)
        c->set_callbacks([](StatusCode, std::vector<byte>&&) {}, onError);
    },
    onError);
  {
    std::unique_lock<std::mutex> lk(mx);
    EXPECT_TRUE(cv.wait_for(lk, 2s, [&]() { return gotError; }));
  }
  run.closed = transport->wait_for_close(500ms);
  run.writes = transport->writes();
  cp.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return run;
}
}  // namespace

// Part 6 7.1.5 defines ERR as the Server's notification to the Client, so a client's ERR is a Message
// type the Server does not accept (Table 70, Bad_TcpMessageTypeInvalid). Its body is not read - neither its
// claimed size nor its Reason reaches the server - and the server's own ERR carries no Reason of the
// client's. The server used to read the body and echo the client's Reason back.
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-01-A-CLIENT-ERR-IS-REFUSED-UNREAD
TEST(ConnectionProtocolTests, AClientErrIsRefusedUnreadAsAMessageTypeTheServerDoesNotAccept)
{
  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 8192, 8192, 0, 0, "opc.tcp://127.0.0.1:4840"));
  std::vector<byte> err = build_header({'E', 'R', 'R'}, 'F', 8 + 4 + 4 + 5);
  const std::array<uint8_t, 13> body{0x00, 0x00, 0x86, 0x80, 0x05, 0x00, 0x00, 0x00, 'e', 'v', 'i', 'l', '!'};
  for (const auto b : body)
    err.push_back(static_cast<byte>(b));
  // Header then body, with the body also offered to the synchronous read the ERR path used (the fake
  // serves both from this entry point).
  transport->enqueue_hello_message(std::move(err));

  const auto run = run_server_until_error(transport);
  EXPECT_EQ(run.errorStatus, Status::BadTcpMessageTypeInvalid);
  ASSERT_EQ(run.writes.size(), 2u) << "the ACK, then the server's ERR";
  const auto reply = parse_err(run.writes[1]);
  EXPECT_EQ(reply.error, static_cast<uint32_t>(Status::BadTcpMessageTypeInvalid));
  // RATIFIED EXPECTATION CHANGE (owner decision 2, 2026-10-01): a refusal with no fixed reason of its own now
  // carries the specification's description of its status rather than an empty Reason. What this test
  // guards is unchanged: the client's own Reason ("evil!") is never echoed.
  EXPECT_EQ(std::string_view{reply.reason}.find("evil!"), std::string_view::npos)
    << "the client's Reason must not be echoed";
  EXPECT_EQ(std::string_view{reply.reason}, ua::description(Status::BadTcpMessageTypeInvalid));
  EXPECT_TRUE(run.closed);
}

// A refusal whose caller supplies no fixed reason - the case for transport and exception text, which goes to
// the ErrorDetail instead - carries the specification's description of its status on the wire, never empty
// and never the internal text (owner decision 2).
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-01-A-CLIENT-ERR-IS-REFUSED-UNREAD
TEST(ConnectionProtocolTests, AnErrWithoutAFixedReasonCarriesTheSpecificationDescription)
{
  EXPECT_FALSE(ua::description(Status::BadTcpMessageTypeInvalid).empty())
    << "the generated table has no description for the status the refusal uses";
  EXPECT_FALSE(ua::description(Status::BadTcpInternalError).empty());
  EXPECT_TRUE(ua::description(static_cast<Status>(0x80FF0000U)).empty())
    << "an unknown code has no description";
}

// Part 6 7.1.2.3 Table 66: the EndpointUrl's encoded value (its four-byte length plus its bytes) shall be
// less than 4096 bytes, and an over-long one is refused with Bad_TcpEndpointUrlInvalid. A 4092-byte URL
// (encoded 4096) is the shortest refused; the 4091-byte one is accepted
// (ServerSentErrReasonNeverExceedsFourThousandNinetySixBytes reaches the URL check behind the gate).
// @verifies AC-SVR-TCP-010-URLLEN
TEST(ConnectionProtocolTests, AnEndpointUrlWhoseEncodedValueIs4096BytesIsRefused)
{
  auto transport = std::make_shared<FakeTransportConnection>();
  std::string url{"opc.tcp://127.0.0.1:4840/"};
  url.resize(4092, 'a');
  transport->enqueue_hello_message(build_hello(0, 8192, 8192, 0, 0, url));

  const auto run = run_server_until_error(transport);
  EXPECT_EQ(run.errorStatus, Status::BadTcpEndpointUrlInvalid);
  ASSERT_EQ(run.writes.size(), 1u);
  const auto err = parse_err(run.writes[0]);
  EXPECT_EQ(err.error, static_cast<uint32_t>(Status::BadTcpEndpointUrlInvalid));
  // The length gate refused it, not the recognition check behind it (which draws the same status).
  EXPECT_EQ(std::string_view{err.reason}, "EndpointUrl exceeds the maximum size");
  EXPECT_TRUE(run.closed);
}

// Text that came from the transport (an operating-system error string) stays local: the error sink
// receives it, the ERR sent to the peer carries the status and no Reason of it.
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-03-TRANSPORT-TEXT-STAYS-LOCAL
TEST(ConnectionProtocolTests, TransportErrorTextIsNotSentToThePeer)
{
  auto transport = std::make_shared<FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello(0, 8192, 8192, 0, 0, "opc.tcp://127.0.0.1:4840"));
  transport->enqueue_read_error(
    StatusCode{Status::BadTcpInternalError}, "system : 104 : Connection reset by peer");

  const auto run = run_server_until_error(transport);
  EXPECT_EQ(run.errorStatus, Status::BadTcpInternalError);
  ASSERT_EQ(run.writes.size(), 2u) << "the ACK, then the ERR";
  const auto reply = parse_err(run.writes[1]);
  EXPECT_EQ(std::string_view{reply.reason}.find("system"), std::string_view::npos)
    << "the ERR Reason must not carry the operating system's error text, got: "
    << std::string_view{reply.reason};
}
