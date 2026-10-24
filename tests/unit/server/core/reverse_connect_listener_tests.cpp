// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for ReverseConnectListener.
///
/// Verifies lifecycle (create/start/stop) and error handling behavior.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_tcp_transport_connection.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "fake_connection_protocol_deps.h"

#include "ua_connection_protocol.h"
#include "ua_connection_protocol_limits.h"
#include "ua_error_detail.h"
#include "ua_reverse_hello.h"
#include "ua_server_reverse_connect_listener.h"
#include "ua_server_configuration.h"
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/write.hpp>

using namespace ua;
using namespace ua::server;

namespace
{

// --- Fake dependencies ---

class FakeReverseConnectListenerDeps : public ReverseConnectListenerDependencies
{
public:
  explicit FakeReverseConnectListenerDeps(boost::asio::any_io_executor executor)
    : mExecutor(std::move(executor))
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  ua::Logger logger() override
  {
    return {};
  }

  std::string server_uri() override
  {
    return serverUri;
  }

  std::weak_ptr<ua::ConnectionProtocolDependencies> connection_protocol_dependencies() override
  {
    return connectionProtocolDeps;
  }

  ua::connection_protocol::Limits connection_protocol_limits() override
  {
    return {};
  }

  std::chrono::seconds connection_protocol_timeout() override
  {
    return std::chrono::seconds{5};
  }

  std::chrono::milliseconds connection_protocol_message_read_timeout() override
  {
    return std::chrono::milliseconds{10000};
  }

  size_t write_queue_depth_cap() override
  {
    return 4096;
  }

  size_t write_queue_bytes_cap() override
  {
    return ua::TcpTransportConnection::defaultWriteQueueBytesCap;
  }

  void on_reverse_connection_ready(std::shared_ptr<ua::ConnectionProtocol> /*connection*/,
    ua::connection_protocol::NegotiatedLimits /*negotiatedLimits*/) override
  {
    connectionReadyCount.fetch_add(1, std::memory_order_relaxed);
  }

  void on_reverse_connect_opened(const std::string& remoteAddress) override
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    ++openedCount;
    lastOpenedRemoteAddress = remoteAddress;
  }

  void on_reverse_connect_closed(const std::string& remoteAddress, ua::StatusCode reason) override
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    ++closedCount;
    lastClosedRemoteAddress = remoteAddress;
    lastClosedReason = reason;
  }

  /// Number of times the outbound socket came up, and the address it came up to.
  int opened_count()
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    return openedCount;
  }

  std::string last_opened_remote_address()
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    return lastOpenedRemoteAddress;
  }

  void on_reverse_connect_error(ua::VoidResult error) override
  {
    {
      std::lock_guard<std::mutex> guard(errorMutex);
      lastErrorStatus = error.status_code();
      auto detail = error.shared_detail();
      lastErrorDescription = detail ? detail->summary : "";
      errorCount++;
    }
    errorCv.notify_all();
  }

  /// Wait until at least `count` errors have been reported, with timeout.
  bool wait_for_errors(int count, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> guard(errorMutex);
    return errorCv.wait_for(guard, timeout, [&] { return errorCount >= count; });
  }

  std::string serverUri{"urn:test:server"};
  std::weak_ptr<ua::ConnectionProtocolDependencies> connectionProtocolDeps;
  std::atomic<int> connectionReadyCount{0};

  std::mutex errorMutex;
  int openedCount{0};
  int closedCount{0};
  std::string lastOpenedRemoteAddress;
  std::string lastClosedRemoteAddress;
  ua::StatusCode lastClosedReason{};
  std::condition_variable errorCv;
  int errorCount{0};  // guarded by errorMutex
  ua::StatusCode lastErrorStatus;
  std::string lastErrorDescription;

private:
  boost::asio::any_io_executor mExecutor;
};

ServerConfig::ReverseConnectTarget make_target(
  std::string clientUrl = "opc.tcp://127.0.0.1:4841", uint32_t maxPending = 5)
{
  ServerConfig::ReverseConnectTarget target;
  target.name = "TestTarget";
  target.clientApplicationUri = "urn:test:client";
  target.clientEndpointUrl = std::move(clientUrl);
  target.serverEndpointUrl = "opc.tcp://localhost:4840";
  target.periodicConnectInterval = std::chrono::seconds{30};
  target.maxPendingSockets = maxPending;
  return target;
}

// --- Tests ---

class ServerReverseConnectListenerTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mDeps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  boost::asio::thread_pool mThreadPool{2};
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<FakeReverseConnectListenerDeps> mDeps;
};

TEST_F(ServerReverseConnectListenerTest, OutboundSocketUpRaisesOpenedWithTheRemoteAddress)
{
  // The three reverse-connect ServerObserver hooks were declared, documented, and NEVER EMITTED:
  // ua_server_reverse_connect_listener.cpp notified nothing at all, so a chapter that told readers
  // "these hooks are the only visibility into reverse-connect state" was pointing at silence.
  // This pins the first of the three at its real moment - the outbound socket coming up - and
  // asserts the address, so a regression that fires it with an empty or wrong peer also fails.
  boost::asio::io_context acceptorContext;
  boost::asio::ip::tcp::acceptor acceptor{
    acceptorContext, boost::asio::ip::tcp::endpoint{boost::asio::ip::tcp::v4(), 0}};
  acceptor.listen();
  const auto port = acceptor.local_endpoint().port();

  // Accept one connection on a throwaway thread so the connect completes.
  std::thread accepting{[&acceptorContext, &acceptor]
    {
      boost::system::error_code ec;
      boost::asio::ip::tcp::socket peer{acceptorContext};
      acceptor.accept(peer, ec);
      std::this_thread::sleep_for(std::chrono::milliseconds{200});
    }};

  auto manager =
    ReverseConnectListener::create(mDeps, make_target(fmt::format("opc.tcp://127.0.0.1:{}", port)));
  manager->start();

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while ((mDeps->opened_count() == 0) && (std::chrono::steady_clock::now() < deadline))
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }

  EXPECT_GE(mDeps->opened_count(), 1)
    << "on_reverse_connect_opened must fire when the outbound socket comes up";
  EXPECT_EQ(mDeps->last_opened_remote_address(), fmt::format("127.0.0.1:{}", port))
    << "the hook must carry the address the target actually connected to";

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  acceptor.close();
  acceptorContext.stop();
  if (accepting.joinable())
  {
    accepting.join();
  }
}

// create() builds the strand and logger from the dependencies, so it cannot construct a listener
// without them. It used to assert() the pointer and dereference regardless - which compiles out
// under NDEBUG, making every shipped build dereference unguarded. It now fails closed.
//
// Falsifiable: restore the unconditional dereference and this crashes (or, in debug, aborts on the
// assert) instead of returning null.
TEST_F(ServerReverseConnectListenerTest, CreateReturnsNullWhenDependenciesHaveExpired)
{
  std::weak_ptr<ReverseConnectListenerDependencies> expired;
  {
    auto temporary = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    expired = temporary;
    ASSERT_FALSE(expired.expired());
  }
  ASSERT_TRUE(expired.expired()) << "the fixture must actually release the dependencies";

  EXPECT_EQ(ReverseConnectListener::create(expired, make_target()), nullptr);
}

TEST_F(ServerReverseConnectListenerTest, CreateSucceedsWhileDependenciesAreAlive)
{
  EXPECT_NE(ReverseConnectListener::create(mDeps, make_target()), nullptr)
    << "the positive arm: fail-closed must not reject a live dependency";
}

TEST_F(ServerReverseConnectListenerTest, StopBeforeStartSucceeds)
{
  auto manager = ReverseConnectListener::create(mDeps, make_target());

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });

  auto future = stopped.get_future();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(future.get().is_good());
}

// @relation(SVR-RC-018, SVR-RC-025, scope=function)
TEST_F(ServerReverseConnectListenerTest, StartThenStopCallsCallback)
{
  auto manager = ReverseConnectListener::create(mDeps, make_target());
  manager->start();

  // Verify start() actually initiated connection attempts (unreachable target -> error).
  ASSERT_TRUE(mDeps->wait_for_errors(1, std::chrono::seconds{5}))
    << "Expected at least one connection error, confirming start() initiated work";

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });

  auto stopFuture = stopped.get_future();
  ASSERT_EQ(stopFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(stopFuture.get().is_good());
}

// @relation(SVR-RC-012, SVR-RC-023, SVR-RC-025, scope=function)
TEST_F(ServerReverseConnectListenerTest, InvalidClientUrlReportsError)
{
  // Use an invalid URL that will fail parsing.
  auto manager = ReverseConnectListener::create(mDeps, make_target("http://not-opcua:1234"));
  manager->start();

  // Wait for the error callback via deterministic signal.
  ASSERT_TRUE(mDeps->wait_for_errors(1, std::chrono::seconds{5}));

  {
    std::lock_guard<std::mutex> guard(mDeps->errorMutex);
    EXPECT_EQ(mDeps->lastErrorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
  }

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// @relation(SVR-RC-023, scope=function)
TEST_F(ServerReverseConnectListenerTest, ConnectToUnreachableHostReportsErrorAndStopsCleanly)
{
  // Use loopback on an unlikely port - connection refused is immediate.
  // Verifies both that the error is reported and that the manager can be stopped cleanly.
  auto manager = ReverseConnectListener::create(mDeps, make_target("opc.tcp://127.0.0.1:19999"));
  manager->start();

  ASSERT_TRUE(mDeps->wait_for_errors(1, std::chrono::seconds{10}))
    << "Expected connection error for unreachable host";

  {
    std::lock_guard<std::mutex> guard(mDeps->errorMutex);
    EXPECT_TRUE(mDeps->lastErrorStatus.is_bad());
  }

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "Manager should stop cleanly even after failed connection attempts";
}

// @relation(SVR-RC-018, scope=function)
TEST_F(ServerReverseConnectListenerTest, StopMultipleTimesIsSafe)
{
  auto manager = ReverseConnectListener::create(mDeps, make_target());
  manager->start();

  // Stop twice in rapid succession.
  std::promise<VoidResult> stopped1;
  std::promise<VoidResult> stopped2;

  manager->stop_async([&stopped1](VoidResult result) { stopped1.set_value(std::move(result)); });
  manager->stop_async([&stopped2](VoidResult result) { stopped2.set_value(std::move(result)); });

  auto future1 = stopped1.get_future();
  auto future2 = stopped2.get_future();
  ASSERT_EQ(future1.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  ASSERT_EQ(future2.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_TRUE(future1.get().is_good());
  EXPECT_TRUE(future2.get().is_good());
}

// Smoke test: verifies no crash when the manager is destroyed without
// an explicit stop_async() call. Does not assert functional behavior.
// @relation(SVR-RC-018, scope=function)
TEST_F(ServerReverseConnectListenerTest, DestroyWithoutStop_SmokeTest)
{
  auto manager = ReverseConnectListener::create(mDeps, make_target());
  manager->start();

  // Destroy the manager without calling stop_async.
  manager.reset();

  // Wait for any in-flight work to drain. We stop and restart the thread pool,
  // which guarantees all posted work (including the manager's strand) has completed.
  // The manager's weak_from_this() captures prevent use-after-free.
  ::ua::test_utils::drain_with_timeout(mThreadPool);
}

// @relation(SVR-RC-012, SVR-RC-023, scope=function)
TEST_F(ServerReverseConnectListenerTest, EmptyHostnameReportsError)
{
  auto manager = ReverseConnectListener::create(mDeps, make_target("opc.tcp://:4840"));
  manager->start();

  ASSERT_TRUE(mDeps->wait_for_errors(1, std::chrono::seconds{5}));

  {
    std::lock_guard<std::mutex> guard(mDeps->errorMutex);
    EXPECT_EQ(mDeps->lastErrorStatus, StatusCode{Status::BadTcpEndpointUrlInvalid});
  }

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

TEST_F(ServerReverseConnectListenerTest, ConnectSucceedsWithExpiredDependenciesDropsGracefully)
{
  // Regression for an uncaught-exception process abort. When the reverse-connect
  // TCP connect SUCCEEDS (something is listening on the target endpoint) but
  // connection_protocol_dependencies() has expired (a normal server-shutdown
  // race), on_tcp_connected used to let the ConnectionProtocol constructor throw
  // BadInvalidArgument. The throw escaped this strand-posted asio handler,
  // unwound io_context::run(), and called std::terminate - killing the whole
  // process. The listener must instead drop the connection gracefully.
  //
  // The fake's connectionProtocolDeps is left empty (expired) - reproducing the
  // race deterministically. A local acceptor on an ephemeral port makes the TCP
  // connect succeed so on_tcp_connected actually reaches the construction path
  // (the existing tests only avoid the crash because their targets are
  // unreachable, so on_tcp_connected returns at the status check before create).
  // Before the fix this test aborts the entire test binary; after it, it passes.
  boost::asio::io_context acceptorIoc;
  boost::asio::ip::tcp::acceptor acceptor(
    acceptorIoc, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
  const uint16_t port = acceptor.local_endpoint().port();

  std::atomic<int> acceptedCount{0};
  std::mutex socketsMutex;
  std::vector<boost::asio::ip::tcp::socket> acceptedSockets;

  std::function<void()> acceptNext;
  acceptNext = [&]()
  {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptorIoc);
    acceptor.async_accept(*socket,
      [&, socket](boost::system::error_code ec)
      {
        if (ec)
          return;
        {
          std::lock_guard<std::mutex> guard(socketsMutex);
          acceptedSockets.push_back(std::move(*socket));
        }
        acceptedCount.fetch_add(1, std::memory_order_relaxed);
        acceptNext();
      });
  };
  acceptNext();

  std::thread acceptorThread([&]() { acceptorIoc.run(); });

  auto manager =
    ReverseConnectListener::create(mDeps, make_target("opc.tcp://127.0.0.1:" + std::to_string(port)));
  manager->start();

  // Wait until the acceptor has accepted the reverse connection - proof that the
  // TCP connect succeeded and on_tcp_connected ran the construction path against
  // expired dependencies (the path that aborted the process before the fix).
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (acceptedCount.load(std::memory_order_relaxed) == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  EXPECT_GE(acceptedCount.load(), 1) << "reverse connection was never accepted; path not exercised";

  // Give on_tcp_connected a moment to process the accepted connection and drop it.
  std::this_thread::sleep_for(std::chrono::milliseconds{100});

  // The connection must have been dropped before delivery, since the
  // ConnectionProtocol dependencies were expired.
  EXPECT_EQ(mDeps->connectionReadyCount.load(), 0)
    << "connection delivered as ready despite expired dependencies";

  // The manager must still stop cleanly.
  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  EXPECT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  acceptorIoc.stop();
  acceptorThread.join();
}

// @relation(SVR-RC-018, scope=function)
TEST_F(ServerReverseConnectListenerTest, StopCancelsInflightConnect)
{
  // Target a non-routable address (TEST-NET-1, RFC 5737). async_connect will
  // hang until the OS times out (~60-90s). stop_async must cancel the pending
  // connector via close_async and complete its callback within seconds.
  auto manager = ReverseConnectListener::create(mDeps, make_target("opc.tcp://192.0.2.1:4840"));
  manager->start();

  // Brief pause to ensure connect_one has actually issued the async_connect.
  std::this_thread::sleep_for(std::chrono::milliseconds{100});

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });

  EXPECT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "stop_async must cancel an in-flight async_connect, not wait for OS timeout";
}

// ---------------------------------------------------------------------------
// Wire-level fixtures: a stand-in reverse-connect Client
// ---------------------------------------------------------------------------
//
// The tests below assert on the bytes the Server puts on a connection it opened. That needs two
// things the older tests above deliberately avoid: a live ConnectionProtocolDependencies (so the
// listener really builds a Server-role ConnectionProtocol with reverseConnect=true instead of
// dropping the socket), and a peer that speaks the transport handshake by hand rather than through
// the SDK's own client, so a bug shared by both encoder and decoder cannot cancel itself out.

/// Dependencies that additionally supply a live ConnectionProtocolDependencies and keep the ready
/// connection alive, so a test can carry on reading and writing on the negotiated transport.
class HandshakingReverseConnectDeps final : public FakeReverseConnectListenerDeps
{
public:
  explicit HandshakingReverseConnectDeps(boost::asio::any_io_executor executor)
    : FakeReverseConnectListenerDeps(executor),
      mProtocolDeps(std::make_shared<ua::test_helpers::FakeConnectionProtocolDeps>(executor))
  {
    connectionProtocolDeps = mProtocolDeps;
  }

  void on_reverse_connection_ready(std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits) override
  {
    {
      std::lock_guard<std::mutex> guard(errorMutex);
      if (!mReadyConnection)
      {
        mReadyConnection = std::move(connection);
        mNegotiatedLimits = negotiatedLimits;
      }
    }
    connectionReadyCount.fetch_add(1, std::memory_order_relaxed);
  }

  /// Waits until the handshake has delivered a ready connection. False on timeout.
  bool wait_for_ready(std::chrono::milliseconds timeout)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (connectionReadyCount.load(std::memory_order_relaxed) > 0)
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return connectionReadyCount.load(std::memory_order_relaxed) > 0;
  }

  /// Moves the ready connection out, so the test owns it and it dies with the test body.
  std::shared_ptr<ua::ConnectionProtocol> take_ready_connection()
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    return std::move(mReadyConnection);
  }

  ua::connection_protocol::NegotiatedLimits negotiated_limits()
  {
    std::lock_guard<std::mutex> guard(errorMutex);
    return mNegotiatedLimits;
  }

private:
  std::shared_ptr<ua::test_helpers::FakeConnectionProtocolDeps> mProtocolDeps;
  std::shared_ptr<ua::ConnectionProtocol> mReadyConnection;
  ua::connection_protocol::NegotiatedLimits mNegotiatedLimits;
};

/// What a post-handshake ConnectionProtocol delivered upward. Held by shared_ptr so the callbacks
/// installed on the protocol never reference a dead stack frame.
struct PostHandshakeSink
{
  /// Waits until at least one terminal error has been reported upward. False on timeout.
  /// The transport writes its ERR frame before it notifies upward, so a test that has already read
  /// the frame off the wire may still be ahead of the notification.
  bool wait_for_error(std::chrono::milliseconds timeout)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      {
        std::lock_guard<std::mutex> guard(mutex);
        if (errorCount > 0)
          return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    std::lock_guard<std::mutex> guard(mutex);
    return errorCount > 0;
  }

  std::mutex mutex;
  int chunkCount{0};
  int errorCount{0};
  ua::StatusCode lastError{};
};

/// A stand-in reverse-connect Client: the acceptor the Server dials, the accepted socket, and
/// deadline-bounded read/write helpers. Every wait is bounded so a Server that never writes fails
/// the test instead of hanging the suite.
class ReverseConnectPeer
{
public:
  ReverseConnectPeer()
    : mAcceptor(mIoContext, boost::asio::ip::tcp::endpoint{boost::asio::ip::tcp::v4(), 0}),
      mSocket(mIoContext)
  {
    mAcceptor.listen();
  }

  uint16_t port() const
  {
    return mAcceptor.local_endpoint().port();
  }

  /// Waits for the Server's outbound connection. False on timeout.
  bool accept_one(std::chrono::milliseconds timeout)
  {
    bool completed{false};
    boost::system::error_code result;
    mAcceptor.async_accept(mSocket,
      [&completed, &result](boost::system::error_code ec)
      {
        completed = true;
        result = ec;
      });
    return run_until_complete(completed, result, timeout);
  }

  /// Reads exactly @p count bytes into @p out. False on timeout or transport error.
  bool read_exactly(size_t count, std::vector<std::byte>& out, std::chrono::milliseconds timeout)
  {
    out.assign(count, std::byte{0});
    bool completed{false};
    boost::system::error_code result;
    boost::asio::async_read(mSocket,
      boost::asio::buffer(out.data(), out.size()),
      [&completed, &result](boost::system::error_code ec, size_t)
      {
        completed = true;
        result = ec;
      });
    return run_until_complete(completed, result, timeout);
  }

  bool write_all(const std::vector<std::byte>& bytes)
  {
    boost::system::error_code ec;
    boost::asio::write(mSocket, boost::asio::buffer(bytes.data(), bytes.size()), ec);
    return !ec;
  }

  /// Hands the accepted connection to the caller and leaves the peer ready to accept the next one.
  /// A test that has to keep an earlier connection OPEN while a later one arrives - the reconnect
  /// and spare-socket cases - needs this: closing it instead would itself be a reconnect trigger.
  /// The moved-from member is left as if freshly constructed, so accept_one() works again.
  boost::asio::ip::tcp::socket take_accepted()
  {
    return std::move(mSocket);
  }

private:
  bool run_until_complete(
    const bool& completed, const boost::system::error_code& result, std::chrono::milliseconds timeout)
  {
    mIoContext.restart();
    mIoContext.run_for(timeout);
    return completed && !result;
  }

  boost::asio::io_context mIoContext;
  boost::asio::ip::tcp::acceptor mAcceptor;
  boost::asio::ip::tcp::socket mSocket;
};

/// Little-endian uint32 at @p offset, per the Part 6 binary encoding.
uint32_t decode_uint32(const std::vector<std::byte>& bytes, size_t offset)
{
  return static_cast<uint32_t>(bytes[offset]) | (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 16) | (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

void append_uint32(std::vector<std::byte>& out, uint32_t value)
{
  out.push_back(static_cast<std::byte>(value & 0xFFu));
  out.push_back(static_cast<std::byte>((value >> 8) & 0xFFu));
  out.push_back(static_cast<std::byte>((value >> 16) & 0xFFu));
  out.push_back(static_cast<std::byte>((value >> 24) & 0xFFu));
}

/// The three-character MessageType at the front of a transport frame, as text.
std::string frame_type(const std::vector<std::byte>& frame)
{
  std::string type;
  for (size_t i = 0; (i < ua::connection_protocol::messageTypeSize) && (i < frame.size()); ++i)
  {
    type.push_back(static_cast<char>(frame[i]));
  }
  return type;
}

/// Reads one framed transport message: the 8-byte header, then the remainder it announces.
/// Returns the whole frame (header + body), or an empty vector on timeout / malformed size.
std::vector<std::byte> read_frame(ReverseConnectPeer& peer, std::chrono::milliseconds timeout)
{
  std::vector<std::byte> frame;
  if (!peer.read_exactly(ua::connection_protocol::headerSize, frame, timeout))
    return {};

  const uint32_t messageSize = decode_uint32(frame, 4);
  if ((messageSize < ua::connection_protocol::headerSize) ||
      (messageSize > ua::connection_protocol::maxReverseHelloSize))
  {
    return {};
  }

  const size_t bodySize = messageSize - ua::connection_protocol::headerSize;
  if (bodySize == 0)
    return frame;

  std::vector<std::byte> body;
  if (!peer.read_exactly(bodySize, body, timeout))
    return {};

  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

/// A conforming HEL frame, as a reverse-connect Client sends after receiving the RHE.
/// Hand-rolled rather than produced by the SDK's own client so an encoder/decoder bug cannot
/// cancel itself out.
std::vector<std::byte> build_hello(const std::string& endpointUrl, uint32_t receiveBufferSize,
  uint32_t sendBufferSize, uint32_t maxMessageSize, uint32_t maxChunkCount)
{
  std::vector<std::byte> body;
  append_uint32(body, 0u);  // ProtocolVersion
  append_uint32(body, receiveBufferSize);
  append_uint32(body, sendBufferSize);
  append_uint32(body, maxMessageSize);
  append_uint32(body, maxChunkCount);
  append_uint32(body, static_cast<uint32_t>(endpointUrl.size()));
  for (const char character : endpointUrl)
  {
    body.push_back(static_cast<std::byte>(character));
  }

  std::vector<std::byte> frame{std::byte{'H'}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'}};
  append_uint32(frame, static_cast<uint32_t>(ua::connection_protocol::headerSize + body.size()));
  frame.insert(frame.end(), body.begin(), body.end());
  return frame;
}

/// The Part 6 String starting at @p offset, as text.
std::string decode_wire_string(const std::vector<std::byte>& frame, size_t offset, uint32_t length)
{
  std::string text;
  for (uint32_t i = 0; i < length; ++i)
  {
    text.push_back(static_cast<char>(frame[offset + i]));
  }
  return text;
}

// Part 6 section 7.1.3: on a TransportConnection the Server opened, the very first wire payload must be a
// well-formed ReverseHello. A plausible implementation reuses the inbound Server path unchanged and
// simply waits for the Client's HEL, or - having dialled - mistakes itself for the Client and sends
// a HEL: in both cases the peer has no way to learn who dialled it or which role to take. The
// observation is only meaningful against the *first* bytes off the socket, so this reads the raw
// stream before writing anything back.
// @verifies AC-SVR-RC-001-REVERSEHELLO-FIRST
TEST_F(ServerReverseConnectListenerTest, ServerInitiatedConnectionSendsReverseHelloBeforeAnyOtherBytes)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  ReverseConnectPeer peer;

  auto manager =
    ReverseConnectListener::create(deps, make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port())));
  ASSERT_NE(manager, nullptr);
  manager->start();

  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5})) << "the server never opened the outbound connection";

  // The first frame on the wire - nothing has been read or written before this point, so whatever
  // this is, it is what the server sent first.
  const auto frame = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(frame.empty()) << "the server wrote nothing at all on the connection it opened";
  ASSERT_GE(frame.size(), ua::connection_protocol::headerSize);

  EXPECT_EQ(frame_type(frame), "RHE")
    << "the first message on a server-initiated connection must be a ReverseHello";
  EXPECT_EQ(static_cast<char>(frame[3]), 'F') << "ReverseHello is always a single final chunk";

  // ...and it is a ReverseHello in substance, not just in its first three bytes.
  const auto decoded = ua::detail::decode_reverse_hello(frame);
  EXPECT_TRUE(decoded.is_good()) << "the first frame did not decode as a ReverseHello: 0x" << std::hex
                                 << decoded.status_code().as_uint32();

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// Part 6 section 7.1.2: the RHE ServerUri is the *Server's own* ApplicationUri, Part 6 String-encoded. It
// is the first identity claim the Client can check against its configured trust, and the obvious
// slip is to fill it from whatever URI is nearest in the target configuration - the Client's
// ApplicationUri - which every Client would then dutifully match against itself. The fixture keeps
// the two URIs distinct so that substitution is visible, and asserts the raw length prefix so a
// String written with the wrong framing also fails.
// @verifies AC-SVR-RC-003-RHE-SERVERURI
TEST_F(ServerReverseConnectListenerTest, ReverseHelloCarriesTheServersOwnApplicationUri)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  deps->serverUri = "urn:test:server:application-identity";
  ReverseConnectPeer peer;

  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
  ASSERT_NE(deps->serverUri, target.clientApplicationUri)
    << "the fixture must keep the server and client identities distinguishable";

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
  const auto frame = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(frame.empty());
  ASSERT_EQ(frame_type(frame), "RHE");

  const auto decoded = ua::detail::decode_reverse_hello(frame);
  ASSERT_TRUE(decoded.is_good()) << "RHE did not decode: 0x" << std::hex << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().serverUri, deps->serverUri)
    << "ServerUri must be the server's own ApplicationUri";
  EXPECT_NE(decoded.value().serverUri, target.clientApplicationUri)
    << "ServerUri must not be the client's ApplicationUri";

  // Part 6 String framing: Int32 length prefix followed by exactly that many UTF-8 bytes.
  const size_t lengthOffset = ua::connection_protocol::headerSize;
  ASSERT_GE(frame.size(), lengthOffset + sizeof(uint32_t));
  const uint32_t serverUriLength = decode_uint32(frame, lengthOffset);
  EXPECT_EQ(serverUriLength, static_cast<uint32_t>(deps->serverUri.size()))
    << "the String length prefix must state the URI's byte length";
  ASSERT_GE(frame.size(), lengthOffset + sizeof(uint32_t) + serverUriLength);
  EXPECT_EQ(decode_wire_string(frame, lengthOffset + sizeof(uint32_t), serverUriLength), deps->serverUri);

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// Part 6 section 7.1.2: the RHE EndpointUrl names the Server endpoint the Client must use for the eventual
// SecureChannel. There is no discovery step on a reverse connection, so this field is the only
// statement of which endpoint the subsequent handshake is for; the tempting substitution is the
// Client URL the target dialled, which is the one URL guaranteed to be in scope at the point the
// RHE is built. Both conjuncts of the observation are asserted: the field identifies an endpoint
// the server serves, and the handshake then proceeds against that exact value.
// @verifies AC-SVR-RC-004-RHE-ENDPOINTURL
TEST_F(ServerReverseConnectListenerTest, ReverseHelloCarriesTheEndpointUrlTheClientMustUse)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  ReverseConnectPeer peer;

  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
  target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
  ASSERT_NE(target.serverEndpointUrl, target.clientEndpointUrl)
    << "the fixture must keep the advertised endpoint and the dialled client URL distinguishable";

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
  const auto frame = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(frame.empty());
  ASSERT_EQ(frame_type(frame), "RHE");

  const auto decoded = ua::detail::decode_reverse_hello(frame);
  ASSERT_TRUE(decoded.is_good()) << "RHE did not decode: 0x" << std::hex << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().endpointUrl, target.serverEndpointUrl)
    << "EndpointUrl must be the server endpoint the client is to use";
  EXPECT_NE(decoded.value().endpointUrl, target.clientEndpointUrl)
    << "EndpointUrl must not be the client URL the target dialled";

  // Part 6 String framing of the second body field, after the ServerUri.
  const size_t serverUriLengthOffset = ua::connection_protocol::headerSize;
  ASSERT_GE(frame.size(), serverUriLengthOffset + sizeof(uint32_t));
  const uint32_t serverUriLength = decode_uint32(frame, serverUriLengthOffset);
  const size_t endpointLengthOffset = serverUriLengthOffset + sizeof(uint32_t) + serverUriLength;
  ASSERT_GE(frame.size(), endpointLengthOffset + sizeof(uint32_t));
  const uint32_t endpointUrlLength = decode_uint32(frame, endpointLengthOffset);
  EXPECT_EQ(endpointUrlLength, static_cast<uint32_t>(target.serverEndpointUrl.size()));
  ASSERT_GE(frame.size(), endpointLengthOffset + sizeof(uint32_t) + endpointUrlLength);
  EXPECT_EQ(decode_wire_string(frame, endpointLengthOffset + sizeof(uint32_t), endpointUrlLength),
    target.serverEndpointUrl);

  // Second conjunct: the channel opens against that URL. Echoing the advertised value back in the
  // HEL - which is what a conforming client does - must carry the handshake through to completion,
  // not be refused as an unrecognised endpoint.
  ASSERT_TRUE(peer.write_all(build_hello(decoded.value().endpointUrl, 32768, 16384, 2 * 1024 * 1024, 64)));

  const auto response = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(response.empty()) << "the server answered nothing to a HEL echoing its own EndpointUrl";
  EXPECT_EQ(frame_type(response), "ACK")
    << "a HEL echoing the advertised EndpointUrl must be accepted, not refused";
  EXPECT_TRUE(deps->wait_for_ready(std::chrono::seconds{5}))
    << "the handshake must complete against the advertised endpoint";

  auto ready = deps->take_ready_connection();
  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  if (ready)
  {
    std::promise<VoidResult> closed;
    ready->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
    EXPECT_EQ(closed.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }
}

// Part 6 section 7.1.3: only the dialling is inverted, not the protocol. After the RHE the Server enters
// exactly the state an inbound acceptor is in on a fresh socket - it awaits the Client's HEL, answers
// with an ACK, and the negotiated buffer sizes come out of that exchange. The plausible error is to
// treat the RHE as having already settled the connection and skip the negotiation, leaving the peer
// with no agreed buffer sizes. Both conjuncts are asserted: an ACK is returned on the wire, and the
// handshake proceeds - the connection is delivered upward carrying the limits the ACK announced.
// @verifies AC-SVR-RC-007-HELLO-ACK-AFTER-RHE
TEST_F(ServerReverseConnectListenerTest, HelloAfterReverseHelloIsAnsweredWithAcknowledge)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  ReverseConnectPeer peer;

  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
  target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
  const auto rhe = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(rhe.empty());
  ASSERT_EQ(frame_type(rhe), "RHE");

  // Asymmetric, non-default buffer sizes: the ACK values are then only right if they were actually
  // negotiated against this HEL rather than echoed from the server's own configuration (65536).
  const uint32_t helReceiveBufferSize{32768};
  const uint32_t helSendBufferSize{16384};
  const uint32_t helMaxMessageSize{2 * 1024 * 1024};
  const uint32_t helMaxChunkCount{64};
  ASSERT_TRUE(peer.write_all(build_hello(
    target.serverEndpointUrl, helReceiveBufferSize, helSendBufferSize, helMaxMessageSize, helMaxChunkCount)));

  const auto ack = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(ack.empty()) << "the server did not answer the HEL that followed its ReverseHello";
  ASSERT_EQ(ack.size(), ua::connection_protocol::acknowledgeSize);
  EXPECT_EQ(frame_type(ack), "ACK");
  EXPECT_EQ(decode_uint32(ack, 4), static_cast<uint32_t>(ua::connection_protocol::acknowledgeSize));
  EXPECT_EQ(decode_uint32(ack, 8), 0u) << "ACK ProtocolVersion must be 0";

  // Clamped to the smaller of the local proposal and the peer's Hello, and directional: the ACK's
  // ReceiveBufferSize answers the Hello's SendBufferSize, and vice versa.
  EXPECT_EQ(decode_uint32(ack, 12), helSendBufferSize) << "ACK ReceiveBufferSize";
  EXPECT_EQ(decode_uint32(ack, 16), helReceiveBufferSize) << "ACK SendBufferSize";

  // Second conjunct: the handshake proceeded, and what it handed upward matches what went on the wire.
  ASSERT_TRUE(deps->wait_for_ready(std::chrono::seconds{5}))
    << "an ACK was sent but the connection was never delivered as ready";
  const auto negotiated = deps->negotiated_limits();
  EXPECT_EQ(negotiated.receiveBufferSize, helSendBufferSize);
  EXPECT_EQ(negotiated.sendBufferSize, helReceiveBufferSize);
  EXPECT_EQ(negotiated.sendMaxMessageSize, helMaxMessageSize)
    << "the client's message-size limit must bind the server's sends";
  EXPECT_EQ(negotiated.sendMaxChunkCount, helMaxChunkCount)
    << "the client's chunk-count limit must bind the server's sends";

  auto ready = deps->take_ready_connection();
  EXPECT_NE(ready, nullptr);

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  if (ready)
  {
    std::promise<VoidResult> closed;
    ready->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
    EXPECT_EQ(closed.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }
}

// Part 6 section 7.1.2: Hello and Acknowledge may be exchanged once per TransportConnection. A second HEL
// would renegotiate the buffer sizes mid-stream, invalidating chunks already sized against the first
// with no way for either side to say which sizes applied to which chunk. The plausible mistake is a
// handler that recognises HEL by message type wherever it appears and simply runs the negotiation
// again - which looks harmless in a test that only ever sends one. The error must be observable, so
// the ERR frame is read straight off the wire before anything drains or closes the connection.
// @verifies AC-SVR-RC-008-HELLO-ONCE-PER-CONNECTION
TEST_F(ServerReverseConnectListenerTest, SecondHelloOnAnEstablishedConnectionIsRejectedNotRenegotiated)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  ReverseConnectPeer peer;

  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
  target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  // Antecedent: a genuinely established connection, driven through the real RHE -> HEL -> ACK path.
  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
  const auto rhe = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(rhe.empty());
  ASSERT_EQ(frame_type(rhe), "RHE");

  ASSERT_TRUE(peer.write_all(build_hello(target.serverEndpointUrl, 32768, 16384, 2 * 1024 * 1024, 64)));
  const auto ack = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(ack.empty());
  ASSERT_EQ(frame_type(ack), "ACK") << "the handshake must complete before the repeat can be tested";
  ASSERT_TRUE(deps->wait_for_ready(std::chrono::seconds{5}));

  auto ready = deps->take_ready_connection();
  ASSERT_NE(ready, nullptr);

  // Take the connection into service, as the SecureChannel layer does: this is what arms the
  // post-handshake read pump that has to police the repeat.
  auto sink = std::make_shared<PostHandshakeSink>();
  ready->set_callbacks(
    [sink](ua::StatusCode, std::vector<ua::byte>&&)
    {
      std::lock_guard<std::mutex> guard(sink->mutex);
      ++sink->chunkCount;
    },
    [sink](ua::StatusCode status, ua::string_view, ua::FatalCloseDisposition)
    {
      std::lock_guard<std::mutex> guard(sink->mutex);
      ++sink->errorCount;
      sink->lastError = status;
    });

  ASSERT_TRUE(peer.write_all(build_hello(target.serverEndpointUrl, 65536, 65536, 4 * 1024 * 1024, 128)));

  const auto response = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(response.empty()) << "the server neither reported an error nor answered the repeated HEL";
  EXPECT_EQ(frame_type(response), "ERR") << "a repeated HEL must be reported as an error";
  EXPECT_NE(frame_type(response), "ACK") << "a repeated HEL must not be renegotiated";
  ASSERT_GE(response.size(), ua::connection_protocol::headerSize + sizeof(uint32_t));
  EXPECT_EQ(StatusCode{decode_uint32(response, ua::connection_protocol::headerSize)},
    StatusCode{Status::BadTcpMessageTypeInvalid})
    << "the ERR must name the repeated Hello as an invalid message type";

  // The repeat must not have been passed off as payload either.
  EXPECT_TRUE(sink->wait_for_error(std::chrono::seconds{5}))
    << "the transport must report the failure upward, not just on the wire";
  {
    std::lock_guard<std::mutex> guard(sink->mutex);
    EXPECT_EQ(sink->chunkCount, 0) << "a repeated HEL must never reach the SecureChannel as a chunk";
    EXPECT_GE(sink->errorCount, 1) << "the transport must report the failure upward";
    EXPECT_EQ(sink->lastError, StatusCode{Status::BadTcpMessageTypeInvalid});
  }

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  std::promise<VoidResult> closed;
  ready->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
  EXPECT_EQ(closed.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// Part 6 section 7.1.3: the Server dials out only to Clients an administrator configured, and SVR-RC-012
// makes an incomplete target - missing the Client's ApplicationUri, or the Server EndpointUrl the
// ReverseHello has to advertise - a configuration error the start operation must surface rather than
// act on. A plausible implementation validates only the field it needs to open the socket (the
// Client's URL) and dials on the strength of that alone, so a half-configured target produces an
// outbound connection nobody authorised. The first two phases keep the negative falsifiable: an
// unstarted listener must dial nothing, and a fully configured one must dial, so a silent acceptor
// cannot pass the malformed cases by accident.
// @verifies AC-SVR-RC-012-ADMIN-SUPPLIED-TARGETS
TEST_F(ServerReverseConnectListenerTest, ReverseConnectTargetsAreDialledOnlyWhenAdministratorSupplied)
{
  // Phase 1: configuration alone is not a dial - nothing goes out until the server is started.
  {
    ReverseConnectPeer peer;
    auto manager =
      ReverseConnectListener::create(mDeps, make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port())));
    ASSERT_NE(manager, nullptr);

    EXPECT_FALSE(peer.accept_one(std::chrono::seconds{1}))
      << "a listener that was never started dialled out on its own initiative";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }

  // Phase 2: control - a fully administrator-supplied target does dial, so the negatives below are
  // not passing simply because this fixture can never observe a connection.
  {
    ReverseConnectPeer peer;
    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto manager =
      ReverseConnectListener::create(deps, make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port())));
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}))
      << "the control target never dialled; the negative phases below would be vacuous";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }

  // Phase 3: the Client's ApplicationUri was never supplied.
  {
    ReverseConnectPeer peer;
    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.clientApplicationUri.clear();

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    EXPECT_FALSE(peer.accept_one(std::chrono::seconds{2}))
      << "a target with no administrator-supplied client ApplicationUri was dialled anyway";
    EXPECT_TRUE(deps->wait_for_errors(1, std::chrono::milliseconds{500}))
      << "the malformed target was neither dialled-nor-refused: no bad Result was surfaced";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }

  // Phase 4: the Server EndpointUrl the ReverseHello must advertise was never supplied.
  {
    ReverseConnectPeer peer;
    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.serverEndpointUrl.clear();

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    EXPECT_FALSE(peer.accept_one(std::chrono::seconds{2}))
      << "a target with no administrator-supplied server EndpointUrl was dialled anyway";
    EXPECT_TRUE(deps->wait_for_errors(1, std::chrono::milliseconds{500}))
      << "the malformed target was neither dialled-nor-refused: no bad Result was surfaced";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }
}

// Part 6 section 7.1.3: "Once a Client closes a SecureChannel or if the socket is closed without
// establishing a SecureChannel the Server shall create a new socket and send a new ReverseHello
// message." Both triggers bind and both are asserted here. They fail differently: the pre-channel
// close is seen by the read that is already pending for the client's HEL, whereas a connection that
// has been handed upward has no read pending until its consumer takes it into service - so a design
// that only reacts to errors reaching the listener stops reacting the moment a connection succeeds,
// and the spare-socket invariant hides that in everyday operation. The periodic interval is pushed
// far out of the way and the spare is consumed first, so the socket asserted on can only be the
// replacement for the loss; earlier connections are parked open rather than closed so they are not
// themselves reconnect triggers. Nothing here replaces the listener's own error sink - the
// connection is left exactly as the listener handed it over.
// @verifies AC-SVR-RC-013-NEW-SOCKET-AFTER-CLOSE
TEST_F(ServerReverseConnectListenerTest, ClosedReverseConnectionIsReplacedByANewSocketAndReverseHello)
{
  // Case (b): the socket is closed before any channel is established.
  {
    auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
    ReverseConnectPeer peer;

    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
    target.periodicConnectInterval = std::chrono::seconds{600};

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
    const auto firstRhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(firstRhe.empty());
    ASSERT_EQ(frame_type(firstRhe), "RHE") << "the first connection must carry a ReverseHello";

    // The client drops the socket without ever sending a HEL: nothing was established, so there is
    // no channel whose teardown could be observed.
    {
      auto dropped = peer.take_accepted();
      boost::system::error_code ignored;
      dropped.close(ignored);
    }

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}))
      << "a socket closed before any channel existed was never replaced";
    const auto replacementRhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(replacementRhe.empty()) << "the replacement socket carried no message at all";
    EXPECT_EQ(frame_type(replacementRhe), "RHE") << "the replacement socket must carry a new ReverseHello";
    const auto decoded = ua::detail::decode_reverse_hello(replacementRhe);
    ASSERT_TRUE(decoded.is_good()) << "the replacement frame did not decode as a ReverseHello: 0x" << std::hex
                                   << decoded.status_code().as_uint32();
    EXPECT_EQ(decoded.value().endpointUrl, target.serverEndpointUrl)
      << "the new ReverseHello must advertise the same target's endpoint";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }

  // Case (a): a fully handshaken connection is closed by the client.
  {
    auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
    ReverseConnectPeer peer;

    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
    target.periodicConnectInterval = std::chrono::seconds{600};

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
    const auto rhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(rhe.empty());
    ASSERT_EQ(frame_type(rhe), "RHE");

    ASSERT_TRUE(peer.write_all(build_hello(target.serverEndpointUrl, 32768, 16384, 2 * 1024 * 1024, 64)));
    const auto ack = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(ack.empty());
    ASSERT_EQ(frame_type(ack), "ACK") << "the connection must be established before it can be closed";
    ASSERT_TRUE(deps->wait_for_ready(std::chrono::seconds{5}));
    auto ready = deps->take_ready_connection();
    ASSERT_NE(ready, nullptr);
    // Take the connection into service, as ServerSecureChannel does. The post-handshake read pump is
    // what observes a peer close; without callbacks the test closes a deliberately idle transport.
    ready->set_callbacks([](ua::StatusCode, std::vector<ua::byte>&&) {},
      [](ua::StatusCode, ua::string_view, ua::FatalCloseDisposition) {});

    // Park the established connection, then consume the spare that establishment itself produces
    // (SVR-RC-014), so the socket asserted on below can only be the replacement for the close.
    auto established = peer.take_accepted();
    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}))
      << "no spare followed establishment; the close-replacement could not be told apart";
    const auto spareRhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(spareRhe.empty());
    ASSERT_EQ(frame_type(spareRhe), "RHE");
    auto spare = peer.take_accepted();

    // The client closes the reverse-connected channel.
    boost::system::error_code closeError;
    established.close(closeError);

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{3}))
      << "a reverse connection closed by the client was never replaced by a new socket";
    const auto replacementRhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(replacementRhe.empty()) << "the replacement socket carried no message at all";
    EXPECT_EQ(frame_type(replacementRhe), "RHE") << "the replacement socket must carry a new ReverseHello";
    const auto decoded = ua::detail::decode_reverse_hello(replacementRhe);
    ASSERT_TRUE(decoded.is_good()) << "the replacement frame did not decode as a ReverseHello: 0x" << std::hex
                                   << decoded.status_code().as_uint32();
    EXPECT_EQ(decoded.value().endpointUrl, target.serverEndpointUrl)
      << "the new ReverseHello must advertise the same target's endpoint";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

    std::promise<VoidResult> closed;
    ready->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
    EXPECT_EQ(closed.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }
}

// Part 6 section 7.1.3: "When a SecureChannel is established, the Server shall immediately create a new
// socket and sends a new ReverseHello to ensure the Client is able to create another SecureChannel
// if it is needed." The client cannot dial, so a server that only replaces a connection once the
// previous one has gone leaves the client with no way to obtain a second channel; the word that
// carries the obligation is "immediately", which a plausible implementation dilutes by letting the
// periodic timer supply the next socket. The configured interval is set to ten minutes here, so a
// socket arriving within seconds can only have come from establishment itself, and the established
// connection is parked open so it is not the thing that triggered the replacement.
// @verifies AC-SVR-RC-014-NEW-SOCKET-ON-CHANNEL-ESTABLISHED
TEST_F(ServerReverseConnectListenerTest, EstablishingAConnectionImmediatelyOpensAnotherSocketAndReverseHello)
{
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  deps->serverUri = "urn:test:server:spare-connection";
  ReverseConnectPeer peer;

  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
  target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
  target.periodicConnectInterval = std::chrono::seconds{600};

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
  const auto rhe = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(rhe.empty());
  ASSERT_EQ(frame_type(rhe), "RHE");

  ASSERT_TRUE(peer.write_all(build_hello(target.serverEndpointUrl, 32768, 16384, 2 * 1024 * 1024, 64)));
  const auto ack = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(ack.empty());
  ASSERT_EQ(frame_type(ack), "ACK") << "the connection must be established before the spare is due";
  ASSERT_TRUE(deps->wait_for_ready(std::chrono::seconds{5}));
  auto ready = deps->take_ready_connection();
  ASSERT_NE(ready, nullptr);

  // Keep the established connection open - the spare must be an additional socket, not a
  // replacement for one that went away.
  auto established = peer.take_accepted();

  const auto establishedAt = std::chrono::steady_clock::now();
  ASSERT_TRUE(peer.accept_one(std::chrono::seconds{3}))
    << "establishing a connection opened no further socket to the same target";
  const auto spareAfter =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - establishedAt);
  EXPECT_LT(spareAfter, std::chrono::milliseconds{3000})
    << "the spare must follow establishment immediately, not be paced by the periodic interval";

  const auto spareRhe = read_frame(peer, std::chrono::seconds{5});
  ASSERT_FALSE(spareRhe.empty()) << "the additional socket carried no message at all";
  EXPECT_EQ(frame_type(spareRhe), "RHE") << "the additional socket must carry a new ReverseHello";
  const auto decoded = ua::detail::decode_reverse_hello(spareRhe);
  ASSERT_TRUE(decoded.is_good()) << "the spare's first frame did not decode as a ReverseHello: 0x" << std::hex
                                 << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().serverUri, deps->serverUri)
    << "the spare's ReverseHello must come from the same server";
  EXPECT_EQ(decoded.value().endpointUrl, target.serverEndpointUrl)
    << "the spare must be offered to the same target, advertising the same endpoint";

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  std::promise<VoidResult> closed;
  ready->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
  EXPECT_EQ(closed.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// Part 4 section 6.7: the Server "is not able to actively check the connection status; therefore the Server
// shall initiate a new connection in a configurable interval, even if a connection to the Client is
// established". A connection lost without a clean close leaves the Server nothing to fail on, so a
// design that reconnects only in response to an observed error stops dialling forever - and one that
// dials in a hard-coded or absent interval is equally wrong. Both failure shapes are covered: the
// short-interval phase catches "once or never", and the long-interval phase catches an interval that
// is not actually read from the target's configuration.
// @verifies AC-SVR-RC-015-RECONNECT-INTERVAL
TEST_F(ServerReverseConnectListenerTest, ReverseConnectDialsRepeatedlyAtTheConfiguredInterval)
{
  // Phase 1: a one-second interval must produce repeated dials, paced rather than spun.
  int shortIntervalDials{0};
  {
    boost::asio::io_context acceptorIoc;
    boost::asio::ip::tcp::acceptor acceptor(
      acceptorIoc, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    const uint16_t port = acceptor.local_endpoint().port();

    std::atomic<int> acceptedCount{0};
    std::mutex socketsMutex;
    std::vector<boost::asio::ip::tcp::socket> acceptedSockets;

    std::function<void()> acceptNext;
    acceptNext = [&]()
    {
      auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptorIoc);
      acceptor.async_accept(*socket,
        [&, socket](boost::system::error_code ec)
        {
          if (ec)
            return;
          {
            std::lock_guard<std::mutex> guard(socketsMutex);
            acceptedSockets.push_back(std::move(*socket));
          }
          acceptedCount.fetch_add(1, std::memory_order_relaxed);
          acceptNext();
        });
    };
    acceptNext();
    std::thread acceptorThread([&]() { acceptorIoc.run(); });

    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", port));
    target.periodicConnectInterval = std::chrono::seconds{1};
    target.maxPendingSockets = 0;  // the cap is a separate obligation; do not let it mask the timer

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    std::this_thread::sleep_for(std::chrono::milliseconds{4300});
    shortIntervalDials = acceptedCount.load(std::memory_order_relaxed);

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

    acceptorIoc.stop();
    acceptorThread.join();
  }

  EXPECT_GE(shortIntervalDials, 3)
    << "a one-second interval produced " << shortIntervalDials
    << " connections in four seconds: the server retried once or never, not repeatedly";
  EXPECT_LE(shortIntervalDials, 12)
    << "the server dialled " << shortIntervalDials
    << " times in four seconds: retries are not paced by the configured interval";

  // Phase 2: a ten-second interval must produce only the initial dial in the same window, proving
  // the interval comes from the target's configuration.
  int longIntervalDials{0};
  {
    boost::asio::io_context acceptorIoc;
    boost::asio::ip::tcp::acceptor acceptor(
      acceptorIoc, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    const uint16_t port = acceptor.local_endpoint().port();

    std::atomic<int> acceptedCount{0};
    std::mutex socketsMutex;
    std::vector<boost::asio::ip::tcp::socket> acceptedSockets;

    std::function<void()> acceptNext;
    acceptNext = [&]()
    {
      auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptorIoc);
      acceptor.async_accept(*socket,
        [&, socket](boost::system::error_code ec)
        {
          if (ec)
            return;
          {
            std::lock_guard<std::mutex> guard(socketsMutex);
            acceptedSockets.push_back(std::move(*socket));
          }
          acceptedCount.fetch_add(1, std::memory_order_relaxed);
          acceptNext();
        });
    };
    acceptNext();
    std::thread acceptorThread([&]() { acceptorIoc.run(); });

    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", port));
    target.periodicConnectInterval = std::chrono::seconds{10};
    target.maxPendingSockets = 0;

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    std::this_thread::sleep_for(std::chrono::milliseconds{3500});
    longIntervalDials = acceptedCount.load(std::memory_order_relaxed);

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

    acceptorIoc.stop();
    acceptorThread.join();
  }

  ASSERT_GE(longIntervalDials, 1) << "the long-interval target never dialled at all";
  EXPECT_EQ(longIntervalDials, 1)
    << "a ten-second interval produced " << longIntervalDials
    << " connections in three and a half seconds: the interval is not the configured one";
}

// Part 6 section 7.1.3: "Administrators may limit the number of simultaneous sockets that a Server will
// create." Reverse connect makes the Server the dialler, so the periodic timer that satisfies
// SVR-RC-015 is also a connection flood waiting to happen: each tick opens another socket, and
// nothing in the Client's behaviour throttles it. The plausible implementation checks the cap only
// where it first wrote it - on the establishment path - and lets the timer overshoot it. Nothing
// closes a socket during the measured window, so the accepted count is the simultaneous count.
// @verifies AC-SVR-RC-016-SOCKET-LIMIT
TEST_F(ServerReverseConnectListenerTest, SimultaneousReverseConnectSocketsDoNotExceedTheConfiguredLimit)
{
  constexpr int socketLimit{2};

  boost::asio::io_context acceptorIoc;
  boost::asio::ip::tcp::acceptor acceptor(
    acceptorIoc, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
  const uint16_t port = acceptor.local_endpoint().port();

  std::atomic<int> acceptedCount{0};
  std::mutex socketsMutex;
  std::vector<boost::asio::ip::tcp::socket> acceptedSockets;

  std::function<void()> acceptNext;
  acceptNext = [&]()
  {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptorIoc);
    acceptor.async_accept(*socket,
      [&, socket](boost::system::error_code ec)
      {
        if (ec)
          return;
        {
          std::lock_guard<std::mutex> guard(socketsMutex);
          acceptedSockets.push_back(std::move(*socket));
        }
        acceptedCount.fetch_add(1, std::memory_order_relaxed);
        acceptNext();
      });
  };
  acceptNext();
  std::thread acceptorThread([&]() { acceptorIoc.run(); });

  // Live connection-protocol dependencies, so every accepted socket really becomes a pending
  // reverse connection rather than being dropped and freeing its slot again. The peer never answers
  // the ReverseHello, so each socket stays pending for the whole window.
  auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
  auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", port));
  target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
  target.periodicConnectInterval = std::chrono::seconds{1};
  target.maxPendingSockets = static_cast<uint32_t>(socketLimit);

  auto manager = ReverseConnectListener::create(deps, target);
  ASSERT_NE(manager, nullptr);
  manager->start();

  std::this_thread::sleep_for(std::chrono::milliseconds{3500});
  const int openSockets = acceptedCount.load(std::memory_order_relaxed);

  std::promise<VoidResult> stopped;
  manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  acceptorIoc.stop();
  acceptorThread.join();

  ASSERT_GE(openSockets, 1) << "the target never dialled at all; the limit was never exercised";
  EXPECT_GE(openSockets, socketLimit) << "only " << openSockets
                                      << " sockets were opened: the periodic tick stopped short of the cap, "
                                         "so the cap itself was not what bounded the count";
  EXPECT_LE(openSockets, socketLimit)
    << openSockets << " simultaneous sockets were open against a configured limit of " << socketLimit;
}

// The repository's async contract, recorded as SVR-RC-023: an `*_async` implementation must not
// substitute a good Result for a bad downstream one. Reverse connect inverts who dials, so a failure
// arrives on a path the application never initiated - a failure reported only to the log leaves the
// application waiting for a connection that will never be reported as failed. The three stages fail
// in three different places (the connector, the transport read pump, the handshake validator), and
// an implementation that surfaces the one it wrote first and logs the rest looks healthy in any test
// that exercises a single stage. Every stage is checked for all three conjuncts: an error was
// delivered at all, its StatusCode is bad, and it carries an ErrorDetail rather than a bare status.
// @verifies AC-SVR-RC-023-REVERSE-CONNECT-ERRORS
TEST_F(ServerReverseConnectListenerTest, EveryReverseConnectFailureStageSurfacesABadResultWithItsCause)
{
  // Stage 1: the outbound socket is refused.
  StatusCode refusedStatus;
  std::string refusedSummary;
  {
    auto deps = std::make_shared<FakeReverseConnectListenerDeps>(mExecutor);
    auto manager = ReverseConnectListener::create(deps, make_target("opc.tcp://127.0.0.1:19999"));
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(deps->wait_for_errors(1, std::chrono::seconds{10}))
      << "a refused outbound socket was reported only in a log, never as a Result";
    {
      std::lock_guard<std::mutex> guard(deps->errorMutex);
      refusedStatus = deps->lastErrorStatus;
      refusedSummary = deps->lastErrorDescription;
    }

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{10}), std::future_status::ready);
  }

  // Stage 2: the peer closes the connection before the handshake completes.
  StatusCode droppedStatus;
  std::string droppedSummary;
  {
    auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
    ReverseConnectPeer peer;

    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
    target.periodicConnectInterval = std::chrono::seconds{600};

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
    const auto rhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(rhe.empty());
    ASSERT_EQ(frame_type(rhe), "RHE") << "the handshake must have started before it can be cut short";
    {
      auto dropped = peer.take_accepted();
      boost::system::error_code ignored;
      dropped.close(ignored);
    }

    ASSERT_TRUE(deps->wait_for_errors(1, std::chrono::seconds{10}))
      << "a peer that vanished mid-handshake was reported only in a log, never as a Result";
    {
      std::lock_guard<std::mutex> guard(deps->errorMutex);
      droppedStatus = deps->lastErrorStatus;
      droppedSummary = deps->lastErrorDescription;
    }

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{10}), std::future_status::ready);
  }

  // Stage 3: the handshake itself is rejected - a HEL whose buffer sizes are below the absolute
  // minimum, which the server must refuse rather than negotiate.
  StatusCode rejectedStatus;
  std::string rejectedSummary;
  {
    auto deps = std::make_shared<HandshakingReverseConnectDeps>(mExecutor);
    ReverseConnectPeer peer;

    auto target = make_target(fmt::format("opc.tcp://127.0.0.1:{}", peer.port()));
    target.serverEndpointUrl = "opc.tcp://server.example:4855/UA/Advertised";
    target.periodicConnectInterval = std::chrono::seconds{600};

    auto manager = ReverseConnectListener::create(deps, target);
    ASSERT_NE(manager, nullptr);
    manager->start();

    ASSERT_TRUE(peer.accept_one(std::chrono::seconds{5}));
    const auto rhe = read_frame(peer, std::chrono::seconds{5});
    ASSERT_FALSE(rhe.empty());
    ASSERT_EQ(frame_type(rhe), "RHE");

    ASSERT_TRUE(peer.write_all(build_hello(target.serverEndpointUrl, 100, 100, 65536, 8)))
      << "the rejected HEL was never delivered";

    ASSERT_TRUE(deps->wait_for_errors(1, std::chrono::seconds{10}))
      << "a rejected handshake was reported only in a log, never as a Result";
    {
      std::lock_guard<std::mutex> guard(deps->errorMutex);
      rejectedStatus = deps->lastErrorStatus;
      rejectedSummary = deps->lastErrorDescription;
    }
    EXPECT_EQ(deps->connectionReadyCount.load(), 0)
      << "the rejected handshake was delivered upward as a ready connection";

    std::promise<VoidResult> stopped;
    manager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
    ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{10}), std::future_status::ready);
  }

  EXPECT_TRUE(refusedStatus.is_bad()) << "a refused socket surfaced a good Result";
  EXPECT_TRUE(droppedStatus.is_bad()) << "a dropped connection surfaced a good Result";
  EXPECT_TRUE(rejectedStatus.is_bad()) << "a rejected handshake surfaced a good Result";

  EXPECT_FALSE(refusedSummary.empty()) << "the refused-socket Result carried no ErrorDetail";
  EXPECT_FALSE(droppedSummary.empty()) << "the dropped-connection Result carried no ErrorDetail";
  EXPECT_FALSE(rejectedSummary.empty()) << "the rejected-handshake Result carried no ErrorDetail";

  EXPECT_NE(refusedSummary, droppedSummary)
    << "the ErrorDetail must name the stage that failed, not a single generic cause";
  EXPECT_NE(rejectedSummary, refusedSummary)
    << "the rejected-handshake ErrorDetail must be distinct from a refused outbound socket";
  EXPECT_NE(rejectedSummary, droppedSummary)
    << "the rejected-handshake ErrorDetail must be distinct from a peer dropping mid-handshake";
}

}  // namespace
