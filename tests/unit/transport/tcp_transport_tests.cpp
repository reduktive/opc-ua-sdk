// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <array>
#include <stdexcept>

#include "test_utilities.h"
#include "fmt/format.h"
#include "ua_tcp_transport_acceptor.h"
#include "ua_tcp_transport_connector.h"
#include "ua_tcp_transport_connection.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>

using namespace ua;
using namespace std::chrono_literals;

// A port already in use is the most common deployment failure a server hits, and it used to
// escape as a raw boost::system::system_error - which the generic conversion flattened to
// BadInternalError, a status that reads as an SDK defect. Pin the operator-actionable shape:
// a resource status, the symbolic step that failed, and the address/port/OS-reason triple that
// says which listener to fix.
TEST(TcpTransportTests, BindToAPortAlreadyInUseReportsTheAddressAndTheOsReason)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  TcpTransportAcceptor::NewConnectionCallback newConnectionCallback =
    [](StatusCode, string_view, shared_ptr<TcpTransportConnection>) {
    };

  asio::ip::tcp::endpoint ephemeral{asio::ip::make_address("127.0.0.1"), 0};
  auto first = TcpTransportAcceptor::create(executor, ephemeral, newConnectionCallback);
  const auto taken = first->get_local_endpoint();

  try
  {
    auto second = TcpTransportAcceptor::create(executor, taken, newConnectionCallback);
    FAIL() << "expected the second bind on " << taken.port() << " to be refused";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadResourceUnavailable);
    const auto* detail = ex.detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "ListenerBindFailed");

    auto contextValue = [&](ContextKey key) -> std::string
    {
      for (const auto& entry : detail->context)
      {
        if (entry.key == key.value())
        {
          return entry.value;
        }
      }
      return {};
    };
    EXPECT_EQ(contextValue(ContextKeys::endpointAddress), "127.0.0.1");
    EXPECT_EQ(contextValue(ContextKeys::endpointPort), std::to_string(taken.port()));
    // The OS reason is passed through verbatim rather than re-worded, so the message the
    // operator sees matches what every other tool on the box reports.
    EXPECT_FALSE(contextValue(ContextKeys::errorMessage).empty());
  }

  threadPool.stop();
  threadPool.join();
}

TEST(TcpTransportTests, Connect)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  std::condition_variable cv;
  std::mutex mtx;

  TcpTransportAcceptor::NewConnectionCallback newConnectionCallback =
    [](StatusCode status, string_view statusDescription, shared_ptr<TcpTransportConnection>)
  {
    if (status.is_bad())
    {
      fmt::print("TcpTransportAcceptor async_accept failed with {}\n", statusDescription);
    }
  };

  // Use an ephemeral port for tests to avoid port conflicts.
  asio::ip::tcp::endpoint ipEndpoint{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = TcpTransportAcceptor::create(executor, ipEndpoint, newConnectionCallback);
  const auto boundEndpoint = acceptor->get_local_endpoint();

  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 1s);
  }

  std::atomic<bool> connected{false};

  TcpTransportConnector::ConnectedCallback connectedCallback =
    [&cv, &connected](
      StatusCode status, string_view statusDescription, shared_ptr<TcpTransportConnection> connection)
  {
    if (status.is_good() && connection)
    {
      connected = true;
    }
    else
    {
      fmt::print("TcpTransportConnector connect failed with {}\n", statusDescription);
    }
    cv.notify_all();
  };

  auto connector = TcpTransportConnector::create(executor, boundEndpoint, connectedCallback);

  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 1s);
  }

  GTEST_ASSERT_TRUE(connected);

  // Tear the acceptor down via its documented shutdown contract, not by simply
  // dropping the shared_ptr. `connected` is set by the *client* connect
  // callback, which can fire while the *server*-side async_accept that
  // satisfied it is still completing on a pool thread - boost::asio assigns the
  // accepted socket into mSocket on the worker before our handler runs.
  // Resetting the acceptor here would free mSocket from under that in-flight
  // do_assign (the data race TSan reported). close_async() cancels the accept
  // loop; draining the pool joins every worker so nothing touches the acceptor
  // when it is finally destroyed at end of scope.
  acceptor->close_async();
  connector.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
  acceptor.reset();
}

// The connect callback runs inside an Asio completion handler: an exception out of it would leave the
// handler and end the process. It is caught and logged, the pool thread keeps running, and a close issued
// from inside the callback still completes. (That the callback now runs outside the connector's lock has no
// observable here: close_async is posted to the connector's strand and never takes the lock re-entrantly,
// so the lock move is design coverage.)
// @verifies AC-COMP-CORE-CONNECTION-PROTOCOL-04-A-CONNECT-CALLBACK-CANNOT-END-THE-PROCESS
TEST(TcpTransportTests, AThrowingConnectCallbackDoesNotEndTheProcess)
{
  boost::asio::thread_pool threadPool{1};
  auto executor = threadPool.get_executor();

  auto acceptor = TcpTransportAcceptor::create(executor,
    asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), 0},
    [](StatusCode, string_view, shared_ptr<TcpTransportConnection>) {});

  std::promise<void> called;
  std::promise<void> closed;
  std::shared_ptr<TcpTransportConnector> connector;
  std::mutex connectorMutex;
  {
    const std::lock_guard<std::mutex> lock(connectorMutex);
    connector = TcpTransportConnector::create(executor,
      acceptor->get_local_endpoint(),
      [&](StatusCode, string_view, shared_ptr<TcpTransportConnection>)
      {
        {
          const std::lock_guard<std::mutex> inner(connectorMutex);
          connector->close_async([&closed](VoidResult) { closed.set_value(); });
        }
        called.set_value();
        throw std::runtime_error{"connect callback failure"};
      });
  }

  ASSERT_EQ(called.get_future().wait_for(5s), std::future_status::ready);
  EXPECT_EQ(closed.get_future().wait_for(5s), std::future_status::ready)
    << "a close issued from the callback completes";
  std::promise<void> later;
  boost::asio::post(executor, [&later] { later.set_value(); });
  EXPECT_EQ(later.get_future().wait_for(5s), std::future_status::ready)
    << "the pool thread survived the throw";

  acceptor->close_async();
  {
    const std::lock_guard<std::mutex> lock(connectorMutex);
    connector.reset();
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
  acceptor.reset();
}

// The peer-closed probe the reverse-connect listener uses on connections with no read armed: an open
// connection is reported open (with and without data waiting, which it does not consume), and one whose peer
// has closed is reported closed.
// @verifies AC-CL-RC-007-A-FULL-REVERSE-CONNECT-QUEUE-REFUSES-THE-NEWCOMER
TEST(TcpTransportTests, ThePeerClosedProbeTellsAnOpenConnectionFromAClosedOne)
{
  boost::asio::io_context ioc;
  asio::ip::tcp::acceptor acceptor{ioc, asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
  asio::ip::tcp::socket client{ioc};
  client.connect(acceptor.local_endpoint());
  auto transport = TcpTransportConnection::create(acceptor.accept());

  using PeerState = ua::TransportConnection::PeerState;
  EXPECT_EQ(transport->peer_state(), PeerState::Open) << "an open, silent connection";
  const std::array<char, 3> payload{'a', 'b', 'c'};
  asio::write(client, asio::buffer(payload));
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (transport->bytes_available_to_read() < payload.size() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  EXPECT_EQ(transport->peer_state(), PeerState::DataWaiting) << "an open connection with data waiting";
  EXPECT_EQ(transport->bytes_available_to_read(), payload.size()) << "the probe consumes nothing";

  // Drain the data so the next probe sees the end of stream, then close the client side.
  std::vector<byte> drained(payload.size());
  ASSERT_TRUE(transport->read(drained).is_good());
  client.close();
  bool closed = false;
  const auto closeDeadline = std::chrono::steady_clock::now() + 2s;
  while (!(closed = transport->peer_state() == PeerState::Closed) &&
         std::chrono::steady_clock::now() < closeDeadline)
    std::this_thread::sleep_for(1ms);
  EXPECT_TRUE(closed) << "a connection whose peer closed";
}

TEST(TcpTransportTests, ConnectFallsThroughResolvedEndpointsAfterFirstAddressRefused)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto acceptor = TcpTransportAcceptor::create(executor,
    asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), 0},
    [](StatusCode, string_view, shared_ptr<TcpTransportConnection>) {});
  const auto liveEndpoint = acceptor->get_local_endpoint();
  const asio::ip::tcp::endpoint refusedIpv6Endpoint{asio::ip::address_v6::loopback(), liveEndpoint.port()};

  std::promise<bool> connected;
  auto connectedFuture = connected.get_future();
  auto connector = TcpTransportConnector::create(executor,
    std::vector<asio::ip::tcp::endpoint>{refusedIpv6Endpoint, liveEndpoint},
    [&connected](StatusCode status, string_view, shared_ptr<TcpTransportConnection> connection)
    { connected.set_value(status.is_good() && connection != nullptr); });

  ASSERT_EQ(connectedFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(connectedFuture.get())
    << "a refusal from the first resolved address must fall through to the next address";

  acceptor->close_async();
  connector.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
  acceptor.reset();
}

// Synchronisation state shared between the accept/connect callbacks (which run
// on a pool thread) and the waiting test thread. It is held via shared_ptr and
// captured by value, so it outlives the callbacks even if a cancelled accept or
// connect handler fires after create_connections() has returned - avoiding both
// the "destroy condition_variable while a notify is in flight" race and a
// use-after-free on the local state. The flag is set and the cv notified under
// the mutex, establishing a happens-before with the waiter's predicate read.
struct ConnectSyncState
{
  std::mutex mutex;
  std::condition_variable condition;
  bool ready{false};
  shared_ptr<TcpTransportConnection> connection;

  void signal(shared_ptr<TcpTransportConnection> established)
  {
    std::lock_guard<std::mutex> lock(mutex);
    connection = std::move(established);
    ready = true;
    condition.notify_all();
  }

  shared_ptr<TcpTransportConnection> wait()
  {
    std::unique_lock<std::mutex> lock(mutex);
    condition.wait_for(lock, 1s, [this]() { return ready; });
    return connection;
  }
};

std::vector<shared_ptr<TcpTransportConnection>> create_connections(boost::asio::any_io_executor executor)
{
  auto serverState = std::make_shared<ConnectSyncState>();

  TcpTransportAcceptor::NewConnectionCallback newConnectionCallback =
    [serverState](
      StatusCode status, string_view statusDescription, shared_ptr<TcpTransportConnection> connection)
  {
    if (status.is_bad())
    {
      fmt::print("TcpTransportAcceptor async_accept failed with {}\n", statusDescription);
    }
    serverState->signal(std::move(connection));
  };

  // Use an ephemeral port for tests to avoid port conflicts.
  asio::ip::tcp::endpoint ipEndpoint{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = TcpTransportAcceptor::create(executor, ipEndpoint, newConnectionCallback);
  const auto boundEndpoint = acceptor->get_local_endpoint();

  auto clientState = std::make_shared<ConnectSyncState>();

  TcpTransportConnector::ConnectedCallback connectedCallback =
    [clientState](
      StatusCode status, string_view statusDescription, shared_ptr<TcpTransportConnection> connection)
  {
    if (status.is_good() && connection)
    {
      clientState->signal(std::move(connection));
    }
    else
    {
      fmt::print("TcpTransportConnector connect failed with {}\n", statusDescription);
      clientState->signal(nullptr);
    }
  };

  auto connector = TcpTransportConnector::create(executor, boundEndpoint, connectedCallback);

  shared_ptr<TcpTransportConnection> clientConnection = clientState->wait();
  shared_ptr<TcpTransportConnection> serverConnection = serverState->wait();

  GTEST_EXPECT_TRUE(clientConnection);
  GTEST_EXPECT_TRUE(serverConnection);

  std::vector<shared_ptr<TcpTransportConnection>> connections;
  connections.push_back(clientConnection);
  connections.push_back(serverConnection);

  return connections;
}

namespace ua
{
struct TcpTransportConnectionTestAccess
{
  static boost::asio::any_io_executor socket_executor(TcpTransportConnection& connection)
  {
    return connection.mSocket.get_executor();
  }
};
}  // namespace ua

// asio::async_read and asio::async_write re-issue their partial operations from completion handlers that
// run on the socket's executor and take no SDK lock, and close_async runs close() on that same executor.
// On a multi-threaded pool those run on different threads at once, which a socket does not allow; an
// accepted socket therefore runs on a strand, and a strand of its own, so connections do not serialize
// each other.
// @relation(AC-TRANSPORT-ACCEPTED-SOCKET-ON-OWN-STRAND, scope=function)
TEST(TcpTransportTests, EachAcceptedSocketRunsOnAStrandOfItsOwn)
{
  boost::asio::thread_pool threadPool{4};
  auto first = create_connections(threadPool.get_executor());
  auto second = create_connections(threadPool.get_executor());
  ASSERT_EQ(first.size(), 2u);
  ASSERT_EQ(second.size(), 2u);
  ASSERT_TRUE(first[1] && second[1]);

  using SocketStrand = boost::asio::strand<boost::asio::any_io_executor>;
  auto firstExecutor = TcpTransportConnectionTestAccess::socket_executor(*first[1]);
  auto secondExecutor = TcpTransportConnectionTestAccess::socket_executor(*second[1]);
  const auto* firstStrand = firstExecutor.target<SocketStrand>();
  const auto* secondStrand = secondExecutor.target<SocketStrand>();
  ASSERT_NE(firstStrand, nullptr) << "an accepted socket runs on the bare pool executor";
  ASSERT_NE(secondStrand, nullptr) << "an accepted socket runs on the bare pool executor";
  EXPECT_FALSE(*firstStrand == *secondStrand) << "two accepted connections share one strand";

  for (auto& connection : first)
    connection->close_async();
  for (auto& connection : second)
    connection->close_async();
  threadPool.join();
}

TEST(TcpTransportTests, ReadAndWrite)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto connections = create_connections(executor);
  auto clientConnection = connections[0];
  auto serverConnection = connections[1];

  TransportConnection::ErrorCallback errorCallback = [](StatusCode status, string_view statusDescription)
  {
    fmt::print("TransportConnection::ErrorCallback status.is_good(): {}, statusDescription: {}\n",
      status.is_good(),
      statusDescription);
  };

  std::condition_variable cv1, cv2;
  std::mutex mtx1, mtx2;

  std::atomic<bool> dataSent{false};

  TransportConnection::WriteCompleteCallback writeCompleteCallback =
    [&cv2, &dataSent](StatusCode status, string_view statusDescription)
  {
    fmt::print("TransportConnection::WriteCompleteCallback status.is_good(): {}, statusDescription: {}\n",
      status.is_good(),
      statusDescription);
    dataSent = true;
    cv2.notify_all();
  };

  std::atomic<bool> dataReceived{false};
  std::mutex receivedMtx;
  std::vector<byte> receivedData;

  TransportConnection::ReadCompleteCallback readCompleteCallback =
    [&cv1, &dataReceived, &receivedMtx, &receivedData](
      StatusCode status, string_view statusDescription, std::vector<byte>&& buffer)
  {
    fmt::print(
      "TransportConnection::ReadCompleteCallback status.is_good(): {}, statusDescription: {}, bytesRead: "
      "{}\n",
      status.is_good(),
      statusDescription,
      buffer.size());
    {
      std::lock_guard lk(receivedMtx);
      receivedData = std::move(buffer);
    }
    dataReceived = true;
    cv1.notify_all();
  };

  clientConnection->register_error_callback(errorCallback);
  clientConnection->register_read_callback(readCompleteCallback);
  clientConnection->register_write_callback(writeCompleteCallback);

  serverConnection->register_error_callback(errorCallback);
  serverConnection->register_read_callback(readCompleteCallback);
  serverConnection->register_write_callback(writeCompleteCallback);

  const std::vector<byte> expectedData{byte{0x01}, byte{0x02}, byte{0x03}};
  std::vector<byte> dataToSend = expectedData;
  clientConnection->async_write(std::move(dataToSend));
  std::vector<byte> readBuffer;
  readBuffer.resize(3);
  serverConnection->async_read(std::move(readBuffer));

  std::unique_lock<std::mutex> lock2(mtx2);
  cv2.wait_for(lock2, 1s, [&dataSent]() { return dataSent.load(); });
  std::unique_lock<std::mutex> lock1(mtx1);
  cv1.wait_for(lock1, 1s, [&dataReceived]() { return dataReceived.load(); });

  ASSERT_TRUE(dataSent);
  ASSERT_TRUE(dataReceived);
  std::lock_guard lk(receivedMtx);
  EXPECT_EQ(receivedData, expectedData);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Regression test for the race in TcpTransportConnection::write() / completion handler.
// Pre-fix, the completion handler released the mutex after clearing mActive*, then
// re-acquired it to call write() and drain mPendingWriteBuffers. During that gap a
// concurrent async_write() caller could see mActiveWriteBuffers empty and submit its
// own asio::async_write - and then the original completion handler's write() would
// append more buffers to mActiveAsioWriteBuffers and submit a second concurrent
// asio::async_write on the same socket. Asio forbids concurrent writes on a socket;
// the symptom was a write callback reporting BadTcpInternalError because asio's
// internal byte accounting got confused (bytesWritten != bytesToWrite with ec=success).
TEST(TcpTransportTests, ConcurrentAsyncWritesNeverOverlap)
{
  boost::asio::thread_pool threadPool{4};
  auto executor = threadPool.get_executor();
  auto connections = create_connections(executor);
  auto clientConnection = connections[0];
  auto serverConnection = connections[1];

  std::atomic<size_t> badWriteCount{0};
  std::atomic<size_t> writeCallbackInvocations{0};

  TransportConnection::ErrorCallback noopError = [](StatusCode, string_view) {
  };

  TransportConnection::WriteCompleteCallback writeCompleteCallback =
    [&badWriteCount, &writeCallbackInvocations](StatusCode status, string_view)
  {
    ++writeCallbackInvocations;
    if (status.is_bad())
      ++badWriteCount;
  };

  clientConnection->register_error_callback(noopError);
  clientConnection->register_write_callback(writeCompleteCallback);
  serverConnection->register_error_callback(noopError);

  constexpr size_t writerCount = 8;
  constexpr size_t iterationsPerWriter = 200;
  constexpr size_t bytesPerWrite = 113;  // Mirrors the buffer size from the CI failure.
  const size_t totalBytes = writerCount * iterationsPerWriter * bytesPerWrite;

  std::condition_variable readCv;
  std::mutex readMtx;
  bool readDone{false};
  std::atomic<bool> readError{false};
  size_t readBytesObserved{0};

  TransportConnection::ReadCompleteCallback readCompleteCallback =
    [&readCv, &readMtx, &readDone, &readError, &readBytesObserved](
      StatusCode status, string_view, std::vector<byte>&& buffer)
  {
    if (status.is_bad())
      readError.store(true);
    {
      std::lock_guard lk(readMtx);
      readBytesObserved = buffer.size();
      readDone = true;
    }
    readCv.notify_all();
  };

  serverConnection->register_read_callback(readCompleteCallback);

  std::vector<byte> readBuffer(totalBytes);
  serverConnection->async_read(std::move(readBuffer));

  std::vector<std::thread> writers;
  writers.reserve(writerCount);
  for (size_t w = 0; w < writerCount; ++w)
  {
    writers.emplace_back(
      [clientConnection, w]()
      {
        const auto fillByte = byte{static_cast<unsigned char>(w & 0xFF)};
        for (size_t i = 0; i < iterationsPerWriter; ++i)
        {
          std::vector<byte> chunk(bytesPerWrite, fillByte);
          clientConnection->async_write(std::move(chunk));
        }
      });
  }

  for (auto& t : writers)
    t.join();

  {
    std::unique_lock<std::mutex> lk(readMtx);
    readCv.wait_for(lk, 30s, [&readDone]() { return readDone; });
  }

  EXPECT_TRUE(readDone) << "Read did not complete - concurrent writes may have stalled the socket";
  EXPECT_FALSE(readError.load());
  EXPECT_EQ(readBytesObserved, totalBytes);
  EXPECT_EQ(badWriteCount.load(), 0u)
    << "Write callback reported BadTcpInternalError - concurrent asio::async_writes overlapped";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// --- close_async drain semantics --------------------------------------------

TEST(TcpTransportTests, ConnectionCloseAsyncFiresCallback)
{
  boost::asio::thread_pool threadPool;
  auto connections = create_connections(threadPool.get_executor());
  ASSERT_EQ(connections.size(), 2u);

  std::promise<void> done;
  auto fut = done.get_future();
  connections[0]->close_async([&done](VoidResult) { done.set_value(); });

  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TcpTransportTests, ConnectionCloseAsyncCancelsPendingRead)
{
  // close_async on a connection with a pending async_read must cause the
  // read callback to fire (with a bad status) BEFORE the close_async user
  // callback fires, so callers know all in-flight reads have been resolved
  // by the time their close completion runs.
  boost::asio::thread_pool threadPool;
  auto connections = create_connections(threadPool.get_executor());
  ASSERT_EQ(connections.size(), 2u);
  auto& client = connections[0];

  std::atomic<bool> readFired{false};
  std::atomic<bool> closeFired{false};
  std::atomic<bool> readBeforeClose{false};

  client->register_read_callback(
    [&readFired, &closeFired, &readBeforeClose](StatusCode, string_view, std::vector<byte>&&)
    {
      readFired.store(true, std::memory_order_release);
      // Capture ordering: was close fired before this read callback?
      readBeforeClose.store(!closeFired.load(std::memory_order_acquire), std::memory_order_release);
    });

  // Queue a read for more bytes than will arrive - pending until close cancels.
  std::vector<byte> buf(64);
  client->async_read(std::move(buf));

  std::promise<void> closeDone;
  auto closeFut = closeDone.get_future();
  client->close_async(
    [&closeFired, &closeDone](VoidResult)
    {
      closeFired.store(true, std::memory_order_release);
      closeDone.set_value();
    });

  ASSERT_EQ(closeFut.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(closeFired.load());
  EXPECT_TRUE(readFired.load()) << "Read callback should fire (with operation_aborted error) on close";
  EXPECT_TRUE(readBeforeClose.load())
    << "Read cancellation handler must run before close_async callback (drain ordering)";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TcpTransportTests, ConnectionCloseAsyncIsIdempotent)
{
  boost::asio::thread_pool threadPool;
  auto connections = create_connections(threadPool.get_executor());
  ASSERT_EQ(connections.size(), 2u);

  std::promise<void> first;
  std::promise<void> second;
  auto firstFut = first.get_future();
  auto secondFut = second.get_future();

  connections[0]->close_async([&first](VoidResult) { first.set_value(); });
  connections[0]->close_async([&second](VoidResult) { second.set_value(); });

  EXPECT_EQ(firstFut.wait_for(2s), std::future_status::ready);
  EXPECT_EQ(secondFut.wait_for(2s), std::future_status::ready);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TcpTransportTests, AcceptorCloseAsyncFiresCallback)
{
  boost::asio::thread_pool threadPool;
  auto acceptor = TcpTransportAcceptor::create(threadPool.get_executor(),
    asio::ip::tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0},
    [](StatusCode, string_view, shared_ptr<TcpTransportConnection>) {});

  std::promise<void> done;
  auto fut = done.get_future();
  acceptor->close_async([&done](VoidResult) { done.set_value(); });

  EXPECT_EQ(fut.wait_for(2s), std::future_status::ready);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TcpTransportTests, AcceptorCloseAsyncStopsAcceptingNewConnections)
{
  // After close_async's callback fires, no further accept callbacks may
  // deliver successful connections (would indicate the listener is still
  // accepting after stop completion was signalled).
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  std::atomic<int> goodAccepts{0};

  auto acceptor = TcpTransportAcceptor::create(executor,
    asio::ip::tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0},
    [&goodAccepts](StatusCode status, string_view, shared_ptr<TcpTransportConnection>)
    {
      if (status.is_good())
        goodAccepts.fetch_add(1, std::memory_order_relaxed);
    });

  const auto bound = acceptor->get_local_endpoint();

  std::promise<void> closed;
  auto closedFut = closed.get_future();
  acceptor->close_async([&closed](VoidResult) { closed.set_value(); });
  ASSERT_EQ(closedFut.wait_for(2s), std::future_status::ready);

  // Try to connect - the acceptor is closed so no good accept should fire.
  // On Linux async_connect fails immediately with ECONNREFUSED; on Windows the
  // TCP stack may not deliver a RST promptly for a recently-closed ephemeral
  // port, so we cancel the connector explicitly to guarantee the callback fires
  // on all platforms rather than waiting for an OS-defined connect timeout.
  std::promise<bool> connectResult;
  auto connectFut = connectResult.get_future();
  auto connector = TcpTransportConnector::create(executor,
    bound,
    [&connectResult](StatusCode status, string_view, shared_ptr<TcpTransportConnection> conn)
    { connectResult.set_value(status.is_good() && conn != nullptr); });

  std::promise<void> connectorClosed;
  auto connectorClosedFut = connectorClosed.get_future();
  connector->close_async([&connectorClosed](VoidResult) { connectorClosed.set_value(); });
  ASSERT_EQ(connectorClosedFut.wait_for(2s), std::future_status::ready);

  // close_async drains the connect completion before firing its callback, so
  // connectFut is already ready at this point.
  ASSERT_EQ(connectFut.wait_for(0s), std::future_status::ready);
  EXPECT_FALSE(connectFut.get()) << "Connector should not succeed against a closed acceptor";
  EXPECT_EQ(goodAccepts.load(), 0) << "No good accept callback should fire after close_async completion";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TcpTransportTests, ConnectorCloseAsyncCancelsInflightConnect)
{
  // Use TEST-NET-1 (192.0.2.0/24, RFC 5737) - non-routable. async_connect
  // hangs; close_async must cancel it and drain within seconds.
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  std::atomic<bool> connectCallbackFired{false};

  auto connector = TcpTransportConnector::create(executor,
    asio::ip::tcp::endpoint{asio::ip::make_address("192.0.2.1"), 4840},
    [&connectCallbackFired](StatusCode, string_view, shared_ptr<TcpTransportConnection>)
    { connectCallbackFired.store(true, std::memory_order_release); });

  // Brief pause so async_connect has actually started.
  std::this_thread::sleep_for(50ms);

  std::promise<void> closed;
  auto closedFut = closed.get_future();
  connector->close_async([&closed](VoidResult) { closed.set_value(); });

  // Without cancellation this would block until the OS connect timeout (~60-90s).
  EXPECT_EQ(closedFut.wait_for(5s), std::future_status::ready)
    << "close_async must cancel an in-flight async_connect";
  EXPECT_TRUE(connectCallbackFired.load())
    << "Connect callback should fire (with operation_aborted) when socket is closed";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// P1.D #2: the pending-write queue is bounded. When a peer stops draining the socket, async_write
// fails closed (BadTcpNotEnoughResources) rather than letting the queue grow without limit.
//
// Determinism without timing: the io_context is never run, so the first async_write's asio operation
// stays "in flight" (mActiveWriteBuffers non-empty) and never completes. Every later write therefore
// accumulates in the pending queue until the cap is reached, at which point async_write fails closed.
TEST(TcpTransportTests, WriteQueueDepthCapFailsClosed)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();
  boost::asio::ip::tcp::socket clientSock(ioc);
  clientSock.connect({boost::asio::ip::address_v4::loopback(), port});
  auto serverSock = acceptor.accept();

  constexpr size_t cap = 4;
  auto conn = TcpTransportConnection::create(std::move(clientSock), Logger{}, cap);

  std::mutex m;
  std::vector<StatusCode> statuses;
  conn->register_write_callback(
    [&](StatusCode s, std::string_view)
    {
      std::lock_guard lk(m);
      statuses.push_back(s);
    });

  // Write #1 goes active (posted to the never-run io_context); the next cap fill the pending queue;
  // the one after that exceeds the cap and fails closed.
  for (size_t i = 0; i < cap + 2; ++i)
  {
    conn->async_write(std::vector<byte>(16, byte{0xAB}));
  }

  // The overflow callback fires synchronously inside async_write.
  {
    std::lock_guard lk(m);
    ASSERT_EQ(statuses.size(), 1u);
    EXPECT_EQ(statuses.back(), StatusCode{Status::BadTcpNotEnoughResources});
  }

  conn.reset();  // close the socket before the (never-run) io_context is destroyed
}

// A failed connect must say WHAT failed. Refused, unreachable and timed-out are different operator
// problems - a wrong port, a wrong host or a firewall silently dropping packets - and the distinction
// exists only in the error code the connect completed with. Reported as one blanket status it
// survives nowhere but a platform message, leaving a caller to string-match on text that varies by
// platform and locale.
TEST(TcpTransportConnectorStatusMapping, RefusedAndUnreachableMapToConnectionRejected)
{
  namespace errc = boost::system::errc;
  const auto status = [](auto code)
  {
    return ua::connect_failure_status(boost::system::error_code{make_error_code(code)}).as_status();
  };

  EXPECT_EQ(status(errc::connection_refused), ua::Status::BadConnectionRejected)
    << "nothing listening on that port";
  EXPECT_EQ(status(errc::host_unreachable), ua::Status::BadConnectionRejected)
    << "the host is not reachable from here";
  EXPECT_EQ(status(errc::network_unreachable), ua::Status::BadConnectionRejected)
    << "no route to that network";
  EXPECT_EQ(status(errc::network_down), ua::Status::BadConnectionRejected);
}

TEST(TcpTransportConnectorStatusMapping, TimedOutMapsToTimeout)
{
  const boost::system::error_code timedOut{make_error_code(boost::system::errc::timed_out)};
  EXPECT_EQ(ua::connect_failure_status(timedOut).as_status(), ua::Status::BadTimeout)
    << "a connect that never answered is a timeout, not an internal error";
}

TEST(TcpTransportConnectorStatusMapping, UnresolvableHostMapsToConnectionRejected)
{
  const boost::system::error_code notFound{boost::asio::error::host_not_found};
  EXPECT_EQ(ua::connect_failure_status(notFound).as_status(), ua::Status::BadConnectionRejected)
    << "a name that does not resolve is a rejected connection, not a transport-internal fault";
}

// An error the mapping does not recognise keeps the generic status rather than being forced into the
// nearest specific one - claiming "refused" for something that was not refused is worse than saying
// nothing, because it sends the operator to the wrong place.
TEST(TcpTransportConnectorStatusMapping, UnrecognisedErrorKeepsTheGenericStatus)
{
  const boost::system::error_code other{make_error_code(boost::system::errc::permission_denied)};
  EXPECT_EQ(ua::connect_failure_status(other).as_status(), ua::Status::BadTcpInternalError);
}

// A failed accept (a descriptor or buffer shortage) fails again at once when the loop re-arms
// immediately: the pending connection stays in the backlog, so an immediate re-arm spins a core and
// floods the log for as long as the condition lasts. The schedule is pure: nothing after a success,
// then 100 ms doubling per consecutive failure, capped at 5 s.
// @verifies AC-SVR-TCP-040-A-FAILED-ACCEPT-RE-ARMS-THROUGH-A-BACKOFF
TEST(TcpTransportAcceptorTests, AcceptRetryDelayStartsAtZeroDoublesPerFailureAndCapsAtFiveSeconds)
{
  using std::chrono::milliseconds;
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(0), milliseconds{0}) << "a success re-arms at once";
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(1), milliseconds{100});
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(2), milliseconds{200});
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(3), milliseconds{400});
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(6), milliseconds{3200});
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(7), milliseconds{5000}) << "6400 clamps to the ceiling";
  EXPECT_EQ(TcpTransportAcceptor::accept_retry_delay(40), milliseconds{5000})
    << "the doubling stops at the ceiling, however long the outage";
}

// The depth cap bounds the buffer COUNT; a peer that negotiated large chunks and stops reading would
// hold depth x chunk size. The byte budget bounds the bytes queued plus in flight whatever the chunk
// size: same determinism as the depth arm above (the io_context is never run, so the first write
// stays in flight). A NEW message arriving while the budget is already held is refused, with a
// description that names the budget, not the depth cap.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST(TcpTransportTests, WriteQueueByteBudgetFailsClosed)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();
  boost::asio::ip::tcp::socket clientSock(ioc);
  clientSock.connect({boost::asio::ip::address_v4::loopback(), port});
  auto serverSock = acceptor.accept();

  constexpr size_t depthCap = 4096;  // not the binding limit here
  constexpr size_t bytesCap = 100;
  auto conn = TcpTransportConnection::create(std::move(clientSock), Logger{}, depthCap, bytesCap);

  std::mutex m;
  std::vector<std::pair<StatusCode, std::string>> outcomes;
  conn->register_write_callback(
    [&](StatusCode s, std::string_view description)
    {
      std::lock_guard lk(m);
      outcomes.emplace_back(s, std::string{description});
    });

  conn->async_write(std::vector<byte>(64, byte{0xAB}));  // in flight: 64 of 100 (budget not yet held)
  conn->async_write(std::vector<byte>(64, byte{0xAB}));  // admitted: 64 < 100 when it arrived; now 128
  {
    std::lock_guard lk(m);
    ASSERT_TRUE(outcomes.empty()) << "a message that arrives while the budget has room is admitted";
  }
  conn->async_write(std::vector<byte>(16, byte{0xAB}));  // 128 held >= 100: a new message is refused
  {
    std::lock_guard lk(m);
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes.back().first, StatusCode{Status::BadTcpNotEnoughResources});
    EXPECT_EQ(outcomes.back().second, "Pending-write byte budget reached")
      << "the refusal names the limit that fired";
  }

  conn.reset();  // close the socket before the (never-run) io_context is destroyed
}

// Both caps are applied at a message's FIRST chunk: a continuation chunk of a message already admitted
// is queued whatever the budget holds, so a peer that reads slowly is never cut off mid-message (a
// multi-chunk message is delivered whole or not at all).
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST(TcpTransportTests, AContinuationChunkOfAnAdmittedMessageIsQueuedPastTheBudget)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();
  boost::asio::ip::tcp::socket clientSock(ioc);
  clientSock.connect({boost::asio::ip::address_v4::loopback(), port});
  auto serverSock = acceptor.accept();

  constexpr size_t bytesCap = 100;
  auto conn = TcpTransportConnection::create(std::move(clientSock), Logger{}, 4096, bytesCap);

  std::mutex m;
  std::vector<StatusCode> statuses;
  conn->register_write_callback(
    [&](StatusCode s, std::string_view)
    {
      std::lock_guard lk(m);
      statuses.push_back(s);
    });

  conn->async_write(std::vector<byte>(64, byte{0xAB}), /*startsMessage*/ true);  // in flight
  conn->async_write(std::vector<byte>(64, byte{0xAB}), /*startsMessage*/ true);  // admitted; 128 held
  conn->async_write(std::vector<byte>(16, byte{0xAB}), /*startsMessage*/ false);  // continuation
  {
    std::lock_guard lk(m);
    EXPECT_TRUE(statuses.empty()) << "a continuation chunk is never refused";
  }
  conn->async_write(std::vector<byte>(16, byte{0xAB}), /*startsMessage*/ true);  // a new message is
  {
    std::lock_guard lk(m);
    ASSERT_EQ(statuses.size(), 1u);
    EXPECT_EQ(statuses.back(), StatusCode{Status::BadTcpNotEnoughResources});
  }

  conn.reset();
}

namespace
{
struct AcceptOutcome
{
  bool good;
  std::chrono::steady_clock::time_point at;
};
}  // namespace

// The wiring of the schedule: a failed accept re-arms the loop only after the backoff (the next
// connection in the backlog is not accepted before it), the delays grow per consecutive failure, and
// a success resets them so the next failure waits 100 ms again, not the next doubling. The failed
// accept is driven through the acceptor's outcome injector, since a real descriptor shortage is not
// something a test may cause.
// @verifies AC-SVR-TCP-040-A-FAILED-ACCEPT-RE-ARMS-THROUGH-A-BACKOFF
TEST(TcpTransportAcceptorTests, AFailedAcceptReArmsAfterTheBackoffAndASuccessResetsIt)
{
  boost::asio::thread_pool threadPool{2};
  auto executor = threadPool.get_executor();

  std::mutex m;
  std::condition_variable cv;
  std::vector<AcceptOutcome> outcomes;
  std::vector<shared_ptr<TcpTransportConnection>> accepted;
  TcpTransportAcceptor::NewConnectionCallback newConnectionCallback =
    [&](StatusCode status, string_view, shared_ptr<TcpTransportConnection> connection)
  {
    std::lock_guard lk(m);
    outcomes.push_back({status.is_good() && connection != nullptr, std::chrono::steady_clock::now()});
    if (connection)
      accepted.push_back(std::move(connection));
    cv.notify_all();
  };

  asio::ip::tcp::endpoint ephemeral{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = TcpTransportAcceptor::create(executor, ephemeral, newConnectionCallback);
  const auto bound = acceptor->get_local_endpoint();

  std::atomic<int> failuresToInject{3};
  acceptor->set_accept_outcome_injector_for_tests(
    [&](boost::system::error_code ec)
    {
      if (failuresToInject.fetch_sub(1) > 0)
        return boost::system::error_code{make_error_code(boost::system::errc::too_many_files_open)};
      failuresToInject.store(0);
      return ec;
    });

  boost::asio::io_context clientIoc;
  std::vector<boost::asio::ip::tcp::socket> clients;
  // Every client connects up front (the kernel completes the handshake into the backlog), so the
  // outcomes are paced by the acceptor's timer alone, not by this thread's scheduling.
  const auto connectClients = [&](size_t count)
  {
    for (size_t i = 0; i < count; ++i)
    {
      clients.emplace_back(clientIoc);
      clients.back().connect(bound);
    }
  };
  const auto waitForOutcomes = [&](size_t outcomeCount)
  {
    std::unique_lock lk(m);
    return cv.wait_for(lk, std::chrono::seconds{10}, [&] { return outcomes.size() >= outcomeCount; });
  };

  // Three failures in a row, then a success: the gaps grow 100, 200, 400 ms.
  connectClients(4);
  ASSERT_TRUE(waitForOutcomes(4)) << "the four outcomes never arrived";
  std::vector<AcceptOutcome> seen;
  {
    std::lock_guard lk(m);
    seen = outcomes;
  }
  ASSERT_EQ(seen.size(), 4u);
  EXPECT_FALSE(seen[0].good);
  EXPECT_FALSE(seen[1].good);
  EXPECT_FALSE(seen[2].good);
  EXPECT_TRUE(seen[3].good) << "the fourth accept, with the injector passing the real outcome, succeeds";
  const auto gap = [&](size_t a, size_t b)
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(seen[b].at - seen[a].at);
  };
  EXPECT_GE(gap(0, 1), std::chrono::milliseconds{100}) << "the first retry waits the first delay";
  EXPECT_GE(gap(1, 2), std::chrono::milliseconds{200}) << "the second retry waits the doubled delay";
  EXPECT_GE(gap(2, 3), std::chrono::milliseconds{400}) << "the loop re-armed after the third delay";

  // After the success the count is reset: the next failure waits 100 ms, not the 800 ms a fourth
  // consecutive failure would wait.
  failuresToInject.store(1);
  connectClients(2);
  ASSERT_TRUE(waitForOutcomes(6));
  {
    std::lock_guard lk(m);
    seen = outcomes;
  }
  ASSERT_EQ(seen.size(), 6u);
  EXPECT_FALSE(seen[4].good);
  EXPECT_TRUE(seen[5].good);
  EXPECT_GE(gap(4, 5), std::chrono::milliseconds{100});
  EXPECT_LT(gap(4, 5), std::chrono::milliseconds{700}) << "a success reset the backoff (800 ms otherwise)";

  acceptor->close_async();
  accepted.clear();
  clients.clear();
  ::ua::test_utils::drain_with_timeout(threadPool);
  acceptor.reset();
}

// Control: the budget is over bytes HELD, not bytes ever written. Once the in-flight write completes
// (the io_context runs and the loopback peer's kernel buffer takes the bytes) the same volume again
// is accepted.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST(TcpTransportTests, WriteQueueByteBudgetIsReleasedAsTheSocketDrains)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();
  boost::asio::ip::tcp::socket clientSock(ioc);
  clientSock.connect({boost::asio::ip::address_v4::loopback(), port});
  auto serverSock = acceptor.accept();

  constexpr size_t bytesCap = 100;
  auto conn = TcpTransportConnection::create(std::move(clientSock), Logger{}, 4096, bytesCap);

  std::mutex m;
  std::vector<StatusCode> statuses;
  conn->register_write_callback(
    [&](StatusCode s, std::string_view)
    {
      std::lock_guard lk(m);
      statuses.push_back(s);
    });

  for (int round = 0; round < 3; ++round)
  {
    conn->async_write(std::vector<byte>(64, byte{0xAB}));
    ioc.restart();
    ioc.run_for(std::chrono::milliseconds{500});  // lets the write complete and release its bytes
  }

  {
    std::lock_guard lk(m);
    ASSERT_EQ(statuses.size(), 3u) << "each write completed";
    for (const auto& s : statuses)
      EXPECT_TRUE(s.is_good()) << "192 bytes in total pass a 100-byte budget once each write has drained";
  }

  conn.reset();
}

// The backoff answers a resource shortage of the process or host; a failure that belongs to the one
// connection being accepted re-arms at once, as accept(2) prescribes.
// @verifies AC-SVR-TCP-040-A-FAILED-ACCEPT-RE-ARMS-THROUGH-A-BACKOFF
TEST(TcpTransportAcceptorTests, OnlyAResourceShortageBacksOffTheAcceptLoop)
{
  namespace errc = boost::system::errc;
  const auto code = [](errc::errc_t e)
  {
    return boost::system::error_code{make_error_code(e)};
  };
  EXPECT_TRUE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::too_many_files_open)));
  EXPECT_TRUE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::too_many_files_open_in_system)));
  EXPECT_TRUE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::no_buffer_space)));
  EXPECT_TRUE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::not_enough_memory)));
  EXPECT_FALSE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::host_unreachable)))
    << "the peer's network problem is not a reason to stall every other peer";
  EXPECT_FALSE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::connection_aborted)));
  EXPECT_FALSE(TcpTransportAcceptor::accept_failure_backs_off(code(errc::network_down)));
}

// A message whose first chunk was refused is dropped whole: its continuation chunks are not queued
// either, so the peer never receives a message tail and the refused message holds no memory. Observed
// on the wire: after the queue drains, the peer has received exactly the two admitted messages.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST(TcpTransportTests, TheContinuationChunksOfARefusedMessageAreDroppedWithIt)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::address_v4::loopback(), 0});
  auto port = acceptor.local_endpoint().port();
  boost::asio::ip::tcp::socket clientSock(ioc);
  clientSock.connect({boost::asio::ip::address_v4::loopback(), port});
  auto serverSock = acceptor.accept();

  constexpr size_t bytesCap = 100;
  auto conn = TcpTransportConnection::create(std::move(clientSock), Logger{}, 4096, bytesCap);

  std::mutex m;
  std::vector<StatusCode> statuses;
  conn->register_write_callback(
    [&](StatusCode s, std::string_view)
    {
      std::lock_guard lk(m);
      statuses.push_back(s);
    });

  conn->async_write(std::vector<byte>(64, byte{0x01}), true);  // message A, in flight
  conn->async_write(std::vector<byte>(64, byte{0x02}), true);  // message B, admitted: 128 held
  conn->async_write(std::vector<byte>(16, byte{0x03}), true);  // message C's first chunk: refused
  conn->async_write(std::vector<byte>(16, byte{0x03}), false);  // C's continuation: dropped with it
  conn->async_write(std::vector<byte>(16, byte{0x03}), false);  // C's final chunk: dropped with it
  {
    std::lock_guard lk(m);
    ASSERT_EQ(statuses.size(), 1u) << "one refusal for the message, none for its continuations";
    EXPECT_EQ(statuses.front(), StatusCode{Status::BadTcpNotEnoughResources});
  }

  // Drain: the socket takes A and B; what the peer receives is what was queued.
  ioc.restart();
  ioc.run_for(std::chrono::milliseconds{500});
  std::vector<byte> received(256);
  boost::system::error_code ec;
  serverSock.non_blocking(true);
  size_t total = 0;
  for (int i = 0; i < 20 && total < received.size(); ++i)
  {
    const auto n =
      serverSock.read_some(boost::asio::buffer(received.data() + total, received.size() - total), ec);
    if (!ec)
      total += n;
    else if (ec != boost::asio::error::would_block)
      break;
    else
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  EXPECT_EQ(total, 128u) << "the peer received the two admitted messages and nothing of the refused one";
  EXPECT_EQ(std::count(received.begin(), received.begin() + static_cast<long>(total), byte{0x03}), 0);

  conn.reset();
}

// The classification is what the accept handler acts on: a failure that belongs to the one connection
// being accepted (here ECONNABORTED) is reported but counts as no failure, so the loop re-arms at once
// (a 0 ms delay) and the next connection is accepted; a resource shortage right after it is the FIRST
// consecutive failure, not the second.
// @verifies AC-SVR-TCP-040-A-FAILED-ACCEPT-RE-ARMS-THROUGH-A-BACKOFF
TEST(TcpTransportAcceptorTests, APerConnectionAcceptFailureIsNotCountedTowardsTheBackoff)
{
  boost::asio::thread_pool threadPool{2};
  auto executor = threadPool.get_executor();

  std::mutex m;
  std::condition_variable cv;
  std::vector<bool> outcomes;
  std::vector<shared_ptr<TcpTransportConnection>> accepted;
  TcpTransportAcceptor::NewConnectionCallback newConnectionCallback =
    [&](StatusCode status, string_view, shared_ptr<TcpTransportConnection> connection)
  {
    std::lock_guard lk(m);
    outcomes.push_back(status.is_good() && connection != nullptr);
    if (connection)
      accepted.push_back(std::move(connection));
    cv.notify_all();
  };
  asio::ip::tcp::endpoint ephemeral{asio::ip::make_address("127.0.0.1"), 0};
  auto acceptor = TcpTransportAcceptor::create(executor, ephemeral, newConnectionCallback);
  const auto bound = acceptor->get_local_endpoint();

  std::atomic<int> injected{0};
  acceptor->set_accept_outcome_injector_for_tests(
    [&](boost::system::error_code ec)
    {
      const int n = injected.fetch_add(1);
      if (n == 0)
        return boost::system::error_code{make_error_code(boost::system::errc::connection_aborted)};
      if (n == 1)
        return boost::system::error_code{make_error_code(boost::system::errc::too_many_files_open)};
      return ec;
    });

  boost::asio::io_context clientIoc;
  std::vector<boost::asio::ip::tcp::socket> clients;
  for (int i = 0; i < 3; ++i)
  {
    clients.emplace_back(clientIoc);
    clients.back().connect(bound);
  }
  {
    std::unique_lock lk(m);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds{10}, [&] { return outcomes.size() >= 3; }));
  }
  std::vector<bool> seen;
  {
    std::lock_guard lk(m);
    seen = outcomes;
  }
  ASSERT_EQ(seen.size(), 3u);
  EXPECT_FALSE(seen[0]) << "the aborted accept is reported";
  EXPECT_FALSE(seen[1]) << "the resource shortage is reported";
  EXPECT_TRUE(seen[2]) << "the loop re-armed after both and accepted the third connection";
  EXPECT_EQ(acceptor->consecutive_accept_failures_for_tests(), 0u) << "reset by the success";

  // Now the counting itself: an aborted accept alone leaves the count at zero (it would be one if the
  // handler backed off on every failure); a resource shortage alone makes it one.
  injected.store(0);
  clients.emplace_back(clientIoc);
  clients.back().connect(bound);
  {
    std::unique_lock lk(m);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds{10}, [&] { return outcomes.size() >= 4; }));
  }
  EXPECT_EQ(acceptor->consecutive_accept_failures_for_tests(), 0u)
    << "a failure that belongs to the one connection is not a consecutive failure of the loop";
  clients.emplace_back(clientIoc);
  clients.back().connect(bound);
  {
    std::unique_lock lk(m);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds{10}, [&] { return outcomes.size() >= 5; }));
  }
  EXPECT_EQ(acceptor->consecutive_accept_failures_for_tests(), 1u) << "the resource shortage is the first";

  acceptor->close_async();
  accepted.clear();
  clients.clear();
  ::ua::test_utils::drain_with_timeout(threadPool);
  acceptor.reset();
}

// Part 6 7.1.5 (owner decision 2): after a fatal error the client's CloseSecureChannel is queued on the
// transport and the transport is then closed. close_async aborts writes still in flight, so the close
// that follows a CloseSecureChannel waits for the queued bytes: every byte queued before
// an AfterPendingWrites close reaches the peer, and only then does the peer see the end of the stream.
// @verifies AC-CL-TCP-014-03-THE-CLOSE-WAITS-FOR-THE-QUEUED-WRITES
TEST(TcpTransportTests, CloseAfterWritesDeliversEveryQueuedByteBeforeTheClose)
{
  boost::asio::io_context ioc;
  auto work = boost::asio::make_work_guard(ioc);
  std::thread runner{[&ioc]
    {
      ioc.run();
    }};

  asio::ip::tcp::acceptor acceptor{ioc, asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
  asio::ip::tcp::socket peer{ioc};
  peer.connect(acceptor.local_endpoint());
  auto transport = TcpTransportConnection::create(acceptor.accept());
  transport->register_error_callback([](StatusCode, string_view) {});
  transport->register_write_callback([](StatusCode, string_view) {});

  // Large enough that the socket cannot take it in one system call, so the writes are still queued
  // or in flight when the close is requested.
  constexpr size_t chunk = 256 * 1024;
  constexpr size_t chunks = 32;
  for (size_t i = 0; i < chunks; ++i)
    transport->async_write(std::vector<byte>(chunk, static_cast<byte>(i + 1)));

  std::promise<void> closed;
  auto closedFuture = closed.get_future();
  transport->close_async(
    [&closed](VoidResult) { closed.set_value(); }, TcpTransportConnection::CloseMode::AfterPendingWrites);

  // The peer drains on its own thread, bounded: a regression that never closes must fail, not hang.
  boost::system::error_code ec;
  auto drained = std::async(std::launch::async,
    [&peer, &ec]
    {
      size_t count = 0;
      std::array<char, 64 * 1024> buffer{};
      while (!ec)
        count += peer.read_some(asio::buffer(buffer), ec);
      return count;
    });
  if (drained.wait_for(10s) != std::future_status::ready)
  {
    boost::system::error_code ignored;
    peer.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    ADD_FAILURE() << "the transport was not closed after its queued writes";
  }
  const size_t received = drained.get();

  EXPECT_EQ(ec, asio::error::eof) << ec.message();
  EXPECT_EQ(received, chunk * chunks) << "every queued byte arrives before the end of the stream";
  EXPECT_EQ(closedFuture.wait_for(5s), std::future_status::ready) << "the close completes";

  transport.reset();
  work.reset();
  ioc.stop();
  runner.join();
}
