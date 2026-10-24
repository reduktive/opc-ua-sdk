// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for ReverseConnectListener.
///
/// Verifies lifecycle (create/start/stop), endpoint matching, waiter timeout,
/// and shutdown behavior.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <chrono>
#include <future>
#include <thread>
#include <vector>

#include "ua_reverse_connect_listener.h"
#include "ua_reverse_connect_admission.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include "fake_connection_protocol_deps.h"
#include "fake_transport_connection.h"
#include "ua_connection_protocol.h"

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

ReverseConnectListenerConfig make_test_config()
{
  ReverseConnectListenerConfig config;
  config.bind.address = "127.0.0.1:0";
  config.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  config.expectedServers.push_back(ExpectedServer{
    .serverUri = "urn:test:server",
    .endpointUrls = {"opc.tcp://127.0.0.1:4840"},
  });
  config.maxQueuedConnections = 5;
  config.initialMessageTimeout = std::chrono::seconds{5};
  return config;
}

}  // namespace

class ReverseConnectListenerTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mDeps = std::make_shared<FakeConnectionProtocolDeps>(mThreadPool.get_executor());
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::shared_ptr<ReverseConnectListener> create_listener(
    ReverseConnectListenerConfig config = make_test_config())
  {
    return ReverseConnectListener::create(mThreadPool.get_executor(), mDeps, std::move(config));
  }

  boost::asio::thread_pool mThreadPool{2};
  std::shared_ptr<FakeConnectionProtocolDeps> mDeps;
};

// @relation(SVR-RC-018, scope=function)
TEST_F(ReverseConnectListenerTest, StopBeforeStartSucceeds)
{
  auto listener = create_listener();

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  EXPECT_EQ(stopped.get_future().wait_for(2s), std::future_status::ready);
}

TEST_F(ReverseConnectListenerTest, StartAndStopCallbackFires)
{
  auto listener = create_listener();

  listener->start();

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  auto future = stopped.get_future();
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(future.get().is_good());
}

TEST_F(ReverseConnectListenerTest, MatchesEndpointWithConfiguredUrl)
{
  auto listener = create_listener();

  EXPECT_TRUE(listener->matches_endpoint("opc.tcp://127.0.0.1:4840"));
  EXPECT_FALSE(listener->matches_endpoint("opc.tcp://192.168.1.1:4840"));
}

TEST_F(ReverseConnectListenerTest, MatchesEndpointWithEmptyUrlList)
{
  auto config = make_test_config();
  config.expectedServers[0].endpointUrls.clear();

  auto listener = create_listener(std::move(config));

  EXPECT_TRUE(listener->matches_endpoint("opc.tcp://anything:1234"));
}

TEST_F(ReverseConnectListenerTest, ConsumeBeforeConnectionTimesOut)
{
  auto listener = create_listener();

  listener->start();

  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    std::chrono::seconds{1},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  auto result = resultPromise.get_future().get();
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTimeout});

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

TEST_F(ReverseConnectListenerTest, StopFailsWaitersWithBadShutdown)
{
  auto listener = create_listener();

  listener->start();

  // Register a waiter with a long timeout.
  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    std::chrono::seconds{60},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  // Stop the listener - should fail the waiter with BadShutdown.
  // No sleep needed: stop_async is sequenced after consume_connection on the strand.
  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);

  auto result = resultPromise.get_future().get();
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadShutdown});
}

TEST_F(ReverseConnectListenerTest, MultipleStopsAreSafe)
{
  auto listener = create_listener();

  listener->start();

  std::promise<VoidResult> stopped1;
  listener->stop_async([&stopped1](VoidResult result) { stopped1.set_value(std::move(result)); });
  auto future1 = stopped1.get_future();
  ASSERT_EQ(future1.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(future1.get().is_good());

  // Second stop should also succeed.
  std::promise<VoidResult> stopped2;
  listener->stop_async([&stopped2](VoidResult result) { stopped2.set_value(std::move(result)); });
  auto future2 = stopped2.get_future();
  ASSERT_EQ(future2.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(future2.get().is_good());
}

TEST_F(ReverseConnectListenerTest, ConsumeAfterStopReturnsBadShutdown)
{
  auto listener = create_listener();
  listener->start();

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);

  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    std::chrono::seconds{5},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  auto result = resultPromise.get_future().get();
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadShutdown});
}

TEST_F(ReverseConnectListenerTest, StartWithInvalidBindAddressReportsError)
{
  ReverseConnectListenerConfig config = make_test_config();
  config.bind.address = "not-a-valid-address";
  auto listener = create_listener(std::move(config));

  std::promise<VoidResult> startResult;
  listener->start([&startResult](VoidResult result) { startResult.set_value(std::move(result)); });

  auto result = startResult.get_future().get();
  EXPECT_TRUE(result.is_bad()) << "start() with invalid bind address should report error";

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

TEST_F(ReverseConnectListenerTest, StartWithValidAddressReportsSuccess)
{
  auto listener = create_listener();

  std::promise<VoidResult> startResult;
  listener->start([&startResult](VoidResult result) { startResult.set_value(std::move(result)); });

  auto result = startResult.get_future().get();
  EXPECT_TRUE(result.is_good()) << "start() with valid bind address should succeed";

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// A reverse-connect listener binds a port like any other acceptor, so a port already in use has
// to reach the caller as an actionable status rather than escaping the posted start handler as a
// raw system_error. Pin that start() reports it, and that the detail names the port - the
// reverse-connect chapter tells readers to trust the start result on this path.
TEST_F(ReverseConnectListenerTest, StartOnAPortAlreadyInUseReportsTheBindFailure)
{
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor holder(
    ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
  const uint16_t taken = holder.local_endpoint().port();

  ReverseConnectListenerConfig config = make_test_config();
  config.bind.address = "127.0.0.1:" + std::to_string(taken);
  auto listener = create_listener(std::move(config));

  std::promise<VoidResult> startResult;
  listener->start([&startResult](VoidResult result) { startResult.set_value(std::move(result)); });

  auto result = startResult.get_future().get();
  ASSERT_TRUE(result.is_bad()) << "start() on a taken port must not report success";
  EXPECT_EQ(result.status_code().as_status(), Status::BadResourceUnavailable);
  auto detail = result.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ListenerBindFailed");

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

TEST_F(ReverseConnectListenerTest, NoExpectedServersMatchesNothing)
{
  ReverseConnectListenerConfig config = make_test_config();
  config.expectedServers.clear();
  auto listener = create_listener(std::move(config));

  EXPECT_FALSE(listener->matches_endpoint("opc.tcp://127.0.0.1:4840"));
}

TEST_F(ReverseConnectListenerTest, ConsumeWithNonMatchingUrlTimesOut)
{
  auto listener = create_listener();
  listener->start();

  // Request a connection for a URL that no server will connect with.
  // Even if connections arrive for other URLs, this specific waiter should time out.
  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://192.168.99.99:9999",
    std::chrono::seconds{1},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  auto result = resultPromise.get_future().get();
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTimeout});

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// ---------------------------------------------------------------------------
// CL-RC-006 - pull-model connection surfacing (waiter-satisfied + queued-match)
// ---------------------------------------------------------------------------

namespace ua::test_helpers
{

/// Realises the forward-declared friend interface declared in
/// ua_reverse_connect_listener.h (`friend class
/// ::ua::test_helpers::ReverseConnectListenerTestAccess`). It injects a
/// synthesized handshake result at the exact production entry the real
/// handshake-completion callback uses (ReverseConnectListener::on_handshake_complete),
/// posting onto the listener's private strand and blocking the caller until the
/// handler has run. Driving the real on_handshake_complete (rather than
/// enqueue_or_dispatch directly) exercises the real branch logic - the RHE /
/// NegotiatedLimits routing a real ConnectionProtocol handshake would produce -
/// with no TCP I/O. The strand FIFO order relative to a preceding
/// consume_connection post is what lets the tests choose the waiter-satisfied
/// vs queued-match path deterministically.
class ReverseConnectListenerTestAccess
{
public:
  static void inject_handshake_complete(const std::shared_ptr<ua::client::ReverseConnectListener>& listener,
    ua::StatusCode status, std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits,
    std::optional<ua::detail::ReverseHelloMessage> reverseHello)
  {
    std::promise<void> handlerRan;
    auto future = handlerRan.get_future();
    boost::asio::post(listener->mStrand,
      [listener,
        status,
        connection = std::move(connection),
        negotiatedLimits,
        reverseHello = std::move(reverseHello),
        &handlerRan]() mutable
      {
        listener->on_handshake_complete(
          status, std::move(connection), negotiatedLimits, std::move(reverseHello));
        handlerRan.set_value();
      });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "injected on_handshake_complete never ran on the listener strand";
  }

  /// Snapshots the listener's in-flight handshakes WEAKLY, on the listener's own strand. Weak on
  /// purpose: the question a caller asks of this is whether anything still owns a handshake once the
  /// listener has let go of it, and a snapshot that owned one could never answer it.
  static std::vector<std::weak_ptr<ua::ConnectionProtocol>> pending_handshakes(
    const std::shared_ptr<ua::client::ReverseConnectListener>& listener)
  {
    std::promise<std::vector<std::weak_ptr<ua::ConnectionProtocol>>> snapshot;
    auto future = snapshot.get_future();
    boost::asio::post(listener->mStrand,
      [listener, &snapshot]()
      {
        std::vector<std::weak_ptr<ua::ConnectionProtocol>> pending;
        for (const auto& handshake : listener->mPendingHandshakes)
        {
          pending.emplace_back(handshake.connection);
        }
        snapshot.set_value(std::move(pending));
      });
    if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
    {
      return {};
    }
    return future.get();
  }

  /// A completed handshake from `address`: the pending entry the accept path would have recorded is
  /// added first, so the completion takes its address from it as production does.
  static void inject_handshake_complete_from(
    const std::shared_ptr<ua::client::ReverseConnectListener>& listener, std::string address,
    ua::detail::ReverseHelloMessage reverseHello,
    std::shared_ptr<ua::ConnectionProtocol> connection = nullptr)
  {
    std::promise<void> handlerRan;
    auto future = handlerRan.get_future();
    boost::asio::post(listener->mStrand,
      [listener,
        address = std::move(address),
        reverseHello = std::move(reverseHello),
        connection = std::move(connection),
        &handlerRan]() mutable
      {
        listener->mPendingHandshakes.push_back(ua::client::detail::PendingHandshake{connection, address});
        listener->on_handshake_complete(StatusCode{Status::Good},
          std::move(connection),
          ua::connection_protocol::NegotiatedLimits{},
          std::move(reverseHello));
        handlerRan.set_value();
      });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  }

  /// The ServerUris of the queued connections, oldest first, read on the listener's strand.
  static std::vector<std::string> queued_server_uris(
    const std::shared_ptr<ua::client::ReverseConnectListener>& listener)
  {
    std::promise<std::vector<std::string>> snapshot;
    auto future = snapshot.get_future();
    boost::asio::post(listener->mStrand,
      [listener, &snapshot]()
      {
        std::vector<std::string> uris;
        for (const auto& queued : listener->mQueuedConnections)
        {
          uris.push_back(queued.reverseHello.serverUri);
        }
        snapshot.set_value(std::move(uris));
      });
    if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
    {
      return {};
    }
    return future.get();
  }

  static void inject_reportable_handshake_error(
    const std::shared_ptr<ua::client::ReverseConnectListener>& listener, ua::StatusCode status,
    std::string description, std::optional<std::string> endpointUrl)
  {
    std::promise<void> handlerRan;
    auto future = handlerRan.get_future();
    boost::asio::post(listener->mStrand,
      [listener,
        status,
        description = std::move(description),
        endpointUrl = std::move(endpointUrl),
        &handlerRan]() mutable
      {
        listener->report_handshake_error_to_waiters(status, description, endpointUrl);
        handlerRan.set_value();
      });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "injected reportable handshake error never ran on the listener strand";
  }
};

}  // namespace ua::test_helpers

// Waiter-satisfied path: a consumer registers a waiter FIRST, then a completed
// handshake arrives on the SAME strand. Production's enqueue_or_dispatch must
// find the registered waiter and dispatch_to_waiter must fire the consume
// callback inline with the fully-populated connection (endpoint + negotiated
// limits). Falsified if the arriving connection is wrongly queued instead of
// routed to the waiter (callback never fires -> future times out), if it fires
// with a bad StatusCode, with a mismatched endpoint URL, or with default/zeroed
// NegotiatedLimits (the surface dropping negotiated metadata).
// @verifies CL-RC-006
// @relation(CL-RC-006, scope=function)
TEST_F(ReverseConnectListenerTest, SurfacesConnectionToRegisteredWaiter)
{
  auto listener = create_listener();
  listener->start();

  // Register a waiter first: this posts onto the strand and registers the waiter.
  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    std::chrono::seconds{60},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  // Then inject a completed handshake onto the SAME strand. FIFO ordering means
  // it runs after the waiter is registered, so enqueue_or_dispatch routes it to
  // the waiter. The sentinel send-buffer size is distinct from any default.
  ua::connection_protocol::NegotiatedLimits limits;
  limits.sendBufferSize = 65535;
  ReverseConnectListenerTestAccess::inject_handshake_complete(listener,
    StatusCode{Status::Good},
    std::shared_ptr<ua::ConnectionProtocol>{},
    limits,
    ua::detail::ReverseHelloMessage{
      .serverUri = "urn:test:server", .endpointUrl = "opc.tcp://127.0.0.1:4840"});

  auto future = resultPromise.get_future();
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready)
    << "consume callback never fired: connection was not routed to the registered waiter";
  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << "surfaced connection carried a bad status: "
                                << to_string(result.status_code().as_status());
  EXPECT_EQ(result.value().reverseHello.endpointUrl, "opc.tcp://127.0.0.1:4840");
  EXPECT_EQ(result.value().negotiatedLimits.sendBufferSize, 65535u);

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// A full queue of unclaimed reverse connections refuses the NEW connection rather than evicting the oldest:
// a peer whose ReverseHello passes the validator (its strings are public) could otherwise displace a
// legitimate server's queued connection at will. Five connections from five addresses fill the queue
// (maxQueuedConnections = 5); a sixth is refused and the first five stay queued, oldest first.
// @verifies AC-CL-RC-007-A-FULL-REVERSE-CONNECT-QUEUE-REFUSES-THE-NEWCOMER
TEST_F(ReverseConnectListenerTest, AFullQueueRefusesTheNewcomerInsteadOfEvictingTheOldest)
{
  auto listener = create_listener();
  listener->start();
  for (int k = 1; k <= 6; ++k)
  {
    ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
      "10.0.0." + std::to_string(k),
      ua::detail::ReverseHelloMessage{
        .serverUri = "urn:test:server:" + std::to_string(k), .endpointUrl = "opc.tcp://127.0.0.1:4840"});
  }
  const std::vector<std::string> expected{
    "urn:test:server:1", "urn:test:server:2", "urn:test:server:3", "urn:test:server:4", "urn:test:server:5"};
  EXPECT_EQ(ReverseConnectListenerTestAccess::queued_server_uris(listener), expected)
    << "the oldest queued connection must survive and the newcomer be refused";

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// A queued connection its server has closed is dropped when the listener next admits a connection: a queued
// connection has no read armed, so the listener probes each one's transport. With the newcomer refused at
// capacity, a dead entry would otherwise hold a slot, and lock out the server's reconnection, until its
// idle timer. Five connections fill the queue; the first one's server closes it; a sixth is admitted.
// @verifies AC-CL-RC-007-A-FULL-REVERSE-CONNECT-QUEUE-REFUSES-THE-NEWCOMER
TEST_F(ReverseConnectListenerTest, AQueuedConnectionItsServerClosedFreesItsSlot)
{
  auto listener = create_listener();
  listener->start();
  std::vector<std::shared_ptr<FakeTransportConnection>> transports;
  for (int k = 1; k <= 5; ++k)
  {
    transports.push_back(std::make_shared<FakeTransportConnection>());
    auto connection = ua::ConnectionProtocol::create(
      ua::ConnectionProtocolRole::Client,
      mDeps,
      transports.back(),
      /*reverseConnect*/ true,
      std::chrono::seconds{60},
      [](StatusCode,
        std::shared_ptr<ua::ConnectionProtocol>,
        ua::connection_protocol::NegotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage>) {},
      [](StatusCode, string_view, ua::FatalCloseDisposition) {});
    ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
      "10.0.1." + std::to_string(k),
      ua::detail::ReverseHelloMessage{
        .serverUri = "urn:test:server:" + std::to_string(k), .endpointUrl = "opc.tcp://127.0.0.1:4840"},
      std::move(connection));
  }

  transports.front()->set_peer_state(ua::TransportConnection::PeerState::Closed);
  // The second one's server wrote an ERR and closed: the bytes hide the close from the probe, and a server
  // sends nothing before the client's OpenSecureChannel, so waiting bytes alone make it unusable.
  transports[1]->set_peer_state(ua::TransportConnection::PeerState::DataWaiting);
  ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
    "10.0.1.7",
    ua::detail::ReverseHelloMessage{
      .serverUri = "urn:test:server:7", .endpointUrl = "opc.tcp://127.0.0.1:4840"});
  ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
    "10.0.1.6",
    ua::detail::ReverseHelloMessage{
      .serverUri = "urn:test:server:6", .endpointUrl = "opc.tcp://127.0.0.1:4840"});

  const std::vector<std::string> expected{
    "urn:test:server:3", "urn:test:server:4", "urn:test:server:5", "urn:test:server:7", "urn:test:server:6"};
  EXPECT_EQ(ReverseConnectListenerTestAccess::queued_server_uris(listener), expected)
    << "the closed connection and the one written to must leave the queue and both newcomers be admitted";

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// One address cannot fill the queue: its queued connections are bounded by the per-address bound
// (maxPendingHandshakesPerAddress, here 2), and another address is still queued afterwards.
// @verifies AC-CL-RC-007-A-FULL-REVERSE-CONNECT-QUEUE-REFUSES-THE-NEWCOMER
TEST_F(ReverseConnectListenerTest, OneAddressCannotFillTheQueue)
{
  auto config = make_test_config();
  config.maxPendingHandshakesPerAddress = 2;
  auto listener = create_listener(config);
  listener->start();
  for (int k = 1; k <= 3; ++k)
  {
    ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
      "10.0.0.9",
      ua::detail::ReverseHelloMessage{
        .serverUri = "urn:test:same:" + std::to_string(k), .endpointUrl = "opc.tcp://127.0.0.1:4840"});
  }
  ReverseConnectListenerTestAccess::inject_handshake_complete_from(listener,
    "10.0.0.10",
    ua::detail::ReverseHelloMessage{
      .serverUri = "urn:test:other", .endpointUrl = "opc.tcp://127.0.0.1:4840"});
  const std::vector<std::string> expected{"urn:test:same:1", "urn:test:same:2", "urn:test:other"};
  EXPECT_EQ(ReverseConnectListenerTestAccess::queued_server_uris(listener), expected);

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// Immediate queued-match path: a completed handshake arrives FIRST (no waiter,
// so enqueue_or_dispatch queues it under an idle timer that will not fire), then
// a consumer calls consume_connection. Production's queued-match loop must find
// the queued connection, cancel its idle timer, and dispatch it inline with the
// fully-populated connection. Falsified if the already-queued connection is not
// matched and a waiter is registered instead (BadTimeout after 1s), if the
// callback fires with a bad StatusCode / mismatched endpoint, or with
// default/zeroed NegotiatedLimits.
// @verifies CL-RC-006
// @relation(CL-RC-006, scope=function)
TEST_F(ReverseConnectListenerTest, SurfacesAlreadyQueuedConnectionOnConsume)
{
  auto listener = create_listener();
  listener->start();

  // Inject a completed handshake first: with no waiter present, it is queued.
  ua::connection_protocol::NegotiatedLimits limits;
  limits.sendBufferSize = 65535;
  ReverseConnectListenerTestAccess::inject_handshake_complete(listener,
    StatusCode{Status::Good},
    std::shared_ptr<ua::ConnectionProtocol>{},
    limits,
    ua::detail::ReverseHelloMessage{
      .serverUri = "urn:test:server", .endpointUrl = "opc.tcp://127.0.0.1:4840"});

  // Now consume: the queued-match loop must find the queued connection and
  // dispatch it inline. A short timeout proves the match is immediate (a missed
  // match would instead register a waiter and time out).
  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    std::chrono::seconds{1},
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  auto future = resultPromise.get_future();
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << "queued connection was not matched: "
                                << to_string(result.status_code().as_status());
  EXPECT_EQ(result.value().reverseHello.endpointUrl, "opc.tcp://127.0.0.1:4840");
  EXPECT_EQ(result.value().negotiatedLimits.sendBufferSize, 65535u);

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// @verifies CL-RC-005
// @relation(CL-RC-005, scope=function)
TEST_F(ReverseConnectListenerTest, FatalHandshakeErrorReachesMatchingWaiterWithStatusAndReason)
{
  auto listener = create_listener();
  listener->start();

  std::promise<QueuedConnectionResult> resultPromise;
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    60s,
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  ReverseConnectListenerTestAccess::inject_reportable_handshake_error(listener,
    StatusCode{Status::BadTcpServerTooBusy},
    "server outbound buffers exhausted",
    std::string{"opc.tcp://127.0.0.1:4840"});

  auto future = resultPromise.get_future();
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
  auto result = future.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTcpServerTooBusy});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReverseConnectHandshakeError");
  ASSERT_EQ(result.shared_detail()->context.size(), 2u);
  EXPECT_EQ(result.shared_detail()->context[0].value, "opc.tcp://127.0.0.1:4840");
  EXPECT_EQ(result.shared_detail()->context[1].value, "server outbound buffers exhausted");

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// @verifies CL-RC-005
// @relation(CL-RC-005, scope=function)
TEST_F(ReverseConnectListenerTest, FatalHandshakeErrorAfterReverseHelloDoesNotFailDifferentEndpoint)
{
  auto listener = create_listener();
  listener->start();

  std::promise<QueuedConnectionResult> resultPromise;
  auto future = resultPromise.get_future();
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    60s,
    [&resultPromise](QueuedConnectionResult result) { resultPromise.set_value(std::move(result)); });

  ReverseConnectListenerTestAccess::inject_reportable_handshake_error(listener,
    StatusCode{Status::BadTcpServerTooBusy},
    "different endpoint failed",
    std::string{"opc.tcp://127.0.0.1:4841"});
  EXPECT_EQ(future.wait_for(100ms), std::future_status::timeout);

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(future.get().status_code(), StatusCode{Status::BadShutdown});
}

// @verifies CL-RC-005
// @relation(CL-RC-005, scope=function)
TEST_F(ReverseConnectListenerTest, FatalErrorBeforeReverseHelloReportsToEveryPendingConsumer)
{
  auto listener = create_listener();
  listener->start();

  std::promise<QueuedConnectionResult> firstPromise;
  std::promise<QueuedConnectionResult> secondPromise;
  auto firstFuture = firstPromise.get_future();
  auto secondFuture = secondPromise.get_future();
  listener->consume_connection("opc.tcp://127.0.0.1:4840",
    60s,
    [&firstPromise](QueuedConnectionResult result) { firstPromise.set_value(std::move(result)); });
  listener->consume_connection("opc.tcp://127.0.0.1:4841",
    60s,
    [&secondPromise](QueuedConnectionResult result) { secondPromise.set_value(std::move(result)); });

  ReverseConnectListenerTestAccess::inject_reportable_handshake_error(
    listener, StatusCode{Status::BadTcpMessageTypeInvalid}, "ERR arrived before RHE", std::nullopt);

  ASSERT_EQ(firstFuture.wait_for(5s), std::future_status::ready);
  ASSERT_EQ(secondFuture.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(firstFuture.get().status_code(), StatusCode{Status::BadTcpMessageTypeInvalid});
  EXPECT_EQ(secondFuture.get().status_code(), StatusCode{Status::BadTcpMessageTypeInvalid});

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready);
}

// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-IN-TOTAL
// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-PER-ADDRESS
// The admission rule on its own: the total bound, the per-address bound, and that addresses are counted
// separately.
TEST(ReverseConnectAdmission, RefusesBeyondTheTotalAndThePerAddressBound)
{
  using ua::client::detail::admit_pending_handshake;
  using ua::client::detail::PendingHandshake;
  std::vector<PendingHandshake> pending;
  pending.push_back({nullptr, "10.0.0.1"});
  pending.push_back({nullptr, "10.0.0.1"});
  pending.push_back({nullptr, "10.0.0.2"});

  EXPECT_TRUE(admit_pending_handshake(pending, "10.0.0.3", 4, 2)) << "under both bounds";
  EXPECT_FALSE(admit_pending_handshake(pending, "10.0.0.1", 4, 2)) << "the address holds its 2 already";
  EXPECT_TRUE(admit_pending_handshake(pending, "10.0.0.2", 4, 2)) << "another address has room";
  EXPECT_FALSE(admit_pending_handshake(pending, "10.0.0.9", 3, 8)) << "the total is reached";
  EXPECT_TRUE(admit_pending_handshake({}, "10.0.0.1", 1, 1)) << "an empty list admits the first";
  EXPECT_FALSE(admit_pending_handshake({}, "10.0.0.1", 0, 1)) << "a zero total admits nothing";
}

namespace
{
/// Binds a free loopback port (the config needs the number up front; 127.0.0.1:0 only reveals it after the
/// acceptor is inside the listener).
std::uint16_t free_loopback_port()
{
  boost::asio::io_context probeContext;
  boost::asio::ip::tcp::acceptor probe(
    probeContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
  return probe.local_endpoint().port();
}

/// Connects a silent peer (no ReverseHello) and reports whether the listener closed it within @p timeout.
struct SilentPeer
{
  boost::asio::io_context context;
  boost::asio::ip::tcp::socket socket{context};

  bool connect(std::uint16_t port)
  {
    boost::system::error_code error;
    socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), port), error);
    return !error;
  }

  bool closed_by_peer(std::chrono::milliseconds timeout)
  {
    socket.non_blocking(true);
    const auto giveUpAt = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < giveUpAt)
    {
      std::array<char, 16> buffer{};
      boost::system::error_code error;
      socket.read_some(boost::asio::buffer(buffer), error);
      if (error == boost::asio::error::eof || error == boost::asio::error::connection_reset)
      {
        return true;
      }
      if (error && error != boost::asio::error::would_block && error != boost::asio::error::try_again)
      {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
  }
};

std::size_t wait_for_pending(const std::shared_ptr<ReverseConnectListener>& listener, std::size_t atLeast)
{
  const auto giveUpAt = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  std::size_t count = 0;
  while (std::chrono::steady_clock::now() < giveUpAt)
  {
    count = ReverseConnectListenerTestAccess::pending_handshakes(listener).size();
    if (count >= atLeast)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  return count;
}
}  // namespace

// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-IN-TOTAL
// Total 1, per-address 4: the second silent loopback peer is closed at accept, the first stays pending.
TEST_F(ReverseConnectListenerTest, AcceptBeyondThePendingHandshakeBoundIsClosed)
{
  const auto port = free_loopback_port();
  ReverseConnectListenerConfig config = make_test_config();
  config.bind.address = "127.0.0.1:" + std::to_string(port);
  config.maxPendingHandshakes = 1;
  config.maxPendingHandshakesPerAddress = 4;
  auto listener = create_listener(config);
  std::promise<VoidResult> started;
  listener->start([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_EQ(started.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  SilentPeer first;
  ASSERT_TRUE(first.connect(port));
  ASSERT_EQ(wait_for_pending(listener, 1), 1u) << "the first peer must be pending";
  SilentPeer second;
  ASSERT_TRUE(second.connect(port));

  EXPECT_TRUE(second.closed_by_peer(std::chrono::seconds{2})) << "the second peer is refused at accept";
  EXPECT_EQ(ReverseConnectListenerTestAccess::pending_handshakes(listener).size(), 1u);
  EXPECT_FALSE(first.closed_by_peer(std::chrono::milliseconds{200})) << "the first peer stays pending";

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-PER-ADDRESS
// Total 4, per-address 1: the same stimulus, and the second loopback peer is refused on the per-address
// bound alone (the total has room).
TEST_F(ReverseConnectListenerTest, AcceptBeyondThePerAddressHandshakeBoundIsClosed)
{
  const auto port = free_loopback_port();
  ReverseConnectListenerConfig config = make_test_config();
  config.bind.address = "127.0.0.1:" + std::to_string(port);
  config.maxPendingHandshakes = 4;
  config.maxPendingHandshakesPerAddress = 1;
  auto listener = create_listener(config);
  std::promise<VoidResult> started;
  listener->start([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_EQ(started.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);

  SilentPeer first;
  ASSERT_TRUE(first.connect(port));
  ASSERT_EQ(wait_for_pending(listener, 1), 1u);
  SilentPeer second;
  ASSERT_TRUE(second.connect(port));

  EXPECT_TRUE(second.closed_by_peer(std::chrono::seconds{2})) << "the second peer is refused at accept";
  EXPECT_EQ(ReverseConnectListenerTestAccess::pending_handshakes(listener).size(), 1u);

  std::promise<VoidResult> stopped;
  listener->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
}

// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-IN-TOTAL
// A bound of zero could never admit a handshake; start refuses it.
TEST_F(ReverseConnectListenerTest, StartRefusesAZeroPendingHandshakeBound)
{
  ReverseConnectListenerConfig config = make_test_config();
  config.maxPendingHandshakes = 0;
  auto listener = create_listener(config);
  std::promise<VoidResult> started;
  listener->start([&started](VoidResult result) { started.set_value(std::move(result)); });
  auto future = started.get_future();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument);
}

// @verifies AC-CL-RC-007-PENDING-HANDSHAKES-ARE-BOUNDED-PER-ADDRESS
// The per-address bound of zero is refused at start the same way.
TEST_F(ReverseConnectListenerTest, StartRefusesAZeroPerAddressHandshakeBound)
{
  ReverseConnectListenerConfig config = make_test_config();
  config.maxPendingHandshakesPerAddress = 0;
  auto listener = create_listener(config);
  std::promise<VoidResult> started;
  listener->start([&started](VoidResult result) { started.set_value(std::move(result)); });
  auto future = started.get_future();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  EXPECT_EQ(future.get().status_code().as_status(), ua::Status::BadInvalidArgument);
}

// A handshake in flight is owned by the listener's `mPendingHandshakes` and by nothing else. The
// ConnectionProtocol owns the two callbacks the listener hands it, and those callbacks carry the
// per-handshake state that names the connection; if that state owned the connection back, the pair would
// keep each other alive and only a terminal callback could separate them. Executors do not promise to run
// what they have queued - a stopped pool destroys its work instead - so an ownership ring that only an
// invocation can open outlives everything that could open it.
//
// Staged exactly that way: a peer connects and then says nothing, so the listener accepts it and builds a
// ConnectionProtocol that waits for a ReverseHello that never comes. The pool is then stopped and
// destroyed with that handshake still in flight, so no completion and no error callback can ever run, and
// the listener is dropped without a stop. Nothing is left that could break a ring, so a surviving
// connection here means there was one.
// @relation(CL-RC-006, scope=function)
TEST_F(ReverseConnectListenerTest, PendingHandshakeDiesWithTheListenerWhenNoTerminalCallbackCanRun)
{
  // Bind a port the listener can take: the config needs the number up front, and 127.0.0.1:0 only
  // reveals it after the acceptor is already inside the listener.
  std::uint16_t port = 0;
  {
    boost::asio::io_context probeContext;
    boost::asio::ip::tcp::acceptor probe(
      probeContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    port = probe.local_endpoint().port();
  }

  ReverseConnectListenerConfig config = make_test_config();
  config.bind.address = "127.0.0.1:" + std::to_string(port);

  std::vector<std::weak_ptr<ua::ConnectionProtocol>> pending;
  std::shared_ptr<ReverseConnectListener> listener;
  {
    boost::asio::thread_pool pool{2};
    auto deps = std::make_shared<FakeConnectionProtocolDeps>(pool.get_executor());
    listener = ReverseConnectListener::create(pool.get_executor(), deps, config);

    std::promise<VoidResult> started;
    listener->start([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_EQ(started.get_future().wait_for(5s), std::future_status::ready);

    boost::asio::io_context peerContext;
    boost::asio::ip::tcp::socket peer{peerContext};
    boost::system::error_code connectError;
    peer.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), port), connectError);
    ASSERT_FALSE(connectError) << "the peer could not reach the listener: " << connectError.message();

    const auto giveUpAt = std::chrono::steady_clock::now() + 5s;
    while (pending.empty() && std::chrono::steady_clock::now() < giveUpAt)
    {
      pending = ReverseConnectListenerTestAccess::pending_handshakes(listener);
      if (pending.empty())
      {
        std::this_thread::sleep_for(10ms);
      }
    }
    ASSERT_EQ(pending.size(), 1u) << "the accepted connection produced no handshake to observe";

    peer.close(connectError);
    pool.stop();  // whatever is queued will now never run
    listener.reset();  // and the listener lets go of its pending handshake without a stop
  }  // the pool's destructor destroys the work it abandoned

  EXPECT_TRUE(pending[0].expired())
    << "the ConnectionProtocol outlived the listener, the peer and the executor, so something in that "
       "handshake still owns it - the per-handshake state the connection's own callbacks carry";
}
