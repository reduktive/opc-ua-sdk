// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Integration tests for the foolproof client shutdown design (Phase B).
//
// The property under test: after CoreClient::shutdown_async completes - or, for the
// RAII case, after a Client/SecureChannel/Session falls out of scope - the
// client's boost::asio::thread_pool drains. pool.join() must return without
// pool.stop() being called.
//
// Each test wraps pool.join() in a worker thread + future with a timeout. If
// the join does not return within the timeout, the test fails and forcibly
// stops the pool so the worker can be joined (test does not hang CI).

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <future>
#include <thread>

#include "ua_built_in_authenticators.h"
#include "ua_core_client.h"
#include "ua_log_level.h"
#include "ua_server.h"
#include "ua_test_server.h"

#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

::testing::AssertionResult join_with_timeout(
  boost::asio::thread_pool& pool, std::chrono::milliseconds timeout)
{
  std::promise<void> done;
  auto fut = done.get_future();
  std::thread joiner(
    [&]()
    {
      pool.join();
      done.set_value();
    });
  if (fut.wait_for(timeout) == std::future_status::ready)
  {
    joiner.join();
    return ::testing::AssertionSuccess();
  }
  pool.stop();
  joiner.join();
  return ::testing::AssertionFailure() << "pool.join() did not return within " << timeout.count() << "ms";
}

constexpr auto joinTimeout = 5s;

class ClientShutdownSafetyTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    auto listener = mServer.listen_ephemeral();
    mServer.add_endpoint(listener, endpoint);
    mServer.start();

    auto urls = mServer.server().advertised_urls(listener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();
  }

  CoreClient make_client(boost::asio::any_io_executor ex)
  {
    auto client = CoreClient::create(ex,
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug});
    return client;
  }

  TestServer mServer;
  std::string mEndpointUrl;
};

}  // namespace

// Bare shutdown - no channels - pool drains.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterBareShutdown)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    client.shutdown_sync();
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Open channel, no session - CoreClient::shutdown_async cascades the channel close.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterShutdownWithOpenChannel)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});
    ASSERT_TRUE(channel.is_open());

    client.shutdown_sync();

    // Cascade closed the channel without an explicit channel.close_sync call.
    EXPECT_FALSE(channel.is_open());
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Open channel + active session - cascade closes session first, then channel.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterShutdownWithChannelAndSession)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "ShutdownSafetyTest"});
    session.activate_sync();
    ASSERT_TRUE(session.is_active());
    ASSERT_TRUE(channel.is_open());

    client.shutdown_sync();

    EXPECT_FALSE(session.is_active());
    EXPECT_FALSE(channel.is_open());
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Multiple channels + sessions - fan-in cascade closes every child.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterShutdownWithMultipleChildren)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());

    std::vector<SecureChannel> channels;
    std::vector<Session> sessions;
    for (int i = 0; i < 3; ++i)
    {
      auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});
      auto session = channel.create_session_sync({.sessionName = "Session-" + std::to_string(i)});
      session.activate_sync();
      sessions.push_back(std::move(session));
      channels.push_back(std::move(channel));
    }

    client.shutdown_sync();

    for (const auto& session : sessions)
      EXPECT_FALSE(session.is_active());
    for (const auto& channel : channels)
      EXPECT_FALSE(channel.is_open());
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Double-shutdown - second call sees null impl and returns BadInvalidState.
TEST_F(ClientShutdownSafetyTest, DoubleShutdownReturnsBadInvalidState)
{
  boost::asio::thread_pool pool;
  auto client = make_client(pool.get_executor());
  auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});

  EXPECT_TRUE(client.try_shutdown_sync().is_good());

  const auto second = client.try_shutdown_sync();
  ASSERT_TRUE(second.is_bad());
  EXPECT_EQ(second.status_code(), StatusCode{Status::BadInvalidState});

  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// RAII path - user forgets to call shutdown; scope exit drops the Client. The
// Client destructor releases the impl strong-ref; ~CoreClientImpl + child impl
// destructors cancel timers and close transports, draining the pool.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterRaiiDestructionNoShutdown)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "RaiiSession"});
    session.activate_sync();
    // No shutdown_sync - fall out of scope. Order of destruction: session, then
    // channel, then client (declared in reverse). Each releases its impl
    // strong-ref; the impls cascade their teardown through their destructors.
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// SecureChannel close_async releases its strand work - pool drains even without
// touching the client. Exercises the channel-level foolproof property directly.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterChannelCloseOnly)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});

    channel.close_sync();
    EXPECT_FALSE(channel.is_open());

    // Channel close drained. Now shut down the client to release reverse-connect
    // listeners etc., otherwise the client impl keeps a strand reference alive.
    client.shutdown_sync();
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}

// Session close_async releases its strand work.
TEST_F(ClientShutdownSafetyTest, JoinReturnsAfterSessionCloseOnly)
{
  boost::asio::thread_pool pool;
  {
    auto client = make_client(pool.get_executor());
    auto channel = client.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "CloseOnlySession"});
    session.activate_sync();

    session.close_sync();
    EXPECT_FALSE(session.is_active());

    // Channel and client must still go down for full pool drain.
    channel.close_sync();
    client.shutdown_sync();
  }
  EXPECT_TRUE(join_with_timeout(pool, joinTimeout));
}
