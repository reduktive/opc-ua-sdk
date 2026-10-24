// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_server.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <future>
#include "posting_writes_namespace.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;

// Covers SVR-DISC-GE-005 (coverage-audit retag).
// @relation(SVR-DISC-GE-005, SVR-DISC-MDL-003, scope=function)
TEST(ServerListenerEndpointsTests, EndpointsAreScopedPerListener)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bindA;
  bindA.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bindA.address = "0.0.0.0:0";

  ua::transport::BindAddress bindB;
  bindB.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bindB.address = "127.0.0.1:0";

  const auto handleA = server.listen_sync(std::move(bindA), {});
  const auto handleB = server.listen_sync(std::move(bindB), {});

  ServerEndpointConfig epA;
  epA.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  epA.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  epA.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  ServerEndpointConfig epB;
  epB.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  epB.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
  epB.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  server.add_endpoint(handleA, epA);
  server.add_endpoint(handleB, epB);

  const auto endpointsA = server.endpoints(handleA);
  const auto endpointsB = server.endpoints(handleB);

  ASSERT_EQ(endpointsA.size(), 1u);
  ASSERT_EQ(endpointsB.size(), 1u);
  EXPECT_EQ(endpointsA.front(), epA);
  EXPECT_EQ(endpointsB.front(), epB);

  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Every public configuration field must be proven end to end at a NON-DEFAULT value.
// `ListenOptions::failIfAlreadyListening` is the one knob on
// `ServerConfig::mListeners[].listenOptions`, and its whole purpose is to make a repeated
// listen on an address already served idempotent instead of an error - so both settings are
// asserted here, against the same bind address.
TEST(ServerListenerEndpointsTests, FailIfAlreadyListeningDecidesWhetherARepeatedListenIsAnError)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";

  const auto first = server.listen_sync(bind, {});

  // The DEFAULT (true): a second listen on the same bind address is refused.
  EXPECT_THROW((void)server.listen_sync(bind, ua::server::ListenOptions{}), ua::UaException)
    << "the default must refuse a duplicate listen rather than silently returning the first handle";

  // NON-DEFAULT (false): the same call becomes idempotent and yields the EXISTING listener, which is
  // what makes a re-entrant start safe rather than merely quiet.
  ua::server::ListenOptions idempotent;
  idempotent.failIfAlreadyListening = false;
  const auto again = server.listen_sync(bind, idempotent);
  EXPECT_EQ(again, first) << "an idempotent listen must return the handle already serving that address";

  server.shutdown_sync();
}

// On a running Server, adding a secured endpoint fetches the application certificates, and the store
// answers that fetch by a post to the Server's executor. Called from a thread of that executor - from a
// handler or callback - the wait could never end; add_endpoint must refuse with Bad_WouldBlock instead.
TEST(ServerListenerEndpointsTests, AddEndpointOnTheServersExecutorRefusesInsteadOfDeadlocking)
{
  ua::test::OneThreadExecutor executor;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = Server::create(executor.executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  const auto handle = server.listen_sync(std::move(bind), {});
  ASSERT_TRUE(server.try_start_sync().is_good());

  ServerEndpointConfig secured;
  secured.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  secured.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  secured.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  auto outcome = std::make_shared<std::promise<StatusCode>>();
  auto future = outcome->get_future();
  boost::asio::post(executor.executor(),
    [&server, handle, secured, outcome]
    {
      try
      {
        server.add_endpoint(handle, secured);
        outcome->set_value(StatusCode{Status::Good});
      }
      catch (const UaException& error)
      {
        outcome->set_value(error.status_code());
      }
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "add_endpoint blocked the thread its certificate fetch answers on";
  EXPECT_EQ(future.get(), StatusCode{Status::BadWouldBlock});
  EXPECT_TRUE(server.endpoints(handle).empty()) << "a refused endpoint must not be added";

  server.shutdown_sync();
}

// Server::create populates and wires the address space with blocking calls whose answers run on the
// Server's executor. Called from a thread of that executor it must refuse with Bad_WouldBlock rather
// than build a Server by waiting on itself.
TEST(ServerListenerEndpointsTests, CreateOnTheServersOwnExecutorRefusesInsteadOfBlockingIt)
{
  ua::test::OneThreadExecutor executor;
  auto outcome = std::make_shared<std::promise<StatusCode>>();
  auto future = outcome->get_future();
  boost::asio::post(executor.executor(),
    [executor = executor.executor(), outcome]
    {
      try
      {
        ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
          .application = test_utils::create_test_config(),
          .server = ua::server::ServerConfig{}};
        auto server = Server::create(
          executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
        outcome->set_value(StatusCode{Status::Good});
      }
      catch (const UaException& error)
      {
        outcome->set_value(error.status_code());
      }
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{20}), std::future_status::ready)
    << "Server::create blocked the thread of its own executor";
  EXPECT_EQ(future.get(), StatusCode{Status::BadWouldBlock});
}
