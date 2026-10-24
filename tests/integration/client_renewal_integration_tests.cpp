// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief End-to-end SecurityToken renewal (OPC 10000-6 6.7.4): a public Connection keeps working across
///        several renewals of its SecureChannel.

#include "test_log_sink.h"
#include "test_utilities.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_error_chain.h"
#include "ua_test_server.h"
#include "ua_variable_id.h"
#include "test_components.h"

#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <thread>

namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

constexpr auto lifetime = 1000ms;

class ClientRenewalIntegration : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // The server grants the short lifetime the client asks for, so the channel renews every ~750 ms.
    mServer.create([](ApplicationConfig& application)
      { application.stack_limits().secureChannelMinimumLifetime = lifetime; },
      nullptr);
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
    mClient.emplace(client::Client::create(mClientPool.executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = ua::test_utils::create_test_config()},
      client::ClientComponents{.crypto = ua::test_helpers::test_crypto(),
        .logSink = ua::test_helpers::test_log_sink(),
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    mClient.reset();
    ua::test_utils::stop_pool_in_teardown(mClientPool, "renewal-client");
  }

  ua::test_helpers::TestServer mServer;
  boost::asio::thread_pool mClientPool{2};
  std::optional<client::Client> mClient;
  std::string mEndpointUrl;
};

}  // namespace

// CL-SC-009 (OPC 10000-6 6.7.4; owner decision 2026-10-03, BR-11): after each renewal the client sends under
// the new token, so the server - which keeps the old token only until it sees the new one - stays in step. A
// Read every 250 ms for 5 s spans several renewals; every one succeeds. Falsifiable: the former client kept
// sending under the old token until it received a new-token message, so after the second renewal the server
// no longer knew its token and refused the request (BadSecureChannelTokenUnknown).
// @relation(AC-CL-SC-009-02, scope=function)
TEST_F(ClientRenewalIntegration, AConnectionKeepsWorkingAcrossTwoRenewals)
{
  client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.channelLifetime = lifetime;
  config.reconnect = std::nullopt;
  auto connected = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connected.is_good()) << ua::format(connected.status_code());
  auto connection = std::move(connected).value();

  const auto end = std::chrono::steady_clock::now() + 5s;
  int reads = 0;
  while (std::chrono::steady_clock::now() < end)
  {
    const auto value = connection.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
    ASSERT_TRUE(value.is_good()) << "read " << reads
                                 << " failed after renewals: " << ua::format(value.status_code());
    ++reads;
    std::this_thread::sleep_for(250ms);
  }
  EXPECT_GE(reads, 15);
  (void)connection.try_close_sync();
}
