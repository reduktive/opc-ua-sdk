// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// There is no default crypto provider (security review B3-8, owner decisions 1 and 1a): a server or a
// client created without the application's provider is refused, from every factory, with
// Bad_ConfigurationError and the ErrorDetail code CryptoProviderRequired.

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include <string>

#include "test_components.h"
#include "test_utilities.h"
#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_core_client.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_server.h"
#include "ua_server_with_discovery.h"

using namespace ua;

namespace
{

server::CreateConfig server_config()
{
  server::CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = ApplicationConfig::load_default(),
    .server = server::ServerConfig{}};
  config.application.application_description_part().applicationUri = "urn:test:crypto-provider-required";
  return config;
}

client::CreateConfig client_config()
{
  return client::CreateConfig{
    .identity = ApplicationIdentity::load_default(), .application = ApplicationConfig::load_default()};
}

void expect_crypto_provider_required(const StatusCode& status)
{
  EXPECT_EQ(status.as_status(), Status::BadConfigurationError);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "CryptoProviderRequired");
}

class CryptoProviderRequired : public ::testing::Test
{
protected:
  boost::asio::thread_pool mPool{2};

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }
};

}  // namespace

// @verifies AC-SVR-SECADMIN-072-NO-DEFAULT-CRYPTO-PROVIDER
TEST_F(CryptoProviderRequired, AServerWithoutACryptoProviderIsRefused)
{
  try
  {
    server::Server::create(mPool.get_executor(), server_config(), {});
    FAIL() << "Server::create accepted a null crypto provider";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "CryptoProviderRequired");
  }

  const auto refused = server::Server::try_create(mPool.get_executor(), server_config(), {});
  ASSERT_TRUE(refused.is_bad());
  expect_crypto_provider_required(refused.status_code());

  const auto refusedWrapper = app::ServerWithDiscovery::try_create(
    mPool.get_executor(), server_config(), {}, app::DiscoveryRegistrationConfig{});
  ASSERT_TRUE(refusedWrapper.is_bad());
  expect_crypto_provider_required(refusedWrapper.status_code());
  // API-9.1: create, which replaced the public constructor, throws the same failure.
  try
  {
    (void)app::ServerWithDiscovery::create(
      mPool.get_executor(), server_config(), {}, app::DiscoveryRegistrationConfig{});
    ADD_FAILURE() << "ServerWithDiscovery::create accepted a null crypto provider";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "CryptoProviderRequired");
  }

  // Controls: the same calls with a provider create the server and the wrapper.
  auto created = server::Server::try_create(
    mPool.get_executor(), server_config(), {.crypto = test_helpers::test_crypto()});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code().as_status());
  created.value().shutdown_sync();

  auto createdWrapper = app::ServerWithDiscovery::try_create(mPool.get_executor(),
    server_config(),
    {.crypto = test_helpers::test_crypto()},
    app::DiscoveryRegistrationConfig{});
  ASSERT_TRUE(createdWrapper.is_good()) << to_string(createdWrapper.status_code().as_status());
  createdWrapper.value().server().shutdown_sync();
}

// @verifies AC-SVR-SECADMIN-072-NO-DEFAULT-CRYPTO-PROVIDER
TEST_F(CryptoProviderRequired, AClientWithoutACryptoProviderIsRefused)
{
  const auto refusedCore = client::CoreClient::try_create(mPool.get_executor(), client_config(), {});
  ASSERT_TRUE(refusedCore.is_bad());
  expect_crypto_provider_required(refusedCore.status_code());

  const auto refused = client::Client::try_create(mPool.get_executor(), client_config(), {});
  ASSERT_TRUE(refused.is_bad());
  expect_crypto_provider_required(refused.status_code());

  try
  {
    client::Client::create(mPool.get_executor(), client_config(), {});
    FAIL() << "Client::create accepted a null crypto provider";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status(), Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "CryptoProviderRequired");
  }

  // Controls: the same calls with a provider create the clients.
  auto createdCore = client::CoreClient::try_create(
    mPool.get_executor(), client_config(), {.crypto = test_helpers::test_crypto()});
  ASSERT_TRUE(createdCore.is_good()) << to_string(createdCore.status_code().as_status());
  EXPECT_TRUE(createdCore.value().try_shutdown_sync().is_good());

  auto created = client::Client::try_create(
    mPool.get_executor(), client_config(), {.crypto = test_helpers::test_crypto()});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code().as_status());
  EXPECT_TRUE(created.value().try_shutdown_sync().is_good());
}
