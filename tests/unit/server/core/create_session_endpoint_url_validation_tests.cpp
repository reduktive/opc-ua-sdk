// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <stdexcept>
#include <unordered_map>

#include "ua_discovery_service_set.h"

using namespace ua;
using namespace ua::server;

namespace
{

class FakeDiscoveryDependencies final : public DiscoveryDependencies
{
public:
  ListenerHandleList listenersValue;
  std::unordered_map<std::uint64_t, std::vector<ua::transport::EndpointUrl>> advertised;

  boost::asio::any_io_executor executor() override
  {
    throw std::runtime_error{"not used"};
  }

  ::ua::ApplicationIdentity identity() override
  {
    throw std::runtime_error{"not used"};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    throw std::runtime_error{"not used"};
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    throw std::runtime_error{"not used"};
  }

  shared_ptr<ua::CertificateStore> default_application_group_certificate_store() override
  {
    throw std::runtime_error{"not used"};
  }

  shared_ptr<ua::server::RegisteredServerStore> registered_server_store() override
  {
    return nullptr;
  }

  ::ua::server::ListenerHandleList listeners() override
  {
    return listenersValue;
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle /*listener*/) override
  {
    throw std::runtime_error{"not used"};
  }

  std::vector<::ua::transport::EndpointUrl> advertised_urls(::ua::server::ListenerHandle listener) override
  {
    const auto it = advertised.find(listener.value);
    if (it == advertised.end())
    {
      return {};
    }
    return it->second;
  }

  ::ua::Logger logger() override
  {
    return {};
  }
};

}  // namespace

TEST(CreateSessionEndpointUrlValidationTests, EmptyEndpointUrlIsRejected)
{
  FakeDiscoveryDependencies deps;
  deps.listenersValue = {ListenerHandle{1}};
  deps.advertised.emplace(
    1, std::vector<ua::transport::EndpointUrl>{ua::transport::EndpointUrl{"opc.tcp://a:1"}});

  EXPECT_FALSE(Discovery::is_endpoint_url_accepted("", deps));
}

TEST(CreateSessionEndpointUrlValidationTests, DifferentPortIsRejected)
{
  FakeDiscoveryDependencies deps;
  deps.listenersValue = {ListenerHandle{1}};
  deps.advertised.emplace(
    1, std::vector<ua::transport::EndpointUrl>{ua::transport::EndpointUrl{"opc.tcp://a:1"}});

  EXPECT_FALSE(Discovery::is_endpoint_url_accepted("opc.tcp://a:2", deps));
}

TEST(CreateSessionEndpointUrlValidationTests, DifferentHostSamePortIsAccepted)
{
  // Port + path matching means any hostname is accepted for the same listener resource.
  FakeDiscoveryDependencies deps;
  deps.listenersValue = {ListenerHandle{1}};
  deps.advertised.emplace(
    1, std::vector<ua::transport::EndpointUrl>{ua::transport::EndpointUrl{"opc.tcp://myhostname:4840"}});

  EXPECT_TRUE(Discovery::is_endpoint_url_accepted("opc.tcp://localhost:4840", deps));
}

TEST(CreateSessionEndpointUrlValidationTests, MatchingEndpointUrlIsAccepted)
{
  FakeDiscoveryDependencies deps;
  deps.listenersValue = {ListenerHandle{1}, ListenerHandle{2}};
  deps.advertised.emplace(
    1, std::vector<ua::transport::EndpointUrl>{ua::transport::EndpointUrl{"opc.tcp://a:1"}});
  deps.advertised.emplace(
    2, std::vector<ua::transport::EndpointUrl>{ua::transport::EndpointUrl{"opc.tcp://b:2"}});

  EXPECT_TRUE(Discovery::is_endpoint_url_accepted("opc.tcp://b:2", deps));
}
