// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_FAKE_DISCOVERY_DEPENDENCIES_H
#define UA_TEST_HELPERS_FAKE_DISCOVERY_DEPENDENCIES_H

#include <unordered_map>
#include <utility>
#include <vector>

#include "services/ua_discovery_service_set.h"
#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_transport_address.h"

namespace ua::test_helpers
{

/// Concrete `DiscoveryDependencies` for tests.
///
/// All methods are sync getters (the underlying interface has no async surface).
/// Construct with an `boost::asio::any_io_executor`; populate identity / config / endpoints via
/// `set_*` methods or fluent setters as needed by the test.
class FakeDiscoveryDependencies final : public ua::server::DiscoveryDependencies
{
public:
  explicit FakeDiscoveryDependencies(boost::asio::any_io_executor executor)
    : mExecutor(std::move(executor)), mIdentity(ua::ApplicationIdentity::load_default()),
      mAppConfiguration(ua::ApplicationConfig::load_default())
  {}

  FakeDiscoveryDependencies& set_identity(ua::ApplicationIdentity identity)
  {
    mIdentity = std::move(identity);
    return *this;
  }

  FakeDiscoveryDependencies& set_application_configuration(ua::ApplicationConfig config)
  {
    mAppConfiguration = std::move(config);
    return *this;
  }

  FakeDiscoveryDependencies& set_server_configuration(ua::server::ServerConfig config)
  {
    mServerConfiguration = std::move(config);
    return *this;
  }

  FakeDiscoveryDependencies& set_default_application_group_certificate_store(
    std::shared_ptr<ua::CertificateStore> store)
  {
    mCertificateStore = std::move(store);
    return *this;
  }

  /// Install the inbound LDS registry. nullptr (the default) models the feature gated OFF, so
  /// the FindServers aggregation and the RegisterServer feature-gate see a null store.
  FakeDiscoveryDependencies& set_registered_server_store(
    std::shared_ptr<ua::server::RegisteredServerStore> store)
  {
    mRegisteredServerStore = std::move(store);
    return *this;
  }

  /// Register a listener handle with associated endpoint configurations and advertised URLs.
  /// The listener is appended to the listeners() return value in registration order.
  FakeDiscoveryDependencies& add_listener(::ua::server::ListenerHandle handle,
    std::vector<::ua::server::ServerEndpointConfig> endpoints,
    std::vector<::ua::transport::EndpointUrl> advertisedUrls = {})
  {
    mListeners.push_back(handle);
    mEndpointsByListener.emplace(handle, std::move(endpoints));
    mAdvertisedUrlsByListener.emplace(handle, std::move(advertisedUrls));
    return *this;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  ua::ApplicationIdentity identity() override
  {
    return mIdentity;
  }

  const ua::ApplicationConfig& configuration() override
  {
    return mAppConfiguration;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerConfiguration;
  }

  std::shared_ptr<ua::CertificateStore> default_application_group_certificate_store() override
  {
    return mCertificateStore;
  }

  std::shared_ptr<ua::server::RegisteredServerStore> registered_server_store() override
  {
    // nullptr (default) models the feature gated OFF; tests opt in via
    // set_registered_server_store(...) to exercise the server-as-LDS write/aggregation paths.
    return mRegisteredServerStore;
  }

  ::ua::server::ListenerHandleList listeners() override
  {
    return mListeners;
  }

  std::vector<::ua::server::ServerEndpointConfig> endpoints(::ua::server::ListenerHandle listener) override
  {
    auto it = mEndpointsByListener.find(listener);
    if (it == mEndpointsByListener.end())
      return {};
    return it->second;
  }

  std::vector<::ua::transport::EndpointUrl> advertised_urls(::ua::server::ListenerHandle listener) override
  {
    auto it = mAdvertisedUrlsByListener.find(listener);
    if (it == mAdvertisedUrlsByListener.end())
      return {};
    return it->second;
  }

  ::ua::Logger logger() override
  {
    return mLogger;
  }

  /// Install a logger (e.g. one backed by a recording sink) so a test can assert the discovery error
  /// paths log the full ErrorDetail server-side even though it is masked on the wire.
  void set_logger(::ua::Logger logger)
  {
    mLogger = std::move(logger);
  }

private:
  struct ListenerHandleHash
  {
    std::size_t operator()(::ua::server::ListenerHandle handle) const noexcept
    {
      return std::hash<std::uint64_t>{}(handle.value);
    }
  };

  boost::asio::any_io_executor mExecutor;
  ua::ApplicationIdentity mIdentity;
  ua::ApplicationConfig mAppConfiguration;
  ::ua::server::ServerConfig mServerConfiguration{};
  std::shared_ptr<ua::CertificateStore> mCertificateStore;
  std::shared_ptr<ua::server::RegisteredServerStore> mRegisteredServerStore;
  ::ua::server::ListenerHandleList mListeners;
  std::unordered_map<::ua::server::ListenerHandle, std::vector<::ua::server::ServerEndpointConfig>,
    ListenerHandleHash>
    mEndpointsByListener;
  std::unordered_map<::ua::server::ListenerHandle, std::vector<::ua::transport::EndpointUrl>,
    ListenerHandleHash>
    mAdvertisedUrlsByListener;
  ::ua::Logger mLogger;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_FAKE_DISCOVERY_DEPENDENCIES_H
