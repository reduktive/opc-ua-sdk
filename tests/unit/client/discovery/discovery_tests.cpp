// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Unit tests for the Client-level Discovery facade (client design section 7.6).
///
/// Drives ua::client::Discovery over a fake ephemeral-channel factory (the tier-0 interface) and a fake
/// mDNS transport - no real server. Verifies request threading, response decode, service-fault and
/// open-failure surfacing (ErrorDetail preserved and source-tagged), ephemeral-channel close on every
/// path, cached-endpoint admin (no discovery issued), and the mDNS browse path.

#include <gtest/gtest.h>

#include "ua_discovery.h"
#include "ua_discovery_channel.h"
#include "ua_discovery_test_access.h"
#include "ua_mdns_transport.h"

#include "ua_application_description.h"
#include "ua_endpoint_description.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_logger.h"
#include "ua_server_on_network.h"
#include "ua_object_id.h"
#include "ua_ref_structure.h"

#include "fake_certificate_store.h"
#include "test_pki_helpers.h"
#include "fake_discovery_dependencies.h"
#include "test_utilities.h"
#include "ua_application_configuration.h"
#include "ua_crypto_types.h"
#include "ua_discovery_registration.h"
#include "ua_discovery_service_set.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_response.h"
#include "ua_lds_registrar.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_registered_server.h"
#include "ua_registered_server_store.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include "ua_transport_address.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

using namespace ua;
using namespace ua::client;

namespace
{

// ------- Fake tier-0 ephemeral discovery channel + factory -------

/// Shared state between the fake factory and the channel it produces, so a test can preset the canned
/// responses and inspect what the facade actually issued.
struct FakeState
{
  // Recorded open() calls.
  int openCount{0};
  std::vector<std::string> openedUrls;

  // Force open() to fail (before any channel is created).
  bool failOpen{false};
  ua::StatusCode openFailStatus{ua::Status::BadTcpInternalError};

  // Recorded requests actually issued on the channel.
  std::optional<ua::FindServersRequest> findServersRequest;
  std::optional<ua::GetEndpointsRequest> getEndpointsRequest;
  std::optional<ua::FindServersOnNetworkRequest> findServersOnNetworkRequest;

  // Canned responses (default: Good, empty).
  ua::Result<ua::FindServersResponse> findServersResponse{ua::FindServersResponse{}};
  ua::Result<ua::GetEndpointsResponse> getEndpointsResponse{ua::GetEndpointsResponse{}};
  ua::Result<ua::FindServersOnNetworkResponse> findServersOnNetworkResponse{
    ua::FindServersOnNetworkResponse{}};

  // close() bookkeeping.
  int closeCount{0};

  // Temporary GDS Connection bookkeeping.
  int gdsOpenCount{0};
  std::vector<ua::client::ConnectionConfig> gdsOpenConfigs;
  int gdsCloseCount{0};
  bool deferGdsClose{false};
  std::function<void(ua::VoidResult)> gdsCloseCallback;
  bool exposeGdsNamespace{true};
  std::optional<ua::StatusCode> gdsOpenFailure;
  std::vector<ua::NodeIdResult> translationResults;
  std::vector<ua::RelativePath> translatedPaths;
  std::optional<ua::NodeId> calledObject;
  std::optional<ua::NodeId> calledMethod;
  std::vector<ua::Variant> callArguments;
  bool throwFromCall{false};
  ua::Result<ua::CallResult> gdsCallResult{ua::CallResult{ua::CallMethodResult{}}};
};

class FakeGdsConnection : public ua::client::detail::GdsConnection
{
public:
  explicit FakeGdsConnection(std::shared_ptr<FakeState> state) : mState(std::move(state))
  {
    std::vector<std::string> uris{"http://opcfoundation.org/UA/", "urn:test"};
    if (mState->exposeGdsNamespace)
    {
      uris.emplace_back("http://opcfoundation.org/UA/GDS/");
    }
    auto table = ua::client::NamespaceTable::create(std::move(uris), std::nullopt, 0);
    mNamespaceTable = std::move(table).value();
  }

  std::shared_ptr<const ua::client::NamespaceTable> namespace_table() const override
  {
    return mNamespaceTable;
  }

  void resolve_path_async(
    ua::NodeId /*start*/, ua::RelativePath path, std::function<void(ua::NodeIdResult)> callback) override
  {
    mState->translatedPaths.push_back(std::move(path));
    if (!mState->translationResults.empty())
    {
      auto result = std::move(mState->translationResults.front());
      mState->translationResults.erase(mState->translationResults.begin());
      callback(std::move(result));
      return;
    }
    if (mState->translatedPaths.size() == 1)
    {
      callback(ua::NodeIdResult{ua::NodeId{2, 5000}});
      return;
    }
    callback(ua::NodeIdResult{ua::NodeId{2, 5001}});
  }

  void call_method_async(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments,
    std::function<void(ua::Result<ua::CallResult>)> callback) override
  {
    mState->calledObject = std::move(object);
    mState->calledMethod = std::move(method);
    mState->callArguments = std::move(arguments);
    if (mState->throwFromCall)
    {
      throw std::runtime_error{"fake call dispatch failure"};
    }
    callback(mState->gdsCallResult);
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    ++mState->gdsCloseCount;
    if (mState->deferGdsClose)
    {
      mState->gdsCloseCallback = std::move(callback);
      return;
    }
    callback(ua::VoidResult{});
  }

private:
  std::shared_ptr<FakeState> mState;
  std::shared_ptr<const ua::client::NamespaceTable> mNamespaceTable;
};

class FakeDiscoveryChannel : public ua::client::detail::DiscoveryChannel
{
public:
  explicit FakeDiscoveryChannel(std::shared_ptr<FakeState> state) : mState(std::move(state))
  {}

  void find_servers_async(ua::FindServersRequest request,
    std::function<void(ua::Result<ua::FindServersResponse>)> callback) override
  {
    mState->findServersRequest = request;
    callback(mState->findServersResponse);
  }

  void get_endpoints_async(ua::GetEndpointsRequest request,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    mState->getEndpointsRequest = request;
    callback(mState->getEndpointsResponse);
  }

  void find_servers_on_network_async(ua::FindServersOnNetworkRequest request,
    std::function<void(ua::Result<ua::FindServersOnNetworkResponse>)> callback) override
  {
    mState->findServersOnNetworkRequest = request;
    callback(mState->findServersOnNetworkResponse);
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    ++mState->closeCount;
    callback(ua::VoidResult{});
  }

private:
  std::shared_ptr<FakeState> mState;
};

class FakeDiscoveryChannelFactory : public ua::client::detail::DiscoveryChannelFactory
{
public:
  explicit FakeDiscoveryChannelFactory(std::shared_ptr<FakeState> state) : mState(std::move(state))
  {}

  void open_async(std::string discoveryUrl, std::optional<std::chrono::milliseconds> /*timeout*/,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>>)> callback) override
  {
    using ChannelResult = ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>>;
    ++mState->openCount;
    mState->openedUrls.push_back(discoveryUrl);
    if (mState->failOpen)
    {
      callback(ChannelResult{mState->openFailStatus,
        ua::ErrorDetail::build("FakeTransportConnectFailed", "connect refused", "test.fake")});
      return;
    }
    callback(ChannelResult{std::static_pointer_cast<ua::client::detail::DiscoveryChannel>(
      std::make_shared<FakeDiscoveryChannel>(mState))});
  }

  void open_gds_async(ua::client::ConnectionConfig config,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::GdsConnection>>)> callback) override
  {
    ++mState->gdsOpenCount;
    mState->gdsOpenConfigs.push_back(std::move(config));
    if (mState->gdsOpenFailure)
    {
      callback(ua::Result<std::shared_ptr<ua::client::detail::GdsConnection>>{*mState->gdsOpenFailure,
        ua::make_error_detail("FakeGdsOpenFailed", "GDS open failed", "test.gds.open")});
      return;
    }
    callback(ua::Result<std::shared_ptr<ua::client::detail::GdsConnection>>{
      std::static_pointer_cast<ua::client::detail::GdsConnection>(
        std::make_shared<FakeGdsConnection>(mState))});
  }

private:
  std::shared_ptr<FakeState> mState;
};

// ------- Deferred-close ephemeral channel (W1 lifetime interface) -------

/// Shared state for the deferred-close fake. The fake channel's close_async STORES its callback and
/// returns WITHOUT firing (modelling a future channel whose close is genuinely asynchronous / deferred),
/// and the factory records a weak_ptr to the channel object so a test can observe whether the channel is
/// still alive at the moment the close completes.
struct DeferredCloseState
{
  std::function<void(ua::VoidResult)> storedCloseCallback;
  std::weak_ptr<void> channelWeak;  // observes the channel object's lifetime (non-owning).
  bool issued{false};
};

class DeferredCloseDiscoveryChannel : public ua::client::detail::DiscoveryChannel
{
public:
  explicit DeferredCloseDiscoveryChannel(std::shared_ptr<DeferredCloseState> state) : mState(std::move(state))
  {}

  void find_servers_async(ua::FindServersRequest /*request*/,
    std::function<void(ua::Result<ua::FindServersResponse>)> callback) override
  {
    mState->issued = true;
    callback(ua::Result<ua::FindServersResponse>{ua::FindServersResponse{}});
  }

  void get_endpoints_async(ua::GetEndpointsRequest /*request*/,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    callback(ua::Result<ua::GetEndpointsResponse>{ua::GetEndpointsResponse{}});
  }

  void find_servers_on_network_async(ua::FindServersOnNetworkRequest /*request*/,
    std::function<void(ua::Result<ua::FindServersOnNetworkResponse>)> callback) override
  {
    callback(ua::Result<ua::FindServersOnNetworkResponse>{ua::FindServersOnNetworkResponse{}});
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    // Deferred close: capture the completion and return WITHOUT firing. A correct caller must keep the
    // channel object alive until this stored callback is eventually invoked.
    mState->storedCloseCallback = std::move(callback);
  }

private:
  std::shared_ptr<DeferredCloseState> mState;
};

class DeferredCloseDiscoveryChannelFactory : public ua::client::detail::DiscoveryChannelFactory
{
public:
  explicit DeferredCloseDiscoveryChannelFactory(std::shared_ptr<DeferredCloseState> state)
    : mState(std::move(state))
  {}

  void open_async(std::string /*discoveryUrl*/, std::optional<std::chrono::milliseconds> /*timeout*/,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>>)> callback) override
  {
    auto channel = std::make_shared<DeferredCloseDiscoveryChannel>(mState);
    mState->channelWeak = channel;  // non-owning observation of the channel's lifetime.
    callback(ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>>{
      std::static_pointer_cast<ua::client::detail::DiscoveryChannel>(std::move(channel))});
  }

  void open_gds_async(ua::client::ConnectionConfig /*config*/,
    std::function<void(ua::Result<std::shared_ptr<ua::client::detail::GdsConnection>>)> callback) override
  {
    callback(ua::Result<std::shared_ptr<ua::client::detail::GdsConnection>>{ua::Status::BadNotSupported});
  }

private:
  std::shared_ptr<DeferredCloseState> mState;
};

// ------- Fake mDNS transport + browser -------

class FakeMdnsBrowser : public ua::mdns::MdnsBrowser
{
public:
  void set_callbacks(DiscoveredCallback discovered, LostCallback lost) override
  {
    mDiscovered = std::move(discovered);
    mLost = std::move(lost);
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    closed = true;
    if (callback)
      callback(ua::VoidResult{});
  }

  /// Test hook: pushes a record to the installed discovered callback.
  void emit(ua::mdns::ServiceRecord record)
  {
    if (mDiscovered)
      mDiscovered(std::move(record));
  }

  bool closed{false};

private:
  DiscoveredCallback mDiscovered;
  LostCallback mLost;
};

class FakeMdnsTransport : public ua::mdns::MdnsTransport
{
public:
  ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>> start_browse(
    std::string serviceType, ua::mdns::MdnsBrowseConfig /*config*/) override
  {
    lastServiceType = serviceType;
    ++startCount;
    if (fail)
    {
      return ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>>{
        failStatus, ua::ErrorDetail::build("FakeMdnsSocketFailed", "no multicast interface", "test.fake")};
    }
    browser = std::make_shared<FakeMdnsBrowser>();
    return ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>>{browser};
  }

  std::string lastServiceType;
  int startCount{0};
  bool fail{false};
  ua::StatusCode failStatus{ua::Status::BadNotSupported};
  std::shared_ptr<FakeMdnsBrowser> browser;
};

// ------- Builders + fixtures -------

Discovery make_discovery(std::shared_ptr<FakeState> state,
  std::shared_ptr<ua::mdns::MdnsTransport> mdns = nullptr, bool allowDeprecatedSecurityPolicies = false)
{
  return DiscoveryTestAccess::make(std::make_shared<FakeDiscoveryChannelFactory>(std::move(state)),
    std::move(mdns),
    allowDeprecatedSecurityPolicies);
}

ua::FindServersResponse make_find_servers_response(
  std::vector<std::string> applicationUris, ua::StatusCode serviceResult = ua::StatusCode{})
{
  ua::FindServersResponse response;
  response.response_header().service_result() = serviceResult;
  for (const auto& uri : applicationUris)
  {
    ua::ApplicationDescription app;
    app.application_uri() = uri;
    response.servers().push_back(app);
  }
  return response;
}

ua::GetEndpointsResponse make_get_endpoints_response(
  std::vector<std::string> endpointUrls, ua::StatusCode serviceResult = ua::StatusCode{})
{
  ua::GetEndpointsResponse response;
  response.response_header().service_result() = serviceResult;
  for (const auto& url : endpointUrls)
  {
    ua::EndpointDescription endpoint;
    endpoint.endpoint_url() = url;
    response.endpoints().push_back(endpoint);
  }
  return response;
}

ua::Result<ua::CallResult> make_gds_query_servers_result(
  ua::UtcTime resetTime, std::vector<std::string> discoveryUrls)
{
  ua::Array<ua::RefStructure<ua::Structure>> structures;
  for (const auto& discoveryUrl : discoveryUrls)
  {
    auto server = std::make_unique<ua::ServerOnNetwork>();
    server->discovery_url() = discoveryUrl;
    std::unique_ptr<ua::Structure> structure = std::move(server);
    ua::RefStructure<ua::Structure> reference;
    reference = std::move(structure);
    structures.push_back(std::move(reference));
  }
  ua::CallMethodResult methodResult;
  methodResult.output_arguments().push_back(ua::Variant{resetTime});
  methodResult.output_arguments().push_back(ua::Variant{std::move(structures)});
  return ua::Result<ua::CallResult>{ua::CallResult{std::move(methodResult)}};
}

ua::Result<ua::CallResult> make_gds_query_applications_result(
  ua::UtcTime resetTime, std::uint32_t nextRecordId, std::vector<std::string> applicationUris)
{
  ua::Array<ua::RefStructure<ua::Structure>> structures;
  for (const auto& applicationUri : applicationUris)
  {
    auto application = std::make_unique<ua::ApplicationDescription>();
    application->application_uri() = applicationUri;
    std::unique_ptr<ua::Structure> structure = std::move(application);
    ua::RefStructure<ua::Structure> reference;
    reference = std::move(structure);
    structures.push_back(std::move(reference));
  }
  ua::CallMethodResult methodResult;
  methodResult.output_arguments().push_back(ua::Variant{resetTime});
  methodResult.output_arguments().push_back(ua::Variant{nextRecordId});
  methodResult.output_arguments().push_back(ua::Variant{std::move(structures)});
  return ua::Result<ua::CallResult>{ua::CallResult{std::move(methodResult)}};
}

}  // namespace

// ===================== FindServers =====================

// @verifies AC-CL-DISC-003-FINDSERVERS-URL
// @verifies CL-DISC-002
// @relation(AC-CL-DISC-003-FINDSERVERS-URL, CL-DISC-002, CL-DISC-003, scope=function)
TEST(ClientDiscoveryFindServers, ThreadsCallerUrlAsEndpointUrlOnEphemeralChannel)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({"urn:Server:A"});
  auto discovery = make_discovery(state);

  const std::string url = "opc.tcp://host.example:4840/UADiscovery";
  auto result = discovery.try_find_servers_sync(url, FindServersOptions{});

  ASSERT_TRUE(result.is_good()) << format(result.status_code());
  // The ephemeral channel was opened against the exact caller URL (no hard-coded LDS default).
  ASSERT_EQ(state->openCount, 1);
  EXPECT_EQ(state->openedUrls.at(0), url);
  // The request's endpointUrl is the caller URL, threaded verbatim.
  ASSERT_TRUE(state->findServersRequest.has_value());
  EXPECT_EQ(std::string{state->findServersRequest->endpoint_url()}, url);
  // Response decoded.
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(std::string{result.value().at(0).application_uri()}, "urn:Server:A");
}

// @verifies CL-DISC-008
// @relation(CL-DISC-008, scope=function)
TEST(ClientDiscoveryFindServers, PassesServerUrisFilterVerbatim)
{
  auto state = std::make_shared<FakeState>();
  auto discovery = make_discovery(state);

  FindServersOptions options;
  options.serverUris = {"urn:A", "urn:B"};
  discovery.try_find_servers_sync("opc.tcp://lds:4840", options);

  ASSERT_TRUE(state->findServersRequest.has_value());
  const auto& serverUris = state->findServersRequest->server_uris();
  ASSERT_EQ(serverUris.size(), 2u);
  EXPECT_EQ(std::string{serverUris[0]}, "urn:A");
  EXPECT_EQ(std::string{serverUris[1]}, "urn:B");
}

// @verifies CL-DISC-008
// @relation(CL-DISC-008, scope=function)
TEST(ClientDiscoveryFindServers, EmptyResultWithGoodStatusIsGoodNotError)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({});  // Good, empty servers[].
  auto discovery = make_discovery(state);

  auto result = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().empty());
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST(ClientDiscoveryFindServers, SurfacesServiceFaultAsSourceTaggedBadResult)
{
  auto state = std::make_shared<FakeState>();
  // Good transport delivery, but the response header carries a bad serviceResult.
  state->findServersResponse = make_find_servers_response({}, ua::StatusCode{ua::Status::BadNothingToDo});
  auto discovery = make_discovery(state);

  auto result = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNothingToDo));
  ASSERT_NE(result.error_detail(), nullptr) << "service fault must carry an ErrorDetail";
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST(ClientDiscoveryFindServers, ClosesEphemeralChannelOnSuccess)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({"urn:A"});
  auto discovery = make_discovery(state);

  discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  EXPECT_EQ(state->closeCount, 1) << "the ephemeral channel must be closed after a successful query";
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST(ClientDiscoveryFindServers, ClosesEphemeralChannelOnServiceFault)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({}, ua::StatusCode{ua::Status::BadInternalError});
  auto discovery = make_discovery(state);

  discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  EXPECT_EQ(state->closeCount, 1) << "the ephemeral channel must be closed even when the query faults";
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST(ClientDiscoveryFindServers, OpenFailureSurfacesSourceTaggedDetailAndIssuesNoRequest)
{
  auto state = std::make_shared<FakeState>();
  state->failOpen = true;
  state->openFailStatus = ua::StatusCode{ua::Status::BadTcpInternalError};
  auto discovery = make_discovery(state);

  auto result = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadTcpInternalError));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
  // The tier-0 connect ErrorDetail is preserved as the cause (never discarded).
  ASSERT_NE(result.error_detail()->cause, nullptr);
  EXPECT_EQ(result.error_detail()->cause->source, "test.fake");
  // No FindServers request was ever issued because the channel never opened.
  EXPECT_FALSE(state->findServersRequest.has_value());
  EXPECT_EQ(state->closeCount, 0);
}

// @verifies CL-DISC-007
// @relation(CL-DISC-007, scope=function)
TEST(ClientDiscoveryFindServers, FacadeSecondCallAfterFirstFailureSucceeds)
{
  auto state = std::make_shared<FakeState>();
  // First call: service fault.
  state->findServersResponse = make_find_servers_response({}, ua::StatusCode{ua::Status::BadInternalError});
  auto discovery = make_discovery(state);

  auto first = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});
  ASSERT_TRUE(first.is_bad());

  // Second call: server recovers. The facade holds no sticky error state (stateless per call).
  state->findServersResponse = make_find_servers_response({"urn:Recovered"});
  auto second = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().size(), 1u);
  EXPECT_EQ(std::string{second.value().at(0).application_uri()}, "urn:Recovered");
  EXPECT_EQ(state->openCount, 2) << "each call opens its own ephemeral channel";
}

// @verifies CL-DISC-007
// A repeat call with identical arguments issues a fresh wire request and returns the server's CURRENT set
// (S2), not a memoised copy of the first (S1) - the facade holds no per-call state. Falsifier: a memoising
// facade would open no second channel and return the stale S1.
// @relation(CL-DISC-003, CL-DISC-007, scope=function)
TEST(ClientDiscoveryFindServers, FacadeRepeatCallReturnsFreshResult)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({"urn:S1"});
  auto discovery = make_discovery(state);

  auto first = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().size(), 1u);
  EXPECT_EQ(std::string{first.value().at(0).application_uri()}, "urn:S1");

  // The server's set changes between calls: a stateless facade observes S2, a memoising one returns S1.
  state->findServersResponse = make_find_servers_response({"urn:S2a", "urn:S2b"});
  auto second = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});
  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().size(), 2u) << "the second call must observe the changed set, not a cached S1";
  EXPECT_EQ(state->openCount, 2) << "each call opens its own ephemeral channel (no memoization)";
}

// @verifies CL-DISC-003
// Exact-code passthrough: find_servers surfaces the response header's serviceResult VERBATIM (never masked to
// a generic code) for each discovery error code the CTT FindServersBasic/Err-001 suite injects, and always
// source-tags the failure with a client.Discovery ErrorDetail. A parameterized body (not eight hand-copies)
// covers all matrix codes at the facade-logic layer.
class FindServersServiceResultPassthrough : public ::testing::TestWithParam<ua::Status>
{};

TEST_P(FindServersServiceResultPassthrough, SurfacesServiceResultVerbatim)
{
  const ua::StatusCode injected{GetParam()};
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({}, injected);
  auto discovery = make_discovery(state);

  auto result = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), injected) << "the injected serviceResult must reach the caller verbatim";
  ASSERT_NE(result.error_detail(), nullptr) << "the failure must carry an ErrorDetail";
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
}

INSTANTIATE_TEST_SUITE_P(FindServersMatrixCodes, FindServersServiceResultPassthrough,
  ::testing::Values(ua::Status::BadInternalError, ua::Status::BadNothingToDo, ua::Status::BadOutOfMemory,
    ua::Status::BadRequestTooLarge, ua::Status::BadResponseTooLarge, ua::Status::BadServerUriInvalid,
    ua::Status::BadUnexpectedError, ua::Status::BadUserAccessDenied));

// ===================== GetEndpoints =====================

// @verifies AC-CL-DISC-009-GETENDPOINTS-URL
// @verifies CL-DISC-010
// @relation(AC-CL-DISC-009-GETENDPOINTS-URL, CL-DISC-010, scope=function)
TEST(ClientDiscoveryGetEndpoints, ThreadsCallerUrlAndPreservesDistinctSameUrlEndpoints)
{
  auto state = std::make_shared<FakeState>();
  // Two endpoints with the SAME url - the facade must NOT de-duplicate (CL-DISC-010).
  state->getEndpointsResponse = make_get_endpoints_response({"opc.tcp://srv:4840", "opc.tcp://srv:4840"});
  auto discovery = make_discovery(state);

  const std::string url = "opc.tcp://srv:4840";
  auto result = discovery.try_get_endpoints_sync(url, GetEndpointsOptions{});

  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(state->getEndpointsRequest.has_value());
  EXPECT_EQ(std::string{state->getEndpointsRequest->endpoint_url()}, url);
  EXPECT_EQ(result.value().size(), 2u) << "same-URL endpoints must be preserved as distinct records";
}

// @verifies CL-DISC-007
// A repeat call with identical arguments issues a fresh wire request and returns the server's CURRENT set
// (E2), not a memoised copy of the first (E1). Falsifier: a facade cache or one-shot latch would suppress
// the second channel open or return the stale E1.
// @relation(CL-DISC-007, scope=function)
TEST(ClientDiscoveryGetEndpoints, FacadeRepeatCallReturnsFreshResult)
{
  auto state = std::make_shared<FakeState>();
  state->getEndpointsResponse = make_get_endpoints_response({"opc.tcp://e1-host:4840/UA"});
  auto discovery = make_discovery(state);

  auto first = discovery.try_get_endpoints_sync("opc.tcp://lds:4840", GetEndpointsOptions{});
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().size(), 1u);
  EXPECT_EQ(std::string{first.value().at(0).endpoint_url()}, "opc.tcp://e1-host:4840/UA");

  state->getEndpointsResponse =
    make_get_endpoints_response({"opc.tcp://e2a-host:4840/UA", "opc.tcp://e2b-host:4840/UA"});
  auto second = discovery.try_get_endpoints_sync("opc.tcp://lds:4840", GetEndpointsOptions{});

  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().size(), 2u) << "the second call must observe the changed set, not a cached E1";
  EXPECT_EQ(state->openCount, 2) << "each call opens its own ephemeral channel (no memoization)";
}

// @verifies AC-CL-DISC-010-DISTINCT-ENDPOINTS
// Part 4 section 5.4.4.1: a Server may return separate EndpointDescription records with the SAME endpointUrl
// but DIFFERENT security configurations; the client must treat each as a distinct Endpoint (NOT de-duplicate
// by URL, which would silently drop the secure endpoint). This pins the requirement's exact scenario: two
// same-URL endpoints differing by securityMode / securityPolicyUri are both preserved and distinguishable.
// @relation(AC-CL-DISC-010-DISTINCT-ENDPOINTS, scope=function)
TEST(ClientDiscoveryGetEndpoints, PreservesSameUrlEndpointsWithDifferentSecurity)
{
  auto state = std::make_shared<FakeState>();
  const std::string url = "opc.tcp://srv:4840";
  ua::GetEndpointsResponse response;
  ua::EndpointDescription none;
  none.endpoint_url() = url;
  none.security_mode() = ua::MessageSecurityMode::None;
  none.security_policy_uri() = ua::String{"http://opcfoundation.org/UA/SecurityPolicy#None"};
  ua::EndpointDescription secure;
  secure.endpoint_url() = url;
  secure.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  secure.security_policy_uri() = ua::String{"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"};
  response.endpoints().push_back(none);
  response.endpoints().push_back(secure);
  state->getEndpointsResponse = std::move(response);
  auto discovery = make_discovery(state);

  auto result = discovery.try_get_endpoints_sync(url, GetEndpointsOptions{});

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u)
    << "same-URL endpoints with DIFFERENT security must NOT be de-duplicated (Part 4 section 5.4.4.1)";
  // Both distinct security configurations survive verbatim and remain distinguishable.
  EXPECT_EQ(result.value()[0].security_mode(), ua::MessageSecurityMode::None);
  EXPECT_EQ(result.value()[1].security_mode(), ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_NE(std::string{result.value()[0].security_policy_uri()},
    std::string{result.value()[1].security_policy_uri()})
    << "the two same-URL records differ by security policy - keeping both is the whole point";
}

// Default discovery publication removes every recognised deprecated candidate while preserving current and
// None candidates in their original wire order.
// @verifies AC-CL-SECADMIN-011-DEPRECATED-OPT-IN
// @relation(AC-CL-SECADMIN-011-DEPRECATED-OPT-IN, scope=function)
TEST(ClientDiscoveryGetEndpoints, FiltersDeprecatedPoliciesByDefault)
{
  auto state = std::make_shared<FakeState>();
  ua::GetEndpointsResponse response;
  for (const auto policyUri : {"http://opcfoundation.org/UA/SecurityPolicy#None",
         "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
         "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
         "http://opcfoundation.org/UA/SecurityPolicy#Basic256"})
  {
    ua::EndpointDescription endpoint;
    endpoint.endpoint_url() = "opc.tcp://srv:4840";
    endpoint.security_policy_uri() = policyUri;
    response.endpoints().push_back(std::move(endpoint));
  }
  state->getEndpointsResponse = std::move(response);
  auto discovery = make_discovery(state);

  auto result = discovery.try_get_endpoints_sync("opc.tcp://srv:4840", GetEndpointsOptions{});

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_EQ(
    std::string{result.value()[0].security_policy_uri()}, "http://opcfoundation.org/UA/SecurityPolicy#None");
  EXPECT_EQ(std::string{result.value()[1].security_policy_uri()},
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
}

// @verifies AC-CL-SECADMIN-011-DEPRECATED-OPT-IN
// @relation(AC-CL-SECADMIN-011-DEPRECATED-OPT-IN, scope=function)
TEST(ClientDiscoveryGetEndpoints, KeepsDeprecatedPoliciesWithExplicitOptIn)
{
  auto state = std::make_shared<FakeState>();
  ua::GetEndpointsResponse response;
  ua::EndpointDescription deprecated;
  deprecated.endpoint_url() = "opc.tcp://srv:4840";
  deprecated.security_policy_uri() = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
  deprecated.security_level() = 255;  // hostile rank: deprecation still keeps it below a current policy.
  ua::EndpointDescription current;
  current.endpoint_url() = "opc.tcp://srv:4840";
  current.security_policy_uri() = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
  current.security_level() = 1;
  response.endpoints().push_back(std::move(deprecated));
  response.endpoints().push_back(std::move(current));
  state->getEndpointsResponse = std::move(response);
  auto discovery = make_discovery(state, nullptr, true);

  auto result = discovery.try_get_endpoints_sync("opc.tcp://srv:4840", GetEndpointsOptions{});

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_EQ(std::string{result.value()[0].security_policy_uri()},
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
  EXPECT_EQ(std::string{result.value()[1].security_policy_uri()},
    "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15");
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST(ClientDiscoveryGetEndpoints, SurfacesServiceFaultAsSourceTaggedBadResult)
{
  auto state = std::make_shared<FakeState>();
  state->getEndpointsResponse = make_get_endpoints_response({}, ua::StatusCode{ua::Status::BadServerHalted});
  auto discovery = make_discovery(state);

  auto result = discovery.try_get_endpoints_sync("opc.tcp://srv:4840", GetEndpointsOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadServerHalted));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
  EXPECT_EQ(state->closeCount, 1);
}

// ===================== FindServersOnNetwork =====================

// @verifies CL-DISC-013
// @relation(CL-DISC-013, scope=function)
TEST(ClientDiscoveryFindServersOnNetwork, ThreadsPaginationInputs)
{
  auto state = std::make_shared<FakeState>();
  auto discovery = make_discovery(state);

  FindServersOnNetworkOptions options;
  options.startingRecordId = 11;
  options.maxRecordsToReturn = 50;
  options.serverCapabilityFilter = {"LDS"};
  discovery.try_find_servers_on_network_sync("opc.tcp://lds-me:4840", options);

  ASSERT_TRUE(state->findServersOnNetworkRequest.has_value());
  EXPECT_EQ(state->findServersOnNetworkRequest->starting_record_id(), 11u);
  EXPECT_EQ(state->findServersOnNetworkRequest->max_records_to_return(), 50u);
  ASSERT_EQ(state->findServersOnNetworkRequest->server_capability_filter().size(), 1u);
  EXPECT_EQ(std::string{state->findServersOnNetworkRequest->server_capability_filter()[0]}, "LDS");
}

// @verifies CL-DISC-013
// @relation(CL-DISC-013, scope=function)
TEST(ClientDiscoveryFindServersOnNetwork, DecodesServerRecords)
{
  auto state = std::make_shared<FakeState>();
  ua::FindServersOnNetworkResponse response;
  ua::ServerOnNetwork record;
  record.record_id() = 7;
  record.server_name() = "MyServer";
  record.discovery_url() = "opc.tcp://myhost.local:4840";
  response.servers().push_back(record);
  state->findServersOnNetworkResponse = response;
  auto discovery = make_discovery(state);

  auto result =
    discovery.try_find_servers_on_network_sync("opc.tcp://lds-me:4840", FindServersOnNetworkOptions{});

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().servers.size(), 1u);
  EXPECT_EQ(result.value().servers.at(0).record_id(), 7u);
  EXPECT_EQ(std::string{result.value().servers.at(0).server_name()}, "MyServer");
}

// CL-DISC-013: FindServersOnNetwork must surface the response's lastCounterResetTime so a paginating caller
// can detect a server record-counter reset (Part 4 section 5.4.3 - a newer value than seen on a prior page
// means records may have been missed and the caller must re-request from startingRecordId=0). Falsifiable:
// before the reply carried the field, the value was discarded and unobservable.
// @verifies CL-DISC-013
// @relation(CL-DISC-013, scope=function)
TEST(ClientDiscoveryFindServersOnNetwork, SurfacesLastCounterResetTime)
{
  auto state = std::make_shared<FakeState>();
  ua::FindServersOnNetworkResponse response;
  const ua::DateTime resetTime = ua::DateTime::parse("2021-06-15T12:30:45Z");
  response.last_counter_reset_time() = resetTime;
  ua::ServerOnNetwork record;
  record.record_id() = 3;
  record.server_name() = "ResetProbe";
  response.servers().push_back(record);
  state->findServersOnNetworkResponse = response;
  auto discovery = make_discovery(state);

  auto result =
    discovery.try_find_servers_on_network_sync("opc.tcp://lds-me:4840", FindServersOnNetworkOptions{});

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().lastCounterResetTime, resetTime)
    << "the response's lastCounterResetTime must be surfaced to the caller (CL-DISC-013)";
  ASSERT_EQ(result.value().servers.size(), 1u);
  EXPECT_EQ(result.value().servers.at(0).record_id(), 3u);
}

// CL-DISC-013: the canonical Part 4 section 5.4.3 pagination-end case - a page with NO records still carries
// the server's lastCounterResetTime, so the caller can still compare it (a reset can occur on any page,
// including an empty final one).
// @verifies CL-DISC-013
// @relation(CL-DISC-013, scope=function)
TEST(ClientDiscoveryFindServersOnNetwork, SurfacesResetTimeOnEmptyPage)
{
  auto state = std::make_shared<FakeState>();
  ua::FindServersOnNetworkResponse response;
  const ua::DateTime resetTime = ua::DateTime::parse("2022-01-01T00:00:00Z");
  response.last_counter_reset_time() = resetTime;
  // No server records on this page.
  state->findServersOnNetworkResponse = response;
  auto discovery = make_discovery(state);

  auto result =
    discovery.try_find_servers_on_network_sync("opc.tcp://lds-me:4840", FindServersOnNetworkOptions{});

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().servers.empty());
  EXPECT_EQ(result.value().lastCounterResetTime, resetTime);
}

// CL-DISC-013: a serviceResult fault on FindServersOnNetwork surfaces as a bad Result (no partial reply),
// source-tagged by the facade, and the ephemeral channel is still closed. Exercises the changed
// Result<FindServersOnNetworkReply> error path.
// @verifies CL-DISC-013
// @relation(CL-DISC-013, scope=function)
TEST(ClientDiscoveryFindServersOnNetwork, ServiceFaultSurfacesBadResult)
{
  auto state = std::make_shared<FakeState>();
  ua::FindServersOnNetworkResponse response;
  response.response_header().service_result() = ua::StatusCode{ua::Status::BadServerHalted};
  state->findServersOnNetworkResponse = response;
  auto discovery = make_discovery(state);

  auto result =
    discovery.try_find_servers_on_network_sync("opc.tcp://lds-me:4840", FindServersOnNetworkOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadServerHalted));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
  EXPECT_EQ(state->closeCount, 1);
}

// ===================== GDS QueryServers =====================

// @verifies CL-DISC-013
// @verifies CL-DISC-016
// @relation(CL-DISC-013, CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, QueryServersMapsPart12InputsAndClosesBeforeCompletion)
{
  auto state = std::make_shared<FakeState>();
  state->deferGdsClose = true;
  const ua::UtcTime resetTime{2026, 7, 24, 12, 0, 0};
  state->gdsCallResult = make_gds_query_servers_result(resetTime, {"opc.tcp://server.example:4840"});
  auto discovery = make_discovery(state);

  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";
  GdsServerFilter filter;
  filter.startingRecordId = 41;
  filter.maxRecordsToReturn = 25;
  filter.applicationName = "Plant%";
  filter.applicationUri = "urn:example:%";
  filter.productUri = "urn:product:%";
  filter.serverCapabilities = {"DA", "HA"};

  std::optional<Discovery::GdsQueryServersResult> completed;
  discovery.gds_query_servers_async(std::move(config),
    std::move(filter),
    [&completed](Discovery::GdsQueryServersResult result) { completed = std::move(result); });

  ASSERT_EQ(state->gdsOpenCount, 1);
  ASSERT_EQ(state->gdsOpenConfigs.size(), 1u);
  EXPECT_EQ(state->gdsOpenConfigs[0].endpointUrl, "opc.tcp://gds.example:58810");
  ASSERT_EQ(state->translatedPaths.size(), 2u);
  ASSERT_TRUE(state->calledObject);
  ASSERT_TRUE(state->calledMethod);
  EXPECT_EQ(*state->calledObject, ua::NodeId(2, 5000));
  EXPECT_EQ(*state->calledMethod, ua::NodeId(2, 5001));
  ASSERT_EQ(state->callArguments.size(), 6u);
  EXPECT_EQ(state->callArguments[0].as<std::uint32_t>(), 41u);
  EXPECT_EQ(state->callArguments[1].as<std::uint32_t>(), 25u);
  EXPECT_EQ(std::string{state->callArguments[2].as<ua::String>()}, "Plant%");
  EXPECT_EQ(std::string{state->callArguments[3].as<ua::String>()}, "urn:example:%");
  EXPECT_EQ(std::string{state->callArguments[4].as<ua::String>()}, "urn:product:%");
  const auto& capabilities = state->callArguments[5].as<ua::Array<ua::String>>();
  ASSERT_EQ(capabilities.size(), 2u);
  EXPECT_EQ(std::string{capabilities[0]}, "DA");
  EXPECT_EQ(std::string{capabilities[1]}, "HA");

  EXPECT_EQ(state->gdsCloseCount, 1);
  EXPECT_FALSE(completed.has_value()) << "the facade must not complete before graceful GDS close";
  ASSERT_TRUE(state->gdsCloseCallback);
  auto closeCallback = std::move(state->gdsCloseCallback);
  state->gdsCloseCallback = {};
  closeCallback(ua::VoidResult{});

  ASSERT_TRUE(completed);
  ASSERT_TRUE(completed->is_good()) << format(completed->status_code());
  EXPECT_EQ(completed->value().lastCounterResetTime, resetTime);
  ASSERT_EQ(completed->value().servers.size(), 1u);
  EXPECT_EQ(std::string{completed->value().servers[0].discovery_url()}, "opc.tcp://server.example:4840");
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, TwoQueriesOpenAndCloseTwoIndependentConnections)
{
  auto state = std::make_shared<FakeState>();
  state->gdsCallResult = make_gds_query_servers_result(ua::UtcTime{}, {});
  auto discovery = make_discovery(state);

  ua::client::ConnectionConfig first;
  first.endpointUrl = "opc.tcp://gds.example:58810";
  ua::client::ConnectionConfig second = first;
  auto firstResult = discovery.try_gds_query_servers_sync(std::move(first), GdsServerFilter{});
  auto secondResult = discovery.try_gds_query_servers_sync(std::move(second), GdsServerFilter{});

  ASSERT_TRUE(firstResult.is_good()) << format(firstResult.status_code());
  ASSERT_TRUE(secondResult.is_good()) << format(secondResult.status_code());
  EXPECT_EQ(state->gdsOpenCount, 2);
  EXPECT_EQ(state->gdsCloseCount, 2);
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, MethodFailureStillClosesAndPreservesRichError)
{
  auto state = std::make_shared<FakeState>();
  std::unique_ptr<ua::ErrorDetail> innerDetail =
    ua::ErrorDetail::build("FakeGdsDenied", "GDS denied QueryServers", "test.gds");
  state->gdsCallResult = ua::Result<ua::CallResult>{ua::Status::BadUserAccessDenied, std::move(innerDetail)};
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadUserAccessDenied);
  EXPECT_EQ(state->gdsCloseCount, 1);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{result.status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "FakeGdsDenied"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, CloseFailureIsNotReportedAsSuccessfulDisconnect)
{
  auto state = std::make_shared<FakeState>();
  state->deferGdsClose = true;
  state->gdsCallResult = make_gds_query_servers_result(ua::UtcTime{}, {});
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  std::optional<Discovery::GdsQueryServersResult> completed;
  discovery.gds_query_servers_async(std::move(config),
    GdsServerFilter{},
    [&completed](Discovery::GdsQueryServersResult result) { completed = std::move(result); });
  ASSERT_TRUE(state->gdsCloseCallback);
  std::unique_ptr<ua::ErrorDetail> closeDetail =
    ua::ErrorDetail::build("FakeCloseFailed", "GDS close failed", "test.gds.close");
  auto closeCallback = std::move(state->gdsCloseCallback);
  state->gdsCloseCallback = {};
  closeCallback(ua::VoidResult{ua::Status::BadSecureChannelClosed, std::move(closeDetail)});

  ASSERT_TRUE(completed);
  ASSERT_TRUE(completed->is_bad());
  EXPECT_EQ(completed->status_code(), ua::Status::BadSecureChannelClosed);
  ASSERT_NE(completed->error_detail(), nullptr);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{completed->status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "FakeCloseFailed"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, OpenFailurePropagatesWithoutAttemptingClose)
{
  auto state = std::make_shared<FakeState>();
  state->gdsOpenFailure = ua::StatusCode{ua::Status::BadConnectionRejected};
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadConnectionRejected);
  EXPECT_EQ(state->gdsOpenCount, 1);
  EXPECT_EQ(state->gdsCloseCount, 0);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{result.status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "FakeGdsOpenFailed"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, MissingGdsNamespaceFailsAndStillCloses)
{
  auto state = std::make_shared<FakeState>();
  state->exposeGdsNamespace = false;
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://not-a-gds.example:4840";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadNodeIdUnknown);
  EXPECT_EQ(state->gdsCloseCount, 1);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{result.status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "GdsNamespaceMissing"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, BrowsePathFailurePreservesErrorAndStillCloses)
{
  auto state = std::make_shared<FakeState>();
  state->translationResults.emplace_back(ua::Status::BadNoMatch,
    ua::make_error_detail("FakeDirectoryMissing", "Directory path missing", "test.gds.path"));
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadNoMatch);
  EXPECT_EQ(state->gdsCloseCount, 1);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{result.status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "FakeDirectoryMissing"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, MalformedMethodOutputsFailAndStillClose)
{
  auto state = std::make_shared<FakeState>();
  ua::CallMethodResult methodResult;
  methodResult.output_arguments().push_back(ua::Variant{ua::UtcTime{}});
  state->gdsCallResult = ua::Result<ua::CallResult>{ua::CallResult{std::move(methodResult)}};
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadUnexpectedError);
  EXPECT_EQ(state->gdsCloseCount, 1);
  EXPECT_TRUE(std::ranges::any_of(ua::ErrorChainView{result.status_code()},
    [](const ua::ErrorDetail& detail) { return detail.code == "GdsQueryServersOutputCountMismatch"; }));
}

// @verifies CL-DISC-016
// @relation(CL-DISC-016, scope=function)
TEST(ClientDiscoveryGds, CollaboratorExceptionBecomesBadResultAndStillCloses)
{
  auto state = std::make_shared<FakeState>();
  state->throwFromCall = true;
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_servers_sync(std::move(config), GdsServerFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::Status::BadInternalError);
  EXPECT_EQ(state->gdsCloseCount, 1);
}

// ===================== GDS QueryApplications =====================

// @verifies CL-DISC-018
// @relation(CL-DISC-018, scope=function)
TEST(ClientDiscoveryGdsApplications, ThreadsEveryConjunctiveFilterVerbatim)
{
  auto state = std::make_shared<FakeState>();
  const ua::UtcTime resetTime{2026, 7, 24, 13, 0, 0};
  state->gdsCallResult = make_gds_query_applications_result(resetTime, 88, {"urn:application:returned"});
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";
  GdsApplicationFilter filter;
  filter.startingRecordId = 17;
  filter.maxRecordsToReturn = 9;
  filter.applicationName = "MyApp";
  filter.applicationUri = "urn:my:%";
  filter.applicationType = 0x3;
  filter.productUri = "urn:product:%";
  filter.capabilities = {"LDS", "DA"};

  auto result = discovery.try_gds_query_applications_sync(std::move(config), std::move(filter));

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().lastCounterResetTime, resetTime);
  EXPECT_EQ(result.value().nextRecordId, 88u);
  ASSERT_EQ(result.value().applications.size(), 1u);
  EXPECT_EQ(std::string{result.value().applications[0].application_uri()}, "urn:application:returned");
  ASSERT_EQ(state->translatedPaths.size(), 2u);
  ASSERT_EQ(state->callArguments.size(), 7u);
  EXPECT_EQ(state->callArguments[0].as<std::uint32_t>(), 17u);
  EXPECT_EQ(state->callArguments[1].as<std::uint32_t>(), 9u);
  EXPECT_EQ(std::string{state->callArguments[2].as<ua::String>()}, "MyApp");
  EXPECT_EQ(std::string{state->callArguments[3].as<ua::String>()}, "urn:my:%");
  EXPECT_EQ(state->callArguments[4].as<std::uint32_t>(), 0x3u);
  EXPECT_EQ(std::string{state->callArguments[5].as<ua::String>()}, "urn:product:%");
  const auto& capabilities = state->callArguments[6].as<ua::Array<ua::String>>();
  ASSERT_EQ(capabilities.size(), 2u);
  EXPECT_EQ(std::string{capabilities[0]}, "LDS");
  EXPECT_EQ(std::string{capabilities[1]}, "DA");
  EXPECT_EQ(state->gdsCloseCount, 1);
  EXPECT_EQ(state->translatedPaths[1].elements()[0].target_name().name(), "QueryApplications");
}

// @verifies CL-DISC-018
// @relation(CL-DISC-018, scope=function)
TEST(ClientDiscoveryGdsApplications, DefaultFilterSendsOnlyEmptyAndZeroValues)
{
  auto state = std::make_shared<FakeState>();
  state->gdsCallResult = make_gds_query_applications_result(ua::UtcTime{}, 0, {});
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_applications_sync(std::move(config), GdsApplicationFilter{});

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(state->callArguments.size(), 7u);
  EXPECT_EQ(state->callArguments[0].as<std::uint32_t>(), 0u);
  EXPECT_EQ(state->callArguments[1].as<std::uint32_t>(), 0u);
  EXPECT_TRUE(state->callArguments[2].as<ua::String>().empty());
  EXPECT_TRUE(state->callArguments[3].as<ua::String>().empty());
  EXPECT_EQ(state->callArguments[4].as<std::uint32_t>(), 0u);
  EXPECT_TRUE(state->callArguments[5].as<ua::String>().empty());
  EXPECT_TRUE(state->callArguments[6].as<ua::Array<ua::String>>().empty());
  EXPECT_TRUE(result.value().applications.empty());
}

// @verifies CL-DISC-018
// @relation(CL-DISC-018, scope=function)
TEST(ClientDiscoveryGdsApplications, MalformedOutputFailsRichlyAndStillCloses)
{
  auto state = std::make_shared<FakeState>();
  ua::CallMethodResult methodResult;
  methodResult.output_arguments().push_back(ua::Variant{ua::UtcTime{}});
  methodResult.output_arguments().push_back(ua::Variant{std::uint32_t{0}});
  state->gdsCallResult = ua::Result<ua::CallResult>{ua::CallResult{std::move(methodResult)}};
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";

  auto result = discovery.try_gds_query_applications_sync(std::move(config), GdsApplicationFilter{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "GdsQueryApplicationsOutputCountMismatch");
  EXPECT_EQ(state->gdsCloseCount, 1);
}

// Part 12 section 6.6.10: the applications returned "shall pass all of the filters provided" - the filters
// are AND-combined, and the capabilities array is itself conjunctive. That makes the client's
// obligation a shape obligation: every supplied filter must travel inside ONE QueryApplications
// invocation, and the answer must be returned as the GDS gave it. A plausible implementation that
// reads the array-valued capabilities filter as "any of these" fans the query out - one call per
// capability, or one per filter field - and unions the answers, which returns applications matching
// only some filters while reporting the result as the complete conjunctive set. Here the GDS answers
// every call with the same single application, so a fanned-out facade shows up twice over: as extra
// browse-path resolutions and as a result set inflated past what the GDS returned.
// @verifies AC-CL-DISC-018-CONJUNCTIVE-FILTERS
TEST(ClientDiscoveryGdsApplications, SuppliesEveryFilterInOneConjunctiveQuery)
{
  auto state = std::make_shared<FakeState>();
  state->gdsCallResult =
    make_gds_query_applications_result(ua::UtcTime{}, 0, {"urn:application:passes:both"});
  auto discovery = make_discovery(state);
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";
  GdsApplicationFilter filter;
  filter.applicationName = "PlantServer";
  filter.applicationUri = "urn:plant:%";
  filter.capabilities = {"DA", "HA"};

  auto result = discovery.try_gds_query_applications_sync(std::move(config), std::move(filter));

  ASSERT_TRUE(result.is_good()) << format(result.status_code());
  // One GDS connection and one Directory/QueryApplications browse-path pair: a facade that ORed the
  // filters would resolve and call once per filter (or per capability), so these counts would grow.
  EXPECT_EQ(state->gdsOpenCount, 1) << "a conjunctive query is a single query, not one per filter";
  ASSERT_EQ(state->translatedPaths.size(), 2u)
    << "exactly one QueryApplications invocation was prepared - two paths, resolved once";
  // Both scalar filters and the whole capabilities array reached the server in the SAME request.
  ASSERT_EQ(state->callArguments.size(), 7u);
  EXPECT_EQ(std::string{state->callArguments[2].as<ua::String>()}, "PlantServer");
  EXPECT_EQ(std::string{state->callArguments[3].as<ua::String>()}, "urn:plant:%");
  const auto& capabilities = state->callArguments[6].as<ua::Array<ua::String>>();
  ASSERT_EQ(capabilities.size(), 2u) << "the capabilities filter must travel whole, not one per call";
  EXPECT_EQ(std::string{capabilities[0]}, "DA");
  EXPECT_EQ(std::string{capabilities[1]}, "HA");
  // The GDS's answer is surfaced verbatim - no union of per-filter answers widening the set.
  ASSERT_EQ(result.value().applications.size(), 1u)
    << "the caller must see only what passed every filter, not a union of per-filter results";
  EXPECT_EQ(std::string{result.value().applications[0].application_uri()}, "urn:application:passes:both");
}

// ===================== Status routing: the server's code reaches the caller =====================

namespace
{

// @p call with its CallMethodResult answered under @p status.
ua::Result<ua::CallResult> with_method_status(ua::Result<ua::CallResult> call, ua::StatusCode status)
{
  ua::CallResult method = std::move(call).value();
  ua::CallMethodResult methodResult = std::move(method).value();
  return ua::Result<ua::CallResult>{ua::CallResult{std::move(methodResult), std::move(status)}};
}

bool chain_has(const ua::StatusCode& status, std::string_view code)
{
  return std::ranges::any_of(
    ua::ErrorChainView{status}, [code](const ua::ErrorDetail& detail) { return detail.code == code; });
}

ua::client::ConnectionConfig gds_config()
{
  ua::client::ConnectionConfig config;
  config.endpointUrl = "opc.tcp://gds.example:58810";
  return config;
}

}  // namespace

// A Good subcode in the FindServers response's ServiceResult is the Result's code, with the servers.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDiscoveryStatusRouting, AFindServersServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    auto state = std::make_shared<FakeState>();
    state->findServersResponse = make_find_servers_response({"urn:Server:A"}, ua::StatusCode{serviceStatus});
    auto discovery = make_discovery(state);

    auto result = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});

    ASSERT_TRUE(result.is_good()) << format(result.status_code());
    EXPECT_EQ(result.status_code(), ua::StatusCode{serviceStatus});
    ASSERT_EQ(result.value().size(), 1u);
    EXPECT_EQ(std::string{result.value().at(0).application_uri()}, "urn:Server:A");
    EXPECT_EQ(state->closeCount, 1);
  }
}

// An Uncertain ServiceResult on a GetEndpoints response is the Result's code, with the endpoints.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDiscoveryStatusRouting, AnUncertainGetEndpointsServiceResultReachesTheApplication)
{
  auto state = std::make_shared<FakeState>();
  state->getEndpointsResponse = make_get_endpoints_response(
    {"opc.tcp://server.example:4840"}, ua::StatusCode{ua::Status::UncertainLastUsableValue});
  auto discovery = make_discovery(state);

  auto result = discovery.try_get_endpoints_sync("opc.tcp://server.example:4840", GetEndpointsOptions{});

  EXPECT_TRUE(result.is_uncertain()) << format(result.status_code());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_EQ(state->closeCount, 1);
}

// The discovery query is sent only over a Good channel: an Uncertain open is refused with
// Bad_InternalError (ServiceAnswerUncertain) and nothing is sent.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDiscoveryStatusRouting, AnUncertainChannelOpenIsRefusedAndNothingIsSent)
{
  auto state = std::make_shared<FakeState>();
  state->failOpen = true;
  state->openFailStatus = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  auto discovery = make_discovery(state);

  std::optional<Discovery::FindServersResult> completed;
  discovery.find_servers_async("opc.tcp://lds:4840",
    FindServersOptions{},
    [&completed](Discovery::FindServersResult result) { completed = std::move(result); });

  ASSERT_TRUE(completed.has_value());
  EXPECT_EQ(completed->status_code().as_status(), ua::Status::BadInternalError);
  EXPECT_TRUE(chain_has(completed->status_code(), "DiscoveryChannelOpenFailed"));
  EXPECT_TRUE(chain_has(completed->status_code(), "ServiceAnswerUncertain"));
  EXPECT_FALSE(state->findServersRequest.has_value());
}

// A Good subcode on the QueryServers Method's statusCode is the Result's code, with the reply.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDiscoveryStatusRouting, AGdsQueryServersGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    auto state = std::make_shared<FakeState>();
    state->gdsCallResult =
      with_method_status(make_gds_query_servers_result(ua::UtcTime{}, {"opc.tcp://server.example:4840"}),
        ua::StatusCode{methodStatus});
    auto discovery = make_discovery(state);

    auto result = discovery.try_gds_query_servers_sync(gds_config(), GdsServerFilter{});

    ASSERT_TRUE(result.is_good()) << format(result.status_code());
    EXPECT_EQ(result.status_code(), ua::StatusCode{methodStatus});
    ASSERT_EQ(result.value().servers.size(), 1u);
    EXPECT_EQ(std::string{result.value().servers[0].discovery_url()}, "opc.tcp://server.example:4840");
    EXPECT_EQ(state->gdsCloseCount, 1);
  }
}

// A Good subcode on the QueryApplications Method's statusCode is the Result's code, with the reply.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDiscoveryStatusRouting, AGdsQueryApplicationsGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    auto state = std::make_shared<FakeState>();
    state->gdsCallResult =
      with_method_status(make_gds_query_applications_result(ua::UtcTime{}, 7, {"urn:application:a"}),
        ua::StatusCode{methodStatus});
    auto discovery = make_discovery(state);

    auto result = discovery.try_gds_query_applications_sync(gds_config(), GdsApplicationFilter{});

    ASSERT_TRUE(result.is_good()) << format(result.status_code());
    EXPECT_EQ(result.status_code(), ua::StatusCode{methodStatus});
    ASSERT_EQ(result.value().applications.size(), 1u);
    EXPECT_EQ(std::string{result.value().applications[0].application_uri()}, "urn:application:a");
    EXPECT_EQ(state->gdsCloseCount, 1);
  }
}

// An Uncertain QueryServers answer without output arguments gives its code alone, and the Connection is
// closed.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientDiscoveryStatusRouting, AnUncertainGdsQueryWithoutAReplyGivesTheCodeAlone)
{
  auto state = std::make_shared<FakeState>();
  state->gdsCallResult =
    ua::Result<ua::CallResult>{ua::CallResult{ua::StatusCode{ua::Status::UncertainLastUsableValue}}};
  auto discovery = make_discovery(state);

  auto result = discovery.try_gds_query_servers_sync(gds_config(), GdsServerFilter{});

  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(state->gdsCloseCount, 1);
}

// The Directory the query is sent to is resolved only from a Good answer: an Uncertain resolution is refused
// with Bad_InternalError (ReferencesAnswerUncertain), no Method is called and the Connection is closed.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientDiscoveryStatusRouting, AnUncertainGdsPathResolutionIsRefusedAndNothingIsCalled)
{
  auto state = std::make_shared<FakeState>();
  state->translationResults.emplace_back(ua::StatusCode{ua::Status::UncertainLastUsableValue});
  auto discovery = make_discovery(state);

  auto result = discovery.try_gds_query_servers_sync(gds_config(), GdsServerFilter{});

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  EXPECT_TRUE(chain_has(result.status_code(), "GdsDirectoryResolutionFailed"));
  EXPECT_TRUE(chain_has(result.status_code(), "ReferencesAnswerUncertain"));
  EXPECT_FALSE(state->calledMethod.has_value());
  EXPECT_EQ(state->translatedPaths.size(), 1u);
  EXPECT_EQ(state->gdsCloseCount, 1);
}

// ===================== Cached-endpoint admin (CL-DISC-001) =====================

// @verifies CL-DISC-001
// @relation(CL-DISC-001, scope=function)
TEST(ClientDiscoveryConfigureEndpoint, BuildsEndpointWithoutIssuingDiscovery)
{
  auto state = std::make_shared<FakeState>();
  auto discovery = make_discovery(state);

  ManualEndpointConfig config;
  config.endpointUrl = "opc.tcp://cached:4840";
  config.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  config.securityMode = ua::MessageSecurityMode::None;

  auto result = discovery.configure_endpoint(config);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(std::string{result.value().endpoint_url()}, "opc.tcp://cached:4840");
  EXPECT_EQ(
    std::string{result.value().security_policy_uri()}, "http://opcfoundation.org/UA/SecurityPolicy#None");
  // The bypass: NO channel was opened and NO FindServers/GetEndpoints was issued.
  EXPECT_EQ(state->openCount, 0);
  EXPECT_FALSE(state->findServersRequest.has_value());
  EXPECT_FALSE(state->getEndpointsRequest.has_value());
}

// @verifies CL-DISC-001
// @relation(CL-DISC-001, scope=function)
TEST(ClientDiscoveryConfigureEndpoint, RejectsMissingUrlWithFieldNamedDetail)
{
  auto discovery = make_discovery(std::make_shared<FakeState>());

  ManualEndpointConfig config;
  config.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  auto result = discovery.configure_endpoint(config);

  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
}

// @verifies CL-DISC-001
// @relation(CL-DISC-001, scope=function)
TEST(ClientDiscoveryConfigureEndpoint, RejectsMissingSecurityPolicy)
{
  auto discovery = make_discovery(std::make_shared<FakeState>());

  ManualEndpointConfig config;
  config.endpointUrl = "opc.tcp://cached:4840";  // policy omitted
  auto result = discovery.configure_endpoint(config);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadSecurityPolicyRejected));
  ASSERT_NE(result.error_detail(), nullptr);
}

// @verifies AC-CL-SECADMIN-011-DEPRECATED-OPT-IN
// @relation(AC-CL-SECADMIN-011-DEPRECATED-OPT-IN, scope=function)
TEST(ClientDiscoveryConfigureEndpoint, RejectsDeprecatedPolicyByDefault)
{
  auto discovery = make_discovery(std::make_shared<FakeState>());
  ManualEndpointConfig config;
  config.endpointUrl = "opc.tcp://cached:4840";
  config.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;

  auto result = discovery.configure_endpoint(config);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_NE(
    ua::to_string(*result.shared_detail()).find("AllowDeprecatedSecurityPolicies"), std::string::npos);
}

// @verifies AC-CL-SECADMIN-011-DEPRECATED-OPT-IN
// @relation(AC-CL-SECADMIN-011-DEPRECATED-OPT-IN, scope=function)
TEST(ClientDiscoveryConfigureEndpoint, AllowsDeprecatedPolicyWithExplicitOptIn)
{
  auto discovery = make_discovery(std::make_shared<FakeState>(), nullptr, true);
  ManualEndpointConfig config;
  config.endpointUrl = "opc.tcp://cached:4840";
  config.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;

  auto result = discovery.configure_endpoint(config);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(
    std::string{result.value().security_policy_uri()}, "http://opcfoundation.org/UA/SecurityPolicy#Basic256");
}

// @verifies AC-CL-DISC-015-MDNS-SERVICE-NAME
// @relation(AC-CL-DISC-015-MDNS-SERVICE-NAME, scope=function)
TEST(ClientDiscoveryMdnsBrowse, UsesCorrectServiceNamePerScheme)
{
  auto transport = std::make_shared<FakeMdnsTransport>();
  auto discovery = make_discovery(std::make_shared<FakeState>(), transport);

  [[maybe_unused]] const auto browseTcp =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});
  EXPECT_EQ(transport->lastServiceType, "_opcua-tcp._tcp.local.");

  [[maybe_unused]] const auto browseWss =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Wss});
  EXPECT_EQ(transport->lastServiceType, "_opcua-tls._tcp.local.");

  [[maybe_unused]] const auto browseHttps =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Https});
  EXPECT_EQ(transport->lastServiceType, "_opcua-https._tcp.local.");
}

// @verifies CL-DISC-015
// @relation(CL-DISC-015, scope=function)
TEST(ClientDiscoveryMdnsBrowse, DeliversBrowsedServiceRecordsOverInjectedTransport)
{
  auto transport = std::make_shared<FakeMdnsTransport>();
  auto discovery = make_discovery(std::make_shared<FakeState>(), transport);

  auto browseResult =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});
  ASSERT_TRUE(browseResult.is_good());
  auto browser = browseResult.value();
  ASSERT_NE(browser, nullptr);

  std::optional<ua::mdns::ServiceRecord> received;
  browser->set_callbacks([&](ua::mdns::ServiceRecord record) { received = std::move(record); }, nullptr);

  ua::mdns::ServiceRecord record;
  record.serviceName = "MyServer._opcua-tcp._tcp.local.";
  record.hostName = "uaserver.example.com";
  record.port = 4840;
  transport->browser->emit(record);

  ASSERT_TRUE(received.has_value());
  EXPECT_EQ(received->serviceName, "MyServer._opcua-tcp._tcp.local.");
  EXPECT_EQ(received->hostName, "uaserver.example.com");
  EXPECT_EQ(received->port, 4840);
}

// @verifies CL-DISC-015
// @relation(CL-DISC-015, scope=function)
TEST(ClientDiscoveryMdnsBrowse, FailingTransportSurfacesSourceTaggedBadResult)
{
  auto transport = std::make_shared<FakeMdnsTransport>();
  transport->fail = true;
  transport->failStatus = ua::StatusCode{ua::Status::BadNotSupported};
  auto discovery = make_discovery(std::make_shared<FakeState>(), transport);

  auto result =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadNotSupported));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
  // The transport's own ErrorDetail is preserved as the cause (never discarded).
  ASSERT_NE(result.error_detail()->cause, nullptr);
  EXPECT_EQ(result.error_detail()->cause->source, "test.fake");
}

// @verifies AC-CL-DISC-006-NO-MDNS-DEPENDENCE
// @relation(AC-CL-DISC-006-NO-MDNS-DEPENDENCE, scope=function)
TEST(ClientDiscoveryFacadeIndependence, LdsFindServersWorksWhenMdnsTransportFails)
{
  auto state = std::make_shared<FakeState>();
  state->findServersResponse = make_find_servers_response({"urn:LdsServer"});
  auto transport = std::make_shared<FakeMdnsTransport>();
  transport->fail = true;  // mDNS is administratively disabled / unavailable.
  auto discovery = make_discovery(state, transport);

  // mDNS branch fails...
  auto mdns =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});
  EXPECT_TRUE(mdns.is_bad());

  // ...but the independent LDS FindServers path still succeeds.
  auto servers = discovery.try_find_servers_sync("opc.tcp://lds:4840", FindServersOptions{});
  ASSERT_TRUE(servers.is_good());
  ASSERT_EQ(servers.value().size(), 1u);
  EXPECT_EQ(std::string{servers.value().at(0).application_uri()}, "urn:LdsServer");
}

// @verifies AC-CL-DISC-006-NO-MDNS-DEPENDENCE
// @relation(AC-CL-DISC-006-NO-MDNS-DEPENDENCE, scope=function)
TEST(ClientDiscoveryFacadeIndependence, StartMdnsBrowseWithoutTransportReportsNotSupported)
{
  // A Discovery with no mDNS transport installed: mDNS is optional; the call must fail cleanly rather
  // than crash, and it must not be a prerequisite for the other paths.
  auto discovery = make_discovery(std::make_shared<FakeState>(), nullptr);

  auto result =
    discovery.start_mdns_browse(ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});

  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
}

// ===================== Ephemeral-channel lifetime (W1) =====================

// @verifies CL-DISC-003
// The close continuation must keep the ephemeral channel object alive until the close actually completes.
// A deferred-close channel stores its close callback and returns without firing; the channel must survive
// that window. With the pre-fix capture (callback + outcome only) the sole channel owner was destroyed as
// run_discovery unwound, so the object was freed while its own close_async was still in flight (a latent
// use-after-free the moment a channel impl captures `this` in a deferred close). RED before the fix.
// @relation(CL-DISC-003, scope=function)
TEST(ClientDiscoveryChannelLifetime, DeferredCloseKeepsChannelAliveUntilCloseCompletes)
{
  auto deferred = std::make_shared<DeferredCloseState>();
  auto discovery =
    DiscoveryTestAccess::make(std::make_shared<DeferredCloseDiscoveryChannelFactory>(deferred), nullptr);

  std::optional<Discovery::FindServersResult> delivered;
  discovery.find_servers_async("opc.tcp://lds:4840",
    FindServersOptions{},
    [&](Discovery::FindServersResult outcome) { delivered = std::move(outcome); });

  // The request was issued and the channel then scheduled a deferred close, so the discovery callback has
  // NOT been delivered yet: we are inside the close window.
  ASSERT_TRUE(deferred->issued);
  ASSERT_TRUE(static_cast<bool>(deferred->storedCloseCallback));
  ASSERT_FALSE(delivered.has_value());

  // The channel object must still be alive while its own close is pending. Pre-fix this weak_ptr was
  // already expired here (the channel was freed as run_discovery unwound) -> RED.
  EXPECT_FALSE(deferred->channelWeak.expired())
    << "the ephemeral channel was destroyed while its own close_async was still in flight (UAF)";

  // Completing the deferred close delivers the outcome. The close continuation still owns `channel` while
  // it runs, so the channel is only reclaimed once that continuation itself is dropped.
  auto storedClose = std::move(deferred->storedCloseCallback);
  storedClose(ua::VoidResult{});

  ASSERT_TRUE(delivered.has_value());
  EXPECT_TRUE(delivered->is_good()) << format(delivered->status_code());

  storedClose = nullptr;  // drop the close continuation -> release the final channel reference.
  EXPECT_TRUE(deferred->channelWeak.expired())
    << "no owner other than the close continuation should keep the channel alive";
}

// ===================== Production factory: client-gone bail (W2) =====================

// @verifies CL-DISC-002
// The production ephemeral-channel factory holds a weak_ptr to the owning client and must fail fast when
// that client has been destroyed, rather than dereferencing a dangling owner. An empty weak_ptr models an
// already-gone client.
// @relation(CL-DISC-002, scope=function)
TEST(ClientDiscoveryProductionFactory, OpenAsyncBailsBadInvalidStateWhenClientExpired)
{
  auto factory = ua::client::detail::make_secure_channel_discovery_factory(
    std::weak_ptr<ua::client::CoreClientImpl>{}, ua::Logger{});

  int fireCount = 0;
  std::optional<ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>>> captured;
  const std::string url = "opc.tcp://lds:4840/UADiscovery";
  factory->open_async(url,
    std::nullopt,
    [&](ua::Result<std::shared_ptr<ua::client::detail::DiscoveryChannel>> result)
    {
      ++fireCount;
      captured = std::move(result);
    });

  EXPECT_EQ(fireCount, 1) << "the open callback must fire exactly once";
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().value(), static_cast<uint32_t>(ua::Status::BadInvalidState));
  ASSERT_NE(captured->error_detail(), nullptr);
  EXPECT_EQ(captured->error_detail()->source, "client.Discovery");
  EXPECT_EQ(captured->error_detail()->code, "DiscoveryClientGone");
  // The endpointUrl context is recorded so the diagnostic names the target.
  const std::string endpointUrlKey{ua::ContextKeys::endpointUrl.value()};
  bool sawEndpointUrl = false;
  for (const auto& fact : captured->error_detail()->context)
  {
    if (fact.key == endpointUrlKey && fact.value == url)
    {
      sawEndpointUrl = true;
    }
  }
  EXPECT_TRUE(sawEndpointUrl) << "the DiscoveryClientGone detail must carry the endpointUrl context";
}

// ===================== Inert / null-factory Discovery (W3) =====================

// @verifies CL-DISC-002
// A Discovery constructed with no channel factory (e.g. a moved-from Client) must fail fast with a
// source-tagged BadInvalidState rather than dereferencing the null factory.
// @relation(CL-DISC-002, scope=function)
TEST(ClientDiscoveryNullFactory, TryFindServersSyncFailsBadInvalidState)
{
  auto discovery = DiscoveryTestAccess::make(nullptr, nullptr);

  auto result = discovery.try_find_servers_sync("opc.tcp://x", FindServersOptions{});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), static_cast<uint32_t>(ua::Status::BadInvalidState));
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "client.Discovery");
}

// ===================== Server discovery surface =====================
//
// The obligations below are the SERVER half of the discovery contract this facade consumes, so a
// canned response from FakeDiscoveryChannel could only ever test the fake. They are driven through
// the real production handler instead - `ua::server::DiscoveryServiceSet<RequestType>` and the
// `ua::server::Discovery` endpoint builder behind it - with only the dependency bundle faked, the
// same arrangement tests/unit/server/discovery/lds uses.

namespace
{

/// The single URL the staged listener advertises.
constexpr const char* advertisedUrl = "opc.tcp://localhost:4840/";

/// Same port and path as the advertised URL, but a HostName the server has never heard of - what a
/// NAT or a reverse proxy in front of the server puts in front of a client.
constexpr const char* unrecognisedHostUrl = "opc.tcp://nat-gateway.example.net:4840/";

constexpr const char* serverApplicationUri = "urn:reduktive:test:discovery-surface-server";

/// A None-policy, None-mode endpoint carrying one Anonymous user token policy. None policy keeps the
/// endpoint in the response even though the fake certificate store holds no application certificate.
ua::server::ServerEndpointConfig make_none_server_endpoint(std::string name)
{
  ua::server::ServerEndpointConfig configuration;
  configuration.name = std::move(name);
  configuration.securityPolicyId = ua::SecurityPolicyId::None;
  configuration.messageSecurityMode = ua::MessageSecurityMode::None;
  configuration.transportProfile = ua::TransportProfileId::UaTcpUaScUaBinary;
  configuration.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  return configuration;
}

class ServerDiscoveryResponseSurface : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mCertStore = ua::test_helpers::FakeCertificateStore::create();
    mDeps = std::make_shared<ua::test_helpers::FakeDiscoveryDependencies>(mPool->executor());
    mDeps->set_default_application_group_certificate_store(mCertStore);

    // The default configuration leaves applicationUri empty; a deployment always sets one, and the
    // serverEndpoints floor is about it being carried, not about it being defaulted.
    auto configuration = ua::ApplicationConfig::load_default();
    configuration.application_description_part().applicationUri = serverApplicationUri;
    mDeps->set_application_configuration(std::move(configuration));

    mDeps->add_listener(ua::server::ListenerHandle{1},
      {make_none_server_endpoint("ep1")},
      {ua::transport::EndpointUrl{advertisedUrl}});
  }

  void TearDown() override
  {
    mDeps.reset();
    mCertStore.reset();
    if (mPool)
    {
      mPool->stop();
      mPool->join();
    }
  }

  ua::Response run_find_servers(ua::FindServersRequest&& request)
  {
    std::promise<ua::Response> promised;
    auto future = promised.get_future();
    auto service = ua::server::DiscoveryServiceSet<ua::FindServersRequest>::create(mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&promised](ua::Response response) { promised.set_value(std::move(response)); });
    if (future.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the FindServers handler never completed";
      return ua::Response{};
    }
    return future.get();
  }

  ua::Response run_get_endpoints(ua::GetEndpointsRequest&& request)
  {
    std::promise<ua::Response> promised;
    auto future = promised.get_future();
    auto service = ua::server::DiscoveryServiceSet<ua::GetEndpointsRequest>::create(mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&promised](ua::Response response) { promised.set_value(std::move(response)); });
    if (future.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the GetEndpoints handler never completed";
      return ua::Response{};
    }
    return future.get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<ua::test_helpers::FakeCertificateStore> mCertStore;
  std::shared_ptr<ua::test_helpers::FakeDiscoveryDependencies> mDeps;
};

}  // namespace

// Part 4 section 5.4.2.1: when the endpointUrl a client supplies carries a HostName the server does not
// recognise, the server should still answer with a usable default discoveryUrl rather than an error
// or an empty discoveryUrls list. A plausible implementation matches the client URL against its
// advertised URLs whole - HostName included - finds nothing, and returns an empty servers[] or a
// fault, which makes the server undiscoverable from exactly the NAT / reverse-proxy networks that
// produce an unrecognised host in the first place.
// @verifies AC-SVR-DISC-FS-022-DEFAULT-URL-ON-UNKNOWN-HOST
TEST_F(ServerDiscoveryResponseSurface, FindServersAnswersUnrecognisedHostNameWithUsableDefaultUrl)
{
  ua::FindServersRequest request;
  request.endpoint_url() = ua::String{unrecognisedHostUrl};

  auto response = run_find_servers(std::move(request));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
    << "an unrecognised HostName is not an error condition";
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);

  const auto& servers = findResponse->servers().payload();
  ASSERT_FALSE(servers.empty()) << "the server must still describe itself";
  const auto& discoveryUrls = servers[0].discovery_urls().payload();
  ASSERT_FALSE(discoveryUrls.empty())
    << "an unrecognised HostName must not collapse discoveryUrls to an empty list";
  for (const auto& discoveryUrl : discoveryUrls)
  {
    const std::string text{discoveryUrl};
    EXPECT_FALSE(text.empty()) << "an empty discoveryUrl is not a usable default";
    EXPECT_EQ(text.rfind("opc.tcp://", 0), 0u) << "the default must be a usable URL, got: " << text;
  }
}

// Part 4 section 5.4.4.1 - the GetEndpoints twin of the FindServers clause above. An endpointUrl is a
// routing hint, not a filter key: an unrecognised HostName must still yield a usable endpointUrl.
// The plausible failure is the same one, and it is worse here because GetEndpoints is what a client
// uses to pick a security configuration - an empty endpoints[] leaves it nothing to connect with.
// @verifies AC-SVR-DISC-GE-019-DEFAULT-URL-ON-UNKNOWN-HOST
TEST_F(ServerDiscoveryResponseSurface, GetEndpointsAnswersUnrecognisedHostNameWithUsableDefaultUrl)
{
  ua::GetEndpointsRequest request;
  request.endpoint_url() = ua::String{unrecognisedHostUrl};

  auto response = run_get_endpoints(std::move(request));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
    << "an unrecognised HostName is not an error condition";
  auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr);
  EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);

  const auto& endpoints = getResponse->endpoints().payload();
  ASSERT_FALSE(endpoints.empty())
    << "an unrecognised HostName must not collapse endpoints[] to an empty list";
  for (const auto& endpoint : endpoints)
  {
    const std::string text{endpoint.endpoint_url()};
    EXPECT_FALSE(text.empty()) << "an empty endpointUrl is not a usable default";
    EXPECT_EQ(text.rfind("opc.tcp://", 0), 0u) << "the default must be a usable URL, got: " << text;
  }
}

// Part 4 section 7.2: a null `discoveryProfileUri` in an ApplicationDescription is the DEFAULT - it means
// the standard section 5.4 Discovery Services - not an absence of discovery capability. The SDK's server
// leaves the field null, so both halves must hold together: the field is null AND the endpoints it
// describes really do answer FindServers and GetEndpoints. Reading null as "no discovery support"
// (or, on the publishing side, filling the field in to "declare" support) would make a conforming
// server undiscoverable, since most servers leave it null precisely because they implement section 5.4.
// @verifies AC-SVR-DISC-GE-AD-001-DISCOVERYPROFILEURI-DEFAULT
TEST_F(ServerDiscoveryResponseSurface, NullDiscoveryProfileUriStillServesTheStandardDiscoveryServices)
{
  // (a) GetEndpoints - one of the two section 5.4 services - is served at the advertised URL, and every
  //     ApplicationDescription it publishes leaves discoveryProfileUri null.
  ua::GetEndpointsRequest endpointsRequest;
  endpointsRequest.endpoint_url() = ua::String{advertisedUrl};
  auto endpointsResponse = run_get_endpoints(std::move(endpointsRequest));
  auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(endpointsResponse.second.get());
  ASSERT_NE(getResponse, nullptr) << "GetEndpoints (Part 4 section 5.4.4) must be served";
  EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);
  const auto& endpoints = getResponse->endpoints().payload();
  ASSERT_FALSE(endpoints.empty()) << "no endpoint means nothing to make the claim about";
  for (const auto& endpoint : endpoints)
  {
    EXPECT_TRUE(endpoint.server().discovery_profile_uri().empty())
      << "the null default is what commits these endpoints to the section 5.4 Discovery Services";
  }

  // (b) FindServers - the other section 5.4 service - is served at the same URL, and makes the same claim.
  ua::FindServersRequest serversRequest;
  serversRequest.endpoint_url() = ua::String{advertisedUrl};
  auto serversResponse = run_find_servers(std::move(serversRequest));
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(serversResponse.second.get());
  ASSERT_NE(findResponse, nullptr) << "FindServers (Part 4 section 5.4.2) must be served";
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);
  const auto& servers = findResponse->servers().payload();
  ASSERT_FALSE(servers.empty());
  for (const auto& server : servers)
  {
    EXPECT_TRUE(server.discovery_profile_uri().empty())
      << "the server publishes the null default on the FindServers surface too";
    EXPECT_FALSE(server.discovery_urls().payload().empty())
      << "a description claiming section 5.4 support must name where those services live";
  }
}

// Part 4 section 5.6.2 recommends a server trim the CreateSession `serverEndpoints[]` entries, and this is
// the FLOOR below which trimming must not go: applicationUri, endpointUrl, securityMode,
// securityPolicyUri and the user token policies are exactly the fields the client compares against
// the unsecured GetEndpoints response, so dropping any one of them makes that cross-check
// impossible - the trimming recommendation reads as licence to null more than it permits.
// `serverEndpoints` is assigned verbatim from `ua::server::Discovery::get_endpoints_async`
// (ua_server_session.cpp, Session::on_create_response_endpoints_fetched), so that builder is the
// artefact under test.
// @verifies AC-SVR-DISC-GEN-018-MINIMAL-SERVERENDPOINTS
TEST_F(ServerDiscoveryResponseSurface, ServerEndpointsCarryTheFieldsTheClientCrossCheckNeeds)
{
  auto discovery = ua::server::Discovery::create();

  std::promise<ua::server::EndpointDescriptionListResult> promised;
  auto future = promised.get_future();
  discovery->get_endpoints_async(std::string{advertisedUrl},
    mDeps,
    [&promised](ua::server::EndpointDescriptionListResult result) { promised.set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "the serverEndpoints builder never completed";

  const auto serverEndpoints = future.get();
  ASSERT_TRUE(serverEndpoints.is_good()) << format(serverEndpoints.status_code());
  ASSERT_FALSE(serverEndpoints.value().empty())
    << "an empty serverEndpoints[] leaves the client nothing to verify against";

  for (const auto& endpoint : serverEndpoints.value())
  {
    EXPECT_EQ(std::string{endpoint.server().application_uri()}, serverApplicationUri)
      << "server.applicationUri is the identity half of the cross-check";
    EXPECT_FALSE(std::string{endpoint.endpoint_url()}.empty()) << "endpointUrl must survive the trim";
    EXPECT_NE(endpoint.security_mode(), ua::MessageSecurityMode::Invalid)
      << "securityMode must be populated, not left at the default-constructed Invalid";
    EXPECT_EQ(endpoint.security_mode(), ua::MessageSecurityMode::None)
      << "and it must be the mode the endpoint was configured with";
    EXPECT_FALSE(std::string{endpoint.security_policy_uri()}.empty())
      << "securityPolicyUri must survive the trim";
    const auto& userTokenPolicies = endpoint.user_identity_tokens().payload();
    ASSERT_FALSE(userTokenPolicies.empty()) << "the user token policies must survive the trim";
    for (const auto& policy : userTokenPolicies)
    {
      EXPECT_FALSE(std::string{policy.policy_id()}.empty())
        << "a policy the client cannot name back is not usable";
    }
  }
}

// @relation(AC-COMP-SVR-DISCOVERY-ENDPOINT-BUILDER-01-CERTIFICATE-LIST-FAILURE, scope=function)
TEST_F(ServerDiscoveryResponseSurface, CertificateListFailurePreservesExactResult)
{
  const std::shared_ptr<const ua::ErrorDetail> sentinelDetail =
    ua::make_error_detail("DiscoveryCertificateListSentinel",
      "Application certificate enumeration failed",
      "ServerDiscoveryResponseSurface");
  constexpr auto sentinelStatus = ua::Status::BadCertificateInvalid;
  mCertStore->getApplicationCertificatesResult.emplace(ua::StatusCode{sentinelStatus}, sentinelDetail);

  auto discovery = ua::server::Discovery::create();
  std::promise<ua::server::EndpointDescriptionListResult> promised;
  auto future = promised.get_future();
  std::atomic<std::size_t> completionCount{0};

  discovery->get_endpoints_async(std::string{advertisedUrl},
    mDeps,
    [&promised, &completionCount](ua::server::EndpointDescriptionListResult result) mutable
    {
      if (completionCount.fetch_add(1, std::memory_order_relaxed) == 0)
      {
        promised.set_value(std::move(result));
      }
    });

  ASSERT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready)
    << "Discovery did not surface the certificate-list failure";
  const auto observed = future.get();
  ASSERT_TRUE(observed.is_bad());
  EXPECT_EQ(observed.status_code().value(), ua::StatusCode{sentinelStatus}.value());
  EXPECT_EQ(observed.shared_detail(), sentinelDetail);
  EXPECT_EQ(completionCount.load(std::memory_order_relaxed), 1u);
}

// Part 4 section 5.4.4.1: the GetEndpoints `localeIds` list is a PRIORITY order, not a set - when the
// server can localize its text into more than one of the requested locales it must use the one
// appearing FIRST in the request. The plausible implementation copies the configured
// applicationName straight through (which is what
// `ApplicationConfig::construct_application_description` does), so the client receives the
// server's own canonical translation whatever it asked for: a client that ranked fr above de is
// answered in de, and the ordering contract is unobservable to it. Picking "the first locale the
// server holds that is mentioned anywhere in the request" is the same error seen from the other
// side, and this arrangement separates the two - the server's canonical translation is the LAST
// requested locale, so only a request-ordered pick yields fr.
// @verifies AC-SVR-DISC-GE-021-FIRST-MATCHING-LOCALE
TEST_F(ServerDiscoveryResponseSurface, GetEndpointsLocalizesWithTheFirstRequestedLocaleItSupports)
{
  // The server holds two translations of its application name: "de" (canonical, first-inserted)
  // and "fr". It holds no "es" translation.
  auto identity = ua::ApplicationIdentity::load_default();
  identity.applicationName = ua::LocalizedText{ua::LocaleId{"de"},
    ua::String{"Werksserver"}}.with_translation(ua::LocaleId{"fr"}, ua::String{"Serveur d usine"});
  mDeps->set_identity(std::move(identity));

  ua::GetEndpointsRequest request;
  request.endpoint_url() = ua::String{advertisedUrl};
  // Requested in priority order: es (unsupported), fr (supported), de (supported).
  request.locale_ids().push_back(ua::LocaleId{"es"});
  request.locale_ids().push_back(ua::LocaleId{"fr"});
  request.locale_ids().push_back(ua::LocaleId{"de"});

  auto response = run_get_endpoints(std::move(request));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
    << "a localeIds list the server can only partly satisfy is not an error condition";
  auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr);
  EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);

  const auto& endpoints = getResponse->endpoints().payload();
  ASSERT_FALSE(endpoints.empty()) << "no endpoint means nothing to make the claim about";
  for (const auto& endpoint : endpoints)
  {
    const auto& applicationName = endpoint.server().application_name();
    EXPECT_EQ(std::string{applicationName.locale()}, "fr")
      << "the first REQUESTED locale the server supports wins - not its own canonical locale, and "
         "not the last requested one";
    EXPECT_EQ(std::string{applicationName.text()}, "Serveur d usine")
      << "the text must be the fr translation, not the de text carrying an fr tag";
    EXPECT_EQ(applicationName.translation_count(), 1u)
      << "the wire form of a LocalizedText is a single {locale, text} pair, so the choice must "
         "already have been made server-side";
  }
}

// Part 12 section 5.1: a device shipping one Server and no separate LDS process hosts the LDS surface
// itself, so both section 5.4 Discovery Services must answer a request carrying the well-known discovery
// address - the only address a Client in that deployment has to try. The plausible implementation
// treats the request endpointUrl as a filter key: the well-known address carries the `/UADiscovery`
// path, which matches no advertised URL, so a strict match returns an empty servers[] / endpoints[]
// or faults, and the embedded server is undiscoverable to precisely the Client the clause exists
// for. The deployment staged here is the embedded case - one listener, and no RegisteredServerStore
// installed, so nothing but the server's own description can populate the FindServers answer.
// @verifies AC-SVR-DISC-EMB-001-SELFHOST
TEST_F(ServerDiscoveryResponseSurface, ServesFindServersAndGetEndpointsAtTheWellKnownAddress)
{
  const std::string wellKnownUrl = "opc.tcp://localhost:4840/UADiscovery";

  // (a) FindServers answers at the well-known address, with a record describing THIS server.
  ua::FindServersRequest serversRequest;
  serversRequest.endpoint_url() = ua::String{wellKnownUrl};
  auto serversResponse = run_find_servers(std::move(serversRequest));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(serversResponse.second.get()), nullptr)
    << "the well-known discovery address is not an error condition";
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(serversResponse.second.get());
  ASSERT_NE(findResponse, nullptr)
    << "FindServers (Part 4 section 5.4.2) must answer at the well-known address";
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);

  const auto& servers = findResponse->servers().payload();
  ASSERT_FALSE(servers.empty()) << "an embedded self-hosting server must still describe itself";
  bool describesThisServer = false;
  for (const auto& server : servers)
  {
    if (std::string{server.application_uri()} != serverApplicationUri)
    {
      continue;
    }
    describesThisServer = true;
    const auto& discoveryUrls = server.discovery_urls().payload();
    EXPECT_FALSE(discoveryUrls.empty())
      << "a self-hosting record must name where its discovery services live";
    for (const auto& discoveryUrl : discoveryUrls)
    {
      const std::string text{discoveryUrl};
      EXPECT_EQ(text.rfind("opc.tcp://", 0), 0u) << "the published address must be usable, got: " << text;
    }
  }
  EXPECT_TRUE(describesThisServer)
    << "with no separate Discovery Server, the only record FindServers can return is this server's";

  // (b) GetEndpoints - the other section 5.4 service - answers at the same well-known address.
  ua::GetEndpointsRequest endpointsRequest;
  endpointsRequest.endpoint_url() = ua::String{wellKnownUrl};
  auto endpointsResponse = run_get_endpoints(std::move(endpointsRequest));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(endpointsResponse.second.get()), nullptr)
    << "the well-known discovery address is not an error condition";
  auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(endpointsResponse.second.get());
  ASSERT_NE(getResponse, nullptr)
    << "GetEndpoints (Part 4 section 5.4.4) must answer at the well-known address";
  EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);

  const auto& endpoints = getResponse->endpoints().payload();
  ASSERT_FALSE(endpoints.empty())
    << "a Client that knows only the well-known address is left nothing to connect with";
  for (const auto& endpoint : endpoints)
  {
    const std::string text{endpoint.endpoint_url()};
    EXPECT_EQ(text.rfind("opc.tcp://", 0), 0u) << "the returned endpoint must be usable, got: " << text;
  }
}

// Part 6 section 7.6 makes the `/discovery` path-append CONDITIONAL: a Server derives a DiscoveryEndpoint
// address that way only when it needs one distinct from its base address. The deployment staged
// here needs no distinct address - one listener, one advertised URL, no separate discovery address
// configured - so the unconditional half of the obligation is what is on trial: the base address is
// published unchanged. The plausible implementation reads the clause as a convention rather than a
// condition and appends `/discovery` to whatever it advertises, which publishes an address that
// differs from the one the operator configured and the clients were handed, and it fails silently
// because the published string still parses and still looks like a discovery URL. Both section 5.4
// surfaces publish the address, so both are checked: FindServers in `discoveryUrls`, GetEndpoints in
// `endpointUrl`.
// @verifies AC-SVR-DISC-ADDR-004-DISCOVERY-PATH
TEST_F(ServerDiscoveryResponseSurface, PublishesTheBaseAddressWithNoDiscoveryPathAppended)
{
  ua::FindServersRequest serversRequest;
  serversRequest.endpoint_url() = ua::String{advertisedUrl};
  auto serversResponse = run_find_servers(std::move(serversRequest));

  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(serversResponse.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);
  const auto& servers = findResponse->servers().payload();
  ASSERT_FALSE(servers.empty()) << "no record means nothing to make the claim about";
  const auto& discoveryUrls = servers[0].discovery_urls().payload();
  ASSERT_FALSE(discoveryUrls.empty()) << "the server must name where its discovery services live";
  for (const auto& discoveryUrl : discoveryUrls)
  {
    const std::string text{discoveryUrl};
    EXPECT_EQ(text, advertisedUrl)
      << "with no distinct DiscoveryEndpoint address required, the configured base address must be "
         "published unchanged";
    EXPECT_EQ(text.find("/discovery"), std::string::npos)
      << "`/discovery` is appended only to derive a DISTINCT DiscoveryEndpoint address, got: " << text;
  }

  ua::GetEndpointsRequest endpointsRequest;
  endpointsRequest.endpoint_url() = ua::String{advertisedUrl};
  auto endpointsResponse = run_get_endpoints(std::move(endpointsRequest));

  auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(endpointsResponse.second.get());
  ASSERT_NE(getResponse, nullptr);
  EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);
  const auto& endpoints = getResponse->endpoints().payload();
  ASSERT_FALSE(endpoints.empty()) << "no endpoint means nothing to make the claim about";
  for (const auto& endpoint : endpoints)
  {
    const std::string text{endpoint.endpoint_url()};
    EXPECT_EQ(text, advertisedUrl) << "the GetEndpoints surface publishes the same unchanged address";
    EXPECT_EQ(text.find("/discovery"), std::string::npos)
      << "`/discovery` is appended only to derive a DISTINCT DiscoveryEndpoint address, got: " << text;
  }
}

// ===================== Server-as-LDS inbound registration surface =====================
//
// The obligations below govern what the server ACCEPTS when it serves the LDS role, so they are
// driven through the real inbound handler - `ua::server::DiscoveryServiceSet<RegisterServer2Request>`
// - with a live `ua::server::RegisteredServerStore` behind it. Only the dependency bundle is faked,
// so a refusal (or the absence of one) and the record left behind are both the server's own.

namespace
{

/// A registration that clears every inbound gate except the one the test under way is probing:
/// non-empty serverNames, a Server applicationType, and a discoveryUrl for the online case.
ua::RegisteredServer make_lds_registration(const std::string& serverUri)
{
  ua::RegisteredServer registration;
  registration.server_uri() = ua::String{serverUri};
  registration.product_uri() = ua::String{"urn:reduktive:test:lds-peer-product"};
  registration.server_type() = ua::ApplicationType::Server;
  registration.server_names().payload().push_back(
    ua::LocalizedText{ua::LocaleId{"en"}, ua::String{"LDS Peer"}});
  registration.discovery_urls().payload().push_back(ua::String{"opc.tcp://peer.example:4840/"});
  registration.is_online() = true;
  return registration;
}

/// The staged deployment of `ServerDiscoveryResponseSurface` plus a live inbound LDS registry, so
/// an accepted registration is observable in the store and a refused one is observably absent.
class ServerLdsRegistrationSurface : public ServerDiscoveryResponseSurface
{
protected:
  void SetUp() override
  {
    ServerDiscoveryResponseSurface::SetUp();
    ua::server::ServerConfig::LocalDiscoveryServer ldsConfiguration;
    ldsConfiguration.enabled = true;
    ldsConfiguration.registrationExpiry = std::chrono::seconds{600};
    mStore = ua::server::RegisteredServerStore::create(mPool->executor(), ldsConfiguration);
    mDeps->set_registered_server_store(mStore);
  }

  void TearDown() override
  {
    if (mStore)
    {
      std::promise<void> done;
      mStore->shutdown_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(std::chrono::seconds{2});
    }
    mStore.reset();
    ServerDiscoveryResponseSurface::TearDown();
  }

  /// Drives one RegisterServer2 through the real session-less handler on an authenticated channel
  /// whose peer certificate names exactly the serverUri being registered, so neither the
  /// security-mode gate nor the certificate-continuity gate can be what refuses the request.
  ua::Response run_register_server2(ua::RegisterServer2Request&& request)
  {
    ua::server::InboundRegistrationContext context;
    context.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
    context.peerApplicationUri = std::string{request.server().server_uri()};

    std::promise<ua::Response> promised;
    auto future = promised.get_future();
    auto service = ua::server::DiscoveryServiceSet<ua::RegisterServer2Request>::create(
      mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&promised](ua::Response response) { promised.set_value(std::move(response)); },
      std::move(context));
    if (future.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the RegisterServer2 handler never completed";
      return ua::Response{};
    }
    return future.get();
  }

  std::shared_ptr<ua::server::RegisteredServerStore> mStore;
};

}  // namespace

// Part 4 section 5.4.5.3 Table 7 read through Table 182 ("The Server URI is not valid"): a registration
// carrying no serverUri at all is refused at the service level with `Bad_ServerUriInvalid`. Only
// emptiness is driven here, because section 5.4.2.1 lets the ServerUri be "a GUID or similar construct",
// so a non-empty value carries no scheme or syntax obligation to fail; the other mandatory serverUri
// refusal - serverUri not matching the certificate applicationUri (section 5.4.5.1) - belongs to
// SVR-DISC-RS-003. Every other inbound gate is deliberately cleared: serverNames, serverType and
// discoveryUrls are populated, and the peer applicationUri is taken from the request's own serverUri
// so certificate continuity cannot be what refuses this. The registry is read with the store still
// live, so a record accepted despite the fault would be visible rather than lost to teardown.
// @verifies AC-SVR-DISC-RS-016-SERVERURIINVALID
TEST_F(ServerLdsRegistrationSurface, RefusesAnEmptyServerUriWithBadServerUriInvalid)
{
  ua::RegisterServer2Request emptyUriRequest;
  emptyUriRequest.server() = make_lds_registration("");
  auto emptyUriResponse = run_register_server2(std::move(emptyUriRequest));

  auto* emptyUriFault = dynamic_cast<ua::ServiceFault*>(emptyUriResponse.second.get());
  EXPECT_NE(emptyUriFault, nullptr) << "an empty serverUri must be refused, not registered";
  if (emptyUriFault != nullptr)
  {
    EXPECT_EQ(emptyUriFault->response_header().service_result(), ua::Status::BadServerUriInvalid);
  }

  // The refusal is at the service level, so no record may survive it - a registry entry keyed by an
  // empty serverUri is exactly what the refusal exists to keep out.
  EXPECT_TRUE(mStore->snapshot().empty())
    << "a registration refused for an empty serverUri must not appear in the registry";
}

// ===================== Inbound registration: the channel the request arrived on =====================
//
// The gates below all live in the channel context rather than in the request body, so they need a
// runner that leaves `InboundRegistrationContext` to the test (the fixture's own runner always
// stages a conforming channel). Every test here pairs its probe with a CONTROL registration over a
// conforming channel: a handler that refused every registration would otherwise pass a
// "was it refused?" assertion without implementing any gate at all.

namespace
{

/// One inbound-registration probe's identifiers, kept distinct per test so an accepted record and a
/// refused one are told apart by serverUri rather than by counting.
constexpr const char* controlPeerUri = "urn:reduktive:test:lds-peer-control";

/// `ServerLdsRegistrationSurface` with the channel context under the test's control, and with the
/// RegisterServer (v1) twin of the fixture's RegisterServer2 runner - Part 4 section 5.4.5.1 and
/// section 5.4.6.1 place the same client-authentication obligation on both services, so both are driven.
class ServerLdsRegistrationChannelSurface : public ServerLdsRegistrationSurface
{
protected:
  /// A conforming registration channel: message security is on, and the peer certificate's
  /// applicationUri is exactly the serverUri being registered.
  static ua::server::InboundRegistrationContext authenticated_channel(const std::string& serverUri)
  {
    ua::server::InboundRegistrationContext context;
    context.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
    context.peerApplicationUri = serverUri;
    return context;
  }

  /// A channel that secures the messages but cannot authenticate the CLIENT - the HTTPS case named
  /// in Part 4 section 5.4.5.1 / section 5.4.6.1, where the transport authenticates the server only and no
  /// client certificate reaches the application layer.
  static ua::server::InboundRegistrationContext client_unauthenticated_channel()
  {
    ua::server::InboundRegistrationContext context;
    context.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
    context.peerApplicationUri = std::nullopt;
    return context;
  }

  ua::Response run_register_server2_on(
    ua::RegisterServer2Request&& request, ua::server::InboundRegistrationContext context)
  {
    std::promise<ua::Response> promised;
    auto future = promised.get_future();
    auto service = ua::server::DiscoveryServiceSet<ua::RegisterServer2Request>::create(
      mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&promised](ua::Response response) { promised.set_value(std::move(response)); },
      std::move(context));
    if (future.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the RegisterServer2 handler never completed";
      return ua::Response{};
    }
    return future.get();
  }

  ua::Response run_register_server_v1_on(
    ua::RegisterServerRequest&& request, ua::server::InboundRegistrationContext context)
  {
    std::promise<ua::Response> promised;
    auto future = promised.get_future();
    auto service = ua::server::DiscoveryServiceSet<ua::RegisterServerRequest>::create(
      mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&promised](ua::Response response) { promised.set_value(std::move(response)); },
      std::move(context));
    if (future.wait_for(std::chrono::seconds{2}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the RegisterServer handler never completed";
      return ua::Response{};
    }
    return future.get();
  }

  bool store_holds(const std::string& serverUri)
  {
    const auto snapshot = mStore->snapshot();
    for (const auto& registered : snapshot)
    {
      if (std::string{registered.server_uri()} == serverUri)
      {
        return true;
      }
    }
    return false;
  }

  /// Registers `controlPeerUri` over a conforming channel and asserts it landed, so a later
  /// "refused" assertion cannot be satisfied by a handler that refuses everything.
  void register_control_peer()
  {
    ua::RegisterServer2Request control;
    control.server() = make_lds_registration(controlPeerUri);
    auto response = run_register_server2_on(std::move(control), authenticated_channel(controlPeerUri));
    ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
      << "the control registration arrives on a conforming channel and must be accepted - without it "
         "the refusal under test proves nothing";
    ASSERT_TRUE(store_holds(controlPeerUri)) << "the control registration must reach the registry";
  }

  /// Reports the refusal a probe drew, or nullopt when the handler accepted it.
  static std::optional<ua::StatusCode> refusal_of(const ua::Response& response)
  {
    auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
    if (fault == nullptr)
    {
      return std::nullopt;
    }
    return fault->response_header().service_result();
  }
};

}  // namespace

// Part 4 section 5.4.5.1: "A Server shall establish a SecureChannel with the Discovery Server before
// calling this Service" - the registration is session-less, so the channel is the ONLY thing that
// carries the registering server's identity. A request that reaches the handler with no channel
// state behind it must therefore be refused rather than stored. The plausible implementation
// validates only the request body - serverUri, serverNames, discoveryUrls are all well-formed here
// - and writes the record, which lets anyone who can reach the discovery port publish a directory
// entry. The status code is deliberately not pinned: Table 7 names no code for this refusal, so the
// obligation is that it IS refused and leaves no record.
// @verifies AC-SVR-DISC-RS-001-CHANNEL-BEFORE-REGISTER
TEST_F(ServerLdsRegistrationChannelSurface, RefusesRegisterServerThatArrivedWithoutASecureChannel)
{
  ASSERT_NO_FATAL_FAILURE(register_control_peer());

  const std::string probeUri = "urn:reduktive:test:lds-peer-no-channel";
  ua::RegisterServerRequest probe;
  probe.server() = make_lds_registration(probeUri);
  // A default-constructed context is what the dispatch fills in when there is no established,
  // secured channel behind the request: no negotiated message security, no peer certificate.
  auto response = run_register_server_v1_on(std::move(probe), ua::server::InboundRegistrationContext{});

  const auto refusal = refusal_of(response);
  ASSERT_TRUE(refusal.has_value())
    << "a RegisterServer with no SecureChannel behind it must be refused, not registered";
  EXPECT_TRUE(refusal->is_bad()) << "the refusal must carry a Bad serviceResult";
  GTEST_LOG_(INFO) << "no-channel RegisterServer refused with " << format(*refusal);
  EXPECT_FALSE(store_holds(probeUri)) << "the refused registration must leave no registry record";
  EXPECT_TRUE(store_holds(controlPeerUri)) << "and must not disturb the control record";
}

// Part 4 section 5.4.5.1: "This Service can only be invoked via SecureChannels that support Client
// authentication (i.e. HTTPS cannot be used to call this Service)." The channel staged here is the
// HTTPS case: the messages are secured, but no client certificate reaches the application layer, so
// there is nothing to compare the claimed serverUri against (section 5.4.5.1's other sentence, which
// AC-SVR-DISC-RS-003-SERVERURI-MATCHES-CERT owns). The plausible implementation checks only that
// the channel is not plaintext - message security mode != None - and accepts, which reopens exactly
// the impersonation hole the certificate comparison exists to close.
// @verifies AC-SVR-DISC-RS-015-CLIENT-AUTHENTICATED-CHANNEL
TEST_F(ServerLdsRegistrationChannelSurface, RefusesRegisterServerOnAChannelThatCannotAuthenticateTheClient)
{
  ASSERT_NO_FATAL_FAILURE(register_control_peer());

  const std::string probeUri = "urn:reduktive:test:lds-peer-no-client-auth-v1";
  ua::RegisterServerRequest probe;
  probe.server() = make_lds_registration(probeUri);
  auto response = run_register_server_v1_on(std::move(probe), client_unauthenticated_channel());

  const auto refusal = refusal_of(response);
  ASSERT_TRUE(refusal.has_value())
    << "RegisterServer over a channel with no client authentication must be refused (HTTPS is not "
       "an acceptable transport for it)";
  EXPECT_TRUE(refusal->is_bad());
  GTEST_LOG_(INFO) << "client-unauthenticated RegisterServer refused with " << format(*refusal);
  EXPECT_FALSE(store_holds(probeUri)) << "the refused registration must leave no registry record";
  EXPECT_TRUE(store_holds(controlPeerUri));
}

// Part 4 section 5.4.6.1 repeats section 5.4.5.1's sentence verbatim for RegisterServer2: "This Service can
// only be invoked via SecureChannels that support Client authentication (i.e. HTTPS cannot be used to call
// this Service)." Both halves of "cannot authenticate the client" are driven - a channel with no message
// security at all, and a secured channel carrying no client certificate (HTTPS) - because an implementation
// that gates only on MessageSecurityMode passes the first and fails the second, and that is precisely the
// implementation the clause is written against. RegisterServer2 is the service a modern server tries first
// (section 5.4.6.1), so a gap here is the one that gets exercised.
// @verifies AC-SVR-DISC-RS2-004-CLIENT-AUTHENTICATED-CHANNEL
TEST_F(ServerLdsRegistrationChannelSurface, RefusesRegisterServer2OnAChannelThatCannotAuthenticateTheClient)
{
  ASSERT_NO_FATAL_FAILURE(register_control_peer());

  // (a) No message security at all - no certificate was exchanged, so no client was authenticated.
  const std::string unsecuredUri = "urn:reduktive:test:lds-peer-unsecured-v2";
  ua::RegisterServer2Request unsecured;
  unsecured.server() = make_lds_registration(unsecuredUri);
  ua::server::InboundRegistrationContext noneChannel;
  noneChannel.messageSecurityMode = ua::MessageSecurityMode::None;
  auto unsecuredResponse = run_register_server2_on(std::move(unsecured), std::move(noneChannel));

  const auto unsecuredRefusal = refusal_of(unsecuredResponse);
  ASSERT_TRUE(unsecuredRefusal.has_value())
    << "RegisterServer2 over an unauthenticated channel must be refused";
  EXPECT_TRUE(unsecuredRefusal->is_bad());
  GTEST_LOG_(INFO) << "unsecured RegisterServer2 refused with " << format(*unsecuredRefusal);
  EXPECT_FALSE(store_holds(unsecuredUri));

  // (b) The HTTPS case: messages are secured, but no client certificate reached the handler.
  const std::string httpsLikeUri = "urn:reduktive:test:lds-peer-no-client-auth-v2";
  ua::RegisterServer2Request httpsLike;
  httpsLike.server() = make_lds_registration(httpsLikeUri);
  auto httpsLikeResponse = run_register_server2_on(std::move(httpsLike), client_unauthenticated_channel());

  const auto httpsLikeRefusal = refusal_of(httpsLikeResponse);
  ASSERT_TRUE(httpsLikeRefusal.has_value())
    << "a transport that authenticates only the server (HTTPS) is not an acceptable transport for "
       "RegisterServer2";
  EXPECT_TRUE(httpsLikeRefusal->is_bad());
  GTEST_LOG_(INFO) << "client-unauthenticated RegisterServer2 refused with " << format(*httpsLikeRefusal);
  EXPECT_FALSE(store_holds(httpsLikeUri)) << "the refused registration must leave no registry record";
  EXPECT_TRUE(store_holds(controlPeerUri));
}

// Part 4 section 5.4.5.1: "Discovery Servers shall reject registrations if the serverUri provided does not
// match the applicationUri in Server Certificate used to create the SecureChannel." The channel here
// is fully conforming - signed and encrypted, with a peer certificate - and the ONLY defect is that
// the certificate names a different application than the record being published. The plausible
// implementation treats the peer certificate as an authentication check that has already passed by
// the time the request body is read, and never compares the two URIs; the result is that any holder
// of a valid certificate can publish a directory record claiming another application's URI, which
// every client then discovers as that application. The status code is not pinned (Table 7 offers
// Bad_ServerUriInvalid but the clause mandates the rejection, not a code); the obligations under
// test are that it is refused and that no record is created.
// @verifies AC-SVR-DISC-RS-003-SERVERURI-MATCHES-CERT
TEST_F(ServerLdsRegistrationChannelSurface, RefusesARegistrationWhoseServerUriIsNotTheCertificateUri)
{
  ASSERT_NO_FATAL_FAILURE(register_control_peer());

  const std::string claimedUri = "urn:reduktive:test:lds-peer-impersonated";
  ua::RegisterServer2Request probe;
  probe.server() = make_lds_registration(claimedUri);

  ua::server::InboundRegistrationContext mismatchedChannel;
  mismatchedChannel.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  mismatchedChannel.peerApplicationUri = std::string{"urn:reduktive:test:lds-peer-actual-certificate"};
  auto response = run_register_server2_on(std::move(probe), std::move(mismatchedChannel));

  const auto refusal = refusal_of(response);
  ASSERT_TRUE(refusal.has_value())
    << "a serverUri that differs from the channel certificate's applicationUri must be rejected";
  EXPECT_TRUE(refusal->is_bad());
  GTEST_LOG_(INFO) << "serverUri/certificate mismatch refused with " << format(*refusal);
  EXPECT_FALSE(store_holds(claimedUri)) << "no record may be created for the impersonated serverUri";
  EXPECT_FALSE(store_holds("urn:reduktive:test:lds-peer-actual-certificate"))
    << "and the rejection must not be silently repaired by storing the certificate's URI instead";
  EXPECT_TRUE(store_holds(controlPeerUri));
}

// ===================== FindServers: filters, response shape, empty filter =====================

// Part 4 section 5.4.2.2 Table 3, serverUris: "List of Servers to return. All known Servers are returned if
// the list is empty. A serverUri matches the applicationUri from the ApplicationDescription." A
// populated list is therefore an instruction the server must honour, not a hint. The plausible
// implementation aggregates its registry and its own description and returns the lot - the filter
// is easy to skip because the unfiltered answer is a superset and looks correct to a casual client,
// and it is exactly what a Client that asked for one server out of a large directory must not get.
// The filter used here names one registered peer AND this server's own applicationUri, which keeps
// the test clear of the one genuinely disputed case: whether section 5.4.2.1's "shall always return a
// record that describes itself" survives a filter that excludes it. SVR-DISC-GE-AD-002 rules that
// the self-record obligation "applies only when the filter does not exclude it", so that case
// belongs to AC-SVR-DISC-GE-AD-002-FINDSERVERS-RESPONSE-TYPE below, not here.
// @verifies AC-SVR-DISC-FS-001-CLIENT-FILTERS
TEST_F(ServerLdsRegistrationSurface, FindServersReturnsOnlyTheServerUrisTheClientAskedFor)
{
  const std::vector<std::string> peers = {
    "urn:reduktive:test:lds-peer-a", "urn:reduktive:test:lds-peer-b", "urn:reduktive:test:lds-peer-c"};
  for (const auto& peer : peers)
  {
    ua::RegisterServer2Request registration;
    registration.server() = make_lds_registration(peer);
    auto response = run_register_server2(std::move(registration));
    ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
      << "staging registration rejected for " << peer;
  }
  // Non-vacuity: a filter test over a directory of one proves nothing, so the population the filter
  // has to discriminate within is asserted before anything is filtered.
  ASSERT_EQ(mStore->snapshot().size(), peers.size())
    << "the registry must hold every staged peer for the filter to have something to exclude";
  GTEST_LOG_(INFO) << "filter denominator: " << peers.size() << " registered peers plus this server";

  ua::FindServersRequest request;
  request.endpoint_url() = ua::String{advertisedUrl};
  request.server_uris().payload().push_back(ua::String{"urn:reduktive:test:lds-peer-b"});
  request.server_uris().payload().push_back(ua::String{serverApplicationUri});
  auto response = run_find_servers(std::move(request));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
    << "a serverUris filter is a normal request, not an error condition";
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);

  std::vector<std::string> returned;
  for (const auto& server : findResponse->servers().payload())
  {
    returned.push_back(std::string{server.application_uri()});
  }
  EXPECT_EQ(returned.size(), 2u) << "only the two named applicationUris may be returned";
  EXPECT_NE(std::ranges::find(returned, std::string{"urn:reduktive:test:lds-peer-b"}), returned.end())
    << "the named peer must be returned";
  EXPECT_NE(std::ranges::find(returned, std::string{serverApplicationUri}), returned.end())
    << "the named self-record must be returned";
  EXPECT_EQ(std::ranges::find(returned, std::string{"urn:reduktive:test:lds-peer-a"}), returned.end())
    << "a registered server the filter did not name must be excluded";
  EXPECT_EQ(std::ranges::find(returned, std::string{"urn:reduktive:test:lds-peer-c"}), returned.end())
    << "a registered server the filter did not name must be excluded";
}

// Part 4 section 5.4.2.2 Table 3: `servers[]` is a list of ApplicationDescription (the section 7.2 type), and
// "This list is empty if no Servers meet the criteria" - an empty result is a Good response with an
// empty list, never a fault. Both halves are checked because they fail in opposite directions: a
// server that returns records stripped to a bare applicationUri satisfies the type but gives a
// Client nothing to connect to (applicationName and discoveryUrls are what section 5.4.2.1 says the
// service exists to publish), while a server that treats "nothing matched" as an error condition
// turns a normal filtered query into Bad_NoMatch and breaks a client that is enumerating.
// SVR-DISC-GE-AD-002 also settles the self-record interaction: the section 5.4.2.1 self-record obligation
// "applies only when the filter does not exclude it", so the excluding filter below must yield an
// EMPTY list rather than a self-record smuggled past the filter.
// @verifies AC-SVR-DISC-GE-AD-002-FINDSERVERS-RESPONSE-TYPE
TEST_F(ServerLdsRegistrationSurface, FindServersReturnsPopulatedApplicationDescriptionsAndEmptyOnNoMatch)
{
  auto identity = ua::ApplicationIdentity::load_default();
  identity.applicationName = ua::LocalizedText{ua::LocaleId{"en"}, ua::String{"Discovery Surface Server"}};
  identity.applicationType = ua::ApplicationType::Server;
  identity.productUri = ua::String{"urn:reduktive:test:discovery-surface-product"};
  mDeps->set_identity(std::move(identity));

  ua::RegisterServer2Request registration;
  registration.server() = make_lds_registration("urn:reduktive:test:lds-peer-described");
  auto registrationResponse = run_register_server2(std::move(registration));
  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(registrationResponse.second.get()), nullptr);

  ua::FindServersRequest request;
  request.endpoint_url() = ua::String{advertisedUrl};
  auto response = run_find_servers(std::move(request));

  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);

  const auto& servers = findResponse->servers().payload();
  // The element type is the section 7.2 ApplicationDescription, checked where it cannot silently drift.
  static_assert(std::is_same_v<std::decay_t<decltype(servers[0])>, ua::ApplicationDescription>,
    "FindServers servers[] must be a list of ApplicationDescription (Part 4 section 7.2)");
  // Non-vacuity: this server's own record plus the one registered peer.
  ASSERT_EQ(servers.size(), 2u) << "expected the self-record and the one registered peer";
  GTEST_LOG_(INFO) << "inspecting " << servers.size() << " ApplicationDescription records";
  for (const auto& server : servers)
  {
    const std::string applicationUri{server.application_uri()};
    EXPECT_FALSE(applicationUri.empty()) << "applicationUri is the record's identity";
    EXPECT_FALSE(std::string{server.application_name().text()}.empty())
      << "applicationName is what section 5.4.2.1 calls the human readable ServerName: " << applicationUri;
    EXPECT_FALSE(std::string{server.product_uri()}.empty()) << "productUri must survive: " << applicationUri;
    EXPECT_EQ(server.application_type(), ua::ApplicationType::Server)
      << "applicationType must describe the record, not be left at a default: " << applicationUri;
    EXPECT_FALSE(server.discovery_urls().payload().empty())
      << "a record with no discoveryUrls cannot be connected to: " << applicationUri;
  }

  // A filter that matches nothing is an empty Good answer, not a fault - and not a self-record the
  // filter did not name.
  ua::FindServersRequest excluding;
  excluding.endpoint_url() = ua::String{advertisedUrl};
  excluding.server_uris().payload().push_back(ua::String{"urn:reduktive:test:no-such-server"});
  auto excludedResponse = run_find_servers(std::move(excluding));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(excludedResponse.second.get()), nullptr)
    << "a filter that matches nothing is not an error condition";
  auto* excludedFindResponse = dynamic_cast<ua::FindServersResponse*>(excludedResponse.second.get());
  ASSERT_NE(excludedFindResponse, nullptr);
  EXPECT_EQ(excludedFindResponse->response_header().service_result(), ua::Status::Good);
  EXPECT_TRUE(excludedFindResponse->servers().payload().empty())
    << "no server met the criteria, so the list is returned empty";
}

// Part 4 section 5.4.2.2 Table 3 is explicit that FindServers' arrays are FILTERS, not operation arrays:
// serverUris - "All known Servers are returned if the list is empty"; localeIds - "The Server
// chooses an appropriate default locale if this list is empty". SVR-DISC-SVC-002 exists to record
// that exemption: the general "an empty operation array is a service-level Bad" rule (nodesToRead
// and friends) must NOT be extended to these, and the discovery services carry no operation array
// of their own for the general rule to apply to. The criterion's title summarises the general rule
// rather than the discovery obligation, so this is written to the specification and to the parent
// requirement, which say the opposite for this surface: an empty filter must not be faulted. The
// plausible implementation is a shared dispatcher that empty-checks every inbound array uniformly
// and faults FindServers with Bad_NothingToDo, which makes the most common discovery call of all -
// "tell me everything you know" - fail against a server that is otherwise conforming.
TEST_F(ServerLdsRegistrationSurface, FindServersTreatsEmptyFilterArraysAsNoFilterRatherThanAFault)
{
  ua::RegisterServer2Request registration;
  registration.server() = make_lds_registration("urn:reduktive:test:lds-peer-unfiltered");
  auto registrationResponse = run_register_server2(std::move(registration));
  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(registrationResponse.second.get()), nullptr);
  ASSERT_EQ(mStore->snapshot().size(), 1u)
    << "the peer must be registered for 'return all' to mean something";

  ua::FindServersRequest request;
  request.endpoint_url() = ua::String{advertisedUrl};
  // Both filter arrays left empty - the shape a dispatcher applying the general empty-operation-array
  // rule would reject.
  ASSERT_TRUE(request.server_uris().payload().empty());
  ASSERT_TRUE(request.locale_ids().payload().empty());
  auto response = run_find_servers(std::move(request));

  ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
    << "an empty serverUris/localeIds means 'no filter', and must not be turned into a service fault";
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good)
    << "an empty filter is a Good request";

  // "All known Servers are returned if the list is empty" - the self-record and the registered peer.
  std::vector<std::string> returned;
  for (const auto& server : findResponse->servers().payload())
  {
    returned.push_back(std::string{server.application_uri()});
  }
  EXPECT_NE(std::ranges::find(returned, std::string{serverApplicationUri}), returned.end())
    << "an empty filter returns everything known, starting with this server";
  EXPECT_NE(
    std::ranges::find(returned, std::string{"urn:reduktive:test:lds-peer-unfiltered"}), returned.end())
    << "an empty filter must not silently narrow the answer either";
}

// ===================== Multi-homed GetEndpoints =====================

namespace
{

/// A listener reachable under two HostNames on the same port and path - one physical endpoint, two
/// names, which is what "multi-homed" means for Part 4 section 5.4.4.1's URL-rewrite obligation. Kept on a
/// port of its own so the base fixture's single-name listener cannot answer for it.
constexpr const char* multiHomeFirstUrl = "opc.tcp://alpha.plant.example:4841/";
constexpr const char* multiHomeSecondUrl = "opc.tcp://beta.plant.example:4841/";

class ServerMultiHomedDiscoverySurface : public ServerDiscoveryResponseSurface
{
protected:
  void SetUp() override
  {
    ServerDiscoveryResponseSurface::SetUp();
    mDeps->add_listener(ua::server::ListenerHandle{2},
      {make_none_server_endpoint("multi-homed")},
      {ua::transport::EndpointUrl{multiHomeFirstUrl}, ua::transport::EndpointUrl{multiHomeSecondUrl}});
  }
};

/// The same two names on a Sign-and-Encrypt endpoint. A None endpoint whose only user-token policy is
/// Anonymous/None needs no certificate, so `resolve_certificate_type_for_endpoint` returns nothing and
/// the Server presents none - correctly. The certificate half of Part 12 section 5.3 therefore has no
/// subject on the fixture above, and gets one here.
class ServerMultiHomedSecuredDiscoverySurface : public ServerDiscoveryResponseSurface
{
protected:
  void SetUp() override
  {
    ServerDiscoveryResponseSurface::SetUp();

    ua::server::ServerEndpointConfig secured;
    secured.name = "multi-homed-secured";
    secured.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    secured.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
    secured.transportProfile = ua::TransportProfileId::UaTcpUaScUaBinary;
    secured.userIdentityTokens.push_back(ua::server::create_user_token_policy(
      ua::UserTokenType::Anonymous, ua::SecurityPolicyId::Basic256Sha256));

    mDeps->add_listener(ua::server::ListenerHandle{3},
      {std::move(secured)},
      {ua::transport::EndpointUrl{multiHomeFirstUrl}, ua::transport::EndpointUrl{multiHomeSecondUrl}});
  }
};

}  // namespace

// Part 4 section 5.4.4.1: "A Server may have multiple HostNames. For this reason, the Client shall pass the
// URL it used to connect to the Endpoint to this Service. The implementation of this Service shall
// use this information to return responses that are accessible to the Client via the provided URL."
// Part 12 section 5.3 adds the certificate half - the name returned must be one the certificate declares -
// which is why SVR-DISC-GEN-016 requires every reachable name to be in the certificate: a rewrite to
// a name the certificate does not carry produces a URL the Client will dial and then refuse. The
// plausible implementation publishes its advertised URLs verbatim, so a Client that reached the
// server through beta is handed alpha and either loses the route (NAT / split-horizon DNS) or trips
// its own hostname-vs-certificate check. Both the endpointUrl and the ApplicationDescription's
// discoveryUrls are checked, because they are shaped separately and only one of them is usually
// remembered.
//
// The SAN half of the certificate clause is NOT fully asserted here, and the population it
// quantifies over is counted rather than silently skipped: the staged deployment publishes
// None-policy endpoints against a certificate store that holds no application certificate, so no
// endpoint carries a serverCertificate whose SAN could be compared with the dialled name. What IS
// on trial of that half is the part this interface can see - the server must answer EVERY name it is
// reachable under the same way, so presenting a certificate for one HostName and none for the other
// (which would leave the second name's Client nothing to run SVR-DISC-GEN-013 against) fails here.
// The SAN comparison itself needs an integration deployment with a real multi-SAN application
// certificate; the count below records that the check ran over an empty population.
TEST_F(ServerMultiHomedDiscoverySurface, GetEndpointsRewritesUrlsToTheHostNameTheCallerDialled)
{
  const std::pair<const char*, const char*> names[] = {
    {multiHomeFirstUrl, "alpha.plant.example"}, {multiHomeSecondUrl, "beta.plant.example"}};

  std::vector<std::size_t> certificateBearingEndpointsPerName;

  for (const auto& [dialledUrl, dialledHost] : names)
  {
    ua::GetEndpointsRequest request;
    request.endpoint_url() = ua::String{dialledUrl};
    auto response = run_get_endpoints(std::move(request));

    ASSERT_EQ(dynamic_cast<ua::ServiceFault*>(response.second.get()), nullptr)
      << "dialling a name the server is reachable under is not an error: " << dialledUrl;
    auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get());
    ASSERT_NE(getResponse, nullptr);
    EXPECT_EQ(getResponse->response_header().service_result(), ua::Status::Good);

    const auto& endpoints = getResponse->endpoints().payload();
    // Non-vacuity: an empty endpoints[] would pass every per-element check below.
    ASSERT_FALSE(endpoints.empty()) << "no endpoint was returned for " << dialledUrl;
    GTEST_LOG_(INFO) << "dialled " << dialledUrl << ": " << endpoints.size() << " endpoint(s) returned";

    std::size_t certificateBearingEndpoints = 0;
    for (const auto& endpoint : endpoints)
    {
      const std::string endpointUrl{endpoint.endpoint_url()};
      EXPECT_NE(endpointUrl.find(dialledHost), std::string::npos)
        << "the returned endpointUrl must carry the HostName the caller used (" << dialledHost
        << "), got: " << endpointUrl;
      for (const auto& discoveryUrl : endpoint.server().discovery_urls().payload())
      {
        const std::string text{discoveryUrl};
        EXPECT_NE(text.find(dialledHost), std::string::npos)
          << "the published discoveryUrl must carry the same HostName, got: " << text;
      }
      if (!endpoint.server_certificate().empty())
      {
        ++certificateBearingEndpoints;
      }
    }
    certificateBearingEndpointsPerName.push_back(certificateBearingEndpoints);
  }

  // The certificate half, to the extent this interface can see it: whatever the server presents, it must
  // present it for every name it is reachable under. A deployment that answered alpha with a
  // certificate and beta with none would hand the beta Client an endpoint it cannot check.
  ASSERT_EQ(certificateBearingEndpointsPerName.size(), 2u) << "both dialled names must have been probed";
  GTEST_LOG_(INFO) << "endpoints carrying a serverCertificate: alpha="
                   << certificateBearingEndpointsPerName[0]
                   << ", beta=" << certificateBearingEndpointsPerName[1];
  EXPECT_EQ(certificateBearingEndpointsPerName[0], certificateBearingEndpointsPerName[1])
    << "a multi-homed server must answer every reachable HostName with the same certificate "
       "material - presenting one for a caller that dialled alpha and none for a caller that "
       "dialled beta leaves the second with nothing to run its hostname-vs-certificate check on";
  if (certificateBearingEndpointsPerName[0] == 0)
  {
    GTEST_LOG_(INFO)
      << "SAN comparison NOT exercised: the staged certificate store holds no application "
         "certificate, so no serverCertificate is returned. The subject/SAN half of Part 12 section 5.3 "
         "needs an integration deployment with a real multi-SAN application certificate.";
  }
}

// The half the test above records as not exercised: Part 12 section 5.3's certificate clause - the HostName
// the rewrite puts in the endpointUrl must be one the application instance certificate declares.
// Rewriting to a name the certificate does not carry produces a URL a Client will dial and then
// refuse against its own hostname check (`AC-CL-DISC-005-HOSTNAME-MATCH`), which is a worse failure
// than not rewriting at all: the Client gets a route it cannot use and a trust error rather than a
// clear absence.
//
// The test above could not reach this because its certificate store held no application certificate,
// so `endpoint.server_certificate()` was empty on every endpoint and the population the SAN check
// quantifies over was empty. That was recorded honestly rather than skipped, and the fix is the
// fixture rather than the assertion: `FakeCertificateStore` now carries a settable application
// certificate, and this stages one whose SubjectAlternativeName declares both reachable HostNames -
// which is what `AC-SVR-DISC-GEN-016-ALL-HOSTNAMES` requires a multi-homed deployment to issue.
//
// The comparison is made against the certificate the Server actually returned rather than against the
// one the fixture staged, because the obligation is about what the caller receives. A Server that
// rewrote correctly and then returned a certificate for a different name would pass a check written
// the other way round.
// @relation(AC-SVR-DISC-GE-022-MULTI-HOSTNAME-REWRITE, scope=function)
TEST_F(ServerMultiHomedSecuredDiscoverySurface, TheRewrittenHostNameIsOneTheReturnedCertificateDeclares)
{
  // The keypair is written out PEM-encrypted, so the crypto needs a credential callback; the
  // no-argument factory throws on the first private-key materialisation without one.
  auto crypto = ua::create_default_crypto([]() { return ua::SecureString{"password"}; });
  ua::TestPki pki{crypto};

  auto caKeys = crypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  auto caCert = pki.create_root_ca(caKeys, "MultiHome Test Root", "1");
  auto leafKeys = crypto->create_asymmetric_key_pair_sync(ua::CertificateKeyAlgorithm::Rsa, 2048);
  const auto from = ua::DateTime::now();
  const ua::DateTime to{from.value() + std::chrono::days{30}};
  auto leafCert = pki.create_leaf_cert(leafKeys,
    caKeys,
    caCert,
    from,
    to,
    {std::string{serverApplicationUri}},
    {std::string{"alpha.plant.example"}, std::string{"beta.plant.example"}},
    "MultiHomedServer");

  mCertStore->applicationCertificate = ua::CertificateStore::ApplicationCertificate{
    ua::CertificateType::RsaSha256Application, leafCert, leafKeys};

  const std::pair<const char*, const char*> names[] = {
    {multiHomeFirstUrl, "alpha.plant.example"}, {multiHomeSecondUrl, "beta.plant.example"}};

  // Counted per name rather than in total: the listener publishes both HostNames, so one dial can
  // return several EndpointDescriptions, and a total would hide the case where one name contributed
  // every comparison and the other none.
  std::vector<std::size_t> comparisonsPerName;
  for (const auto& [dialledUrl, dialledHost] : names)
  {
    std::size_t comparisonsMade = 0;
    ua::GetEndpointsRequest request;
    request.endpoint_url() = ua::String{dialledUrl};
    auto response = run_get_endpoints(std::move(request));

    auto* getResponse = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get());
    ASSERT_NE(getResponse, nullptr) << "dialling " << dialledUrl << " produced no GetEndpointsResponse";
    const auto& endpoints = getResponse->endpoints().payload();
    ASSERT_FALSE(endpoints.empty()) << "no endpoint was returned for " << dialledUrl;

    for (const auto& endpoint : endpoints)
    {
      const std::string endpointUrl{endpoint.endpoint_url()};
      ASSERT_NE(endpointUrl.find(dialledHost), std::string::npos)
        << "precondition: the rewrite must have happened before the certificate can be compared "
           "against it. Got: "
        << endpointUrl;

      const auto& der = endpoint.server_certificate();
      ASSERT_FALSE(der.empty())
        << "the endpoint returned for " << dialledUrl
        << " carries no serverCertificate, so a Client has nothing to check the rewritten HostName "
           "against and this obligation cannot be met at all";

      auto parsed = crypto->read_certificate_from_der(der);
      ASSERT_NE(parsed, nullptr) << "the returned serverCertificate did not parse";

      const auto declared = parsed->san_hostnames();
      EXPECT_NE(std::find(declared.begin(), declared.end(), std::string{dialledHost}), declared.end())
        << "the Server rewrote its endpointUrl to " << dialledHost
        << " and returned a certificate that does not declare that HostName among its " << declared.size()
        << " SubjectAlternativeName entries. A Client dialling that URL will check the name against "
           "this certificate and refuse the connection the Server just told it to make";
      ++comparisonsMade;
    }
    comparisonsPerName.push_back(comparisonsMade);
  }

  ASSERT_EQ(comparisonsPerName.size(), 2u) << "both reachable HostNames must have been dialled";
  for (std::size_t i = 0; i < comparisonsPerName.size(); ++i)
  {
    EXPECT_GT(comparisonsPerName[i], 0u)
      << "dialling " << names[i].first
      << " produced no endpoint carrying a certificate, so the SAN comparison never ran for that "
         "name and this test says nothing about it";
  }
}

// ===================== Outbound registration: the register-with-LDS driver =====================
//
// The obligations below govern what the server DOES when it registers itself with a Discovery
// Server, so they are driven through the real driver - `ua::app::DiscoveryRegistration` - with only
// the one-cycle registrar interface (`ua::app::LdsRegistrar`) faked, the same arrangement
// tests/unit/app/discovery uses. The interface is the boundary of what a socket-free test can reach: the
// RegisterServer2 -> RegisterServer transition WITHIN one cycle belongs to ClientLdsRegistrar and
// needs a live channel; everything the driver decides - which target, which service preference, and
// what a cycle's outcome does to the next one - is observable here.

namespace
{

/// Records every cycle the driver asks for, including the target the driver chose to send it to,
/// and lets the test script the outcome.
class RecordingLdsRegistrar : public ua::app::LdsRegistrar
{
public:
  struct Cycle
  {
    std::string discoveryUrl;
    ua::MessageSecurityMode securityMode{ua::MessageSecurityMode::Invalid};
    std::optional<ua::SecurityPolicyId> securityPolicyId;
    bool isOnline{false};
    bool preferFallback{false};
  };

  /// Completes every cycle with a good outcome reporting `usedFallback`.
  void succeed_with_fallback(bool usedFallback)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mFailWith.reset();
    mUsedFallback = usedFallback;
  }

  /// Completes every cycle with the given failure status.
  void fail_with(ua::StatusCode status)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mFailWith = status;
  }

  void register_async(ua::app::DiscoveryTarget target, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>> /*discoveryConfiguration*/, bool preferFallback,
    RegisterResultCallback callback) noexcept override
  {
    std::optional<ua::StatusCode> failWith;
    bool usedFallback = false;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mCycles.push_back(Cycle{target.discoveryUrl,
        target.messageSecurityMode,
        target.securityPolicyId,
        server.is_online(),
        preferFallback});
      failWith = mFailWith;
      usedFallback = mUsedFallback;
    }
    if (!callback)
    {
      return;
    }
    if (failWith)
    {
      callback(ua::Result<RegisterOutcome>{*failWith});
      return;
    }
    callback(ua::Result<RegisterOutcome>{RegisterOutcome{usedFallback}});
  }

  std::vector<Cycle> cycles() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mCycles;
  }

  std::size_t online_cycle_count() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::size_t count = 0;
    for (const auto& cycle : mCycles)
    {
      if (cycle.isOnline)
      {
        ++count;
      }
    }
    return count;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Cycle> mCycles;
  std::optional<ua::StatusCode> mFailWith;
  bool mUsedFallback{false};
};

/// Counts the edge notifications the driver publishes about a target.
class CountingRegistrationObserver : public ua::app::DiscoveryRegistrationObserver
{
public:
  void on_registration_established(const ua::app::DiscoveryRegistrationInfo& info) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    ++mEstablished;
    mLastEstablishedUrl = info.discoveryUrl;
  }

  void on_registration_failed(const ua::app::DiscoveryRegistrationInfo& /*info*/, ua::StatusCode /*status*/,
    std::shared_ptr<const ua::ErrorDetail> /*detail*/,
    std::chrono::steady_clock::time_point /*nextAttempt*/) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    ++mFailed;
  }

  void on_registration_fallback(const ua::app::DiscoveryRegistrationInfo& /*info*/) override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    ++mFallback;
  }

  int established() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mEstablished;
  }

  int failed() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mFailed;
  }

  int fallback() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mFallback;
  }

  std::string last_established_url() const
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastEstablishedUrl;
  }

private:
  mutable std::mutex mMutex;
  int mEstablished{0};
  int mFailed{0};
  int mFallback{0};
  std::string mLastEstablishedUrl;
};

class ServerLdsRegistrationDriverSurface : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/2);
    mRegistrar = std::make_shared<RecordingLdsRegistrar>();
    mObserver = std::make_shared<CountingRegistrationObserver>();
  }

  void TearDown() override
  {
    if (mDriver)
    {
      std::promise<void> stopped;
      mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
      stopped.get_future().wait_for(std::chrono::seconds{5});
      mDriver.reset();
    }
    mObserver.reset();
    mRegistrar.reset();
    if (mPool)
    {
      ua::test_utils::drain_with_timeout(*mPool);
    }
  }

  /// The identity this server publishes to every Discovery Server it registers with.
  static ua::RegisteredServer server_identity()
  {
    ua::RegisteredServer identity;
    identity.server_uri() = ua::String{"urn:reduktive:test:registering-server"};
    identity.product_uri() = ua::String{"urn:reduktive:test:registering-product"};
    identity.server_type() = ua::ApplicationType::Server;
    identity.server_names().payload().push_back(
      ua::LocalizedText{ua::LocaleId{"en"}, ua::String{"Registering Server"}});
    identity.discovery_urls().payload().push_back(ua::String{"opc.tcp://registering-server:4840/"});
    return identity;
  }

  /// A configuration whose cadence and backoff are long enough that exactly ONE cycle per target
  /// runs inside a test, so a recorded second cycle is the driver's decision and not the clock's.
  static ua::app::DiscoveryRegistrationConfig single_cycle_config(
    std::vector<ua::app::DiscoveryTarget> targets)
  {
    ua::app::DiscoveryRegistrationConfig config;
    config.targets = std::move(targets);
    config.cadence = std::chrono::seconds{600};
    config.backoffInitial = std::chrono::seconds{600};
    config.backoffCap = std::chrono::seconds{600};
    config.shutdownDeregisterTimeout = std::chrono::seconds{1};
    return config;
  }

  /// A configuration whose cadence and backoff are the smallest the driver's second-granularity
  /// config can express, so a SECOND cycle runs inside the test and the memo one cycle left behind
  /// is observable in the preference the next cycle carries.
  static ua::app::DiscoveryRegistrationConfig repeating_cycle_config(
    std::vector<ua::app::DiscoveryTarget> targets)
  {
    ua::app::DiscoveryRegistrationConfig config;
    config.targets = std::move(targets);
    config.cadence = std::chrono::seconds{1};
    config.backoffInitial = std::chrono::seconds{1};
    config.backoffCap = std::chrono::seconds{1};
    config.shutdownDeregisterTimeout = std::chrono::seconds{1};
    return config;
  }

  void start_driver(ua::app::DiscoveryRegistrationConfig config)
  {
    mDriver = ua::app::DiscoveryRegistration::create(
      mPool->executor(), mRegistrar, server_identity(), std::move(config));
    mDriver->set_observer(mObserver);
    std::promise<void> started;
    mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
    ASSERT_EQ(started.get_future().wait_for(std::chrono::seconds{2}), std::future_status::ready)
      << "the registration driver never started";
  }

  std::vector<ua::app::DiscoveryRegistration::Status> status_sync()
  {
    std::promise<std::vector<ua::app::DiscoveryRegistration::Status>> promised;
    auto future = promised.get_future();
    mDriver->status_async([&promised](std::vector<ua::app::DiscoveryRegistration::Status> status)
      { promised.set_value(std::move(status)); });
    EXPECT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready);
    return future.get();
  }

  template<typename Predicate>
  bool poll_until(Predicate predicate, std::chrono::milliseconds budget)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (predicate())
      {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    return predicate();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<RecordingLdsRegistrar> mRegistrar;
  std::shared_ptr<CountingRegistrationObserver> mObserver;
  std::shared_ptr<ua::app::DiscoveryRegistration> mDriver;
};

}  // namespace

// Part 4 section 5.4.6.1: "Servers that support RegisterServer2 shall try to register with the Discovery
// Server using this Service and shall fall back to RegisterServer if RegisterServer2 fails with the
// status Bad_ServiceUnsupported." The ordering is the obligation: RegisterServer2 first, on a Server
// that supports it. The observable at the driver's interface is the preference it hands each cycle -
// `preferFallback == false` means "send RegisterServer2 first, fall back only if it is rejected as
// unsupported". The plausible implementation configures the legacy service as the safe default
// (every Discovery Server accepts it) and never sends RegisterServer2 at all, which silently drops
// the mDNS discovery configuration that only RegisterServer2 can carry, so the server never appears
// in FindServersOnNetwork and nothing reports an error.
// @verifies AC-SVR-DISC-RS2-001-PREFER-REGISTERSERVER2
// Public API review item 9 (API-9.3, D9): a target that names only its URL registers SignAndEncrypt, leaving
// the policy to the strongest the discovery server offers. Part 4 5.4.5.1 makes a discovery server refuse an
// insecure registration channel, so a None default could never register with a conformant one.
TEST(DiscoveryTargetDefaults, ATargetNamingOnlyItsUrlIsSignAndEncryptWithTheStrongestPolicy)
{
  const ua::app::DiscoveryTarget target{.discoveryUrl = "opc.tcp://lds.plant.example:4840/"};
  EXPECT_EQ(target.messageSecurityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_FALSE(target.securityPolicyId.has_value())
    << "unset means the strongest the discovery server offers";
}

TEST_F(ServerLdsRegistrationDriverSurface, FirstRegistrationCyclePrefersRegisterServer2)
{
  mRegistrar->succeed_with_fallback(false);
  ua::app::DiscoveryTarget target;
  target.discoveryUrl = "opc.tcp://lds.plant.example:4840/";
  ASSERT_NO_FATAL_FAILURE(start_driver(single_cycle_config({target})));

  ASSERT_TRUE(
    poll_until([&] { return mRegistrar->online_cycle_count() >= 1; }, std::chrono::milliseconds{2000}))
    << "the driver issued no registration cycle at all";
  const auto cycles = mRegistrar->cycles();
  ASSERT_FALSE(cycles.empty());
  GTEST_LOG_(INFO) << "inspecting the first of " << cycles.size() << " recorded cycle(s)";
  EXPECT_FALSE(cycles.front().preferFallback)
    << "the first cycle against a Discovery Server supporting both services must attempt "
       "RegisterServer2, not open with the v1 fallback";
  EXPECT_TRUE(cycles.front().isOnline) << "a registration cycle publishes isOnline = true";
}

// Part 4 section 5.4.6.1 makes the fallback conditional on ONE status: RegisterServer2 is retried as
// RegisterServer when, and only when, it "fails with the status Bad_ServiceUnsupported". A cycle
// that reports it used the v1 fallback is the driver's cue to keep using it; any other failure is a
// rejection on the merits and must leave the preference alone, because retrying a registration the
// Discovery Server refused (an invalid serverUri, a denied user) as a different service just repeats
// the refusal and hides why. The plausible implementation treats "RegisterServer2 failed" as the
// fallback trigger, so one Bad_UserAccessDenied permanently downgrades the server to the legacy
// service and drops its mDNS capability information for good.
//
// The RegisterServer2 -> RegisterServer transition inside a single cycle is ClientLdsRegistrar's and
// needs a live channel; what is on trial here is the driver half - which outcome turns the fallback
// on, and which must not. The required observable is the PREFERENCE THE NEXT CYCLE CARRIES, not
// the `fallbackActive` status field: the driver copies that field straight from the outcome the
// cycle reported, so a driver that memoised the fallback on any failure would still report
// `fallbackActive == false` for the failed cycle and only reveal itself on the cycle after. Both
// halves therefore run with a repeating cadence/backoff and inspect the second cycle.
TEST_F(ServerLdsRegistrationDriverSurface, FallbackIsAdoptedOnlyWhenACycleReportsItUsedRegisterServer)
{
  // (a) A cycle that fell back succeeds, the driver records that it is now on the v1 service, and
  //     the NEXT cycle is issued with that preference.
  mRegistrar->succeed_with_fallback(true);
  ua::app::DiscoveryTarget target;
  target.discoveryUrl = "opc.tcp://legacy-lds.plant.example:4840/";
  ASSERT_NO_FATAL_FAILURE(start_driver(repeating_cycle_config({target})));

  ASSERT_TRUE(poll_until([&] { return mObserver->established() >= 1; }, std::chrono::milliseconds{3000}))
    << "a cycle that fell back to RegisterServer still SUCCEEDS - the registration is established";
  EXPECT_TRUE(poll_until([&] { return mObserver->fallback() >= 1; }, std::chrono::milliseconds{3000}))
    << "the fallback edge must be reported so an operator can see the mDNS configuration was dropped";
  auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  EXPECT_TRUE(status.front().fallbackActive)
    << "after a fallback cycle the target is recorded as using RegisterServer";
  EXPECT_EQ(mObserver->last_established_url(), "opc.tcp://legacy-lds.plant.example:4840/");

  ASSERT_TRUE(poll_until([&] { return mRegistrar->cycles().size() >= 2; }, std::chrono::milliseconds{4000}))
    << "a second cycle is needed to observe what the fallback memo did";
  const auto fallbackCycles = mRegistrar->cycles();
  GTEST_LOG_(INFO) << "fallback arm: " << fallbackCycles.size() << " recorded cycle(s)";
  EXPECT_FALSE(fallbackCycles.front().preferFallback) << "the first cycle always re-probes RegisterServer2";
  EXPECT_TRUE(fallbackCycles[1].preferFallback)
    << "a cycle that reported it used RegisterServer is the ONE outcome that adopts the fallback, so "
       "the cycle after it must carry that preference";

  // (b) A cycle that failed for an unrelated reason must NOT turn the fallback on - and the proof of
  //     that is the preference the NEXT cycle carries, since the failure path never writes the
  //     status field this could otherwise be read off. A fresh driver is used so the second target
  //     starts from the same unmemoised state as the first.
  std::promise<void> stopped;
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  mDriver.reset();

  mRegistrar = std::make_shared<RecordingLdsRegistrar>();
  mObserver = std::make_shared<CountingRegistrationObserver>();
  mRegistrar->fail_with(ua::StatusCode{ua::Status::BadUserAccessDenied});
  ua::app::DiscoveryTarget rejecting;
  rejecting.discoveryUrl = "opc.tcp://strict-lds.plant.example:4840/";
  ASSERT_NO_FATAL_FAILURE(start_driver(repeating_cycle_config({rejecting})));

  ASSERT_TRUE(poll_until([&] { return mObserver->failed() >= 1; }, std::chrono::milliseconds{3000}))
    << "the rejected cycle must be reported as a failure";
  ASSERT_TRUE(poll_until([&] { return mRegistrar->cycles().size() >= 2; }, std::chrono::milliseconds{4000}))
    << "a retry cycle is needed to observe whether the rejection downgraded the service";
  const auto rejectedCycles = mRegistrar->cycles();
  GTEST_LOG_(INFO) << "rejection arm: " << rejectedCycles.size() << " recorded cycle(s)";
  for (std::size_t index = 0; index < rejectedCycles.size(); ++index)
  {
    EXPECT_FALSE(rejectedCycles[index].preferFallback)
      << "cycle " << index
      << ": Bad_UserAccessDenied is a rejection on the merits, not Bad_ServiceUnsupported, so it must "
         "never move the target onto the legacy RegisterServer service";
  }
  auto rejectedStatus = status_sync();
  ASSERT_EQ(rejectedStatus.size(), 1u);
  EXPECT_FALSE(rejectedStatus.front().fallbackActive)
    << "a rejection on the merits is not Bad_ServiceUnsupported and must not downgrade the service";
  EXPECT_EQ(mObserver->fallback(), 0)
    << "no fallback edge may be reported for a failure that was not Bad_ServiceUnsupported";
}

// Part 4 section 5.4.5.1: "The Administrator of the Server shall provide the Server with an
// EndpointDescription for the Discovery Server as part of the configuration process." Registration
// is a WRITE into a directory every Client reads, so the target must be one an administrator chose,
// not one the network offered - and the server must not go looking for a Discovery Server to
// register with, which would be both circular (discovery is what registration feeds) and unsecured.
// Both halves are driven: the configured description reaches the registrar exactly as configured
// (url, security mode and policy together - a driver that keeps the URL but silently drops to None
// registers over a channel that cannot authenticate it at all, per section 5.4.5.1), and a server with no
// configured target registers with nobody rather than falling back to a well-known default address.
// @verifies AC-SVR-DISC-RS-002-ADMIN-SUPPLIES-ENDPOINT
TEST_F(ServerLdsRegistrationDriverSurface, RegistersOnlyWithTheAdministratorConfiguredDiscoveryEndpoint)
{
  mRegistrar->succeed_with_fallback(false);
  ua::app::DiscoveryTarget configured;
  configured.discoveryUrl = "opc.tcp://configured-lds.plant.example:4840/UADiscovery";
  configured.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  configured.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  ASSERT_NO_FATAL_FAILURE(start_driver(single_cycle_config({configured})));

  ASSERT_TRUE(
    poll_until([&] { return mRegistrar->online_cycle_count() >= 1; }, std::chrono::milliseconds{2000}))
    << "the configured discovery endpoint was never registered with";
  const auto cycles = mRegistrar->cycles();
  ASSERT_FALSE(cycles.empty());
  EXPECT_EQ(cycles.front().discoveryUrl, "opc.tcp://configured-lds.plant.example:4840/UADiscovery")
    << "the configured EndpointDescription's URL must be used verbatim - not a discovered or "
       "defaulted one";
  EXPECT_EQ(cycles.front().securityMode, ua::MessageSecurityMode::SignAndEncrypt)
    << "the configured message security mode is part of the EndpointDescription the administrator "
       "supplied";
  EXPECT_EQ(cycles.front().securityPolicyId, ua::SecurityPolicyId::Basic256Sha256)
    << "so is the configured security policy";
  for (const auto& cycle : cycles)
  {
    EXPECT_EQ(cycle.discoveryUrl, "opc.tcp://configured-lds.plant.example:4840/UADiscovery")
      << "no target other than the configured one may be contacted";
  }

  // (b) The other half of the same obligation: with no EndpointDescription configured there is
  //     nothing to register with, and the server must not go and find a Discovery Server for
  //     itself. A driver that read an empty target list as "use the well-known local address" would
  //     publish this server's record into a directory no administrator chose. A fresh driver and a
  //     fresh recorder are used so the cycles counted below can only be the unconfigured driver's.
  std::promise<void> stopped;
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(stopped.get_future().wait_for(std::chrono::seconds{5}), std::future_status::ready);
  mDriver.reset();

  mRegistrar = std::make_shared<RecordingLdsRegistrar>();
  mObserver = std::make_shared<CountingRegistrationObserver>();
  mRegistrar->succeed_with_fallback(false);
  ASSERT_NO_FATAL_FAILURE(start_driver(single_cycle_config({})));

  // The configured target above was contacted well inside this budget, so an unconfigured driver
  // staying silent across the same window is the observable difference.
  std::this_thread::sleep_for(std::chrono::milliseconds{300});
  EXPECT_EQ(mRegistrar->online_cycle_count(), 0u)
    << "with no administrator-supplied EndpointDescription the server must register with nobody - it "
       "must not go looking for a Discovery Server of its own";
  EXPECT_TRUE(mRegistrar->cycles().empty());
  EXPECT_EQ(mObserver->established(), 0);
}

// Part 4 section 5.4.5.1: "Servers shall be able to register themselves with a Discovery Server running on
// the same machine." That deployment - one LDS process per host, reached over loopback at the
// well-known discovery address - is what OPC 10000-12 section 5.1 assumes of every installation, so the
// register-client must accept a loopback target like any other and drive a full cycle against it.
// The plausible implementation special-cases the local address: either as a guard against a server
// registering with "itself", or by rejecting loopback as an implausible LDS address at configuration
// time. Either way the cycle is never issued and the server never appears in the machine's LDS,
// silently, because nothing failed.
// @verifies AC-SVR-DISC-RS-006-SAME-MACHINE-REGISTRATION
TEST_F(ServerLdsRegistrationDriverSurface, RegistersWithALocalDiscoveryServerAtTheWellKnownAddress)
{
  mRegistrar->succeed_with_fallback(false);
  ua::app::DiscoveryTarget localhost;
  localhost.discoveryUrl = "opc.tcp://localhost:4840/UADiscovery";
  ASSERT_NO_FATAL_FAILURE(start_driver(single_cycle_config({localhost})));

  ASSERT_TRUE(
    poll_until([&] { return mRegistrar->online_cycle_count() >= 1; }, std::chrono::milliseconds{2000}))
    << "a same-machine Discovery Server at the well-known address must be registered with like any "
       "other target";
  const auto cycles = mRegistrar->cycles();
  ASSERT_FALSE(cycles.empty());
  EXPECT_EQ(cycles.front().discoveryUrl, "opc.tcp://localhost:4840/UADiscovery")
    << "the loopback target must be used verbatim, not rewritten or skipped";
  EXPECT_TRUE(cycles.front().isOnline);

  ASSERT_TRUE(poll_until([&] { return mObserver->established() >= 1; }, std::chrono::milliseconds{2000}))
    << "the same-machine registration must be reported as established";
  EXPECT_EQ(mObserver->failed(), 0) << "loopback must not be treated as a failure condition";
  auto status = status_sync();
  ASSERT_EQ(status.size(), 1u);
  EXPECT_TRUE(status.front().lastSuccess.has_value())
    << "the driver must record the same-machine registration as having succeeded";
  EXPECT_FALSE(status.front().lastError.is_bad()) << format(status.front().lastError);
}
