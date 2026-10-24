// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientDiscoveryGetEndpoints` integration cluster - the GetEndpoints slice of the client
///        integration-test matrix (the `ClientDiscoveryGetEndpoints.*` rows; CL-DISC-007/009/010, client
///        design section 7.6).
///
/// Tier-2 entry: `ua::client::Discovery::get_endpoints_async` (obtained from `Client::discovery()`). The
/// facade opens an ephemeral None-policy channel to the discovery URL, threads the URL verbatim into the
/// `GetEndpointsRequest.endpointUrl`, issues the session-less request, flattens a bad `ResponseHeader
/// .serviceResult` into a bad `Result`, and returns every `EndpointDescription` verbatim (no URL dedup).
///
/// Fixture: a self-contained server with a single None endpoint and the same strand-safe request-observer +
/// response-interceptor interfaces the ClientUsernamePassword / ClientEcc slices use
/// (`ServerImplTestAccess::set_on_secure_channel_available` + `SecureChannelTestAccess`). The observer
/// captures each outgoing `GetEndpointsRequest.endpointUrl`; the interceptor mutates the outgoing
/// `GetEndpointsResponse` (inject a serviceResult, replace the endpoint list with same-URL/distinct-security
/// records, or return a distinct set per call) BEFORE it is encoded - the MisbehavingServer capability the
/// matrix assigns these rows, realised against one real in-tree server.
///
/// Each row is falsifiable and asserts an EXACT observable - the surfaced status code, the threaded
/// endpointUrl, the returned record count/URL.
///
#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_address_space.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_core_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_crypto.h"
#include "ua_discovery.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_generic_event.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_to_result.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_status.h"
#include "ua_simple_attribute_operand.h"
#include "ua_variable_id.h"
#include "ua_x509_certificate.h"

#include "ua_endpoint_description.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_easy_connect_policy.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_user_identity.h"
#include "ua_response_header.h"

#include "ua_message_security_mode.h"
#include "ua_security_policy.h"

#include "fire_and_forget_scanner.h"
#include "helpers/subscription.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <future>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

std::string policy_uri(SecurityPolicyId id)
{
  return std::string{SecurityPolicy::create(id)->uri()};
}

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial make_rsa_cert(
  const std::shared_ptr<const Crypto>& crypto, std::string_view commonName, std::string_view uri)
{
  Crypto::Name subject;
  subject.commonName = std::string{commonName};
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(std::string{uri});
  altName.hostnames.push_back("localhost");
  altName.hostnames.push_back("127.0.0.1");
  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
  if (result.is_bad())
    throw std::runtime_error("failed to create certificate: " + std::string{commonName});
  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

// Mutex-guarded observation co-owned by the fixture and the strand-side interfaces. The server is drained
// before this is released (fixture teardown), so a late strand turn never touches dead state.
struct Observation
{
  mutable std::mutex mutex;

  // Captured GetEndpointsRequest.endpointUrl values, in observation order.
  std::vector<std::string> requestEndpointUrls;

  // --- Response-mutation controls (armed by the test thread BEFORE the call) ---
  // Inject this serviceResult into every GetEndpointsResponse.
  std::optional<ua::StatusCode> injectServiceResult;
  // Replace the response's endpoint list with three same-URL / distinct-security records.
  bool replaceWithMultiEndpoint{false};
  // Return a distinct endpoint set per GetEndpoints call (first: E1, second+: E2).
  bool perCallDistinctEndpoints{false};
  // Replace every returned EndpointDescription's SecurityPolicyUri.
  std::optional<std::string> replaceSecurityPolicyUri;
  // Replace every returned EndpointDescription's claimed Server ApplicationUri.
  std::optional<std::string> replaceApplicationUri;
  // CL-DISC-019 shaping, applied to the GetEndpointsResponse AND to CreateSessionResponse.serverEndpoints so
  // the CL-DISC-004 set comparison still holds: drop every secured endpoint (what a stripped list looks like)
  // and/or raise the unsecured endpoint's advertised securityLevel.
  bool stripSecuredEndpoints{false};
  std::optional<uint8_t> unsecuredSecurityLevel;

  // Number of CreateSessionRequests observed (any channel).
  int createSessionRequests{0};

  // Number of GetEndpointsResponse objects intercepted (one per wire GetEndpoints call).
  int getEndpointsResponseCount{0};

  void observe_request(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* getEndpoints = dynamic_cast<const ua::GetEndpointsRequest*>(&request))
    {
      requestEndpointUrls.push_back(std::string{getEndpoints->endpoint_url()});
    }
    if (dynamic_cast<const ua::CreateSessionRequest*>(&request) != nullptr)
    {
      ++createSessionRequests;
    }
  }

  template<typename Endpoints>
  void shape_endpoints(Endpoints& endpoints) const
  {
    if (stripSecuredEndpoints)
    {
      std::erase_if(endpoints.payload(),
        [](const ua::EndpointDescription& endpoint)
        { return endpoint.security_mode() != ua::MessageSecurityMode::None; });
    }
    if (unsecuredSecurityLevel)
    {
      for (auto& endpoint : endpoints.payload())
      {
        if (endpoint.security_mode() == ua::MessageSecurityMode::None)
          endpoint.security_level() = *unsecuredSecurityLevel;
      }
    }
  }

  void intercept_response(ua::Response& response)
  {
    std::lock_guard lock(mutex);
    if (auto* createSession = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
    {
      shape_endpoints(createSession->server_endpoints());
      return;
    }
    auto* getEndpoints = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get());
    if (!getEndpoints)
      return;
    const int callIndex = getEndpointsResponseCount++;

    if (injectServiceResult)
      getEndpoints->response_header().service_result() = *injectServiceResult;

    if (replaceWithMultiEndpoint)
    {
      getEndpoints->endpoints().clear();
      const std::string url = "opc.tcp://same-host:4840/UA";
      ua::EndpointDescription none;
      none.endpoint_url() = url;
      none.security_mode() = ua::MessageSecurityMode::None;
      none.security_policy_uri() = policy_uri(SecurityPolicyId::None);
      ua::EndpointDescription basic;
      basic.endpoint_url() = url;
      basic.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
      basic.security_policy_uri() = policy_uri(SecurityPolicyId::Basic256Sha256);
      ua::EndpointDescription aes;
      aes.endpoint_url() = url;
      aes.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
      aes.security_policy_uri() = policy_uri(SecurityPolicyId::Aes128Sha256RsaOaep);
      getEndpoints->endpoints().push_back(std::move(none));
      getEndpoints->endpoints().push_back(std::move(basic));
      getEndpoints->endpoints().push_back(std::move(aes));
    }

    if (perCallDistinctEndpoints)
    {
      getEndpoints->endpoints().clear();
      if (callIndex == 0)
      {
        // E1: a single endpoint.
        ua::EndpointDescription only;
        only.endpoint_url() = "opc.tcp://e1-host:4840/UA";
        only.security_mode() = ua::MessageSecurityMode::None;
        only.security_policy_uri() = policy_uri(SecurityPolicyId::None);
        getEndpoints->endpoints().push_back(std::move(only));
      }
      else
      {
        // E2: two endpoints (a distinct set - proves a fresh wire request, not a cached E1).
        ua::EndpointDescription first;
        first.endpoint_url() = "opc.tcp://e2-host-a:4840/UA";
        first.security_mode() = ua::MessageSecurityMode::None;
        first.security_policy_uri() = policy_uri(SecurityPolicyId::None);
        ua::EndpointDescription second;
        second.endpoint_url() = "opc.tcp://e2-host-b:4840/UA";
        second.security_mode() = ua::MessageSecurityMode::None;
        second.security_policy_uri() = policy_uri(SecurityPolicyId::None);
        getEndpoints->endpoints().push_back(std::move(first));
        getEndpoints->endpoints().push_back(std::move(second));
      }
    }

    if (replaceSecurityPolicyUri)
    {
      for (auto& endpoint : getEndpoints->endpoints())
        endpoint.security_policy_uri() = *replaceSecurityPolicyUri;
    }

    if (replaceApplicationUri)
    {
      for (auto& endpoint : getEndpoints->endpoints())
        endpoint.server().application_uri() = *replaceApplicationUri;
    }

    shape_endpoints(getEndpoints->endpoints());
  }

  int create_session_requests() const
  {
    std::lock_guard lock(mutex);
    return createSessionRequests;
  }

  std::vector<std::string> request_endpoint_urls() const
  {
    std::lock_guard lock(mutex);
    return requestEndpointUrls;
  }

  int get_endpoints_response_count() const
  {
    std::lock_guard lock(mutex);
    return getEndpointsResponseCount;
  }
};

}  // namespace

// =============================================================================================
// Fixture: a server with a single None endpoint + the request-observer / response-interceptor interfaces,
// and a client that queries it through the Discovery facade.
// =============================================================================================
class ClientDiscoveryGetEndpoints : public ::testing::Test
{
protected:
  /// Lets a derived fixture widen the granted Roles. The default session is Anonymous, which
  /// `well_known_role_permissions` gives {Browse, Read} - not enough for obligations whose operation
  /// needs ReceiveEvents, Call or AddNode.
  virtual void configure_components(server::ServerComponents&)
  {}

  virtual void configure_server_configuration(ServerConfig&)
  {}

  /// Lets a derived fixture change the CLIENT's application configuration (for example close the
  /// process-wide `allowInsecureEndpoints` gate the test config opens).
  virtual void configure_client_configuration(ApplicationConfig&)
  {}

  virtual void add_endpoints()
  {
    {
      ServerEndpointConfig endpoint;
      endpoint.name = "None_None";
      endpoint.messageSecurityMode = MessageSecurityMode::None;
      endpoint.securityPolicyId = SecurityPolicyId::None;
      endpoint.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(endpoint));
    }
    add_authenticated_endpoint();
  }

  void add_authenticated_endpoint()
  {
    ServerEndpointConfig endpoint;
    endpoint.name = "Basic256Sha256_SignAndEncrypt";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(endpoint));
  }

  void SetUp() override
  {
    mObservation = std::make_shared<Observation>();
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    mServerRsa = make_rsa_cert(mCrypto, "DiscoveryServer", "urn:test:disc:server");
    mClientRsa = make_rsa_cert(mCrypto, "DiscoveryClient", "urn:test:disc:client");

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_disc_ge_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = mServerRsa.cert;
    appCert.keys = mServerRsa.keys;
    mServerCertStore->add_to_application_certificates_sync(appCert);
    mServerCertStore->add_to_trusted_certificates_sync(mClientRsa.cert);

    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    CertificateStore::ApplicationCertificate clientAppCert;
    clientAppCert.certificateType = CertificateType::RsaSha256Application;
    clientAppCert.certificate = mClientRsa.cert;
    clientAppCert.keys = mClientRsa.keys;
    mClientCertStore->add_to_application_certificates_sync(clientAppCert);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.application_description_part().applicationUri = "urn:test:disc:server";

    server::ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .authenticator = std::make_shared<AnonymousAuthenticator>(),
      .roleConfiguration = RoleConfiguration::from_well_known_grants(
        {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}}),
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    configure_components(components);

    server::CreateConfig serverCreateCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    configure_server_configuration(serverCreateCfg.server);

    mServer.emplace(
      Server::create(mServerThreadPool.executor(), std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    add_endpoints();

    install_wire_ops();
    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:disc:client";
    configure_client_configuration(clientAppCfg);
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning}));
  }

  void TearDown() override
  {
    // Close + drain the server BEFORE releasing the shared observation state: no in-flight strand turn can
    // then touch dead state.
    mClient.reset();
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
    mObservation.reset();

    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  void install_wire_ops()
  {
    auto& serverImpl = ServerTestAccess::impl(*mServer);
    ServerImplTestAccess(serverImpl)
      .set_on_secure_channel_available(
        [observation = mObservation](std::shared_ptr<ua::server::SecureChannel> secureChannel)
        {
          ua::server::SecureChannelTestAccess::post_on_strand(std::move(secureChannel),
            [observation](auto& guard)
            {
              guard.set_request_observer([observation](uint32_t /*requestId*/, const ua::Structure& request)
                { observation->observe_request(request); });
              guard.set_response_interceptor(
                [observation](ua::Response& response) { observation->intercept_response(response); });
            });
        });
  }

  ua::client::Discovery::GetEndpointsResult get_endpoints()
  {
    return mClient->discovery().try_get_endpoints_sync(mEndpointUrl, {});
  }

  // Arm the server to inject @p status into the GetEndpoints response's serviceResult, query GetEndpoints,
  // and assert the facade surfaces exactly that code with an ErrorDetail naming the discovery URL. Any other
  // code (or a Good result) falsifies the passthrough.
  void expect_surfaces_service_result(ua::StatusCode status)
  {
    {
      std::lock_guard lock(mObservation->mutex);
      mObservation->injectServiceResult = status;
    }
    auto result = get_endpoints();
    ASSERT_TRUE(result.is_bad()) << "an injected bad serviceResult must produce a bad Result";
    EXPECT_EQ(result.status_code(), status) << "the injected serviceResult must reach the caller verbatim";
    ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
    EXPECT_THAT(ua::to_string(*result.shared_detail()), ::testing::HasSubstr(mEndpointUrl))
      << "the ErrorDetail must name the discovery URL";
  }

  void expect_auto_best_rejects_policy(std::string policyUri)
  {
    {
      std::lock_guard lock(mObservation->mutex);
      mObservation->replaceSecurityPolicyUri = policyUri;
    }

    ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.endpointSelection = EndpointSelection::AutoBest;
    config.reconnect = std::nullopt;
    auto result = mClient->try_connect_sync(std::move(config));

    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
    ASSERT_NE(result.shared_detail(), nullptr);
    const auto context = std::ranges::find_if(result.shared_detail()->context,
      [](const NamedValue& value) { return value.key == ContextKeys::securityPolicy.value(); });
    ASSERT_NE(context, result.shared_detail()->context.end())
      << "managed connect must retain the rejected policy URI as structured context";
    EXPECT_EQ(context->value, policyUri);
  }

  void expect_auto_best_rejects_application_uri(std::string applicationUri)
  {
    {
      std::lock_guard lock(mObservation->mutex);
      mObservation->replaceApplicationUri = applicationUri;
    }

    ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.endpointSelection = EndpointSelection::AutoBest;
    config.reconnect = std::nullopt;
    auto result = mClient->try_connect_sync(std::move(config));

    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUriInvalid});
    ASSERT_NE(result.shared_detail(), nullptr);
    const auto context = std::ranges::find_if(result.shared_detail()->context,
      [](const NamedValue& value) { return value.key == ContextKeys::applicationUri.value(); });
    ASSERT_NE(context, result.shared_detail()->context.end());
    EXPECT_EQ(context->value, applicationUri);
  }

  std::shared_ptr<const Crypto> mCrypto;
  KeyMaterial mServerRsa;
  KeyMaterial mClientRsa;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::shared_ptr<Observation> mObservation;
};

// =============================================================================================
// Status propagation (CL-DISC-009) - the facade flattens a bad serviceResult verbatim.
// =============================================================================================

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadInternalError)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadInternalError});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadNothingToDo)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadNothingToDo});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadOutOfMemory)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadOutOfMemory});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadRequestTooLarge)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadRequestTooLarge});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadResponseTooLarge)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadResponseTooLarge});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadTimeout)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadTimeout});
}

// @verifies CL-DISC-009
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadUnexpectedError)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadUnexpectedError});
}

// @verifies AC-CL-DISC-009-GETENDPOINTS-URL
// @relation(CL-DISC-009, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, SurfacesServiceResultBadUserAccessDenied)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadUserAccessDenied});
}

// =============================================================================================
// endpointUrl threading (CL-DISC-009) and no-URL-dedup / stateless facade (CL-DISC-010 / CL-DISC-007).
// =============================================================================================

// @verifies AC-CL-DISC-009-GETENDPOINTS-URL
// The caller URL is threaded verbatim into the outgoing GetEndpointsRequest.endpointUrl. Falsifier: an
// empty/defaulted endpointUrl would leave a multi-hostname server unable to return reachable endpoints.
//
// NOTE (matrix nuance): the matrix names a fictional URL ("opc.tcp://host.example:4840/UADiscovery"), but the
// Discovery facade uses the discovery URL BOTH to open the ephemeral channel AND as the request.endpointUrl,
// so the URL must be the real (connectable) server URL. The verbatim-threading assertion is preserved: the
// captured request.endpointUrl equals the exact caller URL.
// @relation(AC-CL-DISC-009-GETENDPOINTS-URL, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, PassesCallerUrlAsEndpointUrl)
{
  auto result = get_endpoints();
  ASSERT_TRUE(result.is_good()) << "GetEndpoints over the None channel must succeed: 0x" << std::hex
                                << result.status_code().as_uint32();

  auto urls = mObservation->request_endpoint_urls();
  ASSERT_EQ(urls.size(), 1u) << "exactly one GetEndpoints request must have been observed";
  EXPECT_EQ(urls[0], mEndpointUrl) << "the caller URL must be threaded verbatim into request.endpointUrl";
}

// @verifies AC-CL-DISC-010-DISTINCT-ENDPOINTS
// Same-URL endpoints that differ only in security are distinct records, not duplicates: the facade returns
// all three same-URL / distinct-(mode,policy) records verbatim without collapsing them by URL. Falsifier: a
// URL-dedup facade would return size 1 and silently drop the secure endpoints.
//
// NOTE (matrix-oracle deviation, batched): the matrix additionally expects the client to run
// `EndpointSelection::AutoBest` and select the highest-securityLevel record. That selector does NOT exist in
// the client (no EndpointSelection / AutoBest anywhere; security_level is server-side only), so this row
// asserts the real, in-scope observable of the GetEndpoints facade - no URL dedup, all records surfaced
// verbatim (CL-DISC-010). AutoBest selection is a deferred tier-1 slice (see the file-level SCOPE NOTE).
// @relation(AC-CL-DISC-010-DISTINCT-ENDPOINTS, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, PreservesSameUrlWithDifferentSecurity)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->replaceWithMultiEndpoint = true;
  }

  auto result = get_endpoints();
  ASSERT_TRUE(result.is_good()) << "GetEndpoints must succeed: 0x" << std::hex
                                << result.status_code().as_uint32();
  const auto& endpoints = result.value();
  ASSERT_EQ(endpoints.size(), 3u) << "all three same-URL records must be returned (no URL dedup)";

  const std::string url = "opc.tcp://same-host:4840/UA";
  for (const auto& endpoint : endpoints)
    EXPECT_EQ(std::string{endpoint.endpoint_url()}, url) << "every record must carry the same endpoint URL";

  // The three records are distinct by (mode, policy) - none collapsed away.
  bool hasNone = false;
  bool hasBasic = false;
  bool hasAes = false;
  for (const auto& endpoint : endpoints)
  {
    const std::string policyUri{endpoint.security_policy_uri()};
    if (endpoint.security_mode() == ua::MessageSecurityMode::None &&
        policyUri == policy_uri(SecurityPolicyId::None))
      hasNone = true;
    if (endpoint.security_mode() == ua::MessageSecurityMode::SignAndEncrypt &&
        policyUri == policy_uri(SecurityPolicyId::Basic256Sha256))
      hasBasic = true;
    if (endpoint.security_mode() == ua::MessageSecurityMode::SignAndEncrypt &&
        policyUri == policy_uri(SecurityPolicyId::Aes128Sha256RsaOaep))
      hasAes = true;
  }
  EXPECT_TRUE(hasNone) << "the None/None record must be preserved";
  EXPECT_TRUE(hasBasic) << "the SignAndEncrypt/Basic256Sha256 record must be preserved";
  EXPECT_TRUE(hasAes) << "the SignAndEncrypt/Aes128_Sha256_RsaOaep record must be preserved";
}

// @verifies CL-DISC-007
// The facade is stateless per call: a second GetEndpoints with identical arguments issues a fresh wire
// request and returns the server's CURRENT endpoint set (E2), not a memoised copy of the first (E1). The
// server returns a single-record set on the first call and a distinct two-record set on the second.
// Falsifier: a memoising facade would emit no second request and return the stale E1.
// @relation(CL-DISC-007, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RepeatCallReturnsFreshResult)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->perCallDistinctEndpoints = true;
  }

  auto first = get_endpoints();
  ASSERT_TRUE(first.is_good()) << "first GetEndpoints must succeed: 0x" << std::hex
                               << first.status_code().as_uint32();
  ASSERT_EQ(first.value().size(), 1u) << "the first call must observe E1 (a single endpoint)";
  EXPECT_EQ(std::string{first.value()[0].endpoint_url()}, "opc.tcp://e1-host:4840/UA");

  auto second = get_endpoints();
  ASSERT_TRUE(second.is_good()) << "second GetEndpoints must succeed: 0x" << std::hex
                                << second.status_code().as_uint32();
  ASSERT_EQ(second.value().size(), 2u)
    << "the second call must issue a fresh request and observe the changed set E2, not the cached E1";

  EXPECT_EQ(mObservation->get_endpoints_response_count(), 2)
    << "each call must produce its own wire GetEndpoints request/response (no memoization)";
}

// @verifies AC-CL-DISC-011-UNKNOWN-POLICY
// @relation(AC-CL-DISC-011-UNKNOWN-POLICY, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RejectsEmptySecurityPolicyUri)
{
  expect_auto_best_rejects_policy("");
}

// @verifies AC-CL-DISC-011-UNKNOWN-POLICY
// @relation(AC-CL-DISC-011-UNKNOWN-POLICY, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RejectsInvalidSecurityPolicyUriString)
{
  expect_auto_best_rejects_policy("not-a-valid-uri");
}

// @verifies AC-CL-DISC-011-UNKNOWN-POLICY
// @relation(AC-CL-DISC-011-UNKNOWN-POLICY, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RejectsUnsupportedSecurityPolicyUri)
{
  expect_auto_best_rejects_policy("http://opcfoundation.org/UA/SecurityPolicy#NotARealPolicy");
}

// The ECC policy URIs that 1.05.07 removed are unknown to the client: a server endpoint advertising one is
// rejected by the managed connect with Bad_SecurityPolicyRejected, naming the URI.
// @relation(AC-CL-SCE-001-REMOVED-URI-UNKNOWN, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RejectsEveryRemovedEccSecurityPolicyUri)
{
  for (const char* removed : {
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaCha20Poly1305",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_ChaCha20Poly1305",
       })
  {
    SCOPED_TRACE(removed);
    expect_auto_best_rejects_policy(removed);
  }
}

// @verifies AC-CL-DISC-012-APPURI-MATCH
// @relation(AC-CL-DISC-012-APPURI-MATCH, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, RejectsMismatchedApplicationUri)
{
  expect_auto_best_rejects_application_uri("urn:test:disc:mismatched");
}

// =============================================================================================
// Namespace-mutator diagnosis (SVR-DIAG-012) - a failure raised inside a Namespace mutator must
// still carry its ErrorDetail when the caller reads it at the public AddressSpace API.
// =============================================================================================

// SVR-DIAG-012 (the repository error-propagation contract, no SpecStatement): every
// `NamespaceImpl::*_async` mutator - `delete_node_async` is named explicitly - must construct an
// ErrorDetail at the failure site and that chain must reach the outbound Result. The plausible
// implementation that gets this wrong is the one that returns a bare `StatusCode{Status::BadNodeIdUnknown}`
// from the mutator: the numeric code alone is indistinguishable from a rich failure at every interface above,
// so the caller sees a correct-looking status and a null detail, and nothing above the namespace can
// re-manufacture the diagnosis it never received. The stimulus is driven through the real server's real
// address space (no stub namespace), and both controls below prove the failure is genuinely the mutator's:
// deleting a node the namespace owns succeeds (the delete reaches the namespace), and the READ side of the
// same AddressSpace/Namespace crossing does deliver its detail (the interface does not strip details
// wholesale).
// @verifies AC-SVR-DIAG-012-NAMESPACE-MUTATOR-DETAIL
TEST_F(ClientDiscoveryGetEndpoints, NamespaceMutatorFailurePreservesItsErrorDetailAtThePublicApi)
{
  auto addressSpace = mServer->address_space();

  // Two ids well above the standard NS0 identifier range: one this namespace will own, one it never will.
  const NodeId ownedId{uint16_t{0}, uint32_t{9000001}};
  const NodeId absentId{uint16_t{0}, uint32_t{9000002}};

  const auto creation = addressSpace.try_create_node_sync(ownedId, NodeClass::Object);
  ASSERT_TRUE(creation.is_good()) << "the fixture could not seed the owned node: 0x" << std::hex
                                  << creation.status_code().as_uint32();

  // Control 1 - the delete mutator really does reach this namespace. Without it, the bad-path assertions
  // below could be satisfied by an interface that refused before the namespace was ever entered.
  const auto goodDeletion =
    addressSpace.try_delete_node_sync(ownedId, /*deleteForwardHierarchicallyReferencedNodes=*/false);
  ASSERT_TRUE(goodDeletion.is_good()) << "deleting a node the namespace owns must succeed: 0x" << std::hex
                                      << goodDeletion.status_code().as_uint32();

  // Control 2 - the READ side of the same AddressSpace/Namespace crossing carries the namespace's own
  // ErrorDetail through unchanged, so a null detail on the mutator cannot be blamed on the interface.
  const auto lookup = addressSpace.try_find_node_sync(absentId);
  ASSERT_TRUE(lookup.is_bad()) << "an unknown node id must not resolve";
  ASSERT_NE(lookup.shared_detail(), nullptr)
    << "the AddressSpace/Namespace interface drops ErrorDetail wholesale - the mutator assertion below would "
       "be unattributable";

  // The obligation - the mutator failure path must arrive at the public API with its detail intact.
  const auto badDeletion =
    addressSpace.try_delete_node_sync(absentId, /*deleteForwardHierarchicallyReferencedNodes=*/false);
  ASSERT_TRUE(badDeletion.is_bad()) << "deleting an unknown node id must fail";
  EXPECT_EQ(badDeletion.status_code(), StatusCode{Status::BadNodeIdUnknown});
  ASSERT_NE(badDeletion.shared_detail(), nullptr)
    << "a Namespace mutator failure reached the public AddressSpace API with no ErrorDetail: the detail "
       "was never built at the failure site";
  EXPECT_FALSE(badDeletion.shared_detail()->code.empty())
    << "the surviving ErrorDetail must name the failure, not be an empty envelope";
  EXPECT_FALSE(badDeletion.shared_detail()->source.empty())
    << "the surviving ErrorDetail must name the producing component";
}

// SVR-DIAG-012 (repository error-propagation contract, no SpecStatement) binds EVERY
// `NamespaceImpl::*_async` mutator, not just `delete_node_async`. The create mutator has a genuine
// in-namespace refusal - `default_ns::Namespace::create_node_internal` rejects `NodeClass::Unspecified` -
// so it is the second mutator whose failure path can be driven through the real address space. The
// plausible implementation that gets this wrong is the one whose `catch (...)` at the mutator boundary
// re-manufactures a bare `StatusCode` from the exception's numeric status: the caller then sees the right
// code with a null (or upper-layer) detail, and the diagnosis built at the failure site is gone. Asserting
// the surviving detail's SOURCE is what makes that falsifiable - a detail allocated by `AddressSpace` above
// the namespace would carry a different producer and would not name the offending node id.
// @verifies AC-SVR-DIAG-012-NAMESPACE-MUTATOR-DETAIL
TEST_F(ClientDiscoveryGetEndpoints, NamespaceCreateMutatorFailurePreservesItsErrorDetailAtThePublicApi)
{
  auto addressSpace = mServer->address_space();

  // Ids well above the standard NS0 identifier range, so neither collides with a seeded node.
  const NodeId acceptedId{uint16_t{0}, uint32_t{9000101}};
  const NodeId rejectedId{uint16_t{0}, uint32_t{9000102}};

  // Control - the create mutator really is reached, and it succeeds for a node class it accepts. Without
  // it the refusal below could be an interface above the namespace declining before the mutator ever ran.
  const auto accepted = addressSpace.try_create_node_sync(acceptedId, NodeClass::Object);
  ASSERT_TRUE(accepted.is_good()) << "creating an Object in this namespace must succeed: 0x" << std::hex
                                  << accepted.status_code().as_uint32();

  // The obligation - the namespace's own refusal must arrive at the public API with its detail intact.
  const auto rejected = addressSpace.try_create_node_sync(rejectedId, NodeClass::Unspecified);
  ASSERT_TRUE(rejected.is_bad()) << "a node class the namespace cannot instantiate must be refused";
  EXPECT_EQ(rejected.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_NE(rejected.shared_detail(), nullptr)
    << "a Namespace mutator failure reached the public AddressSpace API with no ErrorDetail: the detail "
       "built at the failure site did not survive the crossing";
  EXPECT_FALSE(rejected.shared_detail()->code.empty())
    << "the surviving ErrorDetail must name the failure, not be an empty envelope";
  EXPECT_EQ(rejected.shared_detail()->source, "DefaultNamespace")
    << "the surviving ErrorDetail must be the one the namespace built, not one re-manufactured above it";

  const auto context = std::ranges::find_if(rejected.shared_detail()->context,
    [](const NamedValue& value) { return value.key == ContextKeys::nodeId.value(); });
  ASSERT_NE(context, rejected.shared_detail()->context.end())
    << "the mutator's detail must retain the offending node id as structured context";
  EXPECT_THAT(context->value, ::testing::HasSubstr("9000102"))
    << "the retained node id must be the one the caller asked for";
}

// =============================================================================================
// Exception conversion at an async boundary (SVR-DIAG-007).
// =============================================================================================

namespace
{

// A throwable that derives from nothing: the "any other exception" class of the contract, reached only by
// the trailing `catch (...)`.
struct NonStandardPinException
{};

}  // namespace

// SVR-DIAG-007 (the repository error-propagation contract, no SpecStatement; the rule "At async
// boundaries (callbacks, strand lambdas, ASIO completion handlers), use a single `catch(...)` with
// `ua::exception_to_status_code(std::current_exception())`"). An exception escaping into an executor
// has nowhere to go - the callback's caller is a scheduler, not the originating code - so an unconverted
// throw ends the process rather than the operation. The plausible implementation that gets this wrong
// splits the catch in two, `catch (const UaException& e)` followed by `catch (...)`, which reads as the
// more precise handling and is the shape a C++ reviewer expects to see. It is not: the UaException arm
// almost always narrows to `e.status()`, the bare symbolic code, and the ErrorDetail the throw site built
// is gone by the time the caller reads the failure; the catch-all arm then flattens `bad_alloc` and
// everything else into one indistinguishable code. Arms 1-3 therefore assert the CONTENT of the
// conversion for each of the three exception classes the contract names - in particular that a
// UaException's own detail survives by identity, which a status-only arm cannot satisfy. Arm 4 leaves
// the helper behind and drives a real SDK boundary (`MethodAdapter`, which invokes user code under a
// single `catch (...)`): the exception must be converted THERE and delivered through the completion
// callback. Note the obligation is about an exception travelling TOWARD a boundary from inside the SDK,
// so the mirror-image case - a user callback that itself throws - is deliberately not the stimulus; it
// cannot be "delivered through the callback" at all, and on an SDK that does not guard user callbacks
// it ends the process rather than failing an assertion.
// @verifies AC-SVR-DIAG-007-CATCHALL-TO-STATUSCODE
TEST_F(ClientDiscoveryGetEndpoints, AnExceptionEscapingTowardAnAsyncBoundaryBecomesAStatusCode)
{
  // --- Arm 1: a UaException. Its rich StatusCode must survive whole, detail included. --------------
  const std::shared_ptr<const ::ua::ErrorDetail> injected = ::ua::make_error_detail(
    "PinInjectedAsyncBoundaryFailure", "an exception carrying a rich detail", "AC-SVR-DIAG-007");
  ASSERT_NE(injected, nullptr);

  ::ua::StatusCode converted{};
  try
  {
    throw ::ua::UaException{::ua::StatusCode{::ua::Status::BadUserAccessDenied, injected}};
  }
  catch (...)
  {
    converted = ::ua::exception_to_status_code(std::current_exception());
  }

  EXPECT_EQ(converted.as_status(), ::ua::Status::BadUserAccessDenied)
    << "a UaException's own status must survive the conversion rather than being flattened";
  ASSERT_NE(converted.shared_detail(), nullptr)
    << "a UaException's ErrorDetail was dropped at the conversion - the caller receives a bare code and "
       "the diagnosis built at the throw site is unrecoverable";
  EXPECT_TRUE(converted.shared_detail() == injected)
    << "the surviving detail must be the one the throw site built, not one re-manufactured at the "
       "boundary from the numeric status";

  // --- Arm 2: std::bad_alloc, the one std::exception the contract maps by name. --------------------
  ::ua::StatusCode allocConverted{};
  try
  {
    throw std::bad_alloc{};
  }
  catch (...)
  {
    allocConverted = ::ua::exception_to_status_code(std::current_exception());
  }
  EXPECT_EQ(allocConverted.as_status(), ::ua::Status::BadOutOfMemory)
    << "an allocation failure must reach the caller as Bad_OutOfMemory, not as an undifferentiated "
       "internal error";
  EXPECT_NE(allocConverted.shared_detail(), nullptr)
    << "the conversion must name the failure it manufactured a status for";

  // --- Arm 3: anything else, including a throwable that is not a std::exception at all. ------------
  ::ua::StatusCode unknownConverted{};
  try
  {
    throw NonStandardPinException{};
  }
  catch (...)
  {
    unknownConverted = ::ua::exception_to_status_code(std::current_exception());
  }
  EXPECT_EQ(unknownConverted.as_status(), ::ua::Status::BadInternalError)
    << "an exception of no known type must still become a StatusCode";
  EXPECT_NE(unknownConverted.shared_detail(), nullptr)
    << "even the least informative conversion must say where it came from";

  // --- Arm 4: a real SDK boundary rather than a locally-written try/catch. `MethodAdapter::operator()`
  // is the address-space interface that hands a decoded Call to user code, and it is documented never to
  // throw: a handler that throws instead of completing has its exception converted at that boundary and
  // delivered through the completion callback. That is exactly this obligation's shape - an exception
  // escaping TOWARD an async boundary, becoming a StatusCode the caller reads. The handler is invoked
  // from a Call flow whose caller is an executor, so a boundary that let the throw pass would unwind
  // into a scheduler with no caller left to catch it. `ASSERT_NO_THROW` is the "does not cross the
  // boundary as an exception" half; the delivered CallResult is the "becomes a StatusCode" half, and
  // asserting the handler's own detail survives separates a single `catch (...)` +
  // `exception_to_status_code` from a split catch that re-manufactures a bare code. -----------------
  using PinCallArgs = std::tuple<int32_t>;
  const std::shared_ptr<const ::ua::ErrorDetail> handlerDetail = ::ua::make_error_detail(
    "PinHandlerThrewAtBoundary", "a method handler threw instead of completing", "AC-SVR-DIAG-007");

  bool handlerRan = false;
  ::ua::MethodAdapter<PinCallArgs> adapter{[&handlerRan, handlerDetail](const ::ua::NodeId&,
                                             const PinCallArgs&,
                                             std::shared_ptr<const ::ua::MethodCallContext>,
                                             ::ua::CallMethodResult,
                                             ::ua::CallMethodCompleteCallback)
    {
      handlerRan = true;
      throw ::ua::UaException{::ua::StatusCode{::ua::Status::BadUserAccessDenied, handlerDetail}};
    }};

  ::ua::CallMethodRequest callRequest;
  callRequest.input_arguments().resize(1);
  callRequest.input_arguments()[0] = int32_t{1};

  std::optional<::ua::CallResult> delivered;
  ASSERT_NO_THROW(
    adapter(callRequest, nullptr, [&delivered](::ua::CallResult result) { delivered = std::move(result); }))
    << "the handler's exception crossed the async boundary instead of being converted there";

  ASSERT_TRUE(handlerRan)
    << "the handler never ran, so nothing was thrown at the boundary and this arm asserts nothing";
  ASSERT_TRUE(delivered.has_value())
    << "the boundary absorbed the exception without completing the call - the caller is left waiting on "
       "a callback that will never fire, which is no better than the throw";
  EXPECT_TRUE(delivered->is_bad()) << "a handler that threw must not be reported as a successful call";
  EXPECT_EQ(delivered->status_code().as_status(), ::ua::Status::BadUserAccessDenied)
    << "the thrown UaException's own status must reach the caller, not a flattened BadInternalError";
  EXPECT_TRUE(delivered->shared_detail() == handlerDetail)
    << "the detail the handler's exception carried must reach the caller intact - a boundary that "
       "re-manufactures a StatusCode from the numeric status alone loses the diagnosis";
}

// =============================================================================================
// Diagnostic-discipline obligations whose artefact is the source text (SVR-DIAG-003/004/008).
// The observable is the repository's own source tree, reached through the target-level
// TEST_RESOURCE_DIR definition (tests/integration/CMakeLists.txt).
// =============================================================================================

namespace
{

// The repository root. TEST_RESOURCE_DIR is "<repo>/tests/integration/../resources", so two levels up
// is the root (tests/integration/CMakeLists.txt defines it on the integration_tests target).
std::filesystem::path repository_root()
{
  return std::filesystem::weakly_canonical(std::filesystem::path{TEST_RESOURCE_DIR} / ".." / "..");
}

std::vector<std::filesystem::path> source_files(const std::filesystem::path& root, const char* extension)
{
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::exists(root))
    return files;
  const auto options = std::filesystem::directory_options::skip_permission_denied;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root, options))
  {
    if (entry.is_regular_file() && entry.path().extension() == extension)
      files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::vector<std::string> source_lines(const std::filesystem::path& file)
{
  std::vector<std::string> lines;
  std::ifstream stream(file);
  std::string line;
  while (std::getline(stream, line))
    lines.push_back(std::move(line));
  return lines;
}

// A comment-only line carries no code: a line that merely DOCUMENTS a pattern is not an occurrence of it.
bool is_comment_line(const std::string& line)
{
  const auto firstNonSpace = line.find_first_not_of(" \t");
  if (firstNonSpace == std::string::npos)
    return true;
  return line.compare(firstNonSpace, 2, "//") == 0 || line.compare(firstNonSpace, 2, "/*") == 0 ||
         line[firstNonSpace] == '*';
}

std::string lowercased(std::string text)
{
  std::transform(text.begin(),
    text.end(),
    text.begin(),
    [](char character)
    { return character >= 'A' && character <= 'Z' ? static_cast<char>(character - 'A' + 'a') : character; });
  return text;
}

bool is_identifier_character(char character)
{
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '_';
}

// The contiguous run of comment lines immediately above `index`, lowercased. A blank line ends the run:
// a comment separated from what it documents by whitespace documents something else.
std::string comment_block_above(const std::vector<std::string>& lines, std::size_t index)
{
  std::string block;
  for (std::size_t above = index; above-- > 0;)
  {
    if (lines[above].find_first_not_of(" \t") == std::string::npos || !is_comment_line(lines[above]))
      break;
    block = lowercased(lines[above]) + "\n" + block;
  }
  return block;
}

// The root identifier of the value an `is_bad()` guard tests: `cr.result.is_bad()` yields `cr`,
// `folder->is_bad()` yields `folder`. What was bound to that identifier says where the failure came from.
std::string guarded_value(const std::string& line)
{
  const auto probe = line.find("is_bad()");
  if (probe == std::string::npos)
    return {};
  std::size_t begin = probe;
  while (begin > 0)
  {
    const char previous = line[begin - 1];
    if (!is_identifier_character(previous) && previous != '.' && previous != '-' && previous != '>')
      break;
    --begin;
  }
  std::size_t end = begin;
  while (end < line.size() && is_identifier_character(line[end]))
    ++end;
  return line.substr(begin, end - begin);
}

// The initialiser on the nearest binding of `name` at or above `index`: the text right of its `=`, or
// right of the `:` of a range-`for` header. An initialiser broken across the line break continues on the
// next line, so an empty one reads on. Empty when no binding is in view.
std::string initialiser_of(const std::vector<std::string>& lines, std::size_t index, const std::string& name)
{
  if (name.empty())
    return {};

  const std::size_t first = index >= 12 ? index - 12 : 0;
  for (std::size_t above = index + 1; above-- > first;)
  {
    const std::string& line = lines[above];
    if (is_comment_line(line))
      continue;

    const auto at = line.find(name);
    if (at == std::string::npos)
      continue;
    if (at > 0 && (is_identifier_character(line[at - 1]) || line[at - 1] == '.' || line[at - 1] == '>'))
      continue;

    // A binding, not a use: the next non-space character is a lone `=` or `:`, never `==` or `::`.
    std::size_t cursor = at + name.size();
    while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t'))
      ++cursor;
    if (cursor >= line.size() || (line[cursor] != '=' && line[cursor] != ':'))
      continue;
    if (cursor + 1 < line.size() && (line[cursor + 1] == '=' || line[cursor + 1] == ':'))
      continue;

    std::string initialiser = line.substr(cursor + 1);
    if (initialiser.find_first_not_of(" \t") == std::string::npos && above + 1 < lines.size())
      initialiser = lines[above + 1];
    return initialiser;
  }
  return {};
}

}  // namespace

// SVR-DIAG-004 (repository error-propagation contract, no SpecStatement; the rule "Fire-and-forget
// callbacks (`[](VoidResult){}`) inside `*_async` bodies must justify themselves ... Acceptable only when
// (a) the caller is documented as having no use for the result, or (b) the failure is logged at the caller
// before being dropped"). A stub completion callback discards the called operation's rich StatusCode and
// its whole ErrorDetail chain, and - this is the point of the obligation - a deliberate discard and an
// accidental one are byte-identical in the code. The plausible implementation that gets this wrong is the
// one that writes `[](VoidResult) {}` under a comment describing WHAT the call does: a reviewer skimming
// for a comment sees one, but nothing states that the result is not needed, so a real failure of the
// kicked-off operation vanishes with no reader ever having decided that it may.
//
// Two things bound what is asserted. The antecedent is the enclosing body: SVR-DIAG-004 binds a stub
// callback *inside an `*_async` body*, where the discarded status is the one the async operation was
// meant to hand back, so a stub in a synchronous body is outside it and is not counted. And permitted
// form (b) is unreachable for this population by construction - an empty callback body cannot log - so
// what is checked is form (a), the caller documented as having no use for the result. "Documented" is
// not "documented at the call": the search covers the comment block above the call, the one above the
// enclosing definition, and the one on that function's declaration in a header. Both the whole stub set
// and the governed subset are asserted non-empty so a detector that stops matching cannot pass this
// vacuously.
// @relation(AC-SVR-DIAG-004-FIRE-AND-FORGET-JUSTIFIED, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, EveryServerFireAndForgetCallbackStatesWhyItDiscardsItsResult)
{
  const auto root = repository_root();
  const auto scan = ua::test_helpers::fire_and_forget::scan_repository(root);

  ASSERT_FALSE(scan.stubs.empty())
    << "no fire-and-forget completion callback was found at all - with an empty denominator this test "
       "would assert nothing about the SDK";
  ASSERT_FALSE(scan.governed.empty())
    << "of " << scan.stubs.size()
    << " stub completion callbacks none was placed inside an `*_async` body, so the enclosing-body "
       "derivation has stopped working";
  EXPECT_THAT(scan.unjustified, ::testing::IsEmpty())
    << "these `*_async` bodies invoke a callback without observing its outcome, and neither the call site "
       "nor the caller's own documentation states that the result is not needed, so a deliberate discard "
       "cannot be told from an accidental one at review";
}

// SVR-DIAG-003 (repository error-propagation contract, no SpecStatement; the rule "Per-item failures
// during iteration may be skipped when the contract is genuinely best-effort ... Document the skip with a
// one-line comment at the skip site stating *why* the per-item failure is non-fatal. Reviewers reject
// undocumented skips"). AC-SVR-DIAG-001 forbids silent discards outright; SVR-DIAG-003 is the narrow
// permission to take one, and the whole of the permission is that the skip is VISIBLE. The plausible
// implementation that gets this wrong is the one that writes `if (item.is_bad()) continue;` under a comment
// naming what the loop does - "wire the write notifiers", "advertise the aggregate functions". A reviewer
// skimming for a comment finds one, but nothing anywhere states that losing this item is acceptable, so a
// per-item failure that the contract does NOT permit to be dropped looks exactly like one it does, and the
// difference is invisible for the rest of the file's life.
//
// What is counted. The population is the skip shape the contract names: a `continue` guarded by a per-item
// `is_bad()` inside a loop. Of those, two shapes are REPORTED rather than discarded - the caller or the
// operator still sees the failure - leaving only the traceless skip, the deliberate discard, governed. The
// first writes the per-item status into the operation's own results array or emits it to the logger before
// the loop moves on. The second is a guard over a status the operation computed BEFORE the loop and reads
// back out of the batch it is post-processing: that status is already on its way to the caller, and the loop
// is declining follow-up work for an item that has already failed rather than dropping a failure of its own.
// The two are told apart by how the guarded value was bound - from a call the loop body makes, or from an
// element of a batch that already exists. Both the whole skip set and the governed discard subset are
// asserted non-empty, so a detector that stops matching cannot pass this vacuously. "At the site" is read
// generously against the implementation: the contiguous comment block above the guard, any comment on the
// guard or skip lines, and any comment in the twelve lines above, which reaches the comment on the enclosing
// loop header.
//
// The OBSERVATION's second conjunct - "the contract it implements permits the skip" - is asserted only so far
// as the source can carry it: the justification must name the non-fatal CHARACTER of the contract
// (best-effort, advisory, optional, tolerated) rather than merely restate the skip. Whether the contract so
// named is genuinely best-effort is a reviewer's judgement with no artefact in the tree, and no assertion
// here reaches it.
// @relation(AC-SVR-DIAG-003-BEST-EFFORT-DOCUMENTED, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, EveryDeliberateBestEffortSkipStatesWhyTheItemFailureIsNonFatal)
{
  const auto root = repository_root();
  const std::vector<std::filesystem::path> scanned{
    root / "sdk" / "implementation" / "server", root / "sdk" / "implementation" / "address_space"};

  // A justification names why losing the item is acceptable. A comment that only describes the loop is not
  // one - that is exactly the omission this obligation exists to catch.
  static constexpr std::string_view justifications[]{"best-effort",
    "best effort",
    "non-fatal",
    "non fatal",
    "not fatal",
    "nonfatal",
    "harmless",
    "advisory",
    "tolerate",
    "safe to skip",
    "may be absent",
    "may not exist",
    "optional"};

  std::vector<std::string> skips;
  std::vector<std::string> discards;
  std::vector<std::string> undocumented;

  for (const auto& directory : scanned)
  {
    ASSERT_TRUE(std::filesystem::exists(directory)) << "source directory not found: " << directory.string();

    for (const auto& file : source_files(directory, ".cpp"))
    {
      const auto lines = source_lines(file);
      for (std::size_t index = 0; index < lines.size(); ++index)
      {
        if (is_comment_line(lines[index]) || lines[index].find("continue;") == std::string::npos)
          continue;

        // Pair the skip with the per-item failure test that guards it: the nearest `is_bad()` at or within
        // the four lines above. Anything further away guards a different decision.
        bool guarded = false;
        std::size_t guard = 0;
        const std::size_t nearest = index >= 4 ? index - 4 : 0;
        for (std::size_t above = index + 1; above-- > nearest;)
        {
          if (!is_comment_line(lines[above]) && lines[above].find("is_bad()") != std::string::npos)
          {
            guard = above;
            guarded = true;
            break;
          }
        }
        if (!guarded)
          continue;

        const std::string site =
          std::filesystem::relative(file, root).generic_string() + ":" + std::to_string(index + 1);
        skips.push_back(site);

        // Reported, not discarded: the per-item status reaches the operation's own results array, or the
        // logger, before the loop moves on. Only a traceless skip is the discard this obligation governs.
        std::string skipBody;
        for (std::size_t within = guard; within <= index; ++within)
          skipBody += lowercased(lines[within]) + "\n";
        if (skipBody.find("status_code()") != std::string::npos ||
            skipBody.find("logger") != std::string::npos)
          continue;

        // The same reporting, spelled differently. A site can PUSH the per-item status into the
        // operation's own results container instead of naming it through status_code() - as
        // CompiledEventFilter does with `fields.emplace_back(*projected.status())`, where the bad
        // status travels to the client as that Event field's status. By the rule stated just above
        // that is reported, not discarded; only the accessor differs, and matching solely on
        // `status_code()` classified a fully-handled branch as a traceless skip.
        if (skipBody.find(".status()") != std::string::npos &&
            (skipBody.find("emplace_back") != std::string::npos ||
              skipBody.find("push_back") != std::string::npos))
          continue;

        // Also reported: the guard tests a status the loop did not produce. A value bound from an element
        // of an already-computed batch is that operation's own per-item result, which reaches the caller
        // whatever the loop does; only a value the loop body obtained from a call is a failure of the
        // loop's own attempt, which nothing but the loop has seen.
        const std::string initialiser = initialiser_of(lines, guard, guarded_value(lines[guard]));
        if (!initialiser.empty() && initialiser.find('(') == std::string::npos)
          continue;
        discards.push_back(site);

        std::string documentation = comment_block_above(lines, guard);
        const std::size_t first = guard >= 12 ? guard - 12 : 0;
        for (std::size_t above = first; above <= index; ++above)
        {
          if (is_comment_line(lines[above]) || lines[above].find("//") != std::string::npos)
            documentation += lowercased(lines[above]) + "\n";
        }

        const bool justified = std::ranges::any_of(justifications,
          [&documentation](std::string_view marker)
          { return documentation.find(marker) != std::string::npos; });
        if (!justified)
          undocumented.push_back(site);
      }
    }
  }

  ASSERT_FALSE(skips.empty())
    << "no per-item `is_bad()` skip was found at all - with an empty denominator this test would assert "
       "nothing about the SDK";
  ASSERT_FALSE(discards.empty())
    << "of " << skips.size()
    << " per-item skips every one was found to report or log its failure, so the reported-versus-discarded "
       "derivation has stopped working and no deliberate discard is being checked";
  EXPECT_THAT(undocumented, ::testing::IsEmpty())
    << "these iteration sites drop a per-item bad Result without recording it anywhere, and no comment at "
       "the skip site says why losing the item is non-fatal, so a permitted best-effort skip cannot be told "
       "from a swallowed failure at review";
}

// SVR-DIAG-014: channel-fatal transport and chunk-decode failures converge on the report-before-clear
// Session handoff. Recoverable request-body decode remains a ServiceFault-only path. Runtime unit
// arms prove value preservation; this scan is a supplementary structural durability control.
// @relation(AC-SVR-DIAG-014-SECURECHANNEL-DETAIL, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, EverySecureChannelFailureClassReachesTheOwningSession)
{
  const auto channel = repository_root() / "sdk" / "implementation" / "server" / "secure_channel" /
                       "ua_server_secure_channel.cpp";
  ASSERT_TRUE(std::filesystem::exists(channel)) << "the secure-channel source was not found";

  std::ifstream in{channel};
  ASSERT_TRUE(in.is_open());
  const std::string source{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};

  const auto functionBody = [&source](std::string_view signature, std::string_view nextSignature)
  {
    const auto begin = source.find(signature);
    EXPECT_NE(begin, std::string::npos) << signature << " was not found";
    if (begin == std::string::npos)
      return std::string_view{};

    const auto end = source.find(nextSignature, begin + signature.size());
    EXPECT_NE(end, std::string::npos) << nextSignature << " was not found";
    if (end == std::string::npos)
      return std::string_view{};

    return std::string_view{source}.substr(begin, end - begin);
  };

  constexpr std::string_view fatalWireOps = "report_fatal_error_to_sessions_and_clear(";
  const auto transportFailure = functionBody(
    "void SecureChannel::receive_transport_error(", "void SecureChannel::receive_request_message(");
  const auto chunkFailure =
    functionBody("void SecureChannel::handle_chunk_decode_failure(", "void SecureChannel::drain_outgoing(");
  const auto requestDecodeFailure = functionBody(
    "void SecureChannel::handle_request_decode_failure(", "bool SecureChannel::handle_decoded_request(");
  const auto reportBeforeClear = functionBody("void SecureChannel::report_fatal_error_to_sessions_and_clear(",
    "SecureChannelInfo SecureChannel::build_secure_channel_info(");

  ASSERT_FALSE(transportFailure.empty());
  ASSERT_FALSE(chunkFailure.empty());
  ASSERT_FALSE(requestDecodeFailure.empty());
  ASSERT_FALSE(reportBeforeClear.empty());
  EXPECT_NE(transportFailure.find(fatalWireOps), std::string_view::npos);
  EXPECT_NE(chunkFailure.find(fatalWireOps), std::string_view::npos);
  EXPECT_EQ(requestDecodeFailure.find(fatalWireOps), std::string_view::npos);
  EXPECT_NE(requestDecodeFailure.find("create_service_fault("), std::string_view::npos);
  EXPECT_NE(requestDecodeFailure.find("send_response_message_internal("), std::string_view::npos);

  const auto report = reportBeforeClear.find("report_fatal_error_to_sessions(");
  const auto clear = reportBeforeClear.find("mSessionCallbacks.clear()");
  ASSERT_NE(report, std::string_view::npos);
  ASSERT_NE(clear, std::string_view::npos);
  EXPECT_LT(report, clear);
}

// Part 6 Table 106 lists the steps every certificate validation performs, and an ECC SecurityPolicy
// adds one: the certificate's curve must be one the policy lists. `AC-SVR-ECC-006` states it as an
// ADDITION - "the curve check is applied in addition to the standard steps, not instead of them" -
// which is what makes the shape of the SDK's implementation the thing to look at.
//
// `SecurityPolicy::validate_certificate_async` (`ua_security_policy.cpp`) opens by bounding the
// public-key length against the policy's min and max, and then skips exactly that step for ECC:
//
// Part 6 section 6.8.2: an ECC ApplicationInstance Certificate's named curve must appear in the
// SecurityPolicy's permitted-curve list. The runtime unit proves rejection and the permitted control;
// this scan ensures the policy-level comparison remains in the certificate-validation path.
// @verifies AC-SVR-ECC-006-NAMED-CURVE-VALIDATION
// @relation(AC-SVR-ECC-006-NAMED-CURVE-VALIDATION, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, AnEccPolicyChecksTheCertificatesCurveAgainstItsOwn)
{
  const auto policy =
    repository_root() / "sdk" / "implementation" / "core" / "security" / "ua_security_policy.cpp";
  ASSERT_TRUE(std::filesystem::exists(policy)) << "the security-policy source was not found";

  std::ifstream in{policy};
  ASSERT_TRUE(in.is_open());
  const std::string source{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};

  const auto at = source.find("void SecurityPolicy::validate_certificate_async");
  ASSERT_NE(at, std::string::npos) << "validate_certificate_async was not found, so this scan is "
                                      "reading for a function that has been renamed";
  // The function body, to its closing brace at column 0.
  const auto end = source.find("\n}\n", at);
  ASSERT_NE(end, std::string::npos);
  const std::string body = source.substr(at, end - at);

  // Restated (owner review 2026-10-02, ratified): the curve rule is
  // SecurityPolicy::check_certificate_compliance (SecPolEphemeralKey's), which the validator runs on every
  // chain certificate at Table 106 step 4 for the policy the request names; validate_certificate_async is the
  // thin wrapper that names this policy.
  EXPECT_NE(body.find("request.policyId = id()"), std::string::npos)
    << "validate_certificate_async must hand this policy to the validator, whose Security Policy Check "
       "calls check_certificate_compliance (the ECC curve rule) for every chain certificate";
}

// A session that MAY receive events. `well_known_role_permissions` gives Anonymous exactly
// {Browse, Read} - no ReceiveEvents - and namespace 0 is stamped with those derived permissions, so
// an Anonymous session cannot receive ANY Event from the Server Object and the per-field question
// below is never reached. Observer carries {Browse, Read, ReadHistory, ReceiveEvents}. Only Observer
// is granted, not Observer AND Anonymous: permissions union across granted Roles, so leaving
// Anonymous in place would let the field denial below be satisfied by the other Role.
class ClientDiscoveryGetEndpointsAsObserver : public ClientDiscoveryGetEndpoints
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration =
      RoleConfiguration::from_well_known_grants({{WellKnownRole::Observer, IdentityCriteriaType::Anonymous}});
  }
};

// Part 4 section 7.22.3 requires per-field authorization: the Event is delivered and only a selected
// field inaccessible to the Session user is replaced by Bad_UserAccessDenied.
// @relation(AC-SVR-MI-EVT-005-FIELD-USERACCESSDENIED, scope=function)
TEST_F(ClientDiscoveryGetEndpointsAsObserver, EveryEventFieldIsAuthorisedAgainstTheSessionsUser)
{
  auto severityNode = mServer->address_space().find_node_sync(NodeId{VariableId::BaseEventType_Severity});
  RolePermissionType severityPermissions;
  severityPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Observer};
  severityPermissions.permissions() = PermissionType{{PermissionType::Bit::Browse}};
  severityNode.set_role_permissions(std::vector<RolePermissionType>{severityPermissions});

  CoreClient::OpenChannelConfig openConfig;
  openConfig.endpointUrl = mEndpointUrl;
  openConfig.timeout = std::chrono::seconds{5};
  auto channel = mClient->core().open_channel_sync(std::move(openConfig));
  auto session = channel.create_session_sync({.sessionName = "EventFieldAuthorization"});
  session.activate_sync();

  const auto subscriptionId =
    create_subscription(session, {.publishingInterval = 50.0, .keepAliveCount = 30});

  EventFilter filter;
  SimpleAttributeOperand message;
  message.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  message.browse_path().push_back(QualifiedName{0, "Message"});
  message.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(message));

  SimpleAttributeOperand severity;
  severity.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  severity.browse_path().push_back(QualifiedName{0, "Severity"});
  severity.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(severity));

  const auto monitoredItemId = create_event_monitored_item(session,
    subscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    {.clientHandle = 73, .samplingInterval = 0.0, .queueSize = 10});
  ASSERT_NE(monitoredItemId, 0u);

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"EventFieldAuthorization"};
  event.message = LocalizedText{"", "MI-EVT-005 mixed authorization"};
  event.severity = 733;
  mServer->emit_event(event);

  auto notification = wait_for_event(
    session,
    subscriptionId,
    [](const EventFieldList& fields)
    {
      if (fields.event_fields().size() != 2)
        return false;
      const auto* text = fields.event_fields()[0].try_as<LocalizedText>();
      return text != nullptr && text->text() == String{"MI-EVT-005 mixed authorization"};
    },
    std::chrono::seconds{5});
  ASSERT_TRUE(notification) << "the Event must still be delivered when one selected field is denied";
  ASSERT_EQ(notification->event_fields().size(), 2u);
  ASSERT_TRUE(notification->event_fields()[0].is_localized_text());
  EXPECT_EQ(
    notification->event_fields()[0].as<LocalizedText>().text(), String{"MI-EVT-005 mixed authorization"});
  ASSERT_TRUE(notification->event_fields()[1].is_status_code());
  EXPECT_EQ(notification->event_fields()[1].as<StatusCode>().as_status(), Status::BadUserAccessDenied);

  delete_subscription(session, subscriptionId);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 9 section 5.8.2: a re-alarm clears SilenceState and AckedState and moves the Alarm active time to the
// re-alarm instant.
//
// The pure AlarmConditionLogic unit verifies those values. This control keeps the strand-owned timer
// callback wired through that transition, so the shell cannot bypass the state machine when emitting.
// @verifies AC-SVR-AC-123-REALARM-RESETS-STATES
// @relation(AC-SVR-AC-123-REALARM-RESETS-STATES, scope=function)
TEST_F(ClientDiscoveryGetEndpoints, ARealarmResetsTheSilencedAndAcknowledgedStates)
{
  const auto instance =
    repository_root() / "sdk" / "implementation" / "server" / "conditions" / "ua_condition_instance.cpp";
  ASSERT_TRUE(std::filesystem::exists(instance)) << "the condition instance source was not found";

  std::ifstream in{instance};
  ASSERT_TRUE(in.is_open());
  const std::string source{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};

  const auto start = source.find("case TimerCommand::Kind::StartReAlarmTimer:");
  ASSERT_NE(start, std::string::npos) << "the re-alarm timer case has moved; this scan is out of date";
  const auto end = source.find("case TimerCommand::Kind::CancelReAlarmTimer:", start);
  ASSERT_NE(end, std::string::npos);
  const std::string callback = source.substr(start, end - start);

  EXPECT_NE(callback.find("on_re_alarm_timer_expired()"), std::string::npos)
    << "the timer callback must ask AlarmConditionLogic to perform the re-alarm transition";

  EXPECT_NE(callback.find("apply_transition(transition)"), std::string::npos)
    << "the timer callback must apply the logic result through the normal event/snapshot/timer path";

  EXPECT_EQ(callback.find("emit_condition_event()"), std::string::npos)
    << "the timer callback must not emit before the state-machine transition is applied";
  EXPECT_EQ(callback.find("update_snapshot()"), std::string::npos)
    << "the timer callback must not update a stale pre-transition snapshot";
  EXPECT_EQ(callback.find("notify_wired_variables()"), std::string::npos)
    << "the timer callback must not notify stale pre-transition variables";
}

class ClientDiscoveryEndpointDisabled : public ClientDiscoveryGetEndpoints
{
protected:
  void configure_server_configuration(ServerConfig& config) override
  {
    config.discoveryEndpointEnabled = false;
  }

  void add_endpoints() override
  {
    add_authenticated_endpoint();
  }
};

// Part 4 section 5.4.1. With no configured None endpoint, the discovery facade must be unable to open
// the server's discovery-only channel. The same listener's authenticated endpoint is then reached through
// public ExactUrl managed connect, proving the non-default setting removes discovery rather than stopping
// the server.
// @relation(AC-SVR-DISC-GEN-009-DISCOVERY-DISABLEABLE, scope=function)
TEST_F(ClientDiscoveryEndpointDisabled, ConfigurationRejectsDiscoveryWhileAuthenticatedEndpointWorks)
{
  auto discovery = get_endpoints();
  ASSERT_TRUE(discovery.is_bad()) << "a disabled DiscoveryEndpoint must not answer GetEndpoints";
  EXPECT_EQ(discovery.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  ASSERT_NE(discovery.shared_detail(), nullptr)
    << "the client boundary must retain context for the failed discovery channel open";

  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::ExactUrl;
  config.securityMode = MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = mServerRsa.cert;
  config.reconnect = std::nullopt;
  auto connected = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connected.is_good())
    << "disabling discovery must not disable the listener's configured authenticated endpoint";
  EXPECT_TRUE(connected.value().try_close_sync().is_good());
}

// Part 12 section 5.5.2: a Server registering with a Discovery Server calls RegisterServer2 and falls back to
// RegisterServer when the Discovery Server does not implement it. `AC-SVR-DISC-RS2-002` states the
// discrimination as the obligation - "The fallback is triggered by that code **specifically**" - and the
// discrimination is the whole content: falling back on any bad status would retry a v1 registration
// after a rejection that v1 will also reject, turning one refusal into two and hiding the real cause
// behind whichever code the second call happens to return.
//
// `LdsRegistrar::send_register2` (`sdk/implementation/app/ua_lds_registrar.cpp:137-142`) gets it right:
// it compares `outcome.as_status()` against `Bad_ServiceUnsupported` and only then calls
// `send_fallback`; every other bad status takes `make_failure` and closes the channel. Nothing covered
// it.
//
// Asserted over the source rather than through a fake Discovery Server, because the interface is a concrete
// `ua::client::SecureChannel` and a runtime arm would need a real peer answering RegisterServer2 with
// that specific code - worth building and larger than this. What this check defends is the
// discrimination: it fails if the comparison is widened to `is_bad()`, which is the plausible
// simplification and the one that would silently double every failed registration.
// @verifies AC-SVR-DISC-RS2-002-FALLBACK-ON-UNSUPPORTED
TEST_F(ClientDiscoveryGetEndpoints, TheRegisterServer2FallbackIsGatedOnServiceUnsupportedAlone)
{
  const auto registrar = repository_root() / "sdk" / "implementation" / "app" / "ua_lds_registrar.cpp";
  ASSERT_TRUE(std::filesystem::exists(registrar)) << "the LDS registrar source was not found";

  std::ifstream in{registrar};
  ASSERT_TRUE(in.is_open());
  const std::string source{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};

  const auto at = source.find("RegisterServer2ResponseResult result");
  ASSERT_NE(at, std::string::npos) << "the RegisterServer2 completion has moved; this check is stale";
  const auto end = source.find("close_channel(", at);
  ASSERT_NE(end, std::string::npos);
  const std::string completion = source.substr(at, end - at);

  EXPECT_NE(completion.find("Status::BadServiceUnsupported"), std::string::npos)
    << "the RegisterServer2 completion no longer names Bad_ServiceUnsupported, so whatever now decides "
       "the fallback is not the code Part 12 ties it to";
  EXPECT_NE(completion.find("send_fallback"), std::string::npos)
    << "no fallback is invoked from the RegisterServer2 completion at all";

  // The discrimination: the fallback must be reached through the status comparison and not from a bare
  // is_bad(). A fallback on any failure re-sends a v1 registration the peer has already refused.
  const auto gate = completion.find("Status::BadServiceUnsupported");
  const auto fallback = completion.find("send_fallback");
  EXPECT_LT(gate, fallback)
    << "send_fallback is reached before the Bad_ServiceUnsupported comparison, so the fallback is not "
       "gated on that code: a Discovery Server rejecting RegisterServer2 for any other reason would "
       "have a v1 registration sent after it, and the caller would be handed whichever code the second "
       "call returned rather than the one that actually refused";
}

// =============================================================================================
// CL-DISC-019 - discovery-driven selection over an unauthenticated endpoint list. The server offers a None
// endpoint and a Basic256Sha256/SignAndEncrypt endpoint; the interceptor shapes what the client sees.
// =============================================================================================

/// The client with the process-wide None gate CLOSED (`allowInsecureEndpoints = false`): tier-0 refuses a
/// Session over an unsecured channel, so a connect that completes proves the endpoint AutoBest opened was
/// secured. This is the wire-level oracle for the inflated-level arm; it needs no view of the server channel.
class ClientDiscoveryGetEndpointsSecuredClient : public ClientDiscoveryGetEndpoints
{
protected:
  void configure_client_configuration(ApplicationConfig& config) override
  {
    config.allowInsecureEndpoints = false;
  }
};

/// A server offering ONLY an unsecured endpoint, advertising Anonymous and UserName token policies.
class ClientDiscoveryGetEndpointsUnsecuredOnly : public ClientDiscoveryGetEndpoints
{
protected:
  void add_endpoints() override
  {
    ServerEndpointConfig endpoint;
    endpoint.name = "None_None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256));
    mServer->add_endpoint(mListenerHandle, std::move(endpoint));
  }
};

namespace
{
ConnectionConfig auto_best_config(const std::string& endpointUrl, bool allowUnsecuredEndpoint)
{
  ConnectionConfig config;
  config.endpointUrl = endpointUrl;
  config.endpointSelection = EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = allowUnsecuredEndpoint;
  config.reconnect = std::nullopt;
  return config;
}

std::string detail_chain_of(const StatusCode& status)
{
  const auto detail = status.shared_detail();
  return detail ? to_string(*detail) : std::string{};
}
}  // namespace

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// The secured endpoints are removed from the GetEndpoints response in transit (and from the CreateSession
// echo, so the CL-DISC-004 comparison is not what refuses). With the test configuration's process-wide None
// gate OPEN, a selector that took the remaining None endpoint would complete the connect; the per-connection
// default refuses before any Session exists.
TEST_F(ClientDiscoveryGetEndpoints, AutoBestRefusesAStrippedUnsecuredOnlyListWithoutTheOptIn)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->stripSecuredEndpoints = true;
  }

  auto result = mClient->try_connect_sync(auto_best_config(mEndpointUrl, /*allowUnsecuredEndpoint=*/false));

  ASSERT_TRUE(result.is_bad())
    << "a list showing only an unsecured endpoint must not be connected to by default";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityModeRejected);
  EXPECT_THAT(
    detail_chain_of(result.status_code()), ::testing::HasSubstr("AutoBestUnsecuredEndpointRefused"));
  EXPECT_EQ(mObservation->create_session_requests(), 0)
    << "no Session may be created over the refused endpoint";
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// The control, and the non-default-value proof for ConnectionConfig::allowUnsecuredEndpoint: the same
// stripped list, one field set.
TEST_F(ClientDiscoveryGetEndpoints, AutoBestConnectsToAnUnsecuredOnlyListWhenOptedIn)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->stripSecuredEndpoints = true;
  }

  auto result = mClient->try_connect_sync(auto_best_config(mEndpointUrl, /*allowUnsecuredEndpoint=*/true));

  ASSERT_TRUE(result.is_good()) << detail_chain_of(result.status_code());
  EXPECT_EQ(mObservation->create_session_requests(), 1);
  std::move(result).value().close_sync();
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// The None endpoint is advertised at securityLevel 255 (in the GetEndpoints response and the CreateSession
// echo alike) and is a candidate (opted in), so only the client's own ranking keeps it from winning. The
// client's None gate is closed: had AutoBest opened the None endpoint, CreateSession would have been refused
// and the connect would not complete.
TEST_F(ClientDiscoveryGetEndpointsSecuredClient, AutoBestIgnoresAnInflatedSecurityLevel)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->unsecuredSecurityLevel = 255;
  }

  auto result = mClient->try_connect_sync(auto_best_config(mEndpointUrl, /*allowUnsecuredEndpoint=*/true));

  ASSERT_TRUE(result.is_good()) << "the secured endpoint must win regardless of the advertised level: "
                                << detail_chain_of(result.status_code());
  EXPECT_EQ(mObservation->create_session_requests(), 1);
  std::move(result).value().close_sync();
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// A server that offers only an unsecured endpoint is indistinguishable, at the client, from a stripped
// list; the default policy refuses it before any Session exists.
TEST_F(ClientDiscoveryGetEndpointsUnsecuredOnly, EasyConnectRefusesTheUnsecuredOnlyServerWithoutTheOptIn)
{
  EasyConnectConfig policy;
  policy.endpointUrl = mEndpointUrl;

  auto result = mClient->try_easy_connect_sync(std::move(policy));

  ASSERT_TRUE(result.is_bad()) << "an unsecured-only server must be refused by the default policy";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityModeRejected);
  EXPECT_THAT(detail_chain_of(result.status_code()), ::testing::HasSubstr("EasyConnectRefusedUnsecured"));
  EXPECT_EQ(mObservation->create_session_requests(), 0);
}

// @verifies AC-CL-DISC-019-EASYCONNECT-REFUSES-AN-UNSECURED-WINNER-WITHOUT-THE-OPT-IN
// The control: the bootstrap opt-in with the default anonymous identity completes over the same server.
TEST_F(ClientDiscoveryGetEndpointsUnsecuredOnly, EasyConnectConnectsAnonymouslyWhenOptedIn)
{
  EasyConnectConfig policy;
  policy.endpointUrl = mEndpointUrl;
  policy.allowAnonymousFirstConnect = true;

  auto result = mClient->try_easy_connect_sync(std::move(policy));

  ASSERT_TRUE(result.is_good()) << detail_chain_of(result.status_code());
  EXPECT_EQ(mObservation->create_session_requests(), 1);
  std::move(result).value().close_sync();
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-IS-ANONYMOUS-ONLY
// The opt-in is set and the server advertises a UserName policy on its unsecured endpoint; the identity is
// what refuses the connect, before any Session exists.
TEST_F(ClientDiscoveryGetEndpointsUnsecuredOnly, EasyConnectRefusesAUsernameIdentityWhenOptedIn)
{
  EasyConnectConfig policy;
  policy.endpointUrl = mEndpointUrl;
  policy.allowAnonymousFirstConnect = true;
  policy.identity = UsernamePasswordIdentity{"operator", "secret"};

  auto result = mClient->try_easy_connect_sync(std::move(policy));

  ASSERT_TRUE(result.is_bad()) << "a user name over an unsecured endpoint must be refused even when opted in";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityModeRejected);
  EXPECT_THAT(
    detail_chain_of(result.status_code()), ::testing::HasSubstr("EasyConnectUnsecuredRequiresAnonymous"));
  EXPECT_EQ(mObservation->create_session_requests(), 0);
}
