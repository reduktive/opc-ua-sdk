// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientDiscoveryFindServers` integration cluster - the FindServers slice of the client
///        integration-test matrix (the `ClientDiscoveryFindServers.*` rows;
///        CL-DISC-003/004/005/006/007/008/014, client design section 7.6).
///
/// Tier-2 entry for the facade rows: `ua::client::Discovery::find_servers_async` (obtained from
/// `Client::discovery()`). The facade opens an ephemeral None-policy channel to the discovery URL, threads
/// the URL verbatim into `FindServersRequest.endpointUrl`, threads the `serverUris` filter verbatim, issues
/// the session-less request, flattens a bad `ResponseHeader.serviceResult` into a bad `Result`, and returns
/// every `ApplicationDescription` verbatim.
///
/// Fixture: one self-contained server with a `None` endpoint (facade rows) AND a `Basic256Sha256`
/// SignAndEncrypt endpoint with mutual RSA trust (the validation gap-pin rows drive a full
/// open->create->activate), using the same strand-safe request-observer + response-interceptor interfaces the
/// ClientDiscoveryGetEndpoints / ClientSession slices use
/// (`ServerImplTestAccess::set_on_secure_channel_available`
/// + `SecureChannelTestAccess`). The observer captures the outgoing `FindServersRequest` (endpointUrl,
/// serverUris) and the `ActivateSession` occurrence; the interceptor mutates the outgoing
/// `FindServersResponse` (inject a serviceResult, replace the server list, per-call-distinct sets,
/// empty-list) OR the outgoing `CreateSessionResponse` (mutate a serverEndpoints field) BEFORE it is encoded
/// - the MisbehavingServer capability the matrix assigns these rows, realised against one real in-tree
/// server.
///
/// KEY SECURITY BOUNDARY:
///   * The FindServers facade performs NO client-side validation of the discovery response. FindServers is
///     session-less and `ApplicationDescription` carries no server certificate, no EndpointDescriptions and
///     no endpointUrl-host, so the applicationUri / server-cert / endpoint-set / hostname consistency checks
///     the matrix rows 1-5 describe are NOT expressible at, nor performed by, this facade - they are
///     SESSION-CREATION cross-checks (CL-DISC-004/005/014) that live in the connect->CreateSession path.
///   * CL-DISC-004 is exercised through public tier-1 `Client::connect` with
///     `EndpointSelection::AutoBest`: GetEndpoints evidence is retained into CreateSession, certificate /
///     ApplicationUri and endpoint-set substitutions fail closed, and ActivateSession is never emitted.
///   * CL-DISC-005 is exercised through public tier-1 `Client::connect` with `EndpointSelection::ExactUrl`:
///     the CreateSession endpoint for the connected resource is checked against the channel/CreateSession
///     certificate and a mismatch fails before ActivateSession.
///   * CL-DISC-014 is the paired positive: `.local` is removed from the returned endpoint host before it is
///     compared with the unqualified certificate DNS SAN. The live negative CL-DISC-005 row in this same
///     group makes the positive falsifiable if the comparator is removed.

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_url_parser.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_client_session.h"
#include "ua_connection_config.h"
#include "ua_connection.h"
#include "ua_crypto.h"
#include "ua_discovery.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_mdns_transport.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_status.h"
#include "ua_user_identity.h"
#include "ua_x509_certificate.h"

#include "ua_application_description.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_response_header.h"

#include "ua_message_security_mode.h"
#include "ua_security_policy.h"

#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

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

// An mDNS transport whose browse always fails - used to prove the LDS FindServers path is orthogonal to mDNS
// availability (CL-DISC-006). It never produces a browser.
class FailingMdnsTransport : public ua::mdns::MdnsTransport
{
public:
  ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>> start_browse(
    std::string /*serviceType*/, ua::mdns::MdnsBrowseConfig /*config*/) override
  {
    ++startCount;
    return ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>>{ua::Status::BadNotSupported,
      ua::ErrorDetail::build("FakeMdnsSocketFailed", "no multicast interface", "test.fake")};
  }

  int startCount{0};
};

// Mutex-guarded observation co-owned by the fixture and the strand-side interfaces. The server is drained
// before this is released (fixture teardown), so a late strand turn never touches dead state.
struct Observation
{
  mutable std::mutex mutex;

  // --- FindServers request capture (in observation order) ---
  std::vector<std::string> requestEndpointUrls;
  std::vector<std::vector<std::string>> requestServerUris;
  int findServersResponseCount{0};
  int getEndpointsRequestCount{0};

  // --- FindServers response-mutation controls (armed by the test thread BEFORE the call) ---
  // Inject this serviceResult into every FindServersResponse (unless injectServiceResultFirstCallOnly).
  std::optional<ua::StatusCode> injectServiceResult;
  // When set, injectServiceResult applies to the FIRST FindServers response only (fail-then-succeed).
  bool injectServiceResultFirstCallOnly{false};
  // Replace the response's server list with three registered servers (multi-server registry).
  bool replaceWithMultiServer{false};
  // Empty the server list but keep serviceResult Good (empty-filtered-result).
  bool clearServers{false};
  // Return a distinct server set per FindServers call (first: S1, second+: S2).
  bool perCallDistinctServers{false};

  // --- CreateSession response-mutation controls (validation gap-pins) ---
  bool injectMismatchedEndpointApplicationUri{false};  // serverEndpoints[*].server.applicationUri = rogue
  bool injectMismatchedEndpointHost{false};  // serverEndpoints[*].endpointUrl host = host-b.example
  bool injectLocalSuffixEndpointHost{false};  // serverEndpoints[*].endpointUrl host = localhost.local
  // Values the client actually saw AFTER injection (precondition evidence).
  std::vector<std::string> createEndpointUrls;
  std::vector<std::string> createEndpointApplicationUris;
  int activateCount{0};

  void observe_request(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* findServers = dynamic_cast<const ua::FindServersRequest*>(&request))
    {
      requestEndpointUrls.push_back(std::string{findServers->endpoint_url()});
      std::vector<std::string> uris;
      for (const auto& uri : findServers->server_uris())
        uris.push_back(std::string{uri});
      requestServerUris.push_back(std::move(uris));
    }
    if (dynamic_cast<const ua::GetEndpointsRequest*>(&request))
    {
      ++getEndpointsRequestCount;
    }
    if (dynamic_cast<const ua::ActivateSessionRequest*>(&request))
    {
      ++activateCount;
    }
  }

  void intercept_response(ua::Response& response)
  {
    std::lock_guard lock(mutex);
    if (auto* findServers = dynamic_cast<ua::FindServersResponse*>(response.second.get()))
    {
      intercept_find_servers(*findServers);
      return;
    }
    if (auto* create = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
    {
      intercept_create_session(*create);
      return;
    }
  }

  std::vector<std::string> request_endpoint_urls() const
  {
    std::lock_guard lock(mutex);
    return requestEndpointUrls;
  }

  std::vector<std::vector<std::string>> request_server_uris() const
  {
    std::lock_guard lock(mutex);
    return requestServerUris;
  }

  int find_servers_response_count() const
  {
    std::lock_guard lock(mutex);
    return findServersResponseCount;
  }

  int get_endpoints_request_count() const
  {
    std::lock_guard lock(mutex);
    return getEndpointsRequestCount;
  }

  int activate_count() const
  {
    std::lock_guard lock(mutex);
    return activateCount;
  }

  std::vector<std::string> create_endpoint_urls() const
  {
    std::lock_guard lock(mutex);
    return createEndpointUrls;
  }

  std::vector<std::string> create_endpoint_application_uris() const
  {
    std::lock_guard lock(mutex);
    return createEndpointApplicationUris;
  }

private:
  // Requires: mutex held.
  void intercept_find_servers(ua::FindServersResponse& response)
  {
    const int callIndex = findServersResponseCount++;

    if (injectServiceResult && (!injectServiceResultFirstCallOnly || callIndex == 0))
      response.response_header().service_result() = *injectServiceResult;

    if (clearServers)
      response.servers().clear();

    if (replaceWithMultiServer)
    {
      response.servers().clear();
      response.servers().push_back(make_server("urn:Server:A", "opc.tcp://a-host:4840/UA"));
      response.servers().push_back(make_server("urn:Server:B", "opc.tcp://b-host:4840/UA"));
      response.servers().push_back(make_server("urn:Server:C", "opc.tcp://c-host:4840/UA"));
    }

    if (perCallDistinctServers)
    {
      response.servers().clear();
      if (callIndex == 0)
      {
        response.servers().push_back(make_server("urn:Server:S1", "opc.tcp://s1-host:4840/UA"));
      }
      else
      {
        response.servers().push_back(make_server("urn:Server:S2a", "opc.tcp://s2a-host:4840/UA"));
        response.servers().push_back(make_server("urn:Server:S2b", "opc.tcp://s2b-host:4840/UA"));
      }
    }
  }

  // Requires: mutex held.
  void intercept_create_session(ua::CreateSessionResponse& response)
  {
    for (auto& endpoint : response.server_endpoints().payload())
    {
      if (injectMismatchedEndpointApplicationUri)
        endpoint.server().application_uri() = ua::String{"urn:RogueServer"};
      if (injectMismatchedEndpointHost)
        endpoint.endpoint_url() =
          ua::transport::rewrite_host(std::string_view{endpoint.endpoint_url()}, "host-b.example");
      if (injectLocalSuffixEndpointHost)
        endpoint.endpoint_url() =
          ua::transport::rewrite_host(std::string_view{endpoint.endpoint_url()}, "localhost.local");
    }
    createEndpointUrls.clear();
    createEndpointApplicationUris.clear();
    for (const auto& endpoint : response.server_endpoints().payload())
    {
      createEndpointUrls.push_back(std::string{endpoint.endpoint_url()});
      createEndpointApplicationUris.push_back(std::string{endpoint.server().application_uri()});
    }
  }

  static ua::ApplicationDescription make_server(
    std::string_view applicationUri, std::string_view discoveryUrl)
  {
    ua::ApplicationDescription app;
    app.application_uri() = ua::String{std::string{applicationUri}};
    app.application_type() = ua::ApplicationType::Server;
    app.discovery_urls().push_back(ua::String{std::string{discoveryUrl}});
    return app;
  }
};

}  // namespace

// =============================================================================================
// Fixture: a server with a None endpoint (facade rows) + a Basic256Sha256 endpoint (validation gap-pins),
// mutual RSA trust, and the request-observer / response-interceptor interfaces; a client queries it through
// the Discovery facade and (for the gap-pins) the full open->create->activate path.
// =============================================================================================
class ClientDiscoveryFindServers : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mObservation = std::make_shared<Observation>();
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    mServerRsa = make_rsa_cert(mCrypto, "DiscoveryServer", "urn:test:disc:fs:server");
    mClientRsa = make_rsa_cert(mCrypto, "DiscoveryClient", "urn:test:disc:fs:client");

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_disc_fs_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    add_app_cert(mServerCertStore, mServerRsa);
    mServerCertStore->add_to_trusted_certificates_sync(mClientRsa.cert);

    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    add_app_cert(mClientCertStore, mClientRsa);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.application_description_part().applicationUri = "urn:test:disc:fs:server";

    ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    components.authenticator = std::make_shared<AnonymousAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    server::CreateConfig serverCreateCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

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
    clientAppCfg.application_description_part().applicationUri = "urn:test:disc:fs:client";
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

  static void add_app_cert(const std::shared_ptr<CertificateStore>& store, const KeyMaterial& material)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = material.cert;
    appCert.keys = material.keys;
    store->add_to_application_certificates_sync(appCert);
  }

  void add_endpoints()
  {
    {
      ServerEndpointConfig ep;
      ep.name = "None_None";
      ep.messageSecurityMode = MessageSecurityMode::None;
      ep.securityPolicyId = SecurityPolicyId::None;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }
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

  ua::client::Discovery::FindServersResult find_servers(FindServersOptions options = {})
  {
    return mClient->discovery().try_find_servers_sync(mEndpointUrl, std::move(options));
  }

  // Arm the server to inject @p status into the FindServers response's serviceResult, query FindServers, and
  // assert the facade surfaces exactly that code with an ErrorDetail naming the discovery URL. Any other code
  // (or a Good result) falsifies the passthrough.
  void expect_surfaces_service_result(ua::StatusCode status)
  {
    {
      std::lock_guard lock(mObservation->mutex);
      mObservation->injectServiceResult = status;
    }
    auto result = find_servers();
    ASSERT_TRUE(result.is_bad()) << "an injected bad serviceResult must produce a bad Result";
    EXPECT_EQ(result.status_code(), status) << "the injected serviceResult must reach the caller verbatim";
    ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
    EXPECT_THAT(ua::to_string(*result.shared_detail()), ::testing::HasSubstr(mEndpointUrl))
      << "the ErrorDetail must name the discovery URL";
  }

  // Full open(Basic256Sha256) -> create -> activate(Anonymous) against this fixture. Returns the activation
  // outcome and leaves the channel/session owned by the outcome for the caller to close.
  struct SessionOutcome
  {
    bool channelOpened{false};
    std::optional<ua::client::SecureChannel> channel;
    std::optional<ua::client::Session> session;
    ua::VoidResult activate;
  };

  SessionOutcome open_create_activate_secured()
  {
    SessionOutcome outcome;
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerRsa.cert;
    auto channelResult = mClient->core().try_open_channel_sync(std::move(cfg));
    if (channelResult.is_bad())
    {
      outcome.activate = ua::VoidResult{channelResult.status_code(), channelResult.shared_detail()};
      return outcome;
    }
    outcome.channelOpened = true;
    outcome.channel.emplace(std::move(channelResult).value());

    auto sessionResult = outcome.channel->try_create_session_sync({.sessionName = "DiscFsValidation"});
    if (sessionResult.is_bad())
    {
      outcome.activate = ua::VoidResult{sessionResult.status_code(), sessionResult.shared_detail()};
      return outcome;
    }
    outcome.session.emplace(std::move(sessionResult).value());

    ua::client::Session::ActivateConfig config;
    config.identity = AnonymousIdentity{};
    outcome.activate = outcome.session->try_activate_sync(std::move(config));
    return outcome;
  }

  static void close_session(SessionOutcome& outcome)
  {
    if (outcome.session)
      (void)outcome.session->try_close_sync();
    if (outcome.channel)
      (void)outcome.channel->try_close_sync();
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
// Status propagation (CL-DISC-003) - the facade flattens a bad serviceResult verbatim, never masking it.
// =============================================================================================

// @verifies CL-DISC-002
// @verifies CL-DISC-003
// @relation(CL-DISC-002, CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadInternalError)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadInternalError});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadNothingToDo)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadNothingToDo});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadOutOfMemory)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadOutOfMemory});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadRequestTooLarge)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadRequestTooLarge});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadResponseTooLarge)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadResponseTooLarge});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadServerUriInvalid)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadServerUriInvalid});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadUnexpectedError)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadUnexpectedError});
}

// @verifies CL-DISC-003
// @relation(CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, SurfacesServiceResultBadUserAccessDenied)
{
  expect_surfaces_service_result(ua::StatusCode{ua::Status::BadUserAccessDenied});
}

// =============================================================================================
// Filter / options and stateless-facade behaviour (CL-DISC-002/003/006/007/008).
// =============================================================================================

// @verifies CL-DISC-008
// Default FindServersOptions{} means "return all" - no implicit filter. The captured request.serverUris is
// empty AND every registered server comes back. Falsifier: a facade that injected a spurious default filter
// would send a non-empty serverUris and fewer servers would return.
// @relation(CL-DISC-008, scope=function)
TEST_F(ClientDiscoveryFindServers, EmptyOptionsMeansNoFilter)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->replaceWithMultiServer = true;  // multi-server registry
  }

  auto result = find_servers(FindServersOptions{});
  ASSERT_TRUE(result.is_good()) << "FindServers over the None channel must succeed: 0x" << std::hex
                                << result.status_code().as_uint32();

  auto captured = mObservation->request_server_uris();
  ASSERT_EQ(captured.size(), 1u) << "exactly one FindServers request must have been observed";
  EXPECT_TRUE(captured[0].empty()) << "default options must send an EMPTY serverUris (no implicit filter)";
  EXPECT_EQ(result.value().size(), 3u) << "all registered servers must be returned when no filter is applied";
}

// @verifies CL-DISC-008
// An empty-list-with-Good is a valid outcome, not an error: a serverUris filter matching no registered server
// yields a GOOD Result wrapping an empty vector. Falsifier: mapping empty-list to a bad Result would conflate
// 'no match' with failure.
// @relation(CL-DISC-008, scope=function)
TEST_F(ClientDiscoveryFindServers, HandlesEmptyFilteredResult)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->clearServers = true;  // server responds Good with servers=[]
  }

  FindServersOptions options;
  options.serverUris = {"urn:no-such-server"};
  auto result = find_servers(options);

  ASSERT_TRUE(result.is_good()) << "an empty filtered result with Good status is not an error: 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_TRUE(result.value().empty()) << "no matching server must yield an empty vector, not a bad Result";
}

// @verifies AC-CL-DISC-006-NO-MDNS-DEPENDENCE
// The LDS FindServers path is orthogonal to mDNS: with a failing mDNS transport installed, find_servers still
// returns the server list. Falsifier: if the LDS path depended on mDNS the call would fail because the
// transport rejects start_browse.
// @relation(AC-CL-DISC-006-NO-MDNS-DEPENDENCE, scope=function)
TEST_F(ClientDiscoveryFindServers, LdsWorksWhenMdnsDisabled)
{
  auto failingTransport = std::make_shared<FailingMdnsTransport>();
  mClient->set_mdns_transport(failingTransport);

  // Proof the installed transport is indeed the failing one: the direct mDNS browse fails.
  auto browse = mClient->discovery().start_mdns_browse(
    ua::mdns::MdnsBrowseConfig{.scheme = ua::mdns::OpcUaTransportScheme::Tcp});
  ASSERT_TRUE(browse.is_bad()) << "the failing mDNS transport must reject the browse";
  EXPECT_GE(failingTransport->startCount, 1) << "the installed failing transport must have been consulted";

  // ...yet the independent LDS FindServers path still succeeds.
  auto result = find_servers();
  ASSERT_TRUE(result.is_good()) << "mDNS being unavailable must not disable the LDS FindServers path: 0x"
                                << std::hex << result.status_code().as_uint32();
}

// @verifies AC-CL-DISC-003-FINDSERVERS-URL
// @verifies CL-DISC-003
// The caller URL is threaded verbatim into the outgoing FindServersRequest.endpointUrl. Falsifier: an
// empty/defaulted endpointUrl would leave a multi-hostname server unable to return reachable discoveryUrls.
//
// NOTE (matrix nuance): the matrix names a fictional URL, but the Discovery facade uses the discovery URL
// BOTH to open the ephemeral channel AND as the request.endpointUrl, so the URL must be the real
// (connectable) server URL. The verbatim-threading assertion is preserved: captured request.endpointUrl ==
// caller URL.
// @relation(AC-CL-DISC-003-FINDSERVERS-URL, CL-DISC-003, scope=function)
TEST_F(ClientDiscoveryFindServers, PassesCallerUrlAsEndpointUrl)
{
  auto result = find_servers();
  ASSERT_TRUE(result.is_good()) << "FindServers over the None channel must succeed: 0x" << std::hex
                                << result.status_code().as_uint32();

  auto urls = mObservation->request_endpoint_urls();
  ASSERT_EQ(urls.size(), 1u) << "exactly one FindServers request must have been observed";
  EXPECT_EQ(urls[0], mEndpointUrl) << "the caller URL must be threaded verbatim into request.endpointUrl";
}

// @verifies CL-DISC-008
// The serverUris filter is threaded verbatim, in order, into request.serverUris. Falsifier: dropping,
// reordering, or defaulting the filter would make the captured vector differ and server-side scoping wrong.
// @relation(CL-DISC-008, scope=function)
TEST_F(ClientDiscoveryFindServers, PassesServerUrisFilter)
{
  FindServersOptions options;
  options.serverUris = {"urn:A", "urn:B"};
  auto result = find_servers(options);
  ASSERT_TRUE(result.is_good()) << "FindServers over the None channel must succeed: 0x" << std::hex
                                << result.status_code().as_uint32();

  auto captured = mObservation->request_server_uris();
  ASSERT_EQ(captured.size(), 1u) << "exactly one FindServers request must have been observed";
  ASSERT_EQ(captured[0].size(), 2u) << "both filter entries must be threaded into request.serverUris";
  EXPECT_EQ(captured[0][0], "urn:A") << "the filter must be threaded in order (entry 0)";
  EXPECT_EQ(captured[0][1], "urn:B") << "the filter must be threaded in order (entry 1)";
}

// @verifies CL-DISC-007
// The facade is stateless per call: a second FindServers with identical arguments issues a fresh wire request
// and returns the server's CURRENT set (S2), not a memoised copy of the first (S1). Falsifier: a memoising
// facade would emit no second request and return the stale S1.
// @relation(CL-DISC-007, scope=function)
TEST_F(ClientDiscoveryFindServers, RepeatCallReturnsFreshResult)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->perCallDistinctServers = true;
  }

  auto first = find_servers();
  ASSERT_TRUE(first.is_good()) << "first FindServers must succeed: 0x" << std::hex
                               << first.status_code().as_uint32();
  ASSERT_EQ(first.value().size(), 1u) << "the first call must observe S1 (a single server)";
  EXPECT_EQ(std::string{first.value()[0].application_uri()}, "urn:Server:S1");

  auto second = find_servers();
  ASSERT_TRUE(second.is_good()) << "second FindServers must succeed: 0x" << std::hex
                                << second.status_code().as_uint32();
  ASSERT_EQ(second.value().size(), 2u)
    << "the second call must issue a fresh request and observe the changed set S2, not the cached S1";

  EXPECT_EQ(mObservation->find_servers_response_count(), 2)
    << "each call must produce its own wire FindServers request/response (no memoization)";
}

// @verifies CL-DISC-007
// A prior discovery failure must not poison subsequent calls: the facade holds no sticky error state. The
// server faults the FIRST FindServers and returns a good list on the second. Falsifier: sticky error state
// would also fail the second call.
// @relation(CL-DISC-007, scope=function)
TEST_F(ClientDiscoveryFindServers, SecondCallAfterFirstFailureSucceeds)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectServiceResult = ua::StatusCode{ua::Status::BadInternalError};
    mObservation->injectServiceResultFirstCallOnly = true;
  }

  auto first = find_servers();
  ASSERT_TRUE(first.is_bad()) << "the first call must surface the injected service fault";
  EXPECT_EQ(first.status_code(), ua::StatusCode{ua::Status::BadInternalError});

  auto second = find_servers();
  ASSERT_TRUE(second.is_good())
    << "a prior failure must not poison the stateless facade: the second call must succeed: 0x" << std::hex
    << second.status_code().as_uint32();
  EXPECT_EQ(mObservation->find_servers_response_count(), 2) << "each call issues its own fresh wire request";
}

// =============================================================================================
// Session-creation cross-check gap-pins (CL-DISC-004/005/014).
//
// These matrix rows describe SESSION-CREATION cross-checks, not FindServers-facade behaviour: FindServers is
// session-less and its ApplicationDescription records carry no server certificate / endpoints / endpointUrl-
// host, so the checks can only be exercised over a full connect->CreateSession->ActivateSession flow. Each
// row injects its mismatch into the CreateSession serverEndpoints and asserts the real client-observable
// outcome.
//
// (Two matrix rows are NOT re-authored here - they duplicate existing session-boundary coverage and are
// inexpressible at the FindServers facade: RejectsMismatchedEndpointDescriptions is
// `ClientSession.ClosesWhenCreateSessionEndpointsDifferFromDiscovery` (CL-SESS-005); RejectsMismatchedServer
// Certificate is `ClientSession.ServerCertificateInCreateSessionMatchesChannelCert` (CL-SESS-003).)
// =============================================================================================

// @verifies CL-DISC-001
// @verifies AC-CL-DISC-014-IGNORE-LOCAL-TLD
// @verifies AC-CL-DISC-005-HOSTNAME-MATCH
// Public tier-1 managed ExactUrl connect receives an endpoint with host localhost.local from
// CreateSession while the authenticated certificate DNS SAN is the
// unqualified `localhost`. `.local` is part of the HostName (owner ruling 2026-10-19), so this is a
// mismatch and the connect fails closed before ActivateSession, as `ReportsHostnameMismatch` does.
// @relation(CL-DISC-001, CL-DISC-005, CL-DISC-014, scope=function)
TEST_F(ClientDiscoveryFindServers, RejectsLocalSuffixAgainstAnUnqualifiedCertificateSan)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectLocalSuffixEndpointHost = true;
  }

  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::ExactUrl;
  config.securityMode = MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = mServerRsa.cert;
  config.reconnect = std::nullopt;
  auto result = mClient->try_connect_sync(std::move(config));

  // Precondition: the client saw the `.local` endpointUrl in the CreateSession serverEndpoints.
  auto seenUrls = mObservation->create_endpoint_urls();
  EXPECT_THAT(seenUrls, ::testing::Contains(::testing::HasSubstr("opc.tcp://localhost.local:")))
    << "the injected .local endpointUrl must have reached the client";

  ASSERT_TRUE(result.is_bad()) << "a .local endpointUrl is not declared by an unqualified cert SAN";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateHostNameInvalid});
  EXPECT_EQ(mObservation->activate_count(), 0) << "hostname verification must precede ActivateSession";
  EXPECT_EQ(mObservation->get_endpoints_request_count(), 0)
    << "ExactUrl must use the administrator-supplied endpoint without issuing GetEndpoints";
}

// @verifies CL-DISC-004
// @verifies CL-SESS-005
// Part 4 section 5.4.1: drive the highest public production tier available for discovery-driven connection
// (`Client::connect` is tier 1; no tier-2 easy-connect facade exists yet). AutoBest obtains and retains the
// GetEndpoints evidence. The server then rewrites CreateSession's server.applicationUri to urn:RogueServer
// while its certificate SAN URI remains urn:test:disc:fs:server. The managed connect must fail closed before
// ActivateSession.
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, CL-SESS-005, scope=function)
TEST_F(ClientDiscoveryFindServers, RejectsMismatchedApplicationUri)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectMismatchedEndpointApplicationUri = true;
  }

  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::AutoBest;
  config.reconnect = std::nullopt;
  auto result = mClient->try_connect_sync(std::move(config));

  // Precondition: the client saw the rogue applicationUri in the CreateSession serverEndpoints.
  auto seenUris = mObservation->create_endpoint_application_uris();
  EXPECT_THAT(seenUris, ::testing::Contains(std::string{"urn:RogueServer"}))
    << "the injected rogue applicationUri must have reached the client";

  ASSERT_TRUE(result.is_bad())
    << "the discovery/CreateSession identity substitution must fail managed connect";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_THAT(to_string(*result.shared_detail()), ::testing::HasSubstr("EndpointDescriptions"))
    << "changing ApplicationUri also changes the authenticated endpoint set, so section 5.4.1(c) is the "
       "first "
       "fail-closed discriminator";
  EXPECT_EQ(mObservation->activate_count(), 0) << "fail-closed verification must precede ActivateSession";
}

// @verifies CL-DISC-004
// @verifies CL-SESS-005
// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// EasyConnect performs GetEndpoints, selects and validates the secured endpoint, and then connects
// with ExactUrl. This regression test proves that the complete discovery response crosses that
// internal hand-off: changing the secured CreateSession endpoint set must still fail closed.
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, CL-DISC-004, CL-SESS-005, scope=function)
TEST_F(ClientDiscoveryFindServers, EasyConnectRejectsMismatchedApplicationUri)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectMismatchedEndpointApplicationUri = true;
  }

  EasyConnectConfig policy;
  policy.endpointUrl = mEndpointUrl;
  policy.customize = [](ConnectionConfig& config)
  {
    config.reconnect = std::nullopt;
  };
  auto result = mClient->try_easy_connect_sync(std::move(policy));

  auto seenUris = mObservation->create_endpoint_application_uris();
  EXPECT_THAT(seenUris, ::testing::Contains(std::string{"urn:RogueServer"}))
    << "the injected rogue applicationUri must have reached the client";

  ASSERT_TRUE(result.is_bad())
    << "EasyConnect must retain discovery evidence until the secured CreateSession cross-check";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityChecksFailed});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_THAT(to_string(*result.shared_detail()), ::testing::HasSubstr("EndpointDescriptions"));
  EXPECT_EQ(mObservation->get_endpoints_request_count(), 1)
    << "EasyConnect should discover once and carry that evidence into ExactUrl connect";
  EXPECT_EQ(mObservation->activate_count(), 0) << "fail-closed verification must precede ActivateSession";
}

// @verifies AC-CL-DISC-005-HOSTNAME-MATCH
// Public tier-1 managed ExactUrl connect receives a CreateSession endpointUrl whose host is host-b.example
// while the authenticated channel certificate contains localhost /
// 127.0.0.1. Default policy must fail closed with rich hostname evidence before ActivateSession.
// @relation(AC-CL-DISC-005-HOSTNAME-MATCH, scope=function)
// @verifies AC-SVR-DISC-GEN-013-CERT-HOSTNAME-MATCHES
TEST_F(ClientDiscoveryFindServers, ReportsHostnameMismatch)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectMismatchedEndpointHost = true;
  }

  ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::ExactUrl;
  config.securityMode = MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = mServerRsa.cert;
  config.reconnect = std::nullopt;
  auto result = mClient->try_connect_sync(std::move(config));

  // Precondition: the client saw the mismatched endpointUrl host in the CreateSession serverEndpoints.
  auto seenUrls = mObservation->create_endpoint_urls();
  EXPECT_THAT(seenUrls, ::testing::Contains(::testing::HasSubstr("opc.tcp://host-b.example:")))
    << "the injected mismatched endpointUrl host must have reached the client";

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateHostNameInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_THAT(to_string(*result.shared_detail()), ::testing::HasSubstr("host-b.example"));
  EXPECT_THAT(to_string(*result.shared_detail()), ::testing::HasSubstr("localhost"));
  EXPECT_EQ(mObservation->activate_count(), 0) << "hostname verification must precede ActivateSession";
}
