// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientAnonymous` integration cluster - the anonymous-identity activation slice of the client
///        integration-test matrix (rows 941-944).
///
/// Tier-2 entry point under test: `Session::activate_async` with an `AnonymousIdentity`. The tier-0 token
/// builder (`build_user_token`, ua_client_token_builder.cpp) resolves the endpoint's ANONYMOUS
/// `UserTokenPolicy`, stamps its policyId onto a `ua::AnonymousIdentityToken`, and - because an anonymous
/// token carries no secret and no proof-of-possession - leaves the request's `userTokenSignature` EMPTY (a
/// UserTokenSignature is only produced for X509/issued tokens).
///
/// Each row is falsifiable: it captures the ACTUAL decoded `ActivateSessionRequest` the client put on the
/// wire (via a server-side request observer installed on the SecureChannel strand) and asserts the exact
/// observable - the identity-token TYPE (Anonymous, never a UserName/X509/Issued credential), the resolved
/// `policyId`, and the (empty) `userTokenSignature`. It never asserts merely "did not crash".
///
/// Fixture: a self-contained server (mirrors the ClientUsernamePassword fixture's PKI + strand-safe
/// request-observer interface) with:
///   - a SecurityPolicy None endpoint advertising a single ANONYMOUS `UserTokenPolicy` under the arbitrary
///     policyId "anon-1" (rows 1-3 connect here anonymously and succeed); and
///   - a Basic256Sha256 / SignAndEncrypt endpoint advertising only USERNAME + CERTIFICATE policies - NO
///     anonymous policy - for the no-matching-policy row (row 4).
///
/// The policyId "anon-1" is deliberately NOT the server's auto-generated format: a client that echoes it
/// back could only have read it from the endpoint, which is exactly the CL-IDENT-002 obligation ("the
/// client must not invent a policyId").

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_client_session.h"
#include "ua_crypto.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_user_identity.h"

#include "ua_activate_session_request.h"
#include "ua_anonymous_identity_token.h"
#include "ua_endpoint_description.h"
#include "ua_issued_identity_token.h"
#include "ua_signature_data.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_policy.h"
#include "ua_x509_identity_token.h"

#include "ua_message_security_mode.h"
#include "ua_security_policy.h"

#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

constexpr std::string_view noneUri = "http://opcfoundation.org/UA/SecurityPolicy#None";

// Policy ids the fixture advertises. "anon-1" is deliberately NOT the server's auto-generated
// "UserTokenPolicyId:<type>:<policy>" format, so a client that echoes it back proves it read the value from
// the endpoint rather than fabricating it (CL-IDENT-002: "the client must not invent a policyId").
constexpr std::string_view anonPolicyId = "anon-1";
constexpr std::string_view userPolicyId = "user-1";
constexpr std::string_view certPolicyId = "cert-1";

std::string policy_uri(SecurityPolicyId id)
{
  return std::string{SecurityPolicy::create(id)->uri()};
}

// Build a UserTokenPolicy with an explicit token type, policy id, and effective security policy URI.
UserTokenPolicy make_token_policy(
  UserTokenType tokenType, std::string_view policyId, std::string_view securityPolicyUri)
{
  UserTokenPolicy policy;
  policy.token_type() = tokenType;
  policy.policy_id() = std::string{policyId};
  policy.security_policy_uri() = std::string{securityPolicyUri};
  return policy;
}

// Server RSA key material, owned so the secured endpoint can complete its handshake.
struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial make_cert(
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

// A snapshot of the ActivateSession identity token the client actually put on the wire, captured on the
// server strand at the top of ActivateSession handling and read by the test thread.
struct CapturedActivate
{
  bool tokenPresent{false};
  bool isAnonymous{false};
  bool isUserName{false};
  bool isX509{false};
  bool isIssued{false};
  std::string policyId;
  std::string userTokenSignatureAlgorithm;
  ByteString userTokenSignature;
};

// Mutex-guarded observation co-owned by the fixture and the strand-side request observer. The server is
// drained before this is released (fixture destructor), so a late strand turn never touches dead state.
struct AnonObservation
{
  mutable std::mutex mutex;

  int activateRequestCount{0};
  CapturedActivate activate;

  void observe_activate(const ua::Structure& request)
  {
    const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
    if (!activateRequest)
      return;
    std::lock_guard lock(mutex);
    ++activateRequestCount;

    const ua::Structure* token = activateRequest->user_identity_token().get();
    activate.tokenPresent = (token != nullptr);
    activate.isAnonymous = (dynamic_cast<const ua::AnonymousIdentityToken*>(token) != nullptr);
    activate.isUserName = (dynamic_cast<const ua::UserNameIdentityToken*>(token) != nullptr);
    activate.isX509 = (dynamic_cast<const ua::X509IdentityToken*>(token) != nullptr);
    activate.isIssued = (dynamic_cast<const ua::IssuedIdentityToken*>(token) != nullptr);
    if (const auto* anon = dynamic_cast<const ua::AnonymousIdentityToken*>(token))
      activate.policyId = std::string{anon->policy_id()};

    activate.userTokenSignatureAlgorithm = std::string{activateRequest->user_token_signature().algorithm()};
    activate.userTokenSignature = activateRequest->user_token_signature().signature();
  }

  int activate_count() const
  {
    std::lock_guard lock(mutex);
    return activateRequestCount;
  }

  CapturedActivate captured() const
  {
    std::lock_guard lock(mutex);
    return activate;
  }
};

}  // namespace

// =============================================================================================
// Fixture: a server exposing a None/anonymous endpoint and a secured no-anonymous endpoint, plus the
// request-observer interface, and a client trusting that server.
// =============================================================================================
class ClientAnonymous : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mObservation = std::make_shared<AnonObservation>();

    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    mServerRsa = make_cert(mCrypto, "AnonServer RSA", "urn:test:anon:server");
    auto clientRsa = make_cert(mCrypto, "AnonClient RSA", "urn:test:anon:client");

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_anon_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    add_app_cert(mServerCertStore, mServerRsa);
    mServerCertStore->add_to_trusted_certificates_sync(clientRsa.cert);

    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    add_app_cert(mClientCertStore, clientRsa);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);

    auto appCfg = ua::test_utils::create_test_config();
    // Must match the SAN URI of the certificate this server presents. A discovery-driven connect performs
    // the CL-DISC-012 cross-check - the advertised ApplicationUri has to appear in the endpoint
    // certificate's SAN URIs - and refuses with Bad_CertificateUriInvalid when it does not. The default
    // configuration URI does not, so leaving it made every row here unreachable through the public facade
    // while the hand-built tier-0 path, which runs no discovery, never noticed.
    appCfg.application_description_part().applicationUri = "urn:test:anon:server";
    appCfg.allowInsecureEndpoints = true;

    ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString&) { return username == "alice"; }));
    components.authenticator = composite;
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

    mClient.emplace(make_client());
  }

  void TearDown() override
  {
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

  Client make_client()
  {
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:anon:client";
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    return Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning});
  }

  void add_endpoints()
  {
    // None endpoint: a single ANONYMOUS policy under the arbitrary policyId "anon-1" (rows 1-3).
    {
      ServerEndpointConfig ep;
      ep.name = "None_Anonymous";
      ep.messageSecurityMode = MessageSecurityMode::None;
      ep.securityPolicyId = SecurityPolicyId::None;
      ep.userIdentityTokens.push_back(make_token_policy(UserTokenType::Anonymous, anonPolicyId, noneUri));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // Basic256Sha256 / SignAndEncrypt endpoint: USERNAME + CERTIFICATE only - NO anonymous policy (row 4).
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_NoAnonymous";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(make_token_policy(
        UserTokenType::UserName, userPolicyId, policy_uri(SecurityPolicyId::Basic256Sha256)));
      ep.userIdentityTokens.push_back(make_token_policy(
        UserTokenType::Certificate, certPolicyId, policy_uri(SecurityPolicyId::Basic256Sha256)));
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
                { observation->observe_activate(request); });
            });
        });
  }

  // The outcome of one managed connect attempt.
  //
  // `reachedServer` is observed BY THE SERVER (an ActivateSession request arrived), which is the question a
  // client-side "the channel opened" bool was standing in for: at tier 1 the open, CreateSession and
  // activate are one operation, and where an attempt stopped is settled by what the far side saw plus the
  // ErrorDetail source naming the component that refused.
  struct ActivateOutcome
  {
    ua::VoidResult activate;
    bool reachedServer{false};
  };

  // Full managed connect + activate(anonymous) against the fixture.
  //
  // AGENTS.md: a client integration test drives the highest public production tier that exists - here
  // `Client::connect`, the public managed facade an application uses. @p policyId is left empty by every
  // row, which is the point: tier-0 auto-selects the endpoint's ANONYMOUS policy, and a row that supplied
  // the id could not tell whether it did.
  ActivateOutcome connect_anonymous(MessageSecurityMode mode, SecurityPolicyId policy, std::string policyId)
  {
    const int activatesBefore = mObservation->activate_count();

    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.endpointSelection = EndpointSelection::FirstMatching;
    config.securityMode = mode;
    config.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      config.serverCertificate = mServerRsa.cert;
    config.identity = AnonymousIdentity{};
    config.userTokenPolicyId = std::move(policyId);  // empty => tier-0 auto-selects the anonymous policy
    config.sessionName = "AnonTest";
    config.reconnect = std::nullopt;

    ActivateOutcome outcome;
    auto connectionResult = mClient->try_connect_sync(std::move(config));
    if (connectionResult.is_good())
    {
      outcome.activate = ua::VoidResult{};
      (void)std::move(connectionResult).value().try_close_sync();
    }
    else
    {
      outcome.activate = ua::VoidResult{connectionResult.status_code(), connectionResult.shared_detail()};
    }
    outcome.reachedServer = mObservation->activate_count() > activatesBefore;
    return outcome;
  }

  // True when any link of @p result's ErrorDetail chain was produced by @p source. The managed tier wraps a
  // tier-0 refusal, so the tag naming the component that refused is inside the chain, not at its head.
  static bool refused_by(const ua::VoidResult& result, std::string_view source)
  {
    for (const auto& link : ua::ErrorChainView{result.status_code()})
    {
      if (link.source == source)
        return true;
    }
    return false;
  }

  std::shared_ptr<const Crypto> mCrypto;
  KeyMaterial mServerRsa;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::shared_ptr<AnonObservation> mObservation;
};

// =============================================================================================
// Rows
// =============================================================================================

// @verifies CL-IDENT-001
// Configure AnonymousIdentity; the encoded userIdentityToken on the ActivateSession request is an explicit
// AnonymousIdentityToken extension object - never a UserName/X509/Issued credential. A non-anonymous
// credential in the anonymous case is the falsifier.
// @relation(CL-IDENT-001, scope=function)
TEST_F(ClientAnonymous, ActivateWithAnonymousIdentitySendsAnonymousToken)
{
  auto outcome = connect_anonymous(MessageSecurityMode::None, SecurityPolicyId::None, std::string{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "anonymous activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured();
  ASSERT_TRUE(captured.tokenPresent) << "no userIdentityToken observed on the wire";
  EXPECT_TRUE(captured.isAnonymous) << "the anonymous identity must be carried as an AnonymousIdentityToken";
  // Falsifier guards: never a non-anonymous credential.
  EXPECT_FALSE(captured.isUserName);
  EXPECT_FALSE(captured.isX509);
  EXPECT_FALSE(captured.isIssued);
}

// @verifies CL-IDENT-001
// [neg: no signature for anonymous] Same anonymous connect; the ActivateSession userTokenSignature is
// null/empty. A populated signature (algorithm or bytes) for an anonymous token would be non-conformant -
// only X509/issued tokens carry a UserTokenSignature.
// @relation(CL-IDENT-001, scope=function)
TEST_F(ClientAnonymous, AnonymousActivateOmitsUserTokenSignature)
{
  auto outcome = connect_anonymous(MessageSecurityMode::None, SecurityPolicyId::None, std::string{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "anonymous activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured();
  ASSERT_TRUE(captured.isAnonymous);
  EXPECT_TRUE(captured.userTokenSignatureAlgorithm.empty())
    << "an anonymous token must not name a UserTokenSignature algorithm";
  EXPECT_TRUE(captured.userTokenSignature.empty())
    << "an anonymous token must not carry a UserTokenSignature";
}

// @verifies CL-IDENT-002
// Endpoint advertises an ANONYMOUS UserTokenPolicy with policyId "anon-1"; connect anonymously. The
// AnonymousIdentityToken.policyId equals "anon-1" from the endpoint. An invented or empty policyId is the
// falsifier. "anon-1" is not the server's auto-generated policyId format, so echoing it back proves the
// client resolved it from the endpoint's advertised UserTokenPolicy[] rather than fabricating it.
// @relation(CL-IDENT-002, scope=function)
TEST_F(ClientAnonymous, AnonymousTokenPolicyIdMatchesEndpoint)
{
  auto outcome = connect_anonymous(MessageSecurityMode::None, SecurityPolicyId::None, std::string{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "anonymous activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured();
  ASSERT_TRUE(captured.isAnonymous);
  EXPECT_EQ(captured.policyId, std::string{anonPolicyId})
    << "the AnonymousIdentityToken.policyId must echo the endpoint's advertised ANONYMOUS policyId";
}

// @verifies CL-IDENT-002
// [neg: no anonymous policy advertised] The secured endpoint advertises only USERNAME + CERTIFICATE
// policies; configure AnonymousIdentity. The client now fails fast LOCALLY (a pre-flight refusal in
// build_user_token) with Bad_IdentityTokenRejected - it does NOT send a doomed ActivateSession with an
// empty/invented policyId. This is the ratified "Open design question" resolution (CL-IDENT-002):
// a client-side fail-fast naming the missing ANONYMOUS policy.
// @relation(CL-IDENT-002, scope=function)
TEST_F(ClientAnonymous, AnonymousNoMatchingPolicyFailsFast)
{
  auto outcome =
    connect_anonymous(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, std::string{});

  ASSERT_TRUE(outcome.activate.is_bad()) << "anonymous activation against a no-anonymous endpoint must fail";
  EXPECT_EQ(outcome.activate.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_NE(outcome.activate.shared_detail(), nullptr)
    << "the identity-token rejection must be diagnosable (ErrorDetail is priority #1)";

  // BUILT (CL-IDENT-002): a LOCAL client-side pre-flight refusal - the token-builder detail is surfaced
  // through the managed tier, NOT a server-deferred ServiceFault. The secured channel itself is valid, so a
  // refusal sourced anywhere but the token builder would mean this row passed for the wrong reason.
  EXPECT_TRUE(refused_by(outcome.activate, "client.tier0.token_builder.no_anonymous_policy"))
    << "the rejection is a local pre-flight refusal naming the missing ANONYMOUS policy";

  // The required flip: a local fail-fast must NOT send ActivateSession (no doomed empty-policyId token on
  // the wire). This was `>= 1` (server-deferred) before the pre-flight was built.
  EXPECT_FALSE(outcome.reachedServer)
    << "a local fail-fast must not send ActivateSession - the client refuses before any wire traffic";
}
