// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_security_policy.h"
#include "ua_server_configuration.h"
#include "ua_server_impl.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_service_fault.h"
#include "ua_server_secure_channel_info.h"
#include "ua_stack_utilities.h"
#include "ua_signature_data.h"

#include "ua_crypto.h"
#include "ua_certificate_store_files.h"

// Test-only access to SecureChannel interfaces/state without exposing them publicly.
#include "ua_server_secure_channel_test_access.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <condition_variable>
#include <filesystem>
#include <future>
#include <mutex>

#include "test_components.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
using namespace ua;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

struct CryptoFixture
{
  shared_ptr<const Crypto> crypto;
  shared_ptr<const AsymmetricKeyPair> serverKeys;
  shared_ptr<const X509Certificate> serverCert;
  shared_ptr<CertificateStore> certStore;
  std::filesystem::path tempDir;

  /// @param issuerChain The own certificate's issuer chain (decision 24, ApplicationCertificate::
  ///        mIssuerCertificates); empty for the historical leaf-only fixture.
  explicit CryptoFixture(
    boost::asio::any_io_executor ex, std::vector<shared_ptr<const X509Certificate>> issuerChain = {})
  {
    crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    // Create a self-signed application instance certificate.
    Crypto::Name subject;
    subject.commonName = "Test Server";
    UtcTime expiry{2050, 1, 1, 0, 0, 0};
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:server");

    auto certResult = crypto->try_create_self_signed_application_instance_certificate_sync(
      subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
    if (certResult.is_bad())
      throw std::runtime_error("Failed to create self-signed certificate");
    auto [keys, cert] = std::move(certResult).value();
    serverKeys = std::move(keys);
    serverCert = std::move(cert);

    // Create a temporary cert store and seed it with the server certificate.
    tempDir = std::filesystem::temp_directory_path() / ("ua_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(tempDir);

    TrustListValidationOptions validationOptions;
    certStore = CertificateStoreFiles::create(
      ex, crypto, {.trustListPath = tempDir, .validationOptions = validationOptions});

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = serverCert;
    appCert.keys = serverKeys;
    appCert.issuerCertificates = std::move(issuerChain);
    certStore->add_to_application_certificates_sync(appCert);
  }

  ~CryptoFixture()
  {
    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
  }
};

shared_ptr<ServerImpl> create_test_server_with_authenticated_endpoint(
  boost::asio::any_io_executor ex, shared_ptr<const Crypto> crypto, shared_ptr<CertificateStore> certStore)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    // Unauthenticated endpoint (None).
    ua::server::ServerEndpointConfig epNone;
    epNone.name = "None";
    epNone.messageSecurityMode = ua::MessageSecurityMode::None;
    epNone.securityPolicyId = ua::SecurityPolicyId::None;
    epNone.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(epNone));

    // Authenticated endpoint (Basic256Sha256 / Sign).
    ua::server::ServerEndpointConfig epAuth;
    epAuth.name = "Basic256Sha256_Sign";
    epAuth.messageSecurityMode = ua::MessageSecurityMode::Sign;
    epAuth.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    epAuth.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(epAuth));

    sc.listeners().push_back(std::move(listener));
  }

  sc.validate();
  frozen.server = std::move(sc);

  auto server = ua::server::ServerImpl::create(ex,
    std::move(frozen),
    ua::server::ServerComponents{
      .crypto = std::move(crypto), .applicationGroupCertificateStore = std::move(certStore)});
  TestAccess{*server}.initialise_listeners_from_config();
  return server;
}

struct AuthenticatedScHarness
{
  boost::asio::thread_pool threadPool;
  boost::asio::any_io_executor executor;
  std::unique_ptr<CryptoFixture> cryptoFixture;

  shared_ptr<ServerImpl> server;
  weak_ptr<SecureChannelDependencies> deps;
  shared_ptr<SecureChannel> sc;

  std::mutex mx;
  std::condition_variable cv;
  std::vector<Response> responses;

  void wait_for_responses(size_t count, std::chrono::seconds timeout = 10s)
  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, timeout, [&]() { return responses.size() >= count; }));
  }

  void shutdown()
  {
    if (sc)
      sc->close();
    if (server)
    {
      std::promise<VoidResult> p;
      server->shutdown_async({}, [&p](VoidResult r) { p.set_value(std::move(r)); });
      p.get_future().get();
    }
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
};

std::unique_ptr<AuthenticatedScHarness> create_authenticated_harness(
  std::vector<shared_ptr<const X509Certificate>> serverIssuerChain = {})
{
  auto h = std::make_unique<AuthenticatedScHarness>();
  h->executor = h->threadPool.get_executor();

  h->cryptoFixture = std::make_unique<CryptoFixture>(h->executor, std::move(serverIssuerChain));

  h->server = create_test_server_with_authenticated_endpoint(
    h->executor, h->cryptoFixture->crypto, h->cryptoFixture->certStore);
  h->deps = TestAccess{*h->server}.secure_channel_dependencies();

  h->sc = ua::server::SecureChannel::create(
    h->deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");

  TestAccess{*h->server}.add_secure_channel(h->sc);

  // Set up the secure channel with Basic256Sha256 security policy.
  SecureChannelTestAccess::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_minimal_context_authenticated(h->executor,
        "TestListener/Basic256Sha256_Sign",
        SecurityPolicyId::Basic256Sha256,
        MessageSecurityMode::Sign);
    });
  SCTA::on_strand(*h->sc, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });

  // Wire response sink.
  SCTA::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&h = *h](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lk(h.mx);
            h.responses.push_back(r);
          }
          h.cv.notify_one();
        });
    });

  return h;
}

}  // namespace

// P4-SS-0016: Server shall prove possession by signing the client nonce with its private key.
// P4-SS-0022: SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm from the SecurityPolicy.
// @relation(SVR-SESS-016, scope=function)
TEST(ServerSignatureTests, CreateSessionResponseContainsValidServerSignature)
{
  auto h = create_authenticated_harness();

  // Generate a 32-byte client nonce.
  auto clientNonce = h->cryptoFixture->crypto->get_entropy_sync(32);
  ASSERT_EQ(clientNonce.size(), 32u);

  // Create a client certificate (needed because server signs clientCert || clientNonce).
  Crypto::Name clientSubject;
  clientSubject.commonName = "Test Client";
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName clientAltName;
  clientAltName.uris.push_back("urn:test:client");
  auto clientCertResult =
    h->cryptoFixture->crypto->try_create_self_signed_application_instance_certificate_sync(
      clientSubject, expiry, clientAltName, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(clientCertResult.is_good());
  auto [clientKeys, clientCert] = std::move(clientCertResult).value();

  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  req.session_name() = "test";
  req.client_description().application_uri() = "urn:test:client";
  req.client_description().application_name().text() = "client";
  req.client_nonce() = clientNonce;
  req.client_certificate() = clientCert->der_encoding();

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/Basic256Sha256_Sign",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    clientCert);
  TestAccess{*h->server}.create_session(info, 100, std::move(req));

  h->wait_for_responses(1);

  auto* resp = dynamic_cast<CreateSessionResponse*>(h->responses.back().second.get());
  ASSERT_NE(resp, nullptr) << "Expected CreateSessionResponse, got ServiceFault or other";

  // P4-SS-0022: Algorithm must match the policy's asymmetric signature algorithm URI.
  EXPECT_EQ(resp->server_signature().algorithm(), policy->asymmetric_signature_algorithm_uri());

  // P4-SS-0016: Signature must be non-empty.
  EXPECT_FALSE(resp->server_signature().signature().empty());

  // Verify the signature: data = clientCertificate(DER) || clientNonce.
  ByteString dataToVerify = clientCert->der_encoding();
  std::ranges::copy(clientNonce, std::back_inserter(dataToVerify));

  EXPECT_NO_THROW(h->cryptoFixture->crypto->asymmetric_verify_sync(policy->asymmetric_signature_algorithm(),
    h->cryptoFixture->serverKeys->public_key_der(),
    dataToVerify,
    resp->server_signature().signature()));

  // Server certificate should also be present in the response.
  EXPECT_FALSE(resp->server_certificate().empty());

  h->shutdown();
}

// Negative: SecurityPolicy::None should not produce a server signature.
// @relation(SVR-SESS-016, scope=function)
TEST(ServerSignatureTests, NoServerSignatureOnUnauthenticatedPolicy)
{
  auto h = create_authenticated_harness();

  // Create a second secure channel with SecurityPolicy::None.
  auto scNone = ua::server::SecureChannel::create(
    h->deps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "TestListener");
  TestAccess{*h->server}.add_secure_channel(scNone);
  SecureChannelTestAccess::on_strand(
    *scNone, [&](auto& g) { g.set_minimal_context_none(h->executor, "TestListener/None"); });
  SCTA::on_strand(*scNone, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });

  SCTA::on_strand(*scNone,
    [&](auto& g)
    {
      g.set_response_sink(
        [&h = *h](const Response& r)
        {
          {
            std::lock_guard<std::mutex> lk(h.mx);
            h.responses.push_back(r);
          }
          h.cv.notify_one();
        });
    });

  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  req.session_name() = "test";
  req.client_description().application_name().text() = "client";
  // No client nonce for unauthenticated policy.

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  SecureChannelInfo info(scNone,
    policy,
    MessageSecurityMode::None,
    "TestListener/None",
    SCTA::on_strand(*scNone, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));
  TestAccess{*h->server}.create_session(info, 200, std::move(req));

  h->wait_for_responses(1);

  auto* resp = dynamic_cast<CreateSessionResponse*>(h->responses.back().second.get());
  ASSERT_NE(resp, nullptr) << "Expected CreateSessionResponse, got ServiceFault or other";

  // No signature on unauthenticated policy.
  EXPECT_TRUE(resp->server_signature().signature().empty());
  EXPECT_TRUE(resp->server_signature().algorithm().empty());
  EXPECT_TRUE(resp->server_certificate().empty());

  h->shutdown();
}

// Completeness review C2 (decision 24): the server sends its own chain - leaf then mIssuerCertificates in
// order (OPC 10000-6 6.2.6) - in CreateSessionResponse.serverCertificate and in every serverEndpoints entry's
// serverCertificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-81-SEND-OWN-CHAIN, scope=function)
TEST(ServerSignatureTests, CreateSessionServerCertificateIsTheLeafThenItsIssuers)
{
  // The issuer keys are loaded from cached PEM through Crypto::get_private_key_from_pem, which reads a PEM
  // private key with the credential callback's password and refuses an empty credential; the callback
  // therefore returns one (the PEM itself is unencrypted, so its value is not used).
  const auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  TestPki pki{crypto};
  const auto rootKeys = ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 70);
  const auto iaKeys = ::ua::test_keys::key_pair(*crypto, ::ua::test_keys::KeyType::Rsa2048, 71);
  const auto root = pki.create_root_ca(rootKeys, "Server Chain Root", "7100");
  const auto ia = pki.create_root_ca(iaKeys, "Server Chain IA", "7101");
  auto h = create_authenticated_harness({ia, root});

  auto clientNonce = h->cryptoFixture->crypto->get_entropy_sync(32);
  Crypto::Name clientSubject;
  clientSubject.commonName = "Chain Client";
  Crypto::SubjectAlternateName clientAltName;
  clientAltName.uris.push_back("urn:test:client");
  auto clientCertResult =
    h->cryptoFixture->crypto->try_create_self_signed_application_instance_certificate_sync(clientSubject,
      UtcTime{2050, 1, 1, 0, 0, 0},
      clientAltName,
      CertificateType::RsaSha256Application,
      2048);
  ASSERT_TRUE(clientCertResult.is_good());
  auto [clientKeys, clientCert] = std::move(clientCertResult).value();

  CreateSessionRequest req;
  req.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  req.session_name() = "chain";
  req.client_description().application_uri() = "urn:test:client";
  req.client_nonce() = clientNonce;
  req.client_certificate() = clientCert->der_encoding();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  SecureChannelInfo info(h->sc,
    policy,
    MessageSecurityMode::None,
    "TestListener/Basic256Sha256_Sign",
    SCTA::on_strand(*h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    clientCert);
  TestAccess{*h->server}.create_session(info, 101, std::move(req));
  h->wait_for_responses(1);

  auto* resp = dynamic_cast<CreateSessionResponse*>(h->responses.back().second.get());
  ASSERT_NE(resp, nullptr);
  ByteString expected = h->cryptoFixture->serverCert->der_encoding();
  for (const auto& issuer : {ia, root})
  {
    const auto der = issuer->der_encoding();
    std::ranges::copy(der, std::back_inserter(expected));
  }
  EXPECT_EQ(resp->server_certificate(), expected) << "leaf first, then mIssuerCertificates in order";
  for (const auto& endpoint : resp->server_endpoints())
  {
    if (endpoint.security_mode() != MessageSecurityMode::None)
    {
      EXPECT_EQ(endpoint.server_certificate(), expected) << "serverEndpoints carry the same chain";
    }
  }
  h->shutdown();
}
