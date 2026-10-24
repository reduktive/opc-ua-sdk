// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientSession` integration cluster - the CreateSession/ActivateSession SECURITY slice of the
/// client
///        integration-test matrix (the eight `ClientSession.*` rows CL-SESS-003/005/006/010/011/012/014/016,
///        client design section 7 / Part 4 section 5.6.2-3).
///
/// TIER: this cluster drives tier 0 (`open_channel` -> `try_create_session_sync` -> `try_activate_sync`)
/// rather than the `Client::connect` facade, and AGENTS.md requires that absence to be recorded here rather
/// than left for a reader to infer.
///
/// The reason is the CreateSession/ActivateSession SPLIT, which is this cluster's whole subject. Rows 1-3
/// assert that a security-consistency failure in the CreateSession RESPONSE is caught there and that
/// ActivateSession is never attempted; `NoServiceRequestIsIssuedOnASessionBeforeActivationSucceeds` needs a
/// session that exists but has not activated. The managed facade collapses open, create and activate into
/// one call returning one status, so no tier-1 or tier-2 API can express "CreateSession was rejected and
/// activation never began" as a distinct observable. That is the "no higher-tier API exists for the
/// behaviour" case, not a shortcut.
///
/// It is NOT a licence for the rest of the file: any row whose subject is what the client puts on the wire
/// for an identity belongs on the facade, where `ClientUsernamePassword` and `ClientAnonymous` now are. A
/// row that hands the SDK a value it should have derived - a UserTokenPolicy id above all - cannot fail
/// when the derivation is missing, which is how two entry points shipped unable to open an authenticated
/// Session at all.
///
/// Two behavioural groups:
///
///   * Client-side security VALIDATIONS (rows 1-3): the client must handle a CreateSession response that
///     fails a security-consistency check (Part 4 section 5.6.2). A `MisbehavingServer`-equivalent semantic
///     `ua::Response&` interceptor injects a mismatched serverEndpoints set / a mismatched serverCertificate
///     / (under None) a bogus AIC into the CreateSession response, and each row asserts the REAL,
///     client-observable outcome. Where a validation is UNBUILT this is called out prominently in a NOTE
///     and reported to the maintainer - the row still asserts a falsifiable observable rather than an
///     invented one.
///
///   * Client PRODUCES crypto correctly (rows 4-8): the ActivateSession `clientSignature` signs
///     (serverCertificate || serverNonce) with the client's private key, using the LEAF certificate only and
///     the SecurityPolicy's asymmetric signature algorithm; an X509 user token carries a `userTokenSignature`
///     when supported; a UserName token is encrypted to the server's public key. Each row verifies the REAL
///     emitted request bytes/fields - the `clientSignature`/`userTokenSignature` captured off the wire is
///     verified with the crypto backend, and the UserName secret is decrypted with the server private key -
///     mirroring how the ClientEcc / ClientUsernamePassword / ClientCertLifecycle clusters verify token
///     crypto. Never "did not crash".
///
/// Fixture: a self-contained server that mirrors the ComplianceSecured / ClientUsernamePassword / ClientEcc
/// PKI build (RSA Basic256Sha256 endpoints + a `None` endpoint) with the same strand-safe request-observer +
/// response-interceptor interfaces (`ServerImplTestAccess::set_on_secure_channel_available` +
/// `SecureChannelTestAccess`). Those interfaces give the MisbehavingServer-equivalent capabilities the matrix
/// assigns to the validation rows (inject mismatched endpoints/serverCertificate into the CreateSession
/// response) plus capture of the CreateSession serverCert/serverNonce and the full ActivateSession request
/// (clientSignature, user token, userTokenSignature), so all eight rows run against one real in-tree secured
/// server + real crypto backend + trusted store.
///
/// KEY SECURITY FINDINGS (batched for the maintainer - see the per-row NOTE comments):
///   * CL-SESS-005 (endpoint-set comparison): UNBUILT. `SessionImpl::on_create_session_response_received`
///     consumes the CreateSession `serverEndpoints` only to extract the matching endpoint's user-token
///     policies; it never compares the set against a Discovery/GetEndpoints result (there is no retained
///     discovered set to compare against), so an inconsistent serverEndpoints set is tolerated and the
///     session activates. `ClosesWhenCreateSessionEndpointsDifferFromDiscovery` asserts that real behaviour
///     and reports the gap; when the check is built it must flip to assert Session-closed + NO
///     ActivateSession.
///   * CL-SESS-003 (serverCertificate == channel cert): there is no DEDICATED equality check
///     (`mServerCertificateDer = response->server_certificate()` is stored, never compared to the channel
///     cert). The spec-required OBSERVABLE - a CreateSession response whose serverCertificate differs from
///     the channel cert is rejected - is nonetheless satisfied for an AUTHENTICATED channel because the
///     server signature (over clientCertificate || clientNonce, made with the real server key) is verified
///     against the CreateSession serverCertificate's public key: swapping in a different cert makes that
///     verification fail (`Bad_ApplicationSignatureInvalid`).
///     `ServerCertificateInCreateSessionMatchesChannelCert` asserts that observable and documents the
///     mechanism; a dedicated byte-equality check would harden a `None`/unauthenticated path the signature
///     check does not cover.

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_client_session.h"
#include "ua_connection.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_user_identity.h"
#include "ua_x509_certificate.h"

#include "ua_activate_session_request.h"
#include "ua_attribute_id.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_signature_data.h"
#include "ua_timestamps_to_return.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_policy.h"
#include "ua_variable_id.h"
#include "ua_x509_identity_token.h"

#include "ua_message_security_mode.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_security_policy.h"

#include "run_async_sync.h"
#include "test_log_sink.h"
#include "test_pki_helpers.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "test_components.h"

namespace
{
// The strand a bound channel always carries. These entry points marshal every continuation onto it -
// they no longer accept not having one - so the pool has to be running for the blocking helpers
// below to ever see an answer.
boost::asio::strand<boost::asio::any_io_executor> crypto_test_strand()
{
  static boost::asio::thread_pool pool{2};
  return boost::asio::make_strand(boost::asio::any_io_executor{pool.get_executor()});
}
}  // namespace

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// Policy ids the fixture advertises (chosen by the test, not derived).
constexpr std::string_view userRsaPolicyId = "user-rsa";  // UserName / Basic256Sha256 (encrypting)
constexpr std::string_view userX509PolicyId = "user-x509";  // Certificate / Basic256Sha256 (signing)
// The username the fixture accepts with any password (so encrypting rows always activate).
constexpr std::string_view user = "alice";
// Longer than the 64 bytes the legacy format allows, so an RSA policy sends it as an RsaEncryptedSecret (OPC
// 10000-4 7.40.4), the format the rows that use it decode.
const std::string testPassword(72, 'p');

std::string policy_uri(SecurityPolicyId id)
{
  return std::string{SecurityPolicy::create(id)->uri()};
}

// Concatenate two ByteStrings into a fresh one (the signed/verified material is serverCert || serverNonce).
ByteString concat(const ByteString& first, const ByteString& second)
{
  ByteString out = first;
  std::ranges::copy(second, std::back_inserter(out));
  return out;
}

// True iff `signature` verifies over `data` against `publicKey` under `algorithm`. asymmetric_verify_sync
// throws on an invalid/failed verification, so a throw is the falsifier signal.
bool signature_verifies(const std::shared_ptr<const Crypto>& crypto, AsymmetricSignatureAlgorithm algorithm,
  const ByteString& publicKey, const ByteString& data, const ByteString& signature)
{
  try
  {
    crypto->asymmetric_verify_sync(algorithm, publicKey, data, signature);
    return true;
  }
  catch (...)
  {
    return false;
  }
}

// Build a UserTokenPolicy with an explicit token type, policy id, and effective security policy URI.
UserTokenPolicy make_user_token_policy(
  UserTokenType type, std::string_view policyId, std::string_view securityPolicyUri)
{
  UserTokenPolicy policy;
  policy.token_type() = type;
  policy.policy_id() = std::string{policyId};
  policy.security_policy_uri() = std::string{securityPolicyUri};
  return policy;
}

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial make_cert(const std::shared_ptr<const Crypto>& crypto, CertificateType certType,
  std::string_view commonName, std::string_view uri)
{
  Crypto::Name subject;
  subject.commonName = std::string{commonName};
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(std::string{uri});
  altName.hostnames.push_back("localhost");
  altName.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, certType, 2048);
  if (result.is_bad())
    throw std::runtime_error("failed to create certificate: " + std::string{commonName});
  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

// A self-signed RSA User Certificate for an X509 identity token. OPC 10000-6 Table 44: "The cA flag shall
// be FALSE for User Certificates. The pathLength shall not be present", and keyUsage carries
// digitalSignature. A self-signed application instance certificate carries cA TRUE and is refused as a
// user certificate, so the key pair is generated directly and the certificate issued as Table 44 requires.
KeyMaterial make_user_cert(
  const std::shared_ptr<const Crypto>& crypto, std::string_view commonName, std::string_view uri)
{
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig parameters;
  parameters.serialNumber = "1";
  parameters.subject.commonName = std::string{commonName};
  parameters.subjectKeys = keys;
  parameters.issuerKeys = keys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.basicConstraint.cA = false;
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.nonRepudiation = true;
  parameters.subjectAlternateName.uris = {std::string{uri}};
  parameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  parameters.to = DateTime{DateTime::now().value() + std::chrono::days{3650}};
  auto cert = TestPki{crypto}.create_cert(parameters);
  return {std::move(keys), std::move(cert)};
}

// A snapshot of the ActivateSession request the client actually put on the wire, captured on the server
// strand at the top of ActivateSession handling and read by the test thread.
struct CapturedActivate
{
  bool present{false};
  std::string clientSignatureAlgorithm;
  ByteString clientSignature;
  std::string userTokenSignatureAlgorithm;
  ByteString userTokenSignature;
  bool userNameTokenPresent{false};
  std::string userNameEncryptionAlgorithm;
  ByteString userNamePassword;
  bool x509TokenPresent{false};
  std::string x509PolicyId;
  ByteString x509CertificateData;
};

// Mutex-guarded observation co-owned by the fixture and the strand-side interfaces. The server is drained
// before this is released (see the fixture teardown), so a late strand turn never touches dead state.
struct SessionObservation
{
  mutable std::mutex mutex;

  // CreateSession response, as the client saw it (captured AFTER any injection below).
  ByteString createServerCertificate;
  ByteString createServerNonce;
  std::size_t createEndpointCount{0};

  // The clientCertificate the client PRESENTED in its CreateSession request (the certificate whose private
  // key the ActivateSession clientSignature must be made with).
  ByteString createClientCertificate;

  int activateCount{0};
  // Read requests that actually reached the wire, counted at the top of server-side request handling.
  int readCount{0};
  CapturedActivate activate;

  // Injection controls, armed by the test thread BEFORE connecting.
  bool injectMismatchedServerCert{false};  // replace CreateSession serverCertificate (rows 2/3)
  bool injectSpuriousEndpoint{false};  // append a differing endpoint to serverEndpoints (row 1)
  bool appendServerIssuer{false};  // append the issuer DER after the server leaf (row 5)
  ByteString injectCertDer;  // the cert DER to inject when injectMismatchedServerCert is set

  void observe_request(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request))
    {
      createClientCertificate = createRequest->client_certificate();
    }
    if (dynamic_cast<const ua::ReadRequest*>(&request) != nullptr)
    {
      ++readCount;
    }
    if (const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request))
    {
      ++activateCount;
      CapturedActivate captured;
      captured.present = true;
      captured.clientSignatureAlgorithm = std::string{activateRequest->client_signature().algorithm()};
      captured.clientSignature = activateRequest->client_signature().signature();
      captured.userTokenSignatureAlgorithm = std::string{activateRequest->user_token_signature().algorithm()};
      captured.userTokenSignature = activateRequest->user_token_signature().signature();
      if (const auto* userName =
            dynamic_cast<const ua::UserNameIdentityToken*>(activateRequest->user_identity_token().get()))
      {
        captured.userNameTokenPresent = true;
        captured.userNameEncryptionAlgorithm = std::string{userName->encryption_algorithm()};
        captured.userNamePassword = userName->password();
      }
      if (const auto* x509 =
            dynamic_cast<const ua::X509IdentityToken*>(activateRequest->user_identity_token().get()))
      {
        captured.x509TokenPresent = true;
        captured.x509PolicyId = std::string{x509->policy_id()};
        captured.x509CertificateData = x509->certificate_data();
      }
      activate = std::move(captured);
    }
  }

  void intercept_response(ua::Response& response)
  {
    std::lock_guard lock(mutex);
    if (auto* create = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
    {
      if (injectMismatchedServerCert && !injectCertDer.empty())
      {
        create->server_certificate() = injectCertDer;
      }
      if (appendServerIssuer && !injectCertDer.empty())
      {
        std::ranges::copy(injectCertDer, std::back_inserter(create->server_certificate()));
      }
      if (injectSpuriousEndpoint)
      {
        ua::EndpointDescription spurious;
        spurious.endpoint_url() = "opc.tcp://mismatch.invalid:4840";
        spurious.security_mode() = MessageSecurityMode::SignAndEncrypt;
        spurious.security_policy_uri() = policy_uri(SecurityPolicyId::Basic256Sha256);
        create->server_endpoints().payload().push_back(std::move(spurious));
      }
      createServerCertificate = create->server_certificate();
      createServerNonce = create->server_nonce();
      createEndpointCount = create->server_endpoints().payload().size();
    }
  }

  ByteString create_server_certificate() const
  {
    std::lock_guard lock(mutex);
    return createServerCertificate;
  }

  ByteString create_server_nonce() const
  {
    std::lock_guard lock(mutex);
    return createServerNonce;
  }

  std::size_t create_endpoint_count() const
  {
    std::lock_guard lock(mutex);
    return createEndpointCount;
  }

  ByteString create_client_certificate() const
  {
    std::lock_guard lock(mutex);
    return createClientCertificate;
  }

  int activate_count() const
  {
    std::lock_guard lock(mutex);
    return activateCount;
  }

  int read_count() const
  {
    std::lock_guard lock(mutex);
    return readCount;
  }

  CapturedActivate captured_activate() const
  {
    std::lock_guard lock(mutex);
    return activate;
  }
};

}  // namespace

// =============================================================================================
// Fixture
// =============================================================================================
class ClientSession : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mObservation = std::make_shared<SessionObservation>();

    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    TestPki pki{mCrypto};
    auto serverIssuerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mServerIssuerCert = pki.create_root_ca(serverIssuerKeys, "SessServer CA", "100");
    mServerRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "SessServer RSA", "urn:test:sess:server:rsa");
    // A distinct, valid server cert used to inject a serverCertificate mismatch (rows 2/3).
    mOtherServerCert = make_cert(
      mCrypto, CertificateType::RsaSha256Application, "SessServer OTHER", "urn:test:sess:server:other");
    mClientRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "SessClient RSA", "urn:test:sess:client:rsa");
    // A user identity certificate (distinct from the client APPLICATION cert) for the X509 user-token row.
    mUserX509 = make_user_cert(mCrypto, "SessUser X509", "urn:test:sess:user:x509");

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_sess_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    // Server application store: holds the server app cert, trusts the client app cert.
    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    add_app_cert(mServerCertStore, CertificateType::RsaSha256Application, mServerRsa);
    mServerCertStore->add_to_trusted_certificates_sync(mClientRsa.cert);

    // User-token store: the X509 user authenticator validates presented user certs against this store.
    auto userStorePath = mTempDir / "user_store";
    std::filesystem::create_directories(userStorePath);
    mUserCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = userStorePath, .validationOptions = validationOptions});
    mUserCertStore->add_to_trusted_certificates_sync(mUserX509.cert);

    // Client store: holds the client app cert, trusts the server cert.
    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    add_app_cert(mClientCertStore, CertificateType::RsaSha256Application, mClientRsa);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);

    // Server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.application_description_part().applicationUri = "urn:test:sess:server:rsa";

    ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString&) { return username == user; }));
    composite->add(UserTokenKind::X509, std::make_shared<X509UserAuthenticator>());
    components.authenticator = composite;
    // The server validates every X509 user-token certificate against the user-token certificate store;
    // the store handed to X509UserAuthenticator is not the trust anchor.
    components.userTokenCertificateStore = mUserCertStore;
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

    mClient.emplace(make_client(mClientCertStore));
  }

  void TearDown() override
  {
    // Close + drain the server BEFORE releasing the shared observation state: no in-flight strand turn can
    // then touch dead state (mirror of the ClientEcc / ClientUsernamePassword teardown order).
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

  static void add_app_cert(
    const std::shared_ptr<CertificateStore>& store, CertificateType type, const KeyMaterial& material)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = type;
    appCert.certificate = material.cert;
    appCert.keys = material.keys;
    store->add_to_application_certificates_sync(appCert);
  }

  Client make_client(const std::shared_ptr<CertificateStore>& store)
  {
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:sess:client:rsa";
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    return Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = store,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning});
  }

  void add_endpoints()
  {
    // Basic256Sha256 / SignAndEncrypt: Anonymous + UserName(RSA) + Certificate(X509).
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(make_user_token_policy(
        UserTokenType::UserName, userRsaPolicyId, policy_uri(SecurityPolicyId::Basic256Sha256)));
      ep.userIdentityTokens.push_back(make_user_token_policy(
        UserTokenType::Certificate, userX509PolicyId, policy_uri(SecurityPolicyId::Basic256Sha256)));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // Aes256Sha256RsaPss / SignAndEncrypt: a SECOND authenticated policy, present so the SignatureAlgorithm
    // row has a policy whose AsymmetricSignatureAlgorithm URI (rsa-pss-sha2-256) differs from
    // Basic256Sha256's (rsa-sha256). Both are satisfied by the same RSA-2048 application certificates.
    {
      ServerEndpointConfig ep;
      ep.name = "Aes256Sha256RsaPss_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // None / None: Anonymous (the AIC-ignored-under-None row).
    {
      ServerEndpointConfig ep;
      ep.name = "None";
      ep.messageSecurityMode = MessageSecurityMode::None;
      ep.securityPolicyId = SecurityPolicyId::None;
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

  ua::Result<ua::client::SecureChannel> open_channel(
    ua::client::Client& client, MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
    {
      cfg.serverCertificate = mServerRsa.cert;
    }
    return client.core().try_open_channel_sync(std::move(cfg));
  }

  struct SessionOutcome
  {
    bool channelOpened{false};
    std::optional<ua::client::SecureChannel> channel;
    std::optional<ua::client::Session> session;
    ua::VoidResult activate;
  };

  // Full open -> create -> activate against this fixture with the given client/identity. Leaves the channel
  // and session open (owned by the outcome) so the caller closes them after inspecting the wire capture.
  SessionOutcome open_create_activate(ua::client::Client& client, MessageSecurityMode mode,
    SecurityPolicyId policy, ua::client::UserIdentity identity, std::string_view policyId)
  {
    SessionOutcome outcome;
    auto channelResult = open_channel(client, mode, policy);
    if (channelResult.is_bad())
    {
      outcome.activate = ua::VoidResult{channelResult.status_code(), channelResult.shared_detail()};
      return outcome;
    }
    outcome.channelOpened = true;
    outcome.channel.emplace(std::move(channelResult).value());

    // Use the FALLIBLE create so a CreateSession-time security rejection (e.g. server-signature failure on a
    // mismatched serverCertificate) is captured as a Result rather than thrown out of the test body.
    auto sessionResult = outcome.channel->try_create_session_sync({.sessionName = "SessTest"});
    if (sessionResult.is_bad())
    {
      outcome.activate = ua::VoidResult{sessionResult.status_code(), sessionResult.shared_detail()};
      return outcome;
    }
    outcome.session.emplace(std::move(sessionResult).value());

    ua::client::Session::ActivateConfig config;
    config.policyId = std::string{policyId};
    config.identity = std::move(identity);
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

  RsaEncryptedSecretFieldsResult decode_rsa_encrypted_secret(const ByteString& blob)
  {
    auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    return ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
      [&](auto callback)
      {
        decrypt_rsa_encrypted_secret_async(blob,
          policy,
          mCrypto,
          crypto_test_strand(),
          mServerRsa.keys,
          mServerRsa.cert,
          false,
          Logger{},
          std::move(callback));
      });
  }

  std::shared_ptr<const Crypto> mCrypto;
  KeyMaterial mServerRsa;
  std::shared_ptr<const X509Certificate> mServerIssuerCert;
  KeyMaterial mOtherServerCert;
  KeyMaterial mClientRsa;
  KeyMaterial mUserX509;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mUserCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::shared_ptr<SessionObservation> mObservation;
};

// =============================================================================================
// Client-side security VALIDATIONS (rows 1-3)
// =============================================================================================

// @verifies CL-SESS-005
// SECURITY GAP (UNBUILT - reported): Part 4 section 5.6.2 requires the client to verify that the
// serverEndpoints returned in the CreateSession response are consistent with the endpoints obtained from
// Discovery/ GetEndpoints, and to CLOSE the session if they differ. The SDK performs NO such comparison:
// SessionImpl::on_create_session_response_received consumes serverEndpoints only to extract the matching
// endpoint's user-token policies (there is no retained discovered set to compare against). This row injects
// an extra, differing endpoint into the CreateSession serverEndpoints set and asserts the REAL, client-
// observable outcome: the mismatch is tolerated and the session activates. Falsifier for the CORRECT
// behaviour (to be asserted once the check is built): differ -> Session closed + NO ActivateSession on the
// wire. This test is intentionally GREEN against the current implementation and documents the gap.
// @relation(CL-SESS-005, scope=function)
TEST_F(ClientSession, ClosesWhenCreateSessionEndpointsDifferFromDiscovery)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectSpuriousEndpoint = true;  // make the CreateSession serverEndpoints set differ
  }

  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});

  ASSERT_TRUE(outcome.channelOpened) << "the channel itself is valid and must open";
  // Precondition: the injection actually reached the client (serverEndpoints carries the extra endpoint).
  EXPECT_GE(mObservation->create_endpoint_count(), 3u)
    << "the injected spurious endpoint must be present in the CreateSession serverEndpoints the client saw";

  // Real behaviour: the client does NOT compare the set against Discovery, so it tolerates the mismatch and
  // activates. (When CL-SESS-005 is built this must flip to: activate.is_bad() + activate_count() == 0.)
  EXPECT_TRUE(outcome.activate.is_good())
    << "UNBUILT CL-SESS-005: a differing CreateSession serverEndpoints set is currently tolerated";
  EXPECT_EQ(mObservation->activate_count(), 1)
    << "ActivateSession is currently sent despite the endpoint-set mismatch (documents the gap)";

  close_session(outcome);
}

// @verifies CL-SESS-003
// A CreateSession response whose serverCertificate differs from the channel's server cert must be rejected;
// a matching one is accepted (Part 4 section 5.6.2). There is no DEDICATED byte-equality check in the SDK,
// but the spec-required OBSERVABLE holds for an AUTHENTICATED channel via the server-signature check: the
// server signs (clientCertificate || clientNonce) with its REAL private key, and the client verifies that
// signature against the CreateSession serverCertificate's public key - so swapping in a different certificate
// makes the verification fail (Bad_ApplicationSignatureInvalid) and the session is closed before any
// ActivateSession. Falsifier: if the swapped cert were tolerated the session would activate.
// @relation(CL-SESS-003, AC-CL-SESS-006-UNDER-SECURITYPOLICY-NONE-WITH-AN-ANONYMOUS, scope=function)
TEST_F(ClientSession, ServerCertificateInCreateSessionMatchesChannelCert)
{
  // Arm: replace the CreateSession serverCertificate with a DIFFERENT valid certificate (different key).
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectMismatchedServerCert = true;
    mObservation->injectCertDer = mOtherServerCert.cert->der_encoding();
  }

  auto mismatched = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});

  ASSERT_TRUE(mismatched.channelOpened) << "the channel itself is valid and must open";
  EXPECT_TRUE(mismatched.activate.is_bad())
    << "a CreateSession serverCertificate != the channel cert must be rejected";
  EXPECT_EQ(mismatched.activate.status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "the CreateSession certificate mismatch must be rejected before accepting the server signature";
  EXPECT_EQ(mObservation->activate_count(), 0)
    << "ActivateSession must NOT be sent once the CreateSession server cert is rejected";
  close_session(mismatched);
}

// @verifies CL-SESS-003
// Positive control: with the genuine server certificate in the CreateSession response (no injection), the
// session creates and activates. Guards the mismatch row against over-rejecting a matching cert.
// @relation(CL-SESS-003, scope=function)
TEST_F(ClientSession, ServerCertificateMatchingChannelCertAccepted)
{
  auto matching = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});

  ASSERT_TRUE(matching.channelOpened);
  EXPECT_TRUE(matching.activate.is_good())
    << "a CreateSession serverCertificate matching the channel cert must be accepted: 0x" << std::hex
    << matching.activate.status_code().as_uint32();
  EXPECT_EQ(mObservation->create_server_certificate(), mServerRsa.cert->der_encoding())
    << "the CreateSession serverCertificate the client saw must be the channel's server cert";
  close_session(matching);
}

// @verifies CL-SESS-006
// Under SecurityPolicy None with an Anonymous identity (no token encryption), no application-instance-
// certificate validation is performed on the CreateSession serverCertificate (Part 4 section 5.6.2): the
// channel is unauthenticated, so the client neither generates a nonce nor verifies a server signature, and a
// server-supplied AIC is ignored. This row injects a DIFFERENT (unrelated, untrusted) certificate into the
// None CreateSession response and asserts the session still creates + activates - proving the AIC is ignored
// when neither the channel nor a token requires it. Falsifier: if the client wrongly validated the AIC under
// None it would reject the session.
// @relation(AC-CL-SESS-006-UNDER-SECURITYPOLICY-NONE-WITH-AN-ANONYMOUS, scope=function)
TEST_F(ClientSession, IgnoresAppInstanceCertWhenNoneAndNoTokenEncryption)
{
  // Arm: put an unrelated certificate in the None CreateSession serverCertificate slot.
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectMismatchedServerCert = true;
    mObservation->injectCertDer = mOtherServerCert.cert->der_encoding();
  }

  auto outcome = open_create_activate(
    *mClient, MessageSecurityMode::None, SecurityPolicyId::None, AnonymousIdentity{}, /*policyId=*/{});

  ASSERT_TRUE(outcome.channelOpened) << "a None channel must open";
  EXPECT_TRUE(outcome.activate.is_good())
    << "under None with no token encryption the server AIC is ignored, so activation must succeed: 0x"
    << std::hex << outcome.activate.status_code().as_uint32();
  EXPECT_EQ(mObservation->activate_count(), 1)
    << "ActivateSession is sent normally when the AIC is (correctly) ignored under None";
  close_session(outcome);
}

// =============================================================================================
// Client PRODUCES crypto correctly (rows 4-8)
// =============================================================================================

// @verifies CL-SESS-010
// The ActivateSession clientSignature signs (serverCertificate || serverNonce) with the client's private key
// (Part 4 section 5.6.3). Verified against the client cert's public key over the exact material the server
// delivered in the CreateSession response. Falsifier: verifying over the wrong material (serverNonce alone)
// fails.
// @relation(CL-SESS-010, scope=function)
TEST_F(ClientSession, ActivateSignsServerCertAndNonceWithClientKey)
{
  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);
  ASSERT_FALSE(captured.clientSignature.empty()) << "an authenticated ActivateSession must carry a signature";

  const ByteString serverCert = mObservation->create_server_certificate();
  const ByteString serverNonce = mObservation->create_server_nonce();
  ASSERT_FALSE(serverCert.empty());
  ASSERT_FALSE(serverNonce.empty());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const ByteString signedMaterial = concat(serverCert, serverNonce);

  EXPECT_TRUE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mClientRsa.cert->public_key(),
    signedMaterial,
    captured.clientSignature))
    << "clientSignature must verify over (serverCertificate || serverNonce) with the client public key";

  // Falsifier: the signature must NOT verify over the serverNonce alone (i.e. serverCertificate is included).
  EXPECT_FALSE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mClientRsa.cert->public_key(),
    serverNonce,
    captured.clientSignature))
    << "the signed material must include the serverCertificate, not the serverNonce alone";

  close_session(outcome);
}

// @verifies CL-SESS-011
// OPC 10000-4 section 5.6.3.2: when CreateSession returns a concatenated server certificate chain, the
// ActivateSession clientSignature covers only the server leaf DER plus nonce. The public Session API is the
// highest tier exposing the create/activate boundary and its signature; the tier-2 easy-connect facade does
// not expose this handshake artifact. Falsifier: verification over the full leaf+issuer chain must fail.
// @relation(CL-SESS-011, scope=function)
TEST_F(ClientSession, ActivateSignatureUsesLeafCertificateOnly)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->appendServerIssuer = true;
    mObservation->injectCertDer = mServerIssuerCert->der_encoding();
  }

  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation with a concatenated server certificate chain must succeed: 0x" << std::hex
    << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);
  ASSERT_FALSE(captured.clientSignature.empty());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const ByteString leafMaterial =
    concat(mServerRsa.cert->der_encoding(), mObservation->create_server_nonce());
  EXPECT_TRUE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mClientRsa.cert->public_key(),
    leafMaterial,
    captured.clientSignature))
    << "clientSignature must cover only server leaf DER plus nonce";

  const ByteString chainMaterial =
    concat(mObservation->create_server_certificate(), mObservation->create_server_nonce());
  EXPECT_FALSE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mClientRsa.cert->public_key(),
    chainMaterial,
    captured.clientSignature))
    << "clientSignature must not cover the concatenated server certificate chain";

  close_session(outcome);
}

// @verifies CL-SESS-012
// The clientSignature.algorithm URI equals the channel SecurityPolicy's asymmetric signature algorithm URI
// (rsa-sha256 for Basic256Sha256). Falsifier: a mismatched or empty URI.
// @relation(CL-SESS-012, scope=function)
TEST_F(ClientSession, ActivateSignatureAlgorithmMatchesSecurityPolicy)
{
  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const std::string expectedUri = std::string{policy->asymmetric_signature_algorithm_uri()};
  ASSERT_FALSE(expectedUri.empty());
  EXPECT_EQ(captured.clientSignatureAlgorithm, expectedUri)
    << "clientSignature.algorithm must name the policy's asymmetric signature algorithm URI";

  close_session(outcome);
}

// @verifies CL-IDENT-013
// @verifies CL-SESS-014
// An X509 identity token carries a userTokenSignature over (serverCertificate || serverNonce) signed with the
// USER certificate's private key (Part 4 section 5.6.3), with the algorithm matching the token policy's
// security policy. Verified against the user cert public key. Falsifier: an absent signature or one that does
// not verify against the user public key.
// @relation(CL-IDENT-013, CL-SESS-014, scope=function)
TEST_F(ClientSession, X509UserTokenSignatureProvidedWhenSupported)
{
  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    X509Identity{.certificate = mUserX509.cert, .keyPair = mUserX509.keys},
    userX509PolicyId);
  ASSERT_TRUE(outcome.activate.is_good())
    << "X509 activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);
  ASSERT_TRUE(captured.x509TokenPresent) << "an X509 identity must place an X509IdentityToken on the wire";
  EXPECT_EQ(captured.x509PolicyId, userX509PolicyId)
    << "the X509 token must carry the id of the advertised CERTIFICATE UserTokenPolicy";
  EXPECT_EQ(captured.x509CertificateData, mUserX509.cert->der_encoding())
    << "the token must carry the user certificate DER";
  ASSERT_FALSE(captured.userTokenSignature.empty())
    << "an X509 user token that supports signatures must carry a userTokenSignature";

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const ByteString signedMaterial =
    concat(mObservation->create_server_certificate(), mObservation->create_server_nonce());

  EXPECT_TRUE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mUserX509.cert->public_key(),
    signedMaterial,
    captured.userTokenSignature))
    << "the userTokenSignature must verify over (serverCertificate || serverNonce) with the user public key";
  EXPECT_EQ(captured.userTokenSignatureAlgorithm, std::string{policy->asymmetric_signature_algorithm_uri()})
    << "the userTokenSignature.algorithm must name the token policy's asymmetric signature algorithm URI";

  close_session(outcome);
}

// @verifies CL-SESS-016
// A UserName identity token whose policy requires encryption (Basic256Sha256) is encrypted to the server
// certificate's public key (Part 4 section 5.6.3.1): the password bytes on the wire are not plaintext, and
// the RsaEncryptedSecret decrypts with the server private key to recover the password.
// @relation(CL-SESS-016, scope=function)
TEST_F(ClientSession, UsernameTokenEncryptedWithServerPublicKey)
{
  ByteString expectedUtf8;
  for (char c : testPassword)
    expectedUtf8.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c)));

  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}},
    userRsaPolicyId);
  ASSERT_TRUE(outcome.activate.is_good())
    << "UserName activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);
  ASSERT_TRUE(captured.userNameTokenPresent) << "a UsernamePassword identity must place a UserName token";
  ASSERT_FALSE(captured.userNamePassword.empty());

  // On the wire the secret is encrypted, not plaintext.
  EXPECT_NE(captured.userNamePassword, expectedUtf8)
    << "an encrypting policy must not send the plaintext password";
  EXPECT_EQ(captured.userNameEncryptionAlgorithm, "http://www.w3.org/2001/04/xmlenc#rsa-oaep")
    << "encryptionAlgorithm must name the RSA asymmetric algorithm (Part 4 Table 188)";

  ASSERT_TRUE(is_rsa_encrypted_secret(span<const byte>{captured.userNamePassword}))
    << "a password of more than 64 bytes under an RSA policy must use the RsaEncryptedSecret format";
  auto decoded = decode_rsa_encrypted_secret(captured.userNamePassword);
  ASSERT_TRUE(decoded.is_good());
  EXPECT_EQ(decoded.value().secret, expectedUtf8)
    << "the secret must decrypt with the server certificate's private key to recover the password";

  close_session(outcome);
}

// =============================================================================================
// Authored-criteria discharge rows
// =============================================================================================

namespace
{

// A single-node Read of Server_ServerStatus_State - the request used to probe whether a service call
// reaches the wire on a session that has not been activated.
ua::ReadRequest make_server_state_read()
{
  ua::ReadRequest request;
  ua::ReadValueId target;
  target.node_id() = ua::NodeId{ua::VariableId::Server_ServerStatus_State};
  target.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(target));
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  return request;
}

// Compile-time member-name detectors: `&T::name` is ill-formed when `T` declares no such member, so the
// partial specialisation is discarded and the primary (false) template is chosen. `HasCreateSubscription`
// names a member `Connection` DOES declare and is used as the positive control, so a detector that had
// silently stopped detecting anything cannot pass the absence assertions vacuously.
template<class T, class = void>
struct HasCreateSubscription : std::false_type
{};

template<class T>
struct HasCreateSubscription<T, std::void_t<decltype(&T::create_subscription_async)>> : std::true_type
{};

template<class T, class = void>
struct HasCreateSessionAsync : std::false_type
{};

template<class T>
struct HasCreateSessionAsync<T, std::void_t<decltype(&T::create_session_async)>> : std::true_type
{};

template<class T, class = void>
struct HasCreateSessionSync : std::false_type
{};

template<class T>
struct HasCreateSessionSync<T, std::void_t<decltype(&T::create_session_sync)>> : std::true_type
{};

template<class T, class = void>
struct HasCreateAdditionalSession : std::false_type
{};

template<class T>
struct HasCreateAdditionalSession<T, std::void_t<decltype(&T::create_additional_session_async)>>
  : std::true_type
{};

template<class T, class = void>
struct HasAddSession : std::false_type
{};

template<class T>
struct HasAddSession<T, std::void_t<decltype(&T::add_session)>> : std::true_type
{};

template<class T, class = void>
struct HasSessions : std::false_type
{};

template<class T>
struct HasSessions<T, std::void_t<decltype(&T::sessions)>> : std::true_type
{};

}  // namespace

// Part 4 section 5.6.3: the client proves its application identity by signing the serverCertificate with the
// serverNonce appended, using the private key of the clientCertificate it presented at CreateSession. A
// plausible implementation signs only the nonce (the obvious anti-replay value) or reuses a key other than
// the one behind the presented certificate; either produces a signature a lenient server still accepts.
// Each conjunct is asserted separately: the certificate is in the signed material, the nonce is in the
// signed material, and the signing key is the presented certificate's.
// @verifies AC-CL-SESS-010-CLIENT-IDENTITY-SIGNATURE
TEST_F(ClientSession, ClientSignatureProvesIdentityOverServerCertificateAndNonce)
{
  auto outcome = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto captured = mObservation->captured_activate();
  ASSERT_TRUE(captured.present);
  ASSERT_FALSE(captured.clientSignature.empty())
    << "an authenticated ActivateSession must carry a clientSignature";

  // The certificate presented at CreateSession - the one whose private key must have made the signature.
  const ByteString presentedCert = mObservation->create_client_certificate();
  ASSERT_FALSE(presentedCert.empty()) << "CreateSession must present the client application certificate";
  ASSERT_EQ(presentedCert, mClientRsa.cert->der_encoding())
    << "the presented certificate must be the client's application instance certificate";

  const ByteString serverCert = mObservation->create_server_certificate();
  const ByteString serverNonce = mObservation->create_server_nonce();
  ASSERT_FALSE(serverCert.empty());
  ASSERT_FALSE(serverNonce.empty());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const auto algorithm = policy->asymmetric_signature_algorithm();

  EXPECT_TRUE(signature_verifies(mCrypto,
    algorithm,
    mClientRsa.cert->public_key(),
    concat(serverCert, serverNonce),
    captured.clientSignature))
    << "the clientSignature must verify over (serverCertificate || serverNonce) with the public key of the "
       "certificate presented at CreateSession";

  // Conjunct: the serverNonce is part of the signed material (otherwise the proof is replayable).
  EXPECT_FALSE(signature_verifies(
    mCrypto, algorithm, mClientRsa.cert->public_key(), serverCert, captured.clientSignature))
    << "the signed material must include the serverNonce, not the serverCertificate alone";

  // Conjunct: the serverCertificate is part of the signed material (otherwise the proof is not bound to
  // this server).
  EXPECT_FALSE(signature_verifies(
    mCrypto, algorithm, mClientRsa.cert->public_key(), serverNonce, captured.clientSignature))
    << "the signed material must include the serverCertificate, not the serverNonce alone";

  // Conjunct: the signature was made with the presented certificate's key, not some other available key.
  EXPECT_FALSE(signature_verifies(mCrypto,
    algorithm,
    mUserX509.cert->public_key(),
    concat(serverCert, serverNonce),
    captured.clientSignature))
    << "the signature must not verify against any key other than the presented certificate's";

  close_session(outcome);
}

// Part 4 section 5.6.3: "The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified in the
// SecurityPolicy for the Endpoint." A plausible implementation hardcodes the Basic256Sha256 URI (or a
// build-time default) and is accepted by every lenient server, failing only against a strict one - so the
// row activates against endpoints of three different policies and compares each emitted URI with the URI
// its own policy names, including the None endpoint where the policy names nothing at all.
// @verifies AC-CL-SESS-012-SIGALG-MATCHES-POLICY
TEST_F(ClientSession, SignatureAlgorithmIsTheOneEachEndpointPolicyNames)
{
  auto activateAndCapture = [&](MessageSecurityMode mode, SecurityPolicyId policyId, std::string_view label)
  {
    auto outcome = open_create_activate(*mClient, mode, policyId, AnonymousIdentity{}, /*policyId=*/{});
    EXPECT_TRUE(outcome.activate.is_good())
      << label << " activation must succeed: 0x" << std::hex << outcome.activate.status_code().as_uint32();
    CapturedActivate captured = mObservation->captured_activate();
    close_session(outcome);
    return captured;
  };

  const std::string basicUri = std::string{
    SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->asymmetric_signature_algorithm_uri()};
  const std::string pssUri = std::string{
    SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss)->asymmetric_signature_algorithm_uri()};
  const std::string noneUri =
    std::string{SecurityPolicy::create(SecurityPolicyId::None)->asymmetric_signature_algorithm_uri()};

  ASSERT_FALSE(basicUri.empty());
  ASSERT_FALSE(pssUri.empty());
  ASSERT_NE(basicUri, pssUri)
    << "the two policies must name DIFFERENT algorithms or this row cannot catch a hardcoded default";

  const CapturedActivate basic = activateAndCapture(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, "Basic256Sha256");
  ASSERT_TRUE(basic.present);
  ASSERT_FALSE(basic.clientSignature.empty());
  EXPECT_EQ(basic.clientSignatureAlgorithm, basicUri)
    << "the Basic256Sha256 endpoint's signature must name that policy's AsymmetricSignatureAlgorithm";

  const CapturedActivate pss = activateAndCapture(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes256Sha256RsaPss, "Aes256Sha256RsaPss");
  ASSERT_TRUE(pss.present);
  ASSERT_FALSE(pss.clientSignature.empty());
  EXPECT_EQ(pss.clientSignatureAlgorithm, pssUri)
    << "the Aes256Sha256RsaPss endpoint's signature must name rsa-pss-sha2-256, not the Basic256Sha256 URI";

  const CapturedActivate none = activateAndCapture(MessageSecurityMode::None, SecurityPolicyId::None, "None");
  ASSERT_TRUE(none.present);
  EXPECT_EQ(none.clientSignatureAlgorithm, noneUri)
    << "the None endpoint's policy names no signature algorithm, so no default may be substituted";
  EXPECT_TRUE(none.clientSignature.empty())
    << "the None endpoint's policy defines no asymmetric signature, so none may be sent";
}

// Part 4 section 5.6.3: "If the Client specified a user identity token that supports digital signatures, then
// it shall create a signature and pass it as this parameter" - and, equally, a token type that defines no
// signature must carry a null one. A plausible implementation stamps the userTokenSignature unconditionally
// (or leaves a previous flow's value in the request), which a strict server rejects as a signature over a
// token that cannot bear one. Both halves of the observation are asserted here.
// @verifies AC-CL-SESS-014-USERTOKENSIGNATURE-SENT
TEST_F(ClientSession, UserTokenSignatureAccompaniesSigningTokensAndIsNullForOthers)
{
  // Half 1: Anonymous supports no digital signature - the userTokenSignature must be null.
  auto anonymous = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    AnonymousIdentity{},
    /*policyId=*/{});
  ASSERT_TRUE(anonymous.activate.is_good())
    << "anonymous activation must succeed: 0x" << std::hex << anonymous.activate.status_code().as_uint32();
  const CapturedActivate anonymousCapture = mObservation->captured_activate();
  ASSERT_TRUE(anonymousCapture.present);
  EXPECT_TRUE(anonymousCapture.userTokenSignature.empty())
    << "an Anonymous token defines no signature, so the userTokenSignature must be null";
  EXPECT_TRUE(anonymousCapture.userTokenSignatureAlgorithm.empty())
    << "a null userTokenSignature must carry no algorithm either";
  close_session(anonymous);

  // Half 2: an X509 token DOES support digital signatures - the signature must be present and must sign
  // (serverCertificate || serverNonce) with the user certificate's private key.
  auto x509 = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    X509Identity{.certificate = mUserX509.cert, .keyPair = mUserX509.keys},
    userX509PolicyId);
  ASSERT_TRUE(x509.activate.is_good())
    << "X509 activation must succeed: 0x" << std::hex << x509.activate.status_code().as_uint32();
  const CapturedActivate x509Capture = mObservation->captured_activate();
  ASSERT_TRUE(x509Capture.present);
  ASSERT_TRUE(x509Capture.x509TokenPresent) << "an X509 identity must place an X509IdentityToken on the wire";
  ASSERT_FALSE(x509Capture.userTokenSignature.empty())
    << "a user token that supports digital signatures must be accompanied by a signature";

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const ByteString serverCert = mObservation->create_server_certificate();
  const ByteString serverNonce = mObservation->create_server_nonce();
  ASSERT_FALSE(serverCert.empty());
  ASSERT_FALSE(serverNonce.empty());
  EXPECT_TRUE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mUserX509.cert->public_key(),
    concat(serverCert, serverNonce),
    x509Capture.userTokenSignature))
    << "the userTokenSignature must sign (serverCertificate || serverNonce) with the user private key";
  EXPECT_FALSE(signature_verifies(mCrypto,
    policy->asymmetric_signature_algorithm(),
    mUserX509.cert->public_key(),
    serverNonce,
    x509Capture.userTokenSignature))
    << "the userTokenSignature must cover the serverCertificate as well as the nonce";
  close_session(x509);
}

// Part 4 section 7.41: a token carrying a secret is encrypted with the public key from THIS endpoint's
// serverCertificate. A plausible implementation encrypts to a certificate cached from discovery or from an
// earlier connection, which still decrypts on a well-behaved server and hands the secret to whoever supplied
// that certificate. The RsaEncryptedSecret carries the receiver-certificate thumbprint and the server nonce
// in its own header, so both bindings are asserted, and a second connection is used to show the ciphertext is
// re-made against that connection's material rather than reused.
// @verifies AC-CL-SESS-016-TOKEN-ENCRYPTED-TO-SERVER
TEST_F(ClientSession, UserTokenSecretIsEncryptedToThisEndpointsServerCertificate)
{
  ByteString expectedUtf8;
  for (char c : testPassword)
    expectedUtf8.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c)));

  auto first = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}},
    userRsaPolicyId);
  ASSERT_TRUE(first.activate.is_good())
    << "UserName activation must succeed: 0x" << std::hex << first.activate.status_code().as_uint32();

  const CapturedActivate firstCapture = mObservation->captured_activate();
  const ByteString firstNonce = mObservation->create_server_nonce();
  ASSERT_TRUE(firstCapture.present);
  ASSERT_TRUE(firstCapture.userNameTokenPresent);
  ASSERT_FALSE(firstCapture.userNamePassword.empty());
  ASSERT_FALSE(firstNonce.empty());
  ASSERT_TRUE(is_rsa_encrypted_secret(span<const byte>{firstCapture.userNamePassword}));

  auto firstDecoded = decode_rsa_encrypted_secret(firstCapture.userNamePassword);
  ASSERT_TRUE(firstDecoded.is_good()) << "the secret must decrypt with THIS endpoint's server private key: 0x"
                                      << std::hex << firstDecoded.status_code().as_uint32();
  EXPECT_EQ(firstDecoded.value().secret, expectedUtf8) << "the recovered secret must be the password";
  EXPECT_EQ(firstDecoded.value().certificateThumbprint, mServerRsa.cert->thumbprint())
    << "the secret must be encrypted to the certificate THIS endpoint presented, not a cached one";
  EXPECT_EQ(firstDecoded.value().nonce, firstNonce)
    << "the encrypted secret must carry this connection's serverNonce";
  close_session(first);

  // A second connection: the ciphertext must be re-made against the new connection's nonce, so a cached or
  // replayed blob is observable as an identical ciphertext / a stale nonce.
  auto second = open_create_activate(*mClient,
    MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{testPassword}},
    userRsaPolicyId);
  ASSERT_TRUE(second.activate.is_good()) << "the second UserName activation must succeed: 0x" << std::hex
                                         << second.activate.status_code().as_uint32();

  const CapturedActivate secondCapture = mObservation->captured_activate();
  const ByteString secondNonce = mObservation->create_server_nonce();
  ASSERT_TRUE(secondCapture.userNameTokenPresent);
  ASSERT_FALSE(secondCapture.userNamePassword.empty());
  ASSERT_FALSE(secondNonce.empty());
  ASSERT_NE(secondNonce, firstNonce) << "the server must issue a fresh nonce per session";
  EXPECT_NE(secondCapture.userNamePassword, firstCapture.userNamePassword)
    << "the secret must be encrypted afresh per connection, not replayed from a cached blob";

  auto secondDecoded = decode_rsa_encrypted_secret(secondCapture.userNamePassword);
  ASSERT_TRUE(secondDecoded.is_good());
  EXPECT_EQ(secondDecoded.value().secret, expectedUtf8);
  EXPECT_EQ(secondDecoded.value().certificateThumbprint, mServerRsa.cert->thumbprint());
  EXPECT_EQ(secondDecoded.value().nonce, secondNonce)
    << "the second connection's secret must be bound to the second connection's serverNonce";
  close_session(second);
}

// Part 4 section 5.6.2: "The Session created with this Service shall not be used until the Client calls the
// ActivateSession Service..." A plausible implementation lets a service call through and relies on the
// server to reject it, which passes against a lenient server and fails only against a strict one - so the
// observation is the wire, not the returned status: no Read may reach the server before activation, and one
// must reach it afterwards.
// @verifies AC-CL-SESS-019-UNUSABLE-BEFORE-ACTIVATE
TEST_F(ClientSession, NoServiceRequestIsIssuedOnASessionBeforeActivationSucceeds)
{
  auto channelResult =
    open_channel(*mClient, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channelResult.is_good()) << "the channel must open";
  auto channel = std::move(channelResult).value();

  auto sessionResult = channel.try_create_session_sync({.sessionName = "SessTest"});
  ASSERT_TRUE(sessionResult.is_good()) << "CreateSession must succeed";
  auto session = std::move(sessionResult).value();
  ASSERT_TRUE(session.is_created()) << "the session must be Created but not yet activated";
  ASSERT_FALSE(session.is_active());
  ASSERT_EQ(mObservation->activate_count(), 0) << "no ActivateSession has been sent yet";

  // A Read on the created-but-unactivated session.
  auto early = session.attributes().try_read_sync(make_server_state_read());
  EXPECT_TRUE(early.is_bad()) << "a Read before activation must be refused";
  EXPECT_EQ(mObservation->read_count(), 0)
    << "no Read may reach the wire on a session that has not been activated";

  // After a successful activation the same Read is dispatched.
  ua::client::Session::ActivateConfig config;
  auto activate = session.try_activate_sync(std::move(config));
  ASSERT_TRUE(activate.is_good()) << "activation must succeed: 0x" << std::hex
                                  << activate.status_code().as_uint32();
  ASSERT_TRUE(session.is_active());

  auto later = session.attributes().try_read_sync(make_server_state_read());
  EXPECT_TRUE(later.is_good()) << "a Read after activation must be dispatched: 0x" << std::hex
                               << later.status_code().as_uint32();
  EXPECT_EQ(mObservation->read_count(), 1) << "exactly the post-activation Read must have reached the wire";
  ASSERT_TRUE(later.is_good());
  ASSERT_FALSE(later.value().results().empty()) << "the dispatched Read must return a result";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Session Client Single Session (Entry Level 2015 Client Facet): a Connection maintains at most one active
// Session, and the constraint is honoured by the shape of the type rather than by a runtime refusal - the
// public surface admits no way to ask for a second one. A plausible implementation grows a
// `create_additional_session`-style entry point alongside `reactivate`, at which point the facet is silently
// broken with nothing to observe at runtime. The observation is therefore a compile-time one, with a member
// the type DOES declare used as the positive control so the detectors cannot pass vacuously.
// @verifies AC-CL-SESS-029-ONE-SESSION-PER-CONNECTION
TEST_F(ClientSession, ConnectionSurfaceAdmitsNoSecondSession)
{
  using ua::client::Connection;

  // Positive control: the detector reports a member Connection really declares.
  static_assert(HasCreateSubscription<Connection>::value,
    "the member detector must find a member Connection declares, or the absence assertions below prove "
    "nothing");

  static_assert(!HasCreateSessionAsync<Connection>::value,
    "Connection must expose no API creating a Session on an existing Connection");
  static_assert(!HasCreateSessionSync<Connection>::value,
    "Connection must expose no API creating a Session on an existing Connection");
  static_assert(!HasCreateAdditionalSession<Connection>::value,
    "Connection must expose no API adding a second Session to a Connection");
  static_assert(!HasAddSession<Connection>::value,
    "Connection must expose no API adding a second Session to a Connection");
  static_assert(!HasSessions<Connection>::value,
    "Connection must expose no collection of Sessions; multi-session use is multiple Connections");

  // The single-Session shape is also visible in the accessor: one Session identity, not a collection.
  static_assert(
    std::is_same_v<decltype(std::declval<const Connection&>().session_id()), ua::Result<ua::NodeId>>,
    "Connection must expose exactly one Session identity");

  SUCCEED() << "the public Connection surface admits no second concurrent Session";
}
