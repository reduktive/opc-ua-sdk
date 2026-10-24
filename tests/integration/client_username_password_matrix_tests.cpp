// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `ClientUsernamePassword` integration cluster - the UsernamePasswordIdentity activation slice
///        of the client integration-test matrix.
///
/// Entry point under test: `Client::connect` with a `UsernamePasswordIdentity` - the highest public
/// production tier that covers activation (AGENTS.md), driven with `EndpointSelection::FirstMatching` so the
/// SDK runs its own GetEndpoints and selects the UserTokenPolicy the identity activates under. Rows that
/// need channel-level control the facade does not expose (a corrupted RSA padding, a hand-built
/// ActivateSession) drop to tier 0 through `open_channel`, and say so where they do. The tier-0
/// token builder (`build_user_token` -> `resolve_username_encryption`, Part 4 Table 193) constructs a
/// `ua::UserNameIdentityToken`, resolves the per-token encryption policy, and - for a non-empty password -
/// the session's encrypt pipeline (`encrypt_user_token_async`) fills in the on-wire password:
///   - RSA policy, a password of more than 64 UTF-8 bytes -> an `RsaEncryptedSecret` ExtensionObject (Part 4
///                    1.05.06 section 7.40.2.4; the format is chosen by length, whatever the policy, 7.40.4):
///                    RSA-OAEP-encrypted KeyData (SigningKey|EncryptingKey|IV) + AES-CBC-encrypted payload
///                    (Nonce|Secret) + trailing HMAC. The SDK server auto-detects it by the cleartext
///                    ExtensionObject TypeId and decodes it.
///   - RSA policy, a password of at most 64 bytes -> the LEGACY UserIdentityToken secret (section 7.40.2.2):
///                    `Length(4 LE) || UTF-8(password) || serverNonce`, asymmetric-encrypted into `password`
///                    (`parse_legacy_encrypted_token_secret`).
///                    In both RSA forms `encryptionAlgorithm` is the policy's AsymmetricEncryptionAlgorithm
///                    URI.
///   - ECC policy  -> an `EccEncryptedSecret` blob (Part 4 7.41.2.5) whose cleartext `KeyData` carries the
///                    server's ephemeral public key as `ReceiverPublicKey`.
///   - None policy -> the plaintext UTF-8 password (only legal when the CHANNEL is SignAndEncrypt).
///
/// Each row is falsifiable: it decrypts/decodes the ACTUAL bytes the client put on the wire (captured by a
/// server-side request observer on the decoded ActivateSession request) and asserts the exact observable -
/// never "did not crash".
///
/// Fixture: a self-contained server that mirrors the ComplianceSecured / MisbehavingServer PKI build and
/// installs the same strand-safe request-observer + response-interceptor interfaces
/// (`ServerImplTestAccess::set_on_secure_channel_available` + `SecureChannelTestAccess`) the ClientBrowse
/// slice added, but with USERNAME user-token policies and a username/password authenticator. The one
/// `NoUsernamePolicyFailsFast` row reuses the real `MisbehavingServer` (Anonymous-only endpoints) directly.

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "fake_async_crypto.h"

#include "misbehaving_server.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_client_session.h"
#include "ua_crypto.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_user_identity.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_additional_parameters_type.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_get_endpoints_response.h"
#include "ua_ephemeral_key_type.h"
#include "ua_key_value_pair.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_policy.h"
#include "ua_variable_id.h"

#include "ua_message_security_mode.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_security_policy.h"

#include "run_async_sync.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <thread>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "test_components.h"

namespace
{
// The strand a bound channel always carries. This entry point marshals every continuation onto it -
// it no longer accepts not having one - so the pool has to be running for the blocking helper below
// to ever see an answer.
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

constexpr std::string_view noneUri = "http://opcfoundation.org/UA/SecurityPolicy#None";

// Policy ids the fixture's USERNAME token policies are advertised under (chosen by the test, not derived).
constexpr std::string_view userRsaPolicyId = "user-1";  // UserName / Basic256Sha256 (encrypting)
constexpr std::string_view userNonePolicyId = "user-none";  // UserName / None (plaintext over SaE channel)
constexpr std::string_view userEccPolicyId = "user-ecc";  // UserName / EccNistP256
constexpr std::string_view injectedSignNonePolicyId = "injected-user-none";

// Passed as the UserTokenPolicy id when the SDK is the one that must select the policy. A discovery-driven
// managed connect holds the endpoint's advertised UserTokenPolicies and must name the one the identity
// activates under (Part 4 section 7.42 - the client may not invent a policyId). A test that supplies the id
// instead cannot tell whether the SDK ever derived it: see testing.md, "the converse, for a field the SDK is
// supposed to fill in". Rows that name a policy explicitly do so because the CALLER's choice is their
// subject - the plaintext `user-none` policy, or the injected Sign/None combo.
constexpr std::string_view deriveFromEndpoint = "";

std::string policy_uri(SecurityPolicyId id)
{
  return std::string{SecurityPolicy::create(id)->uri()};
}

ByteString utf8_bytes(std::string_view text)
{
  ByteString out;
  out.reserve(text.size());
  for (char c : text)
    out.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c)));
  return out;
}

// A minimal little-endian reader over a raw blob (ByteString stores uint8_t, so the reader works in
// uint8_t throughout). `valid` goes false on any short read so a malformed blob never reads out of bounds.
struct BlobReader
{
  span<const uint8_t> data;
  std::size_t offset{0};
  bool valid{true};

  uint32_t u32()
  {
    if (offset + 4 > data.size())
    {
      valid = false;
      return 0;
    }
    const uint32_t value =
      static_cast<uint32_t>(data[offset]) | (static_cast<uint32_t>(data[offset + 1]) << 8) |
      (static_cast<uint32_t>(data[offset + 2]) << 16) | (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
  }

  void skip(std::size_t count)
  {
    if (offset + count > data.size())
    {
      valid = false;
      offset = data.size();
      return;
    }
    offset += count;
  }

  // Skip a UA-binary length-prefixed field (String or ByteString): int32 length (-1 = null) + bytes.
  void skip_length_prefixed()
  {
    const auto length = static_cast<int32_t>(u32());
    if (length > 0)
      skip(static_cast<std::size_t>(length));
  }

  // Read a UA-binary ByteString and return its bytes.
  ByteString read_byte_string()
  {
    const auto length = static_cast<int32_t>(u32());
    if (length <= 0)
      return {};
    if (offset + static_cast<std::size_t>(length) > data.size())
    {
      valid = false;
      return {};
    }
    ByteString out{data.subspan(offset, static_cast<std::size_t>(length))};
    offset += static_cast<std::size_t>(length);
    return out;
  }
};

// Extract the `ReceiverPublicKey` (server ephemeral) from an EccEncryptedSecret blob (Part 4 7.41.2.5,
// Table 190). The blob is the ExtensionObject - TypeId, encoding mask, Length - and its body, whose header is
// cleartext:
//   CommonHeader:  SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime, 8 bytes)
//   KeyDataLength: UInt16
//   KeyData:       SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
// so no decryption is needed to recover the receiver (server ephemeral) public key.
std::optional<ByteString> ecc_receiver_public_key(span<const uint8_t> blob)
{
  // The ExtensionObject prefix: the four-byte NodeId of EccEncryptedSecret (namespace 0, i=17546), the
  // ByteString body mask 0x01, and the body Length, which counts every byte after it.
  constexpr std::size_t prefixSize = 9;
  if (blob.size() < prefixSize || blob[0] != 0x01 || blob[1] != 0x00 ||
      (static_cast<unsigned>(blob[2]) | (static_cast<unsigned>(blob[3]) << 8)) != 17546u || blob[4] != 0x01)
    return std::nullopt;
  BlobReader reader{blob};
  reader.skip(5);
  if (reader.u32() != blob.size() - prefixSize)
    return std::nullopt;
  reader.skip_length_prefixed();  // SecurityPolicyUri (String)
  reader.skip_length_prefixed();  // Certificate (ByteString)
  reader.skip(8);  // SigningTime (DateTime)
  reader.skip(2);  // KeyDataLength (UInt16)
  (void)reader.read_byte_string();  // SenderPublicKey
  ByteString receiver = reader.read_byte_string();  // ReceiverPublicKey
  if (!reader.valid)
    return std::nullopt;
  return receiver;
}

// A snapshot of the UserNameIdentityToken the client actually put on the wire, captured on the server
// strand at the top of ActivateSession handling (BEFORE the server decrypts the secret) and read by the
// test thread.
struct CapturedToken
{
  bool present{false};
  std::string policyId;
  std::string userName;
  std::string encryptionAlgorithm;
  ByteString password;
};

// Mutex-guarded observation co-owned by the fixture and the strand-side interfaces. The server is drained
// before this is released (see the fixture destructor), so a late strand turn never touches dead state.
struct UnpObservation
{
  mutable std::mutex mutex;

  int activateRequestCount{0};
  CapturedToken activateToken;
  ByteString serverEphemeralKey;  // ECDHKey from the CreateSession response (the ECC row's oracle EK1)
  std::vector<ByteString> activateResponseNonces;

  // Armed by the test thread BEFORE connecting: inject a UserName/None UserTokenPolicy into the
  // CreateSession response for the Sign endpoint (a compliant server refuses to advertise this combo, so
  // it must be injected to drive the client's Table-193 refusal).
  bool injectSignNoneUserPolicy{false};
  bool rejectIdentityChange{false};

  void observe_activate(const ua::Structure& request)
  {
    const auto* activate = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
    if (!activate)
      return;
    std::lock_guard lock(mutex);
    ++activateRequestCount;
    if (const auto* token =
          dynamic_cast<const ua::UserNameIdentityToken*>(activate->user_identity_token().get()))
    {
      activateToken.present = true;
      activateToken.policyId = std::string{token->policy_id()};
      activateToken.userName = std::string{token->user_name()};
      activateToken.encryptionAlgorithm = std::string{token->encryption_algorithm()};
      activateToken.password = token->password();
    }
  }

  int activate_count() const
  {
    std::lock_guard lock(mutex);
    return activateRequestCount;
  }

  CapturedToken token() const
  {
    std::lock_guard lock(mutex);
    return activateToken;
  }

  ByteString server_ephemeral_key() const
  {
    std::lock_guard lock(mutex);
    return serverEphemeralKey;
  }

  std::vector<ByteString> activate_response_nonces() const
  {
    std::lock_guard lock(mutex);
    return activateResponseNonces;
  }

  bool inject_enabled() const
  {
    std::lock_guard lock(mutex);
    return injectSignNoneUserPolicy;
  }
};

// Extract the server ephemeral public key from a CreateSession response's AdditionalHeader (mirror of the
// client's own extract_server_ephemeral_key).
ByteString extract_ecdh_key(const ua::Structure* additionalHeader)
{
  const auto* params = dynamic_cast<const ua::AdditionalParametersType*>(additionalHeader);
  if (!params)
    return {};
  for (const auto& kv : params->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHKey")
    {
      if (const auto* ephemeral = kv.value().try_as<ua::EphemeralKeyType>())
        return ephemeral->public_key();
    }
  }
  return {};
}

// Build a UserName UserTokenPolicy with an explicit policy id + effective security policy URI.
UserTokenPolicy user_name_policy(std::string_view policyId, std::string_view securityPolicyUri)
{
  UserTokenPolicy policy;
  policy.token_type() = UserTokenType::UserName;
  policy.policy_id() = std::string{policyId};
  policy.security_policy_uri() = std::string{securityPolicyUri};
  return policy;
}

// Add the injected UserName/None policy to every Sign/Basic256Sha256 endpoint in @p endpoints.
//
// A compliant server refuses to advertise UserName/None on a sign-only endpoint, so the combo the client must
// refuse has to be injected. It is injected into BOTH the GetEndpoints and the CreateSession response,
// because a discovery-driven connect cross-checks one against the other (CL-DISC-004, OPC 10000-4 section
// 5.4.1(c)): injecting into CreateSession alone is a genuine endpoint-set substitution, and the SDK rightly
// refuses it with Bad_SecurityChecksFailed before the token is ever built. That refusal is a different row's
// subject. Presenting the same (invalid) advertisement consistently is what lets THIS row reach the gate it
// is about.
template<typename Endpoints>
void inject_sign_none_user_policy(Endpoints& endpoints)
{
  for (auto& endpoint : endpoints)
  {
    if (endpoint.security_mode() == MessageSecurityMode::Sign &&
        std::string_view{endpoint.security_policy_uri()} == policy_uri(SecurityPolicyId::Basic256Sha256))
    {
      endpoint.user_identity_tokens().push_back(user_name_policy(injectedSignNonePolicyId, noneUri));
    }
  }
}

// Server key material (RSA app cert + ECC nistP256 app cert). Owned so the RSA private key is available
// to decrypt the emitted user-token secret.
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

// The username/password the fixture accepts. "alice" is accepted with ANY password so the encoding rows
// activate successfully regardless of the (possibly non-ASCII) password under test.
constexpr std::string_view user = "alice";

// Longer than the 64 bytes the legacy format allows, so an RSA policy sends it as an RsaEncryptedSecret (OPC
// 10000-4 7.40.4): the password of the rows whose subject is that format.
const std::string longPassword(72, 'p');

}  // namespace

// =============================================================================================
// Fixture: builds a server with USERNAME user-token policies over RSA + ECC endpoints, installs the
// request-observer/response-interceptor interfaces, and a client trusting that server.
// =============================================================================================
class ClientUsernamePassword : public ::testing::Test
{
protected:
  virtual std::shared_ptr<const Crypto> client_crypto()
  {
    return mCrypto;
  }

  // Creation-time server-config hook. This fixture is the only one that advertises a UserName token
  // policy, so any row needing a server that can actually REACH the authenticator with UserName
  // credentials (identity throttling, lockout) has to be built here.
  virtual void configure_server_configuration(ua::server::ServerConfig&)
  {}

  void SetUp() override
  {
    mObservation = std::make_shared<UnpObservation>();

    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    mServerRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "UnpServer RSA", "urn:test:unp:server");
    mServerEcc =
      make_cert(mCrypto, CertificateType::EccNistP256Application, "UnpServer ECC", "urn:test:unp:server");
    mClientRsa =
      make_cert(mCrypto, CertificateType::RsaSha256Application, "UnpClient RSA", "urn:test:unp:client");
    mClientEcc =
      make_cert(mCrypto, CertificateType::EccNistP256Application, "UnpClient ECC", "urn:test:unp:client");

    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_unp_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;

    // Server store: holds both server app certs, trusts the client certs.
    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});
    add_app_cert(mServerCertStore, CertificateType::RsaSha256Application, mServerRsa);
    add_app_cert(mServerCertStore, CertificateType::EccNistP256Application, mServerEcc);
    mServerCertStore->add_to_trusted_certificates_sync(mClientRsa.cert);
    mServerCertStore->add_to_trusted_certificates_sync(mClientEcc.cert);

    // Client store: holds both client app certs, trusts the server certs.
    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    add_app_cert(mClientCertStore, CertificateType::RsaSha256Application, mClientRsa);
    add_app_cert(mClientCertStore, CertificateType::EccNistP256Application, mClientEcc);
    mClientCertStore->add_to_trusted_certificates_sync(mServerRsa.cert);
    mClientCertStore->add_to_trusted_certificates_sync(mServerEcc.cert);

    // Server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.application_description_part().applicationUri = "urn:test:unp:server";

    ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Warning};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString& password)
        {
          // "alice" is accepted with any password (so encoding rows always activate);
          // "testuser"/"testpass" is the conventional pair.
          return username == user ||
                 (username == "testuser" && std::string_view{password.c_str()} == "testpass");
        }));
    components.authenticator = composite;
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});

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

    mClient.emplace(make_client(mClientCertStore));
  }

  void TearDown() override
  {
    // Close + drain the server BEFORE releasing the shared observation state (mirror of the
    // MisbehavingServer teardown order): no in-flight strand turn can then touch dead state.
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
    clientAppCfg.application_description_part().applicationUri = "urn:test:unp:client";
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    return Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = client_crypto(),
        .applicationGroupCertificateStore = store,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Warning});
  }

  void add_endpoints()
  {
    // Basic256Sha256 / SignAndEncrypt: Anonymous + UserName(RSA, "user-1") + UserName(None, "user-none").
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(
        user_name_policy(userRsaPolicyId, policy_uri(SecurityPolicyId::Basic256Sha256)));
      ep.userIdentityTokens.push_back(user_name_policy(userNonePolicyId, noneUri));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // Basic256Sha256 / Sign: Anonymous only. The Table-193 row injects a UserName/None policy at runtime.
    {
      ServerEndpointConfig ep;
      ep.name = "Basic256Sha256_Sign";
      ep.messageSecurityMode = MessageSecurityMode::Sign;
      ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListenerHandle, std::move(ep));
    }

    // EccNistP256 / SignAndEncrypt: Anonymous + UserName(ECC, "user-ecc").
    {
      ServerEndpointConfig ep;
      ep.name = "EccNistP256_SignAndEncrypt";
      ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      ep.securityPolicyId = SecurityPolicyId::EccNistP256AesGcm;
      ep.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      ep.userIdentityTokens.push_back(
        user_name_policy(userEccPolicyId, policy_uri(SecurityPolicyId::EccNistP256AesGcm)));
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
              guard.set_response_interceptor(
                [observation](ua::Response& response)
                {
                  if (auto* activateResponse =
                        dynamic_cast<ua::ActivateSessionResponse*>(response.second.get()))
                  {
                    std::lock_guard lock(observation->mutex);
                    observation->activateResponseNonces.push_back(activateResponse->server_nonce());
                    if (observation->rejectIdentityChange && observation->activateRequestCount >= 2)
                    {
                      activateResponse->response_header().service_result() =
                        Status::BadIdentityChangeNotSupported;
                    }
                    return;
                  }
                  if (auto* endpointsResponse =
                        dynamic_cast<ua::GetEndpointsResponse*>(response.second.get()))
                  {
                    if (observation->inject_enabled())
                      inject_sign_none_user_policy(endpointsResponse->endpoints().payload());
                    return;
                  }
                  auto* createResponse = dynamic_cast<ua::CreateSessionResponse*>(response.second.get());
                  if (!createResponse)
                    return;

                  // Always record the server ephemeral key for the ECC row's oracle.
                  auto ecdhKey =
                    extract_ecdh_key(createResponse->response_header().additional_header().get());
                  if (!ecdhKey.empty())
                  {
                    std::lock_guard lock(observation->mutex);
                    observation->serverEphemeralKey = std::move(ecdhKey);
                  }

                  // Table-193 row: the client must see the invalid combo in the authenticated endpoint set
                  // too, and see the SAME set it saw during discovery.
                  if (observation->inject_enabled())
                    inject_sign_none_user_policy(createResponse->server_endpoints().payload());
                });
            });
        });
  }

  // Open a channel of the given mode/policy against the fixture's server, using the provided client.
  ua::Result<ua::client::SecureChannel> open_channel(
    ua::client::Client& client, MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
    {
      cfg.serverCertificate =
        (policy == SecurityPolicyId::EccNistP256AesGcm) ? mServerEcc.cert : mServerRsa.cert;
    }
    return client.core().try_open_channel_sync(std::move(cfg));
  }

  // The outcome of one managed connect attempt.
  //
  // `reachedServer` replaces the older `channelOpened` bool. At tier 1 the channel open, CreateSession and
  // ActivateSession are one operation, so a client-side bool can no longer say where an attempt stopped -
  // and it never was the interesting question. What matters is whether the request reached the far side:
  // `reachedServer` is observed BY THE SERVER (an ActivateSession request arrived), and a pre-flight refusal
  // is identified by the ErrorDetail source that names the component that refused. Both are stronger
  // oracles than "a client-side call returned good".
  struct ActivateOutcome
  {
    ua::VoidResult activate;
    bool reachedServer{false};
  };

  // Full managed connect + activate(UNP) against this fixture.
  //
  // AGENTS.md: a client integration test drives the highest public production tier that exists. That is
  // `Client::connect` - the public managed facade an application actually uses, which opens the channel,
  // creates the Session and activates it as one operation. `EndpointSelection::FirstMatching` makes the SDK
  // run GetEndpoints itself, so passing @ref deriveFromEndpoint as @p policyId exercises the SDK's own
  // UserTokenPolicy selection rather than handing it the answer.
  ActivateOutcome connect_and_activate(MessageSecurityMode mode, SecurityPolicyId policy,
    std::string_view policyId, std::string_view username, std::string_view password,
    bool allowUnencryptedPassword = false)
  {
    const int activatesBefore = mObservation->activate_count();

    ua::client::ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.endpointSelection = EndpointSelection::FirstMatching;
    config.securityMode = mode;
    config.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
    {
      config.serverCertificate =
        (policy == SecurityPolicyId::EccNistP256AesGcm) ? mServerEcc.cert : mServerRsa.cert;
    }
    config.identity = UsernamePasswordIdentity{.username = std::string{username},
      .password = std::string{password},
      .allowUnencryptedPassword = allowUnencryptedPassword};
    config.userTokenPolicyId = std::string{policyId};
    config.sessionName = "UnpTest";
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
  // tier-0 refusal, so the tag that says WHICH component refused is inside the chain, not necessarily at its
  // head - asserting only on the head would make these rows pass for the wrong reason.
  static bool refused_by(const ua::VoidResult& result, std::string_view source)
  {
    for (const auto& link : ua::ErrorChainView{result.status_code()})
    {
      if (link.source == source)
        return true;
    }
    return false;
  }

  // Decrypt an RSA-encrypted legacy UserIdentityToken secret with the server's RSA private key. Returns
  // the recovered plaintext (`Length(4 LE) || password || serverNonce`). Used only for DEPRECATED RSA
  // policies; modern policies emit an RsaEncryptedSecret (see decode_rsa_encrypted_secret).
  ByteString decrypt_with_server_rsa(const ByteString& cipherText)
  {
    auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    std::vector<byte> plainBuffer(cipherText.size());
    auto recovered = mCrypto->asymmetric_decrypt_sync(
      policy->asymmetric_encryption_algorithm(), mServerRsa.keys, span<const byte>{cipherText}, plainBuffer);
    return ByteString{recovered};
  }

  // Decode a modern RsaEncryptedSecret token blob (Part 4 section 7.41.2.4) through the production
  // server-side decoder, using the server's RSA private key. The decode RSA-decrypts the KeyData, verifies
  // the HMAC, then AES-CBC-decrypts the payload - recovering the Nonce and Secret. crypto ops with a nullopt
  // strand run inline, so run_async_function_sync completes on this (gtest main) thread.
  RsaEncryptedSecretFieldsResult decode_rsa_encrypted_secret(const ByteString& blob)
  {
    auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    return ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
      [&](auto cb)
      {
        decrypt_rsa_encrypted_secret_async(blob,
          policy,
          mCrypto,
          crypto_test_strand(),
          mServerRsa.keys,
          mServerRsa.cert,
          false,
          ua::Logger{},
          std::move(cb));
      });
  }

  std::shared_ptr<const Crypto> mCrypto;
  KeyMaterial mServerRsa;
  KeyMaterial mServerEcc;
  KeyMaterial mClientRsa;
  KeyMaterial mClientEcc;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::shared_ptr<UnpObservation> mObservation;
};

class ClientUsernamePasswordInvalidPadding : public ClientUsernamePassword
{
protected:
  std::shared_ptr<const Crypto> client_crypto() override
  {
    return mClientCrypto;
  }

  VoidResult activate_with_authenticated_nonzero_padding()
  {
    auto channelResult =
      open_channel(*mClient, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    if (channelResult.is_bad())
      return VoidResult{channelResult.status_code(), channelResult.shared_detail()};

    auto channel = std::move(channelResult).value();
    auto session = channel.create_session_sync({.sessionName = "InvalidPaddingConfig"});

    const auto mutationsBefore = mClientCrypto->corrupted_rsa_secret_payload_count();
    mClientCrypto->corrupt_next_rsa_secret_payload_padding();

    ua::client::Session::ActivateConfig config;
    config.policyId = std::string{userRsaPolicyId};
    config.identity = UsernamePasswordIdentity{.username = std::string{user}, .password = longPassword};
    auto activation = session.try_activate_sync(std::move(config));

    EXPECT_EQ(mClientCrypto->corrupted_rsa_secret_payload_count(), mutationsBefore + 1)
      << "the peer must put one non-zero padding byte inside an otherwise authenticated "
         "RsaEncryptedSecret";
    EXPECT_TRUE(mObservation->token().present)
      << "the server must receive the mutated UserNameIdentityToken on the wire";

    (void)session.try_close_sync();
    (void)channel.try_close_sync();
    return activation;
  }

private:
  std::shared_ptr<FakeAsyncCrypto> mClientCrypto{FakeAsyncCrypto::create()};
};

class ClientUsernamePasswordAcceptInvalidPadding : public ClientUsernamePasswordInvalidPadding
{
protected:
  void configure_server_configuration(ServerConfig& config) override
  {
    config.acceptInvalidPadding = true;
  }
};

// Part 4 section 7.41.2.2. The client-side crypto decorator changes one RsaEncryptedSecret padding byte
// before AES encryption; the encoder then MACs the resulting ciphertext normally. The request therefore
// reaches the real server decoder as a cryptographically authentic token whose only defect is non-zero
// padding.
// @relation(AC-SVR-IDENT-012-PADDING-CONFIGURABLE, scope=function)
TEST_F(ClientUsernamePasswordInvalidPadding, StrictDefaultRejectsAuthenticatedNonzeroPadding)
{
  ASSERT_FALSE(ServerConfig{}.acceptInvalidPadding)
    << "invalid-padding interoperability accommodation must remain off by default";
  const auto result = activate_with_authenticated_nonzero_padding();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

// Same wire stimulus and production path as the strict control, with the sole configuration difference
// set to its non-default value. Acceptance proves the public setting reaches the decoder rather than being
// a declared-but-inert field.
// @relation(AC-SVR-IDENT-012-PADDING-CONFIGURABLE, scope=function)
TEST_F(ClientUsernamePasswordAcceptInvalidPadding, ConfigurationAcceptsAuthenticatedNonzeroPadding)
{
  const auto result = activate_with_authenticated_nonzero_padding();
  ASSERT_TRUE(result.is_good()) << "configured padding accommodation did not reach the server decoder";
}

// =============================================================================================
// Encoding rows
// =============================================================================================

// @verifies CL-IDENT-004
// Non-ASCII password ('P@ssw<flower>rd') over Basic256Sha256: decrypt the emitted secret with the server
// RSA key and confirm the recovered plaintext is the UTF-8 encoding of the input (not UTF-16 / Latin-1),
// proving UTF-8 conversion precedes encryption.
// @relation(CL-IDENT-004, scope=function)
TEST_F(ClientUsernamePassword, PasswordUtf8BeforeRsaEncrypt)
{
  // 'P@ssw' + U+273F (UTF-8: 0xE2 0x9C 0xBF) + 'rd'.
  const std::string password = longPassword + "P@ssw" + "\xE2\x9C\xBF" + "rd";
  const ByteString expectedUtf8 = utf8_bytes(password);

  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    deriveFromEndpoint,
    user,
    password);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present) << "no UserNameIdentityToken observed on the wire";
  ASSERT_FALSE(token.password.empty());

  // A password of more than 64 bytes under an RSA policy is an RsaEncryptedSecret (Part 4 section 7.40.4).
  // Decoding it recovers the UTF-8 password, proving UTF-8 conversion precedes encryption.
  auto decoded = decode_rsa_encrypted_secret(token.password);
  ASSERT_TRUE(decoded.is_good()) << "RsaEncryptedSecret decode failed: 0x" << std::hex
                                 << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().secret, expectedUtf8)
    << "recovered password is not the UTF-8 encoding of the input";
}

// @verifies CL-IDENT-004
// UserName/None token over a SignAndEncrypt channel: the password field is the plaintext UTF-8 password
// (the channel provides confidentiality). Non-ASCII input must appear as its UTF-8 bytes, not UTF-16.
// @relation(CL-IDENT-004, scope=function)
TEST_F(ClientUsernamePassword, PasswordUtf8Unencrypted)
{
  const std::string password = std::string{"P@ssw"} + "\xE2\x9C\xBF" + "rd";
  const ByteString expectedUtf8 = utf8_bytes(password);

  // Unencrypted UNP is a hard opt-in (CL-IDENT-009): the plaintext path requires allowUnencryptedPassword.
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    userNonePolicyId,
    user,
    password,
    /*allowUnencryptedPassword=*/true);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_TRUE(token.encryptionAlgorithm.empty())
    << "a None-policy token must not name a per-token encryption algorithm";
  EXPECT_EQ(token.password, expectedUtf8) << "the plaintext password must be its UTF-8 encoding";
}

// @verifies CL-IDENT-005
// Basic256Sha256 UserName token: as a modern (non-deprecated) RSA policy, the client emits the secret as an
// RsaEncryptedSecret ExtensionObject (Part 4 section 7.41.2.4) - NOT the legacy section 7.41.2.2 form. This
// row uses a password exceeding 64 bytes to exercise the RsaEncryptedSecret path: the on-wire blob is
// detectable as an RsaEncryptedSecret, decodes with the server's RSA private key (RSA-decrypt KeyData ->
// verify HMAC -> AES-decrypt payload) to recover exactly the UTF-8 password and a >=32-byte server nonce, and
// `encryptionAlgorithm` names the RSA asymmetric algorithm URI. The server accepting it end-to-end
// (activation is_good) further proves it decodes the form.
// @relation(CL-IDENT-005, scope=function)
TEST_F(ClientUsernamePassword, Unp2RsaEncryptedSecretFormat)
{
  const std::string password(65, 'p');
  const ByteString expectedUtf8 = utf8_bytes(password);
  constexpr std::size_t basic256Sha256NonceLength = 32;

  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    deriveFromEndpoint,
    user,
    password);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_EQ(token.encryptionAlgorithm, "http://www.w3.org/2001/04/xmlenc#rsa-oaep")
    << "encryptionAlgorithm must name the RSA asymmetric algorithm";
  ASSERT_FALSE(token.password.empty());

  // The on-wire secret is a self-describing RsaEncryptedSecret ExtensionObject (cleartext TypeId prefix),
  // NOT an opaque legacy RSA ciphertext.
  ASSERT_TRUE(ua::is_rsa_encrypted_secret(span<const byte>{token.password}))
    << "an RSA password exceeding 64 bytes must use RsaEncryptedSecret";

  auto decoded = decode_rsa_encrypted_secret(token.password);
  ASSERT_TRUE(decoded.is_good()) << "RsaEncryptedSecret decode failed: 0x" << std::hex
                                 << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().secret, expectedUtf8)
    << "the RsaEncryptedSecret Secret must be the UTF-8 password";
  EXPECT_GE(decoded.value().nonce.size(), basic256Sha256NonceLength)
    << "the RsaEncryptedSecret payload must carry the server nonce for freshness";
  EXPECT_EQ(decoded.value().securityPolicyUri, policy_uri(SecurityPolicyId::Basic256Sha256))
    << "the RsaEncryptedSecret CommonHeader SecurityPolicyUri must name the RSA policy";
}

// @verifies CL-SESS-026
// @verifies CL-SESS-029
// Exercise the highest public managed tier: Client::connect creates an anonymous Connection, then
// Connection::reactivate changes that live Session to UsernamePassword without replacing its Subscription.
// The second token's encrypted-secret nonce must equal the nonce returned by the first ActivateSession
// response, proving the reactivation consumed the latest challenge rather than the CreateSession nonce.
// @relation(CL-SESS-026, CL-SESS-029, scope=function)
TEST_F(ClientUsernamePassword, ManagedConnectionReactivatesWithNewIdentityAndPreservesSubscription)
{
  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::FirstMatching;
  config.securityMode = MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = mServerRsa.cert;
  config.identity = AnonymousIdentity{};
  config.reconnect = std::nullopt;

  auto connectionResult = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connectionResult.is_good())
    << "managed anonymous connect failed: 0x" << std::hex << connectionResult.status_code().as_uint32();
  auto connection = std::move(connectionResult).value();
  const auto originalSessionId = connection.session_id();
  ASSERT_TRUE(originalSessionId.is_good());

  auto subscriptionResult = connection.subscriptions().try_create_sync({.publishingIntervalMs = 100.0});
  ASSERT_TRUE(subscriptionResult.is_good());
  auto subscription = std::move(subscriptionResult).value();
  const auto subscriptionId = subscription.server_subscription_id();

  auto reactivateResult = connection.try_reactivate_sync(UsernamePasswordIdentity{
    .username = std::string{user}, .password = "reactivated-secret-" + longPassword});
  ASSERT_TRUE(reactivateResult.is_good())
    << "in-place identity change failed: 0x" << std::hex << reactivateResult.status_code().as_uint32();
  const auto reactivatedSessionId = connection.session_id();
  ASSERT_TRUE(reactivatedSessionId.is_good());
  EXPECT_EQ(reactivatedSessionId.value(), originalSessionId.value())
    << "identity reactivation must preserve the Connection's one active Session";

  EXPECT_EQ(mObservation->activate_count(), 2)
    << "managed connect plus in-place identity change must emit exactly two ActivateSession requests";
  const auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_EQ(token.userName, user);
  EXPECT_EQ(token.policyId, userRsaPolicyId);

  auto decoded = decode_rsa_encrypted_secret(token.password);
  ASSERT_TRUE(decoded.is_good());
  const auto responseNonces = mObservation->activate_response_nonces();
  ASSERT_EQ(responseNonces.size(), 2u);
  EXPECT_EQ(decoded.value().nonce, responseNonces.front())
    << "reactivation must encrypt/sign against the latest nonce from the prior ActivateSession response";

  auto liveSubscriptions = connection.subscriptions().list_sync();
  ASSERT_EQ(liveSubscriptions.size(), 1u);
  EXPECT_EQ(liveSubscriptions.front().server_subscription_id(), subscriptionId)
    << "reactivation must preserve the existing server Subscription";

  EXPECT_TRUE(subscription.try_close_sync().is_good());
  EXPECT_TRUE(connection.try_close_sync().is_good());
}

// @verifies CL-SESS-027
// A server may reject a live identity change with BadIdentityChangeNotSupported. Mutate only the second
// ActivateSession response at the server boundary, then prove the managed Connection surfaces that exact
// status while remaining Active and able to issue a subsequent real Read. The unit interface independently
// proves prior-credential bookkeeping and absence of a reconnect trigger.
// @relation(CL-SESS-027, scope=function)
TEST_F(ClientUsernamePassword, ManagedConnectionIdentityChangeRejectionKeepsConnectionUsable)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->rejectIdentityChange = true;
  }

  ua::client::ConnectionConfig config;
  config.endpointUrl = mEndpointUrl;
  config.endpointSelection = EndpointSelection::FirstMatching;
  config.securityMode = MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.serverCertificate = mServerRsa.cert;
  config.identity = UsernamePasswordIdentity{.username = std::string{user}, .password = "original-secret"};
  config.userTokenPolicyId = std::string{userRsaPolicyId};
  config.reconnect = std::nullopt;

  auto connectionResult = mClient->try_connect_sync(std::move(config));
  ASSERT_TRUE(connectionResult.is_good());
  auto connection = std::move(connectionResult).value();

  auto result = connection.try_reactivate_sync(
    UsernamePasswordIdentity{.username = std::string{user}, .password = "replacement-secret"});
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityChangeNotSupported});
  EXPECT_EQ(connection.state(), ConnectionState::Active);

  auto readResult = connection.try_read_value_sync(ua::NodeId{ua::VariableId::Server_ServerStatus_State});
  EXPECT_TRUE(readResult.is_good())
    << "a rejected identity change must not make the existing Session unusable";
  EXPECT_TRUE(connection.try_close_sync().is_good());
}

// @verifies CL-IDENT-003
// Basic256Sha256 UserName policy requires per-token encryption: the emitted password is NOT the plaintext
// bytes (it is an encrypted secret).
// @relation(CL-IDENT-003, scope=function)
TEST_F(ClientUsernamePassword, TokenEncryptedWhenPolicyRequires)
{
  const std::string password = "testpass";

  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    deriveFromEndpoint,
    user,
    password);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_NE(token.password, utf8_bytes(password)) << "an encrypting policy must not send the plaintext";
  EXPECT_EQ(token.encryptionAlgorithm, "http://www.w3.org/2001/04/xmlenc#rsa-oaep")
    << "encryptionAlgorithm must name the RSA asymmetric algorithm";
}

// @verifies CL-IDENT-003
// UserName/None policy over a SignAndEncrypt channel: the ONLY legal plaintext case. The password contains
// the UTF-8 plaintext and no per-token encryption algorithm is named.
// NOTE: the matrix oracle's "channel policy=None" is wrong - a compliant server (and this SDK) refuses a
// cleartext secret over an unencrypted channel (Part 4 Table 193 / server Rule 1). The legal plaintext
// case is token-policy None over a SignAndEncrypt channel, which is what this row exercises.
// @relation(CL-IDENT-003, scope=function)
TEST_F(ClientUsernamePassword, TokenPlaintextOnlyWithNonePolicy)
{
  const std::string password = "testpass";

  // Unencrypted UNP is a hard opt-in (CL-IDENT-009).
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    userNonePolicyId,
    user,
    password,
    /*allowUnencryptedPassword=*/true);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_EQ(token.password, utf8_bytes(password));
  EXPECT_TRUE(token.encryptionAlgorithm.empty());
}

// @verifies CL-IDENT-009
// The unencrypted-password configuration (UserName/None token over a SignAndEncrypt channel) is a HARD
// OPT-IN (Part 4 section 7.41.4 / Table 193): by default - no allowUnencryptedPassword - the client must
// REFUSE rather than put a plaintext password on the wire, even though the channel is confidential.
// Falsifiable: if the opt-in defaulted on (or the gate were absent), the activation would succeed and a
// plaintext password would be sent (observed by activate_count > 0). The positive opt-in path is
// TokenPlaintextOnlyWithNonePolicy / PasswordUtf8Unencrypted.
// @relation(CL-IDENT-009, scope=function)
TEST_F(ClientUsernamePassword, UnpUnencryptedRefusedWithoutOptIn)
{
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    userNonePolicyId,
    user,
    "testpass");  // default config: allowUnencryptedPassword == false
  ASSERT_TRUE(outcome.activate.is_bad())
    << "unencrypted UNP must be refused by default (no opt-in), never silently sent in the clear";
  EXPECT_TRUE(refused_by(outcome.activate, "client.tier0.token_builder.unp.unencrypted_not_allowed"))
    << "the refusal must be the missing opt-in, raised by the token builder - the confidential channel "
       "itself is valid, and a refusal sourced anywhere else would mean this row passed for the wrong "
       "reason";
  EXPECT_EQ(outcome.activate.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  EXPECT_EQ(mObservation->activate_count(), 0)
    << "no ActivateSession carrying a plaintext password may be sent without the opt-in";
}

// @verifies CL-IDENT-008
// The UserNameIdentityToken.policyId echoes the endpoint's advertised USERNAME policy id ('user-1'), not an
// invented value - and the SDK is the one that must work that out. The caller leaves userTokenPolicyId at
// its default, so the id on the wire can only have come from the endpoint the SDK selected during its own
// GetEndpoints. Supplying the id here instead is what let both discovery-driven entry points ship unable to
// open an authenticated Session at all: the test asserted the value it had itself provided.
//
// The endpoint advertises TWO USERNAME policies, 'user-1' (encrypting) then 'user-none' (plaintext). The
// derivation takes the endpoint's advertised order, so a reader can see the encrypting policy is not chosen
// by luck; a caller who wants the plaintext one names it, which PasswordUtf8Unencrypted does.
// @relation(CL-IDENT-008, scope=function)
TEST_F(ClientUsernamePassword, PolicyIdMatchesUsernamePolicyEntry)
{
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    deriveFromEndpoint,
    user,
    "testpass");
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  EXPECT_EQ(token.policyId, std::string{userRsaPolicyId});
}

// =============================================================================================
// Policy / Table-193 rows
// =============================================================================================

// @verifies CL-IDENT-007
// Sign-only channel + UserName/None token policy: the client refuses and NEVER sends ActivateSession (the
// cleartext password cannot travel confidentially on a sign-only channel, Part 4 Table 193).
// NOTE: the SDK refuses with Bad_SecurityPolicyRejected (from resolve_username_encryption's source-tagged
// "unencrypted_secret_rejected" path), not the matrix's Bad_SecurityModeRejected; this row asserts the
// actual status + source tag.
// @relation(CL-IDENT-007, scope=function)
TEST_F(ClientUsernamePassword, RejectsSignOnlyChannelWithNoneTokenPolicy)
{
  {
    std::lock_guard lock(mObservation->mutex);
    mObservation->injectSignNoneUserPolicy = true;  // present the invalid combo to the client
  }

  auto outcome = connect_and_activate(
    MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256, injectedSignNonePolicyId, user, "testpass");

  ASSERT_TRUE(outcome.activate.is_bad());
  EXPECT_EQ(outcome.activate.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  EXPECT_TRUE(refused_by(outcome.activate, "client.tier0.token_builder.unencrypted_secret_rejected"))
    << "the Sign channel itself is valid: the refusal must be sourced at the token builder";
  EXPECT_FALSE(outcome.reachedServer) << "ActivateSession must NOT have been sent";
}

// @verifies CL-IDENT-008
// No USERNAME policy advertised: configuring UNP fails fast with Bad_IdentityTokenRejected and a
// source-tagged ErrorDetail; ActivateSession is never sent. Uses the real MisbehavingServer (Anonymous-only
// endpoints), the matrix-assigned fixture for this row, built locally inside the test.
// @relation(CL-IDENT-008, scope=function)
TEST_F(ClientUsernamePassword, NoUsernamePolicyFailsFast)
{
  MisbehavingServer misbehaving;
  boost::asio::thread_pool pool;

  auto appConfig = ua::test_utils::create_test_config();
  const auto clientStore = misbehaving.client_certificate_store();
  const auto ownCertificates = clientStore->try_get_application_certificates_sync();
  if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
      ownCertificates.value().front().certificate)
  {
    const auto sanUris = ownCertificates.value().front().certificate->san_uris();
    if (!sanUris.empty())
      appConfig.application_description_part().applicationUri = sanUris.front();
  }
  client::CreateConfig clientConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
  std::optional<ua::client::Client> client{Client::create(pool.executor(),
    std::move(clientConfig),
    ua::client::ClientComponents{.crypto = misbehaving.crypto(),
      .applicationGroupCertificateStore = clientStore,
      .logSink = ua::test_helpers::test_log_sink(),
      .logLevel = LogLevel::Warning})};

  CoreClient::OpenChannelConfig openConfig;
  openConfig.endpointUrl = misbehaving.endpoint_url_none();
  auto channel = client->core().open_channel_sync(openConfig);
  auto session = channel.create_session_sync({.sessionName = "NoUnp"});

  // The endpoint advertises no USERNAME policy, so there is no username policy id to reference; a
  // UsernamePasswordIdentity aimed at any username policy id fails fast (before ActivateSession) with a
  // source-tagged Bad_IdentityTokenRejected naming the missing/unadvertised policy.
  ua::client::Session::ActivateConfig config;
  config.policyId = "username";  // no such USERNAME policy is advertised
  config.identity = UsernamePasswordIdentity{.username = "alice", .password = "secret"};
  auto result = session.try_activate_sync(std::move(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_NE(result.shared_detail(), nullptr) << "the missing-USERNAME-policy refusal must be diagnosable";
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.policy_id_not_found");

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
  client.reset();
  ua::test_utils::drain_with_timeout(pool);
}

// =============================================================================================
// Cert-reuse rows
// =============================================================================================

// @verifies CL-IDENT-006
// The token is encrypted with the (channel-validated) server certificate: decrypting the emitted secret
// with the server's private key recovers the password. A token encrypted for any other key would not
// decrypt with the validated server cert's key.
// @relation(CL-IDENT-006, scope=function)
TEST_F(ClientUsernamePassword, EncryptsWithValidatedChannelCert)
{
  const std::string password = longPassword;

  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::Basic256Sha256,
    deriveFromEndpoint,
    user,
    password);
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  ASSERT_FALSE(token.password.empty());

  // A long password under an RSA policy -> RsaEncryptedSecret; its KeyData is RSA-encrypted to the
  // (channel-validated) server certificate, so it decodes only with that cert's private key, recovering the
  // password.
  auto decoded = decode_rsa_encrypted_secret(token.password);
  ASSERT_TRUE(decoded.is_good()) << "RsaEncryptedSecret decode failed: 0x" << std::hex
                                 << decoded.status_code().as_uint32();
  EXPECT_EQ(decoded.value().secret, utf8_bytes(password))
    << "the secret must decrypt with the validated server cert's private key";
}

// @verifies CL-IDENT-006
// Untrusted server certificate: channel validation fails so ActivateSession is NEVER sent and no plaintext
// password can leak to an untrusted cert. A second client whose store does not trust the server cert is
// used so channel open is rejected at OPN.
// @relation(CL-IDENT-006, scope=function)
TEST_F(ClientUsernamePassword, RefusesToEncryptWithUntrustedServerCert)
{
  // Client store that does NOT trust the server certs (holds only a client app cert).
  auto untrustingStorePath = mTempDir / "untrusting_store";
  std::filesystem::create_directories(untrustingStorePath);
  TrustListValidationOptions validationOptions;
  auto untrustingStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = untrustingStorePath, .validationOptions = validationOptions});
  auto clientRsa =
    make_cert(mCrypto, CertificateType::RsaSha256Application, "UntrustClient", "urn:test:unp:client");
  add_app_cert(untrustingStore, CertificateType::RsaSha256Application, clientRsa);
  // Deliberately do NOT add the server cert to the trust list.

  auto untrustingClient = make_client(untrustingStore);

  auto channelResult =
    open_channel(untrustingClient, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  EXPECT_TRUE(channelResult.is_bad())
    << "opening an encrypting channel to an untrusted server cert must be rejected";
  EXPECT_EQ(mObservation->activate_count(), 0) << "ActivateSession must NEVER be sent to an untrusted cert";
}

// =============================================================================================
// ECC EncryptedSecret rows
// =============================================================================================

// @verifies CL-IDENT-005
// Aes128_Sha256_nistP256 UserName token: the EccEncryptedSecret's ReceiverPublicKey equals the server
// ephemeral key (EK1) delivered in the CreateSession response - the ephemeral was threaded from the
// response, not fabricated/absent.
// @relation(CL-IDENT-005, scope=function)
TEST_F(ClientUsernamePassword, Unp2EccEncryptedSecretUsesServerEphemeralKey)
{
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::EccNistP256AesGcm,
    deriveFromEndpoint,
    user,
    "testpass");
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  ASSERT_FALSE(token.password.empty());
  EXPECT_EQ(token.encryptionAlgorithm, policy_uri(SecurityPolicyId::EccNistP256AesGcm));

  const ByteString serverEphemeral = mObservation->server_ephemeral_key();
  ASSERT_FALSE(serverEphemeral.empty()) << "server did not return an ECDHKey in the CreateSession response";

  auto receiver = ecc_receiver_public_key(token.password);
  ASSERT_TRUE(receiver.has_value()) << "could not parse the EccEncryptedSecret header";
  EXPECT_EQ(*receiver, serverEphemeral)
    << "EccEncryptedSecret.ReceiverPublicKey must equal the server ephemeral key from CreateSession";
}

// @verifies CL-IDENT-005
// BLOCKED on unbuilt product surface: Connection::reactivate_async (W9) does not exist yet, so the
// "latest ephemeral on re-activate" behaviour cannot be exercised. The client-observable analog is pinned
// here: a SINGLE activation over the ECC channel already uses the CreateSession ephemeral EK1 as the
// EccEncryptedSecret ReceiverPublicKey (proven by Unp2EccEncryptedSecretUsesServerEphemeralKey). When
// reactivate lands, this row must re-activate and assert the SECOND token uses the fresh ephemeral (EK2),
// never the stale EK1.
// @relation(CL-IDENT-005, scope=function)
TEST_F(ClientUsernamePassword, Unp2EccUsesLatestEphemeralKeyOnReactivate)
{
  auto outcome = connect_and_activate(MessageSecurityMode::SignAndEncrypt,
    SecurityPolicyId::EccNistP256AesGcm,
    deriveFromEndpoint,
    user,
    "testpass");
  ASSERT_TRUE(outcome.activate.is_good())
    << "activation failed: 0x" << std::hex << outcome.activate.status_code().as_uint32();

  auto token = mObservation->token();
  ASSERT_TRUE(token.present);
  const ByteString serverEphemeral = mObservation->server_ephemeral_key();
  ASSERT_FALSE(serverEphemeral.empty());

  auto receiver = ecc_receiver_public_key(token.password);
  ASSERT_TRUE(receiver.has_value());
  // Analog: the (only, until reactivate exists) activation uses the CreateSession ephemeral key.
  EXPECT_EQ(*receiver, serverEphemeral);
}

// =============================================================================================
// Identity-token attack protection (OPC 10000-4 5.6.3, 7.41.2.1).
//
// This is the only fixture advertising a UserName policy, so the lockout rows live here rather
// than beside the other P4-SS requirements in compliance_session_tests.cpp.
// =============================================================================================

class ClientUsernamePasswordLockout : public ClientUsernamePassword
{
protected:
  void configure_server_configuration(ua::server::ServerConfig& cfg) override
  {
    cfg.identityThrottling.enabled = true;
    cfg.identityThrottling.maxFailedAttemptsBeforeLockout = sFailuresBeforeLockout;
    cfg.identityThrottling.lockoutDuration = mLockoutDuration;
  }

  // Lock out, then return the outcome of presenting valid credentials.
  ActivateOutcome lock_out_then_retry_valid()
  {
    for (uint32_t i = 0; i < sFailuresBeforeLockout; ++i)
    {
      EXPECT_TRUE(attempt("testuser", "wrong-password").activate.is_bad());
    }
    return attempt("testuser", "testpass");
  }

  // Each attempt opens its own channel and session, so consecutive attempts arrive on different
  // TCP connections - the shape of a password-guessing attack, and the shape a key that included
  // the peer's ephemeral port could not accumulate across.
  ActivateOutcome attempt(std::string_view username, std::string_view password)
  {
    return connect_and_activate(MessageSecurityMode::SignAndEncrypt,
      SecurityPolicyId::Basic256Sha256,
      deriveFromEndpoint,
      username,
      password);
  }

  static constexpr uint32_t sFailuresBeforeLockout{3};

  // Long enough by default that no row can pass by outliving the lockout it provoked.
  std::chrono::seconds mLockoutDuration{300};
};

// Short enough that a row can observe the lockout expiring inside its own runtime.
class ClientUsernamePasswordExpiringLockout : public ClientUsernamePasswordLockout
{
protected:
  ClientUsernamePasswordExpiringLockout()
  {
    mLockoutDuration = std::chrono::seconds{2};
  }
};

// Requirement: P4-SS-0029 (SHALL)
// Part 4 7.41.2.1: a Server shall lock out Client applications after five failures; 5.6.3 identifies
// the Client by ApplicationInstanceUri on a secured channel.
// @relation(AC-SVR-SESS-029-TOKEN-ATTACK-MEASURES, SVR-SESS-043, scope=function)
TEST_F(ClientUsernamePasswordLockout, P4_SS_0029_IdentityLockoutAfterFailures)
{
  for (uint32_t i = 0; i < sFailuresBeforeLockout; ++i)
  {
    auto outcome = attempt("testuser", "wrong-password");
    ASSERT_TRUE(outcome.reachedServer) << "attempt " << i << " did not reach the authenticator";
    ASSERT_TRUE(outcome.activate.is_bad()) << "attempt " << i << " accepted a wrong password";
  }

  // Correct credentials, which the authenticator accepts, on a fresh connection. Only the lockout
  // can refuse this - an unlocked server activates it.
  auto lockedOut = attempt("testuser", "testpass");
  ASSERT_TRUE(lockedOut.reachedServer) << "the lockout must refuse a token the server actually received";
  EXPECT_TRUE(lockedOut.activate.is_bad())
    << "valid credentials were accepted after " << sFailuresBeforeLockout
    << " failures, so the failure counter did not accumulate across connections";
  EXPECT_EQ(lockedOut.activate.status_code(), ua::StatusCode{ua::Status::BadIdentityTokenInvalid});
}

// Requirement: P4-SS-0030 (SHALL)
// Part 4 5.6.3: "Sporadic failures shall not delay connections with valid tokens." The OFF half of
// the gate - a lockout that fired below its threshold, or against the wrong user, would be as much
// a defect as one that never fires.
// @relation(SVR-SESS-030, SVR-SESS-043, scope=function)
TEST_F(ClientUsernamePasswordLockout, P4_SS_0030_SporadicFailureNoDelay)
{
  for (uint32_t i = 0; i + 1 < sFailuresBeforeLockout; ++i)
  {
    ASSERT_TRUE(attempt("testuser", "wrong-password").activate.is_bad());
  }

  const auto started = std::chrono::steady_clock::now();
  auto accepted = attempt("testuser", "testpass");
  const auto elapsed = std::chrono::steady_clock::now() - started;

  ASSERT_TRUE(accepted.reachedServer);
  EXPECT_TRUE(accepted.activate.is_good()) << "sub-threshold failures locked out a valid token: 0x"
                                           << std::hex << accepted.activate.status_code().as_uint32();
  EXPECT_LT(elapsed, std::chrono::seconds{5}) << "a valid token was delayed by earlier sporadic failures";

  // A different user on the same connection path is unaffected by another user's failures.
  EXPECT_TRUE(attempt("alice", "any-password").activate.is_good());
}

// The lockout ends when the configured duration elapses, and not before. Part 4 prescribes the
// five-failure threshold (7.41.2.1) but says nothing about how long a lockout lasts or how it is
// cleared, so the duration is entirely this SDK's contract to keep.
TEST_F(ClientUsernamePasswordExpiringLockout, LockoutEndsWhenTheConfiguredDurationElapses)
{
  ASSERT_TRUE(lock_out_then_retry_valid().activate.is_bad()) << "the fixture did not lock out";

  std::this_thread::sleep_for(mLockoutDuration + std::chrono::seconds{1});

  auto afterExpiry = attempt("testuser", "testpass");
  ASSERT_TRUE(afterExpiry.reachedServer);
  EXPECT_TRUE(afterExpiry.activate.is_good())
    << "valid credentials still refused after the configured lockout elapsed: 0x" << std::hex
    << afterExpiry.activate.status_code().as_uint32();
}

// The control for the row above: the same wait against the default-length lockout. Without it,
// "accepted after a wait" would be satisfied by a server that never locked out for long at all.
TEST_F(ClientUsernamePasswordLockout, LockoutOutlastsAWaitShorterThanItsDuration)
{
  ASSERT_TRUE(lock_out_then_retry_valid().activate.is_bad()) << "the fixture did not lock out";

  std::this_thread::sleep_for(std::chrono::seconds{3});

  EXPECT_TRUE(attempt("testuser", "testpass").activate.is_bad())
    << "a 300s lockout released after 3s, so the configured duration is not what ends it";
}
