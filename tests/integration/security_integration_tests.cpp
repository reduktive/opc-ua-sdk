// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Security integration tests - channel security policy x user token policy permutation matrix.
///
/// Tests all valid combinations of channel security policy, message security mode,
/// user token type, and user token policy. Invalid combinations are expected to fail
/// at endpoint configuration time (token policy not present on endpoint) or at
/// ActivateSession time.
///
/// TIER: the permutation matrix drives tier 0 (`try_open_channel_sync` -> `try_get_endpoints_sync` ->
/// `try_create_session_sync` -> `try_activate_sync`) rather than the `Client::connect` facade, and
/// AGENTS.md requires that absence to be recorded rather than inferred.
///
/// The reason is that half the matrix is INVALID BY CONSTRUCTION - policy/mode pairs and channel/token
/// family crossings a conforming client would never request and a managed facade will not assemble. The
/// subject here is the admission gate itself: which combinations are refused, and at which step. A facade
/// that declines to build the request cannot observe the step that refuses it. The
/// `SecurityCrossFamilyRejectionTest` rows are further out of the rule's scope entirely: they assert
/// `Server::add_endpoint` throws, with no client involved.
///
/// Family constraints:
/// - Auth token policies on one endpoint must be same certificate family
/// - For auth channels, token family must match channel family
/// - None channel can have any single family (we use RSA for coverage)
///
/// The None/None endpoint uses RSA family tokens only, because:
/// 1. The server can only have one effective None/None endpoint
///    (SecureChannel::select_security_mode picks the first match)
/// 2. Cross-family token policies cannot coexist on one endpoint
///    (validate_user_token_policy_certificate_consistency rejects them)
///
/// ECC cross-curve cert acceptance (Part 12 section 7.8.4.7/9):
///   P256 policies accept P256 or P384 certs; P384 only accepts P384.
///   Same for Brainpool. Ed25519/Ed448 are single-curve.
///   Tests use exact-match certs for simplicity (always valid).
///
/// RSA key size:
///   All RSA-certificate endpoints are offered all 7 RSA-certificate token policies (B128R15..A256 and the
///   two RSA_DH policies); the server drops each one it cannot use there (a UserName, Issued or X509 token
///   under RSA_DH on a legacy RSA channel, a secret under RSA_DH on None/None). This exercises
///   the mixed RsaMin+RsaSha256 constraint. The RsaSha256Application server cert
///   uses exactly 2048-bit keys to satisfy the mixed-endpoint check.

#include <gtest/gtest.h>

#include "sanitizer_budget.h"

#include "ua_role_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_attribute_id.h"
#include "ua_certificate_store_files.h"
#include "ua_core_client.h"
#include "test_log_sink.h"
#include "ua_crypto.h"
#include "ua_data_value.h"
#include "ua_endpoint_description.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_secure_string.h"
#include "ua_session_attribute_services.h"
#include "ua_security_policy.h"
#include "ua_security_policy_compatibility.h"
#include "ua_server.h"
#include "ua_server_state.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_user_identity.h"
#include "ua_variable_id.h"

#include "test_utilities.h"
#include "test_pki_helpers.h"

#include <filesystem>
#include <optional>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;

namespace
{

// ====================== Enums and test parameters ======================

enum class TokenType
{
  Anonymous,
  UserName,
  X509,
  Issued
};

/// Test parameter for the security integration parameterized test.
///
/// tokenPolicy semantics:
///   - std::nullopt  -> "inherit" (empty security_policy_uri on the UserTokenPolicy)
///   - None          -> "explicit None" (security_policy_uri set to None policy URI)
///   - auth policy   -> "explicit auth" (security_policy_uri set to auth policy URI)
struct SecurityTestParam
{
  SecurityPolicyId channelPolicy;
  MessageSecurityMode channelMode;
  TokenType tokenType;
  std::optional<SecurityPolicyId> tokenPolicy;
  bool expectSuccess;
  std::string description;
};

std::string param_name(const ::testing::TestParamInfo<SecurityTestParam>& info)
{
  return info.param.description;
}

// ====================== Policy family groupings ======================

/// The RSA certificate family: the five RSA policies and RSA_DH, which uses RSA certificates too.
const std::vector<SecurityPolicyId> rsaAuthPolicies = {SecurityPolicyId::Basic128Rsa15,
  SecurityPolicyId::Basic256,
  SecurityPolicyId::Basic256Sha256,
  SecurityPolicyId::Aes128Sha256RsaOaep,
  SecurityPolicyId::Aes256Sha256RsaPss,
  SecurityPolicyId::RsaDhAesGcm,
  SecurityPolicyId::RsaDhChaChaPoly};

const std::vector<SecurityPolicyId> nistEccPolicies = {SecurityPolicyId::EccNistP256AesGcm,
  SecurityPolicyId::EccNistP384AesGcm,
  SecurityPolicyId::EccNistP256ChaChaPoly,
  SecurityPolicyId::EccNistP384ChaChaPoly};

const std::vector<SecurityPolicyId> brainpoolPolicies = {SecurityPolicyId::EccBrainpoolP256r1AesGcm,
  SecurityPolicyId::EccBrainpoolP384r1AesGcm,
  SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
  SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly};

const std::vector<SecurityPolicyId> ed25519Policies = {
  SecurityPolicyId::EccCurve25519ChaChaPoly, SecurityPolicyId::EccCurve25519AesGcm};

const std::vector<SecurityPolicyId> ed448Policies = {
  SecurityPolicyId::EccCurve448ChaChaPoly, SecurityPolicyId::EccCurve448AesGcm};

/// All 19 authenticated security policies.
const std::vector<SecurityPolicyId> allAuthPolicies = {SecurityPolicyId::Basic128Rsa15,
  SecurityPolicyId::Basic256,
  SecurityPolicyId::Basic256Sha256,
  SecurityPolicyId::Aes128Sha256RsaOaep,
  SecurityPolicyId::Aes256Sha256RsaPss,
  SecurityPolicyId::EccNistP256AesGcm,
  SecurityPolicyId::EccNistP384AesGcm,
  SecurityPolicyId::EccBrainpoolP256r1AesGcm,
  SecurityPolicyId::EccBrainpoolP384r1AesGcm,
  SecurityPolicyId::EccCurve25519ChaChaPoly,
  SecurityPolicyId::EccCurve448ChaChaPoly,
  SecurityPolicyId::EccNistP256ChaChaPoly,
  SecurityPolicyId::EccNistP384ChaChaPoly,
  SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
  SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
  SecurityPolicyId::EccCurve25519AesGcm,
  SecurityPolicyId::EccCurve448AesGcm,
  SecurityPolicyId::RsaDhAesGcm,
  SecurityPolicyId::RsaDhChaChaPoly};

/// The fourteen policies with SecureChannelEnhancements, which are exactly the ones whose channel and
/// EncryptedSecret use an EphemeralKey (ECC and RSA_DH).
bool is_enhanced_policy(SecurityPolicyId policy)
{
  switch (policy)
  {
  case SecurityPolicyId::EccNistP256AesGcm:
  case SecurityPolicyId::EccNistP256ChaChaPoly:
  case SecurityPolicyId::EccNistP384AesGcm:
  case SecurityPolicyId::EccNistP384ChaChaPoly:
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
  case SecurityPolicyId::EccCurve25519AesGcm:
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
  case SecurityPolicyId::EccCurve448AesGcm:
  case SecurityPolicyId::EccCurve448ChaChaPoly:
  case SecurityPolicyId::RsaDhAesGcm:
  case SecurityPolicyId::RsaDhChaChaPoly:
    return true;
  default:
    return false;
  }
}

/// Expected issued token data - shared between client (sends) and server (validates after decryption).
constexpr std::string_view expectedIssuedTokenData = "test-issued-token-data";

/// Return the same-family auth policies for a given channel policy.
/// For None channel, returns RSA policies (only family we can test on None - see file header).
const std::vector<SecurityPolicyId>& same_family_auth_policies(SecurityPolicyId channelPolicy)
{
  switch (channelPolicy)
  {
  case SecurityPolicyId::Basic128Rsa15:
  case SecurityPolicyId::Basic256:
  case SecurityPolicyId::Basic256Sha256:
  case SecurityPolicyId::Aes128Sha256RsaOaep:
  case SecurityPolicyId::Aes256Sha256RsaPss:
  case SecurityPolicyId::RsaDhAesGcm:
  case SecurityPolicyId::RsaDhChaChaPoly:
  case SecurityPolicyId::None:
    return rsaAuthPolicies;
  case SecurityPolicyId::EccNistP256AesGcm:
  case SecurityPolicyId::EccNistP384AesGcm:
  case SecurityPolicyId::EccNistP256ChaChaPoly:
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return nistEccPolicies;
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return brainpoolPolicies;
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
  case SecurityPolicyId::EccCurve25519AesGcm:
    return ed25519Policies;
  case SecurityPolicyId::EccCurve448ChaChaPoly:
  case SecurityPolicyId::EccCurve448AesGcm:
    return ed448Policies;
  default:
    return rsaAuthPolicies;
  }
}

// ====================== Name helpers ======================

std::string policy_short_name(SecurityPolicyId p)
{
  switch (p)
  {
  case SecurityPolicyId::None:
    return "None";
  case SecurityPolicyId::Basic128Rsa15:
    return "B128R15";
  case SecurityPolicyId::Basic256:
    return "B256";
  case SecurityPolicyId::Basic256Sha256:
    return "B256S256";
  case SecurityPolicyId::Aes128Sha256RsaOaep:
    return "A128";
  case SecurityPolicyId::Aes256Sha256RsaPss:
    return "A256";
  case SecurityPolicyId::EccNistP256AesGcm:
    return "ENP256";
  case SecurityPolicyId::EccNistP384AesGcm:
    return "ENP384";
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
    return "EBP256";
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
    return "EBP384";
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
    return "EC25519";
  case SecurityPolicyId::EccCurve448ChaChaPoly:
    return "EC448";
  case SecurityPolicyId::EccNistP256ChaChaPoly:
    return "ENP256CCP";
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return "ENP384CCP";
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
    return "EBP256CCP";
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return "EBP384CCP";
  case SecurityPolicyId::EccCurve25519AesGcm:
    return "EC25519GCM";
  case SecurityPolicyId::EccCurve448AesGcm:
    return "EC448GCM";
  case SecurityPolicyId::RsaDhAesGcm:
    return "RDHGCM";
  case SecurityPolicyId::RsaDhChaChaPoly:
    return "RDHCCP";
  default:
    return "Unknown";
  }
}

std::string mode_short_name(MessageSecurityMode m)
{
  switch (m)
  {
  case MessageSecurityMode::None:
    return "None";
  case MessageSecurityMode::Sign:
    return "Sign";
  case MessageSecurityMode::SignAndEncrypt:
    return "SaE";
  default:
    return "Unknown";
  }
}

std::string token_type_name(TokenType t)
{
  switch (t)
  {
  case TokenType::Anonymous:
    return "Anon";
  case TokenType::UserName:
    return "User";
  case TokenType::X509:
    return "X509";
  case TokenType::Issued:
    return "Issued";
  default:
    return "Unknown";
  }
}

std::string token_policy_name(std::optional<SecurityPolicyId> tp)
{
  if (!tp.has_value())
    return "Inherit";
  if (*tp == SecurityPolicyId::None)
    return "ExplNone";
  return policy_short_name(*tp);
}

// ====================== Validity helpers ======================

/// A channel combo is valid when policy=None implies mode=None and policy!=None implies mode!=None.
bool is_valid_channel_combo(SecurityPolicyId channelPolicy, MessageSecurityMode channelMode)
{
  if (channelPolicy == SecurityPolicyId::None)
    return channelMode == MessageSecurityMode::None;
  return channelMode != MessageSecurityMode::None;
}

/// Compute the effective token security policy.
/// - nullopt (inherit): effective = channel policy
/// - explicit value: effective = that value
SecurityPolicyId effective_token_policy(
  std::optional<SecurityPolicyId> tokenPolicy, SecurityPolicyId channelPolicy)
{
  if (!tokenPolicy.has_value())
    return channelPolicy;
  return *tokenPolicy;
}

/// Compute whether a test case should succeed end-to-end.
bool compute_expect_success(SecurityPolicyId channelPolicy, MessageSecurityMode channelMode,
  TokenType tokenType, std::optional<SecurityPolicyId> tokenPolicy)
{
  if (!is_valid_channel_combo(channelPolicy, channelMode))
    return false;

  if (tokenType == TokenType::Anonymous)
    return true;

  auto effective = effective_token_policy(tokenPolicy, channelPolicy);

  if (tokenType == TokenType::UserName || tokenType == TokenType::Issued)
  {
    // Cleartext secret: effective None + channel not SaE -> fail.
    if (effective == SecurityPolicyId::None && channelMode != MessageSecurityMode::SignAndEncrypt)
      return false;
    // OPC 10000-4 7.41 (1.05.07) and decision D-16: a secret encrypted under an ECC or RSA_DH policy needs
    // the EphemeralKey of a channel whose own policy agrees one, so neither a None channel nor an RSA channel
    // without key agreement offers it.
    if (is_enhanced_policy(effective) && !is_enhanced_policy(channelPolicy))
      return false;
    return true;
  }

  if (tokenType == TokenType::X509)
  {
    // X509 always requires authenticated effective policy.
    if (effective == SecurityPolicyId::None)
      return false;
    // An enhanced token policy signs the OPC 10000-4 Table 101 data, which starts with the ChannelThumbprint:
    // a secured channel without SecureChannelEnhancements has none (plan guess G-33). A None channel signs
    // the None-mode layout.
    if (is_enhanced_policy(effective) && channelPolicy != SecurityPolicyId::None &&
        !is_enhanced_policy(channelPolicy))
      return false;
    return true;
  }

  return false;
}

// ====================== Key material ======================

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial create_self_signed_cert(const std::shared_ptr<const Crypto>& crypto, CertificateType certType,
  const std::string& commonName, const std::string& uri, size_t keyBits = 2048)
{
  Crypto::Name subject;
  subject.commonName = commonName;
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(uri);
  altName.hostnames.push_back("localhost");

  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, certType, keyBits);
  if (result.is_bad())
    throw std::runtime_error("Failed to create certificate: " + commonName);

  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

// A self-signed User Certificate for an X509 identity token. OPC 10000-6 Table 44: "The cA flag shall be
// FALSE for User Certificates. The pathLength shall not be present", and keyUsage carries
// digitalSignature. An ApplicationInstance self-signed certificate does not qualify (it carries cA TRUE),
// so the key pair of the requested type is minted by the application-instance path and the certificate is
// then re-issued over that key pair as a Table 44 User Certificate with the same signature algorithm.
KeyMaterial create_self_signed_user_cert(const std::shared_ptr<const Crypto>& crypto,
  CertificateType certType, const std::string& commonName, const std::string& uri, size_t keyBits = 2048)
{
  auto applicationMaterial = create_self_signed_cert(crypto, certType, commonName, uri, keyBits);

  Crypto::CreateCertificateConfig parameters;
  parameters.serialNumber = "1";
  parameters.subject.commonName = commonName;
  parameters.subjectKeys = applicationMaterial.keys;
  parameters.issuerKeys = applicationMaterial.keys;
  parameters.certificateSignatureAlgorithm = applicationMaterial.cert->signature_algorithm();
  parameters.basicConstraint.cA = false;
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.nonRepudiation = true;
  parameters.subjectAlternateName.uris = {uri};
  parameters.from = DateTime::now();
  parameters.to = DateTime{parameters.from.value() + std::chrono::days{3650}};
  return {applicationMaterial.keys, TestPki{crypto}.create_cert(parameters)};
}

// ====================== Fixture ======================

class SecurityIntegrationTest : public ::testing::TestWithParam<SecurityTestParam>
{
protected:
  static void SetUpTestSuite()
  {
    sLogSink = ua::test_helpers::test_log_sink();

    // Create crypto provider.
    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    // --- Server certificates (one per cert type) ---
    // RSA: exactly 2048-bit keys for both RsaMin and RsaSha256 to satisfy the mixed-endpoint check.
    sServerRsaMin = create_self_signed_cert(
      sCrypto, CertificateType::RsaMinApplication, "TestServer_RsaMin", "urn:test:server:rsamin", 2048);
    sServerRsa = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestServer_RSA", "urn:test:server:rsa", 2048);
    sServerEccNistP256 = create_self_signed_cert(sCrypto,
      CertificateType::EccNistP256Application,
      "TestServer_EccNistP256",
      "urn:test:server:eccnistp256");
    sServerEccNistP384 = create_self_signed_cert(sCrypto,
      CertificateType::EccNistP384Application,
      "TestServer_EccNistP384",
      "urn:test:server:eccnistp384");
    sServerEccBrainpoolP256r1 = create_self_signed_cert(sCrypto,
      CertificateType::EccBrainpoolP256r1Application,
      "TestServer_EccBrainpoolP256r1",
      "urn:test:server:eccbp256r1");
    sServerEccBrainpoolP384r1 = create_self_signed_cert(sCrypto,
      CertificateType::EccBrainpoolP384r1Application,
      "TestServer_EccBrainpoolP384r1",
      "urn:test:server:eccbp384r1");
    sServerEccCurve25519 = create_self_signed_cert(sCrypto,
      CertificateType::EccCurve25519Application,
      "TestServer_EccCurve25519",
      "urn:test:server:ec25519");
    sServerEccCurve448 = create_self_signed_cert(
      sCrypto, CertificateType::EccCurve448Application, "TestServer_EccCurve448", "urn:test:server:ec448");

    // --- Client certificates (one per cert type) ---
    const std::string clientApplicationUri{"urn:test:security-integration:client"};
    sClientRsaMin = create_self_signed_cert(
      sCrypto, CertificateType::RsaMinApplication, "TestClient_RsaMin", clientApplicationUri, 2048);
    sClientRsa = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestClient_RSA", clientApplicationUri, 2048);
    sClientEccNistP256 = create_self_signed_cert(
      sCrypto, CertificateType::EccNistP256Application, "TestClient_EccNistP256", clientApplicationUri);
    sClientEccNistP384 = create_self_signed_cert(
      sCrypto, CertificateType::EccNistP384Application, "TestClient_EccNistP384", clientApplicationUri);
    sClientEccBrainpoolP256r1 = create_self_signed_cert(sCrypto,
      CertificateType::EccBrainpoolP256r1Application,
      "TestClient_EccBrainpoolP256r1",
      clientApplicationUri);
    sClientEccBrainpoolP384r1 = create_self_signed_cert(sCrypto,
      CertificateType::EccBrainpoolP384r1Application,
      "TestClient_EccBrainpoolP384r1",
      clientApplicationUri);
    sClientEccCurve25519 = create_self_signed_cert(
      sCrypto, CertificateType::EccCurve25519Application, "TestClient_EccCurve25519", clientApplicationUri);
    sClientEccCurve448 = create_self_signed_cert(
      sCrypto, CertificateType::EccCurve448Application, "TestClient_EccCurve448", clientApplicationUri);

    // --- User X509 certificates (one per cert type) ---
    sUserRsaMin = create_self_signed_user_cert(
      sCrypto, CertificateType::RsaMinApplication, "TestUser_RsaMin", "urn:test:user:rsamin", 2048);
    sUserRsa = create_self_signed_user_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestUser_RSA", "urn:test:user:rsa", 2048);
    sUserEccNistP256 = create_self_signed_user_cert(
      sCrypto, CertificateType::EccNistP256Application, "TestUser_EccNistP256", "urn:test:user:eccnistp256");
    sUserEccNistP384 = create_self_signed_user_cert(
      sCrypto, CertificateType::EccNistP384Application, "TestUser_EccNistP384", "urn:test:user:eccnistp384");
    sUserEccBrainpoolP256r1 = create_self_signed_user_cert(sCrypto,
      CertificateType::EccBrainpoolP256r1Application,
      "TestUser_EccBrainpoolP256r1",
      "urn:test:user:eccbp256r1");
    sUserEccBrainpoolP384r1 = create_self_signed_user_cert(sCrypto,
      CertificateType::EccBrainpoolP384r1Application,
      "TestUser_EccBrainpoolP384r1",
      "urn:test:user:eccbp384r1");
    sUserEccCurve25519 = create_self_signed_user_cert(
      sCrypto, CertificateType::EccCurve25519Application, "TestUser_EccCurve25519", "urn:test:user:ec25519");
    sUserEccCurve448 = create_self_signed_user_cert(
      sCrypto, CertificateType::EccCurve448Application, "TestUser_EccCurve448", "urn:test:user:ec448");

    // --- Server infrastructure ---
    sServerThreadPool = std::make_unique<boost::asio::thread_pool>();
    auto serverExecutor = sServerThreadPool->executor();

    sTempDir =
      std::filesystem::temp_directory_path() / ("ua_sec_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(sTempDir);

    // Application group cert store.
    auto appStorePath = sTempDir / "app_group";
    std::filesystem::create_directories(appStorePath);
    TrustListValidationOptions appValidationOptions;
    sAppCertStore = CertificateStoreFiles::create(
      serverExecutor, sCrypto, {.trustListPath = appStorePath, .validationOptions = appValidationOptions});

    auto addServerCert = [&](CertificateType type, const KeyMaterial& km)
    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = type;
      appCert.certificate = km.cert;
      appCert.keys = km.keys;
      sAppCertStore->add_to_application_certificates_sync(appCert);
    };
    addServerCert(CertificateType::RsaMinApplication, sServerRsaMin);
    addServerCert(CertificateType::RsaSha256Application, sServerRsa);
    addServerCert(CertificateType::EccNistP256Application, sServerEccNistP256);
    addServerCert(CertificateType::EccNistP384Application, sServerEccNistP384);
    addServerCert(CertificateType::EccBrainpoolP256r1Application, sServerEccBrainpoolP256r1);
    addServerCert(CertificateType::EccBrainpoolP384r1Application, sServerEccBrainpoolP384r1);
    addServerCert(CertificateType::EccCurve25519Application, sServerEccCurve25519);
    addServerCert(CertificateType::EccCurve448Application, sServerEccCurve448);

    // Trust all client certs.
    auto trustCert = [&](const KeyMaterial& km)
    {
      sAppCertStore->add_to_trusted_certificates_sync(km.cert);
    };
    trustCert(sClientRsaMin);
    trustCert(sClientRsa);
    trustCert(sClientEccNistP256);
    trustCert(sClientEccNistP384);
    trustCert(sClientEccBrainpoolP256r1);
    trustCert(sClientEccBrainpoolP384r1);
    trustCert(sClientEccCurve25519);
    trustCert(sClientEccCurve448);

    // User token group cert store.
    auto userStorePath = sTempDir / "user_token_group";
    std::filesystem::create_directories(userStorePath);
    TrustListValidationOptions userValidationOptions;
    sUserTokenCertStore = CertificateStoreFiles::create(
      serverExecutor, sCrypto, {.trustListPath = userStorePath, .validationOptions = userValidationOptions});

    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserRsaMin.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserRsa.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccNistP256.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccNistP384.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccBrainpoolP256r1.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccBrainpoolP384r1.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccCurve25519.cert);
    sUserTokenCertStore->add_to_trusted_certificates_sync(sUserEccCurve448.cert);

    // Authenticator: anonymous + username + X509 + issued.
    // Each authenticator validates that the decrypted content matches what the client sent,
    // ensuring the server correctly decrypted the token.
    auto authenticator = std::make_shared<CompositeAuthenticator>();
    authenticator->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    {
      // Validates that username and password match after decryption.
      SimpleUserPasswordAuthenticator::ValidateFn validateFn =
        [](std::string_view username, const SecureString& password)
      {
        return username == "testuser" && std::string_view{password.c_str()} == "testpass";
      };
      authenticator->add(
        UserTokenKind::UserName, std::make_shared<SimpleUserPasswordAuthenticator>(std::move(validateFn)));
    }

    authenticator->add(UserTokenKind::X509, std::make_shared<X509UserAuthenticator>());

    // Validates that issued token data matches after decryption.
    class ValidatingIssuedTokenAuthenticator : public UserAuthenticator
    {
    public:
      void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
      {
        if (!req.identity.issuedToken.has_value())
        {
          completion(
            make_authn_failure(StatusCode{Status::BadIdentityTokenInvalid}, "No issued token data present"));
          return;
        }

        auto& tokenData = *req.identity.issuedToken;
        std::string_view received(reinterpret_cast<const char*>(tokenData.data()), tokenData.size());
        if (received != expectedIssuedTokenData)
        {
          completion(make_authn_failure(StatusCode{Status::BadIdentityTokenRejected},
            "Issued token data does not match expected value after decryption"));
          return;
        }

        completion(make_authn_success(ua::server::UserIdentity{
          .userId = "issued-user", .displayName = "Issued Token User", .kind = UserTokenKind::IssuedToken}));
      }
    };

    authenticator->add(UserTokenKind::IssuedToken, std::make_shared<ValidatingIssuedTokenAuthenticator>());

    ServerComponents components{.crypto = sCrypto,
      .applicationGroupCertificateStore = sAppCertStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug};
    components.authenticator = authenticator;
    // The server validates every X509 user-token certificate against the user-token certificate store;
    // the store handed to X509UserAuthenticator is not the trust anchor.
    components.userTokenCertificateStore = sUserTokenCertStore;
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    // Create server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.allowDeprecatedSecurityPolicies = true;

    ServerConfig serverCfg;
    serverCfg.connectionThrottling.enabled = false;

    server::CreateConfig serverCreateCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    // The authentication interval is a constant-time hold, so the authenticator must finish INSIDE it or
    // the session is refused with BadIdentityTokenInvalid. The 1s default is ample for real crypto and is
    // not ample under a sanitizer, where an ECC or RSA activation overruns it and the refusal looks like a
    // rejected credential. Scaled the same way this file already scales the client service timeout;
    // unchanged (1s) in an ordinary build.
    serverCreateCfg.server.authnTimeout = ua::test_utils::scaled(ServerConfig{}.authnTimeout);
    sServer.emplace(Server::create(serverExecutor, std::move(serverCreateCfg), std::move(components)));

    // Listen on ephemeral port.
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    sListenerHandle = sServer->listen_sync(std::move(bind), {});

    // Add all endpoint configurations.
    add_all_endpoints();

    sServer->start_sync();

    auto urls = sServer->advertised_urls(sListenerHandle);
    ASSERT_FALSE(urls.empty());
    sEndpointUrl = urls.front().str();
    const auto loopbackPos = sEndpointUrl.find("127.0.0.1");
    if (loopbackPos != std::string::npos)
    {
      sEndpointUrl.replace(loopbackPos, std::string_view{"127.0.0.1"}.size(), "localhost");
    }

    // --- Client infrastructure ---
    sClientThreadPool = std::make_unique<boost::asio::thread_pool>();

    auto clientStorePath = sTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    TrustListValidationOptions clientValidationOptions;
    sClientCertStore = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePath, .validationOptions = clientValidationOptions});

    auto addClientCert = [&](CertificateType type, const KeyMaterial& km)
    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = type;
      cert.certificate = km.cert;
      cert.keys = km.keys;
      sClientCertStore->add_to_application_certificates_sync(cert);
    };
    addClientCert(CertificateType::RsaMinApplication, sClientRsaMin);
    addClientCert(CertificateType::RsaSha256Application, sClientRsa);
    addClientCert(CertificateType::EccNistP256Application, sClientEccNistP256);
    addClientCert(CertificateType::EccNistP384Application, sClientEccNistP384);
    addClientCert(CertificateType::EccBrainpoolP256r1Application, sClientEccBrainpoolP256r1);
    addClientCert(CertificateType::EccBrainpoolP384r1Application, sClientEccBrainpoolP384r1);
    addClientCert(CertificateType::EccCurve25519Application, sClientEccCurve25519);
    addClientCert(CertificateType::EccCurve448Application, sClientEccCurve448);

    // Trust all server certs.
    sClientCertStore->add_to_trusted_certificates_sync(sServerRsaMin.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerRsa.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccNistP256.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccNistP384.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccBrainpoolP256r1.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccBrainpoolP384r1.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccCurve25519.cert);
    sClientCertStore->add_to_trusted_certificates_sync(sServerEccCurve448.cert);
  }

  static void TearDownTestSuite()
  {
    if (sServer)
      (void)sServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    sServer.reset();

    // CertificateStoreFiles holds a boost::asio::strand<boost::asio::any_io_executor> bound to a pool's
    // io_context, so it MUST be destroyed before the owning boost::asio::thread_pool - otherwise the strand
    // outlives the io_context and its destructor accesses freed memory during exit().
    sAppCertStore.reset();
    sUserTokenCertStore.reset();
    sClientCertStore.reset();

    if (sServerThreadPool)
      sServerThreadPool->join();
    if (sClientThreadPool)
      sClientThreadPool->join();

    sServerThreadPool.reset();
    sClientThreadPool.reset();

    std::error_code ec;
    std::filesystem::remove_all(sTempDir, ec);
  }

  // --- Cert selection helpers ---

  /// Get the server certificate for a channel policy.
  static const KeyMaterial& server_cert_for(SecurityPolicyId policy)
  {
    switch (policy)
    {
    case SecurityPolicyId::Basic128Rsa15:
    case SecurityPolicyId::Basic256:
      return sServerRsaMin;
    case SecurityPolicyId::Basic256Sha256:
    case SecurityPolicyId::Aes128Sha256RsaOaep:
    case SecurityPolicyId::Aes256Sha256RsaPss:
    case SecurityPolicyId::RsaDhAesGcm:
    case SecurityPolicyId::RsaDhChaChaPoly:
      return sServerRsa;
    case SecurityPolicyId::EccNistP256AesGcm:
    case SecurityPolicyId::EccNistP256ChaChaPoly:
      return sServerEccNistP256;
    case SecurityPolicyId::EccNistP384AesGcm:
    case SecurityPolicyId::EccNistP384ChaChaPoly:
      return sServerEccNistP384;
    case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
    case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
      return sServerEccBrainpoolP256r1;
    case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
    case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
      return sServerEccBrainpoolP384r1;
    case SecurityPolicyId::EccCurve25519ChaChaPoly:
    case SecurityPolicyId::EccCurve25519AesGcm:
      return sServerEccCurve25519;
    case SecurityPolicyId::EccCurve448ChaChaPoly:
    case SecurityPolicyId::EccCurve448AesGcm:
      return sServerEccCurve448;
    default:
      return sServerRsa;
    }
  }

  /// Get the user X509 certificate for a given security policy.
  /// Deprecated RSA policies (B128R15, B256) -> RsaMinApplication cert (max 2048-bit).
  /// Modern RSA policies (B256S256, A128, A256) and RSA_DH -> RsaSha256Application cert.
  static const KeyMaterial& user_cert_for(SecurityPolicyId policy)
  {
    switch (policy)
    {
    case SecurityPolicyId::Basic128Rsa15:
    case SecurityPolicyId::Basic256:
      return sUserRsaMin;
    case SecurityPolicyId::Basic256Sha256:
    case SecurityPolicyId::Aes128Sha256RsaOaep:
    case SecurityPolicyId::Aes256Sha256RsaPss:
    case SecurityPolicyId::RsaDhAesGcm:
    case SecurityPolicyId::RsaDhChaChaPoly:
      return sUserRsa;
    case SecurityPolicyId::EccNistP256AesGcm:
    case SecurityPolicyId::EccNistP256ChaChaPoly:
      return sUserEccNistP256;
    case SecurityPolicyId::EccNistP384AesGcm:
    case SecurityPolicyId::EccNistP384ChaChaPoly:
      return sUserEccNistP384;
    case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
    case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
      return sUserEccBrainpoolP256r1;
    case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
    case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
      return sUserEccBrainpoolP384r1;
    case SecurityPolicyId::EccCurve25519ChaChaPoly:
    case SecurityPolicyId::EccCurve25519AesGcm:
      return sUserEccCurve25519;
    case SecurityPolicyId::EccCurve448ChaChaPoly:
    case SecurityPolicyId::EccCurve448AesGcm:
      return sUserEccCurve448;
    default:
      return sUserRsa;
    }
  }

  // --- Endpoint lookup helpers ---

  /// Look up a user token policy_id from an endpoint's advertised user token policies.
  /// Matches by token type and security policy URI.
  ///   - tokenPolicy = nullopt  -> match empty URI (inherit)
  ///   - tokenPolicy = None     -> match None URI
  ///   - tokenPolicy = auth     -> match that auth URI
  static std::string find_token_policy_id(
    const EndpointDescription& endpoint, TokenType tokenType, std::optional<SecurityPolicyId> tokenPolicy)
  {
    auto targetTokenType = [&]()
    {
      switch (tokenType)
      {
      case TokenType::Anonymous:
        return UserTokenType::Anonymous;
      case TokenType::UserName:
        return UserTokenType::UserName;
      case TokenType::X509:
        return UserTokenType::Certificate;
      case TokenType::Issued:
        return UserTokenType::IssuedToken;
      }
      return UserTokenType::Anonymous;
    }();

    for (const auto& utp : endpoint.user_identity_tokens().payload())
    {
      if (utp.token_type() != targetTokenType)
        continue;

      // Anonymous: match by type only (no security policy URI).
      if (tokenType == TokenType::Anonymous)
        return std::string{utp.policy_id()};

      // UserName/X509: match by security policy URI.
      auto utpUri = std::string_view{utp.security_policy_uri()};
      if (!tokenPolicy.has_value())
      {
        // Inherit: match empty URI.
        if (utpUri.empty())
          return std::string{utp.policy_id()};
      }
      else
      {
        // Explicit: match the policy's URI.
        auto targetUri = std::string{utils::get_security_policy_uri(*tokenPolicy)};
        if (utpUri == targetUri)
          return std::string{utp.policy_id()};
      }
    }
    return {};
  }

  /// Find a matching endpoint and token policy_id from the GetEndpoints response.
  /// Searches ALL endpoints with the matching channel policy/mode (handles multiple
  /// None/None endpoints if they exist).
  struct EndpointMatch
  {
    const EndpointDescription* endpoint;
    std::string policyId;
  };

  static std::optional<EndpointMatch> find_matching_endpoint(const Array<EndpointDescription>& endpoints,
    SecurityPolicyId channelPolicy, MessageSecurityMode channelMode, TokenType tokenType,
    std::optional<SecurityPolicyId> tokenPolicy)
  {
    auto policyUri = utils::get_security_policy_uri(channelPolicy);
    for (const auto& ep : endpoints.payload())
    {
      if (std::string_view{ep.security_policy_uri()} != std::string_view{policyUri} ||
          ep.security_mode() != channelMode)
        continue;

      auto policyId = find_token_policy_id(ep, tokenType, tokenPolicy);
      if (!policyId.empty())
        return EndpointMatch{&ep, std::move(policyId)};
    }
    return std::nullopt;
  }

  // --- Endpoint configuration ---

  /// Build user token policies for a single endpoint.
  /// Only includes policies that pass validate_user_token_policy at config time.
  ///
  /// Token policies per endpoint:
  ///   - Anonymous (always)
  ///   - UserName/X509 with inherit (empty URI) - if it passes validation
  ///   - UserName with explicit None - if it passes validation
  ///   - X509 with explicit None - if it passes validation (never passes, X509 needs auth)
  ///   - UserName/X509 with each same-family auth policy
  static std::vector<UserTokenPolicy> build_user_token_policies(
    SecurityPolicyId channelPolicy, MessageSecurityMode channelMode)
  {
    std::vector<UserTokenPolicy> utps;
    auto channelName = policy_short_name(channelPolicy) + "_" + mode_short_name(channelMode);

    // Anonymous - always valid.
    {
      UserTokenPolicy utp;
      utp.policy_id() = channelName + "_anon";
      utp.token_type() = UserTokenType::Anonymous;
      utps.push_back(std::move(utp));
    }

    // Helper: try adding a token policy, skip if it fails validation.
    auto tryAdd = [&](UserTokenPolicy utp)
    {
      auto result = validate_user_token_policy(utp, channelPolicy, channelMode);
      if (result.is_good())
        utps.push_back(std::move(utp));
    };

    // UserName/Issued with inherit (empty URI).
    for (auto [type, prefix] :
      {std::pair{UserTokenType::UserName, "user"}, std::pair{UserTokenType::IssuedToken, "issued"}})
    {
      UserTokenPolicy utp;
      utp.token_type() = type;
      utp.policy_id() = channelName + "_" + prefix + "_inherit";
      tryAdd(std::move(utp));
    }

    // X509 with inherit (empty URI).
    {
      UserTokenPolicy utp;
      utp.token_type() = UserTokenType::Certificate;
      utp.policy_id() = channelName + "_x509_inherit";
      tryAdd(std::move(utp));
    }

    // UserName/Issued with explicit None.
    for (auto [type, prefix] :
      {std::pair{UserTokenType::UserName, "user"}, std::pair{UserTokenType::IssuedToken, "issued"}})
    {
      UserTokenPolicy utp;
      utp.token_type() = type;
      utp.policy_id() = channelName + "_" + prefix + "_explNone";
      utp.security_policy_uri() = utils::get_security_policy_uri(SecurityPolicyId::None);
      tryAdd(std::move(utp));
    }

    // X509 with explicit None (always fails - X509 requires auth).
    {
      UserTokenPolicy utp;
      utp.token_type() = UserTokenType::Certificate;
      utp.policy_id() = channelName + "_x509_explNone";
      utp.security_policy_uri() = utils::get_security_policy_uri(SecurityPolicyId::None);
      tryAdd(std::move(utp));
    }

    // UserName/X509/Issued with each same-family auth policy.
    const auto& familyPolicies = same_family_auth_policies(channelPolicy);
    for (auto authPolicy : familyPolicies)
    {
      auto authPolicyShort = policy_short_name(authPolicy);
      auto authPolicyUri = utils::get_security_policy_uri(authPolicy);

      // UserName
      {
        UserTokenPolicy utp;
        utp.token_type() = UserTokenType::UserName;
        utp.policy_id() = channelName + "_user_" + authPolicyShort;
        utp.security_policy_uri() = authPolicyUri;
        tryAdd(std::move(utp));
      }

      // X509
      {
        UserTokenPolicy utp;
        utp.token_type() = UserTokenType::Certificate;
        utp.policy_id() = channelName + "_x509_" + authPolicyShort;
        utp.security_policy_uri() = authPolicyUri;
        tryAdd(std::move(utp));
      }

      // IssuedToken
      {
        UserTokenPolicy utp;
        utp.token_type() = UserTokenType::IssuedToken;
        utp.policy_id() = channelName + "_issued_" + authPolicyShort;
        utp.security_policy_uri() = authPolicyUri;
        tryAdd(std::move(utp));
      }
    }

    return utps;
  }

  /// Add all 39 endpoint configurations to the server.
  ///   1. None/None - 1 endpoint (RSA family auth tokens)
  ///   2. RSA certificate (5 RSA, 2 RSA_DH) x {Sign, SaE} - 14 endpoints (offered all 7 token policies)
  ///   3. NIST ECC x {Sign, SaE} - 8 endpoints
  ///   4. Brainpool x {Sign, SaE} - 8 endpoints
  ///   5. Curve25519 x {Sign, SaE} - 4 endpoints
  ///   6. Curve448 x {Sign, SaE} - 4 endpoints
  static void add_all_endpoints()
  {
    // 1. None/None endpoint.
    {
      ServerEndpointConfig ep;
      ep.name = "None_None";
      ep.messageSecurityMode = MessageSecurityMode::None;
      ep.securityPolicyId = SecurityPolicyId::None;
      ep.userIdentityTokens = build_user_token_policies(SecurityPolicyId::None, MessageSecurityMode::None);
      sServer->add_endpoint(sListenerHandle, std::move(ep));
    }

    // 2-6. Authenticated endpoints.
    for (auto channelPolicy : allAuthPolicies)
    {
      for (auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
      {
        ServerEndpointConfig ep;
        ep.name = policy_short_name(channelPolicy) + "_" + mode_short_name(mode);
        ep.messageSecurityMode = mode;
        ep.securityPolicyId = channelPolicy;
        ep.userIdentityTokens = build_user_token_policies(channelPolicy, mode);
        sServer->add_endpoint(sListenerHandle, std::move(ep));
      }
    }
  }

  // Static shared state.
  static std::shared_ptr<ua::LogSink> sLogSink;
  static std::shared_ptr<const Crypto> sCrypto;

  static KeyMaterial sServerRsaMin;
  static KeyMaterial sServerRsa;
  static KeyMaterial sServerEccNistP256;
  static KeyMaterial sServerEccNistP384;
  static KeyMaterial sServerEccBrainpoolP256r1;
  static KeyMaterial sServerEccBrainpoolP384r1;
  static KeyMaterial sServerEccCurve25519;
  static KeyMaterial sServerEccCurve448;

  static KeyMaterial sClientRsaMin;
  static KeyMaterial sClientRsa;
  static KeyMaterial sClientEccNistP256;
  static KeyMaterial sClientEccNistP384;
  static KeyMaterial sClientEccBrainpoolP256r1;
  static KeyMaterial sClientEccBrainpoolP384r1;
  static KeyMaterial sClientEccCurve25519;
  static KeyMaterial sClientEccCurve448;

  static KeyMaterial sUserRsaMin;
  static KeyMaterial sUserRsa;
  static KeyMaterial sUserEccNistP256;
  static KeyMaterial sUserEccNistP384;
  static KeyMaterial sUserEccBrainpoolP256r1;
  static KeyMaterial sUserEccBrainpoolP384r1;
  static KeyMaterial sUserEccCurve25519;
  static KeyMaterial sUserEccCurve448;

  static std::unique_ptr<boost::asio::thread_pool> sServerThreadPool;
  static std::unique_ptr<boost::asio::thread_pool> sClientThreadPool;
  static std::filesystem::path sTempDir;
  static std::shared_ptr<CertificateStore> sAppCertStore;
  static std::shared_ptr<CertificateStore> sUserTokenCertStore;
  static std::shared_ptr<CertificateStore> sClientCertStore;
  static std::optional<Server> sServer;
  static ListenerHandle sListenerHandle;
  static std::string sEndpointUrl;
};

// Static member definitions.
std::shared_ptr<ua::LogSink> SecurityIntegrationTest::sLogSink;
std::shared_ptr<const Crypto> SecurityIntegrationTest::sCrypto;

KeyMaterial SecurityIntegrationTest::sServerRsaMin;
KeyMaterial SecurityIntegrationTest::sServerRsa;
KeyMaterial SecurityIntegrationTest::sServerEccNistP256;
KeyMaterial SecurityIntegrationTest::sServerEccNistP384;
KeyMaterial SecurityIntegrationTest::sServerEccBrainpoolP256r1;
KeyMaterial SecurityIntegrationTest::sServerEccBrainpoolP384r1;
KeyMaterial SecurityIntegrationTest::sServerEccCurve25519;
KeyMaterial SecurityIntegrationTest::sServerEccCurve448;

KeyMaterial SecurityIntegrationTest::sClientRsaMin;
KeyMaterial SecurityIntegrationTest::sClientRsa;
KeyMaterial SecurityIntegrationTest::sClientEccNistP256;
KeyMaterial SecurityIntegrationTest::sClientEccNistP384;
KeyMaterial SecurityIntegrationTest::sClientEccBrainpoolP256r1;
KeyMaterial SecurityIntegrationTest::sClientEccBrainpoolP384r1;
KeyMaterial SecurityIntegrationTest::sClientEccCurve25519;
KeyMaterial SecurityIntegrationTest::sClientEccCurve448;

KeyMaterial SecurityIntegrationTest::sUserRsaMin;
KeyMaterial SecurityIntegrationTest::sUserRsa;
KeyMaterial SecurityIntegrationTest::sUserEccNistP256;
KeyMaterial SecurityIntegrationTest::sUserEccNistP384;
KeyMaterial SecurityIntegrationTest::sUserEccBrainpoolP256r1;
KeyMaterial SecurityIntegrationTest::sUserEccBrainpoolP384r1;
KeyMaterial SecurityIntegrationTest::sUserEccCurve25519;
KeyMaterial SecurityIntegrationTest::sUserEccCurve448;

std::unique_ptr<boost::asio::thread_pool> SecurityIntegrationTest::sServerThreadPool;
std::unique_ptr<boost::asio::thread_pool> SecurityIntegrationTest::sClientThreadPool;
std::filesystem::path SecurityIntegrationTest::sTempDir;
std::shared_ptr<CertificateStore> SecurityIntegrationTest::sAppCertStore;
std::shared_ptr<CertificateStore> SecurityIntegrationTest::sUserTokenCertStore;
std::shared_ptr<CertificateStore> SecurityIntegrationTest::sClientCertStore;
std::optional<Server> SecurityIntegrationTest::sServer;
ListenerHandle SecurityIntegrationTest::sListenerHandle{0};
std::string SecurityIntegrationTest::sEndpointUrl;

// ====================== Key sizes that differ across the channel ======================

/// Same server bring-up as the parameterised suite; a separate fixture because gtest does not mix
/// TEST_P and TEST_F on one.
class SecurityIntegrationKeySizeTest : public SecurityIntegrationTest
{};

// OPC 10000-6 6.7.2.5: an asymmetric message carries ExtraPaddingSize when the key it was ENCRYPTED with
// is larger than 2048 bits - the receiver's own key, since the sender encrypts to the receiver. A client
// whose certificate has a 4096-bit key therefore sends a 2048-bit server no ExtraPaddingSize. A server
// that sized the padding by the SENDER's key looked for one, read the padding size from the wrong byte,
// and refused every such OpenSecureChannel (the CTT's Security Certificate Validation 052).
TEST_F(SecurityIntegrationKeySizeTest, AClientWithA4096BitKeyOpensASignAndEncryptChannelToA2048BitServer)
{
  const std::string clientUri{"urn:test:security-integration:client4096"};
  const auto largeClient = create_self_signed_cert(
    sCrypto, CertificateType::RsaSha256Application, "TestClient_Rsa4096", clientUri, 4096);
  sAppCertStore->add_to_trusted_certificates_sync(largeClient.cert);

  auto storePath = sTempDir / "client_store_4096";
  std::filesystem::create_directories(storePath);
  auto clientStore =
    CertificateStoreFiles::create(sClientThreadPool->executor(), sCrypto, {.trustListPath = storePath});
  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = largeClient.cert;
  appCert.keys = largeClient.keys;
  clientStore->add_to_application_certificates_sync(appCert);
  clientStore->add_to_trusted_certificates_sync(sServerRsa.cert);

  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = clientUri;
  client::CreateConfig clientConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  clientConfig.client.defaultServiceTimeout = ua::test_utils::scaled(std::chrono::seconds{10});
  CoreClient client = CoreClient::create(sClientThreadPool->executor(),
    std::move(clientConfig),
    ua::client::ClientComponents{.crypto = sCrypto,
      .applicationGroupCertificateStore = clientStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug});

  CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = sEndpointUrl;
  channelConfig.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelConfig.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelConfig.serverCertificate = sServerRsa.cert;
  auto channelResult = client.try_open_channel_sync(std::move(channelConfig));
  ASSERT_TRUE(channelResult.is_good())
    << "OpenSecureChannel refused: 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();

  GetEndpointsRequest request;
  request.endpoint_url() = sEndpointUrl;
  EXPECT_TRUE(channel.try_get_endpoints_sync(std::move(request)).is_good())
    << "the channel opened but does not carry a request";
  channel.try_close_sync();
}

// ====================== Parameterized test ======================

// Covers SVR-ECC-001 (coverage-audit retag). The RSA_DH channel rows activate only if both sides keep the
// Session nonces within 128 bytes, since each side refuses a longer one.
// @verifies CL-SECADMIN-009
// @relation(CL-SECADMIN-009, scope=function)
// @relation(AC-SVR-SESS-015-SESSION-NONCE-CEILING-ON-A-LONG-CHANNEL-NONCE, scope=function)
// @relation(AC-CL-SESS-002-SESSION-NONCE-CEILING-ON-A-LONG-CHANNEL-NONCE, scope=function)
TEST_P(SecurityIntegrationTest, ActivateSessionAndReadServerState)
{
  const auto& p = GetParam();

  // Create client.
  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = "urn:test:security-integration:client";
  clientAppCfg.allowDeprecatedSecurityPolicies = true;
  client::CreateConfig clientConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  // An instrumented build can spend longer than the default 10s service timeout inside a single
  // ActivateSession, because the ECC and issued-token paths are crypto under instrumentation. The
  // budget scales with the build; what this test proves does not - activation must still succeed,
  // and a server that never answers still fails below with BadTimeout.
  clientConfig.client.defaultServiceTimeout = ua::test_utils::scaled(std::chrono::seconds{10});
  CoreClient client = CoreClient::create(sClientThreadPool->executor(),
    std::move(clientConfig),
    ua::client::ClientComponents{.crypto = sCrypto,
      .applicationGroupCertificateStore = sClientCertStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug});

  // Open channel.
  CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = sEndpointUrl;
  channelConfig.securityMode = p.channelMode;
  channelConfig.securityPolicyId = p.channelPolicy;

  if (p.channelPolicy != SecurityPolicyId::None)
  {
    channelConfig.serverCertificate = server_cert_for(p.channelPolicy).cert;
  }

  // Invalid channel combo -> expect channel open to fail.
  if (!is_valid_channel_combo(p.channelPolicy, p.channelMode))
  {
    auto channelResult = client.try_open_channel_sync(std::move(channelConfig));
    EXPECT_TRUE(channelResult.is_bad())
      << "Expected channel open to fail for invalid channel combo (" << policy_short_name(p.channelPolicy)
      << ", " << mode_short_name(p.channelMode) << ")";
    return;
  }

  auto channelResult = client.try_open_channel_sync(std::move(channelConfig));
  ASSERT_TRUE(channelResult.is_good())
    << "Failed to open channel: 0x" << std::hex << channelResult.status_code().as_uint32() << " for "
    << policy_short_name(p.channelPolicy) << "/" << mode_short_name(p.channelMode);

  auto channel = std::move(channelResult).value();

  // Discover endpoints.
  GetEndpointsRequest getEndpointsReq;
  getEndpointsReq.endpoint_url() = sEndpointUrl;
  auto getEndpointsResult = channel.try_get_endpoints_sync(std::move(getEndpointsReq));
  ASSERT_TRUE(getEndpointsResult.is_good())
    << "GetEndpoints failed: 0x" << std::hex << getEndpointsResult.status_code().as_uint32();

  auto getEndpointsResp = std::move(getEndpointsResult).value();

  // Find the endpoint with the matching token policy.
  auto match = find_matching_endpoint(
    getEndpointsResp.endpoints(), p.channelPolicy, p.channelMode, p.tokenType, p.tokenPolicy);

  if (!match.has_value())
  {
    // Token policy rejected at config time - not present on any matching endpoint.
    EXPECT_FALSE(p.expectSuccess) << "Policy not found on endpoint but expected success for "
                                  << p.description;
    channel.try_close_sync();
    return;
  }

  // Create session.
  // A token policy with an EphemeralKey (ECC or RSA_DH) requests its own key in CreateSession.
  const bool tokenHasEphemeralKey = p.tokenPolicy.has_value() && is_enhanced_policy(*p.tokenPolicy);
  auto sessionResult = channel.try_create_session_sync({.sessionName = "SecurityTest",
    .ecdhPolicyUri = tokenHasEphemeralKey ? std::string{utils::get_security_policy_uri(*p.tokenPolicy)}
                                          : std::string{utils::get_security_policy_uri(p.channelPolicy)}});
  ASSERT_TRUE(sessionResult.is_good())
    << "Failed to create session: 0x" << std::hex << sessionResult.status_code().as_uint32();

  auto session = std::move(sessionResult).value();

  // Build ActivateConfig.
  Session::ActivateConfig activateConfig;
  activateConfig.policyId = match->policyId;

  switch (p.tokenType)
  {
  case TokenType::Anonymous:
    break;
  case TokenType::UserName:
    activateConfig.identity = ua::client::UsernamePasswordIdentity{.username = "testuser",
      .password = "testpass",
      .allowUnencryptedPassword = p.tokenPolicy == SecurityPolicyId::None};
    break;
  case TokenType::X509:
  {
    // Select user cert based on effective policy.
    auto effectivePolicy = effective_token_policy(p.tokenPolicy, p.channelPolicy);
    const auto& userCert =
      (effectivePolicy == SecurityPolicyId::None) ? sUserRsa : user_cert_for(effectivePolicy);
    activateConfig.identity =
      ua::client::X509Identity{.certificate = userCert.cert, .keyPair = userCert.keys};
    break;
  }
  case TokenType::Issued:
  {
    ua::ByteString tokenData;
    tokenData.assign(reinterpret_cast<const uint8_t*>(expectedIssuedTokenData.data()),
      reinterpret_cast<const uint8_t*>(expectedIssuedTokenData.data() + expectedIssuedTokenData.size()));
    activateConfig.identity = ua::client::IssuedTokenIdentity{.tokenData = std::move(tokenData)};
    break;
  }
  }

  // Activate.
  auto activateResult = session.try_activate_sync(std::move(activateConfig));

  if (p.expectSuccess)
  {
    ASSERT_TRUE(activateResult.is_good())
      << "Expected activation to succeed but got: 0x" << std::hex << activateResult.status_code().as_uint32()
      << " for " << p.description;

    EXPECT_TRUE(session.is_active());

    // Read Server_ServerStatus_State to verify the session works.
    ReadRequest readReq;
    ReadValueId rv;
    rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    readReq.nodes_to_read().push_back(std::move(rv));

    auto readResult = session.attributes().try_read_sync(std::move(readReq));
    ASSERT_TRUE(readResult.is_good())
      << "Read failed: 0x" << std::hex << readResult.status_code().as_uint32();

    auto readResp = std::move(readResult).value();
    ASSERT_EQ(readResp.results().size(), 1u);
    if (readResp.results()[0].status().has_value())
    {
      EXPECT_TRUE(readResp.results()[0].status()->is_good())
        << "Read status: 0x" << std::hex << readResp.results()[0].status()->as_uint32();
    }
    EXPECT_TRUE(readResp.results()[0].value().is_int32());
    EXPECT_EQ(readResp.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

    session.try_close_sync();
  }
  else
  {
    EXPECT_TRUE(activateResult.is_bad())
      << "Expected activation to fail but it succeeded for " << p.description;
  }

  channel.try_close_sync();
}

// ====================== Test case generation ======================

/// Generate the full permutation matrix.
///
/// For each of the 39 valid channel combos (None+None, 19 auth x {Sign, SaE}):
///   - Anonymous (inherit only) -> 1 case
///   - for each of UserName, X509 and Issued:
///     - inherit -> 1 case
///     - explicit None -> 1 case
///     - x same-family auth policies -> N cases (7 RSA certificate, 4 NIST, 4 Brainpool, 2 Curve25519,
///       2 Curve448)
///
/// Total: 828 cases (682 pass, 146 fail).
std::vector<SecurityTestParam> generate_test_params()
{
  std::vector<SecurityTestParam> params;

  auto makeDesc = [](SecurityPolicyId cp,
                    MessageSecurityMode cm,
                    TokenType tt,
                    std::optional<SecurityPolicyId>
                      tp,
                    bool expectSuccess)
  {
    auto result = policy_short_name(cp) + "_" + mode_short_name(cm) + "_" + token_type_name(tt) + "_" +
                  token_policy_name(tp);
    if (!expectSuccess)
      result += "_Fail";
    return result;
  };

  auto addCase =
    [&](SecurityPolicyId cp, MessageSecurityMode cm, TokenType tt, std::optional<SecurityPolicyId> tp)
  {
    auto expectSuccess = compute_expect_success(cp, cm, tt, tp);
    params.push_back({cp, cm, tt, tp, expectSuccess, makeDesc(cp, cm, tt, tp, expectSuccess)});
  };

  // Valid channel combos: None+None, plus each auth policy x {Sign, SaE}.
  struct ChannelCombo
  {
    SecurityPolicyId policy;
    MessageSecurityMode mode;
  };

  std::vector<ChannelCombo> channelCombos;
  channelCombos.push_back({SecurityPolicyId::None, MessageSecurityMode::None});
  for (auto authPolicy : allAuthPolicies)
  {
    channelCombos.push_back({authPolicy, MessageSecurityMode::Sign});
    channelCombos.push_back({authPolicy, MessageSecurityMode::SignAndEncrypt});
  }

  for (const auto& [channelPolicy, channelMode] : channelCombos)
  {
    // Anonymous (inherit only).
    addCase(channelPolicy, channelMode, TokenType::Anonymous, std::nullopt);

    // UserName, X509, and Issued: inherit, explicit None, and same-family auth.
    for (auto tokenType : {TokenType::UserName, TokenType::X509, TokenType::Issued})
    {
      // Inherit.
      addCase(channelPolicy, channelMode, tokenType, std::nullopt);

      // Explicit None.
      addCase(channelPolicy, channelMode, tokenType, SecurityPolicyId::None);

      // Same-family auth policies.
      const auto& familyPolicies = same_family_auth_policies(channelPolicy);
      for (auto authPolicy : familyPolicies)
      {
        addCase(channelPolicy, channelMode, tokenType, authPolicy);
      }
    }
  }

  return params;
}

INSTANTIATE_TEST_SUITE_P(
  SecurityIntegration, SecurityIntegrationTest, ::testing::ValuesIn(generate_test_params()), param_name);

// ====================== Cross-family rejection tests ======================

/// Separate test suite verifying that add_endpoint throws BadConfigurationError
/// when token policies from different certificate families are mixed on one endpoint,
/// or when token policy family doesn't match channel family.
class SecurityCrossFamilyRejectionTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    sThreadPool = std::make_unique<boost::asio::thread_pool>();

    sTempDir =
      std::filesystem::temp_directory_path() / ("ua_sec_crossfam_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(sTempDir);

    // Create a minimal cert store with all cert types.
    auto storePath = sTempDir / "cert_store";
    std::filesystem::create_directories(storePath);
    TrustListValidationOptions validationOptions;
    sCertStore = CertificateStoreFiles::create(
      sThreadPool->executor(), sCrypto, {.trustListPath = storePath, .validationOptions = validationOptions});

    auto addCert = [&](
                     CertificateType type, const std::string& cn, const std::string& uri, size_t bits = 2048)
    {
      auto km = create_self_signed_cert(sCrypto, type, cn, uri, bits);
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = type;
      appCert.certificate = km.cert;
      appCert.keys = km.keys;
      sCertStore->add_to_application_certificates_sync(appCert);
    };
    addCert(CertificateType::RsaMinApplication, "CrossFamServer_RsaMin", "urn:test:crossfam:rsamin");
    addCert(CertificateType::RsaSha256Application, "CrossFamServer_Rsa", "urn:test:crossfam:rsa");
    addCert(CertificateType::EccNistP256Application, "CrossFamServer_NistP256", "urn:test:crossfam:nistp256");
    addCert(CertificateType::EccNistP384Application, "CrossFamServer_NistP384", "urn:test:crossfam:nistp384");
    addCert(CertificateType::EccBrainpoolP256r1Application,
      "CrossFamServer_BpoolP256",
      "urn:test:crossfam:bpoolp256");
    addCert(CertificateType::EccBrainpoolP384r1Application,
      "CrossFamServer_BpoolP384",
      "urn:test:crossfam:bpoolp384");
    addCert(CertificateType::EccCurve25519Application, "CrossFamServer_Ec25519", "urn:test:crossfam:ec25519");
    addCert(CertificateType::EccCurve448Application, "CrossFamServer_Ec448", "urn:test:crossfam:ec448");
  }

  static void TearDownTestSuite()
  {
    sCertStore.reset();

    if (sThreadPool)
      sThreadPool->join();
    sThreadPool.reset();

    std::error_code ec;
    std::filesystem::remove_all(sTempDir, ec);
  }

  /// Create a fresh server for each test case.
  std::pair<Server, ListenerHandle> create_server()
  {
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    appCfg.allowDeprecatedSecurityPolicies = true;

    ServerComponents components{.crypto = sCrypto, .applicationGroupCertificateStore = sCertStore};
    components.authenticator = std::make_shared<CompositeAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    server::CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = []
      {
        ServerConfig c;
        c.connectionThrottling.enabled = false;
        return c;
      }()};

    // The authentication interval is a constant-time hold, so the authenticator must finish INSIDE it or
    // the session is refused with BadIdentityTokenInvalid. The 1s default is ample for real crypto and is
    // not ample under a sanitizer, where an ECC or RSA activation overruns it and the refusal looks like a
    // rejected credential. Scaled the same way this file already scales the client service timeout;
    // unchanged (1s) in an ordinary build.
    cfg.server.authnTimeout = ua::test_utils::scaled(ServerConfig{}.authnTimeout);
    Server server = Server::create(sThreadPool->executor(), std::move(cfg), std::move(components));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    auto listener = server.listen_sync(std::move(bind), {});

    return {std::move(server), listener};
  }

  /// Build a ServerEndpointConfig with the given channel policy/mode and token policies.
  static ServerEndpointConfig make_endpoint(SecurityPolicyId channelPolicy, MessageSecurityMode mode,
    std::vector<std::pair<UserTokenType, SecurityPolicyId>> tokenPolicies)
  {
    ServerEndpointConfig ep;
    ep.name = "test_endpoint";
    ep.messageSecurityMode = mode;
    ep.securityPolicyId = channelPolicy;

    int idx = 0;
    for (const auto& [tokenType, tokenSecPolicy] : tokenPolicies)
    {
      UserTokenPolicy utp;
      utp.token_type() = tokenType;
      utp.policy_id() = "tp_" + std::to_string(idx++);
      if (tokenSecPolicy != SecurityPolicyId::None && tokenSecPolicy != SecurityPolicyId::Invalid)
      {
        utp.security_policy_uri() = utils::get_security_policy_uri(tokenSecPolicy);
      }
      ep.userIdentityTokens.push_back(std::move(utp));
    }

    return ep;
  }

  static std::shared_ptr<const Crypto> sCrypto;
  static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  static std::filesystem::path sTempDir;
  static std::shared_ptr<CertificateStore> sCertStore;
};

std::shared_ptr<const Crypto> SecurityCrossFamilyRejectionTest::sCrypto;
std::unique_ptr<boost::asio::thread_pool> SecurityCrossFamilyRejectionTest::sThreadPool;
std::filesystem::path SecurityCrossFamilyRejectionTest::sTempDir;
std::shared_ptr<CertificateStore> SecurityCrossFamilyRejectionTest::sCertStore;

// @relation(SVR-ECC-005, SVR-ECC-010, scope=function)
TEST_F(SecurityCrossFamilyRejectionTest, RsaChannelWithNistEccTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::Basic256Sha256,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::Certificate, SecurityPolicyId::EccNistP256AesGcm}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, RsaChannelWithBrainpoolTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::Basic256Sha256,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::UserName, SecurityPolicyId::EccBrainpoolP256r1AesGcm}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, NistEccChannelWithRsaTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::EccNistP256AesGcm,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, NistEccChannelWithBrainpoolTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::EccNistP256AesGcm,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::UserName, SecurityPolicyId::EccBrainpoolP256r1AesGcm}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, Ed25519ChannelWithRsaTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::EccCurve25519ChaChaPoly,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::Certificate, SecurityPolicyId::Aes256Sha256RsaPss}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, Ed448ChannelWithNistEccTokenPolicy)
{
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::EccCurve448ChaChaPoly,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::UserName, SecurityPolicyId::EccNistP384AesGcm}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, MixedFamiliesWithinTokenPolicies)
{
  // Same endpoint has both RSA and NIST ECC token policies -> rejected.
  auto [server, listener] = create_server();
  auto ep = make_endpoint(SecurityPolicyId::None,
    MessageSecurityMode::None,
    {{UserTokenType::UserName, SecurityPolicyId::Basic256Sha256},
      {UserTokenType::UserName, SecurityPolicyId::EccNistP256AesGcm}});
  EXPECT_THROW(server.add_endpoint(listener, std::move(ep)), UaException);
}

TEST_F(SecurityCrossFamilyRejectionTest, MixedRsaKeyTooLarge)
{
  // Create a server with a 4096-bit RsaSha256 cert, then try to add an endpoint
  // with both RsaMin and RsaSha256 token policies -> should fail at start or add_endpoint.
  auto largeCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

  auto largeTempDir =
    std::filesystem::temp_directory_path() / ("ua_sec_largersa_" + Guid::create_and_generate().as_string());
  std::filesystem::create_directories(largeTempDir);

  auto largeStorePath = largeTempDir / "cert_store";
  std::filesystem::create_directories(largeStorePath);
  TrustListValidationOptions validationOptions;
  auto largeCertStore = CertificateStoreFiles::create(sThreadPool->executor(),
    largeCrypto,
    {.trustListPath = largeStorePath, .validationOptions = validationOptions});

  // Add a 2048-bit RsaMin cert and a 4096-bit RsaSha256 cert.
  auto rsaMinKm = create_self_signed_cert(
    largeCrypto, CertificateType::RsaMinApplication, "LargeRsa_RsaMin", "urn:test:largersa:rsamin", 2048);
  auto rsaSha256Km = create_self_signed_cert(
    largeCrypto, CertificateType::RsaSha256Application, "LargeRsa_Rsa", "urn:test:largersa:rsa", 4096);

  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaMinApplication;
    appCert.certificate = rsaMinKm.cert;
    appCert.keys = rsaMinKm.keys;
    largeCertStore->add_to_application_certificates_sync(appCert);
  }
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = rsaSha256Km.cert;
    appCert.keys = rsaSha256Km.keys;
    largeCertStore->add_to_application_certificates_sync(appCert);
  }

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  appCfg.allowDeprecatedSecurityPolicies = true;

  ServerComponents components{.crypto = largeCrypto, .applicationGroupCertificateStore = largeCertStore};
  components.authenticator = std::make_shared<CompositeAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

  server::CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = std::move(appCfg),
    .server = ServerConfig{}};

  // The authentication interval is a constant-time hold, so the authenticator must finish INSIDE it or
  // the session is refused with BadIdentityTokenInvalid. The 1s default is ample for real crypto and is
  // not ample under a sanitizer, where an ECC or RSA activation overruns it and the refusal looks like a
  // rejected credential. Scaled the same way this file already scales the client service timeout;
  // unchanged (1s) in an ordinary build.
  cfg.server.authnTimeout = ua::test_utils::scaled(ServerConfig{}.authnTimeout);
  Server server = Server::create(sThreadPool->executor(), std::move(cfg), std::move(components));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto listener = server.listen_sync(std::move(bind), {});

  // Add endpoint with mixed RsaMin + RsaSha256 token policies.
  auto ep = make_endpoint(SecurityPolicyId::Basic256Sha256,
    MessageSecurityMode::SignAndEncrypt,
    {{UserTokenType::Anonymous, SecurityPolicyId::Invalid},
      {UserTokenType::UserName, SecurityPolicyId::Basic128Rsa15},
      {UserTokenType::UserName, SecurityPolicyId::Basic256Sha256}});
  server.add_endpoint(listener, std::move(ep));

  // The mixed RSA check runs at start() time via validate_endpoint_certificates.
  EXPECT_THROW(server.start_sync(), UaException);

  std::error_code ec;
  std::filesystem::remove_all(largeTempDir, ec);
}

}  // namespace
