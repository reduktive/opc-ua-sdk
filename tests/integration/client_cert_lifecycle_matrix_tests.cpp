// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientCertLifecycle cluster of the client integration-test matrix (the 15 `ClientCertLifecycle.*`
///        rows).
///
/// These rows cover the application-instance-certificate PRECONDITIONS around `CoreClient::create` /
/// channel-open (client design section 10.2, CU "Security Default ApplicationInstance Certificate" and
/// "Security Certificate Administration") plus the `CertificateStore` behaviours (key persistence,
/// runtime rotation, store injection). They run against the real in-tree secured server built by
/// the `ComplianceSecured` fixture (None / Sign / SignAndEncrypt Basic256Sha256 endpoints, a
/// file-backed client and server `CertificateStore`). Certificates with specific shapes are built
/// with the SDK's own `Crypto::try_create_self_signed_application_instance_certificate_sync`
/// (SAN-URI, key length controllable); each custom client cert is added to the running server's
/// trust list at test time (`add_to_trusted_certificates_internal` updates the in-memory trust list
/// synchronously, so the next OPN sees it) or deliberately left untrusted.
///
/// SHIPPED BEHAVIOR (section 10.2 / Part 6 section 6.2.2 create-time own-certificate validation):
///   * `CoreClient::create` / `CoreClient::try_create` now enforce FIVE structural preconditions on every
///     ApplicationInstance certificate present in the store, at create time (see
///     `validate_own_application_certificate`, ua_client_own_cert_validation.cpp): (1) a SubjectAltName
///     URI is present; (2) a SAN URI exactly equals the configured applicationUri; (3) the required
///     keyUsage bits are present for the key type - an RSA key needs
///     digitalSignature + keyEncipherment + dataEncipherment, an ECC key needs only digitalSignature;
///     (4) an RSA key meets the Basic256Sha256 minimum (2048 bits); (5) a self-signed cert carries
///     keyCertSign. A defective own cert fails create here with a source-tagged `ErrorDetail` naming the
///     offending field, so the fallible surface is `try_create` (bare `create` rethrows it as a
///     `UaException`). A client with NO own certificate (legitimate for a `None` connection) is exempt.
///   * The client-side precondition enforced at channel-open (an authenticated policy with
///     NO retrievable own cert fails OPN with `ClientCertificateRetrievalFailed`,
///     ua_client_secure_channel_impl.cpp) is also exercised here.
///
/// This file authors the authorable rows as falsifiable, client-observable tests, and pins the two
/// reconnect-DRIVEN rotation rows (section 8.3 ReconnectionFSM auto-reconnect is not exercised by the
/// single-shot harness) to their store-swap-then-next-connect analog.
///
/// Product fixes landed with this slice (both caught by these tests):
///   1. `CertificateStoreFiles::write_key` now restricts the private key file to owner read/write
///      (0600 on POSIX). It previously wrote through fopen() at the process umask (0644 -
///      world-readable); `KeyFileWrittenWithRestrictiveMode` caught that.
///   2. `CertificateStoreFiles::add_to_application_certificates_internal` now replaces the in-memory
///      entry of the same CertificateType instead of appending. The on-disk store keeps one file per
///      type (the writes overwrite), but the in-memory list appended, so after a rotation
///      get_application_certificate() returned the stale first-by-type entry - the disk and memory
///      views diverged and a live own-cert/key rotation never took effect. Kept the two views
///      consistent; `KeyRotationDoesNotRequireRestart` / `RotatesCertificateViaStoreSwap` caught it.

#include "certificate_validation_request_helpers.h"
#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_core_client.h"
#include "ua_client_secure_channel.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;

namespace
{

using SelfSignedCert =
  std::pair<std::shared_ptr<const ua::AsymmetricKeyPair>, std::shared_ptr<const ua::X509Certificate>>;

// The RSA-SHA256 application key file the file-backed store writes under a store root
// (<root>/TrustList/ApplicationKeys/ApplicationPrivateKeyRsaSha256.pem - see
// CertificateStoreFiles path constants + key_filename()).
std::filesystem::path rsa_key_file_path(const std::filesystem::path& storeRoot)
{
  return storeRoot / "TrustList" / "ApplicationKeys" / "ApplicationPrivateKeyRsaSha256.pem";
}

// ---------------------------------------------------------------------------
// Fixture: a secured server + PKI, with helpers to allocate shaped client certs,
// build ad-hoc clients over private cert stores, and drive OPN.
// ---------------------------------------------------------------------------
class ClientCertLifecycle : public ComplianceSecured
{
protected:
  // Allocates a fresh self-signed application-instance certificate with the SDK's own generator. The
  // caller controls the SAN URI list and key length; digitalSignature/keyEncipherment/keyCertSign
  // are fixed by the generator (an application-instance cert). Returns the (key, cert) pair.
  SelfSignedCert mint_cert(
    const std::string& commonName, std::vector<std::string> sanUris, std::size_t keyBits)
  {
    Crypto::Name name;
    name.commonName = commonName;
    Crypto::SubjectAlternateName san;
    san.hostnames.push_back("localhost");
    san.uris = std::move(sanUris);
    auto result = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      name, UtcTime{2050, 1, 1, 0, 0, 0}, san, CertificateType::RsaSha256Application, keyBits);
    EXPECT_THAT(result, Good()) << "self-signed cert generation must succeed";
    return std::move(result).value();
  }

  // Creates a private file-backed client cert store under a unique root; the client always trusts
  // the server cert. Returns the store and remembers its root for key-file inspection.
  std::shared_ptr<CertificateStore> make_client_store(const std::string& name)
  {
    auto storeRoot = mTempDir / name;
    std::filesystem::create_directories(storeRoot);
    mStoreRoots[name] = storeRoot;
    TrustListValidationOptions validationOptions;
    auto store = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = storeRoot, .validationOptions = validationOptions});
    store->add_to_trusted_certificates_sync(mServerCert);
    return store;
  }

  // Installs (or overwrites) the RSA-SHA256 application certificate + key in a store.
  static void set_app_cert(CertificateStore& store, const SelfSignedCert& cert)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = cert.second;
    appCert.keys = cert.first;
    store.add_to_application_certificates_sync(appCert);
  }

  // Adds a cert to the RUNNING server's trust list (synchronous, in-memory update - see
  // add_to_trusted_certificates_internal) so a subsequent OPN accepts it.
  void trust_on_server(const std::shared_ptr<const ua::X509Certificate>& cert)
  {
    mServerCertStore->add_to_trusted_certificates_sync(cert);
  }

  // Builds a client bound to a private store, with an optional explicit applicationUri. When no
  // applicationUri is given, it defaults to the store's own-cert first SAN URI so the create-time
  // own-cert precondition (SAN URI == applicationUri) is satisfied; an empty store keeps the config
  // default (no own cert -> the precondition does not fire).
  CoreClient make_client(std::shared_ptr<CertificateStore> store, const std::string& applicationUri = {})
  {
    auto appCfg = ua::test_utils::create_test_config();
    std::string resolvedUri = applicationUri;
    if (resolvedUri.empty())
    {
      auto ownCerts = store->try_get_application_certificates_sync();
      if (ownCerts.is_good() && !ownCerts.value().empty() && ownCerts.value().front().certificate)
      {
        auto sanUris = ownCerts.value().front().certificate->san_uris();
        if (!sanUris.empty())
        {
          resolvedUri = sanUris.front();
        }
      }
    }
    if (!resolvedUri.empty())
    {
      appCfg.application_description_part().applicationUri = resolvedUri;
    }
    client::CreateConfig cfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    return CoreClient::create(mClientThreadPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = std::move(store),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});
  }

  // Attempts to create a client bound to a private store with an explicit applicationUri, returning
  // the fallible create Result (used by the CreateFailsWhen* rows to observe a create-time precondition
  // failure without throwing).
  CoreClient::CreateResult try_make_client(
    std::shared_ptr<CertificateStore> store, const std::string& applicationUri)
  {
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = applicationUri;
    client::CreateConfig cfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    return CoreClient::try_create(mClientThreadPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = std::move(store),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});
  }

  // Allocates a self-signed RSA cert with a caller-controlled keyUsage set (the app-instance generator
  // fixes keyUsage, so precondition-defect certs are built through the lower-level create_certificate).
  // basicConstraints CA is set to match keyCertSign; `ca` marks the certificate cA TRUE (pathLength 0) even
  // without keyCertSign (RFC 5280 4.2.1.9 forbids keyCertSign without cA, so a keyCertSign certificate is
  // always cA TRUE). Returns the (key, cert) pair.
  SelfSignedCert mint_self_signed_with_key_usage(const std::string& commonName,
    std::vector<std::string> sanUris, std::size_t keyBits, const Crypto::KeyUsage& keyUsage, bool ca = false)
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, keyBits);
    Crypto::CreateCertificateConfig params;
    params.serialNumber = "1";
    params.subject.commonName = commonName;
    params.subjectKeys = keys;
    params.issuerKeys = keys;  // self-signed: issuer key == subject key
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    params.from = UtcTime{2020, 1, 1, 0, 0, 0};
    params.to = UtcTime{2050, 1, 1, 0, 0, 0};
    params.keyUsage = keyUsage;
    params.subjectAlternateName.hostnames.push_back("localhost");
    params.subjectAlternateName.uris = std::move(sanUris);
    if (keyUsage.keyCertSign || ca)
    {
      params.basicConstraint.cA = true;
    }
    if (keyUsage.keyCertSign)
    {
      // RFC 5280 4.2.1.9: pathLenConstraint is meaningful only with keyCertSign.
      params.basicConstraint.pathLength = 0;
    }

    std::promise<CertificateResult> promise;
    auto future = promise.get_future();
    mCrypto->create_certificate_async(
      params, [&promise](CertificateResult r) { promise.set_value(std::move(r)); });
    auto result = future.get();
    EXPECT_THAT(result, Good()) << "custom-keyUsage self-signed cert generation must succeed";
    return {keys, std::move(result).value()};
  }

  // Allocates a self-signed ECC (NIST P-256) cert with a caller-controlled keyUsage. A conformant ECC
  // application-instance cert uses digitalSignature [+keyAgreement] and legitimately omits the RSA-only
  // keyEncipherment/dataEncipherment bits, which the app-instance generator (fixes every bit on) cannot
  // shape. basicConstraints CA tracks keyCertSign for the self-signed check.
  SelfSignedCert mint_ecc_self_signed_with_key_usage(
    const std::string& commonName, std::vector<std::string> sanUris, const Crypto::KeyUsage& keyUsage)
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
    Crypto::CreateCertificateConfig params;
    params.serialNumber = "1";
    params.subject.commonName = commonName;
    params.subjectKeys = keys;
    params.issuerKeys = keys;  // self-signed
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
    params.from = UtcTime{2020, 1, 1, 0, 0, 0};
    params.to = UtcTime{2050, 1, 1, 0, 0, 0};
    params.keyUsage = keyUsage;
    params.subjectAlternateName.hostnames.push_back("localhost");
    params.subjectAlternateName.uris = std::move(sanUris);
    if (keyUsage.keyCertSign)
    {
      params.basicConstraint.cA = true;
      params.basicConstraint.pathLength = 0;
    }

    std::promise<CertificateResult> promise;
    auto future = promise.get_future();
    mCrypto->create_certificate_async(
      params, [&promise](CertificateResult r) { promise.set_value(std::move(r)); });
    auto result = future.get();
    EXPECT_THAT(result, Good()) << "ECC custom-keyUsage self-signed cert generation must succeed";
    return {keys, std::move(result).value()};
  }

  // Installs (or overwrites) an ECC-NistP256 application certificate + key in a store.
  static void set_ecc_app_cert(CertificateStore& store, const SelfSignedCert& cert)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::EccNistP256Application;
    appCert.certificate = cert.second;
    appCert.keys = cert.first;
    store.add_to_application_certificates_sync(appCert);
  }

  CoreClient::SecureChannelResult open_sign_encrypt(CoreClient& client)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    return client.try_open_channel_sync(std::move(cfg));
  }

  CoreClient::SecureChannelResult open_none(CoreClient& client)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::None;
    cfg.securityPolicyId = SecurityPolicyId::None;
    return client.try_open_channel_sync(std::move(cfg));
  }

  // Closes an opened channel so it tears down before the client/pool is destroyed.
  static void close_if_open(CoreClient::SecureChannelResult& result)
  {
    if (result.is_good())
    {
      (void)std::move(result).value().try_close_sync();
    }
  }

  std::map<std::string, std::filesystem::path> mStoreRoots;
};

}  // namespace

// ===========================================================================
// Precondition SUCCEED rows
// ===========================================================================

// A client whose own-cert SAN URI equals its applicationUri opens a SignAndEncrypt channel: the
// positive URI-binding case. Guards against a (future) URI check being over-strict and rejecting a
// legitimately matching cert.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(ClientCertLifecycle, CreateSucceedsWhenCertUriMatches)
{
  const std::string uri = "urn:test:ccl:matching-client";
  auto cert = mint_cert("CCL Matching URI Client", {uri}, 2048);
  trust_on_server(cert.second);

  auto store = make_client_store("match_store");
  set_app_cert(*store, cert);
  auto client = make_client(store, uri);

  auto result = open_sign_encrypt(client);
  EXPECT_THAT(result, Good()) << "a cert whose SAN URI matches the applicationUri must be accepted";
  close_if_open(result);
}

// A 2048-bit RSA cert is in range for Basic256Sha256 (min 2048). The default fixture client cert is
// exactly 2048-bit RSA-SHA256 and trusted, so its SignAndEncrypt OPN succeeds. Guards against a key
// length check rejecting an in-range key.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateSucceedsWhenKeyLengthInRange)
{
  auto appCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(appCerts.empty());
  EXPECT_EQ(appCerts.front().certificate->public_key_bit_length(), 2048u)
    << "fixture precondition: the in-range client key is 2048-bit";

  auto result = open_sign_encrypt(mClient->core());
  EXPECT_THAT(result, Good()) << "a 2048-bit key must satisfy the Basic256Sha256 minimum";
  close_if_open(result);
}

// With no own cert AND MessageSecurityMode::None, no certificate is required: the None channel opens
// even though the store holds no application certificate. Guards against the missing-own-cert
// precondition over-firing on the legal no-cert None case.
// @verifies CL-SECADMIN-007
// @relation(CL-SECADMIN-007, scope=function)
TEST_F(ClientCertLifecycle, CreateSucceedsWhenNoOwnCertAndPolicyNone)
{
  auto store = make_client_store("empty_store_none");  // trusts server; NO application cert
  auto client = make_client(store);

  auto result = open_none(client);
  EXPECT_THAT(result, Good()) << "a None channel must not require an own certificate";
  close_if_open(result);
}

// A store holding a valid, server-trusted own cert opens a SignAndEncrypt channel: the own cert is
// presented and accepted on OPN. Falsifier: if the client had no usable own cert it could not
// establish the authenticated channel (contrast CreateFailsWhenNoOwnCertAndSecurityRequired).
// @verifies CL-SECADMIN-007
// @relation(CL-SECADMIN-007, scope=function)
TEST_F(ClientCertLifecycle, CreateSucceedsWhenOwnCertPresent)
{
  auto cert = mint_cert("CCL Own Cert Present", {"urn:test:ccl:own-present"}, 2048);
  trust_on_server(cert.second);

  auto store = make_client_store("own_present_store");
  set_app_cert(*store, cert);
  auto client = make_client(store);

  auto result = open_sign_encrypt(client);
  EXPECT_THAT(result, Good()) << "a present, trusted own cert must open a SignAndEncrypt channel";
  close_if_open(result);
}

// ===========================================================================
// Precondition FAIL row that IS enforced client-side (own cert retrieval)
// ===========================================================================

// SignAndEncrypt requires an own cert; a store with no application certificate fails the OPN on the
// client side, before any network exchange, with a ClientCertificateRetrievalFailed ErrorDetail that
// names the missing own cert. Falsifier: absent the precondition the client would proceed and fail
// only later (or silently downgrade).
// @verifies CL-SECADMIN-007
// @relation(CL-SECADMIN-007, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenNoOwnCertAndSecurityRequired)
{
  auto store = make_client_store("empty_store_sae");  // trusts server; NO application cert
  auto client = make_client(store);

  auto result = open_sign_encrypt(client);
  ASSERT_TRUE(result.is_bad()) << "SignAndEncrypt without an own cert must fail to open";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  EXPECT_THAT(
    ua::to_string(*result.shared_detail()), ::testing::HasSubstr("ClientCertificateRetrievalFailed"))
    << "the ErrorDetail must name the missing own certificate";
}

// ===========================================================================
// Own-cert precondition FAIL rows (enforced at CoreClient::create, section 10.2 / Part 6 section 6.2.2)
// ===========================================================================

// An own cert with NO SubjectAltName URI entry at all fails create: a SAN URI is mandatory for an
// application-instance certificate (Part 6 section 6.2.2). Falsifier: if only URI equality were checked, a
// cert with no SAN URI could slip through as a vacuous (empty) match.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenCertHasNoSanUri)
{
  auto cert = mint_cert("CCL No SAN URI Client", /*sanUris=*/{}, 2048);
  ASSERT_TRUE(cert.second->san_uris().empty()) << "fixture precondition: the cert carries no SAN URI";

  auto store = make_client_store("no_san_uri_store");
  set_app_cert(*store, cert);

  auto result = try_make_client(store, "urn:test:ccl:no-san-app");
  ASSERT_TRUE(result.is_bad()) << "an own cert with no SAN URI must fail create";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateSanUriMissing"))
    << "the ErrorDetail must name the missing-SAN-URI precondition";
  EXPECT_THAT(detail, ::testing::HasSubstr("client.create.own_cert.san_uri_missing"))
    << "the ErrorDetail must carry the source tag for the missing SAN URI";
}

// A present-but-different SAN URI fails at the public CoreClient::try_create boundary and names both
// identities.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenCertUriMismatchesApplicationUri)
{
  auto cert = mint_cert("CCL Mismatched URI Client", {"urn:test:ccl:certificate"}, 2048);
  auto store = make_client_store("mismatched_uri_store");
  set_app_cert(*store, cert);

  auto result = try_make_client(store, "urn:test:ccl:configured");
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUriInvalid});
  ASSERT_TRUE(result.shared_detail());
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateApplicationUriMismatch"));
  EXPECT_THAT(detail, ::testing::HasSubstr("urn:test:ccl:configured"));
  EXPECT_THAT(detail, ::testing::HasSubstr("urn:test:ccl:certificate"));
}

// A non-None-usable RSA own cert that lacks the keyEncipherment key-usage bit fails create citing the
// missing bit. Falsifier: without the check a cert unusable for token/key encryption is accepted and
// only fails later on the wire.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenKeyUsageMissingRequiredBit)
{
  const std::string uri = "urn:test:ccl:key-usage";
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.dataEncipherment = true;
  keyUsage.keyCertSign = true;  // self-signed CA bit present so the self-signed check is not the failure
  keyUsage.keyEncipherment = false;  // the deliberate defect
  auto cert = mint_self_signed_with_key_usage("CCL Missing KeyEncipherment Client", {uri}, 2048, keyUsage);
  ASSERT_FALSE(cert.second->key_usage_key_encipherment()) << "fixture precondition: keyEncipherment absent";

  auto store = make_client_store("key_usage_store");
  set_app_cert(*store, cert);

  auto result = try_make_client(store, uri);
  ASSERT_TRUE(result.is_bad()) << "an own cert missing a required keyUsage bit must fail create";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateKeyUsageInvalid"))
    << "the ErrorDetail must name the keyUsage precondition";
  EXPECT_THAT(detail, ::testing::HasSubstr("keyEncipherment"))
    << "the ErrorDetail must name the specific missing keyUsage bit";
}

// An RSA own cert with a 1024-bit key is below the Basic256Sha256 minimum (2048): create fails naming
// the policy and the observed key length. Falsifier: without the check the server rejects at OPN and
// the SDK cannot explain why.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenOwnCertKeyTooShortForPolicy)
{
  const std::string uri = "urn:test:ccl:short-key";
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.keyCertSign = true;  // full keyUsage so only the key length is the defect
  auto cert = mint_self_signed_with_key_usage("CCL Short Key Client", {uri}, 1024, keyUsage);
  ASSERT_EQ(cert.second->public_key_bit_length(), 1024u) << "fixture precondition: 1024-bit key";

  auto store = make_client_store("short_key_store");
  set_app_cert(*store, cert);

  auto result = try_make_client(store, uri);
  ASSERT_TRUE(result.is_bad()) << "a key below the policy minimum must fail create";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateKeyTooShort"))
    << "the ErrorDetail must name the key-length precondition";
  EXPECT_THAT(detail, ::testing::HasSubstr("Basic256Sha256")) << "the ErrorDetail must name the policy";
  EXPECT_THAT(detail, ::testing::HasSubstr("1024")) << "the ErrorDetail must name the observed key length";
}

// A self-signed RSA own cert with cA TRUE and without the keyCertSign key-usage bit fails create: OPC
// 10000-6 Table 43 "Self-signed Certificates shall also include keyCertSign", applied where cA is TRUE only
// (decision 25; RFC 5280 4.2.1.9 forbids keyCertSign without cA), so a cA FALSE self-signed certificate
// needs no keyCertSign. Falsifier: without the check the malformed self-signed cert is accepted.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateFailsWhenSelfSignedCertLacksKeyCertSign)
{
  const std::string uri = "urn:test:ccl:no-cert-sign";
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.nonRepudiation = true;  // OPC 10000-6 Table 43; the only defect is the missing keyCertSign
  keyUsage.serverAuth = true;
  keyUsage.clientAuth = true;
  keyUsage.keyCertSign = false;  // the deliberate defect on a cA TRUE self-signed cert
  auto cert =
    mint_self_signed_with_key_usage("CCL No KeyCertSign Client", {uri}, 2048, keyUsage, /*ca=*/true);
  ASSERT_TRUE(cert.second->self_signed()) << "fixture precondition: the cert is self-signed";
  ASSERT_TRUE(cert.second->basic_constraints_ca()) << "fixture precondition: the cert has cA TRUE";
  ASSERT_FALSE(cert.second->key_usage_key_cert_sign()) << "fixture precondition: keyCertSign absent";

  auto store = make_client_store("no_cert_sign_store");
  set_app_cert(*store, cert);

  auto result = try_make_client(store, uri);
  ASSERT_TRUE(result.is_bad()) << "a self-signed cert lacking keyCertSign must fail create";
  ASSERT_TRUE(result.shared_detail()) << "the failure must carry an ErrorDetail";
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_THAT(detail, ::testing::HasSubstr("OwnCertificateSelfSignedMissingKeyCertSign"))
    << "the ErrorDetail must name the self-signed-keyCertSign precondition";
  EXPECT_THAT(detail, ::testing::HasSubstr("client.create.own_cert.self_signed_no_key_cert_sign"))
    << "the ErrorDetail must carry the source tag for the self-signed keyCertSign check";
}

// A conformant ECC (NIST P-256) own cert that uses digitalSignature [+keyAgreement] and legitimately
// OMITS the RSA-only keyEncipherment/dataEncipherment bits passes create: the keyUsage precondition is
// key-type-dependent (Part 6 section 6.2.2 / CL-SECADMIN-010), so it must not be rejected for the absent
// RSA-only bits. Falsifier: a key-type-blind keyUsage gate (requiring keyEncipherment on every key)
// would reject this legitimate ECC cert at create.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateSucceedsForConformantEccOwnCertMissingKeyEncipherment)
{
  const std::string uri = "urn:test:ccl:ecc-conformant";
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyAgreement = true;  // ECC derives keys via key agreement, not RSA-style encipherment
  keyUsage.keyCertSign = true;  // self-signed
  // deliberately NO keyEncipherment / dataEncipherment - an ECC key cannot do RSA-style key/data transport
  auto cert = mint_ecc_self_signed_with_key_usage("CCL Conformant ECC Client", {uri}, keyUsage);
  ASSERT_EQ(cert.second->key_algorithm(), CertificateKeyAlgorithm::EccNistP256)
    << "fixture precondition: the cert carries an ECC NIST P-256 key";
  ASSERT_FALSE(cert.second->key_usage_key_encipherment())
    << "fixture precondition: the conformant ECC cert omits keyEncipherment";

  auto store = make_client_store("ecc_conformant_store");
  set_ecc_app_cert(*store, cert);

  auto result = try_make_client(store, uri);
  EXPECT_THAT(result, Good())
    << "a conformant ECC own cert (digitalSignature[+keyAgreement], no keyEncipherment) must pass create";
}

// The THROWING create wrapper (CoreClient::create, not try_create) surfaces a create-time own-cert
// precondition failure as a UaException (error_handling.md: the throwing wrapper's negative path). A
// self-signed cert lacking keyCertSign is the defect; create must throw rather than return.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(ClientCertLifecycle, CreateThrowsUaExceptionOnDefectiveOwnCert)
{
  const std::string uri = "urn:test:ccl:throwing-defect";
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.nonRepudiation = true;  // OPC 10000-6 Table 43; the only defect is the missing keyCertSign
  keyUsage.serverAuth = true;
  keyUsage.clientAuth = true;
  keyUsage.keyCertSign = false;  // defect on a cA TRUE self-signed cert: no keyCertSign (decision 25)
  auto cert =
    mint_self_signed_with_key_usage("CCL Throwing Defect Client", {uri}, 2048, keyUsage, /*ca=*/true);
  ASSERT_TRUE(cert.second->self_signed());
  ASSERT_TRUE(cert.second->basic_constraints_ca());
  ASSERT_FALSE(cert.second->key_usage_key_cert_sign());

  auto store = make_client_store("throwing_defect_store");
  set_app_cert(*store, cert);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.application_description_part().applicationUri = uri;
  client::CreateConfig cfg{.identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
  EXPECT_THROW(
    {
      CoreClient::create(mClientThreadPool.executor(),
        std::move(cfg),
        ua::client::ClientComponents{.crypto = mCrypto,
          .applicationGroupCertificateStore = store,
          .logSink = test_log_sink(),
          .logLevel = LogLevel::Debug});
    },
    ua::UaException)
    << "the throwing create wrapper must raise UaException on a defective own cert";
}

// ===========================================================================
// CertificateStore behaviours
// ===========================================================================

// The private key the store writes to disk must not be readable by group or other. Installing an
// application cert triggers write_key(); the resulting key file's mode is exactly owner read/write
// (0600 on POSIX). Any group/other bit fails the assert. On non-POSIX the mode model differs, so the
// bit assertion is a documented no-op there.
// @verifies CL-SECADMIN-006
// @relation(CL-SECADMIN-006, scope=function)
TEST_F(ClientCertLifecycle, KeyFileWrittenWithRestrictiveMode)
{
  auto cert = mint_cert("CCL Key Mode Client", {"urn:test:ccl:key-mode"}, 2048);
  auto store = make_client_store("key_mode_store");
  set_app_cert(*store, cert);

  const auto keyPath = rsa_key_file_path(mStoreRoots["key_mode_store"]);
  ASSERT_TRUE(std::filesystem::exists(keyPath)) << "the store must have written the private key file";

#ifndef _WIN32
  const auto perms = std::filesystem::status(keyPath).permissions();
  using std::filesystem::perms;
  EXPECT_EQ(perms & (perms::group_all | perms::others_all), perms::none)
    << "a private key file must not grant any group/other access";
  EXPECT_EQ(perms & perms::owner_read, perms::owner_read) << "owner must retain read";
  EXPECT_EQ(perms & perms::owner_write, perms::owner_write) << "owner must retain write";
#else
  GTEST_SUCCEED() << "POSIX file-mode invariant is a documented no-op on non-POSIX";
#endif
}

// A generated self-signed application-instance cert is genuinely self-signed: its embedded signature
// verifies against its own embedded public key (validated here without a server via the store's
// trust-list validation, which checks the self-signature), AND a real SignAndEncrypt OPN against a
// server that trusts it succeeds. Falsifier: an unsigned/tampered blob fails self-verification and
// is rejected.
// @verifies CL-SECADMIN-006
// @relation(CL-SECADMIN-006, scope=function)
TEST_F(ClientCertLifecycle, SelfSignedCertSignatureMatchesPublicKey)
{
  auto cert = mint_cert("CCL Self Signed Client", {"urn:test:ccl:self-signed"}, 2048);
  EXPECT_TRUE(cert.second->self_signed()) << "the generated application-instance cert is self-signed";

  // Unit-level: validating the cert against a trust list that contains only itself exercises the
  // self-signature verification (subject==issuer, signature over the embedded public key).
  auto validationStoreRoot = mTempDir / "self_signed_validation_store";
  std::filesystem::create_directories(validationStoreRoot);
  TrustListValidationOptions validationOptions;
  auto validationStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = validationStoreRoot, .validationOptions = validationOptions});
  validationStore->add_to_trusted_certificates_sync(cert.second);
  auto validation = validationStore->try_validate_certificate_sync(ua::test::make_validation_request(
    cert.second, /*additionalIssuerCertificates=*/{}, /*validationOptions=*/std::nullopt));
  EXPECT_THAT(validation, Good()) << "the self-signature must verify against the embedded public key";

  // Integration-level: the server accepts the self-signed cert on a real OPN.
  trust_on_server(cert.second);
  auto store = make_client_store("self_signed_store");
  set_app_cert(*store, cert);
  auto client = make_client(store);
  auto result = open_sign_encrypt(client);
  EXPECT_THAT(result, Good()) << "the server must accept the validly self-signed cert on OPN";
  close_if_open(result);
}

// Each Client presents the certificate from the store it was given at create - there is no built-in
// or shared cert. Client A's store cert is trusted by the server; Client B's is a different cert the
// server does NOT trust. A connects; B is rejected. Falsifier: a hard-coded/shared cert would make
// both behave identically.
// @verifies CL-SECADMIN-005
// @relation(CL-SECADMIN-005, scope=function)
TEST_F(ClientCertLifecycle, UsesCertificateStoreProvidedAtCreate)
{
  auto certA = mint_cert("CCL Client A", {"urn:test:ccl:client-a"}, 2048);
  auto certB = mint_cert("CCL Client B", {"urn:test:ccl:client-b"}, 2048);
  trust_on_server(certA.second);  // only A is trusted; B is deliberately left untrusted

  auto storeA = make_client_store("store_a");
  set_app_cert(*storeA, certA);
  auto clientA = make_client(storeA);

  auto storeB = make_client_store("store_b");
  set_app_cert(*storeB, certB);
  auto clientB = make_client(storeB);

  auto resultA = open_sign_encrypt(clientA);
  EXPECT_THAT(resultA, Good()) << "Client A must present its own (trusted) store cert";
  close_if_open(resultA);

  auto resultB = open_sign_encrypt(clientB);
  EXPECT_TRUE(resultB.is_bad())
    << "Client B must present its own (untrusted) store cert and be rejected - not a shared cert";
}

// ===========================================================================
// Runtime rotation rows (reconnect-DRIVEN rotation is blocked; see header -
// these pin the store-swap-then-next-connect analog on a single Client instance)
// ===========================================================================

// The private key can be rotated in the store without recreating the Client: the next OPN signs with
// the NEW key. Two certs share the SAME subject/SAN but carry DIFFERENT keys; the server trusts only
// the new one. The first OPN (old key) is rejected; after overwriting the store's key+cert with the
// new pair the SAME Client's next OPN succeeds. Falsifier: a key cached immutably at create would
// still present the old key and stay rejected.
//
// Blocked-unbuilt: the reconnect-DRIVEN rotation (ReconnectionFSM section 8.3 auto-reconnect on
// Cause::CertRotated / CL-RECONN-006) is not exercised - the single-shot harness has no reconnect
// drive. This pins the observable client-side analog (rotation picked up on the next explicit open).
// @verifies CL-SECADMIN-006
// @verifies CL-RECONN-006
// @relation(CL-RECONN-006, CL-SECADMIN-006, scope=function)
TEST_F(ClientCertLifecycle, KeyRotationDoesNotRequireRestart)
{
  const std::string subject = "CCL Rotating Key Client";
  const std::vector<std::string> san = {"urn:test:ccl:key-rotation"};
  auto oldPair = mint_cert(subject, san, 2048);
  auto newPair = mint_cert(subject, san, 2048);  // same identity, fresh key
  trust_on_server(newPair.second);  // server trusts only the NEW key's cert

  auto store = make_client_store("key_rotation_store");
  set_app_cert(*store, oldPair);
  auto client = make_client(store);

  auto before = open_sign_encrypt(client);
  EXPECT_TRUE(before.is_bad()) << "the old key's cert is untrusted and must be rejected";
  close_if_open(before);

  set_app_cert(*store, newPair);  // rotate the private key + cert in place - no Client recreate
  auto after = open_sign_encrypt(client);
  EXPECT_THAT(after, Good()) << "the next OPN must sign with the rotated key and be accepted";
  close_if_open(after);
}

// A brand-new own certificate injected into the store (admin swap) is presented on the next OPN. The
// store starts with cert A (untrusted by the server); after swapping in cert B (trusted) the SAME
// Client's next OPN presents B and is accepted. Falsifier: if the old cert bytes were cached the next
// OPN would still present A and be rejected.
//
// Blocked-unbuilt: the reconnect/renew-DRIVEN swap (ReconnectionFSM section 8.3) is not exercised by the
// single-shot harness. This pins the observable analog: the swap is accepted and the new cert is used
// on the next explicit connect.
// @verifies CL-SECADMIN-005
// @verifies CL-RECONN-006
// @relation(CL-RECONN-006, CL-SECADMIN-005, scope=function)
TEST_F(ClientCertLifecycle, RotatesCertificateViaStoreSwap)
{
  auto certA = mint_cert("CCL Pre-Swap Client", {"urn:test:ccl:pre-swap"}, 2048);
  auto certB = mint_cert("CCL Post-Swap Client", {"urn:test:ccl:post-swap"}, 2048);
  trust_on_server(certB.second);  // server trusts only the post-swap cert

  auto store = make_client_store("cert_swap_store");
  set_app_cert(*store, certA);
  auto client = make_client(store);

  auto before = open_sign_encrypt(client);
  EXPECT_TRUE(before.is_bad()) << "the pre-swap cert is untrusted and must be rejected";
  close_if_open(before);

  set_app_cert(*store, certB);  // admin injects a new own cert into the store
  auto after = open_sign_encrypt(client);
  EXPECT_THAT(after, Good()) << "the next OPN must present the swapped-in cert and be accepted";
  close_if_open(after);
}
