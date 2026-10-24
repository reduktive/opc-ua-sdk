// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Completeness review (certificate coverage review, 2026-10-02), unit halves of C2, C11, C12 and C13,
// through a real CertificateStoreFiles and the ONE request builder every certificate field goes through
// (detail::make_validation_request, approved owner review 2026-10-02 (2)).
//
// Every expected status comes from the specification (OPC 10000-4 6.1.3 Table 106, OPC 10000-6 6.2.6,
// OPC 10000-12 7.8) or a stated SDK decision where the specification is silent - never from what the code
// happens to return. Keys come from the shared test key cache; the PKI is built once per suite.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>
#include <boost/asio/thread_pool.hpp>

#include "certificate_store_test_backends.h"
#include "certificate_validation_request_helpers.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "test_utilities.h"
#include "ua_certificate_store.h"
#include "ua_certificate_store_files.h"
#include "ua_certificate_validation_paths.h"
#include "ua_client_own_cert_validation.h"
#include "ua_crypto.h"
#include "ua_security_policy.h"
#include "ua_secure_channel_context.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"
#include "integration/helpers/sanitizer_budget.h"

namespace fs = std::filesystem;
using namespace ua;
using namespace std::chrono_literals;

namespace
{

using Certificates = std::vector<std::shared_ptr<const X509Certificate>>;

constexpr unsigned sameNameCandidates = 12;

struct CompletenessPki
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const AsymmetricKeyPair> rootKeys;
  std::shared_ptr<const X509Certificate> root;
  std::shared_ptr<const AsymmetricKeyPair> iaKeys;
  std::shared_ptr<const X509Certificate> ia;
  std::shared_ptr<const AsymmetricKeyPair> leafKeys;
  std::shared_ptr<const X509Certificate> leaf;  ///< issued by ia; host completeness.example
  std::shared_ptr<const X509Certificate> expiredLeaf;  ///< issued by root
  std::shared_ptr<const X509Certificate> revokedLeaf;  ///< issued by root, revoked by rootCrl
  std::shared_ptr<const X509Crl> rootCrl;
  std::shared_ptr<const X509Certificate> weakLeaf;  ///< RSA 1024 issued by root
  std::shared_ptr<const X509Certificate> untrustedSelfSigned;
  std::shared_ptr<const X509Certificate> wildcardLeaf;  ///< SAN DNS *.completeness.example, issued by root
  std::shared_ptr<const X509Certificate> notYetValidLeaf;  ///< notBefore now + 120 s
  std::shared_ptr<const X509Certificate> justExpiredLeaf;  ///< notAfter now - 120 s
  std::shared_ptr<const X509Certificate> justValidLeaf;  ///< now - 120 s .. now + 120 s
  Certificates sameNameCas;  ///< sameNameCandidates CAs named "Completeness Twin CA", issued by root
  std::shared_ptr<const X509Certificate> twinIssuedLeaf;  ///< issued by the LAST of sameNameCas
  std::shared_ptr<const X509Certificate> sha1OwnLeaf;  ///< RSA 2048 self-signed with SHA-1
  std::shared_ptr<const X509Certificate> p384OwnLeaf;  ///< P-384 self-signed, ECDSA SHA-384
  std::shared_ptr<const X509Certificate> p256OwnLeaf;  ///< P-256 self-signed, ECDSA SHA-256
  std::shared_ptr<const X509Certificate> serverOnlyLeaf;
  std::shared_ptr<const X509Certificate> clientOnlyLeaf;
  std::shared_ptr<const X509Certificate> noPurposeLeaf;
  std::shared_ptr<const X509Certificate> eccNoPurposeLeaf;
  std::shared_ptr<const X509Certificate> shortNameLeaf;
  std::shared_ptr<const X509Certificate> localNameLeaf;
  std::shared_ptr<const X509Certificate> bothNamesLeaf;
};

std::shared_ptr<const X509Certificate> make_ca(TestPki& pki, std::shared_ptr<const AsymmetricKeyPair> keys,
  std::shared_ptr<const AsymmetricKeyPair> issuerKeys, std::shared_ptr<const X509Certificate> issuer,
  const std::string& name, const std::string& serial)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = std::move(keys);
  p.issuerKeys = std::move(issuerKeys);
  p.issuer = std::move(issuer);
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  p.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
  return pki.create_cert(p);
}

std::shared_ptr<const X509Certificate> make_own_self_signed(TestPki& pki,
  std::shared_ptr<const AsymmetricKeyPair> keys, CertificateSignatureAlgorithm algorithm, bool ecc,
  const std::string& name)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = keys;
  p.subject.commonName = name;
  p.serialNumber = std::to_string(DateTime::now().value().time_since_epoch().count());
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = !ecc;
  p.keyUsage.dataEncipherment = !ecc;
  // A self-signed ApplicationInstance certificate in its usual form: cA TRUE with keyCertSign (Part 6
  // Table 43; owner decision 25).
  p.basicConstraint.cA = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = algorithm;
  p.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
  p.to = DateTime{DateTime::now().value() + std::chrono::days{365}};
  p.subjectAlternateName.uris = {"urn:completeness:own"};
  p.subjectAlternateName.hostnames = {"localhost"};
  return pki.create_cert(p);
}

std::unique_ptr<CompletenessPki> build_pki()
{
  auto pki = std::make_unique<CompletenessPki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = *pki->crypto;
  using test_keys::KeyType;
  const auto now = DateTime::now();
  const DateTime yesterday{now.value() - std::chrono::days{1}};
  const DateTime inThirtyDays{now.value() + std::chrono::days{30}};

  pki->rootKeys = test_keys::key_pair(crypto, KeyType::Rsa2048, 0);
  pki->root = helper.create_root_ca(pki->rootKeys, "Completeness Root", "9100");
  pki->iaKeys = test_keys::key_pair(crypto, KeyType::Rsa2048, 1);
  pki->ia = make_ca(helper, pki->iaKeys, pki->rootKeys, pki->root, "Completeness IA", "9101");
  pki->leafKeys = test_keys::key_pair(crypto, KeyType::Rsa2048, 2);
  pki->leaf = helper.create_leaf_cert(pki->leafKeys,
    pki->iaKeys,
    pki->ia,
    yesterday,
    inThirtyDays,
    {"urn:completeness:leaf"},
    {"completeness.example"},
    "Completeness Leaf");
  pki->expiredLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 3),
    pki->rootKeys,
    pki->root,
    DateTime{now.value() - std::chrono::days{30}},
    yesterday,
    {},
    {},
    "Completeness Expired");
  pki->revokedLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 4),
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {},
    {},
    "Completeness Revoked");
  pki->rootCrl = helper.create_crl(pki->root, pki->rootKeys, {pki->revokedLeaf->serial_number()});
  pki->weakLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa1024, 0),
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {},
    {},
    "Completeness Weak");
  const auto selfKeys = test_keys::key_pair(crypto, KeyType::Rsa2048, 5);
  pki->untrustedSelfSigned = helper.create_leaf_cert(
    selfKeys, selfKeys, nullptr, yesterday, inThirtyDays, {}, {}, "Completeness Untrusted");
  pki->wildcardLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 6),
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {},
    {"*.completeness.example"},
    "Completeness Wildcard");
  pki->notYetValidLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 7),
    pki->rootKeys,
    pki->root,
    DateTime{now.value() + std::chrono::seconds{120}},
    inThirtyDays,
    {},
    {},
    "Completeness Not Yet Valid");
  pki->justExpiredLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 8),
    pki->rootKeys,
    pki->root,
    yesterday,
    DateTime{now.value() - std::chrono::seconds{120}},
    {},
    {},
    "Completeness Just Expired");
  pki->justValidLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 9),
    pki->rootKeys,
    pki->root,
    DateTime{now.value() - std::chrono::seconds{120}},
    DateTime{now.value() + std::chrono::seconds{120}},
    {},
    {},
    "Completeness Just Valid");
  std::shared_ptr<const AsymmetricKeyPair> lastTwinKeys;
  for (unsigned i = 0; i < sameNameCandidates; ++i)
  {
    lastTwinKeys = test_keys::key_pair(crypto, KeyType::Rsa2048, 20 + i);
    pki->sameNameCas.push_back(make_ca(
      helper, lastTwinKeys, pki->rootKeys, pki->root, "Completeness Twin CA", std::to_string(9200 + i)));
  }
  pki->twinIssuedLeaf = helper.create_leaf_cert(test_keys::key_pair(crypto, KeyType::Rsa2048, 10),
    lastTwinKeys,
    pki->sameNameCas.back(),
    yesterday,
    inThirtyDays,
    {},
    {},
    "Completeness Twin Leaf");
  pki->sha1OwnLeaf = make_own_self_signed(helper,
    test_keys::key_pair(crypto, KeyType::Rsa2048, 11),
    CertificateSignatureAlgorithm::RsaPkcs15Sha1,
    false,
    "Completeness Own SHA-1");
  pki->p384OwnLeaf = make_own_self_signed(helper,
    test_keys::key_pair(crypto, KeyType::P384, 0),
    CertificateSignatureAlgorithm::EcDsaSha2384,
    true,
    "Completeness Own P-384");
  pki->p256OwnLeaf = make_own_self_signed(helper,
    test_keys::key_pair(crypto, KeyType::P256, 0),
    CertificateSignatureAlgorithm::EcDsaSha2256,
    true,
    "Completeness Own P-256");
  Crypto::CreateCertificateConfig purposeParameters;
  purposeParameters.subjectKeys = pki->leafKeys;
  purposeParameters.issuerKeys = pki->rootKeys;
  purposeParameters.issuer = pki->root;
  purposeParameters.subject.commonName = "Completeness Purpose Leaf";
  purposeParameters.subjectAlternateName.uris = {"urn:completeness:purpose"};
  purposeParameters.subjectAlternateName.hostnames = {"localhost"};
  purposeParameters.from = yesterday;
  purposeParameters.to = inThirtyDays;
  purposeParameters.basicConstraint.cA = false;
  purposeParameters.keyUsage.digitalSignature = true;
  purposeParameters.keyUsage.nonRepudiation = true;
  purposeParameters.keyUsage.keyEncipherment = true;
  purposeParameters.keyUsage.dataEncipherment = true;
  purposeParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  purposeParameters.serialNumber = "9301";
  purposeParameters.keyUsage.serverAuth = true;
  pki->serverOnlyLeaf = helper.create_cert(purposeParameters);
  purposeParameters.serialNumber = "9302";
  purposeParameters.keyUsage.serverAuth = false;
  purposeParameters.keyUsage.clientAuth = true;
  pki->clientOnlyLeaf = helper.create_cert(purposeParameters);
  purposeParameters.serialNumber = "9303";
  purposeParameters.keyUsage.clientAuth = false;
  pki->noPurposeLeaf = helper.create_cert(purposeParameters);
  purposeParameters.serialNumber = "9304";
  purposeParameters.subjectKeys = test_keys::key_pair(crypto, KeyType::P256, 0);
  purposeParameters.keyUsage.keyEncipherment = false;
  purposeParameters.keyUsage.dataEncipherment = false;
  pki->eccNoPurposeLeaf = helper.create_cert(purposeParameters);
  pki->shortNameLeaf = helper.create_leaf_cert(pki->leafKeys,
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {"urn:completeness:hostname"},
    {"controller"},
    "Completeness Short Host");
  pki->localNameLeaf = helper.create_leaf_cert(pki->leafKeys,
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {"urn:completeness:hostname"},
    {"controller.local"},
    "Completeness Local Host");
  pki->bothNamesLeaf = helper.create_leaf_cert(pki->leafKeys,
    pki->rootKeys,
    pki->root,
    yesterday,
    inThirtyDays,
    {"urn:completeness:hostname"},
    {"controller", "controller.local"},
    "Completeness Both Hosts");
  return pki;
}

ByteString field_of(const Certificates& certificates)
{
  std::vector<uint8_t> bytes;
  for (const auto& certificate : certificates)
  {
    const auto der = certificate->der_encoding();
    bytes.insert(bytes.end(), der.begin(), der.end());
  }
  return ByteString{std::move(bytes)};
}

ByteString raw_field(std::vector<uint8_t> bytes)
{
  return ByteString{std::move(bytes)};
}

class CertificateCompleteness : public ::testing::Test
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sPki = build_pki();
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sThreadPool);
    sThreadPool.reset();
    sPki.reset();
  }

protected:
  void SetUp() override
  {
    ASSERT_NE(sPki, nullptr);
    mRootPath = test_utils::unique_temp_path("cert_completeness");
    fs::remove_all(mRootPath);
  }

  void TearDown() override
  {
    for (const auto& store : mStores)
    {
      store->shutdown();
    }
    mStores.clear();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  /// A files store under @p name that records rejected certificates, for @p use, trusting the root.
  std::shared_ptr<CertificateStore> make_store(
    const std::string& name, CertificateUse use = CertificateUse::ApplicationInstance, bool trustRoot = true)
  {
    auto store = CertificateStoreFiles::create(
      sThreadPool->get_executor(), sPki->crypto, {.trustListPath = mRootPath / name, .use = use});
    if (trustRoot)
    {
      EXPECT_TRUE(store->try_add_to_trusted_certificates_sync(sPki->root).is_good());
      EXPECT_TRUE(store->try_add_to_trusted_crls_sync(sPki->rootCrl).is_good());
    }
    mStores.push_back(store);
    return store;
  }

  /// The rejected list after the store's asynchronous filing has had time to land.
  static Certificates rejected_after_settling(CertificateStore& store)
  {
    std::this_thread::sleep_for(test_utils::scaled(200ms));
    auto rejected = store.try_get_rejected_certificates_sync();
    EXPECT_TRUE(rejected.is_good());
    return rejected.is_good() ? rejected.value() : Certificates{};
  }

  static Status validate(CertificateStore& store, CertificateValidationRequest request)
  {
    return store.try_validate_certificate_sync(std::move(request)).status_code().as_status();
  }

  static std::unique_ptr<CompletenessPki> sPki;
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  fs::path mRootPath;
  std::vector<std::shared_ptr<CertificateStore>> mStores;
};

std::unique_ptr<CompletenessPki> CertificateCompleteness::sPki;

}  // namespace

namespace
{

const TrustListValidationOptions revocationOn{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};

// ---------------------------------------------------------------------------------------------------------
// C12: what the store files as rejected (OPC 10000-12 7.8.2 RejectedList: certificates refused because they
// are not trusted, so an administrator can choose to trust them). A certificate refused for a reason trusting
// it would not cure - expired, revoked, policy-violating - is not filed. Control: an untrusted one is.
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, AnUntrustedCertificateIsFiledAsRejected)
{
  auto store = make_store("untrusted");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->untrustedSelfSigned)),
    Status::BadCertificateUntrusted);
  const auto rejected = rejected_after_settling(*store);
  ASSERT_EQ(rejected.size(), 1u);
  EXPECT_EQ(rejected.front()->thumbprint(), sPki->untrustedSelfSigned->thumbprint());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, AnExpiredCertificateIsNotFiledAsRejected)
{
  auto store = make_store("expired");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->expiredLeaf)),
    Status::BadCertificateTimeInvalid);
  EXPECT_TRUE(rejected_after_settling(*store).empty());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, ARevokedCertificateIsNotFiledAsRejected)
{
  auto store = make_store("revoked");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->revokedLeaf, {}, revocationOn)),
    Status::BadCertificateRevoked);
  EXPECT_TRUE(rejected_after_settling(*store).empty());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, APolicyViolatingCertificateIsNotFiledAsRejected)
{
  auto store = make_store("policy");
  EXPECT_EQ(validate(*store,
              ua::test::make_validation_request_for(
                sPki->weakLeaf, {}, CertificateUse::ApplicationInstance, SecurityPolicyId::Basic256Sha256)),
    Status::BadCertificatePolicyCheckFailed);
  EXPECT_TRUE(rejected_after_settling(*store).empty());
}

// The request's public policyId asks for the Security Policy Check (Table 106 step 4); the certificate that
// fails it above passes every step when no policy is named.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-09-POLICY-KEY, scope=function)
TEST_F(CertificateCompleteness, AnEmptyPolicyIdAsksForNoPolicyCheck)
{
  auto store = make_store("nopolicy");
  EXPECT_EQ(validate(*store,
              ua::test::make_validation_request_for(
                sPki->weakLeaf, {}, CertificateUse::ApplicationInstance, std::nullopt)),
    Status::Good);
}

// A policyId that names no policy fails the check: no certificate can comply with a policy that does not
// exist. The certificate is one whose only fault is the policy it is checked against.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-09-POLICY-KEY, scope=function)
TEST_F(CertificateCompleteness, APolicyIdNamingNoPolicyFailsThePolicyCheck)
{
  auto store = make_store("unknownpolicy");
  for (const auto policyId : {SecurityPolicyId::Invalid,
         SecurityPolicyId::PubSubAes128Ctr,
         SecurityPolicyId::PubSubAes256Ctr,
         utils::from_underlying<SecurityPolicyId>(-1),
         utils::from_underlying<SecurityPolicyId>(100000)})
  {
    const auto result = store->try_validate_certificate_sync(ua::test::make_validation_request_for(
      sPki->weakLeaf, {}, CertificateUse::ApplicationInstance, policyId));
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificatePolicyCheckFailed});
    const auto detail = result.status_code().shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "UnknownSecurityPolicy");
    EXPECT_EQ(detail->source, "CertificateValidation");
    ASSERT_EQ(detail->context.size(), 1u);
    EXPECT_EQ(detail->context.front().key, ContextKeys::securityPolicy.value());
    EXPECT_EQ(detail->context.front().value, std::to_string(utils::to_underlying(policyId)));
  }
}

// A refused certificate presented with its chain: only the leaf is filed, never the presented issuers.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, AChainPresentedRefusalFilesOnlyTheLeaf)
{
  auto store = make_store("chain", CertificateUse::ApplicationInstance, false);
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->leaf, {sPki->ia, sPki->root})),
    Status::BadCertificateUntrusted);
  const auto rejected = rejected_after_settling(*store);
  ASSERT_EQ(rejected.size(), 1u) << "the presented issuers are not filed";
  EXPECT_EQ(rejected.front()->thumbprint(), sPki->leaf->thumbprint());
}

// A user-token refusal goes to the user-token group's rejected list (the store constructed for
// CertificateUse::User), not the application group's.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-92-REJECTED-FILING, scope=function)
TEST_F(CertificateCompleteness, AUserTokenRefusalIsFiledInTheUserTokenGroup)
{
  auto applicationStore = make_store("application");
  auto userStore = make_store("user", CertificateUse::User);
  EXPECT_EQ(validate(*userStore, ua::test::make_validation_request(sPki->untrustedSelfSigned)),
    Status::BadCertificateUntrusted);
  const auto userRejected = rejected_after_settling(*userStore);
  ASSERT_EQ(userRejected.size(), 1u);
  EXPECT_EQ(userRejected.front()->thumbprint(), sPki->untrustedSelfSigned->thumbprint());
  EXPECT_TRUE(rejected_after_settling(*applicationStore).empty());
}

// ---------------------------------------------------------------------------------------------------------
// C2: the files store keeps the own certificate's issuer chain (decision 24,
// ApplicationCertificate::issuerCertificates) and loads it again, in order, from its location.
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-82-OWN-CHAIN-LOAD, scope=function)
TEST_F(CertificateCompleteness, TheFilesStoreLoadsTheOwnCertificateIssuerChainInOrder)
{
  {
    auto writer = make_store("own", CertificateUse::ApplicationInstance, false);
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = sPki->leaf;
    own.keys = sPki->leafKeys;
    own.issuerCertificates = {sPki->ia, sPki->root};
    ASSERT_TRUE(writer->try_add_to_application_certificates_sync(own).is_good());
  }
  auto reader = make_store("own", CertificateUse::ApplicationInstance, false);
  const auto loaded = reader->try_get_application_certificates_sync();
  ASSERT_TRUE(loaded.is_good());
  ASSERT_EQ(loaded.value().size(), 1u);
  const auto& chain = loaded.value().front().issuerCertificates;
  ASSERT_EQ(chain.size(), 2u);
  EXPECT_EQ(chain[0]->thumbprint(), sPki->ia->thumbprint()) << "the leaf's issuer first";
  EXPECT_EQ(chain[1]->thumbprint(), sPki->root->thumbprint());
}

// ---------------------------------------------------------------------------------------------------------
// C11: resource limits and the chain parser. Every certificate field (CreateSession clientCertificate,
// X509IdentityToken certificateData, EccEncryptedSecret Certificate, OPN sender certificate) goes through the
// ONE builder (path wiring tests, AC -39); these drive the builder and the store with the field bytes a
// hostile peer produces and assert the verdict and that the call returns.
// ---------------------------------------------------------------------------------------------------------

Result<CertificateValidationRequest> build(const Crypto& crypto, const ByteString& field)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  return detail::make_validation_request(crypto, field, std::move(fields));
}

/// The first certificate's DER with its outer SEQUENCE length re-encoded in a non-minimal long form
/// (0x83 + three length octets) - legal BER, forbidden by DER (X.690 10.1).
ByteString leaf_with_non_minimal_length(const X509Certificate& certificate)
{
  const auto der = certificate.der_encoding();
  std::vector<uint8_t> bytes(der.begin(), der.end());
  // A certificate of this size is encoded 30 82 hh ll.
  EXPECT_EQ(bytes.at(1), 0x82);
  std::vector<uint8_t> out{0x30, 0x83, 0x00, bytes.at(2), bytes.at(3)};
  out.insert(out.end(), bytes.begin() + 4, bytes.end());
  return raw_field(std::move(out));
}

// DER (OPC 10000-6 6.2.6: certificate fields are DER) forbids a non-minimal long-form length.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-90-PARSER-LENGTH-FORMS, scope=function)
TEST_F(CertificateCompleteness, AFieldWithANonMinimalLongFormLengthIsCertificateInvalid)
{
  const auto request = build(*sPki->crypto, leaf_with_non_minimal_length(*sPki->leaf));
  EXPECT_EQ(request.status_code().as_status(), Status::BadCertificateInvalid);
}

// A one-octet long form (0x81) whose content is shorter than declared: refused, never read past the field.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-90-PARSER-LENGTH-FORMS, scope=function)
TEST_F(CertificateCompleteness, AFieldWithATruncatedOneOctetLongFormIsCertificateInvalid)
{
  const auto request = build(*sPki->crypto, raw_field({0x30, 0x81, 0xF0, 0x02, 0x01, 0x00}));
  EXPECT_EQ(request.status_code().as_status(), Status::BadCertificateInvalid);
}

// A three-octet long form (0x83) declaring 16 MiB in a six-byte field: refused without allocating it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-90-PARSER-LENGTH-FORMS, scope=function)
TEST_F(CertificateCompleteness, AFieldDeclaringMoreThanItHoldsIsCertificateInvalid)
{
  const auto request = build(*sPki->crypto, raw_field({0x30, 0x83, 0xFF, 0xFF, 0xFF, 0x00}));
  EXPECT_EQ(request.status_code().as_status(), Status::BadCertificateInvalid);
}

// The indefinite length (0x80) is BER only; DER forbids it (X.690 10.1).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-90-PARSER-LENGTH-FORMS, scope=function)
TEST_F(CertificateCompleteness, AFieldWithAnIndefiniteLengthIsCertificateInvalid)
{
  const auto der = sPki->leaf->der_encoding();
  std::vector<uint8_t> bytes{0x30, 0x80};
  bytes.insert(bytes.end(), der.begin() + 4, der.end());
  bytes.push_back(0x00);
  bytes.push_back(0x00);
  const auto request = build(*sPki->crypto, raw_field(std::move(bytes)));
  EXPECT_EQ(request.status_code().as_status(), Status::BadCertificateInvalid);
}

// A wide presented chain (the issuer repeated 500 times after the leaf) changes nothing about the verdict:
// with nothing trusted it is Untrusted, and the call returns within a bounded time.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-89-RESOURCE-BOUNDS, scope=function)
TEST_F(CertificateCompleteness, AWidePresentedChainIsRefusedInBoundedTime)
{
  Certificates presented{sPki->leaf};
  for (int i = 0; i < 500; ++i)
  {
    presented.push_back(sPki->ia);
  }
  presented.push_back(sPki->root);
  const auto request = build(*sPki->crypto, field_of(presented));
  ASSERT_TRUE(request.is_good()) << to_string(request.status_code().as_status());
  auto store = make_store("wide", CertificateUse::ApplicationInstance, false);
  const auto started = std::chrono::steady_clock::now();
  EXPECT_EQ(validate(*store, request.value()), Status::BadCertificateUntrusted);
  EXPECT_LT(std::chrono::steady_clock::now() - started, test_utils::scaled(std::chrono::milliseconds{10000}));
}

// Many CAs share the leaf's issuer name; only one signed it. Path building tries the candidates (Table 106
// Build Certificate Chain) and finds the one whose key verifies, in bounded time.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-89-RESOURCE-BOUNDS, scope=function)
TEST_F(CertificateCompleteness, ManySameNameCandidateIssuersStillBuildTheRightPath)
{
  Certificates presented = sPki->sameNameCas;
  auto store = make_store("twins");
  const auto started = std::chrono::steady_clock::now();
  EXPECT_EQ(
    validate(*store, ua::test::make_validation_request(sPki->twinIssuedLeaf, presented)), Status::Good);
  EXPECT_LT(std::chrono::steady_clock::now() - started, test_utils::scaled(std::chrono::milliseconds{10000}));
}

// Control for the same-name case: without the one CA that signed the leaf, no candidate verifies.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-89-RESOURCE-BOUNDS, scope=function)
TEST_F(CertificateCompleteness, SameNameCandidatesThatDidNotSignTheLeafAreChainIncomplete)
{
  Certificates presented(sPki->sameNameCas.begin(), sPki->sameNameCas.end() - 1);
  auto store = make_store("twins_without_signer");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->twinIssuedLeaf, presented)),
    Status::BadCertificateChainIncomplete);
}

// ---------------------------------------------------------------------------------------------------------
// C11 / U6 leftovers.
// ---------------------------------------------------------------------------------------------------------

// Order of the presented issuers. OPC 10000-6 6.2.6 tells the SENDER to order the chain; it states no
// receiver rule, and path building (RFC 4158) does not depend on order. SDK decision: a chain sent out of
// order still builds.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, APresentedChainInTheWrongOrderStillBuilds)
{
  auto store = make_store("order");
  EXPECT_EQ(
    validate(*store, ua::test::make_validation_request(sPki->leaf, {sPki->root, sPki->ia})), Status::Good);
}

// DNS wildcards. OPC 10000-4 6.1.3 (Host Name step) is silent about wildcards. SDK documented behaviour: a
// subjectAltName dNSName is matched literally, so "*.completeness.example" does not match a host under it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, ADnsWildcardDoesNotMatchAHostUnderIt)
{
  auto store = make_store("wildcard");
  EXPECT_EQ(validate(*store,
              ua::test::make_validation_request(sPki->wildcardLeaf,
                {},
                std::nullopt,
                std::nullopt,
                std::string{"opc.tcp://a.completeness.example:4840"})),
    Status::BadCertificateHostNameInvalid);
}

// Host names compare case-insensitively (RFC 4343, DNS names are case-insensitive).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, AHostNameDifferingOnlyInCaseMatches)
{
  auto store = make_store("case");
  EXPECT_EQ(validate(*store,
              ua::test::make_validation_request(sPki->leaf,
                {sPki->ia},
                std::nullopt,
                std::nullopt,
                std::string{"opc.tcp://COMPLETENESS.Example:4840"})),
    Status::Good);
}

// Validity boundaries at now +/- 120 s (Table 106 Validity Period).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, ACertificateValidFromTwoMinutesAheadIsTimeInvalid)
{
  auto store = make_store("not_yet");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->notYetValidLeaf)),
    Status::BadCertificateTimeInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, ACertificateExpiredTwoMinutesAgoIsTimeInvalid)
{
  auto store = make_store("just_expired");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->justExpiredLeaf)),
    Status::BadCertificateTimeInvalid);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-91-U6-LEFTOVERS, scope=function)
TEST_F(CertificateCompleteness, ACertificateValidTwoMinutesEitherSideOfNowIsGood)
{
  auto store = make_store("just_valid");
  EXPECT_EQ(validate(*store, ua::test::make_validation_request(sPki->justValidLeaf)), Status::Good);
}

// ---------------------------------------------------------------------------------------------------------
// C13: the client refuses to use its own certificate when it does not comply with the endpoint's
// SecurityPolicy (OPC 10000-7 profile database; Part 4 6.1.3 Security Policy Check applies to the
// certificate the application presents as much as to the one it receives).
// SEAM client::detail::check_own_certificate_for_endpoint(ownCertificate, signer, policy) in
// ua_client_own_cert_validation.h -> Bad_CertificatePolicyCheckFailed.
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-93-CLIENT-OWN-CERT-POLICY, scope=function)
TEST_F(CertificateCompleteness, TheClientRefusesItsOwnSha1CertificateForBasic256Sha256)
{
  const auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  const auto result =
    client::detail::check_own_certificate_for_endpoint(*sPki->sha1OwnLeaf, *sPki->sha1OwnLeaf, *policy);
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificatePolicyCheckFailed);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-93-CLIENT-OWN-CERT-POLICY, scope=function)
TEST_F(CertificateCompleteness, TheClientRefusesItsOwnP384CertificateForEccNistP256)
{
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto result =
    client::detail::check_own_certificate_for_endpoint(*sPki->p384OwnLeaf, *sPki->p384OwnLeaf, *policy);
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificatePolicyCheckFailed);
}

// Control: the compliant own certificate on its own policy is accepted.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-93-CLIENT-OWN-CERT-POLICY, scope=function)
TEST_F(CertificateCompleteness, TheClientAcceptsItsOwnP256CertificateForEccNistP256)
{
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  EXPECT_TRUE(
    client::detail::check_own_certificate_for_endpoint(*sPki->p256OwnLeaf, *sPki->p256OwnLeaf, *policy)
      .is_good());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-147-DNS-LABEL-PRESERVATION, scope=function)
TEST_F(CertificateCompleteness, TheValidatorPreservesTheLocalDnsLabelUnlessSuppressed)
{
  auto store = make_store("hostname_labels");
  for (const auto& [certificate, endpointUrl] :
    {std::pair{sPki->shortNameLeaf, std::string{"opc.tcp://controller.local:4840"}},
      std::pair{sPki->localNameLeaf, std::string{"opc.tcp://controller:4840"}}})
  {
    SCOPED_TRACE(endpointUrl);
    auto request = ua::test::make_validation_request_for(certificate,
      {},
      CertificateUse::ServerApplicationInstance,
      std::nullopt,
      TrustListValidationOptions{},
      std::nullopt,
      endpointUrl);
    const auto refused = store->try_validate_certificate_sync(request);
    EXPECT_EQ(refused.status_code(), Status::BadCertificateHostNameInvalid);

    request.options = TrustListValidationOptions{TrustListValidationOptions::Bit::SuppressHostNameInvalid};
    const auto suppressed = store->try_validate_certificate_sync(request);
    ASSERT_TRUE(suppressed.is_good());
    const auto faults = detail::suppressed_certificate_errors(suppressed);
    ASSERT_EQ(faults.size(), 1u);
    EXPECT_EQ(faults.front(), Status::BadCertificateHostNameInvalid);

    request.certificate = sPki->bothNamesLeaf;
    request.options = TrustListValidationOptions{};
    EXPECT_TRUE(store->try_validate_certificate_sync(request).is_good());
  }
  for (const auto& [certificate, endpointUrl] :
    {std::pair{sPki->shortNameLeaf, std::string{"opc.tcp://CONTROLLER.:4840"}},
      std::pair{sPki->localNameLeaf, std::string{"opc.tcp://CONTROLLER.LOCAL.:4840"}}})
  {
    EXPECT_TRUE(store
                  ->try_validate_certificate_sync(ua::test::make_validation_request_for(certificate,
                    {},
                    CertificateUse::ServerApplicationInstance,
                    std::nullopt,
                    TrustListValidationOptions{},
                    std::nullopt,
                    endpointUrl))
                  .is_good());
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-148-RSA-ROLE-PURPOSE, scope=function)
TEST_F(CertificateCompleteness, TheStoreRequiresTheRsaPurposeOfTheRequestedRole)
{
  auto store = make_store("role_purpose");
  for (const auto use :
    {CertificateUse::ServerApplicationInstance, CertificateUse::ClientApplicationInstance})
  {
    auto required = sPki->serverOnlyLeaf;
    auto opposite = sPki->clientOnlyLeaf;
    if (use == CertificateUse::ClientApplicationInstance)
    {
      std::swap(required, opposite);
    }
    for (const auto& certificate : {required, sPki->leaf})
    {
      EXPECT_TRUE(
        store
          ->try_validate_certificate_sync(ua::test::make_validation_request_for(
            certificate, {sPki->ia}, use, SecurityPolicyId::Basic256Sha256, TrustListValidationOptions{}))
          .is_good());
    }
    for (const auto& certificate : {opposite, sPki->noPurposeLeaf})
    {
      const auto refused = store->try_validate_certificate_sync(ua::test::make_validation_request_for(
        certificate, {}, use, SecurityPolicyId::Basic256Sha256, TrustListValidationOptions{}));
      EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
      auto cause = refused.shared_detail();
      while (cause && cause->code != "CertificateExtendedKeyUsageInvalid")
      {
        cause = cause->cause;
      }
      ASSERT_TRUE(cause) << "the trust validator must retain the role-specific usage failure";
    }
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-149-GENERIC-AND-ECC-PURPOSE, scope=function)
TEST_F(CertificateCompleteness, GenericUseAndEccOptionalPurposesRemainAccepted)
{
  auto store = make_store("generic_and_ecc_purpose");
  for (const auto& certificate : {sPki->serverOnlyLeaf, sPki->clientOnlyLeaf, sPki->leaf})
  {
    EXPECT_TRUE(store
                  ->try_validate_certificate_sync(ua::test::make_validation_request_for(certificate,
                    {sPki->ia},
                    CertificateUse::ApplicationInstance,
                    std::nullopt,
                    TrustListValidationOptions{}))
                  .is_good());
  }
  const auto refused =
    store->try_validate_certificate_sync(ua::test::make_validation_request_for(sPki->noPurposeLeaf,
      {},
      CertificateUse::ApplicationInstance,
      std::nullopt,
      TrustListValidationOptions{}));
  EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
  auto cause = refused.shared_detail();
  while (cause && cause->code != "CertificateExtendedKeyUsageInvalid")
  {
    cause = cause->cause;
  }
  ASSERT_TRUE(cause);
  for (const auto use :
    {CertificateUse::ServerApplicationInstance, CertificateUse::ClientApplicationInstance})
  {
    EXPECT_TRUE(store
                  ->try_validate_certificate_sync(ua::test::make_validation_request_for(
                    sPki->eccNoPurposeLeaf, {}, use, std::nullopt, TrustListValidationOptions{}))
                  .is_good());
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-150-OWN-CERTIFICATE-PURPOSE, scope=function)
TEST_F(CertificateCompleteness, TheClientOwnCertificateRequiresClientAuth)
{
  const auto refused = client::detail::validate_own_application_certificate(
    "urn:completeness:purpose", *sPki->serverOnlyLeaf, sPki->root.get());
  EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
  auto cause = refused.shared_detail();
  while (cause && cause->code != "CertificateExtendedKeyUsageInvalid")
  {
    cause = cause->cause;
  }
  ASSERT_TRUE(cause) << "the client own-certificate refusal must retain the role-specific usage failure";
  EXPECT_TRUE(client::detail::validate_own_application_certificate(
    "urn:completeness:purpose", *sPki->clientOnlyLeaf, sPki->root.get())
                .is_good());
  EXPECT_TRUE(
    client::detail::validate_own_application_certificate("urn:completeness:leaf", *sPki->leaf, sPki->ia.get())
      .is_good());
}

// The local role identifies the peer's purpose even when hostname verification is explicitly relaxed.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-151-CHANNEL-PEER-PURPOSE, scope=function)
TEST_F(CertificateCompleteness, TheChannelSelectsPeerPurposeIndependentlyOfHostnameRelaxation)
{
  auto store = make_store("channel_peer_purpose");
  const auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  for (const auto role : {ChannelRole::Client, ChannelRole::Server})
  {
    auto required = sPki->serverOnlyLeaf;
    auto opposite = sPki->clientOnlyLeaf;
    if (role == ChannelRole::Server)
    {
      std::swap(required, opposite);
    }
    for (const bool relaxHostname : {false, true})
    {
      for (const bool matchingPurpose : {false, true})
      {
        SecureChannelContext context;
        context.crypto = sPki->crypto;
        context.certStore = store;
        context.role = role;
        context.remoteCertificate = opposite;
        if (matchingPurpose)
        {
          context.remoteCertificate = required;
        }
        context.endpointUrl = "opc.tcp://localhost:4840";
        context.relaxHostNameCheck = relaxHostname;
        auto completion = std::make_shared<std::promise<VoidResult>>();
        auto future = completion->get_future();
        policy->validate_certificate_async(
          context, [completion](VoidResult result) { completion->set_value(std::move(result)); });
        const auto result = future.get();
        if (matchingPurpose)
        {
          EXPECT_TRUE(result.is_good());
          continue;
        }
        EXPECT_EQ(result.status_code(), Status::BadCertificateUseNotAllowed);
        auto cause = result.shared_detail();
        while (cause && cause->code != "CertificateExtendedKeyUsageInvalid")
        {
          cause = cause->cause;
        }
        ASSERT_TRUE(cause) << "the channel must forward the peer role independently of hostname relaxation";
      }
    }
  }
}

}  // namespace
