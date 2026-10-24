// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <boost/asio/ip/address.hpp>
#include <chrono>

#include "certificate_validation_request_helpers.h"
#include "test_utilities.h"
#include "ua_to_string.h"
#include <filesystem>
#include <future>
#include <boost/asio/thread_pool.hpp>
#include "certificate_store_test_backends.h"
#include "test_pki_helpers.h"

namespace fs = std::filesystem;
using namespace ua;
using namespace std::chrono_literals;

template<typename TBackend>
class CertificateStoreGenericNegativeTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = TBackend::create_crypto();
    // Unique per test instance so parallel shards sharing a cwd don't collide on this store.
    mRootPath = test_utils::unique_temp_path(std::string("cert_store_neg_") + std::string(TBackend::name));
    fs::remove_all(mRootPath);

    ua::TrustListValidationOptions opts{};
    mStore = TBackend::create_store(mRootPath, mThreadPool.get_executor(), mCrypto, opts);

    mPki = std::make_unique<TestPki>(mCrypto);

    mRootKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mRootCert = mPki->create_root_ca(mRootKeys);

    this->mStore->add_to_trusted_certificates_sync(mRootCert);
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
    if constexpr (TBackend::supportsFilesystem)
      fs::remove_all(mRootPath);
  }

  fs::path mRootPath;
  std::shared_ptr<const ua::Crypto> mCrypto;
  boost::asio::thread_pool mThreadPool;
  std::shared_ptr<ua::CertificateStore> mStore;
  std::unique_ptr<TestPki> mPki;
  shared_ptr<const AsymmetricKeyPair> mRootKeys;
  shared_ptr<const X509Certificate> mRootCert;
};

TYPED_TEST_SUITE(CertificateStoreGenericNegativeTests, Backends);

/// The negative tests that revoke through a generated CRL, instantiated only for the backends that
/// generate CRLs.
template<typename TBackend>
class CertificateStoreCrlNegativeTests : public CertificateStoreGenericNegativeTests<TBackend>
{};

TYPED_TEST_SUITE(CertificateStoreCrlNegativeTests, CrlGeneratingBackends);

// Covers SVR-SECADMIN-017 (coverage-audit retag).
TYPED_TEST(CertificateStoreCrlNegativeTests, TrustedCrlRevocation)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  // Initially valid
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_TRUE(status.is_good());

  // Create CRL and revoke leaf
  auto crl = this->mPki->create_crl(this->mRootCert, this->mRootKeys, {leaf->serial_number()});
  ASSERT_TRUE(crl != nullptr);

  // Add CRL to store
  auto addStatus = this->mStore->try_add_to_trusted_crls_sync(crl);
  EXPECT_TRUE(addStatus.is_good());

  // Now validation should fail with BadCertificateRevoked
  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  status = this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateRevoked);
}

TYPED_TEST(CertificateStoreCrlNegativeTests, RevocationUnknownLeafAndSuppression)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateRevocationUnknown);

  options.set(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown);
  status = this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_TRUE(status.is_good());
}

TYPED_TEST(CertificateStoreCrlNegativeTests, RevocationUnknownIssuerAndSuppression)
{
  auto intKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig intParams;
  intParams.subjectKeys = intKeys;
  intParams.issuerKeys = this->mRootKeys;
  intParams.issuer = this->mRootCert;
  intParams.subject.commonName = "Intermediate CA";
  intParams.serialNumber = "4001";
  intParams.basicConstraint.cA = true;
  intParams.keyUsage.keyCertSign = true;
  intParams.keyUsage.crlSign = true;
  intParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  intParams.from = DateTime::now();
  intParams.to = DateTime{intParams.from.value() + std::chrono::days{365}};

  auto intCert = this->mPki->create_cert(intParams);
  ASSERT_TRUE(this->mStore->try_add_to_issuer_certificates_sync(intCert).is_good());

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(
    leafKeys, intKeys, intCert, DateTime::now(), DateTime{DateTime::now().value() + std::chrono::days{10}});

  auto intCrl = this->mPki->create_crl(intCert, intKeys, {});
  ASSERT_TRUE(intCrl != nullptr);
  ASSERT_TRUE(this->mStore->try_add_to_issuer_crls_sync(intCrl).is_good());

  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateIssuerRevocationUnknown);

  options.set(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown);
  status = this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_TRUE(status.is_good());
}

TYPED_TEST(CertificateStoreGenericNegativeTests, RevocationOnlineOnlyNotSupported)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOnline};
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_EQ(status.status_code().as_status(), Status::BadNotSupported);
}

TYPED_TEST(CertificateStoreGenericNegativeTests, PathLengthExceeded)
{
  auto rootKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig rootParams;
  rootParams.subjectKeys = rootParams.issuerKeys = rootKeys;
  rootParams.subject.commonName = "Root CA PathLen 0";
  rootParams.serialNumber = "1001";
  rootParams.basicConstraint.cA = true;
  rootParams.basicConstraint.pathLength = 0;
  rootParams.keyUsage.keyCertSign = true;
  rootParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  rootParams.from = DateTime::now();
  rootParams.to = DateTime{rootParams.from.value() + std::chrono::days{365}};

  auto rootCert = this->mPki->create_cert(rootParams);

  auto intKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig intParams;
  intParams.subjectKeys = intKeys;
  intParams.issuerKeys = rootKeys;
  intParams.issuer = rootCert;
  intParams.subject.commonName = "Intermediate CA";
  intParams.serialNumber = "1002";
  intParams.basicConstraint.cA = true;
  intParams.keyUsage.keyCertSign = true;
  intParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  intParams.from = DateTime::now();
  intParams.to = DateTime{intParams.from.value() + std::chrono::days{365}};

  auto intCert = this->mPki->create_cert(intParams);

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(
    leafKeys, intKeys, intCert, DateTime::now(), DateTime{DateTime::now().value() + std::chrono::days{10}});

  fs::path subPath = this->mRootPath / "pathlen";
  auto store = TypeParam::create_store(subPath, this->mThreadPool.get_executor(), this->mCrypto, {});
  store->add_to_trusted_certificates_sync(rootCert);
  store->add_to_issuer_certificates_sync(intCert);

  // The fault is on the intermediate (an issuer), so Table 106 Certificate Usage reports the issuer
  // variant (owner decision 22.3).
  auto status =
    store->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateIssuerUseNotAllowed);
}

// Part 6 section 6.1 permits equal key lengths and signature priorities along an issuer edge.
// @verifies AC-SVR-SECADMIN-022-CHAIN-MONOTONICITY
// @relation(AC-SVR-SECADMIN-022-CHAIN-MONOTONICITY, scope=function)
TYPED_TEST(CertificateStoreGenericNegativeTests, MonotonicChainIsAccepted)
{
  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  EXPECT_TRUE(
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt))
      .is_good());
}

// @relation(AC-SVR-SECADMIN-022-CHAIN-MONOTONICITY, scope=function)
TYPED_TEST(CertificateStoreGenericNegativeTests, LeafKeyLongerThanIssuerIsRejectedWithRichDetail)
{
  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 4096);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  const auto result =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateChainKeyLengthIncreases");
}

// @relation(AC-SVR-SECADMIN-022-CHAIN-MONOTONICITY, scope=function)
TYPED_TEST(CertificateStoreGenericNegativeTests, LeafSignatureStrongerThanIssuerIsRejectedWithRichDetail)
{
  auto issuerKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig issuerParameters;
  issuerParameters.subjectKeys = issuerParameters.issuerKeys = issuerKeys;
  issuerParameters.subject.commonName = "SHA-1 root";
  issuerParameters.serialNumber = "1022";
  issuerParameters.basicConstraint.cA = true;
  issuerParameters.basicConstraint.pathLength = 0;
  issuerParameters.keyUsage.keyCertSign = true;
  issuerParameters.keyUsage.crlSign = true;
  issuerParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha1;
  issuerParameters.from = DateTime::now();
  issuerParameters.to = DateTime{issuerParameters.from.value() + std::chrono::days{365}};
  const auto issuer = this->mPki->create_cert(issuerParameters);
  this->mStore->add_to_trusted_certificates_sync(issuer);

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto leaf = this->mPki->create_leaf_cert(
    leafKeys, issuerKeys, issuer, DateTime::now(), DateTime{DateTime::now().value() + std::chrono::days{10}});

  const auto result =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateChainSignatureStrengthIncreases");
}

// @relation(AC-SVR-SECADMIN-008-URI-MISMATCH-NOT-SUPPRESSIBLE, scope=function)

// Covers SVR-SECADMIN-008 (coverage-audit retag).
TYPED_TEST(CertificateStoreGenericNegativeTests, MismatchedUri)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}},
    {"urn:wrong:uri"});

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, std::nullopt, "urn:right:uri", std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUriInvalid);
}

// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-01-SUPPRESSED-ERROR-CONTINUES, scope=function)
TYPED_TEST(CertificateStoreGenericNegativeTests, SuppressedExpiryDoesNotHideUriMismatch)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto now = DateTime::now();
  const auto expiredFrom = DateTime{now.value() - std::chrono::days{30}};
  const auto expiredTo = DateTime{now.value() - std::chrono::days{1}};
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    expiredFrom,
    expiredTo,
    {"urn:certificate:wrong-application"});

  TrustListValidationOptions options{TrustListValidationOptions::Bit::SuppressCertificateExpired};
  const auto result = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, options, "urn:expected:application", std::nullopt));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid)
    << "suppressing the earlier expiry error must continue to the non-suppressible URI check";
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateUriMismatch");
}

// @relation(AC-SVR-SECADMIN-019-ENDPOINT-HOSTNAME-IN-CERT, scope=function)

TYPED_TEST(CertificateStoreGenericNegativeTests, MismatchedHostName)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(clientKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}},
    {},
    {"wronghost"});

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, std::nullopt, std::nullopt, "opc.tcp://righthost:4840"));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateHostNameInvalid);

  TrustListValidationOptions options;
  options.set(TrustListValidationOptions::Bit::SuppressHostNameInvalid);
  status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, options, std::nullopt, "opc.tcp://righthost:4840"));
  EXPECT_TRUE(status.is_good());
}

// Covers SVR-SECADMIN-024 (coverage-audit retag).
TYPED_TEST(CertificateStoreGenericNegativeTests, IntermediateMissingCABit)
{
  auto intKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig intParams;
  intParams.subjectKeys = intKeys;
  intParams.issuerKeys = this->mRootKeys;
  intParams.issuer = this->mRootCert;
  intParams.subject.commonName = "Not A CA";
  intParams.serialNumber = "2001";
  intParams.basicConstraint.cA = false;
  intParams.keyUsage.digitalSignature = true;
  intParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  intParams.from = DateTime::now();
  intParams.to = DateTime{intParams.from.value() + std::chrono::days{365}};

  auto intCert = this->mPki->create_cert(intParams);
  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(
    leafKeys, intKeys, intCert, DateTime::now(), DateTime{DateTime::now().value() + std::chrono::days{10}});

  this->mStore->add_to_issuer_certificates_sync(intCert);

  // An intermediate without cA TRUE: Table 106 Certificate Usage on an issuer, the issuer variant
  // (Part 6 Table 45; owner decision 22.3).
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateIssuerUseNotAllowed);
}

TYPED_TEST(CertificateStoreGenericNegativeTests, LeafMissingDigitalSignature)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  Crypto::CreateCertificateConfig p;
  p.subjectKeys = clientKeys;
  p.issuerKeys = this->mRootKeys;
  p.issuer = this->mRootCert;
  p.subject.commonName = "No Signature Bit";
  p.serialNumber = "3001";
  p.keyUsage.digitalSignature = false;
  p.keyUsage.keyEncipherment = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{10}};

  auto leaf = this->mPki->create_cert(p);
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateUseNotAllowed);
}

// Covers SVR-SECADMIN-007 (coverage-audit retag).
TYPED_TEST(CertificateStoreGenericNegativeTests, LeafExpiredAndSuppression)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto past = DateTime{now.value() - std::chrono::days{30}};
  auto past2 = DateTime{now.value() - std::chrono::days{1}};
  auto expiredLeaf = this->mPki->create_leaf_cert(clientKeys, this->mRootKeys, this->mRootCert, past, past2);

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(expiredLeaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateTimeInvalid);

  TrustListValidationOptions options{TrustListValidationOptions::Bit::SuppressCertificateExpired};
  status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(expiredLeaf, {}, options));
  EXPECT_TRUE(status.is_good());
}

TYPED_TEST(CertificateStoreGenericNegativeTests, LeafNotYetValid)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto now = DateTime::now();
  auto future = DateTime{now.value() + std::chrono::days{10}};
  auto future2 = DateTime{now.value() + std::chrono::days{20}};
  auto notYetValidLeaf =
    this->mPki->create_leaf_cert(clientKeys, this->mRootKeys, this->mRootCert, future, future2);

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(notYetValidLeaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateTimeInvalid);
}

TYPED_TEST(CertificateStoreGenericNegativeTests, IssuerExpiredAndSuppression)
{
  auto intKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig intParams;
  intParams.subjectKeys = intKeys;
  intParams.issuerKeys = this->mRootKeys;
  intParams.issuer = this->mRootCert;
  intParams.subject.commonName = "Intermediate CA";
  intParams.serialNumber = "300";
  intParams.basicConstraint.cA = true;
  intParams.keyUsage.keyCertSign = true;
  intParams.keyUsage.crlSign = true;
  intParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  auto now = DateTime::now();
  intParams.from = DateTime{now.value() - std::chrono::days{20}};
  intParams.to = DateTime{now.value() - std::chrono::days{10}};

  auto intCert = this->mPki->create_cert(intParams);
  ASSERT_TRUE(this->mStore->try_add_to_issuer_certificates_sync(intCert).is_good());

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    intKeys,
    intCert,
    DateTime{now.value() - std::chrono::days{5}},
    DateTime{now.value() + std::chrono::days{5}});

  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, std::nullopt));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateIssuerTimeInvalid);

  TrustListValidationOptions options{TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired};
  status = this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));
  EXPECT_TRUE(status.is_good());
}

// ---------------------------------------------------------------------------
// Self-signed certificate CRL exemption (Part 4 section 6.1.3, Part 6 Annex E.6)
// ---------------------------------------------------------------------------

TYPED_TEST(CertificateStoreGenericNegativeTests, SelfSignedCertNotRejectedForMissingCrl)
{
  // Self-signed certificates are trusted by direct inclusion in the trust store
  // and revoked by removal - they have no issuing CA and therefore no CRL.
  // CheckRevocationStatusOffline must not cause validation failure for them.

  // A self-signed application certificate: validated as an ApplicationInstance Certificate, so it
  // carries the OPC 10000-6 Table 43 bits (and keyCertSign, as its cA is TRUE).
  auto selfSignedKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto selfSigned =
    this->mPki->create_self_signed_application_root(selfSignedKeys, "Self-Signed App", "9001");
  ASSERT_TRUE(selfSigned->self_signed());

  this->mStore->add_to_trusted_certificates_sync(selfSigned);

  // Without CRL checking - should pass.
  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(selfSigned, {}, std::nullopt));
  EXPECT_TRUE(status.is_good()) << "Self-signed cert should pass without CRL checking";

  // With offline CRL checking - should still pass (no CRL required for self-signed).
  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(selfSigned, {}, options));
  EXPECT_TRUE(status.is_good())
    << "Self-signed cert should pass with CheckRevocationStatusOffline (no CRL required)";
}

TYPED_TEST(CertificateStoreCrlNegativeTests, SelfSignedRootCaCrlExemptionDoesNotAffectLeaf)
{
  // When a CA-issued leaf has no CRL but the self-signed root CA also has no CRL,
  // only the root CA should be exempt - the leaf's missing CRL should still be reported.

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = this->mPki->create_leaf_cert(leafKeys,
    this->mRootKeys,
    this->mRootCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{10}});

  // No CRL provided for either the root CA or the leaf.
  TrustListValidationOptions options{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  auto status =
    this->mStore->try_validate_certificate_sync(ua::test::make_validation_request(leaf, {}, options));

  // The leaf's CRL is missing - this should still fail.
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateRevocationUnknown)
    << "CA-issued leaf with missing CRL should still fail even though root CA is self-signed";
}

// ---------------------------------------------------------------------------
// Table 106 first-failing-step ordering (Part 4, 6.1.3): the engine halts on
// the first failing step and surfaces THAT step's status, never a later one.
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-003
// @relation(CL-SECADMIN-003, scope=function)
TYPED_TEST(CertificateStoreGenericNegativeTests, ValidationHaltsOnFirstFailingStepTrustBeforeValidity)
{
  // A leaf that fails TWO Table 106 steps at once - the Build Certificate Chain step (its issuing CA is
  // absent from the store's trust and issuer material) AND the validity-period step (it is expired) - must
  // report the EARLIER chain step. The sibling LeafExpiredAndSuppression test proves the validity
  // step DOES fire (BadCertificateTimeInvalid) once the chain reaches a trusted anchor, so surfacing
  // BadCertificateChainIncomplete here can only mean the engine halted before ever reaching that step.
  auto now = DateTime::now();

  // An issuing CA deliberately NOT added to the store's trusted or issuer sets.
  auto untrustedCaKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto untrustedCa = this->mPki->create_root_ca(untrustedCaKeys, "Untrusted CA", "7001");

  auto leafKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expiredUntrustedLeaf = this->mPki->create_leaf_cert(leafKeys,
    untrustedCaKeys,
    untrustedCa,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}});

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(expiredUntrustedLeaf, {}, std::nullopt));

  // The earlier chain step wins; the later validity-period error must never be surfaced.
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateChainIncomplete);
  EXPECT_NE(status.status_code().as_status(), Status::BadCertificateTimeInvalid);
}

// ---------------------------------------------------------------------------
// Table 106 (Part 4, 6.1.3): "Each validation step has a unique error status."
// This is the UNIQUE-STATUS-per-step facet of CL-SECADMIN-003 (its sibling
// first-failing-step ORDERING facet is covered by the TYPED_TEST above,
// ValidationHaltsOnFirstFailingStepTrustBeforeValidity). A plain TEST on the
// concrete OpenSSL-files backend so the requirement carries a coverage-checker
// -visible citation (the checker does not recognise TYPED_TEST macros).
//
// Three single-fault leaves, each failing exactly ONE distinct Table 106 step,
// must each report its OWN, step-specific status, and those statuses must be
// pairwise distinct:
//   - chain step            -> BadCertificateChainIncomplete (issuer in neither list)
//   - trust step            -> BadCertificateUntrusted   (complete chain, nothing in it trusted)
//   - validity-period step  -> BadCertificateTimeInvalid (expired, trusted issuer)
//   - revocation step       -> BadCertificateRevoked     (trusted + in-date, on CRL)
//
// Falsifiable: an engine that collapsed every failure to one generic status
// (e.g. BadSecurityChecksFailed) would fail both the per-status equalities and
// the pairwise-distinct assertions; swapping any two steps' statuses fails the
// matching equality.
// ---------------------------------------------------------------------------

// @verifies CL-SECADMIN-003
// @relation(CL-SECADMIN-003, scope=function)
TEST(CertificateStorePerStepStatusTests, EachValidationStepReportsUniqueStatus)
{
  boost::asio::thread_pool pool;
  auto crypto = BackendOpenSslFiles::create_crypto();
  auto root = test_utils::unique_temp_path("cert_store_perstep_status");
  fs::remove_all(root);
  auto store = BackendOpenSslFiles::create_store(root, pool.get_executor(), crypto, {});

  TestPki pki{crypto};
  auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto rootCert = pki.create_root_ca(rootKeys);
  store->add_to_trusted_certificates_sync(rootCert);

  const auto now = DateTime::now();

  // Step 1 (Build Certificate Chain): the leaf's issuing CA is in neither the trust nor the issuer list.
  auto untrustedCaKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto untrustedCa = pki.create_root_ca(untrustedCaKeys, "Untrusted CA", "9001");
  auto untrustedLeafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto untrustedLeaf = pki.create_leaf_cert(
    untrustedLeafKeys, untrustedCaKeys, untrustedCa, now, DateTime{now.value() + std::chrono::days{10}});
  const auto chainStatus =
    store->try_validate_certificate_sync(ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt))
      .status_code()
      .as_status();

  // Step 1b (Trust List Check): a self-signed certificate is its own complete chain, and nothing in it is
  // in the trust list.
  auto unknownSelfSignedKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto unknownSelfSigned = pki.create_root_ca(unknownSelfSignedKeys, "Unknown Self-Signed", "9003");
  const auto trustStatus =
    store
      ->try_validate_certificate_sync(ua::test::make_validation_request(unknownSelfSigned, {}, std::nullopt))
      .status_code()
      .as_status();

  // Step 2 (validity period): issued by the TRUSTED root (trust step passes) but expired.
  auto expiredLeafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto expiredLeaf = pki.create_leaf_cert(expiredLeafKeys,
    rootKeys,
    rootCert,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}});
  const auto validityStatus =
    store->try_validate_certificate_sync(ua::test::make_validation_request(expiredLeaf, {}, std::nullopt))
      .status_code()
      .as_status();

  // Step 3 (revocation): trusted issuer and in-date (trust + validity pass) but on the CRL.
  auto revokedLeafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto revokedLeaf = pki.create_leaf_cert(
    revokedLeafKeys, rootKeys, rootCert, now, DateTime{now.value() + std::chrono::days{10}});
  auto crl = pki.create_crl(rootCert, rootKeys, {revokedLeaf->serial_number()});
  ASSERT_TRUE(store->try_add_to_trusted_crls_sync(crl).is_good());
  TrustListValidationOptions revocationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  const auto revocationStatus =
    store->try_validate_certificate_sync(
           ua::test::make_validation_request(revokedLeaf, {}, revocationOptions))
      .status_code()
      .as_status();

  // Each step reports its own, step-specific status ...
  EXPECT_EQ(chainStatus, Status::BadCertificateChainIncomplete);
  EXPECT_EQ(trustStatus, Status::BadCertificateUntrusted);
  EXPECT_EQ(validityStatus, Status::BadCertificateTimeInvalid);
  EXPECT_EQ(revocationStatus, Status::BadCertificateRevoked);

  // ... and those statuses are pairwise DISTINCT (the "unique error status" property).
  EXPECT_NE(chainStatus, trustStatus);
  EXPECT_NE(chainStatus, validityStatus);
  EXPECT_NE(chainStatus, revocationStatus);
  EXPECT_NE(trustStatus, validityStatus);
  EXPECT_NE(trustStatus, revocationStatus);
  EXPECT_NE(validityStatus, revocationStatus);

  ::ua::test_utils::drain_with_timeout(pool);
  fs::remove_all(root);
}

// An IPv6 endpoint URL carries a bracketed literal (opc.tcp://[::1]:4840). The host-name check reads the
// address the brackets enclose and matches it against the IP SANs; cutting at the first ':' left "["
// and failed every IPv6 endpoint closed (security review B3-12).
// @verifies AC-SVR-SECADMIN-019-AN-IPV6-LITERAL-ENDPOINT-HOST-IS-MATCHED-AGAINST-THE-IP-SANS
TYPED_TEST(CertificateStoreGenericNegativeTests, AnIPv6LiteralEndpointHostIsMatchedAgainstTheIpSans)
{
  auto clientKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = clientKeys;
  p.issuerKeys = this->mRootKeys;
  p.subject.commonName = "IPv6 Leaf";
  p.serialNumber = std::to_string(DateTime::now().value().time_since_epoch().count());
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{DateTime::now().value() + std::chrono::days{10}};
  p.issuer = this->mRootCert;
  p.subjectAlternateName.ipAddresses = {boost::asio::ip::make_address("::1")};
  auto leaf = this->mPki->create_cert(p);
  ASSERT_NE(leaf, nullptr);

  auto status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, std::nullopt, std::nullopt, "opc.tcp://[::1]:4840"));
  EXPECT_TRUE(status.is_good()) << "the literal inside the brackets matches the IP SAN: "
                                << to_string(status.status_code());

  // Control: a different IPv6 literal still fails the host-name check.
  status = this->mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, std::nullopt, std::nullopt, "opc.tcp://[::2]:4840"));
  EXPECT_EQ(status.status_code().as_status(), Status::BadCertificateHostNameInvalid);
}
