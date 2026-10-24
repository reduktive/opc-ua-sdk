// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::validate_own_application_certificate - the create-time own
// ApplicationInstance certificate preconditions (section 10.2 / OPC UA Part 6 section 6.2.2). These drive the
// validation function directly with shaped certificates, bypassing the Client / store round-trip, so
// each precondition (and its source-tagged ErrorDetail) is proven in isolation.

#include <gtest/gtest.h>

#include "ua_client_own_cert_validation.h"

#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"

#include "test_utilities.h"

#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client::detail;

namespace
{

using CertPair = std::pair<std::shared_ptr<const AsymmetricKeyPair>, std::shared_ptr<const X509Certificate>>;

class OwnCertValidation : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // A private-key credential callback is required so the OpenSSL backend can encrypt the generated
    // PEM private key (create_asymmetric_key_pair / create_certificate fail without one).
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    ASSERT_TRUE(mCrypto);
  }

  // A conformant self-signed application-instance cert via the SDK generator (digitalSignature,
  // keyEncipherment, dataEncipherment, keyCertSign all set; 2048-bit RSA).
  CertPair mint_valid(std::vector<std::string> sanUris)
  {
    Crypto::Name name;
    name.commonName = "OwnCertValidation Valid";
    Crypto::SubjectAlternateName san;
    san.hostnames.push_back("localhost");
    san.uris = std::move(sanUris);
    auto result = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      name, UtcTime{2050, 1, 1, 0, 0, 0}, san, CertificateType::RsaSha256Application, 2048);
    EXPECT_TRUE(result.is_good()) << "valid cert generation must succeed";
    return std::move(result).value();
  }

  // A self-signed RSA cert with a caller-controlled keyUsage set + key length (used to shape defects
  // the app-instance generator would not produce). basicConstraints CA tracks keyCertSign.
  // `ca` marks the certificate cA TRUE (pathLength 0) even without keyCertSign; a keyCertSign certificate
  // is always cA TRUE (RFC 5280 4.2.1.9 forbids keyCertSign without cA).
  CertPair mint_custom(const std::string& commonName, std::vector<std::string> sanUris, std::size_t keyBits,
    const Crypto::KeyUsage& keyUsage, bool ca = false)
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, keyBits);
    Crypto::CreateCertificateConfig params;
    params.serialNumber = "1";
    params.subject.commonName = commonName;
    params.subjectKeys = keys;
    params.issuerKeys = keys;  // self-signed
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
    EXPECT_TRUE(result.is_good()) << "custom cert generation must succeed";
    return {keys, std::move(result).value()};
  }

  // A self-signed ECC (NIST P-256) cert with a caller-controlled keyUsage set. A conformant ECC
  // application-instance cert uses digitalSignature [+keyAgreement] and legitimately omits
  // keyEncipherment/dataEncipherment (an ECC key cannot do RSA-style key/data transport), so this
  // shapes the key-type-dependent keyUsage the app-instance generator (which sets every bit) cannot.
  CertPair mint_ecc_custom(
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
    EXPECT_TRUE(result.is_good()) << "ECC custom cert generation must succeed";
    return {keys, std::move(result).value()};
  }

  static Crypto::KeyUsage full_app_key_usage()
  {
    Crypto::KeyUsage keyUsage;
    keyUsage.digitalSignature = true;
    keyUsage.keyEncipherment = true;
    keyUsage.dataEncipherment = true;
    keyUsage.nonRepudiation = true;  // OPC 10000-4 Table 43
    keyUsage.keyCertSign = true;
    return keyUsage;
  }

  // The conformant ECC application-instance keyUsage: digitalSignature + keyAgreement, with keyCertSign
  // set so the self-signed check (#5) is satisfied. Deliberately NO keyEncipherment/dataEncipherment.
  static Crypto::KeyUsage conformant_ecc_key_usage()
  {
    Crypto::KeyUsage keyUsage;
    keyUsage.digitalSignature = true;
    keyUsage.keyAgreement = true;
    keyUsage.keyCertSign = true;
    return keyUsage;
  }

  std::shared_ptr<const Crypto> mCrypto;
};

// A conformant self-signed 2048-bit cert whose SAN URI equals the applicationUri passes every check.
TEST_F(OwnCertValidation, ValidCertificatePasses)
{
  auto cert = mint_valid({"urn:test:own:valid"});
  auto result = validate_own_application_certificate("urn:test:own:valid", *cert.second);
  EXPECT_TRUE(result.is_good()) << "a conformant own cert must pass";
}

// #1: no SAN URI at all -> BadCertificateUriInvalid, OwnCertificateSanUriMissing.
TEST_F(OwnCertValidation, RejectsCertificateWithNoSanUri)
{
  auto cert = mint_custom("No SAN URI", /*sanUris=*/{}, 2048, full_app_key_usage());
  ASSERT_TRUE(cert.second->san_uris().empty());

  auto result = validate_own_application_certificate("urn:test:own:app", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUriInvalid});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateSanUriMissing");
  EXPECT_EQ(result.shared_detail()->source, "client.create.own_cert.san_uri_missing");
}

// #2: the configured applicationUri must appear exactly among the certificate's SAN URIs.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(OwnCertValidation, RejectsCertificateWhoseSanUrisDoNotContainApplicationUri)
{
  auto cert = mint_valid({"urn:test:own:other", "urn:test:own:also-other"});

  auto result = validate_own_application_certificate("urn:test:own:expected", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUriInvalid});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateApplicationUriMismatch");
  EXPECT_EQ(result.shared_detail()->source, "client.create.own_cert.application_uri_mismatch");
  const auto formatted = ua::to_string(*result.shared_detail());
  EXPECT_NE(formatted.find("urn:test:own:expected"), std::string::npos);
  EXPECT_NE(formatted.find("urn:test:own:other"), std::string::npos);
  EXPECT_NE(formatted.find("urn:test:own:also-other"), std::string::npos);
}

// URI equality is exact: changing case identifies a different URI/application.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(OwnCertValidation, ApplicationUriComparisonIsCaseSensitive)
{
  auto cert = mint_valid({"urn:test:own:Client"});
  auto result = validate_own_application_certificate("urn:test:own:client", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateApplicationUriMismatch");
}

// Additional SAN URIs are permitted as long as one entry binds the configured application.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(OwnCertValidation, AcceptsApplicationUriAmongMultipleSanUris)
{
  auto cert = mint_valid({"urn:test:own:alias", "urn:test:own:expected"});
  EXPECT_TRUE(validate_own_application_certificate("urn:test:own:expected", *cert.second).is_good());
}

// #3: missing keyEncipherment -> BadCertificateUseNotAllowed, OwnCertificateKeyUsageInvalid naming the bit.
TEST_F(OwnCertValidation, RejectsCertificateMissingKeyEncipherment)
{
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.dataEncipherment = true;
  keyUsage.keyCertSign = true;  // keep self-signed check happy
  keyUsage.keyEncipherment = false;
  auto cert = mint_custom("Missing KeyEncipherment", {"urn:test:own:ku"}, 2048, keyUsage);

  auto result = validate_own_application_certificate("urn:test:own:ku", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUseNotAllowed});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateKeyUsageInvalid");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::bitName.value()),
    "keyEncipherment");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::expected.value()),
    "digitalSignature, keyEncipherment and dataEncipherment are all required for an RSA key");
}

// #3 (variant): OPC 10000-4 Table 43 - an RSA ApplicationInstance certificate without nonRepudiation is
// refused, naming the bit. Control: ValidCertificatePasses (the generator sets every bit).
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(OwnCertValidation, RejectsRsaCertificateMissingNonRepudiation)
{
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.keyCertSign = true;
  keyUsage.nonRepudiation = false;
  auto cert = mint_custom("Missing NonRepudiation", {"urn:test:own:ku"}, 2048, keyUsage);

  auto result = validate_own_application_certificate("urn:test:own:ku", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUseNotAllowed});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateKeyUsageInvalid");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::bitName.value()),
    "nonRepudiation");
}

// #3 (variant): missing digitalSignature is named as the first missing bit.
TEST_F(OwnCertValidation, RejectsCertificateMissingDigitalSignatureNamingThatBit)
{
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = false;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.keyCertSign = true;
  auto cert = mint_custom("Missing DigitalSignature", {"urn:test:own:ku2"}, 2048, keyUsage);

  auto result = validate_own_application_certificate("urn:test:own:ku2", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateKeyUsageInvalid");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::bitName.value()),
    "digitalSignature");
}

// #3 (key-type gate): a conformant ECC application-instance cert uses digitalSignature [+keyAgreement]
// and legitimately omits keyEncipherment/dataEncipherment (an ECC key cannot do RSA-style key/data
// transport). The keyUsage check is key-type-dependent (Part 6 section 6.2.2 / CL-SECADMIN-010), so such a
// cert must PASS - it is not rejected for the absent RSA-only bits.
TEST_F(OwnCertValidation, AcceptsConformantEccCertificateWithoutKeyEncipherment)
{
  auto cert = mint_ecc_custom("Conformant ECC", {"urn:test:own:ecc"}, conformant_ecc_key_usage());
  ASSERT_EQ(cert.second->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);
  ASSERT_TRUE(cert.second->key_usage_digital_signature());
  ASSERT_FALSE(cert.second->key_usage_key_encipherment()) << "fixture precondition: ECC cert omits keyEnc";

  auto result = validate_own_application_certificate("urn:test:own:ecc", *cert.second);
  EXPECT_TRUE(result.is_good())
    << "a conformant ECC own cert (digitalSignature[+keyAgreement], no keyEncipherment) must pass";
}

// #3 (ECC variant): an ECC cert missing digitalSignature fails, naming that bit.
TEST_F(OwnCertValidation, RejectsEccCertificateMissingDigitalSignature)
{
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = false;  // the deliberate defect
  keyUsage.keyAgreement = true;
  keyUsage.keyCertSign = true;  // keep the self-signed check happy
  auto cert = mint_ecc_custom("ECC No DigitalSignature", {"urn:test:own:ecc2"}, keyUsage);
  ASSERT_EQ(cert.second->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);

  auto result = validate_own_application_certificate("urn:test:own:ecc2", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUseNotAllowed});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateKeyUsageInvalid");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::bitName.value()),
    "digitalSignature");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::expected.value()),
    "digitalSignature is required for an ECC key");
}

// #4: RSA key below the Basic256Sha256 minimum -> BadCertificateInvalid, OwnCertificateKeyTooShort
// naming the policy and the observed length.
// @verifies CL-SECADMIN-010
// @relation(CL-SECADMIN-010, scope=function)
TEST_F(OwnCertValidation, RejectsRsaKeyBelowPolicyMinimum)
{
  auto cert = mint_custom("Short Key", {"urn:test:own:short"}, 1024, full_app_key_usage());
  ASSERT_EQ(cert.second->public_key_bit_length(), 1024u);

  auto result = validate_own_application_certificate("urn:test:own:short", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateInvalid});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateKeyTooShort");
  EXPECT_EQ(result.shared_detail()->source, "client.create.own_cert.key_too_short");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::securityPolicy.value()),
    "Basic256Sha256");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::actual.value()), "1024");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::min.value()), "2048");
}

// #5: self-signed with cA TRUE but without keyCertSign -> BadCertificateUseNotAllowed,
// OwnCertificateSelfSignedMissingKeyCertSign. Decision 25 (OPC 10000-6 Table 43 "Self-signed Certificates
// shall also include keyCertSign", applied where cA is TRUE only: RFC 5280 4.2.1.9 forbids keyCertSign
// without cA), so the stimulus is a cA TRUE self-signed certificate; a cA FALSE one needs no keyCertSign.
TEST_F(OwnCertValidation, RejectsSelfSignedCertificateWithoutKeyCertSign)
{
  Crypto::KeyUsage keyUsage;
  keyUsage.digitalSignature = true;
  keyUsage.keyEncipherment = true;
  keyUsage.dataEncipherment = true;
  keyUsage.nonRepudiation = true;  // OPC 10000-6 Table 43; the only defect is the missing keyCertSign
  keyUsage.serverAuth = true;
  keyUsage.clientAuth = true;
  keyUsage.keyCertSign = false;
  auto cert = mint_custom("No KeyCertSign", {"urn:test:own:nocs"}, 2048, keyUsage, /*ca=*/true);
  ASSERT_TRUE(cert.second->self_signed());
  ASSERT_TRUE(cert.second->basic_constraints_ca());
  ASSERT_FALSE(cert.second->key_usage_key_cert_sign());

  auto result = validate_own_application_certificate("urn:test:own:nocs", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateUseNotAllowed});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateSelfSignedMissingKeyCertSign");
  EXPECT_EQ(result.shared_detail()->source, "client.create.own_cert.self_signed_no_key_cert_sign");
}

// Missing SAN is reported by the more specific first check, not collapsed into mismatch.
// @verifies CL-SECADMIN-008
// @relation(CL-SECADMIN-008, scope=function)
TEST_F(OwnCertValidation, MissingSanPrecedesApplicationUriMismatch)
{
  auto cert = mint_custom("No SAN URI", /*sanUris=*/{}, 2048, full_app_key_usage());
  auto result = validate_own_application_certificate("urn:test:own:expected", *cert.second);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.shared_detail()->code, "OwnCertificateSanUriMissing");
}

}  // namespace
