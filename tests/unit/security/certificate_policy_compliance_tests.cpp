// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// SecurityPolicy::check_certificate_compliance per policy family (owner review 2026-10-02, item 2): the one
// virtual the validator calls for every chain certificate at Table 106 step 4. One compliant and one refused
// case per rule, small by design - the U7 matrix (certificate_policy_and_error_matrix_tests.cpp) carries the
// exhaustive chains, positions and policies through the validator. The rules come from OPC 10000-7 (the
// profile database entries for each policy), not from the implementation:
//   RSA base - key length within [MinAsymmetricKeyLength, MaxAsymmetricKeyLength]; the certificate
//              signature algorithm one the policy permits (SHA-1 only where the policy permits it); an RSA
//              key. RSA_DH applies the same rules (2048 to 4096 bits, SHA-2).
//   ECDSA    - the end entity and the issuing CA on the policy curve; every higher CA on the policy curve
//              or the larger curve the profile allows; the ECDSA hash matches the SIGNER's curve; an ECC key.
//   EdDSA    - the policy curve and a pure EdDSA signature.
//   None     - no certificate requirement.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "certificate_store_test_backends.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_security_policy.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"

using namespace ua;

namespace
{

using Certificate = std::shared_ptr<const X509Certificate>;
using Keys = std::shared_ptr<const AsymmetricKeyPair>;

class CertificatePolicyCompliance : public ::testing::Test
{
public:
  static void SetUpTestSuite()
  {
    sCrypto = BackendOpenSslFiles::create_crypto();
  }

  static void TearDownTestSuite()
  {
    sCrypto.reset();
  }

protected:
  void SetUp() override
  {
    sNextSlot = 0;
  }

  /// A key of @p algorithm (and @p bits for RSA) from the shared test key cache; every call within a test
  /// takes the next slot, so no two keys of one test are the same key.
  static Keys keys(CertificateKeyAlgorithm algorithm, std::size_t bits = 0)
  {
    return test_keys::key_pair(*sCrypto, cache_type_of(algorithm, bits), sNextSlot++);
  }

  static test_keys::KeyType cache_type_of(CertificateKeyAlgorithm algorithm, std::size_t bits)
  {
    switch (algorithm)
    {
    case CertificateKeyAlgorithm::Rsa:
      switch (bits)
      {
      case 1024:
        return test_keys::KeyType::Rsa1024;
      case 2048:
        return test_keys::KeyType::Rsa2048;
      case 3072:
        return test_keys::KeyType::Rsa3072;
      case 4096:
        return test_keys::KeyType::Rsa4096;
      default:
        break;
      }
      break;
    case CertificateKeyAlgorithm::EccNistP256:
      return test_keys::KeyType::P256;
    case CertificateKeyAlgorithm::EccNistP384:
      return test_keys::KeyType::P384;
    case CertificateKeyAlgorithm::EccNistP521:
      return test_keys::KeyType::P521;
    case CertificateKeyAlgorithm::EccBrainpoolP256r1:
      return test_keys::KeyType::Bp256;
    case CertificateKeyAlgorithm::EccBrainpoolP384r1:
      return test_keys::KeyType::Bp384;
    case CertificateKeyAlgorithm::EccBrainpoolP512r1:
      return test_keys::KeyType::Bp512;
    case CertificateKeyAlgorithm::EccCurve25519:
      return test_keys::KeyType::Ed25519;
    case CertificateKeyAlgorithm::EccCurve448:
      return test_keys::KeyType::Ed448;
    case CertificateKeyAlgorithm::Invalid:
      break;
    }
    throw std::logic_error{"the test key cache has no key type for this algorithm and size"};
  }

  inline static unsigned sNextSlot = 0;

  /// A certificate for @p subject signed by @p issuerKeys with @p algorithm; self-signed when @p issuer is
  /// null.
  static Certificate certificate(const Keys& subject, const Keys& issuerKeys, const Certificate& issuer,
    CertificateSignatureAlgorithm algorithm, bool ca, const std::string& name)
  {
    TestPki pki{sCrypto};
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = subject;
    p.issuerKeys = issuerKeys;
    if (issuer)
    {
      p.issuer = issuer;
    }
    p.subject.commonName = name;
    p.serialNumber = std::to_string(++sSerial);
    p.basicConstraint.cA = ca;
    p.keyUsage.keyCertSign = ca;
    p.keyUsage.crlSign = ca;
    p.keyUsage.digitalSignature = !ca;
    p.certificateSignatureAlgorithm = algorithm;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{30}};
    return pki.create_cert(p);
  }

  /// A self-signed CA on @p caKeys and an end entity on @p leafKeys it signed with @p algorithm.
  struct Pair
  {
    Certificate signer;
    Certificate subject;
  };

  static Pair issued(const Keys& caKeys, CertificateSignatureAlgorithm caSelf, const Keys& leafKeys,
    CertificateSignatureAlgorithm algorithm, bool leafIsCa = false)
  {
    const auto ca = certificate(caKeys, caKeys, nullptr, caSelf, true, "Compliance CA");
    return {ca, certificate(leafKeys, caKeys, ca, algorithm, leafIsCa, "Compliance Subject")};
  }

  static std::shared_ptr<const SecurityPolicy> policy(SecurityPolicyId id)
  {
    return SecurityPolicy::create(id);
  }

  static Status check(SecurityPolicyId id, const Pair& pair, CertificateChainPosition position)
  {
    const auto p = policy(id);
    if (!p)
    {
      return Status::BadNotSupported;
    }
    return p->check_certificate_compliance(*pair.subject, *pair.signer, position).status_code().as_status();
  }

  static std::shared_ptr<const Crypto> sCrypto;
  static inline int sSerial = 7800;
};

std::shared_ptr<const Crypto> CertificatePolicyCompliance::sCrypto;

constexpr auto refused = Status::BadCertificatePolicyCheckFailed;
constexpr auto rsaSha256 = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
constexpr auto ecdsa256 = CertificateSignatureAlgorithm::EcDsaSha2256;
constexpr auto ecdsa384 = CertificateSignatureAlgorithm::EcDsaSha2384;
constexpr auto ecdsa512 = CertificateSignatureAlgorithm::EcDsaSha2512;

// --- RSA base -------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, RsaKeyBelowTheMinimumIsRefusedAndTheMinimumIsCompliant)
{
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto atMinimum = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 2048), rsaSha256);
  const auto belowMinimum = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 1024), rsaSha256);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic256Sha256, atMinimum, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic256Sha256, belowMinimum, CertificateChainPosition::EndEntity), refused);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, RsaKeyAboveTheMaximumIsRefusedAndTheMaximumIsCompliant)
{
  ASSERT_TRUE(policy(SecurityPolicyId::Basic128Rsa15)) << "Basic128Rsa15 (maximum 2048 bits)";
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto atMaximum = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 2048), rsaSha256);
  const auto aboveMaximum = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 4096), rsaSha256);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic128Rsa15, atMaximum, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic128Rsa15, aboveMaximum, CertificateChainPosition::EndEntity), refused);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, RsaSha1SignatureIsRefusedWhereThePolicyDoesNotPermitIt)
{
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto leaf = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto sha256 = issued(ca, rsaSha256, leaf, rsaSha256);
  const auto sha1 = issued(ca, rsaSha256, leaf, CertificateSignatureAlgorithm::RsaPkcs15Sha1);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic256Sha256, sha256, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::Basic256Sha256, sha1, CertificateChainPosition::EndEntity), refused);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, RsaPolicyRefusesAnEccKey)
{
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto rsa = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 2048), rsaSha256);
  const auto ecc = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::EccNistP256), rsaSha256);
  EXPECT_EQ(check(SecurityPolicyId::Basic256Sha256, rsa, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::Basic256Sha256, ecc, CertificateChainPosition::EndEntity), refused);
}

// The RSA rules hold for a CA as for the end entity.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, RsaRulesApplyToTheIssuingCa)
{
  const auto root = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto strong = issued(root, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 2048), rsaSha256, true);
  const auto weak = issued(root, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 1024), rsaSha256, true);
  EXPECT_EQ(
    check(SecurityPolicyId::Basic256Sha256, strong, CertificateChainPosition::IssuingCa), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::Basic256Sha256, weak, CertificateChainPosition::IssuingCa), refused);
}

// --- ECDSA ----------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-37-COMPLIANCE-ECC, scope=function)
TEST_F(CertificatePolicyCompliance, EccEndEntityMustBeOnThePolicyCurve)
{
  const auto ca = keys(CertificateKeyAlgorithm::EccNistP256);
  const auto onCurve = issued(ca, ecdsa256, keys(CertificateKeyAlgorithm::EccNistP256), ecdsa256);
  const auto offCurve = issued(ca, ecdsa256, keys(CertificateKeyAlgorithm::EccNistP384), ecdsa256);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, onCurve, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, offCurve, CertificateChainPosition::EndEntity), refused);
}

// The CA that issues the end entity is held to the end-entity curve, not the larger curve.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-37-COMPLIANCE-ECC, scope=function)
TEST_F(CertificatePolicyCompliance, EccIssuingCaMustBeOnThePolicyCurve)
{
  const auto root = keys(CertificateKeyAlgorithm::EccNistP384);
  const auto onCurve = issued(root, ecdsa384, keys(CertificateKeyAlgorithm::EccNistP256), ecdsa384, true);
  const auto larger = issued(root, ecdsa384, keys(CertificateKeyAlgorithm::EccNistP384), ecdsa384, true);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, onCurve, CertificateChainPosition::IssuingCa), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::EccNistP256AesGcm, larger, CertificateChainPosition::IssuingCa), refused);
}

// Every CA above the issuing CA may use the larger curve the profile allows (nistP384 for nistP256), and no
// curve beyond it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-37-COMPLIANCE-ECC, scope=function)
TEST_F(CertificatePolicyCompliance, EccHigherCaMayUseTheLargerCurveOnly)
{
  const auto root = keys(CertificateKeyAlgorithm::EccNistP521);
  const auto larger = issued(root, ecdsa512, keys(CertificateKeyAlgorithm::EccNistP384), ecdsa512, true);
  const auto beyond = issued(root, ecdsa512, keys(CertificateKeyAlgorithm::EccNistP521), ecdsa512, true);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, larger, CertificateChainPosition::HigherCa), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::EccNistP256AesGcm, beyond, CertificateChainPosition::HigherCa), refused);
}

// The ECDSA hash follows the size of the SIGNER's curve: SHA-256 for a nistP256 signer.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-37-COMPLIANCE-ECC, scope=function)
TEST_F(CertificatePolicyCompliance, EcdsaHashMustMatchTheSignersCurve)
{
  const auto ca = keys(CertificateKeyAlgorithm::EccNistP256);
  const auto leaf = keys(CertificateKeyAlgorithm::EccNistP256);
  const auto matched = issued(ca, ecdsa256, leaf, ecdsa256);
  const auto mismatched = issued(ca, ecdsa256, leaf, ecdsa384);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, matched, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, mismatched, CertificateChainPosition::EndEntity), refused);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-37-COMPLIANCE-ECC, scope=function)
TEST_F(CertificatePolicyCompliance, EccPolicyRefusesAnRsaKey)
{
  const auto ca = keys(CertificateKeyAlgorithm::EccNistP256);
  const auto ecc = issued(ca, ecdsa256, keys(CertificateKeyAlgorithm::EccNistP256), ecdsa256);
  const auto rsa = issued(ca, ecdsa256, keys(CertificateKeyAlgorithm::Rsa, 2048), ecdsa256);
  EXPECT_EQ(
    check(SecurityPolicyId::EccNistP256AesGcm, ecc, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::EccNistP256AesGcm, rsa, CertificateChainPosition::EndEntity), refused);
}

// --- EdDSA ----------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-38-COMPLIANCE-EDDSA, scope=function)
TEST_F(CertificatePolicyCompliance, EdDsaEndEntityMustBeOnThePolicyCurve)
{
  const auto ca = keys(CertificateKeyAlgorithm::EccCurve25519);
  ASSERT_TRUE(ca) << "no Curve25519 key";
  ASSERT_TRUE(policy(SecurityPolicyId::EccCurve25519ChaChaPoly));
  const auto onCurve = issued(ca,
    CertificateSignatureAlgorithm::PureEdDsa25519,
    keys(CertificateKeyAlgorithm::EccCurve25519),
    CertificateSignatureAlgorithm::PureEdDsa25519);
  const auto offCurve = issued(ca,
    CertificateSignatureAlgorithm::PureEdDsa25519,
    keys(CertificateKeyAlgorithm::EccNistP256),
    CertificateSignatureAlgorithm::PureEdDsa25519);
  EXPECT_EQ(check(SecurityPolicyId::EccCurve25519ChaChaPoly, onCurve, CertificateChainPosition::EndEntity),
    Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::EccCurve25519ChaChaPoly, offCurve, CertificateChainPosition::EndEntity), refused);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-38-COMPLIANCE-EDDSA, scope=function)
TEST_F(CertificatePolicyCompliance, EdDsaPolicyRefusesAnEcdsaSignature)
{
  const auto ed = keys(CertificateKeyAlgorithm::EccCurve25519);
  ASSERT_TRUE(ed) << "no Curve25519 key";
  ASSERT_TRUE(policy(SecurityPolicyId::EccCurve25519ChaChaPoly));
  const auto pure = issued(
    ed, CertificateSignatureAlgorithm::PureEdDsa25519, ed, CertificateSignatureAlgorithm::PureEdDsa25519);
  const auto p256 = keys(CertificateKeyAlgorithm::EccNistP256);
  const auto ecdsaSigned = issued(p256, ecdsa256, ed, ecdsa256);
  EXPECT_EQ(check(SecurityPolicyId::EccCurve25519ChaChaPoly, pure, CertificateChainPosition::EndEntity),
    Status::Good);
  EXPECT_EQ(
    check(SecurityPolicyId::EccCurve25519ChaChaPoly, ecdsaSigned, CertificateChainPosition::EndEntity),
    refused);
}

// --- The fourteen 1.05.07 rows ---------------------------------------------------------------------------

// The certificate key and signature of each row, from the plan's section 1.2 table (the profile database),
// not from the rows under test.
struct RowCertificateCase
{
  SecurityPolicyId id;
  CertificateKeyAlgorithm key;
  std::size_t keyBits;
  CertificateSignatureAlgorithm signature;
  CertificateKeyAlgorithm otherFamily;
  std::size_t otherFamilyBits;
  std::optional<CertificateKeyAlgorithm> otherCurve;  // none for RSA_DH
  const char* name;
};

void PrintTo(const RowCertificateCase& c, std::ostream* os)
{
  *os << c.name;
}

class CertificatePolicyRowCompliance : public CertificatePolicyCompliance,
                                       public ::testing::WithParamInterface<RowCertificateCase>
{};

constexpr auto rsa = CertificateKeyAlgorithm::Rsa;
constexpr auto p256 = CertificateKeyAlgorithm::EccNistP256;
constexpr auto p384 = CertificateKeyAlgorithm::EccNistP384;
constexpr auto bp256 = CertificateKeyAlgorithm::EccBrainpoolP256r1;
constexpr auto bp384 = CertificateKeyAlgorithm::EccBrainpoolP384r1;
constexpr auto ed25519 = CertificateKeyAlgorithm::EccCurve25519;
constexpr auto ed448 = CertificateKeyAlgorithm::EccCurve448;
constexpr auto pureEd25519 = CertificateSignatureAlgorithm::PureEdDsa25519;
constexpr auto pureEd448 = CertificateSignatureAlgorithm::PureEdDsa448;

const RowCertificateCase rowCertificateCases[] = {
  {SecurityPolicyId::EccNistP256AesGcm, p256, 0, ecdsa256, rsa, 2048, p384, "EccNistP256AesGcm"},
  {SecurityPolicyId::EccNistP256ChaChaPoly, p256, 0, ecdsa256, rsa, 2048, p384, "EccNistP256ChaChaPoly"},
  {SecurityPolicyId::EccNistP384AesGcm, p384, 0, ecdsa384, rsa, 2048, p256, "EccNistP384AesGcm"},
  {SecurityPolicyId::EccNistP384ChaChaPoly, p384, 0, ecdsa384, rsa, 2048, p256, "EccNistP384ChaChaPoly"},
  {SecurityPolicyId::EccBrainpoolP256r1AesGcm,
    bp256,
    0,
    ecdsa256,
    rsa,
    2048,
    bp384,
    "EccBrainpoolP256r1AesGcm"},
  {SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    bp256,
    0,
    ecdsa256,
    rsa,
    2048,
    bp384,
    "EccBrainpoolP256r1ChaChaPoly"},
  {SecurityPolicyId::EccBrainpoolP384r1AesGcm,
    bp384,
    0,
    ecdsa384,
    rsa,
    2048,
    bp256,
    "EccBrainpoolP384r1AesGcm"},
  {SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    bp384,
    0,
    ecdsa384,
    rsa,
    2048,
    bp256,
    "EccBrainpoolP384r1ChaChaPoly"},
  {SecurityPolicyId::EccCurve25519AesGcm, ed25519, 0, pureEd25519, rsa, 2048, ed448, "EccCurve25519AesGcm"},
  {SecurityPolicyId::EccCurve25519ChaChaPoly,
    ed25519,
    0,
    pureEd25519,
    rsa,
    2048,
    ed448,
    "EccCurve25519ChaChaPoly"},
  {SecurityPolicyId::EccCurve448AesGcm, ed448, 0, pureEd448, rsa, 2048, ed25519, "EccCurve448AesGcm"},
  {SecurityPolicyId::EccCurve448ChaChaPoly, ed448, 0, pureEd448, rsa, 2048, ed25519, "EccCurve448ChaChaPoly"},
  {SecurityPolicyId::RsaDhAesGcm, rsa, 2048, rsaSha256, p256, 0, std::nullopt, "RsaDhAesGcm"},
  {SecurityPolicyId::RsaDhChaChaPoly, rsa, 2048, rsaSha256, p256, 0, std::nullopt, "RsaDhChaChaPoly"},
};

// An end entity on the row's own key, signed by a CA on that key with the matching algorithm, complies; an
// end entity of the other key family, and for the ECC rows one on another curve, is refused. The CA signs
// every end entity, so only the end entity's own key differs between the arms.
// @relation(AC-COMP-SECPOL-ROWS-CERTIFICATE-RULES, scope=function)
TEST_P(CertificatePolicyRowCompliance, TheRowsKeyCompliesAndAnotherFamilyOrCurveIsRefused)
{
  const auto& row = GetParam();
  ASSERT_TRUE(policy(row.id));
  const auto ca = keys(row.key, row.keyBits);
  const auto own = issued(ca, row.signature, keys(row.key, row.keyBits), row.signature);
  const auto otherFamily =
    issued(ca, row.signature, keys(row.otherFamily, row.otherFamilyBits), row.signature);
  EXPECT_EQ(check(row.id, own, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(check(row.id, otherFamily, CertificateChainPosition::EndEntity), refused);
  if (row.otherCurve)
  {
    const auto otherCurve = issued(ca, row.signature, keys(*row.otherCurve), row.signature);
    EXPECT_EQ(check(row.id, otherCurve, CertificateChainPosition::EndEntity), refused);
  }
}

INSTANTIATE_TEST_SUITE_P(FourteenPolicies, CertificatePolicyRowCompliance,
  ::testing::ValuesIn(rowCertificateCases),
  [](const ::testing::TestParamInfo<RowCertificateCase>& info) { return std::string{info.param.name}; });

// RSA_DH admits RSA certificates of 2048 to 4096 bits signed with RSA-PKCS15 and SHA2-256, -384 or -512 (the
// conformance unit's "SHA2 with 384 or 512 bits may be used instead"), at the end entity and at the issuing
// CA.
// @relation(AC-COMP-SECPOL-ROWS-CERTIFICATE-RULES, scope=function)
TEST_F(CertificatePolicyCompliance, RsaDhAdmitsRsaFrom2048To4096BitsSignedWithSha2)
{
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto leaf = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto at4096 = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 4096), rsaSha256);
  const auto at1024 = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 1024), rsaSha256);
  const auto sha384 = issued(ca, rsaSha256, leaf, CertificateSignatureAlgorithm::RsaPkcs15Sha2384);
  const auto sha512 = issued(ca, rsaSha256, leaf, CertificateSignatureAlgorithm::RsaPkcs15Sha2512);
  const auto sha1 = issued(ca, rsaSha256, leaf, CertificateSignatureAlgorithm::RsaPkcs15Sha1);
  const auto weakCa =
    issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 1024), rsaSha256, /*leafIsCa*/ true);
  for (const auto id : {SecurityPolicyId::RsaDhAesGcm, SecurityPolicyId::RsaDhChaChaPoly})
  {
    SCOPED_TRACE(static_cast<int>(id));
    EXPECT_EQ(check(id, at4096, CertificateChainPosition::EndEntity), Status::Good);
    EXPECT_EQ(check(id, sha384, CertificateChainPosition::EndEntity), Status::Good);
    EXPECT_EQ(check(id, sha512, CertificateChainPosition::EndEntity), Status::Good);
    EXPECT_EQ(check(id, at1024, CertificateChainPosition::EndEntity), refused);
    EXPECT_EQ(check(id, sha1, CertificateChainPosition::EndEntity), refused);
    EXPECT_EQ(check(id, weakCa, CertificateChainPosition::IssuingCa), refused);
  }
}

// --- None -----------------------------------------------------------------------------------------------

// The None policy places no requirement on a certificate. Control: the same certificate is refused by
// Basic256Sha256, so the Good is not vacuous.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-36-COMPLIANCE-RSA, scope=function)
TEST_F(CertificatePolicyCompliance, NonePolicyAcceptsAnyCertificate)
{
  const auto ca = keys(CertificateKeyAlgorithm::Rsa, 2048);
  const auto weak = issued(ca, rsaSha256, keys(CertificateKeyAlgorithm::Rsa, 1024), rsaSha256);
  EXPECT_EQ(check(SecurityPolicyId::None, weak, CertificateChainPosition::EndEntity), Status::Good);
  EXPECT_EQ(check(SecurityPolicyId::Basic256Sha256, weak, CertificateChainPosition::EndEntity), refused);
}

}  // namespace
