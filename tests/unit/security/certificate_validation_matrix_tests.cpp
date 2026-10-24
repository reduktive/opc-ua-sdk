// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Certificate validation matrices (certificate-validation test plan U1, U2, U3 and U4).
//
// Every expected status in this file comes from an ORACLE function below that encodes the specification
// (OPC 10000-4 section 6.1.3 and Table 106; OPC 10000-6 sections 6.2.2 to 6.2.6) and calls no SDK code.
// A case the code disagrees with is a defect in the code, not in the expectation: the expectation is
// never adjusted to what the validator happens to return.

#include "certificate_validation_request_helpers.h"
#include "ua_session_trust_store.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/thread_pool.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certificate_store_test_backends.h"
#include "test_pki_helpers.h"
#include "test_certificate_rewrite.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_crypto.h"
#include "ua_exceptions.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

namespace fs = std::filesystem;
using namespace ua;

namespace
{

// ---------------------------------------------------------------------------------------------------------
// The oracle. Written from the specification only.
// ---------------------------------------------------------------------------------------------------------

/// Where one CA certificate of the chain is when the leaf is validated.
enum class Placement
{
  Trusted,  ///< In the store's trusted list.
  Issuer,  ///< In the store's issuer list.
  Presented,  ///< Presented with the leaf (the additional issuer certificates of the call).
  Absent,  ///< Nowhere.
};

/// OPC 10000-4 section 6.1.3 and Table 106, the Build Certificate Chain and Trust List Check steps, for a
/// chain of otherwise valid certificates.
///
/// - Build Certificate Chain (step 2) precedes the Trust List Check (step 5). The chain must reach a
///   self-signed root, and its material is the trusted list, the issuer list and the certificates presented
///   with the leaf. A certificate that cannot be found is Bad_CertificateChainIncomplete.
/// - A complete chain is trusted if the certificate or at least one certificate in its chain is in the
///   trusted list. The issuer list and the presented certificates never confer trust.
///
/// @param leafTrusted Whether the leaf is in the trusted list.
/// @param cas         The placement of each CA certificate of the chain, from the leaf's issuer to the root.
Status placement_oracle(bool leafTrusted, const std::vector<Placement>& cas)
{
  for (const auto placement : cas)
  {
    if (placement == Placement::Absent)
    {
      return Status::BadCertificateChainIncomplete;
    }
  }
  if (leafTrusted)
  {
    return Status::Good;
  }
  for (const auto placement : cas)
  {
    if (placement == Placement::Trusted)
    {
      return Status::Good;
    }
  }
  return Status::BadCertificateUntrusted;
}

/// What the specification needs to know about a certificate to decide a requested-use validation.
struct UseFacts
{
  bool chainComplete = true;  ///< Every issuer up to a self-signed root can be found.
  bool expired = false;  ///< The certificate under test is outside its validity period.
  bool caFlag = false;  ///< basicConstraints cA TRUE.
  bool selfSigned = false;  ///< The certificate is its own issuer.
  bool revoked = false;  ///< Its issuer's CRL lists it, and revocation is checked.
};

/// OPC 10000-4 Table 106 in order, for a certificate whose chain is anchored at a trusted certificate:
/// Build Certificate Chain (2), Validity Period (6), Certificate Usage (9), Revocation Check (11).
///
/// Certificate Usage, OPC 10000-6 Tables 43 and 45 with the spec expert's correction (2026-10-01): a
/// certificate requested as a CA must declare cA TRUE, and when the certificate under test does not it is
/// Bad_CertificateUseNotAllowed (the issuer variant is for its issuers). An ApplicationInstance certificate
/// issued by a CA must not declare cA TRUE; a self-signed one may.
Status requested_use_oracle(const UseFacts& facts, CertificateUse use)
{
  if (!facts.chainComplete)
  {
    return Status::BadCertificateChainIncomplete;
  }
  if (facts.expired)
  {
    return Status::BadCertificateTimeInvalid;
  }
  if (use == CertificateUse::CertificateAuthority)
  {
    if (!facts.caFlag)
    {
      return Status::BadCertificateUseNotAllowed;
    }
  }
  else if (facts.caFlag && !facts.selfSigned)
  {
    return Status::BadCertificateUseNotAllowed;
  }
  if (facts.revoked)
  {
    return Status::BadCertificateRevoked;
  }
  return Status::Good;
}

// ---------------------------------------------------------------------------------------------------------
// The PKI, built once per test suite (RSA 2048 key generation is the slow part).
// ---------------------------------------------------------------------------------------------------------

std::shared_ptr<const X509Certificate> make_matrix_ca(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& keys,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
  const std::shared_ptr<const X509Certificate>& issuer, const std::string& name, const std::string& serial,
  DateTime from, DateTime to)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = issuerKeys;
  p.issuer = issuer;
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = from;
  p.to = to;
  return pki.create_cert(p);
}

/// An end-entity certificate that declares basicConstraints cA TRUE: self-signed when @p issuer is null.
std::shared_ptr<const X509Certificate> make_ca_flagged_leaf(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& keys,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
  const std::shared_ptr<const X509Certificate>& issuer, const std::string& name, const std::string& serial)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = issuerKeys;
  p.issuer = issuer;
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = true;
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{30}};
  return pki.create_cert(p);
}

/// One CA certificate of a chain with the current, empty CRL it issued.
struct ChainCa
{
  std::shared_ptr<const X509Certificate> certificate;
  std::shared_ptr<const X509Crl> crl;
};

/// R is the self-signed root, Ia an intermediate R issued, Ib an intermediate Ia issued.
/// S0 = leaf0 (self-signed); S1 = leaf1 <- R; S2 = leaf2 <- Ia <- R; S3 = leaf3 <- Ib <- Ia <- R.
struct MatrixPki
{
  std::shared_ptr<const Crypto> crypto;

  std::shared_ptr<const AsymmetricKeyPair> rootKeys;
  std::shared_ptr<const AsymmetricKeyPair> iaKeys;
  std::shared_ptr<const AsymmetricKeyPair> ibKeys;

  ChainCa root;
  ChainCa ia;
  ChainCa ib;

  std::shared_ptr<const X509Certificate> leaf0;
  std::shared_ptr<const X509Certificate> leaf1;
  std::shared_ptr<const X509Certificate> leaf2;
  std::shared_ptr<const X509Certificate> leaf3;

  // U4 material.
  std::shared_ptr<const X509Certificate> expiredIa;
  std::shared_ptr<const X509Certificate> caFlaggedCaIssuedLeaf;
  std::shared_ptr<const X509Certificate> selfSignedCaFlaggedLeaf;
  std::shared_ptr<const X509Crl> rootCrlRevokingIa;

  std::shared_ptr<const X509Certificate> leaf_of(int shape) const
  {
    switch (shape)
    {
    case 0:
      return leaf0;
    case 1:
      return leaf1;
    case 2:
      return leaf2;
    default:
      return leaf3;
    }
  }

  /// The CA certificates of shape @p shape, from the leaf's issuer to the root.
  std::vector<ChainCa> cas_of(int shape) const
  {
    switch (shape)
    {
    case 0:
      return {};
    case 1:
      return {root};
    case 2:
      return {ia, root};
    default:
      return {ib, ia, root};
    }
  }
};

std::unique_ptr<MatrixPki> build_matrix_pki()
{
  auto pki = std::make_unique<MatrixPki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = pki->crypto;

  const auto now = DateTime::now();
  const auto inAYear = DateTime{now.value() + std::chrono::days{365}};
  const auto inTenDays = DateTime{now.value() + std::chrono::days{10}};

  // Keys from the shared test key cache: a slot per key, so no two certificates share one by accident.
  pki->rootKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  pki->iaKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 1);
  pki->ibKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 2);

  pki->root.certificate = helper.create_root_ca(pki->rootKeys, "Matrix Root CA", "9100");
  pki->ia.certificate = make_matrix_ca(helper,
    pki->iaKeys,
    pki->rootKeys,
    pki->root.certificate,
    "Matrix Intermediate CA A",
    "9201",
    now,
    inAYear);
  pki->ib.certificate = make_matrix_ca(
    helper, pki->ibKeys, pki->iaKeys, pki->ia.certificate, "Matrix Intermediate CA B", "9202", now, inAYear);

  pki->root.crl = helper.create_crl(pki->root.certificate, pki->rootKeys, {});
  pki->ia.crl = helper.create_crl(pki->ia.certificate, pki->iaKeys, {});
  pki->ib.crl = helper.create_crl(pki->ib.certificate, pki->ibKeys, {});

  unsigned nextSlot = 3;
  const auto newKeys = [&crypto, &nextSlot]()
  {
    return test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, nextSlot++);
  };

  const auto leaf0Keys = newKeys();
  pki->leaf0 =
    helper.create_leaf_cert(leaf0Keys, leaf0Keys, nullptr, now, inTenDays, {}, {}, "Matrix Leaf S0");
  pki->leaf1 = helper.create_leaf_cert(
    newKeys(), pki->rootKeys, pki->root.certificate, now, inTenDays, {}, {}, "Matrix Leaf S1");
  pki->leaf2 = helper.create_leaf_cert(
    newKeys(), pki->iaKeys, pki->ia.certificate, now, inTenDays, {}, {}, "Matrix Leaf S2");
  pki->leaf3 = helper.create_leaf_cert(
    newKeys(), pki->ibKeys, pki->ib.certificate, now, inTenDays, {}, {}, "Matrix Leaf S3");

  pki->expiredIa = make_matrix_ca(helper,
    pki->iaKeys,
    pki->rootKeys,
    pki->root.certificate,
    "Matrix Expired Intermediate CA",
    "9203",
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}});
  pki->caFlaggedCaIssuedLeaf = make_ca_flagged_leaf(
    helper, newKeys(), pki->rootKeys, pki->root.certificate, "Matrix CA-Flagged CA-Issued Leaf", "9302");
  const auto selfSignedKeys = newKeys();
  pki->selfSignedCaFlaggedLeaf = make_ca_flagged_leaf(
    helper, selfSignedKeys, selfSignedKeys, nullptr, "Matrix Self-Signed CA-Flagged Leaf", "9301");
  pki->rootCrlRevokingIa =
    helper.create_crl(pki->root.certificate, pki->rootKeys, {pki->ia.certificate->serial_number()});
  return pki;
}

// ---------------------------------------------------------------------------------------------------------
// U1: placement matrix.
// ---------------------------------------------------------------------------------------------------------

struct PlacementCase
{
  int shape = 0;  ///< 0..3: the number of CA certificates in the chain.
  bool leafTrusted = false;  ///< The leaf is in the trusted list.
  std::vector<Placement> cas;  ///< From the leaf's issuer to the root.
  bool checkRevocation = false;  ///< CheckRevocationStatusOffline, with every placed CA's CRL installed.
};

const char* placement_name(Placement placement)
{
  switch (placement)
  {
  case Placement::Trusted:
    return "Trusted";
  case Placement::Issuer:
    return "Issuer";
  case Placement::Presented:
    return "Presented";
  case Placement::Absent:
    return "Absent";
  }
  return "Unknown";
}

/// The CA labels of a shape, from the leaf's issuer to the root: I1 is the leaf's issuer in S3.
std::vector<std::string> ca_labels(int shape)
{
  switch (shape)
  {
  case 0:
    return {};
  case 1:
    return {"R"};
  case 2:
    return {"I", "R"};
  default:
    return {"I1", "I2", "R"};
  }
}

/// For example S2_LeafNot_I_Presented_R_Issuer.
std::string placement_case_name(const ::testing::TestParamInfo<PlacementCase>& info)
{
  const auto& c = info.param;
  std::string name = "S" + std::to_string(c.shape) + (c.leafTrusted ? "_LeafTrusted" : "_LeafNot");
  const auto labels = ca_labels(c.shape);
  for (std::size_t i = 0; i < c.cas.size(); ++i)
  {
    name += "_" + labels[i] + "_" + placement_name(c.cas[i]);
  }
  return name;
}

/// Every placement of every shape: S0 2, S1 8, S2 32, S3 128 = 170 cases.
std::vector<PlacementCase> all_placements(bool checkRevocation)
{
  constexpr Placement placements[] = {
    Placement::Trusted, Placement::Issuer, Placement::Presented, Placement::Absent};
  std::vector<PlacementCase> cases;
  for (int shape = 0; shape <= 3; ++shape)
  {
    std::size_t combinations = 1;
    for (int i = 0; i < shape; ++i)
    {
      combinations *= 4;
    }
    for (const bool leafTrusted : {false, true})
    {
      for (std::size_t index = 0; index < combinations; ++index)
      {
        PlacementCase c;
        c.shape = shape;
        c.leafTrusted = leafTrusted;
        c.checkRevocation = checkRevocation;
        std::size_t digits = index;
        for (int i = 0; i < shape; ++i)
        {
          c.cas.push_back(placements[digits % 4]);
          digits /= 4;
        }
        cases.push_back(std::move(c));
      }
    }
  }
  return cases;
}

std::string status_name(Status status)
{
  return to_string(status);
}

class CertificatePlacementMatrix : public ::testing::TestWithParam<PlacementCase>
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sPki = build_matrix_pki();
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
    const auto& c = GetParam();
    mRootPath = test_utils::unique_temp_path("cert_validation_matrix");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sThreadPool->get_executor(), sPki->crypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);

    mLeaf = sPki->leaf_of(c.shape);
    if (c.leafTrusted)
    {
      ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(mLeaf).is_good());
    }

    const auto cas = sPki->cas_of(c.shape);
    ASSERT_EQ(cas.size(), c.cas.size());
    for (std::size_t i = 0; i < cas.size(); ++i)
    {
      switch (c.cas[i])
      {
      case Placement::Trusted:
        ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(cas[i].certificate).is_good());
        if (c.checkRevocation)
        {
          ASSERT_TRUE(mStore->try_add_to_trusted_crls_sync(cas[i].crl).is_good());
        }
        break;
      case Placement::Issuer:
        ASSERT_TRUE(mStore->try_add_to_issuer_certificates_sync(cas[i].certificate).is_good());
        if (c.checkRevocation)
        {
          ASSERT_TRUE(mStore->try_add_to_issuer_crls_sync(cas[i].crl).is_good());
        }
        break;
      case Placement::Presented:
        mPresented.push_back(cas[i].certificate);
        if (c.checkRevocation)
        {
          ASSERT_TRUE(mStore->try_add_to_issuer_crls_sync(cas[i].crl).is_good());
        }
        break;
      case Placement::Absent:
        break;
      }
    }
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  TrustListValidationOptions options() const
  {
    // Always explicit, so the store's default options never decide the outcome.
    return GetParam().checkRevocation
             ? TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline}
             : TrustListValidationOptions{};
  }

  Status expected() const
  {
    return placement_oracle(GetParam().leafTrusted, GetParam().cas);
  }

  static std::unique_ptr<MatrixPki> sPki;

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
  std::shared_ptr<const X509Certificate> mLeaf;
  std::vector<std::shared_ptr<const X509Certificate>> mPresented;
};

std::unique_ptr<MatrixPki> CertificatePlacementMatrix::sPki;

// The store's validate_certificate_async is the path the server's and the client's secure channel take,
// with the certificates the peer presented as the additional issuer certificates.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-01-PLACEMENT, scope=function)
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-02-PLACEMENT-REVOCATION, scope=function)
TEST_P(CertificatePlacementMatrix, TheStoreReturnsTheSpecifiedStatus)
{
  const auto actual =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(mLeaf, mPresented, options()));
  const auto actualStatus = actual.status_code().as_status();
  EXPECT_EQ(actualStatus, expected())
    << "expected " << status_name(expected()) << ", got " << status_name(actualStatus);
}

// The client's SessionTrustStore with no certificate accepted for the session must validate exactly as the
// store it wraps does.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-03-CLIENT-SESSION-STORE, scope=function)
TEST_P(CertificatePlacementMatrix, TheClientSessionTrustStoreReturnsTheSpecifiedStatus)
{
  const auto session = std::make_shared<ua::client::detail::SessionTrustStore>(mStore, nullptr);
  const auto viaSession =
    session->try_validate_certificate_sync(ua::test::make_validation_request(mLeaf, mPresented, options()));
  const auto viaStore =
    mStore->try_validate_certificate_sync(ua::test::make_validation_request(mLeaf, mPresented, options()));
  const auto sessionStatus = viaSession.status_code().as_status();
  const auto storeStatus = viaStore.status_code().as_status();
  EXPECT_EQ(sessionStatus, expected())
    << "expected " << status_name(expected()) << ", got " << status_name(sessionStatus);
  EXPECT_EQ(sessionStatus, storeStatus) << "the session store returned " << status_name(sessionStatus)
                                        << " where the store it wraps returned " << status_name(storeStatus);
}

INSTANTIATE_TEST_SUITE_P(
  RevocationOff, CertificatePlacementMatrix, ::testing::ValuesIn(all_placements(false)), placement_case_name);

INSTANTIATE_TEST_SUITE_P(RevocationOfflineWithCrls, CertificatePlacementMatrix,
  ::testing::ValuesIn(all_placements(true)), placement_case_name);

// ---------------------------------------------------------------------------------------------------------
// U4: requested use, at the Crypto validator.
// ---------------------------------------------------------------------------------------------------------

enum class UseSubject
{
  Root,
  Intermediate,
  CaIssuedLeafWithoutCa,
  CaFlaggedCaIssuedLeaf,
  ExpiredIntermediate,
  IntermediateWithoutRoot,
  RevokedIntermediate,
  SelfSignedCaFlaggedLeaf,
};

/// The facts the specification reasons about, stated for each subject independently of the SDK.
UseFacts facts_of(UseSubject subject)
{
  UseFacts f;
  switch (subject)
  {
  case UseSubject::Root:
    f.caFlag = true;
    f.selfSigned = true;
    break;
  case UseSubject::Intermediate:
    f.caFlag = true;
    break;
  case UseSubject::CaIssuedLeafWithoutCa:
    break;
  case UseSubject::CaFlaggedCaIssuedLeaf:
    f.caFlag = true;
    break;
  case UseSubject::ExpiredIntermediate:
    f.caFlag = true;
    f.expired = true;
    break;
  case UseSubject::IntermediateWithoutRoot:
    f.caFlag = true;
    f.chainComplete = false;
    break;
  case UseSubject::RevokedIntermediate:
    f.caFlag = true;
    f.revoked = true;
    break;
  case UseSubject::SelfSignedCaFlaggedLeaf:
    f.caFlag = true;
    f.selfSigned = true;
    break;
  }
  return f;
}

struct UseCase
{
  const char* name;
  UseSubject subject;
  CertificateUse use;
};

std::string use_case_name(const ::testing::TestParamInfo<UseCase>& info)
{
  return info.param.name;
}

const UseCase useCases[] = {
  {"CaUse_Root", UseSubject::Root, CertificateUse::CertificateAuthority},
  {"CaUse_Intermediate", UseSubject::Intermediate, CertificateUse::CertificateAuthority},
  {"CaUse_CaIssuedLeafWithoutCa", UseSubject::CaIssuedLeafWithoutCa, CertificateUse::CertificateAuthority},
  {"CaUse_CaFlaggedCaIssuedLeaf", UseSubject::CaFlaggedCaIssuedLeaf, CertificateUse::CertificateAuthority},
  {"CaUse_ExpiredIntermediate", UseSubject::ExpiredIntermediate, CertificateUse::CertificateAuthority},
  {"CaUse_IntermediateWithoutRoot",
    UseSubject::IntermediateWithoutRoot,
    CertificateUse::CertificateAuthority},
  {"CaUse_RevokedIntermediate", UseSubject::RevokedIntermediate, CertificateUse::CertificateAuthority},
  {"AppUse_SelfSignedCaFlaggedLeaf",
    UseSubject::SelfSignedCaFlaggedLeaf,
    CertificateUse::ApplicationInstance},
  {"AppUse_CaFlaggedCaIssuedLeaf", UseSubject::CaFlaggedCaIssuedLeaf, CertificateUse::ApplicationInstance},
  {"AppUse_Intermediate", UseSubject::Intermediate, CertificateUse::ApplicationInstance},
  {"AppUse_CaIssuedLeafWithoutCa", UseSubject::CaIssuedLeafWithoutCa, CertificateUse::ApplicationInstance},
};

class CertificateRequestedUseMatrix : public ::testing::TestWithParam<UseCase>
{
public:
  static void SetUpTestSuite()
  {
    sPki = build_matrix_pki();
  }

  static void TearDownTestSuite()
  {
    sPki.reset();
  }

protected:
  /// The validation inputs for a subject: the certificate under test is always anchored at a trusted
  /// certificate except where the subject's chain is incomplete by construction.
  struct Inputs
  {
    std::shared_ptr<const X509Certificate> certificate;
    std::vector<std::shared_ptr<const X509Certificate>> trusted;
    std::vector<std::shared_ptr<const X509Crl>> trustedCrls;
    TrustListValidationOptions options;
  };

  static Inputs inputs_of(UseSubject subject)
  {
    const auto& pki = *sPki;
    Inputs in;
    in.trusted = {pki.root.certificate};
    switch (subject)
    {
    case UseSubject::Root:
      in.certificate = pki.root.certificate;
      break;
    case UseSubject::Intermediate:
      in.certificate = pki.ia.certificate;
      break;
    case UseSubject::CaIssuedLeafWithoutCa:
      in.certificate = pki.leaf1;
      break;
    case UseSubject::CaFlaggedCaIssuedLeaf:
      in.certificate = pki.caFlaggedCaIssuedLeaf;
      break;
    case UseSubject::ExpiredIntermediate:
      in.certificate = pki.expiredIa;
      break;
    case UseSubject::IntermediateWithoutRoot:
      in.certificate = pki.ia.certificate;
      in.trusted.clear();
      break;
    case UseSubject::RevokedIntermediate:
      in.certificate = pki.ia.certificate;
      in.trustedCrls = {pki.rootCrlRevokingIa};
      in.options = TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
      break;
    case UseSubject::SelfSignedCaFlaggedLeaf:
      in.certificate = pki.selfSignedCaFlaggedLeaf;
      in.trusted = {pki.selfSignedCaFlaggedLeaf};
      break;
    }
    return in;
  }

  static VoidResult validate(const Inputs& in, CertificateUse use)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    sPki->crypto->validate_certificate_async(
      ua::test::make_crypto_request(in.certificate, std::nullopt, std::nullopt, use),
      ua::test::make_validation_material(in.options, in.trusted, in.trustedCrls, {}, {}),
      [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static std::unique_ptr<MatrixPki> sPki;
};

std::unique_ptr<MatrixPki> CertificateRequestedUseMatrix::sPki;

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-04-REQUESTED-USE, scope=function)
TEST_P(CertificateRequestedUseMatrix, TheValidatorReturnsTheSpecifiedStatus)
{
  ASSERT_NE(sPki, nullptr);
  const auto& c = GetParam();
  const auto expectedStatus = requested_use_oracle(facts_of(c.subject), c.use);
  const auto actual = validate(inputs_of(c.subject), c.use);
  const auto actualStatus = actual.status_code().as_status();
  EXPECT_EQ(actualStatus, expectedStatus)
    << "expected " << status_name(expectedStatus) << ", got " << status_name(actualStatus);
}

INSTANTIATE_TEST_SUITE_P(
  RequestedUse, CertificateRequestedUseMatrix, ::testing::ValuesIn(useCases), use_case_name);

// ---------------------------------------------------------------------------------------------------------
// U2 and U3: single faults and fault precedence. The oracle first, written from the specification only.
// ---------------------------------------------------------------------------------------------------------

using Bit = TrustListValidationOptions::Bit;

/// The five TrustListValidationOptions suppression bits of OPC 10000-12 Table 31.
constexpr Bit allSuppressionBits[] = {Bit::SuppressCertificateExpired,
  Bit::SuppressHostNameInvalid,
  Bit::SuppressRevocationStatusUnknown,
  Bit::SuppressIssuerCertificateExpired,
  Bit::SuppressIssuerRevocationStatusUnknown};

/// One fault injected into the fault-free chain leaf <- I <- R.
enum class Fault
{
  None,  ///< The fault-free chain (control).
  NotYetValid,  ///< The certificate's notBefore is in the future.
  Expired,  ///< The certificate's notAfter is in the past.
  Revoked,  ///< Its issuer's CRL lists it.
  CrlMissing,  ///< The CRL that decides the certificate's revocation status is not installed.
  CrlOutOfDate,  ///< That CRL is past its nextUpdate.
  CrlForged,  ///< That CRL is signed by a key other than its issuer's.
  SignatureBroken,  ///< One byte of the certificate's signature value is flipped.
  CaTrueOnLeaf,  ///< The CA-issued leaf declares basicConstraints cA TRUE.
  CaFalseOnIssuer,  ///< The intermediate declares basicConstraints cA FALSE.
  PathLenExceeded,  ///< The root's pathLenConstraint is 0, so the intermediate below it exceeds it.
  NoDigitalSignature,  ///< The leaf's keyUsage lacks digitalSignature.
  UriMismatch,  ///< The expected application URI is not among the leaf's URI entries.
  UriMatch,  ///< The expected application URI is the leaf's (control).
  SelfSignedCaLeaf,  ///< A trusted self-signed leaf with cA TRUE, alone (accepted by Table 43).
  HostNameMismatch,  ///< The endpoint URL names a host the leaf does not carry.
  HostNameMatch,  ///< The endpoint URL names the leaf's DNS name (control).
  HostNameNoEndpoint,  ///< No endpoint URL is given.
  Ipv6HostMatch,  ///< The endpoint URL's host is an IPv6 literal equal to the leaf's IP address entry.
  Ipv6HostMismatch,  ///< The endpoint URL's host is a different IPv6 literal.
};

/// Which certificate of the chain carries the fault. For the CRL faults, the certificate whose revocation
/// status the faulted CRL decides: the leaf's is decided by I's CRL, I's by R's CRL.
enum class Position
{
  Leaf,
  Intermediate,
  Root,
};

/// Which suppression bits are set.
enum class Suppression
{
  None,  ///< No bit.
  Own,  ///< The bit that governs the fault.
  Other,  ///< A neighbouring bit that does not govern the fault.
  All,  ///< All five suppression bits.
};

/// Where a revoking CRL is installed.
enum class RevokingCrlPlacement
{
  Trusted,
  Issuer,
};

/// What Table 106 says about one fault at one position.
struct FaultRule
{
  Status code = Status::Good;  ///< The code when the fault is not suppressed.
  std::optional<Bit> ownBit;  ///< The Table 31 bit that suppresses it, if it is suppressible.
  std::optional<Bit> otherBit;  ///< A neighbouring bit that must not suppress it.
  bool needsRevocationChecking = false;  ///< The step runs only when revocation checking is configured.
};

/// OPC 10000-4 Table 106 (with the spec expert's Oracle corrections and the owner decisions of 2026-10-01)
/// for a single fault: the step's code, its issuer variant, and the bit that suppresses it.
FaultRule fault_rule(Fault fault, Position position)
{
  const bool leaf = position == Position::Leaf;
  switch (fault)
  {
  case Fault::None:
  case Fault::UriMatch:
  case Fault::SelfSignedCaLeaf:  // Table 43: TRUE "shall be accepted" for a self-signed certificate.
  case Fault::HostNameMatch:
  case Fault::HostNameNoEndpoint:  // The host name is checked against the endpoint URL, when there is one.
  case Fault::Ipv6HostMatch:
    return {};
  case Fault::NotYetValid:  // Step 6, Validity Period: bit 0 for the certificate, bit 3 for an issuer.
  case Fault::Expired:
    return {leaf ? Status::BadCertificateTimeInvalid : Status::BadCertificateIssuerTimeInvalid,
      leaf ? Bit::SuppressCertificateExpired : Bit::SuppressIssuerCertificateExpired,
      leaf ? Bit::SuppressIssuerCertificateExpired : Bit::SuppressCertificateExpired,
      false};
  case Fault::Revoked:  // Step 11, Revocation Check: never suppressed.
    return {leaf ? Status::BadCertificateRevoked : Status::BadCertificateIssuerRevoked,
      std::nullopt,
      leaf ? Bit::SuppressRevocationStatusUnknown : Bit::SuppressIssuerRevocationStatusUnknown,
      true};
  case Fault::CrlMissing:  // Step 10, Find Revocation List: bit 2 for the certificate, bit 4 for an issuer.
  case Fault::CrlOutOfDate:  // Interpretation (plan): an unusable CRL is a CRL that cannot be found.
  case Fault::CrlForged:
    return {leaf ? Status::BadCertificateRevocationUnknown : Status::BadCertificateIssuerRevocationUnknown,
      leaf ? Bit::SuppressRevocationStatusUnknown : Bit::SuppressIssuerRevocationStatusUnknown,
      leaf ? Bit::SuppressIssuerRevocationStatusUnknown : Bit::SuppressRevocationStatusUnknown,
      true};
  case Fault::SignatureBroken:  // Step 3, Signature: Bad_CertificateInvalid, no issuer variant, never
                                // suppressed.
    return {Status::BadCertificateInvalid, std::nullopt, std::nullopt, false};
  case Fault::CaTrueOnLeaf:  // Step 9, Certificate Usage (Table 43): never suppressed (owner decision).
  case Fault::NoDigitalSignature:
    return {Status::BadCertificateUseNotAllowed, std::nullopt, std::nullopt, false};
  case Fault::CaFalseOnIssuer:  // Step 9 for an issuer; pathLen exceeded is an issuer usage fault (owner).
  case Fault::PathLenExceeded:
    return {Status::BadCertificateIssuerUseNotAllowed, std::nullopt, std::nullopt, false};
  case Fault::UriMismatch:  // Step 8, URI: never suppressed (Part 4; owner), not even by bit 1.
    return {Status::BadCertificateUriInvalid, std::nullopt, Bit::SuppressHostNameInvalid, false};
  case Fault::HostNameMismatch:  // Step 7, Host Name: bit 1.
  case Fault::Ipv6HostMismatch:
    return {Status::BadCertificateHostNameInvalid,
      Bit::SuppressHostNameInvalid,
      Bit::SuppressCertificateExpired,
      false};
  }
  return {Status::BadInternalError, std::nullopt, std::nullopt, false};
}

struct FaultCase
{
  Fault fault = Fault::None;
  Position position = Position::Leaf;
  Suppression suppression = Suppression::None;
  bool checkRevocation = false;  ///< CheckRevocationStatusOffline.
  RevokingCrlPlacement crlList =
    RevokingCrlPlacement::Trusted;  ///< Where the revoking CRL is installed (Fault::Revoked only).
};

/// The expected status of a single-fault case: the step's code, unless the step only runs with revocation
/// checking and it is off, or the step is suppressible and its bit is set.
Status fault_oracle(const FaultCase& c)
{
  const auto rule = fault_rule(c.fault, c.position);
  if (rule.code == Status::Good)
  {
    return Status::Good;
  }
  if (rule.needsRevocationChecking && !c.checkRevocation)
  {
    return Status::Good;
  }
  const bool suppressed =
    rule.ownBit.has_value() && (c.suppression == Suppression::Own || c.suppression == Suppression::All);
  return suppressed ? Status::Good : rule.code;
}

/// The options of a single-fault case: always explicit, so the store's defaults never decide the outcome.
TrustListValidationOptions fault_options(const FaultCase& c)
{
  TrustListValidationOptions options;
  if (c.checkRevocation)
  {
    options.set(Bit::CheckRevocationStatusOffline);
  }
  const auto rule = fault_rule(c.fault, c.position);
  switch (c.suppression)
  {
  case Suppression::None:
    break;
  case Suppression::Own:
    options.set(rule.ownBit.value());
    break;
  case Suppression::Other:
    options.set(rule.otherBit.value());
    break;
  case Suppression::All:
    for (const auto bit : allSuppressionBits)
    {
      options.set(bit);
    }
    break;
  }
  return options;
}

/// One fault on the leaf (or, for the cross-certificate pairs, on the intermediate), for U3.
enum class PrecedenceFault
{
  ChainIncomplete,  ///< The leaf's issuer is in no list.
  Untrusted,  ///< The leaf is self-signed and in no list.
  Expired,
  HostName,
  Uri,
  Usage,  ///< No digitalSignature.
  Revoked,
  IssuerExpired,  ///< The intermediate is expired.
  IssuerRevoked,  ///< The root's CRL revokes the intermediate.
};

struct StepRule
{
  int step = 0;  ///< The Table 106 row, 1-based.
  Status code = Status::Good;
  std::optional<Bit> bit;  ///< The bit that suppresses it, if it is suppressible.
  bool onIssuer = false;  ///< The fault is on the intermediate rather than the leaf.
};

/// OPC 10000-4 Table 106: the step each fault belongs to, its code and its suppression bit.
StepRule precedence_rule(PrecedenceFault fault)
{
  switch (fault)
  {
  case PrecedenceFault::ChainIncomplete:
    return {2, Status::BadCertificateChainIncomplete, std::nullopt, false};
  case PrecedenceFault::Untrusted:
    return {5, Status::BadCertificateUntrusted, std::nullopt, false};
  case PrecedenceFault::Expired:
    return {6, Status::BadCertificateTimeInvalid, Bit::SuppressCertificateExpired, false};
  case PrecedenceFault::HostName:
    return {7, Status::BadCertificateHostNameInvalid, Bit::SuppressHostNameInvalid, false};
  case PrecedenceFault::Uri:
    return {8, Status::BadCertificateUriInvalid, std::nullopt, false};
  case PrecedenceFault::Usage:
    return {9, Status::BadCertificateUseNotAllowed, std::nullopt, false};
  case PrecedenceFault::Revoked:
    return {11, Status::BadCertificateRevoked, std::nullopt, false};
  case PrecedenceFault::IssuerExpired:
    return {6, Status::BadCertificateIssuerTimeInvalid, Bit::SuppressIssuerCertificateExpired, true};
  case PrecedenceFault::IssuerRevoked:
    return {11, Status::BadCertificateIssuerRevoked, std::nullopt, true};
  }
  return {0, Status::BadInternalError, std::nullopt, false};
}

struct PrecedenceCase
{
  PrecedenceFault first = PrecedenceFault::ChainIncomplete;  ///< The fault of the earlier step.
  PrecedenceFault second = PrecedenceFault::ChainIncomplete;  ///< The fault of the later step.
  bool suppressFirst = false;  ///< Set the suppression bit of the first fault.

  bool has(PrecedenceFault fault) const
  {
    return first == fault || second == fault;
  }
};

std::vector<Bit> precedence_suppressed_bits(const PrecedenceCase& c)
{
  if (c.suppressFirst)
  {
    return {precedence_rule(c.first).bit.value()};
  }
  return {};
}

/// The statuses the specification allows for a precedence case. On one certificate the steps run in order
/// and halt at the first error that is not suppressed (OPC 10000-4 section 6.1.3), so its earliest
/// unsuppressed fault decides. Faults on different certificates are not ordered by the specification: either
/// certificate's code is accepted (owner decision 2026-10-01).
std::vector<Status> precedence_oracle(const PrecedenceCase& c)
{
  const auto suppressedBits = precedence_suppressed_bits(c);
  const auto isSuppressed = [&suppressedBits](const StepRule& rule)
  {
    return rule.bit.has_value() &&
           std::find(suppressedBits.begin(), suppressedBits.end(), *rule.bit) != suppressedBits.end();
  };
  std::vector<Status> acceptable;
  for (const bool onIssuer : {false, true})
  {
    std::optional<StepRule> earliest;
    for (const auto fault : {c.first, c.second})
    {
      const auto rule = precedence_rule(fault);
      if (rule.onIssuer != onIssuer || isSuppressed(rule))
      {
        continue;
      }
      if (!earliest || rule.step < earliest->step)
      {
        earliest = rule;
      }
    }
    if (earliest)
    {
      acceptable.push_back(earliest->code);
    }
  }
  if (acceptable.empty())
  {
    acceptable.push_back(Status::Good);
  }
  return acceptable;
}

// ---------------------------------------------------------------------------------------------------------
// The fault PKI. Every variant of a chain position shares that position's subject name and key pair, and
// the authorityKeyIdentifier is the issuer's key identifier, so any variant chains exactly as the
// fault-free certificate does and differs from it only in the injected fault.
// ---------------------------------------------------------------------------------------------------------

constexpr const char* leafUri = "urn:reduktive:certificate-fault-matrix:leaf";
constexpr const char* otherUri = "urn:reduktive:certificate-fault-matrix:other";
constexpr const char* leafHost = "fault-leaf.example";
constexpr const char* leafIpv6 = "2001:db8::1";
constexpr const char* leafEndpoint = "opc.tcp://fault-leaf.example:4840";
constexpr const char* otherEndpoint = "opc.tcp://other-host.example:4840";
constexpr const char* leafIpv6Endpoint = "opc.tcp://[2001:db8::1]:4840";
constexpr const char* otherIpv6Endpoint = "opc.tcp://[2001:db8::2]:4840";

/// A certificate with one byte of its signature value flipped, or the status its parser refused it with.
struct TamperedCertificate
{
  std::shared_ptr<const X509Certificate> certificate;
  Status parseRefusal = Status::Good;
};

/// Flips a byte of the signature value: the last byte of the DER, inside the trailing signatureValue BIT
/// STRING, so the TBSCertificate is untouched and only the signature no longer verifies.
TamperedCertificate break_signature(const Crypto& crypto, const X509Certificate& certificate)
{
  const auto der = certificate.der_encoding();
  std::vector<ua::byte> bytes(der.size());
  std::transform(der.begin(), der.end(), bytes.begin(), [](auto c) { return static_cast<ua::byte>(c); });
  bytes.back() ^= ua::byte{0x5A};
  try
  {
    return {crypto.read_certificate_from_der(span<const ua::byte>{bytes}), Status::Good};
  }
  catch (const UaException& e)
  {
    return {nullptr, e.status()};
  }
}

/// Copied from crypto_generic_tests.cpp: a CRL signed by its issuer whose nextUpdate is a day in the past.
std::shared_ptr<const X509Crl> make_out_of_date_crl(const std::shared_ptr<const Crypto>& crypto, TestPki& pki,
  const std::shared_ptr<const X509Certificate>& issuer,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys)
{
  const auto current = pki.create_crl(issuer, issuerKeys, {"1"});
  const auto der = current->der_encoding();
  const unsigned char* in = der.data();
  std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl{
    d2i_X509_CRL(nullptr, &in, static_cast<long>(der.size())), &X509_CRL_free};
  if (!crl)
    throw std::runtime_error{"d2i_X509_CRL failed"};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> thisUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> nextUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  X509_gmtime_adj(thisUpdate.get(), -2L * 24 * 60 * 60);
  X509_gmtime_adj(nextUpdate.get(), -1L * 24 * 60 * 60);
  X509_CRL_set1_lastUpdate(crl.get(), thisUpdate.get());
  X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get());

  const auto pem = issuerKeys->private_key_pem();
  std::unique_ptr<BIO, decltype(&BIO_free)> bio{
    BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
  char passphrase[] = "password";
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
    PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, passphrase), &EVP_PKEY_free};
  if (!key || X509_CRL_sign(crl.get(), key.get(), EVP_sha256()) <= 0)
    throw std::runtime_error{"re-signing the out-of-date CRL failed"};

  unsigned char* out = nullptr;
  const int length = i2d_X509_CRL(crl.get(), &out);
  if (length <= 0)
    throw std::runtime_error{"i2d_X509_CRL failed"};
  std::vector<ua::byte> bytes(
    reinterpret_cast<const ua::byte*>(out), reinterpret_cast<const ua::byte*>(out) + length);
  OPENSSL_free(out);
  return crypto->read_crl_from_der(span<const ua::byte>{bytes});
}

/// A CA certificate; self-signed when @p issuer is null.
std::shared_ptr<const X509Certificate> make_fault_ca(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& keys,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
  const std::shared_ptr<const X509Certificate>& issuer, const std::string& name, const std::string& serial,
  DateTime from, DateTime to, std::optional<bool> ca = true,
  std::optional<uint32_t> pathLength = std::nullopt)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = issuerKeys;
  p.issuer = issuer;
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = ca;
  p.basicConstraint.pathLength = pathLength;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = from;
  p.to = to;
  return pki.create_cert(p);
}

/// An application instance certificate carrying the leaf URI, DNS name and IPv6 address; self-signed when
/// @p issuer is null. Table 43 complete unless @p digitalSignature is false or @p ca is TRUE.
std::shared_ptr<const X509Certificate> make_fault_leaf(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& keys,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys,
  const std::shared_ptr<const X509Certificate>& issuer, const std::string& name, const std::string& serial,
  DateTime from, DateTime to, bool digitalSignature = true, std::optional<bool> ca = std::nullopt)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = issuerKeys;
  p.issuer = issuer;
  p.subject.commonName = name;
  p.serialNumber = serial;
  p.basicConstraint.cA = ca;
  p.keyUsage.digitalSignature = digitalSignature;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  if (ca.value_or(false))
  {
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
  }
  p.subjectAlternateName.uris = {leafUri};
  p.subjectAlternateName.hostnames = {leafHost};
  p.subjectAlternateName.ipAddresses = {boost::asio::ip::make_address(leafIpv6)};
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = from;
  p.to = to;
  return pki.create_cert(p);
}

/// R (root), I (intermediate) and the leaf, each with its fault variants, and the CRLs.
struct FaultPki
{
  std::shared_ptr<const Crypto> crypto;

  std::shared_ptr<const X509Certificate> root;
  std::shared_ptr<const X509Certificate> rootNotYetValid;
  std::shared_ptr<const X509Certificate> rootExpired;
  std::shared_ptr<const X509Certificate> rootPathLenZero;
  TamperedCertificate rootBroken;

  std::shared_ptr<const X509Certificate> ia;
  std::shared_ptr<const X509Certificate> iaNotYetValid;
  std::shared_ptr<const X509Certificate> iaExpired;
  std::shared_ptr<const X509Certificate> iaCaFalse;
  TamperedCertificate iaBroken;

  std::shared_ptr<const X509Certificate> leaf;
  std::shared_ptr<const X509Certificate> leafNotYetValid;
  std::shared_ptr<const X509Certificate> leafExpired;
  std::shared_ptr<const X509Certificate> leafNoDigitalSignature;
  std::shared_ptr<const X509Certificate> leafExpiredNoDigitalSignature;
  std::shared_ptr<const X509Certificate> leafCaTrue;
  TamperedCertificate leafBroken;

  std::shared_ptr<const X509Certificate> selfSigned;
  std::shared_ptr<const X509Certificate> selfSignedExpired;
  std::shared_ptr<const X509Certificate> selfSignedNoDigitalSignature;
  std::shared_ptr<const X509Certificate> selfSignedCaTrue;

  std::shared_ptr<const X509Crl> rootCrl;  ///< Current, revokes nothing.
  std::shared_ptr<const X509Crl> iaCrl;  ///< Current, revokes nothing.
  std::shared_ptr<const X509Crl> rootCrlRevokingIa;
  std::shared_ptr<const X509Crl> iaCrlRevokingLeaves;  ///< Revokes every CA-issued leaf variant.
  std::shared_ptr<const X509Crl> rootCrlOutOfDate;
  std::shared_ptr<const X509Crl> iaCrlOutOfDate;
  std::shared_ptr<const X509Crl> rootCrlForged;  ///< R's name, signed with another key; null if refused.
  std::shared_ptr<const X509Crl> iaCrlForged;  ///< I's name, signed with another key; null if refused.
};

std::shared_ptr<const X509Crl> try_forge_crl(TestPki& helper,
  const std::shared_ptr<const X509Certificate>& issuer,
  const std::shared_ptr<const AsymmetricKeyPair>& wrongKeys)
{
  try
  {
    return helper.create_crl(issuer, wrongKeys, {});
  }
  catch (const std::exception&)
  {
    return nullptr;
  }
}

std::unique_ptr<FaultPki> build_fault_pki()
{
  auto pki = std::make_unique<FaultPki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = pki->crypto;
  // Keys from the shared test key cache, a slot per key.
  unsigned nextSlot = 0;
  const auto newKeys = [&crypto, &nextSlot]()
  {
    return test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, nextSlot++);
  };
  const auto rootKeys = newKeys();
  const auto iaKeys = newKeys();
  const auto leafKeys = newKeys();
  const auto wrongKeys = newKeys();

  const auto now = DateTime::now();
  const auto days = [&now](int count)
  {
    return DateTime{now.value() + std::chrono::days{count}};
  };

  const std::string rootName = "Fault Matrix Root CA";
  pki->root = make_fault_ca(helper, rootKeys, rootKeys, nullptr, rootName, "9400", now, days(365));
  pki->rootNotYetValid =
    make_fault_ca(helper, rootKeys, rootKeys, nullptr, rootName, "9410", days(10), days(365));
  pki->rootExpired =
    make_fault_ca(helper, rootKeys, rootKeys, nullptr, rootName, "9411", days(-30), days(-1));
  pki->rootPathLenZero =
    make_fault_ca(helper, rootKeys, rootKeys, nullptr, rootName, "9412", now, days(365), true, 0U);
  pki->rootBroken = break_signature(*crypto, *pki->root);

  const std::string iaName = "Fault Matrix Intermediate CA";
  pki->ia = make_fault_ca(helper, iaKeys, rootKeys, pki->root, iaName, "9401", now, days(365));
  pki->iaNotYetValid =
    make_fault_ca(helper, iaKeys, rootKeys, pki->root, iaName, "9420", days(10), days(365));
  pki->iaExpired = make_fault_ca(helper, iaKeys, rootKeys, pki->root, iaName, "9421", days(-30), days(-1));
  // Crypto::create_certificate refuses keyCertSign with cA FALSE unless the certificate is self-signed, so
  // the issuer that is not a CA is a CA certificate signed again with cA FALSE.
  pki->iaCaFalse = ua::test_certificates::resign_with_ca_false(
    *crypto, *make_fault_ca(helper, iaKeys, rootKeys, pki->root, iaName, "9422", now, days(365)), *rootKeys);
  pki->iaBroken = break_signature(*crypto, *pki->ia);

  const std::string leafName = "Fault Matrix Leaf";
  pki->leaf = make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9501", now, days(30));
  pki->leafNotYetValid =
    make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9502", days(10), days(30));
  pki->leafExpired =
    make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9503", days(-30), days(-1));
  pki->leafNoDigitalSignature =
    make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9504", now, days(30), false);
  pki->leafExpiredNoDigitalSignature =
    make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9505", days(-30), days(-1), false);
  pki->leafCaTrue =
    make_fault_leaf(helper, leafKeys, iaKeys, pki->ia, leafName, "9506", now, days(30), true, true);
  pki->leafBroken = break_signature(*crypto, *pki->leaf);

  pki->selfSigned = make_fault_leaf(
    helper, leafKeys, leafKeys, nullptr, "Fault Matrix Self-Signed Leaf", "9601", now, days(30));
  pki->selfSignedExpired = make_fault_leaf(helper,
    leafKeys,
    leafKeys,
    nullptr,
    "Fault Matrix Self-Signed Expired Leaf",
    "9602",
    days(-30),
    days(-1));
  pki->selfSignedNoDigitalSignature = make_fault_leaf(helper,
    leafKeys,
    leafKeys,
    nullptr,
    "Fault Matrix Self-Signed Leaf Without DS",
    "9603",
    now,
    days(30),
    false);
  pki->selfSignedCaTrue = make_fault_leaf(helper,
    leafKeys,
    leafKeys,
    nullptr,
    "Fault Matrix Self-Signed CA Leaf",
    "9604",
    now,
    days(30),
    true,
    true);

  pki->rootCrl = helper.create_crl(pki->root, rootKeys, {});
  pki->iaCrl = helper.create_crl(pki->ia, iaKeys, {});
  pki->rootCrlRevokingIa = helper.create_crl(pki->root, rootKeys, {pki->ia->serial_number()});
  pki->iaCrlRevokingLeaves = helper.create_crl(pki->ia,
    iaKeys,
    {pki->leaf->serial_number(),
      pki->leafExpired->serial_number(),
      pki->leafNoDigitalSignature->serial_number(),
      pki->leafExpiredNoDigitalSignature->serial_number()});
  pki->rootCrlOutOfDate = make_out_of_date_crl(crypto, helper, pki->root, rootKeys);
  pki->iaCrlOutOfDate = make_out_of_date_crl(crypto, helper, pki->ia, iaKeys);
  pki->rootCrlForged = try_forge_crl(helper, pki->root, wrongKeys);
  pki->iaCrlForged = try_forge_crl(helper, pki->ia, wrongKeys);
  return pki;
}

std::unique_ptr<FaultPki> gFaultPki;

/// The trust material of one case. Faulted CRLs are offered to the store without asserting the add: a
/// store that refuses an out-of-date or forged CRL leaves the CRL missing, which the oracle treats the same.
struct Material
{
  std::shared_ptr<const X509Certificate> certificate;  ///< Under validation.
  Status parseRefusal = Status::Good;  ///< The parser refused the faulted certificate with this status.
  std::vector<std::shared_ptr<const X509Certificate>> trusted;
  std::vector<std::shared_ptr<const X509Certificate>> issuers;
  std::vector<std::shared_ptr<const X509Crl>> trustedCrls;
  std::vector<std::shared_ptr<const X509Crl>> issuerCrls;
  std::vector<std::shared_ptr<const X509Crl>> offeredTrustedCrls;
  std::vector<std::shared_ptr<const X509Crl>> offeredIssuerCrls;
};

/// A fresh store per case, the two entry points, and the material installer.
template<typename Case>
class FaultFixtureBase : public ::testing::TestWithParam<Case>
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    gFaultPki = build_fault_pki();
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sThreadPool);
    sThreadPool.reset();
    gFaultPki.reset();
  }

protected:
  void SetUp() override
  {
    ASSERT_NE(gFaultPki, nullptr);
    mRootPath = test_utils::unique_temp_path("cert_fault_matrix");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sThreadPool->get_executor(), gFaultPki->crypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  void install(const Material& m)
  {
    for (const auto& certificate : m.trusted)
    {
      ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(certificate).is_good());
    }
    for (const auto& certificate : m.issuers)
    {
      ASSERT_TRUE(mStore->try_add_to_issuer_certificates_sync(certificate).is_good());
    }
    for (const auto& crl : m.trustedCrls)
    {
      ASSERT_TRUE(mStore->try_add_to_trusted_crls_sync(crl).is_good());
    }
    for (const auto& crl : m.issuerCrls)
    {
      ASSERT_TRUE(mStore->try_add_to_issuer_crls_sync(crl).is_good());
    }
    for (const auto& crl : m.offeredTrustedCrls)
    {
      static_cast<void>(mStore->try_add_to_trusted_crls_sync(crl));
    }
    for (const auto& crl : m.offeredIssuerCrls)
    {
      static_cast<void>(mStore->try_add_to_issuer_crls_sync(crl));
    }
  }

  /// The path the server's and the client's secure channel take.
  Status validate_via_store(const Material& m, TrustListValidationOptions options,
    std::optional<std::string> applicationUri, std::optional<std::string> endpointUrl)
  {
    return mStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(
        m.certificate, {}, options, std::move(applicationUri), std::move(endpointUrl)))
      .status_code()
      .as_status();
  }

  /// The client's SessionTrustStore with no certificate accepted for the session.
  Status validate_via_session(const Material& m, TrustListValidationOptions options,
    std::optional<std::string> applicationUri, std::optional<std::string> endpointUrl)
  {
    const auto session = std::make_shared<ua::client::detail::SessionTrustStore>(mStore, nullptr);
    return session
      ->try_validate_certificate_sync(ua::test::make_validation_request(
        m.certificate, {}, options, std::move(applicationUri), std::move(endpointUrl)))
      .status_code()
      .as_status();
  }

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
};

// ---------------------------------------------------------------------------------------------------------
// U2: single-fault matrix.
// ---------------------------------------------------------------------------------------------------------

const char* fault_name(Fault fault)
{
  switch (fault)
  {
  case Fault::None:
    return "NoFault";
  case Fault::NotYetValid:
    return "NotYetValid";
  case Fault::Expired:
    return "Expired";
  case Fault::Revoked:
    return "Revoked";
  case Fault::CrlMissing:
    return "CrlMissing";
  case Fault::CrlOutOfDate:
    return "CrlOutOfDate";
  case Fault::CrlForged:
    return "CrlForged";
  case Fault::SignatureBroken:
    return "SignatureBroken";
  case Fault::CaTrueOnLeaf:
    return "CaTrueOnCaIssuedLeaf";
  case Fault::CaFalseOnIssuer:
    return "CaFalse";
  case Fault::PathLenExceeded:
    return "PathLenZeroExceeded";
  case Fault::NoDigitalSignature:
    return "NoDigitalSignature";
  case Fault::UriMismatch:
    return "UriMismatch";
  case Fault::UriMatch:
    return "UriMatch";
  case Fault::SelfSignedCaLeaf:
    return "SelfSignedTrustedCaTrue";
  case Fault::HostNameMismatch:
    return "HostNameMismatch";
  case Fault::HostNameMatch:
    return "HostNameMatch";
  case Fault::HostNameNoEndpoint:
    return "HostNameNoEndpointUrl";
  case Fault::Ipv6HostMatch:
    return "Ipv6HostMatch";
  case Fault::Ipv6HostMismatch:
    return "Ipv6HostMismatch";
  }
  return "Unknown";
}

const char* position_name(Position position)
{
  switch (position)
  {
  case Position::Leaf:
    return "Leaf";
  case Position::Intermediate:
    return "I";
  case Position::Root:
    return "R";
  }
  return "Unknown";
}

const char* suppression_name(Suppression suppression)
{
  switch (suppression)
  {
  case Suppression::None:
    return "NoSuppression";
  case Suppression::Own:
    return "OwnBit";
  case Suppression::Other:
    return "NeighbouringBit";
  case Suppression::All:
    return "AllBits";
  }
  return "Unknown";
}

/// For example Revoked_I_CrlInIssuerCrls_RevocationOn_AllBits.
std::string fault_case_name(const ::testing::TestParamInfo<FaultCase>& info)
{
  const auto& c = info.param;
  std::string name = std::string{fault_name(c.fault)} + "_" + position_name(c.position);
  if (c.fault == Fault::Revoked)
  {
    name += c.crlList == RevokingCrlPlacement::Trusted ? "_CrlInTrustedCrls" : "_CrlInIssuerCrls";
  }
  name += c.checkRevocation ? "_RevocationOn_" : "_RevocationOff_";
  return name + suppression_name(c.suppression);
}

/// Every applicable (fault, position), each with every suppression arm its rule defines, and each fault
/// that depends on revocation checking with checking on and off.
std::vector<FaultCase> fault_cases(const std::vector<std::pair<Fault, std::vector<Position>>>& faults)
{
  std::vector<FaultCase> cases;
  for (const auto& [fault, positions] : faults)
  {
    for (const auto position : positions)
    {
      const auto rule = fault_rule(fault, position);
      std::vector<Suppression> suppressions{Suppression::None};
      if (rule.ownBit)
      {
        suppressions.push_back(Suppression::Own);
      }
      if (rule.otherBit)
      {
        suppressions.push_back(Suppression::Other);
      }
      suppressions.push_back(Suppression::All);
      const std::vector<bool> checks = (rule.needsRevocationChecking || fault == Fault::None)
                                         ? std::vector<bool>{false, true}
                                         : std::vector<bool>{false};
      const std::vector<RevokingCrlPlacement> lists =
        fault == Fault::Revoked
          ? std::vector<RevokingCrlPlacement>{RevokingCrlPlacement::Trusted, RevokingCrlPlacement::Issuer}
          : std::vector<RevokingCrlPlacement>{RevokingCrlPlacement::Trusted};
      for (const auto suppression : suppressions)
      {
        for (const bool check : checks)
        {
          for (const auto list : lists)
          {
            cases.push_back(FaultCase{fault, position, suppression, check, list});
          }
        }
      }
    }
  }
  return cases;
}

std::vector<FaultCase> store_fault_cases()
{
  const std::vector<Position> all{Position::Leaf, Position::Intermediate, Position::Root};
  // A self-signed root needs no CRL, so the revocation faults apply to the leaf and the intermediate.
  const std::vector<Position> revocable{Position::Leaf, Position::Intermediate};
  return fault_cases({
    {Fault::None, {Position::Leaf}},
    {Fault::NotYetValid, all},
    {Fault::Expired, all},
    {Fault::Revoked, revocable},
    {Fault::CrlMissing, revocable},
    {Fault::CrlOutOfDate, revocable},
    {Fault::CrlForged, revocable},
    {Fault::SignatureBroken, all},
    {Fault::CaTrueOnLeaf, {Position::Leaf}},
    {Fault::CaFalseOnIssuer, {Position::Intermediate}},
    {Fault::PathLenExceeded, {Position::Root}},
    {Fault::NoDigitalSignature, {Position::Leaf}},
    {Fault::UriMismatch, {Position::Leaf}},
    {Fault::UriMatch, {Position::Leaf}},
    {Fault::SelfSignedCaLeaf, {Position::Leaf}},
  });
}

std::vector<FaultCase> host_name_fault_cases()
{
  return fault_cases({
    {Fault::HostNameMismatch, {Position::Leaf}},
    {Fault::HostNameMatch, {Position::Leaf}},
    {Fault::HostNameNoEndpoint, {Position::Leaf}},
    {Fault::Ipv6HostMatch, {Position::Leaf}},
    {Fault::Ipv6HostMismatch, {Position::Leaf}},
  });
}

/// The fault-free chain with one fault injected: R trusted with its CRL in the trusted CRLs, I in the issuer
/// list with its CRL in the issuer CRLs, and the leaf under validation.
Material single_fault_material(const FaultCase& c)
{
  const auto& pki = *gFaultPki;
  auto leaf = pki.leaf;
  auto ia = pki.ia;
  auto root = pki.root;
  std::shared_ptr<const X509Crl> rootCrl = pki.rootCrl;  // Decides I's status.
  std::shared_ptr<const X509Crl> iaCrl = pki.iaCrl;  // Decides the leaf's status.
  bool rootCrlFaulted = false;
  bool iaCrlFaulted = false;
  bool revokingCrlInIssuerList = false;
  Material m;

  const auto pick = [&c](auto& slot, Position position, const auto& variant)
  {
    if (c.position == position)
    {
      slot = variant;
    }
  };
  const auto pickTampered = [&c, &m](auto& slot, Position position, const TamperedCertificate& variant)
  {
    if (c.position == position)
    {
      slot = variant.certificate;
      m.parseRefusal = variant.parseRefusal;
    }
  };
  // The CRL that decides the faulted position: I's CRL for the leaf, R's CRL for I.
  const auto pickCrl =
    [&](const std::shared_ptr<const X509Crl>& forLeaf, const std::shared_ptr<const X509Crl>& forIa)
  {
    if (c.position == Position::Leaf)
    {
      iaCrl = forLeaf;
      iaCrlFaulted = true;
    }
    else
    {
      rootCrl = forIa;
      rootCrlFaulted = true;
    }
  };

  switch (c.fault)
  {
  case Fault::None:
  case Fault::UriMismatch:
  case Fault::UriMatch:
  case Fault::HostNameMismatch:
  case Fault::HostNameMatch:
  case Fault::HostNameNoEndpoint:
  case Fault::Ipv6HostMatch:
  case Fault::Ipv6HostMismatch:
    break;
  case Fault::NotYetValid:
    pick(leaf, Position::Leaf, pki.leafNotYetValid);
    pick(ia, Position::Intermediate, pki.iaNotYetValid);
    pick(root, Position::Root, pki.rootNotYetValid);
    break;
  case Fault::Expired:
    pick(leaf, Position::Leaf, pki.leafExpired);
    pick(ia, Position::Intermediate, pki.iaExpired);
    pick(root, Position::Root, pki.rootExpired);
    break;
  case Fault::Revoked:
    if (c.position == Position::Leaf)
    {
      iaCrl = pki.iaCrlRevokingLeaves;
    }
    else
    {
      rootCrl = pki.rootCrlRevokingIa;
    }
    revokingCrlInIssuerList = c.crlList == RevokingCrlPlacement::Issuer;
    break;
  case Fault::CrlMissing:
    pickCrl(nullptr, nullptr);
    break;
  case Fault::CrlOutOfDate:
    pickCrl(pki.iaCrlOutOfDate, pki.rootCrlOutOfDate);
    break;
  case Fault::CrlForged:
    pickCrl(pki.iaCrlForged, pki.rootCrlForged);
    break;
  case Fault::SignatureBroken:
    pickTampered(leaf, Position::Leaf, pki.leafBroken);
    pickTampered(ia, Position::Intermediate, pki.iaBroken);
    pickTampered(root, Position::Root, pki.rootBroken);
    break;
  case Fault::CaTrueOnLeaf:
    leaf = pki.leafCaTrue;
    break;
  case Fault::CaFalseOnIssuer:
    ia = pki.iaCaFalse;
    break;
  case Fault::PathLenExceeded:
    root = pki.rootPathLenZero;
    break;
  case Fault::NoDigitalSignature:
    leaf = pki.leafNoDigitalSignature;
    break;
  case Fault::SelfSignedCaLeaf:
    m.certificate = pki.selfSignedCaTrue;
    m.trusted = {pki.selfSignedCaTrue};
    return m;
  }

  m.certificate = leaf;
  if (root)
  {
    m.trusted.push_back(root);
  }
  if (ia)
  {
    m.issuers.push_back(ia);
  }
  if (rootCrl)
  {
    if (rootCrlFaulted)
    {
      m.offeredTrustedCrls.push_back(rootCrl);
    }
    else if (revokingCrlInIssuerList && c.position == Position::Intermediate)
    {
      m.issuerCrls.push_back(rootCrl);
    }
    else
    {
      m.trustedCrls.push_back(rootCrl);
    }
  }
  if (iaCrl)
  {
    if (iaCrlFaulted)
    {
      m.offeredIssuerCrls.push_back(iaCrl);
    }
    else if (c.fault == Fault::Revoked && c.position == Position::Leaf && !revokingCrlInIssuerList)
    {
      m.trustedCrls.push_back(iaCrl);
    }
    else
    {
      m.issuerCrls.push_back(iaCrl);
    }
  }
  return m;
}

std::optional<std::string> fault_application_uri(Fault fault)
{
  switch (fault)
  {
  case Fault::UriMismatch:
    return std::string{otherUri};
  case Fault::UriMatch:
    return std::string{leafUri};
  default:
    return std::nullopt;
  }
}

std::optional<std::string> fault_endpoint_url(Fault fault)
{
  switch (fault)
  {
  case Fault::HostNameMismatch:
    return std::string{otherEndpoint};
  case Fault::HostNameMatch:
    return std::string{leafEndpoint};
  case Fault::Ipv6HostMatch:
    return std::string{leafIpv6Endpoint};
  case Fault::Ipv6HostMismatch:
    return std::string{otherIpv6Endpoint};
  default:
    return std::nullopt;
  }
}

class CertificateSingleFaultMatrix : public FaultFixtureBase<FaultCase>
{};

class CertificateHostNameFaultMatrix : public FaultFixtureBase<FaultCase>
{};

// Each fault through the store's validate_certificate_async, the path the server's and the client's secure
// channel take.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-05-SINGLE-FAULT, scope=function)
TEST_P(CertificateSingleFaultMatrix, TheStoreReturnsTheSpecifiedStatus)
{
  const auto& c = GetParam();
  const auto expected = fault_oracle(c);
  const auto m = single_fault_material(c);
  if (m.parseRefusal != Status::Good)
  {
    // The parser refused the faulted certificate: Table 106 step 1, Certificate Structure.
    EXPECT_EQ(m.parseRefusal, Status::BadCertificateInvalid)
      << "the parser refused the faulted certificate with " << status_name(m.parseRefusal);
    return;
  }
  if (c.fault == Fault::CrlForged)
  {
    ASSERT_NE(c.position == Position::Leaf ? gFaultPki->iaCrlForged : gFaultPki->rootCrlForged, nullptr)
      << "the crypto backend refused to sign a CRL in another issuer's name";
  }
  ASSERT_NE(m.certificate, nullptr);
  ASSERT_NO_FATAL_FAILURE(install(m));
  const auto actual =
    validate_via_store(m, fault_options(c), fault_application_uri(c.fault), fault_endpoint_url(c.fault));
  EXPECT_EQ(actual, expected) << "expected " << status_name(expected) << ", got " << status_name(actual);
}

// The host name is checked by the client only (Table 106), so the host-name arms run through the client's
// SessionTrustStore with no certificate accepted for the session.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-06-HOST-NAME, scope=function)
TEST_P(CertificateHostNameFaultMatrix, TheClientSessionTrustStoreReturnsTheSpecifiedStatus)
{
  const auto& c = GetParam();
  const auto expected = fault_oracle(c);
  const auto m = single_fault_material(c);
  ASSERT_NE(m.certificate, nullptr);
  ASSERT_NO_FATAL_FAILURE(install(m));
  const auto actual =
    validate_via_session(m, fault_options(c), fault_application_uri(c.fault), fault_endpoint_url(c.fault));
  EXPECT_EQ(actual, expected) << "expected " << status_name(expected) << ", got " << status_name(actual);
}

INSTANTIATE_TEST_SUITE_P(
  SingleFault, CertificateSingleFaultMatrix, ::testing::ValuesIn(store_fault_cases()), fault_case_name);

INSTANTIATE_TEST_SUITE_P(
  HostName, CertificateHostNameFaultMatrix, ::testing::ValuesIn(host_name_fault_cases()), fault_case_name);

// ---------------------------------------------------------------------------------------------------------
// U3: precedence matrix.
// ---------------------------------------------------------------------------------------------------------

const char* precedence_fault_name(PrecedenceFault fault)
{
  switch (fault)
  {
  case PrecedenceFault::ChainIncomplete:
    return "ChainIncomplete";
  case PrecedenceFault::Untrusted:
    return "Untrusted";
  case PrecedenceFault::Expired:
    return "Expired";
  case PrecedenceFault::HostName:
    return "HostNameMismatch";
  case PrecedenceFault::Uri:
    return "UriMismatch";
  case PrecedenceFault::Usage:
    return "NoDigitalSignature";
  case PrecedenceFault::Revoked:
    return "Revoked";
  case PrecedenceFault::IssuerExpired:
    return "IExpired";
  case PrecedenceFault::IssuerRevoked:
    return "IRevoked";
  }
  return "Unknown";
}

/// For example Expired_Then_HostNameMismatch_FirstSuppressed.
std::string precedence_case_name(const ::testing::TestParamInfo<PrecedenceCase>& info)
{
  const auto& c = info.param;
  return std::string{precedence_fault_name(c.first)} + "_Then_" + precedence_fault_name(c.second) +
         (c.suppressFirst ? "_FirstSuppressed" : "_NoSuppression");
}

/// Every pair of leaf faults from different steps, in step order, without and (where the earlier fault is
/// suppressible) with the earlier fault suppressed. A self-signed leaf has no issuer to be absent and needs
/// no CRL, so Untrusted is not paired with ChainIncomplete or Revoked.
std::vector<PrecedenceCase> same_certificate_precedence_cases()
{
  constexpr PrecedenceFault inStepOrder[] = {PrecedenceFault::ChainIncomplete,
    PrecedenceFault::Untrusted,
    PrecedenceFault::Expired,
    PrecedenceFault::HostName,
    PrecedenceFault::Uri,
    PrecedenceFault::Usage,
    PrecedenceFault::Revoked};
  constexpr std::size_t count = sizeof(inStepOrder) / sizeof(inStepOrder[0]);
  std::vector<PrecedenceCase> cases;
  for (std::size_t i = 0; i < count; ++i)
  {
    for (std::size_t j = i + 1; j < count; ++j)
    {
      PrecedenceCase c{inStepOrder[i], inStepOrder[j], false};
      if (c.has(PrecedenceFault::Untrusted) &&
          (c.has(PrecedenceFault::ChainIncomplete) || c.has(PrecedenceFault::Revoked)))
      {
        continue;
      }
      cases.push_back(c);
      if (precedence_rule(c.first).bit)
      {
        c.suppressFirst = true;
        cases.push_back(c);
      }
    }
  }
  return cases;
}

std::vector<PrecedenceCase> cross_certificate_precedence_cases()
{
  return {
    {PrecedenceFault::Expired, PrecedenceFault::IssuerRevoked, false},
    {PrecedenceFault::Expired, PrecedenceFault::IssuerRevoked, true},
    {PrecedenceFault::IssuerExpired, PrecedenceFault::Revoked, false},
    {PrecedenceFault::IssuerExpired, PrecedenceFault::Revoked, true},
  };
}

/// The chain with the case's faults: R trusted with its CRL, I in the issuer list (absent for
/// ChainIncomplete) with its CRL, and the leaf variant carrying the leaf's faults. Untrusted replaces the
/// chain with a self-signed leaf in no list.
Material precedence_material(const PrecedenceCase& c)
{
  const auto& pki = *gFaultPki;
  const bool expired = c.has(PrecedenceFault::Expired);
  const bool noDigitalSignature = c.has(PrecedenceFault::Usage);
  Material m;
  if (c.has(PrecedenceFault::Untrusted))
  {
    m.certificate = expired              ? pki.selfSignedExpired
                    : noDigitalSignature ? pki.selfSignedNoDigitalSignature
                                         : pki.selfSigned;
    return m;
  }
  m.certificate = expired && noDigitalSignature ? pki.leafExpiredNoDigitalSignature
                  : expired                     ? pki.leafExpired
                  : noDigitalSignature          ? pki.leafNoDigitalSignature
                                                : pki.leaf;
  m.trusted = {pki.root};
  m.trustedCrls = {c.has(PrecedenceFault::IssuerRevoked) ? pki.rootCrlRevokingIa : pki.rootCrl};
  const auto iaCrl = c.has(PrecedenceFault::Revoked) ? pki.iaCrlRevokingLeaves : pki.iaCrl;
  if (c.has(PrecedenceFault::ChainIncomplete))
  {
    // I is in no list; its CRL is offered, and a store may refuse a CRL whose issuer it does not hold.
    m.offeredIssuerCrls = {iaCrl};
  }
  else
  {
    m.issuers = {c.has(PrecedenceFault::IssuerExpired) ? pki.iaExpired : pki.ia};
    m.issuerCrls = {iaCrl};
  }
  return m;
}

TrustListValidationOptions precedence_options(const PrecedenceCase& c)
{
  TrustListValidationOptions options{Bit::CheckRevocationStatusOffline};
  for (const auto bit : precedence_suppressed_bits(c))
  {
    options.set(bit);
  }
  return options;
}

std::string statuses_text(const std::vector<Status>& statuses)
{
  std::string text;
  for (const auto status : statuses)
  {
    text += (text.empty() ? "" : " or ") + status_name(status);
  }
  return text;
}

class CertificatePrecedenceMatrix : public FaultFixtureBase<PrecedenceCase>
{
protected:
  /// A pair with the host-name fault goes through the client's SessionTrustStore with an endpoint URL (the
  /// server makes no host-name check); every other pair through the store. The expected application URI is
  /// always given, so the URI step always runs.
  Status validate_case(const PrecedenceCase& c, const Material& m)
  {
    const std::optional<std::string> applicationUri{c.has(PrecedenceFault::Uri) ? otherUri : leafUri};
    if (c.has(PrecedenceFault::HostName))
    {
      return validate_via_session(m, precedence_options(c), applicationUri, std::string{otherEndpoint});
    }
    return validate_via_store(m, precedence_options(c), applicationUri, std::nullopt);
  }
};

class CertificateCrossCertificatePrecedenceMatrix : public CertificatePrecedenceMatrix
{};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-07-PRECEDENCE-SAME-CERTIFICATE, scope=function)
TEST_P(CertificatePrecedenceMatrix, TheEarliestUnsuppressedStepDecides)
{
  const auto& c = GetParam();
  const auto acceptable = precedence_oracle(c);
  ASSERT_EQ(acceptable.size(), 1U) << "two faults on one certificate have exactly one specified outcome";
  const auto m = precedence_material(c);
  ASSERT_NE(m.certificate, nullptr);
  ASSERT_NO_FATAL_FAILURE(install(m));
  const auto actual = validate_case(c, m);
  EXPECT_EQ(actual, acceptable.front())
    << "expected " << status_name(acceptable.front()) << ", got " << status_name(actual);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-08-PRECEDENCE-ACROSS-CERTIFICATES, scope=function)
TEST_P(CertificateCrossCertificatePrecedenceMatrix, TheResultIsOneOfTheFaultedCertificatesCodes)
{
  const auto& c = GetParam();
  const auto acceptable = precedence_oracle(c);
  const auto m = precedence_material(c);
  ASSERT_NE(m.certificate, nullptr);
  ASSERT_NO_FATAL_FAILURE(install(m));
  const auto actual = validate_case(c, m);
  EXPECT_NE(std::find(acceptable.begin(), acceptable.end(), actual), acceptable.end())
    << "expected " << statuses_text(acceptable) << ", got " << status_name(actual);
}

INSTANTIATE_TEST_SUITE_P(SameCertificate, CertificatePrecedenceMatrix,
  ::testing::ValuesIn(same_certificate_precedence_cases()), precedence_case_name);

INSTANTIATE_TEST_SUITE_P(AcrossCertificates, CertificateCrossCertificatePrecedenceMatrix,
  ::testing::ValuesIn(cross_certificate_precedence_cases()), precedence_case_name);

}  // namespace

// ---------------------------------------------------------------------------
// The validator's Host Name step (OPC 10000-4 Table 106) is the one host-name rule the client's CreateSession
// check also uses (OPC 10000-4 5.4.1): DNS names compare case-insensitively (RFC 6125 6.4.1), a trailing dot
// of an absolute name is normalised, and an address matches only an iPAddress SAN - "localhost" is a DNS
// name, not this machine's address. Found by the integration matrix (2026-10-02).
// ---------------------------------------------------------------------------

namespace
{

class ValidatorHostNameStep : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sPool = std::make_unique<boost::asio::thread_pool>(2);
    sCrypto = BackendOpenSslFiles::create_crypto();
    TestPki pki{sCrypto};
    auto rootKeys = test_keys::key_pair(*sCrypto, test_keys::KeyType::Rsa2048, 95);
    sRoot = pki.create_root_ca(rootKeys, "Host Name Root", "9501");
    const auto now = DateTime::now();
    const auto later = DateTime{now.value() + std::chrono::days{365}};
    sLocalhostLeaf = pki.create_leaf_cert(test_keys::key_pair(*sCrypto, test_keys::KeyType::Rsa2048, 96),
      rootKeys,
      sRoot,
      now,
      later,
      {"urn:host-name-step:localhost"},
      {"localhost"},
      "Host Name Localhost Leaf");
    sDottedLeaf = pki.create_leaf_cert(test_keys::key_pair(*sCrypto, test_keys::KeyType::Rsa2048, 97),
      rootKeys,
      sRoot,
      now,
      later,
      {"urn:host-name-step:u6"},
      {"u6-leaf.example"},
      "Host Name U6 Leaf");
  }

  static void TearDownTestSuite()
  {
    test_utils::drain_with_timeout(*sPool);
    sPool.reset();
    sCrypto.reset();
    sRoot.reset();
    sLocalhostLeaf.reset();
    sDottedLeaf.reset();
  }

  void SetUp() override
  {
    mRootPath = test_utils::unique_temp_path("cert_host_name_step");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sPool->get_executor(), sCrypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);
    ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sRoot).is_good());
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  /// The store's validation with the endpoint URL the certificate is checked against; no ApplicationUri.
  Status validate(const std::shared_ptr<const X509Certificate>& leaf, std::string endpointUrl)
  {
    return mStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(
        leaf, {}, TrustListValidationOptions{}, std::nullopt, std::move(endpointUrl)))
      .status_code()
      .as_status();
  }

  inline static std::unique_ptr<boost::asio::thread_pool> sPool;
  inline static std::shared_ptr<const Crypto> sCrypto;
  inline static std::shared_ptr<const X509Certificate> sRoot;
  inline static std::shared_ptr<const X509Certificate> sLocalhostLeaf;
  inline static std::shared_ptr<const X509Certificate> sDottedLeaf;
  fs::path mRootPath;
  std::shared_ptr<CertificateStore> mStore;
};

}  // namespace

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-143-VALIDATOR-HOST-NAME-RULE, scope=function)
TEST_F(ValidatorHostNameStep, AnUpperCaseEndpointHostMatchesTheLowerCaseDnsName)
{
  EXPECT_EQ(validate(sLocalhostLeaf, "opc.tcp://LOCALHOST:4840"), Status::Good);
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-143-VALIDATOR-HOST-NAME-RULE, scope=function)
TEST_F(ValidatorHostNameStep, AnEndpointHostWithATrailingDotMatchesTheDnsName)
{
  EXPECT_EQ(validate(sDottedLeaf, "opc.tcp://u6-leaf.example.:4840"), Status::Good);
}

// Control for both matches: the same certificate and store, another host.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-143-VALIDATOR-HOST-NAME-RULE, scope=function)
TEST_F(ValidatorHostNameStep, AnotherEndpointHostIsHostNameInvalid)
{
  EXPECT_EQ(
    validate(sLocalhostLeaf, "opc.tcp://other-host.example:4840"), Status::BadCertificateHostNameInvalid);
  EXPECT_EQ(
    validate(sDottedLeaf, "opc.tcp://u6-leaf.example.other:4840"), Status::BadCertificateHostNameInvalid);
}

// An address matches only an iPAddress SAN: the loopback address does not match a certificate whose only
// host name is the DNS name "localhost".
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-143-VALIDATOR-HOST-NAME-RULE, scope=function)
TEST_F(ValidatorHostNameStep, TheLoopbackAddressDoesNotMatchALocalhostDnsName)
{
  EXPECT_EQ(validate(sLocalhostLeaf, "opc.tcp://127.0.0.1:4840"), Status::BadCertificateHostNameInvalid);
}
