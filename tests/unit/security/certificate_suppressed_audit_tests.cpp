// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Suppressed validation errors are reported (certificate-validation test plan U9, owner decision 22.6).
//
// OPC 10000-4 section 6.1.3: errors that are suppressed "are always reported via auditing". Decision 22.6
// fixes how: a validation that suppressed anything returns Good with an ErrorDetail chain carrying one entry
// per suppressed fault - its Table 106 code as the inner status and the faulty certificate's subject under
// certificate.subject. Each case is a control pair: the same chain with the suppression bit off must fail
// with the fault's code, so the Good arm cannot pass on a chain that has no fault.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>
#include <boost/asio/thread_pool.hpp>

#include "certificate_validation_request_helpers.h"
#include "certificate_store_test_backends.h"
#include "test_pki_helpers.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"

namespace fs = std::filesystem;
using namespace ua;

namespace
{

using Bit = TrustListValidationOptions::Bit;

constexpr const char* rootName = "Suppressed Root CA";
constexpr const char* intermediateName = "Suppressed Intermediate CA";
constexpr const char* leafName = "Suppressed Leaf";

/// A CA certificate with an explicit validity period; self-signed when @p issuer is null.
std::shared_ptr<const X509Certificate> make_ca(TestPki& pki,
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

/// leaf <- intermediate <- root. The expired variants share their valid twin's name and key, so either
/// completes the same chain.
struct SuppressedPki
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const X509Certificate> root;
  std::shared_ptr<const X509Certificate> intermediate;
  std::shared_ptr<const X509Certificate> expiredIntermediate;
  std::shared_ptr<const X509Certificate> leaf;
  std::shared_ptr<const X509Certificate> expiredLeaf;
  std::shared_ptr<const X509Crl> rootCrl;
  std::shared_ptr<const X509Crl> intermediateCrl;
};

std::unique_ptr<SuppressedPki> build_suppressed_pki()
{
  auto pki = std::make_unique<SuppressedPki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = pki->crypto;
  const auto now = DateTime::now();
  const DateTime inAYear{now.value() + std::chrono::days{365}};
  const DateTime inThirtyDays{now.value() + std::chrono::days{30}};
  const DateTime monthAgo{now.value() - std::chrono::days{30}};
  const DateTime yesterday{now.value() - std::chrono::days{1}};

  // Keys from the shared test key cache, a slot per key.
  const auto rootKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  const auto intermediateKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 1);
  const auto leafKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 2);

  pki->root = helper.create_root_ca(rootKeys, rootName, "9500");
  pki->intermediate =
    make_ca(helper, intermediateKeys, rootKeys, pki->root, intermediateName, "9501", now, inAYear);
  pki->expiredIntermediate =
    make_ca(helper, intermediateKeys, rootKeys, pki->root, intermediateName, "9502", monthAgo, yesterday);
  pki->leaf = helper.create_leaf_cert(
    leafKeys, intermediateKeys, pki->intermediate, now, inThirtyDays, {}, {"suppressed.example"}, leafName);
  pki->expiredLeaf = helper.create_leaf_cert(
    leafKeys, intermediateKeys, pki->intermediate, monthAgo, yesterday, {}, {"suppressed.example"}, leafName);
  pki->rootCrl = helper.create_crl(pki->root, rootKeys, {});
  pki->intermediateCrl = helper.create_crl(pki->intermediate, intermediateKeys, {});
  return pki;
}

/// One suppressible fault of OPC 10000-4 Table 106 and the bit that suppresses it.
enum class Suppressible
{
  LeafExpired,
  IntermediateExpired,
  HostName,
  LeafRevocationUnknown,
  IntermediateRevocationUnknown,
};

struct SuppressedCase
{
  Suppressible fault = Suppressible::LeafExpired;
  Bit bit = Bit::SuppressCertificateExpired;
  Status code = Status::Good;  ///< The fault's Table 106 code (leaf or issuer variant).
  const char* certificateName = leafName;  ///< The certificate the fault is on.
  const char* name = "";
};

/// The oracle table, OPC 10000-4 Table 106 with the spec expert's corrections: validity (bit 0 leaf, bit 3
/// issuer), host name (bit 1), revocation unknown (bit 2 leaf, bit 4 issuer).
std::vector<SuppressedCase> suppressed_cases()
{
  return {
    {Suppressible::LeafExpired,
      Bit::SuppressCertificateExpired,
      Status::BadCertificateTimeInvalid,
      leafName,
      "LeafExpired"},
    {Suppressible::IntermediateExpired,
      Bit::SuppressIssuerCertificateExpired,
      Status::BadCertificateIssuerTimeInvalid,
      intermediateName,
      "IntermediateExpired"},
    {Suppressible::HostName,
      Bit::SuppressHostNameInvalid,
      Status::BadCertificateHostNameInvalid,
      leafName,
      "HostName"},
    {Suppressible::LeafRevocationUnknown,
      Bit::SuppressRevocationStatusUnknown,
      Status::BadCertificateRevocationUnknown,
      leafName,
      "LeafRevocationUnknown"},
    {Suppressible::IntermediateRevocationUnknown,
      Bit::SuppressIssuerRevocationStatusUnknown,
      Status::BadCertificateIssuerRevocationUnknown,
      intermediateName,
      "IntermediateRevocationUnknown"},
  };
}

class CertificateSuppressedFaultReport : public ::testing::TestWithParam<SuppressedCase>
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sPki = build_suppressed_pki();
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
    mRootPath = test_utils::unique_temp_path("cert_suppressed_audit");
    fs::remove_all(mRootPath);
    mStore = BackendOpenSslFiles::create_store(
      mRootPath, sThreadPool->get_executor(), sPki->crypto, TrustListValidationOptions{});
    ASSERT_NE(mStore, nullptr);
    ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sPki->root).is_good());
    ASSERT_TRUE(
      mStore
        ->try_add_to_issuer_certificates_sync(
          c.fault == Suppressible::IntermediateExpired ? sPki->expiredIntermediate : sPki->intermediate)
        .is_good());
    // Revocation unknown is produced by withholding exactly one CA's CRL.
    if (c.fault != Suppressible::IntermediateRevocationUnknown)
    {
      ASSERT_TRUE(mStore->try_add_to_trusted_crls_sync(sPki->rootCrl).is_good());
    }
    if (c.fault != Suppressible::LeafRevocationUnknown)
    {
      ASSERT_TRUE(mStore->try_add_to_issuer_crls_sync(sPki->intermediateCrl).is_good());
    }
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  VoidResult validate(bool suppressed) const
  {
    const auto& c = GetParam();
    const bool revocation = c.fault == Suppressible::LeafRevocationUnknown ||
                            c.fault == Suppressible::IntermediateRevocationUnknown;
    TrustListValidationOptions options = revocation
                                           ? TrustListValidationOptions{Bit::CheckRevocationStatusOffline}
                                           : TrustListValidationOptions{};
    if (suppressed)
    {
      options = revocation ? TrustListValidationOptions{Bit::CheckRevocationStatusOffline, c.bit}
                           : TrustListValidationOptions{c.bit};
    }
    const auto& leaf = c.fault == Suppressible::LeafExpired ? sPki->expiredLeaf : sPki->leaf;
    const std::optional<std::string> endpoint =
      c.fault == Suppressible::HostName ? std::optional<std::string>{"opc.tcp://other.example:4840"}
                                        : std::optional<std::string>{"opc.tcp://suppressed.example:4840"};
    return mStore->try_validate_certificate_sync(
      ua::test::make_validation_request(leaf, {}, options, std::nullopt, endpoint));
  }

  static std::unique_ptr<SuppressedPki> sPki;

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
};

std::unique_ptr<SuppressedPki> CertificateSuppressedFaultReport::sPki;

/// Whether the result's ErrorDetail chain has an entry for @p code naming @p certificateName.
bool lists_suppressed_fault(const VoidResult& result, Status code, const std::string& certificateName)
{
  const auto subjectKey = ContextKeys::certificateSubject.value();
  for (const ErrorDetail* detail = result.shared_detail().get(); detail != nullptr;
       detail = detail->cause.get())
  {
    if (detail->innerStatus != StatusCode{code}.value())
    {
      continue;
    }
    for (const auto& entry : detail->context)
    {
      if (entry.key == subjectKey && entry.value.find(certificateName) != std::string::npos)
      {
        return true;
      }
    }
  }
  return false;
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-27-SUPPRESSED-LISTED, scope=function)
TEST_P(CertificateSuppressedFaultReport, TheResultIsGoodAndListsTheSuppressedFault)
{
  const auto& c = GetParam();

  const auto unsuppressed = validate(false);
  EXPECT_EQ(unsuppressed.status_code().as_status(), c.code)
    << "control: without its bit the fault is " << to_string(c.code) << ", got "
    << to_string(unsuppressed.status_code().as_status());

  const auto suppressed = validate(true);
  EXPECT_EQ(suppressed.status_code().as_status(), Status::Good)
    << "with its bit the fault is suppressed, got " << to_string(suppressed.status_code().as_status());
  EXPECT_TRUE(lists_suppressed_fault(suppressed, c.code, c.certificateName))
    << "the Good result's ErrorDetail must list " << to_string(c.code) << " on " << c.certificateName;
}

INSTANTIATE_TEST_SUITE_P(EverySuppressibleFault, CertificateSuppressedFaultReport,
  ::testing::ValuesIn(suppressed_cases()),
  [](const ::testing::TestParamInfo<SuppressedCase>& info) { return std::string{info.param.name}; });

}  // namespace
