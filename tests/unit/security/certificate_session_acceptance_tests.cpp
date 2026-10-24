// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Per-session acceptance (certificate-validation test plan U8, owner decision 22.5) and the default
// offline revocation checking (U10, owner decision 22.1), through a real CertificateStoreFiles.
//
// Every expected status comes from the specification (OPC 10000-4 section 6.1.3 and Table 106; OPC 10000-12
// default TrustListValidationOptions), never from what the code happens to return.

#include "certificate_validation_request_helpers.h"
#include "ua_session_trust_store.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <boost/asio/thread_pool.hpp>

#include "certificate_store_test_backends.h"
#include "test_pki_helpers.h"
#include "test_key_cache.h"
#include "test_utilities.h"
#include "ua_application_configuration.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status_to_string.h"
#include "ua_x509_certificate.h"
#include "ua_security_policy.h"
#include "ua_x509_crl.h"

namespace fs = std::filesystem;
using namespace ua;

namespace
{

/// The value of @p key in the first link of the result's ErrorDetail chain that carries it.
std::string context_in_chain(const VoidResult& result, std::string_view key)
{
  for (const ErrorDetail* detail = result.shared_detail().get(); detail != nullptr;
       detail = detail->cause.get())
  {
    for (const auto& entry : detail->context)
    {
      if (entry.key == key)
      {
        return entry.value;
      }
    }
  }
  return {};
}

/// CA is a self-signed root; caIssued a leaf CA issued; the self-signed leaves carry the host name
/// acceptance.example in their subjectAltName.
struct AcceptancePki
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const AsymmetricKeyPair> caKeys;
  std::shared_ptr<const X509Certificate> ca;
  std::shared_ptr<const X509Crl> caCrl;
  std::shared_ptr<const X509Crl> caCrlRevokingCaIssued;
  std::shared_ptr<const X509Certificate> caIssued;
  std::shared_ptr<const X509Certificate> selfSigned;
  std::shared_ptr<const X509Certificate> expiredSelfSigned;
  std::shared_ptr<const X509Certificate> notAccepted;
  std::shared_ptr<const X509Certificate> weakSelfSigned;  ///< RSA 1024: below the Basic256Sha256 minimum
  std::shared_ptr<const X509Certificate> brokenCaIssued;  ///< caIssued with one signature byte flipped
};

std::unique_ptr<AcceptancePki> build_acceptance_pki()
{
  auto pki = std::make_unique<AcceptancePki>();
  pki->crypto = BackendOpenSslFiles::create_crypto();
  TestPki helper{pki->crypto};
  const auto& crypto = pki->crypto;
  const auto now = DateTime::now();
  const DateTime inThirtyDays{now.value() + std::chrono::days{30}};
  // Keys from the shared test key cache, a slot per key.
  unsigned nextSlot = 0;
  const auto newKeys = [&crypto, &nextSlot]()
  {
    return test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, nextSlot++);
  };

  pki->caKeys = newKeys();
  pki->ca = helper.create_root_ca(pki->caKeys, "Acceptance CA", "8100");
  pki->caIssued = helper.create_leaf_cert(
    newKeys(), pki->caKeys, pki->ca, now, inThirtyDays, {}, {}, "Acceptance CA-Issued Leaf");
  const auto selfKeys = newKeys();
  pki->selfSigned = helper.create_leaf_cert(selfKeys,
    selfKeys,
    nullptr,
    now,
    inThirtyDays,
    {},
    {"acceptance.example"},
    "Acceptance Self-Signed Leaf");
  const auto expiredKeys = newKeys();
  pki->expiredSelfSigned = helper.create_leaf_cert(expiredKeys,
    expiredKeys,
    nullptr,
    DateTime{now.value() - std::chrono::days{30}},
    DateTime{now.value() - std::chrono::days{1}},
    {},
    {"acceptance.example"},
    "Acceptance Expired Leaf");
  const auto otherKeys = newKeys();
  pki->notAccepted = helper.create_leaf_cert(otherKeys,
    otherKeys,
    nullptr,
    now,
    inThirtyDays,
    {},
    {"acceptance.example"},
    "Acceptance Not Accepted Leaf");
  const auto weakKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa1024, 0);
  pki->weakSelfSigned = helper.create_leaf_cert(
    weakKeys, weakKeys, nullptr, now, inThirtyDays, {}, {"acceptance.example"}, "Acceptance Weak Leaf");
  {
    // One byte of the signature value flipped (the last DER byte, inside signatureValue): the TBS is intact.
    const auto der = pki->caIssued->der_encoding();
    std::vector<ua::byte> bytes(der.size());
    std::transform(der.begin(), der.end(), bytes.begin(), [](auto c) { return static_cast<ua::byte>(c); });
    bytes.back() ^= ua::byte{0x5A};
    pki->brokenCaIssued = crypto->read_certificate_from_der(span<const ua::byte>{bytes});
  }
  pki->caCrl = helper.create_crl(pki->ca, pki->caKeys, {});
  pki->caCrlRevokingCaIssued = helper.create_crl(pki->ca, pki->caKeys, {pki->caIssued->serial_number()});
  return pki;
}

class CertificateSessionAcceptance : public ::testing::Test
{
public:
  static void SetUpTestSuite()
  {
    sThreadPool = std::make_unique<boost::asio::thread_pool>(2);
    sPki = build_acceptance_pki();
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
    mRootPath = test_utils::unique_temp_path("cert_session_acceptance");
    fs::remove_all(mRootPath);
  }

  void TearDown() override
  {
    mStore.reset();
    std::error_code ignored;
    fs::remove_all(mRootPath, ignored);
  }

  /// A fresh store with an empty trusted list and the given default options.
  void make_store(TrustListValidationOptions defaults = TrustListValidationOptions{})
  {
    mStore =
      BackendOpenSslFiles::create_store(mRootPath, sThreadPool->get_executor(), sPki->crypto, defaults);
    ASSERT_NE(mStore, nullptr);
  }

  /// Validates @p certificate through the client's SessionTrustStore that accepted @p accepted.
  VoidResult validate_accepted(const std::shared_ptr<const X509Certificate>& accepted,
    const std::shared_ptr<const X509Certificate>& certificate,
    const std::vector<std::shared_ptr<const X509Certificate>>& presented,
    TrustListValidationOptions options = TrustListValidationOptions{},
    std::optional<std::string> endpointUrl = std::nullopt)
  {
    const auto session = std::make_shared<ua::client::detail::SessionTrustStore>(mStore, accepted);
    return session->try_validate_certificate_sync(
      ua::test::make_validation_request(certificate, presented, options, std::nullopt, endpointUrl));
  }

  /// As @ref validate_accepted, with a request the caller built (use, policy, ApplicationUri).
  VoidResult validate_accepted_request(
    const std::shared_ptr<const X509Certificate>& accepted, CertificateValidationRequest request)
  {
    const auto session = std::make_shared<ua::client::detail::SessionTrustStore>(mStore, accepted);
    return session->try_validate_certificate_sync(std::move(request));
  }

  static std::unique_ptr<AcceptancePki> sPki;

  fs::path mRootPath;
  // One pool per suite; every case still gets a fresh store and directory.
  inline static std::unique_ptr<boost::asio::thread_pool> sThreadPool;
  std::shared_ptr<CertificateStore> mStore;
};

std::unique_ptr<AcceptancePki> CertificateSessionAcceptance::sPki;

// ---------------------------------------------------------------------------------------------------------
// U8: per-session acceptance (decision 22.5) - the accepted certificate is a trusted certificate for the
// session, and its chain must still reach a self-signed root.
// ---------------------------------------------------------------------------------------------------------

// A self-signed certificate is its own root: accepting it is enough.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedSelfSignedIsGood)
{
  make_store();
  const auto result = validate_accepted(sPki->selfSigned, sPki->selfSigned, {});
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code().as_status());
}

// The chain material includes the certificates presented with the leaf (OPC 10000-6 section 6.2.6).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedCaIssuedWithTheChainPresentedIsGood)
{
  make_store();
  const auto result = validate_accepted(sPki->caIssued, sPki->caIssued, {sPki->ca});
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code().as_status());
}

// The issuer list completes the chain; it confers no trust, the session's acceptance does.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedCaIssuedWithTheCaInTheIssuerListIsGood)
{
  make_store();
  ASSERT_TRUE(mStore->try_add_to_issuer_certificates_sync(sPki->ca).is_good());
  const auto result = validate_accepted(sPki->caIssued, sPki->caIssued, {});
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code().as_status());
}

// Decision 22.5 removes the partial-chain mode: a CA-issued leaf alone, with its CA nowhere, cannot be
// built into a chain, and the ErrorDetail names the issuer that could not be found.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedLeafAloneWithItsCaUnknownIsChainIncompleteAndNamesTheIssuer)
{
  make_store();
  const auto result = validate_accepted(sPki->caIssued, sPki->caIssued, {});
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateChainIncomplete)
    << to_string(result.status_code().as_status());
  EXPECT_NE(
    context_in_chain(result, ContextKeys::certificateIssuer.value()).find("Acceptance CA"), std::string::npos)
    << "the ErrorDetail must name the missing issuer under certificate.issuer";
}

// Acceptance overrides only the Trust List Check: the Validity Period step still refuses.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButExpiredIsTimeInvalid)
{
  make_store();
  const auto result = validate_accepted(sPki->expiredSelfSigned, sPki->expiredSelfSigned, {});
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateTimeInvalid)
    << to_string(result.status_code().as_status());
}

// Acceptance overrides only the Trust List Check: the Revocation Check still refuses.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButRevokedIsRevoked)
{
  make_store();
  ASSERT_TRUE(mStore->try_add_to_issuer_certificates_sync(sPki->ca).is_good());
  ASSERT_TRUE(mStore->try_add_to_issuer_crls_sync(sPki->caCrlRevokingCaIssued).is_good());
  const auto result = validate_accepted(sPki->caIssued,
    sPki->caIssued,
    {},
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline});
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateRevoked)
    << to_string(result.status_code().as_status());
}

// Acceptance overrides only the Trust List Check: the Host Name step still refuses.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButHostNameMismatchIsHostNameInvalid)
{
  make_store();
  const auto result = validate_accepted(
    sPki->selfSigned, sPki->selfSigned, {}, TrustListValidationOptions{}, "opc.tcp://other.example:4840");
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateHostNameInvalid)
    << to_string(result.status_code().as_status());
}

// Control: the acceptance covers one certificate (by thumbprint); another is untrusted as usual.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-26-SESSION-ACCEPTANCE, scope=function)
TEST_F(CertificateSessionAcceptance, ACertificateThatWasNotAcceptedIsUntrusted)
{
  make_store();
  const auto result = validate_accepted(sPki->selfSigned, sPki->notAccepted, {});
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUntrusted)
    << to_string(result.status_code().as_status());
}

// ---------------------------------------------------------------------------------------------------------
// Completeness review C4: acceptance overrides the Trust List Check only. The Security Policy Check, the
// Signature step, the URI check and the Certificate Usage step each keep their own Table 106 code (OPC
// 10000-4 6.1.3; decision 22.3: usage, policy and URI are non-suppressible).
// ---------------------------------------------------------------------------------------------------------

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-84-ACCEPTANCE-DOES-NOT-OVERRIDE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButBelowThePolicyKeyLengthIsPolicyCheckFailed)
{
  make_store();
  const auto result = validate_accepted_request(sPki->weakSelfSigned,
    ua::test::make_validation_request_for(
      sPki->weakSelfSigned, {}, CertificateUse::ApplicationInstance, SecurityPolicyId::Basic256Sha256));
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificatePolicyCheckFailed)
    << to_string(result.status_code().as_status());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-84-ACCEPTANCE-DOES-NOT-OVERRIDE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButSignatureBrokenIsCertificateInvalid)
{
  make_store();
  ASSERT_NE(sPki->brokenCaIssued, nullptr);
  const auto result = validate_accepted(sPki->brokenCaIssued, sPki->brokenCaIssued, {sPki->ca});
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateInvalid)
    << to_string(result.status_code().as_status());
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-84-ACCEPTANCE-DOES-NOT-OVERRIDE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButUriMismatchIsUriInvalid)
{
  make_store();
  const auto result = validate_accepted_request(sPki->selfSigned,
    ua::test::make_validation_request(
      sPki->selfSigned, {}, std::nullopt, std::string{"urn:acceptance:other"}, std::nullopt));
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUriInvalid)
    << to_string(result.status_code().as_status());
}

// An application instance leaf validated for the CA use is refused at the Usage step (decision 22.4).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-84-ACCEPTANCE-DOES-NOT-OVERRIDE, scope=function)
TEST_F(CertificateSessionAcceptance, AcceptedButWrongUseIsUseNotAllowed)
{
  make_store();
  const auto result = validate_accepted_request(sPki->selfSigned,
    ua::test::make_validation_request_for(
      sPki->selfSigned, {}, CertificateUse::CertificateAuthority, std::nullopt));
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateUseNotAllowed)
    << to_string(result.status_code().as_status());
}

// ---------------------------------------------------------------------------------------------------------
// U10: offline revocation checking is on by default (decision 22.1).
// ---------------------------------------------------------------------------------------------------------

class CertificateRevocationDefault : public CertificateSessionAcceptance
{};

// A store created with the application group's default options checks revocation with no per-call
// options: a CA-issued certificate whose CA published no CRL is revocation-unknown, a current CRL makes it
// Good, and a self-signed certificate needs no CRL.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-30-REVOCATION-DEFAULT-STORE, scope=function)
TEST_F(CertificateRevocationDefault, AStoreWithTheDefaultOptionsNeedsACrlForACaIssuedCertificate)
{
  make_store(ApplicationConfig::FileTrustListConfig{}.defaultApplicationGroupTrustListValidationOptions);
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sPki->ca).is_good());
  ASSERT_TRUE(mStore->try_add_to_trusted_certificates_sync(sPki->selfSigned).is_good());

  const auto withoutCrl = mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(sPki->caIssued, {}, std::nullopt));
  EXPECT_EQ(withoutCrl.status_code().as_status(), Status::BadCertificateRevocationUnknown)
    << to_string(withoutCrl.status_code().as_status());

  const auto selfSigned = mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(sPki->selfSigned, {}, std::nullopt));
  EXPECT_EQ(selfSigned.status_code().as_status(), Status::Good)
    << to_string(selfSigned.status_code().as_status());

  ASSERT_TRUE(mStore->try_add_to_trusted_crls_sync(sPki->caCrl).is_good());
  const auto withCrl = mStore->try_validate_certificate_sync(
    ua::test::make_validation_request(sPki->caIssued, {}, std::nullopt));
  EXPECT_EQ(withCrl.status_code().as_status(), Status::Good) << to_string(withCrl.status_code().as_status());
}

}  // namespace
