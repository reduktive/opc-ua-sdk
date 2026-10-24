// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::SessionTrustStore - the one-certificate, single-Connection trust
// override installed by easy-connect's TrustDecision::AcceptForThisSession (client design section 7.3A).
//
// Falsifiability: the two tests pin the decorator's whole contract - the accepted certificate
// validates Good even though the inner store rejects everything, and a DIFFERENT certificate still
// gets the inner store's verdict. A decorator that trusted everything, or that ignored the accepted
// certificate, fails one of them.

#include "certificate_validation_request_helpers.h"
#include "ua_session_trust_store.h"

#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_x509_certificate.h"

#include "fake_certificate_store.h"
#include "stub_x509_certificate.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace
{
using ua::client::detail::SessionTrustStore;

/// A stub certificate with a caller-chosen thumbprint, so by-thumbprint matching can be exercised
/// (the shared stub returns an empty thumbprint).
class ThumbprintCertificate final : public ua::testing::StubX509Certificate
{
public:
  explicit ThumbprintCertificate(ua::ByteString thumbprint) : mThumbprint(std::move(thumbprint))
  {}

  ua::ByteString thumbprint() const override
  {
    return mThumbprint;
  }

private:
  ua::ByteString mThumbprint;
};

std::shared_ptr<const ua::X509Certificate> cert_with_thumbprint(std::uint8_t tag)
{
  return std::make_shared<const ThumbprintCertificate>(ua::ByteString{tag, 0x02, 0x03});
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// Restated with CL-SECADMIN-003: this arm used to assert that the accepted certificate was Good WITHOUT
// consulting the inner store. The answer to a trust prompt is a trust decision only; the inner store still
// validates the certificate, with the accepted one as an additional trust anchor, so a plain validation
// that would refuse it for trust is overridden while every other check still runs.
TEST(SessionTrustStoreTests, AcceptedCertificateIsValidatedByTheInnerStoreWithItsTrustDecisionOverridden)
{
  auto inner = ua::test_helpers::FakeCertificateStore::create();
  inner->validateCertificateStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};  // plain: untrusted
  inner->validateWithAdditionalTrustStatus = ua::StatusCode{ua::Status::Good};  // with the anchor: good
  auto accepted = cert_with_thumbprint(0xAA);
  SessionTrustStore store{inner, accepted};

  std::optional<ua::VoidResult> verdict;
  store.validate_certificate_async(
    ua::test::make_validation_request(
      accepted, {}, std::nullopt, std::string{"urn:server"}, std::string{"opc.tcp://server.example:4840"}),
    [&verdict](ua::VoidResult r) { verdict = r; });

  ASSERT_TRUE(verdict.has_value());
  EXPECT_TRUE(verdict->is_good()) << "the user accepted exactly this certificate";
  EXPECT_EQ(inner->validateWithAdditionalTrustCallCount.load(), 1) << "validated with additional trust";
  EXPECT_EQ(inner->validateCallCount.load(), 0) << "not the plain validation, which would refuse it";
  ASSERT_EQ(inner->lastAdditionalTrustedCertificates.size(), 1u);
  EXPECT_EQ(inner->lastAdditionalTrustedCertificates[0]->thumbprint(), accepted->thumbprint());
  EXPECT_EQ(inner->lastValidatedApplicationUri, std::optional<std::string>{"urn:server"});
  EXPECT_EQ(
    inner->lastAdditionalTrustEndpointUrl, std::optional<std::string>{"opc.tcp://server.example:4840"});
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// An inner store that cannot anchor the accepted certificate (the CertificateStore base fallback ignores the
// additional trust) refuses it, and the session store passes that verdict through: it never rewrites a
// trust verdict to Good on its own.
TEST(SessionTrustStoreTests, AnInnerStoreThatCannotAnchorTheAcceptedCertificateStillRefusesIt)
{
  auto inner = ua::test_helpers::FakeCertificateStore::create();
  inner->validateWithAdditionalTrustStatus = ua::StatusCode{ua::Status::BadCertificateChainIncomplete};
  auto accepted = cert_with_thumbprint(0xAA);
  SessionTrustStore store{inner, accepted};

  std::optional<ua::VoidResult> verdict;
  store.validate_certificate_async(
    ua::test::make_validation_request(accepted, {}, std::nullopt, std::nullopt, std::nullopt),
    [&verdict](ua::VoidResult r) { verdict = r; });

  ASSERT_TRUE(verdict.has_value());
  EXPECT_EQ(verdict->status_code().as_status(), ua::Status::BadCertificateChainIncomplete)
    << "the inner store's verdict, verbatim: the session store overrides nothing itself";
}

// @verifies AC-CL-SECADMIN-003-AN-ACCEPTED-CERTIFICATE-IS-STILL-DEFECT-CHECKED
// The inner store refuses the accepted certificate for a defect (expiry): the session answer does not
// override that.
TEST(SessionTrustStoreTests, AcceptedCertificateStillFailsDefectChecks)
{
  auto inner = ua::test_helpers::FakeCertificateStore::create();
  inner->validateWithAdditionalTrustStatus = ua::StatusCode{ua::Status::BadCertificateTimeInvalid};
  auto accepted = cert_with_thumbprint(0xAA);
  SessionTrustStore store{inner, accepted};

  std::optional<ua::VoidResult> verdict;
  store.validate_certificate_async(
    ua::test::make_validation_request(accepted, {}, std::nullopt, std::nullopt, std::nullopt),
    [&verdict](ua::VoidResult r) { verdict = r; });

  ASSERT_TRUE(verdict.has_value());
  EXPECT_EQ(verdict->status_code().as_status(), ua::Status::BadCertificateTimeInvalid)
    << "an expired certificate is refused even though the user accepted it";
}

TEST(SessionTrustStoreTests, ADifferentCertificateStillGoesThroughTheRealStore)
{
  auto inner = ua::test_helpers::FakeCertificateStore::create();
  inner->validateCertificateStatus = ua::StatusCode{ua::Status::BadCertificateUntrusted};
  SessionTrustStore store{inner, cert_with_thumbprint(0xAA)};

  std::optional<ua::VoidResult> verdict;
  store.validate_certificate_async(
    ua::test::make_validation_request(
      cert_with_thumbprint(0xBB), {}, std::nullopt, std::nullopt, std::nullopt),
    [&verdict](ua::VoidResult r) { verdict = r; });

  ASSERT_TRUE(verdict.has_value());
  EXPECT_TRUE(verdict->is_bad())
    << "the user's answer covers one certificate; a substituted one must not inherit it";
}

}  // namespace
