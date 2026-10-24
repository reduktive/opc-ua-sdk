// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Per-path wiring of the single certificate-validation request (owner review 2026-10-02, internal A-G): each
// path is a thin caller that BUILDS one CertificateValidationRequest and MAPS the verdict. These tests are
// written against the smallest seam per path - the ONE request builder (make_validation_request, which every
// path calls after setting its own fields), the one server suppressed-error reporter, the one client warning
// reporter, the endpoint-policy compliance check of an own certificate - declared in
// ua_certificate_validation_paths.h (SEAM, not yet existing; see the report). The builder is the function the
// production path calls, so asserting its output asserts what the path hands the store. Each
// stimulus is what a production caller produces: the certificate field bytes off the wire (leaf + issuers),
// the endpoint's SecurityPolicy, the ApplicationDescription URI, the endpoint URL.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "certificate_store_test_backends.h"
#include "stub_x509_certificate.h"
#include "test_key_cache.h"
#include "test_log_sink.h"
#include "test_pki_helpers.h"
#include "ua_certificate_store.h"
#include "ua_certificate_validation_paths.h"
#include "ua_server_cert_validator.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_crypto.h"
#include "ua_security_policy.h"
#include "ua_server_observer.h"
#include "ua_x509_certificate.h"

using namespace ua;

namespace
{

struct WiringPki
{
  std::shared_ptr<const Crypto> crypto;
  std::shared_ptr<const X509Certificate> root;
  std::shared_ptr<const X509Certificate> leaf;
  std::shared_ptr<const X509Certificate> weakLeaf;
  std::shared_ptr<const X509Certificate> serverOnlyLeaf;
  std::shared_ptr<const X509Certificate> clientOnlyLeaf;
  std::shared_ptr<const X509Certificate> noPurposeLeaf;
  std::shared_ptr<const X509Certificate> eccNoPurposeLeaf;
  ByteString chainField;  ///< leaf || root, as a certificate field carries it on the wire
};

class CertificateValidationPathWiring : public ::testing::Test
{
public:
  static void SetUpTestSuite()
  {
    sPki = std::make_unique<WiringPki>();
    sPki->crypto = BackendOpenSslFiles::create_crypto();
    TestPki pki{sPki->crypto};
    // Keys from the shared test key cache, a slot per key.
    const auto rootKeys = test_keys::key_pair(*sPki->crypto, test_keys::KeyType::Rsa2048, 0);
    sPki->root = pki.create_root_ca(rootKeys, "Wiring Root", "8800");
    const auto now = DateTime::now();
    const DateTime later{now.value() + std::chrono::days{30}};
    sPki->leaf = pki.create_leaf_cert(test_keys::key_pair(*sPki->crypto, test_keys::KeyType::Rsa2048, 1),
      rootKeys,
      sPki->root,
      now,
      later,
      {"urn:wiring:peer"},
      {"localhost"},
      "Wiring Leaf");
    sPki->weakLeaf = pki.create_leaf_cert(test_keys::key_pair(*sPki->crypto, test_keys::KeyType::Rsa1024, 0),
      rootKeys,
      sPki->root,
      now,
      later,
      {"urn:wiring:own"},
      {"localhost"},
      "Wiring Weak Own");
    Crypto::CreateCertificateConfig purposeParameters;
    purposeParameters.subjectKeys = test_keys::key_pair(*sPki->crypto, test_keys::KeyType::Rsa2048, 1);
    purposeParameters.issuerKeys = rootKeys;
    purposeParameters.issuer = sPki->root;
    purposeParameters.subject.commonName = "Wiring Purpose Leaf";
    purposeParameters.subjectAlternateName.uris = {"urn:wiring:peer"};
    purposeParameters.subjectAlternateName.hostnames = {"localhost"};
    purposeParameters.from = now;
    purposeParameters.to = later;
    purposeParameters.keyUsage.digitalSignature = true;
    purposeParameters.keyUsage.nonRepudiation = true;
    purposeParameters.keyUsage.keyEncipherment = true;
    purposeParameters.keyUsage.dataEncipherment = true;
    purposeParameters.basicConstraint.cA = false;
    purposeParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    purposeParameters.serialNumber = "8801";
    purposeParameters.keyUsage.serverAuth = true;
    sPki->serverOnlyLeaf = pki.create_cert(purposeParameters);
    purposeParameters.serialNumber = "8802";
    purposeParameters.keyUsage.serverAuth = false;
    purposeParameters.keyUsage.clientAuth = true;
    sPki->clientOnlyLeaf = pki.create_cert(purposeParameters);
    purposeParameters.serialNumber = "8803";
    purposeParameters.keyUsage.clientAuth = false;
    sPki->noPurposeLeaf = pki.create_cert(purposeParameters);
    purposeParameters.serialNumber = "8804";
    purposeParameters.subjectKeys = test_keys::key_pair(*sPki->crypto, test_keys::KeyType::P256, 0);
    purposeParameters.keyUsage.keyEncipherment = false;
    purposeParameters.keyUsage.dataEncipherment = false;
    sPki->eccNoPurposeLeaf = pki.create_cert(purposeParameters);
    std::vector<uint8_t> bytes;
    for (const auto& certificate : {sPki->leaf, sPki->root})
    {
      const auto der = certificate->der_encoding();
      bytes.insert(bytes.end(), der.begin(), der.end());
    }
    sPki->chainField = ByteString{std::move(bytes)};
  }

  static void TearDownTestSuite()
  {
    sPki.reset();
  }

protected:
  static void expect_chain(const CertificateValidationRequest& request)
  {
    ASSERT_TRUE(request.certificate);
    EXPECT_EQ(request.certificate->thumbprint(), sPki->leaf->thumbprint())
      << "the leaf is the first certificate";
    ASSERT_EQ(request.presentedIssuers.size(), 1u) << "the rest of the field is the presented issuers";
    EXPECT_EQ(request.presentedIssuers.front()->thumbprint(), sPki->root->thumbprint());
  }

  static std::unique_ptr<WiringPki> sPki;
};

std::unique_ptr<WiringPki> CertificateValidationPathWiring::sPki;

// SEAM detail::make_validation_request(crypto, certificateField, request): the ONE builder every path calls
// (owner 2026-10-02). The caller sets the path's fields (use, policy, ApplicationDescription URI, endpoint
// URL, connection trust); the builder parses the certificate field with the chain parser into mCertificate +
// presentedIssuers and hands every caller-set field through unchanged. Each test below sets the fields one
// production path sets and asserts the request that path hands the store.
std::shared_ptr<const SecurityPolicy> basic256_sha256()
{
  return SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
}

// Server OPN: the sender certificate field and the channel policy; no ApplicationDescription.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderParsesTheOpnSenderChainAndKeepsTheChannelPolicy)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  const auto request = detail::make_validation_request(*sPki->crypto, sPki->chainField, std::move(fields));
  ASSERT_TRUE(request.is_good());
  expect_chain(request.value());
  EXPECT_EQ(request.value().use, CertificateUse::ApplicationInstance);
  EXPECT_EQ(request.value().policyId, SecurityPolicyId::Basic256Sha256);
  EXPECT_FALSE(request.value().applicationUri.has_value()) << "OPN carries no ApplicationDescription";
  EXPECT_FALSE(request.value().endpointUrl.has_value()) << "server side has no endpoint URL to match";
  EXPECT_TRUE(request.value().trustedForThisConnection.empty()) << "never used server-side";
}

// A field with trailing bytes is refused before any validation (item 7), whichever path calls the builder.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderRefusesAFieldWithTrailingBytes)
{
  auto bytes = std::vector<uint8_t>(sPki->chainField.begin(), sPki->chainField.end());
  bytes.push_back(0x30);
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  const auto request =
    detail::make_validation_request(*sPki->crypto, ByteString{std::move(bytes)}, std::move(fields));
  EXPECT_EQ(request.status_code().as_status(), Status::BadCertificateInvalid);
}

// Control for the refusal: a field holding the leaf alone parses, with no presented issuers.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderParsesAFieldHoldingOnlyTheLeaf)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  const auto request =
    detail::make_validation_request(*sPki->crypto, sPki->leaf->der_encoding(), std::move(fields));
  ASSERT_TRUE(request.is_good());
  ASSERT_TRUE(request.value().certificate);
  EXPECT_EQ(request.value().certificate->thumbprint(), sPki->leaf->thumbprint());
  EXPECT_TRUE(request.value().presentedIssuers.empty());
}

// The field is the only source of the presented chain: issuers already in the request are replaced, not kept.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderReplacesAnyChainAlreadyInTheRequest)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  fields.certificate = sPki->weakLeaf;
  fields.presentedIssuers = {sPki->weakLeaf, sPki->leaf};
  const auto request = detail::make_validation_request(*sPki->crypto, sPki->chainField, std::move(fields));
  ASSERT_TRUE(request.is_good());
  expect_chain(request.value());
}

// Server CreateSession: the client certificate field, the channel policy, and the ApplicationDescription URI.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderKeepsTheCreateSessionApplicationDescriptionUri)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  fields.applicationUri = std::string{"urn:wiring:peer"};
  const auto request = detail::make_validation_request(*sPki->crypto, sPki->chainField, std::move(fields));
  ASSERT_TRUE(request.is_good());
  expect_chain(request.value());
  EXPECT_EQ(request.value().use, CertificateUse::ApplicationInstance);
  EXPECT_EQ(request.value().policyId, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(request.value().applicationUri.has_value());
  EXPECT_EQ(*request.value().applicationUri, "urn:wiring:peer");
}

// Client OPN and CreateSession: the server certificate field, the policy, the endpoint URL, and the
// certificates trusted for this connection; the connection stores the request for revalidation.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderKeepsTheClientEndpointUrlAndConnectionTrust)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicyId::Basic256Sha256;
  fields.endpointUrl = std::string{"opc.tcp://localhost:4840"};
  fields.trustedForThisConnection = {sPki->leaf};
  const auto request = detail::make_validation_request(*sPki->crypto, sPki->chainField, std::move(fields));
  ASSERT_TRUE(request.is_good());
  expect_chain(request.value());
  EXPECT_EQ(request.value().policyId, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(request.value().endpointUrl.has_value());
  EXPECT_EQ(*request.value().endpointUrl, "opc.tcp://localhost:4840");
  ASSERT_EQ(request.value().trustedForThisConnection.size(), 1u);
  EXPECT_EQ(request.value().trustedForThisConnection.front()->thumbprint(), sPki->leaf->thumbprint());
  EXPECT_FALSE(request.value().applicationUri.has_value());
}

// Channelless paths (GetEndpoints, LDS registration): the caller resolves the advertised policy URI to its
// ID; the builder keeps it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-39-PATH-WIRING, scope=function)
TEST_F(CertificateValidationPathWiring, TheBuilderKeepsAPolicyCreatedFromAnAdvertisedUri)
{
  CertificateValidationRequest fields;
  fields.use = CertificateUse::ApplicationInstance;
  fields.policyId = SecurityPolicy::create(basic256_sha256()->uri())->id();
  const auto request = detail::make_validation_request(*sPki->crypto, sPki->chainField, std::move(fields));
  ASSERT_TRUE(request.is_good());
  expect_chain(request.value());
  EXPECT_EQ(request.value().policyId, SecurityPolicyId::Basic256Sha256);
}

// SEAM server::detail::check_own_certificate_against_endpoints(certificate, issuer, endpointPolicies): the
// startup refusal (internal F, Bad_ConfigurationError naming endpoint + rule) and UpdateCertificate's refusal
// (G) share it. Control: the compliant certificate passes for the same endpoint.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-40-OWN-CERTIFICATE-POLICY, scope=function)
TEST_F(CertificateValidationPathWiring, AnOwnCertificateViolatingAServedEndpointPolicyIsAConfigurationError)
{
  const std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>> endpoints{
    {"Basic256Sha256_SignAndEncrypt", SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)}};
  const auto refused =
    server::detail::check_own_certificate_against_endpoints(*sPki->weakLeaf, *sPki->root, endpoints);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadConfigurationError);
  ASSERT_TRUE(refused.shared_detail());
  EXPECT_NE(refused.shared_detail()->summary.find("Basic256Sha256_SignAndEncrypt"), std::string::npos)
    << "the refusal names the endpoint";
  EXPECT_TRUE(
    server::detail::check_own_certificate_against_endpoints(*sPki->leaf, *sPki->root, endpoints).is_good());
}

// Part 6 section 6.2.2: each RSA role requires its own EKU; the other role's EKU does not substitute.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-148-RSA-ROLE-PURPOSE, scope=function)
TEST_F(CertificateValidationPathWiring, RsaApplicationUsageRequiresTheRequestedRoleEku)
{
  for (const auto use :
    {CertificateUse::ServerApplicationInstance, CertificateUse::ClientApplicationInstance})
  {
    auto required = sPki->serverOnlyLeaf;
    auto opposite = sPki->clientOnlyLeaf;
    if (use == CertificateUse::ClientApplicationInstance)
    {
      std::swap(required, opposite);
    }
    EXPECT_TRUE(detail::check_certificate_usage(*required, use).is_good());
    EXPECT_TRUE(detail::check_certificate_usage(*sPki->leaf, use).is_good());
    for (const auto& refusedCertificate : {opposite, sPki->noPurposeLeaf})
    {
      const auto refused = detail::check_certificate_usage(*refusedCertificate, use);
      EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
      ASSERT_TRUE(refused.shared_detail());
      EXPECT_EQ(refused.shared_detail()->code, "CertificateExtendedKeyUsageInvalid");
    }
  }
}

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-149-GENERIC-AND-ECC-PURPOSE, scope=function)
TEST_F(CertificateValidationPathWiring, GenericApplicationUsageStillRequiresEitherRsaPurpose)
{
  for (const auto& accepted : {sPki->serverOnlyLeaf, sPki->clientOnlyLeaf, sPki->leaf})
  {
    EXPECT_TRUE(detail::check_certificate_usage(*accepted, CertificateUse::ApplicationInstance).is_good());
  }
  const auto refused =
    detail::check_certificate_usage(*sPki->noPurposeLeaf, CertificateUse::ApplicationInstance);
  EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
  ASSERT_TRUE(refused.shared_detail());
  EXPECT_EQ(refused.shared_detail()->code, "CertificateExtendedKeyUsageInvalid");
}

// Part 6 section 6.2.2 makes serverAuth and clientAuth optional for ECC profiles.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-149-GENERIC-AND-ECC-PURPOSE, scope=function)
TEST_F(CertificateValidationPathWiring, EccApplicationUsageDoesNotRequireRoleEkus)
{
  ASSERT_FALSE(sPki->eccNoPurposeLeaf->extended_key_usage_server_auth());
  ASSERT_FALSE(sPki->eccNoPurposeLeaf->extended_key_usage_client_auth());
  for (const auto use : {CertificateUse::ServerApplicationInstance,
         CertificateUse::ClientApplicationInstance,
         CertificateUse::ApplicationInstance})
  {
    EXPECT_TRUE(detail::check_certificate_usage(*sPki->eccNoPurposeLeaf, use).is_good());
  }
}

// SEAM server::detail::report_suppressed_certificate_errors(observer, remoteAddress, certificate,
// suppressed): the one server function every path calls with the Good result's suppressed faults (item 9).
// Decision 27: the hook takes one CertificateEventInfo carrying the presented certificate.
class RecordingObserver : public server::ServerObserver
{
public:
  void on_certificate_error_suppressed(const server::CertificateEventInfo& info) override
  {
    calls.push_back(info);
  }

  std::vector<server::CertificateEventInfo> calls;
};

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-41-SUPPRESSED-REPORTING, scope=function)
TEST_F(CertificateValidationPathWiring, TheServerReporterCallsTheHookOncePerSuppressedError)
{
  const auto observer = std::make_shared<RecordingObserver>();
  server::detail::report_suppressed_certificate_errors(observer,
    "10.0.0.1:4840",
    sPki->leaf,
    {StatusCode{Status::BadCertificateTimeInvalid}, StatusCode{Status::BadCertificateRevocationUnknown}});
  ASSERT_EQ(observer->calls.size(), 2u);
  EXPECT_EQ(observer->calls[0].status.as_status(), Status::BadCertificateTimeInvalid);
  EXPECT_EQ(observer->calls[1].status.as_status(), Status::BadCertificateRevocationUnknown);
  EXPECT_EQ(observer->calls[0].remoteAddress, "10.0.0.1:4840");
  ASSERT_TRUE(observer->calls[0].certificate);
  EXPECT_EQ(observer->calls[0].certificate->thumbprint(), sPki->leaf->thumbprint())
    << "decision 27: the hook carries the presented certificate";

  server::detail::report_suppressed_certificate_errors(observer, "10.0.0.1:4840", sPki->leaf, {});
  EXPECT_EQ(observer->calls.size(), 2u) << "no suppressed error, no call";
}

// SEAM client::detail::log_suppressed_certificate_errors(logger, subject, suppressed): one warning each.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-41-SUPPRESSED-REPORTING, scope=function)
TEST_F(CertificateValidationPathWiring, TheClientReporterLogsOneWarningPerSuppressedError)
{
  ua::test::TestLogSink sink;
  client::detail::log_suppressed_certificate_errors(sink.logger(),
    "CN=Wiring Leaf",
    {StatusCode{Status::BadCertificateTimeInvalid}, StatusCode{Status::BadCertificateIssuerTimeInvalid}});
  EXPECT_EQ(sink.count(LogLevel::Warning), 2u);
}

/// A trusted, self-signed CA certificate presented as a SecureChannel peer's own: cA=TRUE and an RSA key.
///
/// By default it has the key usage of the CTT's ctt_ca1T - digitalSignature, keyCertSign and cRLSign,
/// but no keyEncipherment or dataEncipherment. With @p applicationUsage it also carries every usage
/// Table 43 asks of an RSA ApplicationInstance Certificate.
class CaCertificateAsPeer final : public ua::testing::StubX509Certificate
{
public:
  explicit CaCertificateAsPeer(bool applicationUsage = false) : mApplicationUsage(applicationUsage)
  {}

  bool key_usage_key_encipherment() const override
  {
    return mApplicationUsage;
  }

  bool key_usage_data_encipherment() const override
  {
    return mApplicationUsage;
  }

  bool key_usage_non_repudiation() const override
  {
    return mApplicationUsage;
  }

  bool key_usage_key_cert_sign() const override
  {
    return true;
  }

  bool key_usage_crl_sign() const override
  {
    return true;
  }

  bool basic_constraints_ca() const override
  {
    return true;
  }

private:
  bool mApplicationUsage;
};

// A CA certificate presented as the peer's ApplicationInstance Certificate is refused for its use when it
// lacks what OPC 10000-6 Table 43 requires of one: for an RSA key, keyEncipherment and dataEncipherment as
// well as digitalSignature (Part 4 Table 106, Certificate Usage). Ported from the CTT campaign's policy-level
// test (Certificate Validation with ctt_ca1T); the use check now lives in the one validation path.
TEST(ApplicationInstanceCertificateUse, ACaCertificateWithoutTheEnciphermentBitsIsRefusedForTheUse)
{
  const auto refused =
    detail::check_certificate_usage(CaCertificateAsPeer{}, CertificateUse::ApplicationInstance);
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), Status::BadCertificateUseNotAllowed);
}

// Table 43: "The cA flag should be FALSE for self-signed Certificates, however, TRUE shall be accepted to
// ensure backward interoperability." A self-signed certificate with cA=TRUE and the usages an
// ApplicationInstance Certificate needs is accepted; the CA flag alone refuses nothing.
TEST(ApplicationInstanceCertificateUse, ASelfSignedCertificateWithTheCaFlagAndApplicationUsageIsAccepted)
{
  const auto accepted =
    detail::check_certificate_usage(CaCertificateAsPeer{true}, CertificateUse::ApplicationInstance);
  EXPECT_TRUE(accepted.is_good());
}

}  // namespace
