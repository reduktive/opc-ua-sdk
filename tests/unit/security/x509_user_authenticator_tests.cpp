// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for X509UserAuthenticator.

#include <gtest/gtest.h>

#include "ua_built_in_authenticators.h"
#include "ua_certificate_store.h"

#include <type_traits>
#include "ua_x509_certificate.h"

#include <future>

using namespace ua;
using namespace ua::server;

namespace
{

// Minimal X509Certificate test double with configurable subject_common_name and thumbprint.
class FakeX509Cert : public X509Certificate
{
public:
  std::string commonName;
  ByteString thumbprintValue;

  explicit FakeX509Cert(std::string commonName = "TestUser", ByteString thumbprint = {0xAB, 0xCD})
    : commonName(std::move(commonName)), thumbprintValue(std::move(thumbprint))
  {}

  bool operator==(const X509Certificate&) const override
  {
    return false;
  }

  int version() const override
  {
    return 3;
  }

  std::string serial_number() const override
  {
    return "1";
  }

  ByteString signature() const override
  {
    return {};
  }

  std::string issuer() const override
  {
    return "";
  }

  std::string issuer_country() const override
  {
    return "";
  }

  std::string issuer_organization() const override
  {
    return "";
  }

  std::string issuer_organizational_unit() const override
  {
    return "";
  }

  std::string issuer_distinguished_name() const override
  {
    return "";
  }

  std::string issuer_state() const override
  {
    return "";
  }

  std::string issuer_common_name() const override
  {
    return "";
  }

  std::string issuer_domain_component() const override
  {
    return "";
  }

  std::string issuer_locality() const override
  {
    return "";
  }

  UtcTime validity_from() const override
  {
    return {};
  }

  UtcTime validity_to() const override
  {
    return {};
  }

  std::string subject() const override
  {
    return "";
  }

  std::string subject_country() const override
  {
    return "";
  }

  std::string subject_organization() const override
  {
    return "";
  }

  std::string subject_organizational_unit() const override
  {
    return "";
  }

  std::string subject_distinguished_name() const override
  {
    return "";
  }

  std::string subject_state() const override
  {
    return "";
  }

  std::string subject_common_name() const override
  {
    return commonName;
  }

  std::string subject_domain_component() const override
  {
    return "";
  }

  std::string subject_locality() const override
  {
    return "";
  }

  ByteString public_key() const override
  {
    return {};
  }

  size_t public_key_bit_length() const override
  {
    return 2048;
  }

  CertificateKeyAlgorithm key_algorithm() const override
  {
    return CertificateKeyAlgorithm::Rsa;
  }

  ByteString authority_key_identifier() const override
  {
    return {};
  }

  ByteString subject_key_identifier() const override
  {
    return {};
  }

  bool key_usage_digital_signature() const override
  {
    return true;
  }

  bool key_usage_non_repudiation() const override
  {
    return false;
  }

  bool key_usage_key_encipherment() const override
  {
    return true;
  }

  bool key_usage_data_encipherment() const override
  {
    return false;
  }

  bool key_usage_key_agreement() const override
  {
    return false;
  }

  bool key_usage_key_cert_sign() const override
  {
    return false;
  }

  bool key_usage_crl_sign() const override
  {
    return false;
  }

  bool key_usage_encipher_only() const override
  {
    return false;
  }

  bool key_usage_decipher_only() const override
  {
    return false;
  }

  std::vector<boost::asio::ip::address> san_ip_addresses() const override
  {
    return {};
  }

  std::vector<std::string> san_hostnames() const override
  {
    return {};
  }

  std::vector<std::string> san_uris() const override
  {
    return {};
  }

  bool basic_constraints_ca() const override
  {
    return false;
  }

  uint32_t basic_constraints_path_length() const override
  {
    return 0;
  }

  bool extended_key_usage_client_auth() const override
  {
    return true;
  }

  bool extended_key_usage_server_auth() const override
  {
    return false;
  }

  ByteString thumbprint() const override
  {
    return thumbprintValue;
  }

  ByteString der_encoding() const override
  {
    return {uint8_t{0x30}};
  }

  bool issued_by(const X509Certificate&) const override
  {
    return false;
  }

  bool issuer_of(const X509Certificate&) const override
  {
    return false;
  }

  bool self_signed() const override
  {
    return true;
  }

  CertificateSignatureAlgorithm signature_algorithm() const override
  {
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
};

// Minimal CertificateStore that can be configured to accept or reject certificates.
class FakeCertificateStore : public CertificateStore
{
public:
  VoidResult validationResult{VoidResult{}};

  int validateCalls{0};

  void validate_certificate_async(
    CertificateValidationRequest, Crypto::CertificateValidationCompleteCallback callback) noexcept override
  {
    ++validateCalls;
    callback(validationResult);
  }

  // Stubs for unused methods.
  void add_to_application_certificates_async(ApplicationCertificate, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_application_certificate_async(
    CertificateType, GetApplicationCertificateCallback cb) const noexcept override
  {
    cb(StatusCode{Status::BadNotFound});
  }

  void get_application_certificates_async(GetApplicationCertificatesCallback cb) const noexcept override
  {
    cb(ApplicationCertificateListResult{ApplicationCertificateList{}});
  }

  void add_to_trusted_certificates_async(
    shared_ptr<const X509Certificate>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void add_to_trusted_certificates_async(
    std::vector<shared_ptr<const X509Certificate>>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_trusted_certificates_async(GetCertificatesCallback cb) const noexcept override
  {
    cb(CertificateListResult{CertificateList{}});
  }

  void add_to_issuer_certificates_async(
    shared_ptr<const X509Certificate>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void add_to_issuer_certificates_async(
    std::vector<shared_ptr<const X509Certificate>>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_issuer_certificates_async(GetCertificatesCallback cb) const noexcept override
  {
    cb(CertificateListResult{CertificateList{}});
  }

  void add_to_rejected_certificates_async(
    shared_ptr<const X509Certificate>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_rejected_certificates_async(GetCertificatesCallback cb) const noexcept override
  {
    cb(CertificateListResult{CertificateList{}});
  }

  void add_to_trusted_crls_async(shared_ptr<const X509Crl>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void add_to_trusted_crls_async(
    std::vector<shared_ptr<const X509Crl>>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_trusted_crls_async(GetCrlsCallback cb) const noexcept override
  {
    cb(CrlListResult{CrlList{}});
  }

  void add_to_issuer_crls_async(shared_ptr<const X509Crl>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void add_to_issuer_crls_async(std::vector<shared_ptr<const X509Crl>>, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{});
  }

  void get_issuer_crls_async(GetCrlsCallback cb) const noexcept override
  {
    cb(CrlListResult{CrlList{}});
  }

  void replace_trusted_certificates_async(CertificateList, CrlList, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void replace_issuer_certificates_async(CertificateList, CrlList, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void remove_from_trusted_certificates_async(const std::string&, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void remove_from_issuer_certificates_async(const std::string&, CompleteCallback cb) noexcept override
  {
    cb(VoidResult{StatusCode{Status::BadNotSupported}});
  }

  void set_validation_options(TrustListValidationOptions) override
  {}

  TrustListValidationOptions validation_options() const override
  {
    return {};
  }

  void refresh_cache(CompleteCallback cb) override
  {
    cb(VoidResult{});
  }
};

AuthnResult authenticate_sync(X509UserAuthenticator& authenticator, AuthnRequest req)
{
  std::promise<AuthnResult> promise;
  authenticator.authenticate_async(
    std::move(req), [&](AuthnResult result) { promise.set_value(std::move(result)); });
  return promise.get_future().get();
}

AuthnRequest make_x509_request(std::shared_ptr<const X509Certificate> cert)
{
  AuthnRequest req;
  req.identity.kind = UserTokenKind::X509;
  req.identity.x509Certificate = std::move(cert);
  return req;
}

}  // namespace

// D12 (public_api_1_0_design.md section 13.9): the authenticator takes no store. The constructor that took
// one ignored it, so a server that handed it its store and set no userTokenCertificateStore refused every
// X.509 user; the session's user-token store is the only one.
static_assert(!std::is_constructible_v<X509UserAuthenticator, std::shared_ptr<CertificateStore>>);
static_assert(std::is_default_constructible_v<X509UserAuthenticator>);

TEST(X509UserAuthenticatorTest, RejectsAnonymousToken)
{
  X509UserAuthenticator auth;

  AuthnRequest req;
  req.identity.kind = UserTokenKind::Anonymous;

  auto result = authenticate_sync(auth, std::move(req));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(result.is_bad());
}

TEST(X509UserAuthenticatorTest, RejectsUserNameToken)
{
  X509UserAuthenticator auth;

  AuthnRequest req;
  req.identity.kind = UserTokenKind::UserName;
  req.identity.userName = "someuser";
  req.identity.password = SecureString{"pass"};

  auto result = authenticate_sync(auth, std::move(req));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});
}

TEST(X509UserAuthenticatorTest, RejectsIssuedToken)
{
  X509UserAuthenticator auth;

  AuthnRequest req;
  req.identity.kind = UserTokenKind::IssuedToken;

  auto result = authenticate_sync(auth, std::move(req));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});
}

TEST(X509UserAuthenticatorTest, RejectsX509TokenWithMissingCertificate)
{
  X509UserAuthenticator auth;

  AuthnRequest req;
  req.identity.kind = UserTokenKind::X509;
  // No certificate set.

  auto result = authenticate_sync(auth, std::move(req));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

TEST(X509UserAuthenticatorTest, AcceptsValidX509Token)
{
  X509UserAuthenticator auth;

  auto cert = std::make_shared<FakeX509Cert>("Alice", ByteString{0x01, 0x02});
  auto result = authenticate_sync(auth, make_x509_request(cert));

  ASSERT_TRUE(result.is_good());
  const auto& user = result.value().user;
  EXPECT_EQ(user.userId, "Alice");
  EXPECT_EQ(user.displayName, "Alice");
  EXPECT_EQ(user.kind, UserTokenKind::X509);
  EXPECT_TRUE(user.claims.count("thumbprint"));
}

// Owner review 2026-10-02, item 8: the session validates the X509 user certificate through the single
// pipeline BEFORE the authenticator runs, so the authenticator sees only validated certificates and keeps the
// identity -> user mapping alone. The certificate-failure -> Bad_IdentityTokenRejected mapping (OPC 10000-4
// ActivateSession; the Table 106 cause kept in the ErrorDetail) moved with the validation: it is asserted on
// the session's function in certificate_presented_chain_path_tests.cpp
// (EveryCertificateFaultMapsToIdentityTokenRejectedWithItsCause) and through ActivateSession in
// client_signature_verification_tests.cpp
// (ActivateSessionValidatesTheX509UserCertificateBeforeTheAuthenticator). Here: a store that would refuse is
// NOT consulted, and the authenticator maps the identity. Falsifiable: an authenticator that still validates
// returns Bad_IdentityTokenRejected and bumps validateCalls.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-35-USER-TOKEN-SESSION-VALIDATES, scope=function)
TEST(X509UserAuthenticatorTest, DoesNotValidateTheCertificateItself)
{
  auto store = std::make_shared<FakeCertificateStore>();
  store->validationResult = StatusCode{Status::BadCertificateUntrusted};

  // D12: the authenticator takes no store; the server's user-token store reaches it on the request.
  X509UserAuthenticator auth;

  auto cert = std::make_shared<FakeX509Cert>("Alice", ByteString{0x01, 0x02});
  auto request = make_x509_request(cert);
  request.userTokenCertificateStore = store;
  auto result = authenticate_sync(auth, std::move(request));

  ASSERT_TRUE(result.is_good()) << "the authenticator maps an already-validated certificate";
  EXPECT_EQ(result.value().user.userId, "Alice");
  EXPECT_EQ(store->validateCalls, 0) << "validation belongs to the session, before the authenticator";
}

TEST(X509UserAuthenticatorTest, UsesThumbprintAsUserIdWhenCommonNameEmpty)
{
  X509UserAuthenticator auth;

  auto cert = std::make_shared<FakeX509Cert>("", ByteString{0xDE, 0xAD});
  auto result = authenticate_sync(auth, make_x509_request(cert));

  ASSERT_TRUE(result.is_good());
  const auto& user = result.value().user;
  // When CN is empty, userId and displayName fall back to the hex thumbprint.
  EXPECT_FALSE(user.userId.empty());
  EXPECT_EQ(user.userId, user.displayName);
  EXPECT_EQ(user.kind, UserTokenKind::X509);
}
