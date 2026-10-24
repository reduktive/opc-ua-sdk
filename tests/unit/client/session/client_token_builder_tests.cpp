// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "../sdk/implementation/client/session/ua_client_token_builder.h"

#include "ua_anonymous_identity_token.h"
#include "ua_exceptions.h"
#include "ua_issued_identity_token.h"
#include "ua_message_security_mode.h"
#include "ua_security_policy.h"
#include "ua_to_string.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_x509_identity_token.h"

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client;

namespace
{

UserTokenPolicy make_policy(const std::string& id, UserTokenType type, const std::string& secPolicyUri = "")
{
  UserTokenPolicy p;
  p.policy_id() = id;
  p.token_type() = type;
  p.security_policy_uri() = secPolicyUri;
  return p;
}

auto none_policy()
{
  return SecurityPolicy::create(SecurityPolicyId::None);
}

auto b256s256_policy()
{
  return SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
}

auto aes128_policy()
{
  return SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep);
}

const std::string noneUri = "http://opcfoundation.org/UA/SecurityPolicy#None";

// Minimal test double for X509Certificate - only der_encoding() is used by the builder.
class FakeX509Cert : public X509Certificate
{
public:
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
    return "";
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
    return {};
  }

  ByteString der_encoding() const override
  {
    return ByteString{0x30, 0x82, 0x01};
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

class FakeKeyPair : public AsymmetricKeyPair
{
public:
  CertificateKeyAlgorithm algorithm() const override
  {
    return CertificateKeyAlgorithm::Rsa;
  }

  ByteString public_key_der() const override
  {
    return ByteString{uint8_t{0x01}};
  }

  ByteString private_key_pem() const override
  {
    return ByteString{uint8_t{0x02}};
  }
};

}  // namespace

// ==================== Policy Lookup ====================

// @verifies CL-IDENT-001, CL-IDENT-002
// @relation(CL-IDENT-001, CL-IDENT-002, scope=function)
TEST(TokenBuilderTests, AnonymousEmptyPolicyId_AutoDetects)
{
  std::vector<UserTokenPolicy> policies = {make_policy("anon-0", UserTokenType::Anonymous)};
  auto result = build_user_token(AnonymousIdentity{}, "", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<AnonymousIdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(std::string_view{token->policy_id()}, "anon-0");
}

// @verifies CL-IDENT-002
// When the endpoint advertises NO ANONYMOUS UserTokenPolicy (here: only USERNAME) but the user configured an
// AnonymousIdentity, the client must fail fast with Bad_IdentityTokenRejected (the client must not invent a
// policyId nor send a doomed empty-policyId anonymous token; Part 4 section 7.42 / section 7.41.2.1, ratified
// design).
// @relation(CL-IDENT-002, scope=function)
TEST(TokenBuilderTests, AnonymousEmptyPolicyId_NoAnonPolicy_FailsFast)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName)};
  auto result = build_user_token(AnonymousIdentity{}, "", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad()) << "anonymous with no advertised ANONYMOUS policy must fail fast";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadIdentityTokenRejected});
  ASSERT_NE(result.error_detail(), nullptr) << "the refusal must carry a source-tagged ErrorDetail";
  EXPECT_EQ(result.error_detail()->code, "NoAnonymousUserTokenPolicy");
  EXPECT_EQ(result.error_detail()->source, "client.tier0.token_builder.no_anonymous_policy");
}

TEST(TokenBuilderTests, AnonymousExplicitPolicyId_UsesIt)
{
  std::vector<UserTokenPolicy> policies = {make_policy("anon-explicit", UserTokenType::Anonymous)};
  auto result = build_user_token(
    AnonymousIdentity{}, "anon-explicit", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<AnonymousIdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(std::string_view{token->policy_id()}, "anon-explicit");
}

TEST(TokenBuilderTests, UsernameEmptyPolicyId_ReturnsBadIdentityTokenInvalid)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName)};
  auto result = build_user_token(UsernamePasswordIdentity{"user", "pass"},
    "",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
  ASSERT_NE(result.shared_detail(), nullptr) << "the refusal reason must not be a bare, undiagnosable status";
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.missing_policy_id");
}

TEST(TokenBuilderTests, PolicyIdNotInEndpoint_ReturnsBadIdentityTokenRejected)
{
  std::vector<UserTokenPolicy> policies = {make_policy("anon-0", UserTokenType::Anonymous)};
  auto result =
    build_user_token(AnonymousIdentity{}, "nonexistent", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_NE(result.shared_detail(), nullptr) << "an unadvertised policyId must carry a source-tagged reason";
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.policy_id_not_found");
}

// @verifies CL-IDENT-008
// The endpoint advertises no USERNAME policy; a UsernamePasswordIdentity pointed at the (only)
// Anonymous policy must be refused with a source-tagged token-type-mismatch reason, not a bare status.
// @relation(CL-IDENT-008, scope=function)
TEST(TokenBuilderTests, UsernameIdentityAgainstAnonymousPolicy_ReturnsSourceTaggedMismatch)
{
  std::vector<UserTokenPolicy> policies = {make_policy("anon-0", UserTokenType::Anonymous)};
  auto result = build_user_token(UsernamePasswordIdentity{"user", "pass"},
    "anon-0",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_NE(result.shared_detail(), nullptr) << "a token-type mismatch must name why it was rejected";
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.user_token_type_mismatch");
}

TEST(TokenBuilderTests, TypeMismatch_ReturnsBadIdentityTokenRejected)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName)};
  auto result =
    build_user_token(AnonymousIdentity{}, "user-1", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenRejected});
  ASSERT_NE(result.shared_detail(), nullptr) << "a token-type mismatch must carry a source-tagged reason";
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.user_token_type_mismatch");
}

// ==================== Token Construction ====================

// @verifies CL-IDENT-008, CL-SESS-013
// @relation(CL-IDENT-008, CL-SESS-013, scope=function)
TEST(TokenBuilderTests, UsernameConstructsCorrectWireToken)
{
  std::vector<UserTokenPolicy> policies = {
    make_policy("user-1", UserTokenType::UserName, std::string{b256s256_policy()->uri()})};
  auto result = build_user_token(UsernamePasswordIdentity{"alice", "secret"},
    "user-1",
    policies,
    none_policy(),
    MessageSecurityMode::None);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<UserNameIdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(std::string_view{token->policy_id()}, "user-1");
  EXPECT_EQ(std::string_view{token->user_name()}, "alice");

  std::string password(reinterpret_cast<const char*>(token->password().data()), token->password().size());
  EXPECT_EQ(password, "secret");
}

// @verifies CL-IDENT-010
// @verifies CL-IDENT-013
// @relation(CL-IDENT-010, CL-IDENT-013, scope=function)
TEST(TokenBuilderTests, X509ConstructsCorrectWireToken)
{
  auto cert = std::make_shared<FakeX509Cert>();
  auto keys = std::make_shared<FakeKeyPair>();
  std::vector<UserTokenPolicy> policies = {
    make_policy("x509-1", UserTokenType::Certificate, std::string{b256s256_policy()->uri()})};

  auto result = build_user_token(X509Identity{.certificate = cert, .keyPair = keys},
    "x509-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<X509IdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(std::string_view{token->policy_id()}, "x509-1");
  EXPECT_EQ(token->certificate_data(), cert->der_encoding());
}

// ==================== Table 193 Encryption (Username) ====================

TEST(TokenBuilderTests, NoneChannel_EmptyTokenPolicy_Rejected)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, "")};
  auto result = build_user_token(
    UsernamePasswordIdentity{"u", "p"}, "user-1", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
}

TEST(TokenBuilderTests, NoneChannel_ExplicitNoneTokenPolicy_Rejected)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  auto result = build_user_token(
    UsernamePasswordIdentity{"u", "p"}, "user-1", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
}

// OPC 10000-4 7.41 (1.05.07): "If the SecurityMode is None, SecurityPolicies based on ECC or RSA_DH are not
// allowed and Clients shall not use UserTokenPolicies that require encryption with these SecurityPolicies".
// Over a None channel a UserName or IssuedToken policy naming an ECC or an RSA_DH policy yields no token and
// fails with Bad_SecurityPolicyRejected; the same request naming an RSA policy yields a token to encrypt.
// @relation(AC-CL-SCE-013-NO-SECRET-OVER-NONE, scope=function)
TEST(ClientIdentityTokenEncryption, AnEccTokenPolicyOverANoneChannelIsRefused)
{
  for (const auto policyId : {SecurityPolicyId::EccNistP256AesGcm, SecurityPolicyId::RsaDhAesGcm})
  {
    const auto tokenPolicy = SecurityPolicy::create(policyId);
    SCOPED_TRACE(std::string{tokenPolicy->uri()});
    std::vector<UserTokenPolicy> policies = {
      make_policy("user-1", UserTokenType::UserName, std::string{tokenPolicy->uri()})};
    auto refused = build_user_token(
      UsernamePasswordIdentity{"u", "p"}, "user-1", policies, none_policy(), MessageSecurityMode::None);
    ASSERT_TRUE(refused.is_bad());
    EXPECT_EQ(refused.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
    ASSERT_NE(refused.shared_detail(), nullptr);
    EXPECT_EQ(refused.shared_detail()->code, "EphemeralKeySecretOverNoneChannel");

    // An issued token's secret is encrypted the same way, so it is refused the same way.
    std::vector<UserTokenPolicy> issuedPolicies = {
      make_policy("issued-1", UserTokenType::IssuedToken, std::string{tokenPolicy->uri()})};
    auto issued = build_user_token(IssuedTokenIdentity{.tokenData = ByteString{std::vector<uint8_t>{0x01}}},
      "issued-1",
      issuedPolicies,
      none_policy(),
      MessageSecurityMode::None);
    ASSERT_TRUE(issued.is_bad());
    EXPECT_EQ(issued.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
    ASSERT_NE(issued.shared_detail(), nullptr);
    EXPECT_EQ(issued.shared_detail()->code, "EphemeralKeySecretOverNoneChannel");

    // The same token policy over a SignAndEncrypt channel of that policy is used.
    auto secured = build_user_token(UsernamePasswordIdentity{"u", "p"},
      "user-1",
      policies,
      SecurityPolicy::create(policyId),
      MessageSecurityMode::SignAndEncrypt);
    ASSERT_TRUE(secured.is_good()) << to_string(secured.status_code().as_status());
    ASSERT_NE(secured.value().encryptionPolicy, nullptr);
    EXPECT_EQ(secured.value().encryptionPolicy->id(), policyId);
  }

  // Control: an RSA token policy over the None channel yields a token to encrypt.
  std::vector<UserTokenPolicy> rsaPolicies = {
    make_policy("user-1", UserTokenType::UserName, std::string{b256s256_policy()->uri()})};
  auto rsa = build_user_token(
    UsernamePasswordIdentity{"u", "p"}, "user-1", rsaPolicies, none_policy(), MessageSecurityMode::None);
  ASSERT_TRUE(rsa.is_good());
  ASSERT_NE(rsa.value().encryptionPolicy, nullptr);
  EXPECT_EQ(rsa.value().encryptionPolicy->id(), SecurityPolicyId::Basic256Sha256);
}

TEST(TokenBuilderTests, NoneChannel_OtherTokenPolicy_UsesOther)
{
  auto tokenPolicyUri = std::string{b256s256_policy()->uri()};
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, tokenPolicyUri)};
  auto result = build_user_token(
    UsernamePasswordIdentity{"u", "p"}, "user-1", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().encryptionPolicy, nullptr);
  EXPECT_EQ(result.value().encryptionPolicy->id(), SecurityPolicyId::Basic256Sha256);
}

// CL-IDENT-009 (Part 4 section 7.41.4 lines 10531-10535, Table 193): a UserName token whose resolved policy
// is None travels as a PLAINTEXT UTF-8 password. Per the spec this "should not be used" configuration is a
// hard opt-in at the SDK-API level - the client emits the plaintext password only when
// UsernamePasswordIdentity.allowUnencryptedPassword is set. These rows match the CL-IDENT-009
// integration matrix rows.

// Case 1: token policy None + SignAndEncrypt channel + opt-in ON -> permitted (the channel provides
// confidentiality; no per-token encryption). @verifies CL-IDENT-009
TEST(TokenBuilderTests, UnpNoneTokenPolicy_SaEChannel_OptIn_Permitted)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  UsernamePasswordIdentity identity{"u", "p"};
  identity.allowUnencryptedPassword = true;
  auto result =
    build_user_token(identity, "user-1", policies, b256s256_policy(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good()) << "opt-in must permit unencrypted UNP over a confidential channel";
  EXPECT_EQ(result.value().encryptionPolicy, nullptr)
    << "a None token policy over a confidential channel must not per-token-encrypt";
  EXPECT_NE(result.value().wireToken, nullptr);
}

// Case 2: token policy None + SignAndEncrypt channel + opt-in OFF (default) -> REFUSED (the hard opt-in).
// This is the behavioural gap CL-IDENT-009 closes. @verifies CL-IDENT-009
TEST(TokenBuilderTests, UnpNoneTokenPolicy_SaEChannel_NoOptIn_Refused)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  auto result = build_user_token(UsernamePasswordIdentity{"u", "p"},
    "user-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_bad()) << "unencrypted UNP must be refused by default (no opt-in)";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  // Pin the exact gate (distinguish from the resolve-level cleartext-everywhere "unencrypted_secret_rejected"
  // refusal), with a source-tagged diagnostic.
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier0.token_builder.unp.unencrypted_not_allowed");
}

// Case 3: token policy None + None channel + opt-in ON -> REFUSED anyway (the cleartext-everywhere
// extra-strict guard; the opt-in cannot enable a fully-in-clear password). @verifies CL-IDENT-009
TEST(TokenBuilderTests, UnpNoneTokenPolicy_NoneChannel_OptIn_StillRefused)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  UsernamePasswordIdentity identity{"u", "p"};
  identity.allowUnencryptedPassword = true;
  auto result = build_user_token(identity, "user-1", policies, none_policy(), MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad()) << "a fully-in-clear password must be refused even with the opt-in";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
}

TEST(TokenBuilderTests, OtherChannel_EmptyTokenPolicy_UsesChannel)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, "")};
  auto result = build_user_token(UsernamePasswordIdentity{"u", "p"},
    "user-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().encryptionPolicy, nullptr);
  EXPECT_EQ(result.value().encryptionPolicy->id(), SecurityPolicyId::Basic256Sha256);
}

TEST(TokenBuilderTests, OtherChannel_DifferentTokenPolicy_UsesToken)
{
  auto tokenPolicyUri = std::string{aes128_policy()->uri()};
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, tokenPolicyUri)};
  auto result = build_user_token(UsernamePasswordIdentity{"u", "p"},
    "user-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().encryptionPolicy, nullptr);
  EXPECT_EQ(result.value().encryptionPolicy->id(), SecurityPolicyId::Aes128Sha256RsaOaep);
}

// A None token policy over a SignAndEncrypt channel resolves to NO per-token encryption (the channel
// provides confidentiality). This unencrypted configuration is a hard opt-in (CL-IDENT-009), so the identity
// sets allowUnencryptedPassword; the assertion here is the resolution behaviour (no per-token encryption).
TEST(TokenBuilderTests, OtherChannel_SignAndEncrypt_NoneTokenPolicy_NoEncryption)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  UsernamePasswordIdentity identity{"u", "p"};
  identity.allowUnencryptedPassword = true;
  auto result =
    build_user_token(identity, "user-1", policies, b256s256_policy(), MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().encryptionPolicy, nullptr);
}

// @verifies CL-IDENT-007
// @relation(CL-IDENT-007, scope=function)
TEST(TokenBuilderTests, OtherChannel_Sign_NoneTokenPolicy_Rejected)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, noneUri)};
  auto result = build_user_token(
    UsernamePasswordIdentity{"u", "p"}, "user-1", policies, b256s256_policy(), MessageSecurityMode::Sign);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
}

TEST(TokenBuilderTests, UsernameEmptyPassword_NoEncryption)
{
  std::vector<UserTokenPolicy> policies = {make_policy("user-1", UserTokenType::UserName, "")};
  auto result = build_user_token(UsernamePasswordIdentity{"u", ""},
    "user-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().encryptionPolicy, nullptr);
}

// ==================== X509 Signing ====================

TEST(TokenBuilderTests, X509ExplicitTokenPolicy_UsesTokenPolicy)
{
  auto cert = std::make_shared<FakeX509Cert>();
  auto keys = std::make_shared<FakeKeyPair>();
  auto tokenPolicyUri = std::string{b256s256_policy()->uri()};
  std::vector<UserTokenPolicy> policies = {make_policy("x509-1", UserTokenType::Certificate, tokenPolicyUri)};

  auto result = build_user_token(X509Identity{.certificate = cert, .keyPair = keys},
    "x509-1",
    policies,
    aes128_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().signingPolicy, nullptr);
  EXPECT_EQ(result.value().signingPolicy->id(), SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(result.value().userKeyPair, keys);
}

TEST(TokenBuilderTests, X509EmptyTokenPolicy_UsesChannelPolicy)
{
  auto cert = std::make_shared<FakeX509Cert>();
  auto keys = std::make_shared<FakeKeyPair>();
  std::vector<UserTokenPolicy> policies = {make_policy("x509-1", UserTokenType::Certificate, "")};

  auto result = build_user_token(X509Identity{.certificate = cert, .keyPair = keys},
    "x509-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value().signingPolicy, nullptr);
  EXPECT_EQ(result.value().signingPolicy->id(), SecurityPolicyId::Basic256Sha256);
}

TEST(TokenBuilderTests, X509NoneEffectivePolicy_Rejected)
{
  auto cert = std::make_shared<FakeX509Cert>();
  auto keys = std::make_shared<FakeKeyPair>();
  std::vector<UserTokenPolicy> policies = {make_policy("x509-1", UserTokenType::Certificate, "")};

  auto result = build_user_token(X509Identity{.certificate = cert, .keyPair = keys},
    "x509-1",
    policies,
    none_policy(),
    MessageSecurityMode::None);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
}

TEST(TokenBuilderTests, X509NullKeyPair_ReturnsBadIdentityTokenInvalid)
{
  auto cert = std::make_shared<FakeX509Cert>();
  std::vector<UserTokenPolicy> policies = {
    make_policy("x509-1", UserTokenType::Certificate, std::string{b256s256_policy()->uri()})};

  auto result = build_user_token(X509Identity{.certificate = cert, .keyPair = nullptr},
    "x509-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

// ==================== UTF-8 / non-ASCII password preservation ====================

// A password holding non-ASCII multi-byte UTF-8 sequences must be copied into the wire token
// byte-for-byte: the SDK treats the user-supplied std::string as an opaque UTF-8 byte sequence, so it
// must not transcode it, truncate at an embedded NUL, or drop the high bytes before (later) encryption.
// Falsifiable: a builder that reinterpreted, narrowed, or stopped at a NUL would produce a different
// byte sequence and fail the exact-bytes comparison.
// @verifies CL-IDENT-004
// @relation(CL-IDENT-004, scope=function)
TEST(TokenBuilderTests, UsernameUtf8PasswordPreservedByteForByte)
{
  // "p" + U+00E4 (C3 A4) + U+20AC (E2 82 AC) + U+1F600 (F0 9F 98 80): embedded high bytes and a 4-byte
  // code point, spelled with explicit byte escapes so the test does not depend on the source encoding.
  const std::string utf8Password = {
    'p', '\xC3', '\xA4', '\xE2', '\x82', '\xAC', '\xF0', '\x9F', '\x98', '\x80'};

  std::vector<UserTokenPolicy> policies = {
    make_policy("user-1", UserTokenType::UserName, std::string{b256s256_policy()->uri()})};
  auto result = build_user_token(UsernamePasswordIdentity{"alice", utf8Password},
    "user-1",
    policies,
    none_policy(),
    MessageSecurityMode::None);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<UserNameIdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);

  const std::string actual(reinterpret_cast<const char*>(token->password().data()), token->password().size());
  EXPECT_EQ(actual, utf8Password);
}

// ==================== IssuedIdentityToken carrier ====================

// An application-managed issued token is carried byte-exactly in an IssuedIdentityToken.
TEST(TokenBuilderTests, IssuedTokenCarriedByteExactly)
{
  const ByteString tokenBytes{std::vector<uint8_t>{0x00, 0x7f, 0x80, 0xff}};

  std::vector<UserTokenPolicy> policies = {make_policy("issued-1", UserTokenType::IssuedToken, noneUri)};

  auto result = build_user_token(IssuedTokenIdentity{.tokenData = tokenBytes},
    "issued-1",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<IssuedIdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  EXPECT_EQ(token->token_data(), tokenBytes);
}

// ==================== Chaining: identity is preserved or refused, never dropped ====================

// SVR-SC-024: "When the server is itself a client to a downstream server (aggregating / gateway
// role), the upstream client's user identity MUST flow through ... What the server MUST NOT do is
// strip identity and connect as anonymous (or as its own service account) just because impersonation
// is hard."
//
// This SDK is not a gateway - nothing under `sdk/` relays a request to an upstream peer - so the
// mapping policy belongs to whoever builds one. What the SDK owns is the step where that policy would
// go wrong on its own: turning a chosen identity into a wire token. The forbidden behaviour is a
// silent degradation, and it is forbidden here structurally: every path on which the chosen identity
// cannot be honoured returns a bad status with a source-tagged reason and **no wire token at all**,
// before any traffic. A gateway built on this client cannot connect anonymously by accident; it can
// only be told no.
//
// The tests above already pin each refusal's status and source tag. What none of them says is that
// the refusal is empty - and "returns Bad and also an AnonymousIdentityToken the caller might use" is
// exactly the shape this obligation forbids. That is what this asserts, over all three refusal paths.
// @verifies AC-SVR-SC-024-CHAINED-USER-CONTEXT
TEST(TokenBuilderTests, ARefusedUpstreamIdentityYieldsNoTokenRatherThanAnAnonymousOne)
{
  const std::vector<UserTokenPolicy> anonymousOnly = {make_policy("anon-0", UserTokenType::Anonymous)};
  const std::vector<UserTokenPolicy> usernameOnly = {
    make_policy("user-1", UserTokenType::UserName, std::string{b256s256_policy()->uri()})};

  struct Refusal
  {
    const char* what;
    PreparedTokenResult result;
  };

  std::vector<Refusal> refusals;
  // No policyId supplied for a non-anonymous identity.
  refusals.push_back({"a username identity with no policyId",
    build_user_token(UsernamePasswordIdentity{"alice", "secret"},
      "",
      usernameOnly,
      none_policy(),
      MessageSecurityMode::None)});
  // A policyId the endpoint does not advertise.
  refusals.push_back({"a username identity naming an unadvertised policyId",
    build_user_token(UsernamePasswordIdentity{"alice", "secret"},
      "not-advertised",
      usernameOnly,
      none_policy(),
      MessageSecurityMode::None)});
  // The endpoint advertises only an Anonymous policy for a username identity.
  refusals.push_back({"a username identity against an endpoint offering only Anonymous",
    build_user_token(UsernamePasswordIdentity{"alice", "secret"},
      "anon-0",
      anonymousOnly,
      b256s256_policy(),
      MessageSecurityMode::SignAndEncrypt)});

  for (const auto& [what, result] : refusals)
  {
    ASSERT_TRUE(result.is_bad()) << what
                                 << " was accepted, so the identity was honoured by some route "
                                    "this test does not know about";
    ASSERT_NE(result.shared_detail(), nullptr)
      << what
      << " was refused without a reason, so a gateway operator cannot tell a misconfigured "
         "policy from an endpoint that offers none";

    // There is no token to be had: `Result` in the error state has no value, so a caller cannot
    // reach past the status to something usable. This is the structural form of "never substitute" -
    // stronger than a null token, because there is nothing to read at all.
    EXPECT_THROW((void)result.value(), UaException)
      << what
      << " was refused and still yielded a reachable PreparedToken. A caller that reads past the "
         "status connects as somebody the upstream user did not choose";
  }
}

// The other half of the same obligation: identities that CAN be honoured must not collapse onto one
// another. "Each user maps to a distinct upstream identity, by the same rule every time" - so two
// upstream users driven through the same policy must produce two tokens naming two users, and the
// same user driven twice must produce the same one.
// @verifies AC-SVR-SC-024-CHAINED-USER-CONTEXT
TEST(TokenBuilderTests, TwoUpstreamUsersProduceTwoDistinctTokensAndTheMappingRepeats)
{
  const std::vector<UserTokenPolicy> policies = {
    make_policy("user-1", UserTokenType::UserName, std::string{b256s256_policy()->uri()})};

  const auto tokenFor = [&](const char* user, const char* password)
  {
    auto result = build_user_token(
      UsernamePasswordIdentity{user, password}, "user-1", policies, none_policy(), MessageSecurityMode::None);
    EXPECT_TRUE(result.is_good()) << "building a token for " << user << " failed";
    auto* token = dynamic_cast<UserNameIdentityToken*>(result.value().wireToken.get());
    EXPECT_NE(token, nullptr) << "the token for " << user << " is not a UserNameIdentityToken";
    return token != nullptr ? std::string{std::string_view{token->user_name()}} : std::string{};
  };

  const auto alice = tokenFor("alice", "secret");
  const auto bob = tokenFor("bob", "other");
  const auto aliceAgain = tokenFor("alice", "secret");

  EXPECT_EQ(alice, "alice");
  EXPECT_EQ(bob, "bob");
  EXPECT_NE(alice, bob)
    << "two different upstream users produced the same downstream identity '" << alice
    << "'. Collapsing users onto one account is the easy implementation and it erases the upstream "
       "audit trail's ability to attribute anything";
  EXPECT_EQ(alice, aliceAgain)
    << "the same upstream user produced two different downstream identities across two calls, so the "
       "mapping is not deterministic and no upstream record can be read back to a person";
}

// Completeness review C2 (decision 24): X509IdentityToken.certificateData is the user certificate followed by
// client::X509Identity::issuerCertificates in order (OPC 10000-6 6.2.6).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-81-SEND-OWN-CHAIN, scope=function)
TEST(TokenBuilderTests, X509CertificateDataIsTheLeafThenItsIssuers)
{
  auto cert = std::make_shared<FakeX509Cert>();
  auto keys = std::make_shared<FakeKeyPair>();
  auto issuerA = std::make_shared<FakeX509Cert>();
  auto issuerB = std::make_shared<FakeX509Cert>();
  std::vector<UserTokenPolicy> policies = {
    make_policy("x509-chain", UserTokenType::Certificate, std::string{b256s256_policy()->uri()})};

  auto result = build_user_token(
    X509Identity{.certificate = cert, .keyPair = keys, .issuerCertificates = {issuerA, issuerB}},
    "x509-chain",
    policies,
    b256s256_policy(),
    MessageSecurityMode::SignAndEncrypt);

  ASSERT_TRUE(result.is_good());
  auto* token = dynamic_cast<X509IdentityToken*>(result.value().wireToken.get());
  ASSERT_NE(token, nullptr);
  ByteString expected = cert->der_encoding();
  for (const auto& issuer : {issuerA, issuerB})
  {
    const auto der = issuer->der_encoding();
    std::ranges::copy(der, std::back_inserter(expected));
  }
  EXPECT_EQ(token->certificate_data(), expected);
}
