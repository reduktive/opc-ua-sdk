// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Unit tests for resolve_certificate_type_for_endpoint,
/// resolve_nonce_length_for_endpoint, and validate_user_token_policy_certificate_consistency.

#include <gtest/gtest.h>

#include "ua_stack_utilities.h"
#include "ua_security_policy_compatibility.h"
#include "ua_security_policy.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_crypto_types.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_date_time.h"

using namespace ua;

namespace
{

// ============================================================================
// Helper: build a vector of UserTokenPolicy from variadic SecurityPolicyIds.
// All created as UserName type (which requires an authenticated policy).
// ============================================================================

std::vector<UserTokenPolicy> make_token_policies(
  std::initializer_list<std::pair<UserTokenType, SecurityPolicyId>> entries)
{
  std::vector<UserTokenPolicy> result;
  for (const auto& [type, policy] : entries)
  {
    result.push_back(server::create_user_token_policy(type, policy));
  }
  return result;
}

// Convenience: make authenticated (UserName) token policies from policy ids.
std::vector<UserTokenPolicy> make_username_policies(std::initializer_list<SecurityPolicyId> ids)
{
  std::vector<UserTokenPolicy> result;
  for (auto id : ids)
  {
    result.push_back(server::create_user_token_policy(UserTokenType::UserName, id));
  }
  return result;
}

// ============================================================================
// resolve_certificate_type_for_endpoint
// ============================================================================

class ResolveCertificateTypeForEndpoint : public ::testing::Test
{};

TEST_F(ResolveCertificateTypeForEndpoint, AuthenticatedChannelReturnsChannelCertType)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result =
    stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::Basic256Sha256, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::RsaSha256Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelNoTokenPoliciesReturnsNullopt)
{
  std::vector<UserTokenPolicy> empty;
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, empty);
  EXPECT_FALSE(result.has_value());
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelOnlyAnonymousReturnsNullopt)
{
  auto policies = make_token_policies({{UserTokenType::Anonymous, SecurityPolicyId::None}});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  EXPECT_FALSE(result.has_value());
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelTokenWithEmptyPolicyUriReturnsNullopt)
{
  // A token policy with an empty security_policy_uri inherits the channel policy (None),
  // so it does not contribute an authenticated policy.
  UserTokenPolicy tokenPolicy;
  tokenPolicy.token_type() = UserTokenType::UserName;
  // security_policy_uri left empty
  std::vector<UserTokenPolicy> policies{tokenPolicy};
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  EXPECT_FALSE(result.has_value());
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelSingleRsaTokenPolicyReturnsRsaSha256)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::RsaSha256Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelSingleNistP256ReturnsP256)
{
  auto policies = make_username_policies({SecurityPolicyId::EccNistP256AesGcm});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::EccNistP256Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelNistP256AndP384ReturnsP384)
{
  auto policies =
    make_username_policies({SecurityPolicyId::EccNistP256AesGcm, SecurityPolicyId::EccNistP384AesGcm});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::EccNistP384Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelBrainpoolP256ReturnsP256)
{
  auto policies = make_username_policies({SecurityPolicyId::EccBrainpoolP256r1AesGcm});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::EccBrainpoolP256r1Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelEd25519ReturnsEd25519)
{
  auto policies = make_username_policies({SecurityPolicyId::EccCurve25519ChaChaPoly});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::EccCurve25519Application);
}

TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelMixedRsaPoliciesReturnsRsaSha256)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic128Rsa15, SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::RsaSha256Application);
}

// ============================================================================
// resolve_certificate_type_for_endpoint, certificate-aware (owner decision 2026-10-03, BR-15)
// ============================================================================

namespace
{

/// A held RSA application certificate of @p bits, filed under @p type.
CertificateStore::ApplicationCertificate held_rsa(CertificateType type, size_t bits)
{
  static const auto crypto = create_default_crypto([]() { return ua::SecureString{"p"}; });
  Crypto::SubjectAlternateName names;
  names.uris.push_back("urn:test:resolver");
  auto identity = crypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Resolver " + std::to_string(bits)},
    DateTime{2050, 1, 1, 0, 0, 0},
    names,
    type,
    bits);
  EXPECT_TRUE(identity.is_good()) << "a " << bits << "-bit key for the requested type";
  CertificateStore::ApplicationCertificate held;
  held.certificateType = type;
  held.certificate = identity.value().second;
  held.keys = identity.value().first;
  return held;
}

}  // namespace

// OPC 10000-4 7.41.4 Table 193 and OPC 10000-6 6.8.3: a None-channel endpoint presents one certificate valid
// for every token policy. Basic128Rsa15 allows RSA 1024-2048 bits (Part 7 profile "Basic128Rsa15_Limits"), so
// a 4096-bit RsaSha256 certificate cannot serve it and the held 2048-bit RsaMin one is chosen. Falsifiable:
// the type-only resolution always answered RsaSha256.
// @relation(AC-SVR-IDENT-008-A-NONE-ENDPOINT-CERTIFICATE-IS-VALID-FOR-EVERY-TOKEN-POLICY, scope=function)
TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelDeprecatedPolicyUsesAHeldCertificateValidForIt)
{
  const std::vector held{held_rsa(CertificateType::RsaSha256Application, 4096),
    held_rsa(CertificateType::RsaMinApplication, 2048)};
  auto policies = make_username_policies({SecurityPolicyId::Basic128Rsa15});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies, held);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::RsaMinApplication);
}

// One 2048-bit RSA certificate signed with SHA-256 is valid for Basic128Rsa15 and Basic256Sha256 together
// (Part 7: 1024-2048 and 2048-4096 bits), so the mixed endpoint keeps its RsaSha256 certificate.
// @relation(AC-SVR-IDENT-008-A-NONE-ENDPOINT-CERTIFICATE-IS-VALID-FOR-EVERY-TOKEN-POLICY, scope=function)
TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelMixedRsaPoliciesShareA2048BitCertificate)
{
  const std::vector held{held_rsa(CertificateType::RsaSha256Application, 2048)};
  auto policies = make_username_policies({SecurityPolicyId::Basic128Rsa15, SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies, held);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), CertificateType::RsaSha256Application);
}

// No held certificate serves both policies (1024 bits fails Basic256Sha256, 4096 bits fails Basic128Rsa15):
// no certificate is chosen, and the server refuses such an endpoint at start.
// @relation(AC-SVR-IDENT-008-A-NONE-ENDPOINT-CERTIFICATE-IS-VALID-FOR-EVERY-TOKEN-POLICY, scope=function)
TEST_F(ResolveCertificateTypeForEndpoint, NoneChannelWithNoCertificateValidForEveryPolicyResolvesNone)
{
  const std::vector held{held_rsa(CertificateType::RsaSha256Application, 4096),
    held_rsa(CertificateType::RsaMinApplication, 1024)};
  auto policies = make_username_policies({SecurityPolicyId::Basic128Rsa15, SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_certificate_type_for_endpoint(SecurityPolicyId::None, policies, held);
  EXPECT_FALSE(result.has_value());
}

// ============================================================================
// resolve_nonce_length_for_endpoint
// ============================================================================

class ResolveNonceLengthForEndpoint : public ::testing::Test
{};

TEST_F(ResolveNonceLengthForEndpoint, AuthenticatedChannelReturnsChannelNonceLength)
{
  auto channelPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto expected = channelPolicy->nonce_length();

  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::Basic256Sha256, policies);
  EXPECT_EQ(result, expected);
  EXPECT_GT(result, 0u);
}

// Owner decision 11 gave Basic128Rsa15 a 16-byte SecureChannel nonce; the Session nonces stay at
// least 32 bytes (Part 4 5.6.2), so the server's CreateSession/ActivateSession serverNonce on such a
// channel is 32. The control: an ECC channel keeps its longer policy length.
// @verifies AC-SVR-SESS-015-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE
TEST_F(ResolveNonceLengthForEndpoint, ABasic128Rsa15ChannelKeepsThe32ByteSessionNonceFloor)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic128Rsa15});
  EXPECT_EQ(stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::Basic128Rsa15, policies), 32u);

  const auto ecc = SecurityPolicy::create(SecurityPolicyId::EccNistP384AesGcm);
  EXPECT_EQ(stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::EccNistP384AesGcm, {}),
    ecc->nonce_length());
  EXPECT_GT(ecc->nonce_length(), 32u);
}

// OPC 10000-4 1.05.07 5.7.2 / 5.7.3: a Session nonce has "a length between 32 and 128 bytes inclusive",
// whatever the channel's SecureChannelNonceLength. RSA_DH's is 384 (the ffdhe3072 public value), so its
// Session nonce is 128; every other policy keeps its own length within the range. A None endpoint takes the
// longest of its token policies, so an RSA_DH X509 token policy there gives 128 too.
// @relation(AC-SVR-SESS-015-SESSION-NONCE-CEILING-ON-A-LONG-CHANNEL-NONCE, scope=function)
TEST_F(ResolveNonceLengthForEndpoint, EverySessionNonceIsBetween32And128Bytes)
{
  for (const auto policyId : SecurityPolicy::supported_policy_ids())
  {
    if (policyId == SecurityPolicyId::None)
      continue;
    SCOPED_TRACE(std::string{SecurityPolicy::create(policyId)->uri()});
    const auto channelNonceLength = SecurityPolicy::create(policyId)->nonce_length();
    const auto length = stack_utils::resolve_nonce_length_for_endpoint(policyId, {});
    EXPECT_GE(length, 32u);
    EXPECT_LE(length, 128u);
    if (channelNonceLength >= 32 && channelNonceLength <= 128)
      EXPECT_EQ(length, channelNonceLength) << "a channel nonce within the range is kept";
  }
  EXPECT_EQ(SecurityPolicy::create(SecurityPolicyId::RsaDhAesGcm)->nonce_length(), 384u)
    << "the precondition: RSA_DH's channel nonce is longer than the Session ceiling";
  EXPECT_EQ(stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::RsaDhAesGcm, {}), 128u);

  const auto x509UnderRsaDh =
    make_token_policies({{UserTokenType::Certificate, SecurityPolicyId::RsaDhAesGcm}});
  EXPECT_EQ(stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::None, x509UnderRsaDh), 128u);
}

TEST_F(ResolveNonceLengthForEndpoint, NoneChannelNoTokenPoliciesReturnsZero)
{
  std::vector<UserTokenPolicy> empty;
  auto result = stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::None, empty);
  EXPECT_EQ(result, 0u);
}

TEST_F(ResolveNonceLengthForEndpoint, NoneChannelOnlyAnonymousReturnsZero)
{
  auto policies = make_token_policies({{UserTokenType::Anonymous, SecurityPolicyId::None}});
  auto result = stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::None, policies);
  EXPECT_EQ(result, 0u);
}

TEST_F(ResolveNonceLengthForEndpoint, NoneChannelSingleRsaTokenPolicyReturnsAtLeast32)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result = stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::None, policies);
  EXPECT_GE(result, 32u);
}

TEST_F(ResolveNonceLengthForEndpoint, NoneChannelMultiplePoliciesReturnsMaxWithFloor32)
{
  auto policies =
    make_username_policies({SecurityPolicyId::Basic256Sha256, SecurityPolicyId::Aes256Sha256RsaPss});

  // The result should be at least 32 and should be the max of the individual nonce lengths.
  auto nonceA = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->nonce_length();
  auto nonceB = SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss)->nonce_length();
  auto expectedMax = std::max({nonceA, nonceB, size_t{32}});

  auto result = stack_utils::resolve_nonce_length_for_endpoint(SecurityPolicyId::None, policies);
  EXPECT_EQ(result, expectedMax);
}

// ============================================================================
// validate_user_token_policy_certificate_consistency
// ============================================================================

class ValidateUserTokenPolicyCertificateConsistency : public ::testing::Test
{};

TEST_F(ValidateUserTokenPolicyCertificateConsistency, EmptyTokenPoliciesIsValid)
{
  std::vector<UserTokenPolicy> empty;
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, empty);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, OnlyAnonymousIsValid)
{
  auto policies = make_token_policies({{UserTokenType::Anonymous, SecurityPolicyId::None}});
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, policies);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, SingleRsaTokenPolicyIsValid)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, policies);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, TwoRsaTokenPoliciesIsValid)
{
  auto policies =
    make_username_policies({SecurityPolicyId::Basic256Sha256, SecurityPolicyId::Aes128Sha256RsaOaep});
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, policies);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, RsaPlusNistEccIsCrossFamilyError)
{
  auto policies =
    make_username_policies({SecurityPolicyId::Basic256Sha256, SecurityPolicyId::EccNistP256AesGcm});
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, policies);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConfigurationError});
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, AuthenticatedRsaChannelWithRsaTokenIsValid)
{
  auto policies = make_username_policies({SecurityPolicyId::Basic256Sha256});
  auto result =
    validate_user_token_policy_certificate_consistency(SecurityPolicyId::Basic256Sha256, policies);
  EXPECT_TRUE(result.is_good());
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, AuthenticatedRsaChannelWithNistEccTokenIsError)
{
  auto policies = make_username_policies({SecurityPolicyId::EccNistP256AesGcm});
  auto result =
    validate_user_token_policy_certificate_consistency(SecurityPolicyId::Basic256Sha256, policies);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConfigurationError});
}

TEST_F(ValidateUserTokenPolicyCertificateConsistency, NoneChannelWithMixedFamiliesIsError)
{
  auto policies =
    make_username_policies({SecurityPolicyId::EccNistP256AesGcm, SecurityPolicyId::EccBrainpoolP256r1AesGcm});
  auto result = validate_user_token_policy_certificate_consistency(SecurityPolicyId::None, policies);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadConfigurationError});
}

}  // namespace
