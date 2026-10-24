// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_security_policy_compatibility.h"
#include "ua_error_detail.h"
#include "ua_issued_identity_token.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_security_policy.h"
#include "ua_user_name_identity_token.h"
#include "ua_utilities.h"

namespace ua
{

namespace
{

// Only SecPolEphemeralKey negotiates ephemeral keys or has SecureChannelEnhancements, and it is built only
// from a row of the static policy table, so both questions are a scan of that table (fourteen rows): no
// SecurityPolicy is created.
bool negotiates_ephemeral_keys(SecurityPolicyId id)
{
  return find_ephemeral_key_policy(id) != nullptr;
}

bool has_secure_channel_enhancements(SecurityPolicyId id)
{
  return find_ephemeral_key_policy(id) != nullptr;
}

}  // namespace

std::string_view asymmetric_encryption_algorithm_uri(AsymmetricEncryptionAlgorithm algorithm)
{
  switch (algorithm)
  {
  case AsymmetricEncryptionAlgorithm::RsaPkcs15:
    return "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
  case AsymmetricEncryptionAlgorithm::RsaOaepSha1:
    return "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
  case AsymmetricEncryptionAlgorithm::RsaOaepSha2256:
    return "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256";
  default:
    return {};
  }
}

VoidResult validate_user_token_policy(
  const UserTokenPolicy& tokenPolicy, SecurityPolicyId channelPolicy, MessageSecurityMode channelMode)
{
  auto tokenType = tokenPolicy.token_type();

  // Anonymous tokens are always accepted - no secret to protect.
  if (tokenType == UserTokenType::Anonymous)
    return VoidResult{};

  // Determine whether this token type carries a secret that needs encryption.
  const bool carriesSecret =
    (tokenType == UserTokenType::UserName || tokenType == UserTokenType::IssuedToken);

  // Compute the effective token security policy (inherit channel if empty).
  const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
  const SecurityPolicyId effectiveTokenPolicy =
    tokenPolicyUri.empty() ? channelPolicy : utils::get_security_policy_id(tokenPolicyUri);

  // Rule 1: No cleartext secrets.
  // If effective policy is None, the token is not encrypted. The channel must encrypt (SignAndEncrypt).
  if (carriesSecret &&
      (effectiveTokenPolicy == SecurityPolicyId::None || effectiveTokenPolicy == SecurityPolicyId::Invalid))
  {
    if (channelMode != MessageSecurityMode::SignAndEncrypt)
    {
      return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
        ErrorDetail::build("CleartextSecretRejected",
          "User token policy with effective SecurityPolicy None requires MessageSecurityMode "
          "SignAndEncrypt",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
          .context(ua::ContextKeys::securityMode, ua::to_string(channelMode))};
    }
    return VoidResult{};
  }

  // X509 tokens always require an authenticated security policy for the UserTokenSignature.
  // Without one, the server cannot verify proof-of-possession of the user certificate's private key.
  if (tokenType == UserTokenType::Certificate &&
      (effectiveTokenPolicy == SecurityPolicyId::None || effectiveTokenPolicy == SecurityPolicyId::Invalid))
  {
    return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
      ErrorDetail::build("X509RequiresAuthenticatedPolicy",
        "X509 user token policy requires an authenticated security policy for UserTokenSignature, "
        "but effective policy is None",
        "UserTokenPolicyValidation")
        .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})};
  }

  const bool channelSecured = channelMode != MessageSecurityMode::None &&
                              channelPolicy != SecurityPolicyId::None &&
                              channelPolicy != SecurityPolicyId::Invalid;
  // Rendered only for a refusal's ErrorDetail.
  const auto effectivePolicyUri = [effectiveTokenPolicy]
  {
    return std::string{utils::get_security_policy_uri(effectiveTokenPolicy)};
  };

  // OPC 10000-4 7.41 (1.05.07): "If the SecurityMode is None, SecurityPolicies based on ECC or RSA_DH are not
  // allowed" for a token whose secret they encrypt, and the EphemeralKey they encrypt with is exchanged only
  // where the endpoint's own policy uses ephemeral key agreement (decision D-16). The guard runs when the
  // server starts and at every ActivateSession, so such a policy is neither offered nor honoured. Cost: at
  // most three scans of the fourteen-row policy table, no allocation.
  if (carriesSecret && negotiates_ephemeral_keys(effectiveTokenPolicy))
  {
    if (!channelSecured)
    {
      return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
        ErrorDetail::build("EphemeralKeySecretOverNoneChannel",
          "A UserName or IssuedToken policy naming an ECC or RSA_DH SecurityPolicy is not allowed over a "
          "SecureChannel whose SecurityMode is None",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
          .context(ua::ContextKeys::securityPolicy, effectivePolicyUri())};
    }
    if (!negotiates_ephemeral_keys(channelPolicy))
    {
      return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
        ErrorDetail::build("EphemeralKeySecretWithoutKeyAgreement",
          "A UserName or IssuedToken policy naming an ECC or RSA_DH SecurityPolicy needs an endpoint "
          "whose own SecurityPolicy uses ephemeral key agreement",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
          .context(ua::ContextKeys::securityPolicy, effectivePolicyUri())};
    }
  }

  // An X509 token whose policy has SecureChannelEnhancements is signed over the Table 101 data of OPC
  // 10000-4 6.1.8, which starts with the ChannelThumbprint; a secured SecureChannel without them computes
  // none. 6.1.8 gives an OctetString of 0 length where the stack cannot supply one (HTTPS), but peers refuse
  // such a token over a UA-TCP channel (Milo answers Bad_IdentityTokenInvalid at activation), so the SDK does
  // not offer it there (guess G-33). Over a None channel the token signs the None-mode layout.
  if (tokenType == UserTokenType::Certificate && has_secure_channel_enhancements(effectiveTokenPolicy) &&
      channelSecured && !has_secure_channel_enhancements(channelPolicy))
  {
    return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
      ErrorDetail::build("EnhancedTokenPolicyOverLegacyChannel",
        "An X509 token policy whose SecurityPolicy has SecureChannelEnhancements needs a SecureChannel "
        "that has them too, or one whose SecurityMode is None",
        "UserTokenPolicyValidation")
        .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
        .context(ua::ContextKeys::securityPolicy, effectivePolicyUri())};
  }

  return VoidResult{};
}

VoidResult validate_presented_user_token(const UserTokenPolicy& tokenPolicy, SecurityPolicyId channelPolicy,
  MessageSecurityMode channelMode, const Structure& presentedToken)
{
  // Only the two token types that carry a secret are constrained; an X509 token's proof is a
  // signature, and an Anonymous token has nothing to protect.
  const auto* userName = dynamic_cast<const UserNameIdentityToken*>(&presentedToken);
  const auto* issued = dynamic_cast<const IssuedIdentityToken*>(&presentedToken);
  if (userName == nullptr && issued == nullptr)
    return VoidResult{};

  const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
  const SecurityPolicyId effectiveTokenPolicy =
    tokenPolicyUri.empty() ? channelPolicy : utils::get_security_policy_id(tokenPolicyUri);

  // Effective None means the secret is not encrypted by design. validate_user_token_policy has
  // already required the channel to carry SignAndEncrypt in that case, so the secret is protected by
  // the channel instead. A UserName token that nonetheless names an encryptionAlgorithm claims an
  // encryption the policy does not provide: Part 4 7.41.3 leaves the field null when the password is
  // not encrypted, so such a token is malformed against its policy.
  if (effectiveTokenPolicy == SecurityPolicyId::None || effectiveTokenPolicy == SecurityPolicyId::Invalid)
  {
    if (userName != nullptr && !userName->encryption_algorithm().empty())
    {
      return VoidResult{StatusCode{Status::BadIdentityTokenInvalid},
        ErrorDetail::build("UserTokenEncryptionAlgorithmUnexpected",
          "the UserName token names an encryptionAlgorithm under a UserTokenPolicy whose effective "
          "SecurityPolicy is None, so the password is not encrypted",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})};
    }
    return VoidResult{};
  }

  // A token that carries no secret has nothing this guard protects. The obligation is that a secret
  // shall not travel in clear; it is not that the field must be present. A UserName token with an
  // empty password conveys no credential at all - whether the Server should authenticate anyone on
  // that basis is the authenticator's ruling, and refusing it here would answer an authorisation
  // question with an encryption error.
  //
  // This mirrors the client, which encrypts on exactly the same test (`userNameCarriesSecret` /
  // `issuedCarriesSecret` in SessionImpl::start_encrypt_user_token). Sender and receiver must agree
  // on what counts as a secret, or the client emits a token in a shape the server then refuses.
  //
  // Recorded because the first version of this guard omitted the test and refused an empty-password
  // UserName token, which broke
  // SessionShellWiringTests.EndpointAcceptsExactlyThePublishedUserTokenTypes. That was read at first
  // as debt in the fixture; it was over-reach in the guard.
  const bool carriesSecret =
    userName != nullptr ? !userName->password().empty() : !issued->token_data().empty();
  if (!carriesSecret)
    return VoidResult{};

  // An encrypted IssuedIdentityToken is an EncryptedSecret, which names its own SecurityPolicyUri, and for
  // its encryptionAlgorithm "the Client shall set this field to null or empty and Servers shall ignore any
  // value specified" (OPC 10000-4 1.05.06 7.40.6 Table 191). The Session decodes tokenData under the
  // negotiated policy whatever the field holds, and clear or malformed bytes fail that decoder.
  if (issued != nullptr)
    return VoidResult{};

  // The same holds for a UserName token under a SecurityPolicy with SecureChannelEnhancements (Table 188).
  // Each such policy the SDK implements uses ephemeral keys, so the password is an EccEncryptedSecret, which
  // the Session always decodes under the negotiated policy before the application authenticator sees it.
  if (has_secure_channel_enhancements(effectiveTokenPolicy))
    return VoidResult{};

  if (!userName->encryption_algorithm().empty())
  {
    // Part 4 7.41.3: the field is the URI of the asymmetric algorithm that encrypted the password. The
    // effective policy's own URI is accepted as well, because SDK clients have always sent that and the
    // Session's decryption follows the negotiated policy rather than this field.
    const auto policy = SecurityPolicy::create(effectiveTokenPolicy);
    const std::string_view presented{userName->encryption_algorithm()};
    const auto expectedAlgorithm =
      asymmetric_encryption_algorithm_uri(policy->asymmetric_encryption_algorithm());
    if (presented == std::string_view{policy->uri()} ||
        (!expectedAlgorithm.empty() && presented == expectedAlgorithm))
      return VoidResult{};
    return VoidResult{StatusCode{Status::BadIdentityTokenInvalid},
      ErrorDetail::build("UserTokenEncryptionAlgorithmMismatch",
        "the UserName token's encryptionAlgorithm does not name the algorithm of its effective "
        "SecurityPolicy",
        "UserTokenPolicyValidation")
        .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
        .context(ua::ContextKeys::securityPolicy, std::string{policy->uri()})};
  }

  // Bad_IdentityTokenInvalid rather than Rejected: the token is malformed against the policy it
  // names, not a well-formed token the Server declines to accept (OPC 10000-4 Table 182).
  return VoidResult{StatusCode{Status::BadIdentityTokenInvalid},
    ErrorDetail::build("UserTokenNotEncrypted",
      "the presented user identity token carries its secret unencrypted under a UserTokenPolicy "
      "whose effective SecurityPolicy requires encryption",
      "UserTokenPolicyValidation")
      .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})
      .context(ua::ContextKeys::securityPolicy,
        std::string{
          tokenPolicyUri.empty() ? std::string_view{"(channel)"} : std::string_view{tokenPolicyUri}})
      .context(ua::ContextKeys::securityMode, ua::to_string(channelMode))};
}

namespace
{

enum class CertFamily
{
  None,
  Rsa,
  NistEcc,
  BrainpoolEcc,
  Ed25519,
  Ed448
};

CertFamily classify_cert_type(CertificateType certType)
{
  switch (certType)
  {
  case CertificateType::RsaMinApplication:
  case CertificateType::RsaSha256Application:
    return CertFamily::Rsa;
  case CertificateType::EccNistP256Application:
  case CertificateType::EccNistP384Application:
    return CertFamily::NistEcc;
  case CertificateType::EccBrainpoolP256r1Application:
  case CertificateType::EccBrainpoolP384r1Application:
    return CertFamily::BrainpoolEcc;
  case CertificateType::EccCurve25519Application:
    return CertFamily::Ed25519;
  case CertificateType::EccCurve448Application:
    return CertFamily::Ed448;
  default:
    return CertFamily::None;
  }
}

const char* family_name(CertFamily f)
{
  switch (f)
  {
  case CertFamily::Rsa:
    return "RSA";
  case CertFamily::NistEcc:
    return "NIST ECC";
  case CertFamily::BrainpoolEcc:
    return "Brainpool ECC";
  case CertFamily::Ed25519:
    return "Ed25519";
  case CertFamily::Ed448:
    return "Ed448";
  default:
    return "None";
  }
}

}  // namespace

VoidResult validate_user_token_policy_certificate_consistency(
  SecurityPolicyId channelPolicyId, const std::vector<UserTokenPolicy>& userTokenPolicies)
{
  CertFamily tokenFamily = CertFamily::None;

  for (const auto& tokenPolicy : userTokenPolicies)
  {
    const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
    if (tokenPolicyUri.empty())
      continue;

    auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
    if (tokenPolicyId == SecurityPolicyId::None || tokenPolicyId == SecurityPolicyId::Invalid)
      continue;

    auto policy = SecurityPolicy::create(tokenPolicyId);
    auto certType = policy->certificate_type();
    auto family = classify_cert_type(certType);
    if (family == CertFamily::None)
      continue;

    if (tokenFamily == CertFamily::None)
    {
      tokenFamily = family;
    }
    else if (tokenFamily != family)
    {
      return VoidResult{StatusCode{Status::BadConfigurationError},
        ErrorDetail::build("CrossFamilyTokenPolicies",
          "Endpoint has user token policies from incompatible certificate families",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::certificateFamilyExpected, family_name(tokenFamily))
          .context(ua::ContextKeys::certificateFamilyActual, family_name(family))};
    }
  }

  // For authenticated channels, the user token cert family must match the channel family.
  if (tokenFamily != CertFamily::None && channelPolicyId != SecurityPolicyId::None &&
      channelPolicyId != SecurityPolicyId::Invalid)
  {
    auto channelPolicy = SecurityPolicy::create(channelPolicyId);
    auto channelFamily = classify_cert_type(channelPolicy->certificate_type());
    if (channelFamily != CertFamily::None && channelFamily != tokenFamily)
    {
      return VoidResult{StatusCode{Status::BadConfigurationError},
        ErrorDetail::build("TokenPolicyFamilyMismatch",
          "User token certificate family does not match channel security policy certificate family",
          "UserTokenPolicyValidation")
          .context(ua::ContextKeys::certificateFamilyActual, family_name(tokenFamily))
          .context(ua::ContextKeys::certificateFamilyExpected, family_name(channelFamily))};
    }
  }

  return VoidResult{};
}

}  // namespace ua
