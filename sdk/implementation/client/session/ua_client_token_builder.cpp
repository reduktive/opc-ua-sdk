// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_validation_paths.h"
#include "ua_client_token_builder.h"

#include "ua_anonymous_identity_token.h"
#include "ua_error_detail.h"
#include "ua_issued_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_type.h"
#include "ua_x509_identity_token.h"

#include <algorithm>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

namespace ua::client
{

namespace
{

constexpr std::string_view nonePolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";

ua::UserTokenType expected_token_type(const UserIdentity& identity)
{
  return std::visit(
    [](const auto& id) -> ua::UserTokenType
    {
      using T = std::decay_t<decltype(id)>;
      if constexpr (std::is_same_v<T, AnonymousIdentity>)
        return ua::UserTokenType::Anonymous;
      else if constexpr (std::is_same_v<T, UsernamePasswordIdentity>)
        return ua::UserTokenType::UserName;
      else if constexpr (std::is_same_v<T, X509Identity>)
        return ua::UserTokenType::Certificate;
      else if constexpr (std::is_same_v<T, IssuedTokenIdentity>)
        return ua::UserTokenType::IssuedToken;
    },
    identity);
}

/// Resolve the encryption policy for a UserName token with a non-empty password
/// per Part 4 Table 193.
PreparedTokenResult resolve_username_encryption(const ua::UserTokenPolicy& policy,
  const std::shared_ptr<ua::SecurityPolicy>& channelPolicy, ua::MessageSecurityMode channelSecurityMode)
{
  auto tokenSecUri = std::string_view{policy.security_policy_uri()};

  if (!tokenSecUri.empty() && tokenSecUri != nonePolicyUri)
  {
    // Token policy specifies a non-None security policy - use it for encryption.
    // SecurityPolicy::create THROWS on an unknown/malformed URI, and this securityPolicyUri is
    // server-controlled (a UserTokenPolicy the server advertised). Fail CLOSED with a clean source-tagged
    // Bad instead of letting the throw escape the security-decision path.
    std::shared_ptr<ua::SecurityPolicy> encPolicy;
    try
    {
      encPolicy = ua::SecurityPolicy::create(tokenSecUri);
    }
    catch (...)
    {
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
        ua::make_error_detail("TokenSecurityPolicyRejected",
          "the token's securityPolicyUri is not a recognised security policy",
          "client.tier0.token_builder.security_policy_create_failed")};
    }
    if (!encPolicy || !encPolicy->is_authenticated())
    {
      return PreparedTokenResult{ua::Status::BadSecurityPolicyRejected};
    }
    // OPC 10000-4 7.41 (1.05.07): "If the SecurityMode is None, SecurityPolicies based on ECC or RSA_DH are
    // not allowed and Clients shall not use UserTokenPolicies that require encryption with these
    // SecurityPolicies".
    if (encPolicy->ephemeral_key_algorithm() != ua::EphemeralKeyAlgorithm::Invalid &&
        channelSecurityMode == ua::MessageSecurityMode::None)
    {
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
        ua::make_error_detail("EphemeralKeySecretOverNoneChannel",
          "the token policy encrypts its secret under an ECC or RSA_DH SecurityPolicy, which a "
          "SecureChannel with SecurityMode None does not allow",
          "client.tier0.token_builder.ephemeral_key_secret_over_none")};
    }
    return PreparedTokenResult{PreparedToken{.wireToken = nullptr,
      .encryptionPolicy = std::move(encPolicy),
      .signingPolicy = nullptr,
      .userKeyPair = nullptr}};
  }

  if (tokenSecUri.empty())
  {
    // Token policy is empty - fall back to channel policy.
    if (!channelPolicy || !channelPolicy->is_authenticated())
    {
      return PreparedTokenResult{ua::Status::BadSecurityPolicyRejected};
    }
    return PreparedTokenResult{PreparedToken{.wireToken = nullptr,
      .encryptionPolicy = channelPolicy,
      .signingPolicy = nullptr,
      .userKeyPair = nullptr}};
  }

  // Token policy security URI is the None URI.
  if (channelSecurityMode == ua::MessageSecurityMode::SignAndEncrypt)
  {
    // Channel provides confidentiality - no per-token encryption needed.
    return PreparedTokenResult{PreparedToken{
      .wireToken = nullptr, .encryptionPolicy = nullptr, .signingPolicy = nullptr, .userKeyPair = nullptr}};
  }

  // Mode is Sign or None - the token secret would travel without confidentiality. Refuse with a
  // source-tagged Bad.
  return PreparedTokenResult{ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
    ua::make_error_detail("UnencryptedSecretRejected",
      "the user token secret cannot be sent confidentially (no per-token or channel encryption)",
      "client.tier0.token_builder.unencrypted_secret_rejected")};
}

/// Resolve the signing policy for an X509 token.
PreparedTokenResult resolve_x509_signing(const ua::UserTokenPolicy& policy,
  const std::shared_ptr<ua::SecurityPolicy>& channelPolicy, const X509Identity& x509)
{
  if (!x509.keyPair)
  {
    return PreparedTokenResult{ua::Status::BadIdentityTokenInvalid};
  }

  auto tokenSecUri = std::string_view{policy.security_policy_uri()};

  std::shared_ptr<ua::SecurityPolicy> signingPolicy;

  if (!tokenSecUri.empty() && tokenSecUri != nonePolicyUri)
  {
    // Fail CLOSED on a throwing create (server-controlled URI)  -  same hazard as resolve_username_encryption
    // (section 3.1 W7 FIX4).
    try
    {
      signingPolicy = ua::SecurityPolicy::create(tokenSecUri);
    }
    catch (...)
    {
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
        ua::make_error_detail("TokenSecurityPolicyRejected",
          "the token's securityPolicyUri is not a recognised security policy",
          "client.tier0.token_builder.security_policy_create_failed")};
    }
  }
  else if (tokenSecUri.empty())
  {
    signingPolicy = channelPolicy;
  }
  // tokenSecUri == kNonePolicyUri falls through with nullptr signingPolicy.

  if (!signingPolicy || !signingPolicy->is_authenticated())
  {
    return PreparedTokenResult{ua::Status::BadSecurityPolicyRejected};
  }

  return PreparedTokenResult{PreparedToken{.wireToken = nullptr,
    .encryptionPolicy = nullptr,
    .signingPolicy = std::move(signingPolicy),
    .userKeyPair = x509.keyPair}};
}

}  // namespace

PreparedTokenResult build_user_token(const UserIdentity& identity, const std::string& policyId,
  const std::vector<ua::UserTokenPolicy>& endpointPolicies,
  const std::shared_ptr<ua::SecurityPolicy>& channelPolicy, ua::MessageSecurityMode channelSecurityMode)
{
  // --- Step 1: Resolve the policy ---

  const ua::UserTokenPolicy* matchedPolicy = nullptr;

  if (policyId.empty())
  {
    if (std::holds_alternative<AnonymousIdentity>(identity))
    {
      // Auto-find the anonymous policy.
      auto it = std::ranges::find_if(endpointPolicies,
        [](const ua::UserTokenPolicy& p) { return p.token_type() == ua::UserTokenType::Anonymous; });
      if (it != endpointPolicies.end())
      {
        matchedPolicy = &*it;
      }
      else
      {
        // CL-IDENT-002: an AnonymousIdentity requires the endpoint to advertise a UserTokenPolicy of
        // tokenType ANONYMOUS whose policyId the token carries (the client must NOT invent one; Part 4
        // section 7.42 / section 7.41.2.1). When the endpoint advertises no ANONYMOUS policy, anonymous
        // authentication is not supported here - fail fast at connect time with a source-tagged
        // Bad_IdentityTokenRejected rather than send a doomed token with an empty policyId (the ratified
        // open-design-question policy, the design specification section 9).
        return PreparedTokenResult{ua::StatusCode{ua::Status::BadIdentityTokenRejected},
          ua::make_error_detail("NoAnonymousUserTokenPolicy",
            "the endpoint advertises no ANONYMOUS UserTokenPolicy; anonymous authentication is not supported "
            "by this endpoint",
            "client.tier0.token_builder.no_anonymous_policy")};
      }
    }
    else
    {
      // Non-anonymous identity requires an explicit policyId (an empty policyId only auto-selects the
      // anonymous policy). Source-tag the refusal so the caller sees why activation was refused before
      // any wire traffic  -  never a bare status the user cannot diagnose (the design specification).
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadIdentityTokenInvalid},
        ua::make_error_detail("NonAnonymousIdentityRequiresPolicyId",
          "a non-anonymous user identity requires an explicit UserTokenPolicy id; none was supplied",
          "client.tier0.token_builder.missing_policy_id")};
    }
  }
  else
  {
    // Explicit policyId: look it up.
    auto it = std::ranges::find_if(endpointPolicies,
      [&policyId](const ua::UserTokenPolicy& p) { return std::string_view{p.policy_id()} == policyId; });
    if (it == endpointPolicies.end())
    {
      // The requested policyId is not among the endpoint's advertised UserTokenPolicies (e.g. the
      // endpoint advertises no matching USERNAME policy). Source-tag it so the caller can tell the
      // configured policy from an unrecognised one (CL-IDENT-008).
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadIdentityTokenRejected},
        ua::make_error_detail("UserTokenPolicyNotAdvertised",
          "the configured UserTokenPolicy id is not advertised by the endpoint",
          "client.tier0.token_builder.policy_id_not_found")};
    }
    matchedPolicy = &*it;
  }

  // --- Step 2: Validate type match ---

  if (matchedPolicy)
  {
    auto expectedType = expected_token_type(identity);
    if (matchedPolicy->token_type() != expectedType)
    {
      // The endpoint advertises this policyId for a different token kind than the supplied identity  -
      // e.g. a UsernamePasswordIdentity pointed at an Anonymous/Certificate policy because the endpoint
      // advertises no USERNAME policy at all. Source-tag the token-type mismatch (CL-IDENT-008).
      return PreparedTokenResult{ua::StatusCode{ua::Status::BadIdentityTokenRejected},
        ua::make_error_detail("UserTokenTypeMismatch",
          "the configured UserTokenPolicy is for a different token kind than the supplied identity; the "
          "endpoint advertises no matching user-token policy (e.g. no USERNAME policy)",
          "client.tier0.token_builder.user_token_type_mismatch")};
    }
  }

  // --- Step 3: Construct wire token ---

  PreparedToken result;
  result.encryptionPolicy = nullptr;
  result.signingPolicy = nullptr;
  result.userKeyPair = nullptr;

  const std::string resolvedPolicyId =
    matchedPolicy ? std::string{matchedPolicy->policy_id()} : std::string{};

  if (std::holds_alternative<AnonymousIdentity>(identity))
  {
    auto token = std::make_unique<ua::AnonymousIdentityToken>();
    token->policy_id() = resolvedPolicyId;
    result.wireToken = std::move(token);
  }
  else if (const auto* username = std::get_if<UsernamePasswordIdentity>(&identity))
  {
    auto token = std::make_unique<ua::UserNameIdentityToken>();
    token->policy_id() = resolvedPolicyId;
    token->user_name() = username->username;
    // Convert std::string password to ByteString.
    token->password() = ua::ByteString{
      span<const byte>{utils::chars_to_bytes(username->password.data()), username->password.size()}};
    result.wireToken = std::move(token);

    // Resolve encryption policy for non-empty passwords.
    if (!username->password.empty() && matchedPolicy)
    {
      auto encResult = resolve_username_encryption(*matchedPolicy, channelPolicy, channelSecurityMode);
      if (!encResult)
      {
        return encResult;
      }
      result.encryptionPolicy = std::move(encResult.value().encryptionPolicy);

      // CL-IDENT-009 gate: when the resolution yielded NO per-token encryption (token policy None over a
      // SignAndEncrypt channel), the password travels as plaintext UTF-8 inside the token. Per Part 4
      // section 7.41.4 this "should not be used" configuration is a hard opt-in  -  refuse unless the caller
      // set allowUnencryptedPassword. (The cleartext-everywhere None/Sign-channel case is already refused
      // inside resolve_username_encryption, BEFORE this point, so the opt-in can never enable a
      // fully-in-clear password.)
      if (result.encryptionPolicy == nullptr && !username->allowUnencryptedPassword)
      {
        return PreparedTokenResult{ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
          ua::make_error_detail("UnpUnencryptedNotAllowed",
            "the UserName password would be presented as plaintext (token policy None over an encrypted "
            "channel); set allowUnencryptedPassword to opt in",
            "client.tier0.token_builder.unp.unencrypted_not_allowed")};
      }
    }
  }
  else if (const auto* x509 = std::get_if<X509Identity>(&identity))
  {
    auto token = std::make_unique<ua::X509IdentityToken>();
    token->policy_id() = resolvedPolicyId;
    if (x509->certificate)
    {
      // Decision 24: the leaf then X509Identity::issuerCertificates in order (OPC 10000-6 6.2.6).
      token->certificate_data() =
        ua::detail::encode_certificate_field(x509->certificate, x509->issuerCertificates);
    }
    result.wireToken = std::move(token);

    // Resolve signing policy for X509 tokens.
    if (matchedPolicy)
    {
      auto signResult = resolve_x509_signing(*matchedPolicy, channelPolicy, *x509);
      if (!signResult)
      {
        return signResult;
      }
      result.signingPolicy = std::move(signResult.value().signingPolicy);
      result.userKeyPair = std::move(signResult.value().userKeyPair);
    }
  }
  else if (const auto* issued = std::get_if<IssuedTokenIdentity>(&identity))
  {
    auto token = std::make_unique<ua::IssuedIdentityToken>();
    token->policy_id() = resolvedPolicyId;
    token->token_data() = issued->tokenData;
    result.wireToken = std::move(token);

    // IssuedToken follows the same encryption rules as UserName (Part 4, Table 193).
    if (!issued->tokenData.empty() && matchedPolicy)
    {
      auto encResult = resolve_username_encryption(*matchedPolicy, channelPolicy, channelSecurityMode);
      if (!encResult)
      {
        return encResult;
      }
      result.encryptionPolicy = std::move(encResult.value().encryptionPolicy);
    }
  }
  return PreparedTokenResult{std::move(result)};
}

}  // namespace ua::client
