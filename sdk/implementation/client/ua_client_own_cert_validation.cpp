// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Create-time own-certificate validation. See ua_client_own_cert_validation.h.

#include "ua_client_own_cert_validation.h"
#include "ua_client_own_cert_validation_test_access.h"

#include "ua_certificate_validation_paths.h"
#include "ua_crypto_types.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_security_policy.h"
#include "ua_status.h"
#include "ua_x509_certificate.h"

#include <atomic>
#include <algorithm>
#include <optional>
#include <string>

namespace ua::client::detail
{

namespace
{
/// Test-only (OwnCertificateCheckTestAccess, an implementation header that is not installed): lets an
/// integration test build a client presenting a certificate the client's own policy check refuses, so the
/// SERVER's handling of such a peer can be exercised. Never set by product code.
std::atomic<bool> gSkipOwnCertificatePolicyChecksForTests{false};
}  // namespace

void set_skip_own_certificate_policy_checks_for_tests(bool skip) noexcept
{
  gSkipOwnCertificatePolicyChecksForTests.store(skip, std::memory_order_relaxed);
}

namespace
{

/// The short name of a policy (the URI fragment, e.g. Basic256Sha256), for messages.
std::string policy_name(const ua::SecurityPolicy& policy)
{
  std::string uri{policy.uri()};
  const auto hash = uri.rfind('#');
  return hash == std::string::npos ? uri : uri.substr(hash + 1);
}

/// A policy refusal for the certificate's key family or curve says only that the certificate is not for
/// that policy; any other rule says something about the certificate itself.
bool is_key_family_refusal(const ua::VoidResult& refusal)
{
  const auto detail = refusal.shared_detail();
  return detail &&
         (detail->code == "CertificateKeyFamilyNotPermitted" || detail->code == "CertificateKeyNotPermitted");
}

/// Table 106 step 4 at create: Good when at least one usable SecurityPolicy accepts the certificate
/// (check_own_certificate_for_endpoint); otherwise the source-tagged refusal of the first policy whose
/// rule is about the certificate rather than its key family (or of the first policy, if every refusal is
/// a key-family one).
ua::VoidResult check_against_usable_policies(
  const ua::X509Certificate& ownCert, const ua::X509Certificate& signer, bool allowDeprecatedPolicies)
{
  std::shared_ptr<const ua::SecurityPolicy> refusingPolicy;
  ua::VoidResult refusal;
  bool refusalIsKeyFamily = true;
  for (const auto id : ua::SecurityPolicy::supported_policy_ids())
  {
    std::shared_ptr<const ua::SecurityPolicy> policy;
    try
    {
      policy = ua::SecurityPolicy::create(id);
    }
    catch (...)
    {
      continue;  // documented to throw for an unknown id; such a policy cannot be used either
    }
    if (!policy || !policy->is_authenticated() || (policy->is_deprecated() && !allowDeprecatedPolicies))
    {
      continue;
    }
    auto compliance = check_own_certificate_for_endpoint(ownCert, signer, *policy);
    if (compliance.is_good())
    {
      return ua::VoidResult{};
    }
    const bool keyFamily = is_key_family_refusal(compliance);
    if (!refusingPolicy || (refusalIsKeyFamily && !keyFamily))
    {
      refusingPolicy = policy;
      refusal = std::move(compliance);
      refusalIsKeyFamily = keyFamily;
    }
  }
  if (!refusingPolicy)
  {
    return ua::VoidResult{};  // no usable authenticated policy to check against
  }

  const auto cause = refusal.status_code();
  const size_t actualBits = ownCert.public_key_bit_length();
  const size_t minBits = refusingPolicy->min_asymmetric_key_length();
  const auto detail = refusal.shared_detail();
  if (detail && detail->code == "CertificateKeyLengthOutOfRange" && actualBits < minBits)
  {
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateInvalid,
      ua::ErrorDetail::build("OwnCertificateKeyTooShort",
        "The RSA public key is shorter than the minimum required by the security policy",
        "client.create.own_cert.key_too_short")
        .context(ua::ContextKeys::fieldName, "RSA public key bit length")
        .context(ua::ContextKeys::actual, actualBits)
        .context(ua::ContextKeys::min, minBits)
        .context(ua::ContextKeys::securityPolicy, policy_name(*refusingPolicy))
        .cause(cause)}};
  }
  return ua::VoidResult{ua::StatusCode{cause.value(),
    ua::ErrorDetail::build("OwnCertificateViolatesSecurityPolicy",
      "The application instance certificate complies with no SecurityPolicy the client may use",
      "client.create.own_cert.policy_check")
      .context(ua::ContextKeys::securityPolicy, policy_name(*refusingPolicy))
      .cause(cause)}};
}

}  // namespace

// section 10.2 / Part 6 section 6.2.2 ApplicationInstance certificate preconditions. Validating the client's
// OWN certificate at create time turns an otherwise-cryptic server-side OPN rejection (Bad_Certificate*) into
// a clear, source-tagged create-time error naming the offending field. Every rule is the validator's or the
// SecurityPolicy's own, applied in OPC 10000-4 Table 106 order (policy, URI, usage); none is restated here.
ua::VoidResult validate_own_application_certificate(std::string_view applicationUri,
  const ua::X509Certificate& ownCert, const ua::X509Certificate* signer,
  bool allowDeprecatedPolicies) noexcept
{
  // Security Policy Check (Table 106 step 4), first: see check_against_usable_policies.
  try
  {
    if (auto policyCheck =
          check_against_usable_policies(ownCert, signer ? *signer : ownCert, allowDeprecatedPolicies);
        !policyCheck.is_good())
    {
      return policyCheck;
    }
  }
  catch (...)
  {
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificatePolicyCheckFailed},
      ua::make_error_detail("OwnCertificatePolicyCheckFailed",
        "the SecurityPolicy could not check the own application certificate",
        "client.create.own_cert.policy_check")};
  }

  const std::vector<std::string> sanUris = ownCert.san_uris();

  // 1. A subjectAltName URI is mandatory for an ApplicationInstance certificate (Part 6 section 6.2.2). An
  // empty
  //    SAN-URI set can never match the applicationUri, so it is rejected explicitly rather than as a
  //    vacuous mismatch.
  if (sanUris.empty())
  {
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateUriInvalid},
      ua::make_error_detail("OwnCertificateSanUriMissing",
        "the application instance certificate has no subjectAltName URI (Part 6 section 6.2.2)",
        "client.create.own_cert.san_uri_missing")};
  }

  // 2. Every ApplicationInstance certificate identifies THIS configured application (Part 6 section 6.2.2),
  // so
  //    one of its SAN URIs must equal applicationUri exactly. Key type / SecurityPolicy can select among
  //    multiple own certificates, but cannot give those certificates different application identities.
  if (std::ranges::find(sanUris, applicationUri) == sanUris.end())
  {
    auto detail = ua::ErrorDetail::build("OwnCertificateApplicationUriMismatch",
      "the configured applicationUri is absent from the application instance certificate SAN URIs",
      "client.create.own_cert.application_uri_mismatch");
    detail.context(ua::ContextKeys::applicationUri, std::string{applicationUri});
    for (const auto& sanUri : sanUris)
    {
      detail.context(ua::ContextKeys::uri, sanUri);
    }
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateUriInvalid}, detail};
  }

  // 3. Certificate Usage (OPC 10000-6 Table 43): keyUsage, extendedKeyUsage and basicConstraints, by the
  //    validator's own rules (ua::detail::check_certificate_usage, the one implementation of them). The
  //    refusal is source-tagged as a create-time check of the own certificate, with the rule's detail as
  //    its cause.
  ua::VoidResult usage =
    ua::detail::check_certificate_usage(ownCert, ua::CertificateUse::ClientApplicationInstance);
  if (!usage.is_good())
  {
    const auto cause = usage.status_code();
    // The rule names the keyUsage bit it found missing, if it was a keyUsage rule.
    std::string_view bitName;
    if (const auto rule = usage.shared_detail())
    {
      const auto bit = std::ranges::find_if(rule->context,
        [](const ua::NamedValue& fact) { return fact.key == ua::ContextKeys::bitName.value(); });
      if (bit != rule->context.end())
      {
        bitName = bit->value;
      }
    }
    if (bitName == "keyCertSign")
    {
      return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateUseNotAllowed},
        ua::make_error_detail("OwnCertificateSelfSignedMissingKeyCertSign",
          "the self-signed application instance certificate lacks the keyCertSign keyUsage bit",
          "client.create.own_cert.self_signed_no_key_cert_sign",
          cause)};
    }
    if (!bitName.empty())
    {
      return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateUseNotAllowed},
        ua::make_error_detail("OwnCertificateKeyUsageInvalid",
          "The application instance certificate is missing a required keyUsage bit",
          "client.create.own_cert.key_usage_missing",
          cause)};
    }
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificateUseNotAllowed},
      ua::make_error_detail("OwnCertificateUseNotAllowed",
        "The application instance certificate's uses do not match an ApplicationInstance Certificate",
        "client.create.own_cert.use_not_allowed",
        cause)};
  }

  return ua::VoidResult{};
}

ua::VoidResult check_own_certificate_for_endpoint(const ua::X509Certificate& ownCertificate,
  const ua::X509Certificate& signer, const ua::SecurityPolicy& policy) noexcept
{
  if (gSkipOwnCertificatePolicyChecksForTests.load(std::memory_order_relaxed))
    return ua::VoidResult{};
  // The validator's Security Policy Check (OPC 10000-7 profile database) applied to the certificate this
  // application presents: the same per-policy rules, end-entity position.
  try
  {
    return policy.check_certificate_compliance(
      ownCertificate, signer, ua::CertificateChainPosition::EndEntity);
  }
  catch (...)
  {
    return ua::VoidResult{ua::StatusCode{ua::Status::BadCertificatePolicyCheckFailed},
      ua::make_error_detail("OwnCertificatePolicyCheckFailed",
        "the SecurityPolicy could not check the own application certificate",
        "client.connect.own_cert.policy_check")};
  }
}

}  // namespace ua::client::detail
