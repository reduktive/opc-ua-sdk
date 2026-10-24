// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Create-time validation of the client's own ApplicationInstance certificate.
/// @ingroup client

#ifndef UA_CLIENT_OWN_CERT_VALIDATION_H
#define UA_CLIENT_OWN_CERT_VALIDATION_H

#include "ua_result.h"

#include <string_view>

namespace ua
{
class SecurityPolicy;
class X509Certificate;
}  // namespace ua

namespace ua::client::detail
{

/// Validates a loaded own ApplicationInstance certificate against the client configuration
/// (client design section 10.2 / OPC UA Part 6 section 6.2.2), at `CoreClient::create` time.
///
/// The checks run only for a certificate that is actually present in the store: a client that
/// holds no own certificate (legitimate for a `None`-only connection) is exempt, so create-time
/// validation never fires for it. When an own certificate is present its presence implies it is
/// intended for an authenticated (non-`None`) channel, so it must be a well-formed
/// ApplicationInstance certificate.
///
/// The preconditions, in OPC 10000-4 Table 106 order:
///   1. Security Policy Check (step 4): the client configures no SecurityPolicy before it connects (the
///      policy is chosen per connection), so at create the certificate must comply with at least one
///      SecurityPolicy the client may use - every supported authenticated policy, the deprecated ones
///      only when @p allowDeprecatedPolicies - through @ref check_own_certificate_for_endpoint (the
///      policy's check_certificate_compliance). The policy actually chosen is checked again when the
///      channel opens. A refusal names the first policy whose rule (not merely its key family) refused;
///      a key shorter than that policy's minimum is reported as Bad_CertificateInvalid coded
///      OwnCertificateKeyTooShort, naming the policy and the actual and minimum bits; any other refusal
///      keeps the policy's status, coded OwnCertificateViolatesSecurityPolicy;
///   2. URI (step 8): a SubjectAltName URI entry is present (mandatory per Part 6 section 6.2.2) and the
///      configured applicationUri appears among them (Bad_CertificateUriInvalid);
///   3. Certificate Usage (step 9): the certificate's uses match an ApplicationInstance Certificate
///      (OPC 10000-6 Table 43: keyUsage, extendedKeyUsage, basicConstraints), by the validator's rules
///      (ua::detail::check_certificate_usage) - Bad_CertificateUseNotAllowed coded
///      OwnCertificateKeyUsageInvalid (a keyUsage bit), OwnCertificateSelfSignedMissingKeyCertSign (a
///      self-signed cA TRUE certificate without keyCertSign) or OwnCertificateUseNotAllowed (any other
///      usage rule).
///
/// Every refusal is source-tagged and carries the rule's own detail as its cause. Cost: one policy
/// object and one compliance check per supported policy, once per own certificate at create.
///
/// @param applicationUri          The client's configured applicationUri (from the ApplicationDescription).
/// @param ownCert                 The loaded own ApplicationInstance certificate.
/// @param signer                  The certificate that signed @p ownCert (its first issuer); null when it
///                                is self-signed.
/// @param allowDeprecatedPolicies The configured ApplicationConfig::allowDeprecatedSecurityPolicies.
/// @return Good when the certificate satisfies every precondition; otherwise the first refusal. Never
///         throws.
[[nodiscard]] ua::VoidResult validate_own_application_certificate(std::string_view applicationUri,
  const ua::X509Certificate& ownCert, const ua::X509Certificate* signer = nullptr,
  bool allowDeprecatedPolicies = false) noexcept;

/// Checks the client's own certificate against the SecurityPolicy of the endpoint it is about to use
/// (OPC 10000-7 profile database; OPC 10000-4 6.1.3 Security Policy Check), through
/// SecurityPolicy::check_certificate_compliance at the end-entity position.
///
/// @param ownCertificate The own application certificate.
/// @param signer         The certificate that signed it (itself when self-signed).
/// @param policy         The endpoint's SecurityPolicy.
/// @return Good when it complies; otherwise Bad_CertificatePolicyCheckFailed naming the rule. Never throws.
[[nodiscard]] ua::VoidResult check_own_certificate_for_endpoint(const ua::X509Certificate& ownCertificate,
  const ua::X509Certificate& signer, const ua::SecurityPolicy& policy) noexcept;

}  // namespace ua::client::detail

#endif  // UA_CLIENT_OWN_CERT_VALIDATION_H
