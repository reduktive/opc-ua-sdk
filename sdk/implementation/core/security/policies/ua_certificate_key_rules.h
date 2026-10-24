// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The certificate-family rules a security policy applies to each certificate of a chain.
/// @ingroup security

#ifndef UA_CERTIFICATE_KEY_RULES_H
#define UA_CERTIFICATE_KEY_RULES_H

#include <optional>
#include <span>
#include <string>
#include <variant>

#include "ua_crypto_types.h"
#include "ua_security_policy.h"

namespace ua
{
class X509Certificate;

/// The RSA rules of the OPC 10000-7 profile database: an RSA key whose length lies within the bounds at
/// every chain position, signed with one of the permitted CertificateSignatureAlgorithms.
/// @ingroup security
struct RsaCertificateRules
{
  size_t minKeyLength{0};  ///< Smallest permitted RSA key, in bits.
  size_t maxKeyLength{0};  ///< Largest permitted RSA key, in bits.
  /// The permitted CertificateSignatureAlgorithms; a view over static storage.
  std::span<const CertificateSignatureAlgorithm> signatureAlgorithms;
};

/// The ECC rules of the OPC 10000-7 profile database: "An end entity Certificate shall use <curve>. A CA
/// that issues end entity Certificates shall use <curve>. Other CAs may use <larger curve>." An ECDSA
/// curve requires an ECDSA signer and the hash its signer's curve size selects; an EdDSA curve requires a
/// signer on the same curve and PureEdDSA.
/// @ingroup security
struct EccCertificateRules
{
  CertificateKeyAlgorithm curve{CertificateKeyAlgorithm::Invalid};  ///< End entity and issuing CA.
  CertificateKeyAlgorithm higherCaCurve{CertificateKeyAlgorithm::Invalid};  ///< Also permitted above.
};

/// The certificate family of a security policy. It is independent of how the policy negotiates its keys:
/// RSA_DH uses the RSA rules with an ephemeral-key handshake (OPC 10000-6 section 6.9).
/// @ingroup security
using CertificateKeyRules = std::variant<RsaCertificateRules, EccCertificateRules>;

/// Why a certificate breaks its policy's rules: the rule's name and a sentence for the ErrorDetail.
/// @ingroup security
struct CertificateRuleViolation
{
  std::string rule;  ///< Short rule code, such as `CertificateKeyNotPermitted`.
  std::string summary;  ///< What the certificate breaks.
};

/// Checks one chain certificate against @p rules.
///
/// @param rules       The policy's certificate family.
/// @param certificate The certificate to check.
/// @param signer      The certificate that signed it (itself when self-signed).
/// @param position    Where @p certificate stands in the chain.
/// @return Nothing when the certificate complies, else the violated rule.
std::optional<CertificateRuleViolation> check_certificate_key_rules(const CertificateKeyRules& rules,
  const X509Certificate& certificate, const X509Certificate& signer, CertificateChainPosition position);

/// The key algorithm an end-entity certificate of this family has: `Rsa`, or the ECC rules' curve.
///
/// @param rules The policy's certificate family.
/// @return The end-entity certificate key algorithm.
CertificateKeyAlgorithm end_entity_key_algorithm(const CertificateKeyRules& rules) noexcept;

}  // namespace ua

#endif  // UA_CERTIFICATE_KEY_RULES_H
