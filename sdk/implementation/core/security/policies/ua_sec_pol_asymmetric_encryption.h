// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Shared base for the security policies that key the channel by asymmetric encryption.
/// @ingroup security

#ifndef UA_SEC_POL_ASYMMETRIC_ENCRYPTION_H
#define UA_SEC_POL_ASYMMETRIC_ENCRYPTION_H

#include <span>

#include "ua_security_policy.h"

namespace ua
{
/// Common base for the security policies whose OpenSecureChannel is RSA-encrypted and whose keys come
/// from the exchanged nonces (Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep,
/// Aes256_Sha256_RsaPss).
///
/// Fixes the key-type predicates and the RSA certificate rules shared by these policies. Concrete
/// policies still supply the algorithm-specific virtuals declared on @ref SecurityPolicy. The policies
/// that agree their keys by ephemeral key exchange, RSA_DH included, are @ref SecPolEphemeralKey.
/// @ingroup security
/// @see SecurityPolicy, SecPolEphemeralKey
class SecPolAsymmetricEncryption : public SecurityPolicy
{
public:
  /// Reports that this policy family uses RSA asymmetric keys.
  ///
  /// @return Always `true` for every RSA-family policy.
  /// @see is_ecc
  bool is_rsa() const override;

  /// Reports that this policy family does not use ECC asymmetric keys.
  ///
  /// @return Always `false` for every RSA-family policy.
  /// @see is_rsa
  bool is_ecc() const override;

  /// Checks one chain certificate against the RSA rules of the OPC 10000-7 profile database: an RSA
  /// key whose length lies within [@ref min_asymmetric_key_length, @ref max_asymmetric_key_length], at
  /// every chain position, carrying a CertificateSignatureAlgorithm in
  /// @ref certificate_signature_algorithms (an algorithm the SDK does not classify is refused).
  ///
  /// @param certificate The certificate to check.
  /// @param signer      The certificate that signed it (itself when self-signed); not consulted, the
  ///                    algorithm names the signer's key family.
  /// @param position    Where @p certificate stands in the chain (the RSA rules are the same at each).
  /// @return Good, or `Bad_CertificatePolicyCheckFailed` naming the rule, position and subject.
  VoidResult check_certificate_compliance(const X509Certificate& certificate, const X509Certificate& signer,
    CertificateChainPosition position) const final;

protected:
  /// Returns the CertificateSignatureAlgorithms this policy permits on a certificate and every issuer
  /// in its chain (OPC 10000-7 profile database; RSASSA-PKCS1-v1_5 only).
  ///
  /// @return A view over static storage owned by the concrete policy.
  /// @note Policy hook - implemented by each concrete RSA policy.
  virtual std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const = 0;
};

}  // namespace ua

#endif  // UA_SEC_POL_ASYMMETRIC_ENCRYPTION_H
