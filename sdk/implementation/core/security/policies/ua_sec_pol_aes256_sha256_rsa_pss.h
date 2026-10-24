// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The Aes256_Sha256_RsaPss OPC UA security policy.
/// @ingroup security

#ifndef UA_SEC_POL_AES256_SHA256_RSA_PSS_H
#define UA_SEC_POL_AES256_SHA256_RSA_PSS_H

#include "ua_sec_pol_asymmetric_encryption.h"

namespace ua
{
/// The `Aes256_Sha256_RsaPss` RSA-family OPC UA security policy.
///
/// Implements the cryptographic parameters and key derivation defined by the
/// `http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss` profile:
/// AES-256-CBC symmetric encryption, HMAC-SHA-256 symmetric signatures, RSA-OAEP
/// (SHA-256) asymmetric encryption, and RSA-PSS (SHA-256) asymmetric signatures.
///
/// Instances are immutable and stateless; the same policy object may be shared
/// across secure channels and called concurrently from any thread.
/// @see SecurityPolicy, SecPolAsymmetricEncryption
/// @ingroup security
class SecPolAes256Sha256RsaPss : public SecPolAsymmetricEncryption
{
public:
  /// Returns the policy identifier (`SecurityPolicyId::Aes256_Sha256_RsaPss`).
  ///
  /// @return The policy identifier (`SecurityPolicyId::Aes256_Sha256_RsaPss`).
  SecurityPolicyId id() const override;

  /// Returns the OPC UA security policy URI for this policy.
  ///
  /// @return The OPC UA security-policy URI for this policy.
  String uri() const override;

  /// Returns the certificate type required by this policy (RSA).
  ///
  /// @return The RSA certificate type required by this policy.
  CertificateType certificate_type() const override;

  /// Indicates whether the policy provides message authentication.
  ///
  /// @return `true` - this policy signs and (where applicable) encrypts messages.
  bool is_authenticated() const override;

  /// Indicates whether the policy uses RSA asymmetric cryptography.
  ///
  /// @return `true`.
  bool is_rsa() const override;

  /// Indicates whether the policy uses elliptic-curve asymmetric cryptography.
  ///
  /// @return `false`.
  bool is_ecc() const override;

  /// Indicates whether the policy uses the legacy secure-channel sequence-number scheme.
  ///
  /// @return `true` if the policy uses the legacy secure-channel sequence-number scheme.
  bool uses_legacy_sequence_no() const override;

  /// Returns the required length, in bytes, of the secure-channel nonce.
  ///
  /// @return The required secure-channel nonce length, in bytes.
  size_t nonce_length() const override;

  /// Returns the symmetric cipher plaintext block size, in bytes.
  ///
  /// @return The symmetric cipher plaintext block size, in bytes.
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric cipher plaintext block size, in bytes, for the given certificate.
  ///
  /// @param[in] certificate Certificate whose public-key modulus determines the block size.
  ///                        Borrowed for the call; must remain valid until it returns.
  /// @return The asymmetric cipher plaintext block size, in bytes, for @p certificate.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric cipher ciphertext block size, in bytes.
  ///
  /// @return The symmetric cipher ciphertext block size, in bytes.
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric cipher ciphertext block size, in bytes, for the given certificate.
  ///
  /// @param[in] certificate Certificate whose public-key modulus determines the block size.
  ///                        Borrowed for the call; must remain valid until it returns.
  /// @return The asymmetric cipher ciphertext block size, in bytes, for @p certificate.
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature (MAC) size, in bytes.
  ///
  /// @return The symmetric signature (MAC) size, in bytes.
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric signature size, in bytes, for the given certificate.
  ///
  /// @param[in] certificate Certificate whose private-key length determines the signature size.
  ///                        Borrowed for the call; must remain valid until it returns.
  /// @return The asymmetric signature size, in bytes, for @p certificate.
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signing (MAC) key size, in bytes.
  ///
  /// @return The symmetric signing (MAC) key size, in bytes.
  size_t symmetric_signature_key_size() const override;

  /// Returns the symmetric encryption key size, in bytes.
  ///
  /// @return The symmetric encryption key size, in bytes.
  size_t symmetric_encryption_key_size() const override;

  /// Returns the symmetric initialization-vector size, in bytes.
  ///
  /// @return The symmetric initialization-vector size, in bytes.
  size_t symmetric_iv_size() const override;

  /// Returns the minimum accepted RSA key length, in bits.
  ///
  /// @return The minimum accepted RSA key length, in bits.
  size_t min_asymmetric_key_length() const override;

  /// Returns the CertificateSignatureAlgorithms the profile database permits for this policy:
  /// RSA-PKCS15-SHA2-256, or SHA-2 384/512 instead; never PSS, ECDSA, EdDSA, SHA-1 or SHA-224.
  ///
  /// @return A view over static storage.
  std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const override;

  /// Returns the maximum accepted RSA key length, in bits.
  ///
  /// @return The maximum accepted RSA key length, in bits.
  size_t max_asymmetric_key_length() const override;

  /// Returns the asymmetric encryption algorithm used by this policy (RSA-OAEP, SHA-256).
  ///
  /// @return The asymmetric encryption algorithm (RSA-OAEP, SHA-256).
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns the asymmetric signature algorithm used by this policy (RSA-PSS, SHA-256).
  ///
  /// @return The asymmetric signature algorithm (RSA-PSS, SHA-256).
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the OPC UA URI of the asymmetric signature algorithm.
  ///
  /// @return The OPC UA URI of the asymmetric signature algorithm.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns the symmetric encryption algorithm used by this policy (AES-256-CBC).
  ///
  /// @return The symmetric encryption algorithm (AES-256-CBC).
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns the symmetric signature algorithm used by this policy (HMAC-SHA-256).
  ///
  /// @return The symmetric signature algorithm (HMAC-SHA-256).
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric session keys for a secure channel from the exchanged nonces.
  ///
  /// Runs the policy's P-SHA-256 key-derivation function and completes
  /// asynchronously. The callback runs on an unspecified worker thread - do not
  /// block it.
  ///
  /// @param[in] context     Secure-channel context the derived keys belong to. Held for the
  ///                        duration of the derivation; must outlive the call.
  /// @param[in] localNonce  Nonce generated by this endpoint.
  /// @param[in] remoteNonce Nonce received from the peer.
  /// @param[in] role        Whether this endpoint acts as the channel server or client; selects
  ///                        the per-role nonce ordering.
  /// @param[in] callback    Receives the outcome: on success the Result holds the local and remote
  ///                        @ref SecurityToken::Keys; on failure it carries an @ref ErrorDetail.
  ///                        This overload never throws.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_AES256_SHA256_RSA_PSS_H
