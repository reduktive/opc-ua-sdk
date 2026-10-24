// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The Aes128_Sha256_RsaOaep OPC UA security policy.
/// @ingroup security

#ifndef UA_SEC_POL_AES128_SHA256_RSA_OAEP_H
#define UA_SEC_POL_AES128_SHA256_RSA_OAEP_H

#include "ua_sec_pol_asymmetric_encryption.h"

namespace ua
{
/// The Aes128_Sha256_RsaOaep RSA security policy.
///
/// Concrete @ref SecurityPolicy for the OPC UA `Aes128_Sha256_RsaOaep` profile: RSA-OAEP (SHA-1)
/// asymmetric encryption, RSA-PKCS#1 v1.5 (SHA-256) asymmetric signatures, AES-128-CBC symmetric
/// encryption, and HMAC-SHA-256 symmetric signatures. Every method reports the fixed cryptographic
/// parameters of this profile; instances are stateless and may be shared across secure channels.
/// @ingroup security
class SecPolAes128Sha256RsaOaep : public SecPolAsymmetricEncryption
{
public:
  /// Returns the security-policy identifier for this profile.
  ///
  /// @return The security-policy identifier for this profile.
  SecurityPolicyId id() const override;

  /// Returns the canonical OPC UA security-policy URI for this profile.
  ///
  /// @return The canonical OPC UA security-policy URI for this profile.
  String uri() const override;

  /// Returns the certificate type accepted by this profile (an RSA certificate type).
  ///
  /// @return The RSA certificate type accepted by this profile.
  CertificateType certificate_type() const override;

  /// Indicates whether this policy authenticates the peer (signs and/or encrypts).
  ///
  /// @return `true` if this policy authenticates the peer (signs and/or encrypts).
  bool is_authenticated() const override;

  /// Indicates that this is an RSA-family policy. Always `true`.
  ///
  /// @return `true`; this is an RSA-family policy.
  bool is_rsa() const override;

  /// Indicates that this is an ECC-family policy. Always `false`.
  ///
  /// @return `false`; this is not an ECC-family policy.
  bool is_ecc() const override;

  /// Indicates whether this policy uses the legacy secure-channel sequence-number scheme.
  ///
  /// @return `true` if this policy uses the legacy secure-channel sequence-number scheme.
  bool uses_legacy_sequence_no() const override;

  /// Returns the required nonce length, in bytes.
  ///
  /// @return The required nonce length, in bytes.
  size_t nonce_length() const override;

  /// Returns the symmetric cipher plaintext block size, in bytes.
  ///
  /// @return The symmetric cipher plaintext block size, in bytes.
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric (RSA-OAEP) plaintext block size for the peer certificate, in bytes.
  ///
  /// @param certificate Peer certificate whose RSA key size sets the block size. Must not be null.
  /// @return The largest plaintext block, in bytes, that fits one RSA-OAEP encryption block.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric cipher ciphertext block size, in bytes.
  ///
  /// @return The symmetric cipher ciphertext block size, in bytes.
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric (RSA) ciphertext block size for the given peer certificate, in bytes.
  ///
  /// @param certificate Peer certificate whose RSA key size sets the block size. Must not be null.
  /// @return The RSA encryption block size, in bytes (equal to the modulus length).
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature (HMAC) size, in bytes.
  ///
  /// @return The symmetric signature (HMAC) size, in bytes.
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric (RSA) signature size for the given peer certificate, in bytes.
  ///
  /// @param certificate Peer certificate whose RSA key size sets the signature size. Not null.
  /// @return The RSA signature size, in bytes (equal to the modulus length).
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signing (HMAC) key size, in bytes.
  ///
  /// @return The symmetric signing (HMAC) key size, in bytes.
  size_t symmetric_signature_key_size() const override;

  /// Returns the symmetric encryption (AES) key size, in bytes.
  ///
  /// @return The symmetric encryption (AES) key size, in bytes.
  size_t symmetric_encryption_key_size() const override;

  /// Returns the symmetric encryption initialization-vector size, in bytes.
  ///
  /// @return The symmetric encryption initialization-vector size, in bytes.
  size_t symmetric_iv_size() const override;

  /// Returns the minimum permitted asymmetric (RSA) key length, in bits.
  ///
  /// @return The minimum permitted asymmetric (RSA) key length, in bits.
  size_t min_asymmetric_key_length() const override;

  /// Returns the CertificateSignatureAlgorithms the profile database permits for this policy:
  /// RSA-PKCS15-SHA2-256, or SHA-2 384/512 instead; never PSS, ECDSA, EdDSA, SHA-1 or SHA-224.
  ///
  /// @return A view over static storage.
  std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const override;

  /// Returns the maximum permitted asymmetric (RSA) key length, in bits.
  ///
  /// @return The maximum permitted asymmetric (RSA) key length, in bits.
  size_t max_asymmetric_key_length() const override;

  /// Returns the asymmetric encryption algorithm (RSA-OAEP with SHA-1).
  ///
  /// @return The asymmetric encryption algorithm (RSA-OAEP with SHA-1).
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns the asymmetric signature algorithm (RSA-PKCS#1 v1.5 with SHA-256).
  ///
  /// @return The asymmetric signature algorithm (RSA-PKCS#1 v1.5 with SHA-256).
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the canonical URI of the asymmetric signature algorithm.
  ///
  /// @return The canonical URI of the asymmetric signature algorithm.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns the symmetric encryption algorithm (AES-128-CBC).
  ///
  /// @return The symmetric encryption algorithm (AES-128-CBC).
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns the symmetric signature algorithm (HMAC-SHA-256).
  ///
  /// @return The symmetric signature algorithm (HMAC-SHA-256).
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric signing and encryption keys for a channel from the exchanged nonces.
  ///
  /// Runs the profile's PSha-style key derivation and completes asynchronously; the callback runs
  /// on an unspecified worker thread, so do not block it.
  ///
  /// @param context     Secure-channel context the keys are derived for. Must outlive the call.
  /// @param localNonce  Nonce generated by this endpoint for the current token.
  /// @param remoteNonce Nonce received from the peer for the current token.
  /// @param role        Whether this endpoint acts as the server or the client, which fixes nonce
  ///                    ordering during derivation.
  /// @param callback    Receives the outcome: on success the @ref Result holds the local and remote
  ///                    @ref SecurityToken::Keys (signing key, encryption key, IV) as a pair; on
  ///                    failure it carries an @ref ErrorDetail. This overload never throws.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_AES128_SHA256_RSA_OAEP_H
