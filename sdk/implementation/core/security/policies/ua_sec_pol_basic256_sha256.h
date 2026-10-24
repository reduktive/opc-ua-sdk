// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SEC_POL_BASIC256_SHA256_H
#define UA_SEC_POL_BASIC256_SHA256_H

/// @file
/// @brief The Basic256Sha256 RSA security policy.
/// @ingroup security

#include "ua_sec_pol_asymmetric_encryption.h"

namespace ua
{
/// The `Basic256Sha256` OPC UA security policy.
///
/// Implements the RSA-family security policy
/// `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`: RSA-OAEP (SHA-1)
/// asymmetric encryption, RSA-PKCS#1.5 (SHA-256) asymmetric signatures, AES-256-CBC
/// symmetric encryption, and HMAC-SHA-256 symmetric signatures, with P-SHA-256 key
/// derivation. Instances are immutable and stateless; the cryptographic parameters
/// reported by the accessors are fixed by the policy and do not depend on instance
/// state. Obtain one via @ref SecurityPolicy::create rather than constructing it
/// directly.
/// @ingroup security
/// @see SecPolAsymmetricEncryption, SecurityPolicy
class SecPolBasic256Sha256 : public SecPolAsymmetricEncryption
{
public:
  /// Returns the policy identifier, @ref SecurityPolicyId::Basic256Sha256.
  /// @return @ref SecurityPolicyId::Basic256Sha256.
  SecurityPolicyId id() const override;

  /// Returns the policy URI, `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`.
  /// @return The `Basic256Sha256` security policy URI.
  String uri() const override;

  /// Returns the certificate type required by this policy (RSA-SHA-256).
  /// @return The required certificate type (RSA-SHA-256).
  CertificateType certificate_type() const override;

  /// Returns whether the policy authenticates message exchanges; always `true` for Basic256Sha256.
  /// @return `true`; Basic256Sha256 signs message chunks.
  bool is_authenticated() const override;

  /// Returns whether the policy uses the legacy (pre-1.04) sequence-number handling.
  /// @return `true`; Basic256Sha256 uses the legacy sequence-number scheme.
  bool uses_legacy_sequence_no() const override;

  /// Returns the length in bytes of the nonces exchanged during secure-channel setup.
  /// @return The nonce length in bytes.
  size_t nonce_length() const override;

  /// Returns the symmetric plaintext block size in bytes (AES block size).
  /// @return The symmetric plaintext block size in bytes.
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric plaintext block size in bytes for the given certificate's key.
  ///
  /// The block size is the RSA modulus length minus the OAEP padding overhead.
  ///
  /// @param certificate Certificate whose public key determines the modulus length. Must be
  ///                    non-null; not retained beyond the call.
  /// @return The usable plaintext block size in bytes.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric ciphertext block size in bytes (AES block size).
  /// @return The symmetric ciphertext block size in bytes.
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric ciphertext block size in bytes for the given certificate's key.
  ///
  /// Equal to the RSA modulus length in bytes.
  ///
  /// @param certificate Certificate whose public key determines the modulus length. Must be
  ///                    non-null; not retained beyond the call.
  /// @return The ciphertext block size in bytes.
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature (HMAC-SHA-256) size in bytes.
  /// @return The symmetric signature (HMAC-SHA-256) size in bytes.
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric signature size in bytes for the given certificate's key.
  ///
  /// Equal to the RSA modulus length in bytes.
  ///
  /// @param certificate Certificate whose public key determines the signature length. Must be
  ///                    non-null; not retained beyond the call.
  /// @return The asymmetric signature size in bytes.
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the size in bytes of the derived symmetric signing key.
  /// @return The symmetric signing key size in bytes.
  size_t symmetric_signature_key_size() const override;

  /// Returns the size in bytes of the derived symmetric encryption key (32 bytes for AES-256).
  /// @return The symmetric encryption key size in bytes (32 for AES-256).
  size_t symmetric_encryption_key_size() const override;

  /// Returns the size in bytes of the symmetric initialisation vector (AES block size).
  /// @return The symmetric initialisation vector size in bytes.
  size_t symmetric_iv_size() const override;

  /// Returns the minimum permitted asymmetric (RSA) key length in bits.
  /// @return The minimum permitted RSA key length in bits.
  size_t min_asymmetric_key_length() const override;

  /// Returns the CertificateSignatureAlgorithms the profile database permits for this policy:
  /// RSA-PKCS15-SHA2-256, or SHA-2 384/512 instead; never PSS, ECDSA, EdDSA, SHA-1 or SHA-224.
  ///
  /// @return A view over static storage.
  std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const override;

  /// Returns the maximum permitted asymmetric (RSA) key length in bits.
  /// @return The maximum permitted RSA key length in bits.
  size_t max_asymmetric_key_length() const override;

  /// Returns the asymmetric encryption algorithm used by this policy (RSA-OAEP with SHA-1).
  /// @return The asymmetric encryption algorithm (RSA-OAEP with SHA-1).
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns the asymmetric signature algorithm used by this policy (RSA-PKCS#1.5 with SHA-256).
  /// @return The asymmetric signature algorithm (RSA-PKCS#1.5 with SHA-256).
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the URI identifying the asymmetric signature algorithm.
  /// @return The URI identifying the asymmetric signature algorithm.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns the symmetric encryption algorithm used by this policy (AES-256-CBC).
  /// @return The symmetric encryption algorithm (AES-256-CBC).
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns the symmetric signature algorithm used by this policy (HMAC-SHA-256).
  /// @return The symmetric signature algorithm (HMAC-SHA-256).
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric signing, encryption, and IV keys for both directions of the channel.
  ///
  /// Runs the policy's P-SHA-256 key derivation over the two nonces and completes
  /// asynchronously. The callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param context     Secure-channel context the derivation runs against; shared ownership is
  ///                    held for the duration of the operation.
  /// @param localNonce  Nonce generated by this endpoint.
  /// @param remoteNonce Nonce received from the peer.
  /// @param role        Whether this endpoint acts as @ref ChannelRole::Server or
  ///                    @ref ChannelRole::Client, which fixes the nonce ordering.
  /// @param callback    Receives the outcome: on success the Result holds the derived local and
  ///                    remote key sets; on failure it carries an @ref ErrorDetail. This overload
  ///                    never throws.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_BASIC256_SHA256_H
