// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The deprecated OPC UA `Basic256` RSA security policy.
/// @ingroup security

#ifndef UA_SEC_POL_BASIC256_H
#define UA_SEC_POL_BASIC256_H

#include "ua_sec_pol_asymmetric_encryption.h"

namespace ua
{
/// The OPC UA `Basic256` security policy (RSA family).
///
/// Implements @ref SecurityPolicy for the `Basic256` suite: RSA-OAEP (SHA-1)
/// asymmetric encryption, RSA-PKCS#1 v1.5 SHA-1 asymmetric signatures, AES-256-CBC
/// symmetric encryption, and HMAC-SHA-1 symmetric signatures. The accessors below
/// report the fixed cryptographic parameters of this suite and key derivation uses
/// the P-SHA1 scheme.
///
/// This policy is deprecated by the OPC UA specification (SHA-1 is no longer
/// considered secure); prefer @ref SecPolBasic256Sha256 or an AES-GCM policy for
/// new deployments. It remains for interoperability with legacy peers.
///
/// Instances are stateless and created via @ref SecurityPolicy::create.
/// @ingroup security
/// @see SecurityPolicy, SecPolBasic256Sha256
class SecPolBasic256 : public SecPolAsymmetricEncryption
{
public:
  /// Returns the policy identifier, @ref SecurityPolicyId::Basic256.
  /// @return @ref SecurityPolicyId::Basic256.
  SecurityPolicyId id() const override;

  /// Returns the policy URI string that identifies `Basic256` on the wire.
  /// @return The `Basic256` security policy URI.
  String uri() const override;

  /// Returns the certificate type this policy requires (RSA).
  /// @return The required certificate type (RSA).
  CertificateType certificate_type() const override;

  /// Reports whether the policy provides authentication (signing).
  ///
  /// @return `true`; `Basic256` signs message chunks.
  bool is_authenticated() const override;

  /// Reports whether the policy uses the legacy sequence-number scheme.
  ///
  /// @return `true`; `Basic256` predates the modern sequence-number rules.
  bool uses_legacy_sequence_no() const override;

  /// Reports whether the policy is deprecated by the OPC UA specification.
  ///
  /// @return `true`; `Basic256` relies on SHA-1 and should be avoided for new use.
  bool is_deprecated() const override;

  /// Returns the required nonce length in bytes for key derivation.
  /// @return The nonce length in bytes.
  size_t nonce_length() const override;

  /// Returns the symmetric cipher plaintext block size in bytes (AES-256-CBC).
  /// @return The symmetric plaintext block size in bytes.
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric plaintext block size in bytes for the given certificate.
  ///
  /// @param[in] certificate Peer certificate whose RSA key size determines the
  ///                        block size; must not be null.
  /// @return Maximum plaintext bytes that fit in one RSA-OAEP encryption block.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric cipher ciphertext block size in bytes (AES-256-CBC).
  /// @return The symmetric ciphertext block size in bytes.
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric ciphertext block size in bytes for the given certificate.
  ///
  /// @param[in] certificate Peer certificate whose RSA key size determines the
  ///                        block size; must not be null.
  /// @return Size in bytes of one RSA ciphertext block (the RSA modulus size).
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature size in bytes (HMAC-SHA-1).
  /// @return The symmetric signature size in bytes.
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric signature size in bytes for the given certificate.
  ///
  /// @param[in] certificate Signing certificate whose RSA key size determines the
  ///                        signature size; must not be null.
  /// @return Size in bytes of one RSA signature (the RSA modulus size).
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signing key length in bytes (HMAC-SHA-1).
  /// @return The symmetric signing key length in bytes.
  size_t symmetric_signature_key_size() const override;

  /// Returns the symmetric encryption key length in bytes (AES-256).
  /// @return The symmetric encryption key length in bytes.
  size_t symmetric_encryption_key_size() const override;

  /// Returns the symmetric initialization vector size in bytes (AES block size).
  /// @return The symmetric initialization vector size in bytes.
  size_t symmetric_iv_size() const override;

  /// Returns the minimum permitted RSA key length in bits for this policy.
  /// @return The minimum permitted RSA key length in bits.
  size_t min_asymmetric_key_length() const override;

  /// Returns the CertificateSignatureAlgorithms the profile database permits for this policy:
  /// RSA-PKCS15-SHA1, or SHA-2 224/256/384/512 instead ("The SHA2 algorithm with 224, 256, 384 or 512 bits
  /// may be used instead of SHA1").
  ///
  /// @return A view over static storage.
  std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const override;

  /// Returns the maximum permitted RSA key length in bits for this policy.
  /// @return The maximum permitted RSA key length in bits.
  size_t max_asymmetric_key_length() const override;

  /// Returns the asymmetric encryption algorithm (RSA-OAEP with SHA-1).
  /// @return The asymmetric encryption algorithm (RSA-OAEP with SHA-1).
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns the asymmetric signature algorithm (RSA-PKCS#1 v1.5 with SHA-1).
  /// @return The asymmetric signature algorithm (RSA-PKCS#1 v1.5 with SHA-1).
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the URI identifying the asymmetric signature algorithm on the wire.
  /// @return The URI identifying the asymmetric signature algorithm.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns the symmetric encryption algorithm (AES-256-CBC).
  /// @return The symmetric encryption algorithm (AES-256-CBC).
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns the symmetric signature algorithm (HMAC-SHA-1).
  /// @return The symmetric signature algorithm (HMAC-SHA-1).
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric session keys for a secure channel from the exchanged nonces.
  ///
  /// Runs the `Basic256` P-SHA1 key-derivation scheme and produces both the local
  /// and remote @ref SecurityToken::Keys sets used to sign and encrypt symmetric
  /// message chunks. Completes asynchronously; the callback may run on an
  /// unspecified worker thread, so do not block it.
  ///
  /// @param[in] context     Secure channel context the derived keys belong to; must
  ///                         outlive the operation.
  /// @param[in] localNonce  Nonce generated by this endpoint.
  /// @param[in] remoteNonce Nonce received from the peer.
  /// @param[in] role        Whether this endpoint is the server or the client,
  ///                         which fixes the nonce ordering per the spec.
  /// @param[in] callback    Receives the outcome: on success the Result holds the
  ///                         `{local, remote}` key pair; on failure it carries an
  ///                         @ref ErrorDetail. This overload never throws.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_BASIC256_H
