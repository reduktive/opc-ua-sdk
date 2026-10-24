// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The Basic128Rsa15 OPC UA security policy implementation.
/// @ingroup security
#ifndef UA_SEC_POL_BASIC128_RSA15_H
#define UA_SEC_POL_BASIC128_RSA15_H

#include "ua_sec_pol_asymmetric_encryption.h"

namespace ua
{
/// The deprecated Basic128Rsa15 OPC UA security policy.
///
/// Implements the RSA-family @ref SecurityPolicy for the Basic128Rsa15 profile:
/// RSA-PKCS1.5 asymmetric encryption, RSA-SHA1 asymmetric signatures, AES-128-CBC
/// symmetric encryption, and HMAC-SHA1 symmetric signatures. The policy is
/// retained for interoperability only; it is reported as deprecated and should
/// not be selected for new endpoints. Instances are immutable and stateless, so
/// the const accessors are safe to call from any thread.
///
/// @see SecurityPolicy
/// @ingroup security
class SecPolBasic128Rsa15 : public SecPolAsymmetricEncryption
{
public:
  /// Returns the policy identifier (Basic128Rsa15).
  ///
  /// @return The policy identifier (Basic128Rsa15).
  SecurityPolicyId id() const override;

  /// Returns the canonical OPC UA security policy URI for Basic128Rsa15.
  ///
  /// @return The canonical OPC UA security-policy URI for Basic128Rsa15.
  String uri() const override;

  /// Returns the certificate type required by this policy (RSA).
  ///
  /// @return The RSA certificate type required by this policy.
  CertificateType certificate_type() const override;

  /// Returns whether the policy provides message authentication.
  ///
  /// @return `true` if the policy provides message authentication.
  bool is_authenticated() const override;

  /// Returns whether the policy uses the legacy sequence-number handling.
  ///
  /// @return `true` if the policy uses the legacy sequence-number handling.
  bool uses_legacy_sequence_no() const override;

  /// Returns whether the policy is deprecated; always `true` for Basic128Rsa15.
  ///
  /// @return `true`; Basic128Rsa15 is deprecated.
  bool is_deprecated() const override;

  /// Returns the length in bytes of the nonce exchanged during channel setup.
  ///
  /// @return The nonce length exchanged during channel setup, in bytes.
  size_t nonce_length() const override;

  /// Returns the symmetric cipher plaintext block size, in bytes.
  ///
  /// @return The symmetric cipher plaintext block size, in bytes.
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric plaintext block size for the given certificate, in bytes.
  ///
  /// The block size depends on the certificate's RSA key length.
  ///
  /// @param[in] certificate Peer certificate whose key length sizes the block; not retained.
  /// @return The plaintext block size in bytes.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric cipher ciphertext block size, in bytes.
  ///
  /// @return The symmetric cipher ciphertext block size, in bytes.
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric ciphertext block size for the given certificate, in bytes.
  ///
  /// The block size depends on the certificate's RSA key length.
  ///
  /// @param[in] certificate Peer certificate whose key length sizes the block; not retained.
  /// @return The ciphertext block size in bytes.
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature size, in bytes.
  ///
  /// @return The symmetric signature size, in bytes.
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric signature size for the given certificate, in bytes.
  ///
  /// The signature size depends on the certificate's RSA key length.
  ///
  /// @param[in] certificate Peer certificate whose key length sizes the signature; not retained.
  /// @return The signature size in bytes.
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signing key size, in bytes.
  ///
  /// @return The symmetric signing key size, in bytes.
  size_t symmetric_signature_key_size() const override;

  /// Returns the symmetric encryption key size, in bytes.
  ///
  /// @return The symmetric encryption key size, in bytes.
  size_t symmetric_encryption_key_size() const override;

  /// Returns the symmetric initialization-vector size, in bytes.
  ///
  /// @return The symmetric initialization-vector size, in bytes.
  size_t symmetric_iv_size() const override;

  /// Returns the minimum accepted asymmetric (RSA) key length, in bits.
  ///
  /// @return The minimum accepted asymmetric (RSA) key length, in bits.
  size_t min_asymmetric_key_length() const override;

  /// Returns the CertificateSignatureAlgorithms the profile database permits for this policy:
  /// RSA-PKCS15-SHA1, or SHA-2 224/256/384/512 instead ("The SHA2 algorithm with 224, 256, 384 or 512 bits
  /// may be used instead of SHA1").
  ///
  /// @return A view over static storage.
  std::span<const CertificateSignatureAlgorithm> certificate_signature_algorithms() const override;

  /// Returns the maximum accepted asymmetric (RSA) key length, in bits.
  ///
  /// @return The maximum accepted asymmetric (RSA) key length, in bits.
  size_t max_asymmetric_key_length() const override;

  /// Returns the asymmetric encryption algorithm (RSA-PKCS1.5).
  ///
  /// @return The asymmetric encryption algorithm (RSA-PKCS1.5).
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns the asymmetric signature algorithm (RSA-SHA1).
  ///
  /// @return The asymmetric signature algorithm (RSA-SHA1).
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the URI identifying the asymmetric signature algorithm.
  ///
  /// @return The URI identifying the asymmetric signature algorithm.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns the symmetric encryption algorithm (AES-128-CBC).
  ///
  /// @return The symmetric encryption algorithm (AES-128-CBC).
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns the symmetric signature algorithm (HMAC-SHA1).
  ///
  /// @return The symmetric signature algorithm (HMAC-SHA1).
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric key sets for a secure channel from the exchanged nonces.
  ///
  /// Runs the policy's PSha-style key derivation and assembles the local and remote
  /// @ref SecurityToken::Keys. Completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it.
  ///
  /// @param[in] context     Secure channel context for which keys are derived; retained for the
  ///                         duration of the asynchronous flow.
  /// @param[in] localNonce  Nonce generated by this endpoint.
  /// @param[in] remoteNonce Nonce received from the peer.
  /// @param[in] role        Whether this endpoint is the server or the client, fixing nonce ordering.
  /// @param[in] callback    Receives the outcome: on success the Result holds the derived
  ///                         { local, remote } key pair; on failure it carries an @ref ErrorDetail.
  ///                         This overload never throws.
  /// @see SecurityPolicy::derive_symmetric_keys_async
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_BASIC128_RSA15_H
