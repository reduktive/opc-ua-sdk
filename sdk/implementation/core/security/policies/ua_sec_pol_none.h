// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The OPC UA "None" security policy (no signing, no encryption).
/// @ingroup security

#ifndef UA_SEC_POL_NONE_H
#define UA_SEC_POL_NONE_H

#include "ua_security_policy.h"

namespace ua
{
/// The OPC UA `SecurityPolicy#None` policy: messages are neither signed nor encrypted.
///
/// This policy applies no cryptography. Secure channels using it transmit plaintext, perform no
/// certificate-based authentication, and derive no symmetric keys. The signature, key, and nonce
/// accessors report zero and the algorithm accessors report the "no algorithm" variants; the block-size
/// accessors report 1 (a unit block keeps the chunk-size arithmetic well-defined with no cipher). Use it
/// only where confidentiality and integrity are provided by
/// another layer (or are not required).
///
/// Instances are obtained through @ref SecurityPolicy::create rather than constructed directly, and
/// are shared via `shared_ptr`. Like every @ref SecurityPolicy the object is immutable and stateless,
/// so its methods are safe to call concurrently from any thread.
/// @ingroup security
/// @see SecurityPolicy
class SecPolNone : public SecurityPolicy
{
public:
  /// Returns @ref SecurityPolicyId::None.
  /// @return The identifier @ref SecurityPolicyId::None.
  SecurityPolicyId id() const override;

  /// Returns the policy URI `http://opcfoundation.org/UA/SecurityPolicy#None`.
  /// @return The URI `http://opcfoundation.org/UA/SecurityPolicy#None`.
  String uri() const override;

  /// Returns the certificate type required by this policy.
  ///
  /// None does not authenticate with certificates; the returned value reflects that no specific
  /// certificate type is needed.
  ///
  /// @return The certificate type, reflecting that no specific certificate type is required.
  CertificateType certificate_type() const override;

  /// Returns `false`: the None policy performs no certificate-based authentication.
  /// @return `false`; the None policy performs no certificate-based authentication.
  bool is_authenticated() const override;

  /// Returns `false`: the None policy is not an RSA-family policy.
  /// @return `false`; the None policy is not an RSA-family policy.
  bool is_rsa() const override;

  /// Returns `false`: the None policy is not an ECC-family policy.
  /// @return `false`; the None policy is not an ECC-family policy.
  bool is_ecc() const override;

  /// Returns good: the None policy places no requirement on a certificate.
  ///
  /// @param certificate Not consulted.
  /// @param signer      Not consulted.
  /// @param position    Not consulted.
  /// @return A good @ref VoidResult.
  VoidResult check_certificate_compliance(const X509Certificate& certificate, const X509Certificate& signer,
    CertificateChainPosition position) const override;

  /// Returns `false`: the None policy uses the modern sequence-number scheme.
  /// @return `false`; the None policy uses the modern sequence-number scheme.
  bool uses_legacy_sequence_no() const override;

  /// Returns the length, in bytes, of the nonce exchanged during channel setup.
  ///
  /// None exchanges no key material, so the nonce length is zero.
  ///
  /// @return The nonce length in bytes (0).
  size_t nonce_length() const override;

  /// Returns the symmetric plaintext block size in bytes.
  ///
  /// With no cipher this is 1 (a unit block keeps the chunk-size arithmetic well-defined).
  ///
  /// @return The symmetric plaintext block size in bytes (1).
  size_t symmetric_plaintext_block_size() const override;

  /// Returns the asymmetric plaintext block size in bytes.
  ///
  /// With no cipher this is 1 (a unit block keeps the chunk-size arithmetic well-defined).
  ///
  /// @param certificate Certificate whose key size would normally determine the block size; ignored
  ///                    by this policy and may be null.
  /// @return The asymmetric plaintext block size in bytes (1).
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric ciphertext block size in bytes (1; no cipher, a unit block keeps chunk
  /// arithmetic well-defined).
  /// @return The symmetric ciphertext block size in bytes (1).
  size_t symmetric_ciphertext_block_size() const override;

  /// Returns the asymmetric ciphertext block size in bytes (1; no cipher, a unit block keeps chunk
  /// arithmetic well-defined).
  ///
  /// @param certificate Certificate whose key size would normally determine the block size; ignored
  ///                    by this policy and may be null.
  /// @return The asymmetric ciphertext block size in bytes (1).
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature size in bytes (zero; messages are not signed).
  /// @return The symmetric signature size in bytes (0).
  size_t symmetric_signature_size() const override;

  /// Returns the asymmetric signature size in bytes (zero; messages are not signed).
  ///
  /// @param certificate Signing certificate; ignored by this policy and may be null.
  /// @return The asymmetric signature size in bytes (0).
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;

  /// Returns the symmetric signature key size in bytes (zero; no key material is derived).
  /// @return The symmetric signature-key size in bytes (0).
  size_t symmetric_signature_key_size() const override;

  /// Returns the symmetric encryption key size in bytes (zero; no key material is derived).
  /// @return The symmetric encryption-key size in bytes (0).
  size_t symmetric_encryption_key_size() const override;

  /// Returns the symmetric initialization-vector size in bytes (zero; no symmetric encryption).
  /// @return The symmetric IV size in bytes (0).
  size_t symmetric_iv_size() const override;

  /// Returns the minimum accepted asymmetric key length in bits (zero; no asymmetric keys are used).
  /// @return The minimum accepted asymmetric key length in bits (0).
  size_t min_asymmetric_key_length() const override;

  /// Returns the maximum accepted asymmetric key length in bits (zero; no asymmetric keys are used).
  /// @return The maximum accepted asymmetric key length in bits (0).
  size_t max_asymmetric_key_length() const override;

  /// Returns @ref AsymmetricEncryptionAlgorithm "the none/no-encryption asymmetric algorithm".
  /// @return The none/no-encryption @ref AsymmetricEncryptionAlgorithm variant.
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;

  /// Returns @ref AsymmetricSignatureAlgorithm "the none/no-signature asymmetric algorithm".
  /// @return The none/no-signature @ref AsymmetricSignatureAlgorithm variant.
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;

  /// Returns the asymmetric signature algorithm URI, which is empty for the None policy.
  /// @return The asymmetric signature algorithm URI, empty for the None policy.
  String asymmetric_signature_algorithm_uri() const override;

  /// Returns @ref SymmetricEncryptionAlgorithm "the none/no-encryption symmetric algorithm".
  /// @return The none/no-encryption @ref SymmetricEncryptionAlgorithm variant.
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;

  /// Returns @ref SymmetricSignatureAlgorithm "the none/no-signature symmetric algorithm".
  /// @return The none/no-signature @ref SymmetricSignatureAlgorithm variant.
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  /// Derives the symmetric key set for a secure channel.
  ///
  /// For the None policy there is no key material to derive, so the callback is invoked with an empty
  /// key pair. The callback runs on an unspecified worker thread; on success its Result holds the
  /// (local, remote) @ref SecurityToken::Keys pair and on failure it carries an @ref ErrorDetail.
  /// This overload never throws.
  ///
  /// @param context     Secure channel context the keys belong to; must outlive the call.
  /// @param localNonce  This endpoint's nonce; ignored by the None policy and may be empty.
  /// @param remoteNonce The peer's nonce; ignored by the None policy and may be empty.
  /// @param role        Whether this endpoint is the channel's server or client.
  /// @param callback    Receives the derived key pair, or an @ref ErrorDetail on failure.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;
};
}  // namespace ua

#endif  // UA_SEC_POL_NONE_H
