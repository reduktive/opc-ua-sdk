// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The security policies that negotiate their symmetric keys by ephemeral key agreement.
/// @ingroup security

#ifndef UA_SEC_POL_EPHEMERAL_KEY_H
#define UA_SEC_POL_EPHEMERAL_KEY_H

#include <span>
#include <string_view>

#include "ua_certificate_key_rules.h"
#include "ua_security_policy.h"

namespace ua
{

/// One row of OPC 10000-6 Table 49 for a policy whose EphemeralKeyAlgorithm negotiates the keys.
///
/// The values every such policy shares (SecureChannelEnhancements TRUE, LegacySequenceNumbers FALSE, a
/// 96-bit IV, a 128-bit AEAD tag, no derived signing key) are constants of @ref SecPolEphemeralKey. The
/// nonce length, the encryption key length and the tag algorithm follow from the algorithms named here,
/// so a row cannot contradict itself.
/// @ingroup security
struct EphemeralKeyPolicyParameters
{
  SecurityPolicyId id;  ///< The policy's identifier.
  std::string_view uri;  ///< The SecurityPolicyUri.
  CertificateType certificateType;  ///< The application certificate type the policy needs.
  CertificateKeyRules certificateKeyRules;  ///< RSA or ECC certificate rules.
  EphemeralKeyAlgorithm ephemeralKeyAlgorithm;  ///< ECDH curve or finite-field group.
  AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm;  ///< Signs the OpenSecureChannel chunks.
  SymmetricKeyDerivationAlgorithm keyDerivationAlgorithm;  ///< HKDF variant.
  SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm;  ///< The AEAD cipher.
  HashAlgorithm certificateThumbprintAlgorithm;  ///< HASH() of OPC 10000-4 Table 101.
};

/// The fourteen released policies of OPC UA 1.05.07 that negotiate ephemeral keys, in the order of their
/// SecurityPolicyId.
///
/// @return A process-lifetime view.
/// @ingroup security
std::span<const EphemeralKeyPolicyParameters> ephemeral_key_policy_rows() noexcept;

/// Finds the row of @p id.
///
/// @param id The policy identifier.
/// @return The row, or null when @p id does not negotiate ephemeral keys.
/// @ingroup security
const EphemeralKeyPolicyParameters* find_ephemeral_key_policy(SecurityPolicyId id) noexcept;

/// Finds the row whose SecurityPolicyUri is @p uri.
///
/// @param uri The SecurityPolicyUri.
/// @return The row, or null when no such policy negotiates ephemeral keys.
/// @ingroup security
const EphemeralKeyPolicyParameters* find_ephemeral_key_policy(std::string_view uri) noexcept;

/// A security policy that negotiates its symmetric keys by ephemeral key agreement (OPC 10000-6 sections
/// 6.8 and 6.9): the ECC_* policies (ECDH) and RSA_DH (finite-field Diffie-Hellman).
///
/// The OpenSecureChannel chunks are signed, not encrypted; each side's nonce is an ephemeral public key;
/// both sides derive the keys with HKDF from the shared secret; symmetric chunks are AEAD-protected with
/// the per-chunk IV of Table 69. The certificate rules come from the row and are independent of the
/// handshake. One instance serves one row; instances are immutable and safe to share across threads.
/// @ingroup security
/// @see EphemeralKeyPolicyParameters, SecPolAsymmetricEncryption
class SecPolEphemeralKey final : public SecurityPolicy
{
public:
  /// IV length of every AEAD cipher these policies use, in bytes (InitializationVectorLength 96 bits).
  static constexpr size_t ivLength{12};
  /// AEAD tag length, in bytes (SignatureLength 128 bits).
  static constexpr size_t tagLength{16};

  /// Creates the policy for one row.
  ///
  /// @param parameters The row; it must outlive the policy (the rows are static).
  explicit SecPolEphemeralKey(const EphemeralKeyPolicyParameters& parameters) noexcept;

  /// Returns the row this policy was created for.
  ///
  /// @return The row.
  const EphemeralKeyPolicyParameters& parameters() const noexcept;

  /// @copydoc SecurityPolicy::id
  SecurityPolicyId id() const override;
  /// @copydoc SecurityPolicy::uri
  String uri() const override;
  /// @copydoc SecurityPolicy::certificate_type
  CertificateType certificate_type() const override;
  /// Returns `true`: the peer is authenticated by its certificate signature on the OpenSecureChannel.
  /// @return `true`.
  bool is_authenticated() const override;
  /// Returns whether the policy's certificates carry RSA keys (RSA_DH).
  /// @return `true` for RSA certificate rules.
  bool is_rsa() const override;
  /// Returns whether the policy's certificates carry ECC keys (ECC_*).
  /// @return `true` for ECC certificate rules.
  bool is_ecc() const override;
  /// Returns the nonce length: the encoded ephemeral public key (OPC 10000-6 section 6.8.1, Table 72).
  /// @return The nonce length, in bytes.
  size_t nonce_length() const override;
  /// Returns 1: AEAD chunks carry no padding.
  /// @return 1.
  size_t symmetric_plaintext_block_size() const override;
  /// Returns 0: the OpenSecureChannel chunks are not encrypted.
  /// @param certificate Not consulted.
  /// @return 0.
  size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const override;
  /// Returns 1: AEAD chunks carry no padding.
  /// @return 1.
  size_t symmetric_ciphertext_block_size() const override;
  /// Returns 0: the OpenSecureChannel chunks are not encrypted.
  /// @param certificate Not consulted.
  /// @return 0.
  size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const override;
  /// Returns the AEAD tag length, 16 bytes.
  /// @return 16.
  size_t symmetric_signature_size() const override;
  /// Returns the asymmetric signature size: the RSA modulus size, the r || s pair of the certificate's
  /// ECDSA curve, or the EdDSA signature size. Without a certificate, the size for the row's own curve
  /// (ECC) or 0 (RSA).
  /// @param certificate The signing certificate, or null.
  /// @return The signature size, in bytes.
  size_t asymmetric_signature_size(const X509Certificate* certificate) const override;
  /// Returns 0: the AEAD tag is computed with the encrypting key (DerivedSignatureKeyLength 0).
  /// @return 0.
  size_t symmetric_signature_key_size() const override;
  /// Returns the AEAD key length: 16 for AES-128-GCM, 32 for AES-256-GCM and ChaCha20-Poly1305.
  /// @return The encryption key length, in bytes.
  size_t symmetric_encryption_key_size() const override;
  /// Returns @ref ivLength.
  /// @return 12.
  size_t symmetric_iv_size() const override;
  /// Returns the smallest permitted RSA key in bits, or 0 for ECC rules.
  /// @return The minimum key length.
  size_t min_asymmetric_key_length() const override;
  /// Returns the largest permitted RSA key in bits, or 0 for ECC rules.
  /// @return The maximum key length.
  size_t max_asymmetric_key_length() const override;
  /// Returns `Invalid`: nothing is asymmetrically encrypted (for RSA_DH see OPC 10000-7, SD-P7-003).
  /// @return `AsymmetricEncryptionAlgorithm::Invalid`.
  AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;
  /// @copydoc SecurityPolicy::asymmetric_signature_algorithm
  AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;
  /// Applies the row's certificate rules (see @ref check_certificate_key_rules).
  /// @param certificate The certificate to check.
  /// @param signer      The certificate that signed it (itself when self-signed).
  /// @param position    Where @p certificate stands in the chain.
  /// @return Good, or `Bad_CertificatePolicyCheckFailed` naming the rule, position and subject.
  VoidResult check_certificate_compliance(const X509Certificate& certificate, const X509Certificate& signer,
    CertificateChainPosition position) const override;
  /// Returns an empty URI: SignatureData.algorithm is null for these policies (OPC 10000-4 section 7.36).
  /// @return An empty String.
  String asymmetric_signature_algorithm_uri() const override;
  /// @copydoc SecurityPolicy::symmetric_encryption_algorithm
  SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;
  /// Returns the AEAD tag algorithm of the row's cipher.
  /// @return The tag algorithm.
  SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;
  /// @copydoc SecurityPolicy::ephemeral_key_algorithm
  EphemeralKeyAlgorithm ephemeral_key_algorithm() const override;
  /// Returns `true`: every policy of this class has SecureChannelEnhancements.
  /// @return `true`.
  bool secure_channel_enhancements() const override;
  /// @copydoc SecurityPolicy::certificate_thumbprint_algorithm
  HashAlgorithm certificate_thumbprint_algorithm() const override;

  /// Derives the symmetric keys from the ephemeral nonces (OPC 10000-6 section 6.8.1): the shared secret
  /// of the local ephemeral private key and the peer's nonce, then one HKDF per direction with the
  /// `opcua-server` and `opcua-client` salts.
  ///
  /// @param context     Secure-channel context holding the local ephemeral private key; kept alive.
  /// @param localNonce  This side's ephemeral public key.
  /// @param remoteNonce The peer's ephemeral public key.
  /// @param role        Which side this is; orders the nonces in the salts.
  /// @param callback    Receives the (local, remote) keys or an ErrorDetail. Never throws.
  void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const override;

  /// Returns the key algorithm of an end-entity certificate: `Rsa` (RSA_DH) or the row's curve.
  /// @return The end-entity certificate key algorithm.
  CertificateKeyAlgorithm certificate_key_algorithm() const noexcept;

  /// Returns the key algorithm a CA above the issuing CA may also use: the ECC rules' larger curve, or
  /// `Rsa` for RSA_DH.
  /// @return The higher-CA certificate key algorithm.
  CertificateKeyAlgorithm higher_ca_certificate_key_algorithm() const noexcept;

  /// Returns the HKDF variant of the row.
  /// @return The key-derivation algorithm.
  SymmetricKeyDerivationAlgorithm key_derivation_algorithm() const noexcept;

  /// Builds the per-chunk IV from the token's base IV (OPC 10000-6 section 6.8.1, Table 69): the first 8
  /// bytes are XORed with @p tokenId and @p lastSequenceNumber, each a little-endian UInt32.
  ///
  /// @param baseIv             The security token's base IV.
  /// @param tokenId            Identifier of the token the chunk is secured with.
  /// @param lastSequenceNumber Sequence number of the previous chunk sent in the same direction (the
  ///                           OpenSecureChannel chunk counts); 0xFFFFFFFF after the number wraps.
  /// @return The per-chunk IV.
  static ByteString construct_per_message_iv(
    span<const byte> baseIv, uint32_t tokenId, uint32_t lastSequenceNumber);

protected:
  /// Decodes an OpenSecureChannel chunk: checks the policy URI, the receiver thumbprint and the sender
  /// certificate, validates the certificate, verifies the signature, then reassembles the body.
  /// @param context      Secure-channel context being decoded.
  /// @param decoder      Decoder positioned after the message header.
  /// @param messageChunk Raw chunk bytes; copied for the asynchronous part.
  /// @param header       Parsed message header of the chunk.
  /// @param callback     Receives the decoded body (empty until the final chunk) or an ErrorDetail.
  void decode_asymmetric_message_chunk_async(SecureChannelContext& context, UaBinaryDecoder& decoder,
    span<const byte> messageChunk, const stack_utils::UaScMessageHeader& header,
    std::function<void(DecodedMessageChunkResult)> callback) const override;

  /// Encodes an OpenSecureChannel message: chunks the body and signs each chunk.
  /// @param context          Secure-channel context being encoded.
  /// @param requestId        Request identifier for the sequence headers.
  /// @param messageBody      Body to send; copied for the asynchronous part.
  /// @param sendMessageChunk Receives each finished chunk.
  /// @param callback         Receives success or an ErrorDetail.
  void encode_asymmetric_message_async(SecureChannelContext& context, uint32_t requestId,
    span<const byte> messageBody, SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback) const override;

  /// Decodes a symmetric chunk: AEAD verification (and decryption in SignAndEncrypt) with the per-chunk IV,
  /// then the sequence header and body.
  /// @param context      Secure-channel context supplying the token.
  /// @param decoder      Decoder positioned after the message header.
  /// @param messageChunk Raw chunk bytes; copied for the asynchronous part.
  /// @param header       Parsed message header of the chunk.
  /// @param callback     Receives the decoded body (empty until the final chunk) or an ErrorDetail.
  void decode_symmetric_message_chunk_async(SecureChannelContext& context, UaBinaryDecoder& decoder,
    span<const byte> messageChunk, const stack_utils::UaScMessageHeader& header,
    std::function<void(DecodedMessageChunkResult)> callback) const override;

  /// Encodes a symmetric message: chunks the body and AEAD-protects each chunk.
  /// @param context          Secure-channel context supplying the token.
  /// @param requestId        Request identifier for the sequence headers.
  /// @param messageBody      Body to send; copied for the asynchronous part.
  /// @param sendMessageChunk Receives each finished chunk.
  /// @param callback         Receives success or an ErrorDetail.
  /// @param messageType      Message type of the chunks.
  void encode_symmetric_message_async(SecureChannelContext& context, uint32_t requestId,
    span<const byte> messageBody, SendMessageChunk sendMessageChunk, std::function<void(VoidResult)> callback,
    stack_utils::UaScMessageHeader::MessageType messageType =
      stack_utils::UaScMessageHeader::MessageType::Message) const override;

private:
  const EphemeralKeyPolicyParameters* mParameters;
};

}  // namespace ua

#endif  // UA_SEC_POL_EPHEMERAL_KEY_H
