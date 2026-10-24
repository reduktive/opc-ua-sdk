// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SECURITY_POLICY_H
#define UA_SECURITY_POLICY_H

/// @file
/// @brief Abstract OPC UA security policy: the cryptographic profile that secures a secure channel.
/// @ingroup security

#include "ua_includes.h"
#include "ua_crypto_types.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_byte_string.h"
#include "ua_string.h"
#include "ua_channel_role.h"
#include "ua_security_token.h"
#include "ua_stack_utilities.h"

namespace ua
{
enum class SecurityTokenRequestType;
}

namespace ua
{

struct SecureChannelContext;
class Stream;
class X509Certificate;

/// Where a certificate stands in the chain being validated, as the OPC 10000-7 profile database states
/// a policy's certificate requirements (OPC 10000-6 section 6.1: the requirements apply to the
/// certificate and every issuer in its chain).
/// @ingroup security
enum class CertificateChainPosition
{
  EndEntity,  ///< The certificate under validation (the leaf, or a self-signed application certificate).
  IssuingCa,  ///< The CA that issued the end entity.
  HigherCa  ///< Every CA above the issuing CA, the self-signed root included.
};

/// Outcome of decoding one secure channel message chunk.
///
/// On success the optional holds the request id and the assembled message body once the final
/// chunk of a message has been received; it is empty while intermediate chunks are still being
/// accumulated. On failure the Result carries an `ErrorDetail`.
using DecodedMessageChunkResult = Result<optional<std::pair<uint32_t, ByteString>>>;

/// Abstract OPC UA security policy: the cryptographic profile that secures a secure channel.
///
/// A security policy bundles the algorithms, key sizes, and chunk encode/decode logic for one
/// OPC UA SecurityPolicy URI (None, Basic256Sha256, the Aes/RSA profiles, the ECC profiles, ...).
/// The base class supplies the common message-chunk dispatch, certificate validation, padding,
/// and sequence-number checking; concrete subclasses fill in the algorithm-specific block sizes,
/// key lengths, and key derivation.
///
/// Instances are reference-counted (`shared_from_this`) because asynchronous crypto flows capture
/// the policy for their duration. A single policy instance is stateless with respect to a channel:
/// per-channel state lives in the @ref SecureChannelContext passed to each operation.
///
/// @note The `*_async` crypto operations dispatch their continuations onto the strand carried by
///       the @ref SecureChannelContext when one is present; callbacks must not block.
/// @see SecurityPolicyId, SecureChannelContext
/// @ingroup security
namespace test_access
{
// Test-only interface (defined in ua_security_policy_test_access.h) that drives the protected symmetric
// encode path with a caller-supplied SendMessageChunk, so a unit test can inject a mid-stream send failure
// and observe the emitted Abort chunk (CL-TCP-011). Not part of the shipped surface.
struct SymmetricEncodeDriver;
}  // namespace test_access

/// Public security policy API.
/// @ingroup security
class SecurityPolicy : public std::enable_shared_from_this<SecurityPolicy>
{
  friend struct test_access::SymmetricEncodeDriver;

public:
  /// Sink that emits one encoded outgoing message chunk to the transport.
  using SendMessageChunk = std::function<void(ByteString)>;

  virtual ~SecurityPolicy()
  {}

  SecurityPolicy(const SecurityPolicy&) = delete;
  SecurityPolicy& operator=(const SecurityPolicy&) = delete;
  SecurityPolicy(SecurityPolicy&&) = delete;
  SecurityPolicy& operator=(SecurityPolicy&&) = delete;

  /// Returns the enumerated identifier of this policy.
  ///
  /// @return The enumerated identifier of this policy.
  virtual SecurityPolicyId id() const = 0;

  /// Returns the OPC UA SecurityPolicy URI of this policy.
  ///
  /// @return The OPC UA SecurityPolicy URI of this policy.
  virtual String uri() const = 0;

  /// Returns the certificate type this policy requires (RSA or one of the ECC curve types).
  ///
  /// @return The certificate type this policy requires (RSA or an ECC curve type).
  virtual CertificateType certificate_type() const = 0;

  /// Returns whether this policy uses authenticated encryption (an AEAD construction).
  ///
  /// @return @c true if this policy uses authenticated encryption (an AEAD construction).
  virtual bool is_authenticated() const = 0;

  /// Returns whether this policy is an RSA-family policy.
  ///
  /// @return @c true if this is an RSA-family policy.
  virtual bool is_rsa() const = 0;

  /// Returns whether this policy is an ECC-family policy.
  ///
  /// @return @c true if this is an ECC-family policy.
  virtual bool is_ecc() const = 0;

  /// Returns whether this policy uses the legacy (pre-1.04) sequence-number wrapping rules.
  ///
  /// The base implementation returns `false`; deprecated RSA policies override it.
  ///
  /// @return @c true if this policy uses the legacy sequence-number wrapping rules.
  virtual bool uses_legacy_sequence_no() const;

  /// Returns whether this policy is deprecated by the OPC UA specification.
  ///
  /// Deprecated policies remain implemented for interoperability but should not be offered by new
  /// endpoints. The base implementation returns `false`.
  ///
  /// @return @c true if this policy is deprecated by the OPC UA specification.
  virtual bool is_deprecated() const;

  /// Returns the EphemeralKeyAlgorithm of OPC 10000-6 Table 49: how the policy agrees its symmetric keys
  /// by ephemeral key exchange. `Invalid` means the policy does not (the keys come from the nonces of an
  /// asymmetrically encrypted OpenSecureChannel). The base implementation returns `Invalid`.
  ///
  /// @return The ephemeral key algorithm, or `Invalid`.
  virtual EphemeralKeyAlgorithm ephemeral_key_algorithm() const;

  /// Returns the SecureChannelEnhancements flag of OPC 10000-6 Table 49: whether the channel binds the
  /// first OpenSecureChannel response to the request signature, chains the key material across renewals
  /// and uses the channel-bound session signatures of OPC 10000-4. The base implementation returns
  /// `false`.
  ///
  /// @return @c true for a policy with SecureChannelEnhancements.
  virtual bool secure_channel_enhancements() const;

  /// Returns the CertificateThumbprintAlgorithm of the policy's profile: the HASH() of the channel-bound
  /// signatures of OPC 10000-4 section 5.7.3. `Invalid` means the policy defines none. The base
  /// implementation returns `Invalid`.
  ///
  /// @return The certificate thumbprint hash algorithm, or `Invalid`.
  virtual HashAlgorithm certificate_thumbprint_algorithm() const;

  /// Returns the length, in bytes, of the nonce this policy uses for key derivation.
  ///
  /// @return The nonce length, in bytes, used for key derivation.
  virtual size_t nonce_length() const = 0;

  /// Returns the symmetric cipher plaintext block size, in bytes.
  ///
  /// @return The symmetric cipher plaintext block size, in bytes.
  virtual size_t symmetric_plaintext_block_size() const = 0;

  /// Returns the asymmetric plaintext block size, in bytes, for the given peer certificate.
  ///
  /// @param certificate Peer certificate whose key determines the block size; must not be null.
  /// @return The asymmetric plaintext block size, in bytes, for @p certificate.
  virtual size_t asymmetric_plaintext_block_size(const X509Certificate* certificate) const = 0;

  /// Returns the symmetric cipher ciphertext block size, in bytes.
  ///
  /// @return The symmetric cipher ciphertext block size, in bytes.
  virtual size_t symmetric_ciphertext_block_size() const = 0;

  /// Returns the asymmetric ciphertext block size, in bytes, for the given peer certificate.
  ///
  /// @param certificate Peer certificate whose key determines the block size; must not be null.
  /// @return The asymmetric ciphertext block size, in bytes, for @p certificate.
  virtual size_t asymmetric_ciphertext_block_size(const X509Certificate* certificate) const = 0;

  /// Returns the symmetric signature (MAC) size, in bytes.
  ///
  /// @return The symmetric signature (MAC) size, in bytes.
  virtual size_t symmetric_signature_size() const = 0;

  /// Returns the asymmetric signature size, in bytes, for the given peer certificate.
  ///
  /// @param certificate Peer certificate whose key determines the signature size; must not be null.
  /// @return The asymmetric signature size, in bytes, for @p certificate.
  virtual size_t asymmetric_signature_size(const X509Certificate* certificate) const = 0;

  /// Returns the symmetric signing key size, in bytes.
  ///
  /// @return The symmetric signing key size, in bytes.
  virtual size_t symmetric_signature_key_size() const = 0;

  /// Returns the symmetric encryption key size, in bytes.
  ///
  /// @return The symmetric encryption key size, in bytes.
  virtual size_t symmetric_encryption_key_size() const = 0;

  /// Returns the symmetric initialization-vector size, in bytes.
  ///
  /// @return The symmetric initialization-vector size, in bytes.
  virtual size_t symmetric_iv_size() const = 0;

  /// Returns the minimum acceptable asymmetric key length, in bits.
  ///
  /// @return The minimum acceptable asymmetric key length, in bits.
  virtual size_t min_asymmetric_key_length() const = 0;

  /// Returns the maximum acceptable asymmetric key length, in bits.
  ///
  /// @return The maximum acceptable asymmetric key length, in bits.
  virtual size_t max_asymmetric_key_length() const = 0;

  /// Returns the asymmetric encryption algorithm used during channel open.
  ///
  /// @return The asymmetric encryption algorithm used during channel open.
  virtual AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const = 0;

  /// Returns the asymmetric signature algorithm used during channel open.
  ///
  /// @return The asymmetric signature algorithm used during channel open.
  virtual AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const = 0;

  /// Checks one certificate of a chain against this policy's certificate requirements (OPC 10000-4
  /// Table 106 step 4, Security Policy Check; OPC 10000-6 section 6.1; the OPC 10000-7 profile
  /// database entry of the policy): the key family, its length or curve at @p position, and the
  /// CertificateSignatureAlgorithm @p signer put on @p certificate.
  ///
  /// The certificate validator calls this for every certificate of the chain it built when a
  /// @ref CertificateValidationRequest names a policy; the edge-wise rules between a certificate and
  /// its issuer (key length and algorithm priority never increase towards the leaf) are the
  /// validator's, not this function's. Not suppressible.
  ///
  /// @param certificate The certificate to check.
  /// @param signer      The certificate whose key signed @p certificate: its issuer, or @p certificate
  ///                    itself for a self-signed certificate.
  /// @param position    Where @p certificate stands in the chain.
  /// @return A good @ref VoidResult when the certificate complies, else
  ///         `Bad_CertificatePolicyCheckFailed` with an ErrorDetail naming the rule, the position and
  ///         the certificate subject. The None policy places no requirement and returns good.
  virtual VoidResult check_certificate_compliance(const X509Certificate& certificate,
    const X509Certificate& signer, CertificateChainPosition position) const = 0;

  /// Returns the URI of the asymmetric signature algorithm, as carried on the wire.
  ///
  /// @return The URI of the asymmetric signature algorithm, as carried on the wire.
  virtual String asymmetric_signature_algorithm_uri() const = 0;

  /// Returns the symmetric encryption algorithm used for established-channel traffic.
  ///
  /// @return The symmetric encryption algorithm for established-channel traffic.
  virtual SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const = 0;

  /// Returns the symmetric signature algorithm used for established-channel traffic.
  ///
  /// @return The symmetric signature algorithm for established-channel traffic.
  virtual SymmetricSignatureAlgorithm symmetric_signature_algorithm() const = 0;

  /// Pair of derived key sets: the local (signing/encrypting) keys and the remote (verifying/
  /// decrypting) keys, or an @ref ErrorDetail on failure.
  using DeriveSymmetricKeysResult = Result<std::pair<SecurityToken::Keys, SecurityToken::Keys>>;

  /// Decodes one received secure channel message chunk, completing asynchronously.
  ///
  /// Dispatches to the asymmetric or symmetric decode path based on the chunk's message type. The
  /// policy takes ownership of @p messageChunk and retains it for the duration of the flow so that
  /// the internal span views into it stay valid. Continuations run on the strand carried by
  /// @p context when one is present.
  ///
  /// This overload is `virtual` so test fakes may override the whole dispatch; production policies
  /// inherit the base behaviour.
  ///
  /// @param context      Per-channel secure channel state; must outlive the operation.
  /// @param messageChunk The raw received chunk; ownership is taken for the flow's duration.
  /// @param callback     Receives the outcome: on success the @ref DecodedMessageChunkResult holds
  ///                     the request id and assembled body once the final chunk arrives, and is
  ///                     empty for intermediate chunks; on failure it carries an @ref ErrorDetail.
  ///                     Never throws.
  virtual void decode_message_chunk_async(shared_ptr<SecureChannelContext> context, ByteString messageChunk,
    std::function<void(DecodedMessageChunkResult)> callback) const;

  /// Encodes an outgoing message into one or more secure channel chunks, completing asynchronously.
  ///
  /// Dispatches to the asymmetric or symmetric encode path based on the message and channel state,
  /// chunking, padding, signing, and encrypting as the policy requires, then emits each finished
  /// chunk through @p sendMessageChunk. `virtual` for the same reason as
  /// @ref decode_message_chunk_async.
  ///
  /// @param context          Per-channel secure channel state; must outlive the operation.
  /// @param requestId        Request id stamped into each chunk's sequence header.
  /// @param message          Message to encode.
  /// @param sendMessageChunk Sink invoked once per finished outgoing chunk.
  /// @param callback         Receives the outcome as a @ref VoidResult - success, or an
  ///                         @ref ErrorDetail on failure. Never throws.
  virtual void encode_message_async(shared_ptr<SecureChannelContext> context, uint32_t requestId,
    shared_ptr<Structure> message, SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback) const;

  /// Derives the symmetric session keys for an established channel, completing asynchronously.
  ///
  /// Combines the local and remote nonces per this policy's key-derivation function and assembles
  /// both key sets. @p role selects which derived half is the local key set.
  ///
  /// @param context     Per-channel secure channel state; must outlive the operation.
  /// @param localNonce  Nonce generated by this participant.
  /// @param remoteNonce Nonce received from the peer.
  /// @param role        Whether this participant is the server or the client.
  /// @param callback    Receives the outcome as a @ref DeriveSymmetricKeysResult - the
  ///                    (local, remote) key-set pair, or an @ref ErrorDetail on failure.
  ///                    Never throws.
  virtual void derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context, ByteString localNonce,
    ByteString remoteNonce, ChannelRole role,
    std::function<void(DeriveSymmetricKeysResult)> callback) const = 0;

  /// Creates the policy implementation for the given enumerated identifier.
  ///
  /// @param id Policy identifier to instantiate.
  /// @return A shared instance of the matching policy. Never null.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p id is not a known policy.
  /// @see create(string_view)
  static shared_ptr<SecurityPolicy> create(SecurityPolicyId id);

  /// Returns every SecurityPolicy implemented by the secure-channel factory.
  ///
  /// This is the production capability registry used by release documentation and applications that
  /// need to report the SDK's compiled policy set. PubSub-only policies are excluded because this factory
  /// creates UA Secure Conversation policies.
  ///
  /// @return A stable, process-lifetime view of the implemented policy identifiers.
  static span<const SecurityPolicyId> supported_policy_ids() noexcept;

  /// Creates the policy implementation for the given OPC UA SecurityPolicy URI.
  ///
  /// @param uri Policy URI to instantiate.
  /// @return A shared instance of the matching policy. Never null.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p uri matches no known policy.
  /// @see create(SecurityPolicyId)
  static shared_ptr<SecurityPolicy> create(string_view uri);

  /// Validates a received chunk's sequence header against the channel's accumulated state.
  ///
  /// Enforces the policy's sequence-number wrapping rules and that all chunks of a multi-chunk
  /// message carry the same request id, updating @p context accordingly.
  ///
  /// @param context        Per-channel secure channel state; updated in place.
  /// @param sequenceHeader Sequence header decoded from the current chunk.
  /// @throws UaException with @ref Status::BadSequenceNumberInvalid if the sequence number violates
  ///         the ordering rules, or @ref Status::BadDecodingError if the request id does not match
  ///         the in-progress message.
  void check_sequence_header(
    SecureChannelContext& context, const stack_utils::SequenceHeader& sequenceHeader) const;

  /// Appends the remaining decoder bytes to the channel's accumulated message body.
  ///
  /// Used while reassembling a multi-chunk message: copies the unread tail of @p decoder onto the
  /// body buffer in @p context.
  ///
  /// @param context Per-channel secure channel state; its message body buffer is extended.
  /// @param decoder Decoder positioned at the start of this chunk's body.
  void copy_message_body(SecureChannelContext& context, const UaBinaryDecoder& decoder) const;

  /// Returns whether the channel is operating in SignAndEncrypt mode.
  ///
  /// @param context Per-channel secure channel state.
  /// @return @c true if the channel is in SignAndEncrypt mode.
  bool is_encrypted(const SecureChannelContext& context) const;

  /// Asymmetrically decrypts a received OpenSecureChannel chunk, completing asynchronously.
  ///
  /// @param context              Per-channel secure channel state; must outlive the operation.
  /// @param messageChunk         Encrypted chunk bytes; caller retains ownership for the flow.
  /// @param sequenceHeaderOffset Offset, in bytes, to the encrypted region within @p messageChunk.
  /// @param callback             Receives the decrypted bytes, or an @ref ErrorDetail on failure.
  ///                             Never throws.
  void asymmetric_decrypt_async(SecureChannelContext& context, span<const byte> messageChunk,
    size_t sequenceHeaderOffset, std::function<void(ByteStringResult)> callback) const;

  /// Asymmetrically encrypts an outgoing OpenSecureChannel chunk, completing asynchronously.
  ///
  /// @param context    Per-channel secure channel state; must outlive the operation.
  /// @param plainText  Plaintext to encrypt; caller retains ownership for the flow.
  /// @param ciphertext Output buffer receiving the ciphertext; must be sized by the caller and
  ///                   remain valid until the callback runs.
  /// @param callback   Receives the outcome as a @ref VoidResult - success, or an @ref ErrorDetail
  ///                   on failure. Never throws.
  void asymmetric_encrypt_async(SecureChannelContext& context, span<const byte> plainText,
    span<byte> ciphertext, std::function<void(VoidResult)> callback) const;

  /// Symmetrically decrypts a received established-channel chunk, completing asynchronously.
  ///
  /// @param context              Per-channel secure channel state; must outlive the operation.
  /// @param keys                 The remote keys of the token the chunk's TokenId selected; must
  ///                             outlive the operation.
  /// @param messageChunk         Encrypted chunk bytes; caller retains ownership for the flow.
  /// @param sequenceHeaderOffset Offset, in bytes, to the encrypted region within @p messageChunk.
  /// @param callback             Receives the decrypted bytes, or an @ref ErrorDetail on failure.
  ///                             Never throws.
  void symmetric_decrypt_async(SecureChannelContext& context, const SecurityToken::Keys& keys,
    span<const byte> messageChunk, size_t sequenceHeaderOffset,
    std::function<void(ByteStringResult)> callback) const;

  /// Symmetrically encrypts an outgoing established-channel chunk, completing asynchronously.
  ///
  /// @param context    Per-channel secure channel state; must outlive the operation.
  /// @param plainText  Plaintext to encrypt; caller retains ownership for the flow.
  /// @param ciphertext Output buffer receiving the ciphertext; must be sized by the caller and
  ///                   remain valid until the callback runs.
  /// @param callback   Receives the outcome as a @ref VoidResult - success, or an @ref ErrorDetail
  ///                   on failure. Never throws.
  void symmetric_encrypt_async(SecureChannelContext& context, span<const byte> plainText,
    span<byte> ciphertext, std::function<void(VoidResult)> callback) const;

  /// Validates the peer certificate against this policy and the channel's certificate store.
  ///
  /// Checks an RSA certificate's key length or an ECC certificate's named curve against this
  /// policy, then delegates trust-chain validation to the channel's certificate store, completing
  /// asynchronously.
  ///
  /// @param context  Per-channel secure channel state; must outlive the operation.
  /// @param callback Receives the outcome as a @ref VoidResult - success, or an @ref ErrorDetail
  ///                 describing why the certificate was rejected. Never throws.
  void validate_certificate_async(
    SecureChannelContext& context, std::function<void(VoidResult)> callback) const;

  /// Appends padding bytes to the encoder so the message satisfies the cipher's block alignment.
  ///
  /// Computes the padding (including the OPC UA extra-padding byte for keys longer than 2048 bits),
  /// writes the padding and padding-size bytes through @p encoder, and returns the resulting
  /// ciphertext size.
  ///
  /// @param limits             Encoding limits applied while writing the padding.
  /// @param encoder            Encoder positioned at the end of the message body; padding is
  ///                           written here.
  /// @param keyLengthInBits    Asymmetric key length, in bits; selects whether extra padding is
  ///                           required.
  /// @param headerSize         Size, in bytes, of the headers preceding the encrypted region.
  /// @param signatureSize      Size, in bytes, of the trailing signature.
  /// @param plaintextBlockSize Cipher plaintext block size, in bytes.
  /// @param ciphertextBlockSize Cipher ciphertext block size, in bytes.
  /// @return The total ciphertext size, in bytes, after padding and encryption.
  size_t append_padding(const EncodingLimits& limits, UaBinaryEncoder& encoder, size_t keyLengthInBits,
    size_t headerSize, size_t signatureSize, size_t plaintextBlockSize, size_t ciphertextBlockSize) const;

protected:
  /// Default-constructs the base; only subclasses construct a @ref SecurityPolicy.
  SecurityPolicy() = default;

  /// Builds the refusal @ref check_certificate_compliance returns: `Bad_CertificatePolicyCheckFailed`
  /// with an ErrorDetail whose code names the rule, and whose context names this policy, @p position
  /// and the subject of @p certificate.
  ///
  /// @param rule        The rule that failed, as a symbolic ErrorDetail code.
  /// @param summary     A one-line description of the failed rule.
  /// @param certificate The certificate that failed the rule.
  /// @param position    Where @p certificate stands in the chain.
  /// @return The refusal.
  VoidResult certificate_policy_refusal(std::string_view rule, std::string_view summary,
    const X509Certificate& certificate, CertificateChainPosition position) const;

  /// RSA PKCS#1 v1.5 padding overhead, in bytes.
  static constexpr size_t sPkcs1PaddingOverhead{11};
  /// RSA OAEP with SHA-1 padding overhead, in bytes.
  static constexpr size_t sOaepSha1PaddingOverhead{42};
  /// RSA OAEP with SHA-256 padding overhead, in bytes.
  static constexpr size_t sOaepSha256PaddingOverhead{66};

  /// Decodes a chunk whose message type is not yet known, dispatching to the right path.
  ///
  /// Peeks the message header on @p messageChunk to choose the asymmetric or symmetric decode path,
  /// then completes asynchronously.
  ///
  /// @param context      Per-channel secure channel state; must outlive the operation.
  /// @param messageChunk Raw chunk bytes; caller retains ownership for the flow.
  /// @param callback     Receives a @ref DecodedMessageChunkResult, or an @ref ErrorDetail on
  ///                     failure. Never throws.
  void decode_unknown_message_chunk_async(SecureChannelContext& context, span<const byte> messageChunk,
    std::function<void(DecodedMessageChunkResult)> callback) const;

  /// Decodes an asymmetrically secured (OpenSecureChannel) chunk; extension point for subclasses.
  ///
  /// @param context      Per-channel secure channel state; must outlive the operation.
  /// @param decoder      Decoder positioned past the message header.
  /// @param messageChunk Raw chunk bytes backing @p decoder; caller retains ownership for the flow.
  /// @param header       Parsed secure channel message header for this chunk.
  /// @param callback     Receives a @ref DecodedMessageChunkResult, or an @ref ErrorDetail on
  ///                     failure. Never throws.
  virtual void decode_asymmetric_message_chunk_async(SecureChannelContext& context, UaBinaryDecoder& decoder,
    span<const byte> messageChunk, const stack_utils::UaScMessageHeader& header,
    std::function<void(DecodedMessageChunkResult)> callback) const;

  /// Decodes a symmetrically secured (established-channel) chunk; extension point for subclasses.
  ///
  /// @param context      Per-channel secure channel state; must outlive the operation.
  /// @param decoder      Decoder positioned past the message header.
  /// @param messageChunk Raw chunk bytes backing @p decoder; caller retains ownership for the flow.
  /// @param header       Parsed secure channel message header for this chunk.
  /// @param callback     Receives a @ref DecodedMessageChunkResult, or an @ref ErrorDetail on
  ///                     failure. Never throws.
  virtual void decode_symmetric_message_chunk_async(SecureChannelContext& context, UaBinaryDecoder& decoder,
    span<const byte> messageChunk, const stack_utils::UaScMessageHeader& header,
    std::function<void(DecodedMessageChunkResult)> callback) const;

  /// Encodes a message whose securing mode is selected from channel state, then dispatches.
  ///
  /// @param context          Per-channel secure channel state; must outlive the operation.
  /// @param requestId        Request id stamped into each chunk's sequence header.
  /// @param message          Message to encode.
  /// @param sendMessageChunk Sink invoked once per finished outgoing chunk.
  /// @param callback         Receives a @ref VoidResult, or an @ref ErrorDetail on failure. Never
  ///                         throws.
  void encode_unknown_message_async(SecureChannelContext& context, uint32_t requestId,
    shared_ptr<const Structure> message, SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback) const;

  /// Encodes an asymmetrically secured (OpenSecureChannel) message; extension point for subclasses.
  ///
  /// @param context          Per-channel secure channel state; must outlive the operation.
  /// @param requestId        Request id stamped into each chunk's sequence header.
  /// @param messageBody      Already-serialized message body to secure; caller retains ownership
  ///                         for the flow.
  /// @param sendMessageChunk Sink invoked once per finished outgoing chunk.
  /// @param callback         Receives a @ref VoidResult, or an @ref ErrorDetail on failure. Never
  ///                         throws.
  virtual void encode_asymmetric_message_async(SecureChannelContext& context, uint32_t requestId,
    span<const byte> messageBody, SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback) const;

  /// Encodes a symmetrically secured (established-channel) message; extension point for subclasses.
  ///
  /// @param context          Per-channel secure channel state; must outlive the operation.
  /// @param requestId        Request id stamped into each chunk's sequence header.
  /// @param messageBody      Already-serialized message body to secure; caller retains ownership
  ///                         for the flow.
  /// @param sendMessageChunk Sink invoked once per finished outgoing chunk.
  /// @param callback         Receives a @ref VoidResult, or an @ref ErrorDetail on failure. Never
  ///                         throws.
  /// @param messageType      Secure channel message type to stamp into the header; defaults to a
  ///                         normal Message chunk.
  virtual void encode_symmetric_message_async(SecureChannelContext& context, uint32_t requestId,
    span<const byte> messageBody, SendMessageChunk sendMessageChunk, std::function<void(VoidResult)> callback,
    stack_utils::UaScMessageHeader::MessageType messageType =
      stack_utils::UaScMessageHeader::MessageType::Message) const;

  /// Derives both symmetric key sets using the P_SHA construction; shared by RSA-family policies.
  ///
  /// Performs two P_SHA / HKDF-equivalent derivations (local and remote) and assembles a
  /// @ref SecurityToken::Keys for each, completing asynchronously.
  ///
  /// @param algorithm   P_SHA variant to use for the derivation.
  /// @param context     Per-channel secure channel state; must outlive the operation.
  /// @param localNonce  Nonce generated by this participant.
  /// @param remoteNonce Nonce received from the peer.
  /// @param callback    Receives the outcome as a @ref DeriveSymmetricKeysResult - the
  ///                    (local, remote) key-set pair, or an @ref ErrorDetail on failure.
  ///                    Never throws.
  void derive_symmetric_keys_psha_async(SymmetricKeyDerivationAlgorithm algorithm,
    shared_ptr<SecureChannelContext> context, ByteString localNonce, ByteString remoteNonce,
    std::function<void(DeriveSymmetricKeysResult)> callback) const;
};

/// The rank of a SecurityPolicy in the SDK's one security ordering (decision D-7). The server's
/// EndpointDescription.securityLevel (@ref compute_security_level) and the client's endpoint ranking both
/// read it, so the two sides order policies the same way.
///
/// Tier 0 is "not recommended": None, the deprecated Basic128Rsa15 and Basic256, the PubSub-only policies and
/// Invalid. Every policy with SecureChannelEnhancements ranks above every policy without them (ephemeral
/// keys, so forward secrecy; AEAD; channel bound session signatures). Within each group policies rank by
/// effective strength; at equal strength the NIST curves rank one tier below Brainpool and RSA_DH (their
/// curve seeds cannot be verified), and the Bernstein curves one tier above (auditable design, constant
/// time). The AesGcm and the ChaChaPoly policy of one curve share a tier.
///
/// | Tier | Policies                                                |
/// |------|---------------------------------------------------------|
/// | 0    | None, Basic128Rsa15, Basic256, PubSub-*, Invalid        |
/// | 1    | Basic256Sha256                                          |
/// | 2    | Aes128_Sha256_RsaOaep                                   |
/// | 3    | Aes256_Sha256_RsaPss                                    |
/// | 4    | ECC_nistP256_*                                          |
/// | 5    | ECC_brainpoolP256r1_*, RSA_DH_*                         |
/// | 6    | ECC_curve25519_*                                        |
/// | 7    | ECC_nistP384_*                                          |
/// | 8    | ECC_brainpoolP384r1_*                                   |
/// | 9    | ECC_curve448_*                                          |
///
/// @param id The policy.
/// @return The tier, 0 to 9; 0 for a value outside the enumeration.
/// @ingroup security
int security_policy_tier(SecurityPolicyId id) noexcept;

}  // namespace ua

#endif  // UA_SECURITY_POLICY_H
