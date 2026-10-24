// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_SECURITY_POLICY_H
#define FUZZ_SECURITY_POLICY_H

#include "ua_security_policy.h"

#include <functional>

namespace opcua_fuzzer
{

/// Interceptor callback receives the encoded chunk bytes (mutable) before they are forwarded.
/// The interceptor may modify the bytes in-place or replace them entirely.
using ChunkInterceptor = std::function<ua::ByteString(ua::ByteString)>;

/// SecurityPolicy decorator that delegates everything to an inner policy but intercepts
/// outgoing encoded message chunks via a configurable callback. Used by Layer 3/4 harnesses
/// to mutate encoded bytes before they reach the wire.
class FuzzSecurityPolicy final : public ua::SecurityPolicy
{
public:
  explicit FuzzSecurityPolicy(std::shared_ptr<ua::SecurityPolicy> inner);

  void set_encode_interceptor(ChunkInterceptor interceptor);

  // --- Property queries: delegate to inner ---
  ua::SecurityPolicyId id() const override;
  ua::String uri() const override;
  ua::CertificateType certificate_type() const override;
  bool is_authenticated() const override;
  bool is_rsa() const override;
  bool is_ecc() const override;
  ua::EphemeralKeyAlgorithm ephemeral_key_algorithm() const override;
  bool secure_channel_enhancements() const override;
  ua::HashAlgorithm certificate_thumbprint_algorithm() const override;

  // A fake places no requirement on a certificate (the None policy's answer).
  ua::VoidResult check_certificate_compliance(
    const ua::X509Certificate&, const ua::X509Certificate&, ua::CertificateChainPosition) const override
  {
    return {};
  }

  bool uses_legacy_sequence_no() const override;
  bool is_deprecated() const override;
  size_t nonce_length() const override;
  size_t symmetric_plaintext_block_size() const override;
  size_t asymmetric_plaintext_block_size(const ua::X509Certificate* certificate) const override;
  size_t symmetric_ciphertext_block_size() const override;
  size_t asymmetric_ciphertext_block_size(const ua::X509Certificate* certificate) const override;
  size_t symmetric_signature_size() const override;
  size_t asymmetric_signature_size(const ua::X509Certificate* certificate) const override;
  size_t symmetric_signature_key_size() const override;
  size_t symmetric_encryption_key_size() const override;
  size_t symmetric_iv_size() const override;
  size_t min_asymmetric_key_length() const override;
  size_t max_asymmetric_key_length() const override;
  ua::AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;
  ua::AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;
  ua::String asymmetric_signature_algorithm_uri() const override;
  ua::SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;
  ua::SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  // --- Core operations ---
  void decode_message_chunk_async(std::shared_ptr<ua::SecureChannelContext> context,
    ua::ByteString messageChunk, std::function<void(ua::DecodedMessageChunkResult)> callback) const override;

  void encode_message_async(std::shared_ptr<ua::SecureChannelContext> context, uint32_t requestId,
    std::shared_ptr<ua::Structure> message, SendMessageChunk sendMessageChunk,
    std::function<void(ua::VoidResult)> callback) const override;

  void derive_symmetric_keys_async(std::shared_ptr<ua::SecureChannelContext> context,
    ua::ByteString localNonce, ua::ByteString remoteNonce, ua::ChannelRole role,
    std::function<void(ua::SecurityPolicy::DeriveSymmetricKeysResult)> callback) const override;

private:
  std::shared_ptr<ua::SecurityPolicy> mInner;
  ChunkInterceptor mInterceptor;
};

}  // namespace opcua_fuzzer

#endif  // FUZZ_SECURITY_POLICY_H
