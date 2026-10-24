// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fuzz_security_policy.h"

namespace opcua_fuzzer
{

FuzzSecurityPolicy::FuzzSecurityPolicy(std::shared_ptr<ua::SecurityPolicy> inner) : mInner{std::move(inner)}
{}

void FuzzSecurityPolicy::set_encode_interceptor(ChunkInterceptor interceptor)
{
  mInterceptor = std::move(interceptor);
}

// --- Property queries: delegate to inner ---

ua::SecurityPolicyId FuzzSecurityPolicy::id() const
{
  return mInner->id();
}

ua::String FuzzSecurityPolicy::uri() const
{
  return mInner->uri();
}

ua::CertificateType FuzzSecurityPolicy::certificate_type() const
{
  return mInner->certificate_type();
}

bool FuzzSecurityPolicy::is_authenticated() const
{
  return mInner->is_authenticated();
}

bool FuzzSecurityPolicy::is_rsa() const
{
  return mInner->is_rsa();
}

bool FuzzSecurityPolicy::is_ecc() const
{
  return mInner->is_ecc();
}

ua::EphemeralKeyAlgorithm FuzzSecurityPolicy::ephemeral_key_algorithm() const
{
  return mInner->ephemeral_key_algorithm();
}

bool FuzzSecurityPolicy::secure_channel_enhancements() const
{
  return mInner->secure_channel_enhancements();
}

ua::HashAlgorithm FuzzSecurityPolicy::certificate_thumbprint_algorithm() const
{
  return mInner->certificate_thumbprint_algorithm();
}

bool FuzzSecurityPolicy::uses_legacy_sequence_no() const
{
  return mInner->uses_legacy_sequence_no();
}

bool FuzzSecurityPolicy::is_deprecated() const
{
  return mInner->is_deprecated();
}

size_t FuzzSecurityPolicy::nonce_length() const
{
  return mInner->nonce_length();
}

size_t FuzzSecurityPolicy::symmetric_plaintext_block_size() const
{
  return mInner->symmetric_plaintext_block_size();
}

size_t FuzzSecurityPolicy::asymmetric_plaintext_block_size(const ua::X509Certificate* certificate) const
{
  return mInner->asymmetric_plaintext_block_size(certificate);
}

size_t FuzzSecurityPolicy::symmetric_ciphertext_block_size() const
{
  return mInner->symmetric_ciphertext_block_size();
}

size_t FuzzSecurityPolicy::asymmetric_ciphertext_block_size(const ua::X509Certificate* certificate) const
{
  return mInner->asymmetric_ciphertext_block_size(certificate);
}

size_t FuzzSecurityPolicy::symmetric_signature_size() const
{
  return mInner->symmetric_signature_size();
}

size_t FuzzSecurityPolicy::asymmetric_signature_size(const ua::X509Certificate* certificate) const
{
  return mInner->asymmetric_signature_size(certificate);
}

size_t FuzzSecurityPolicy::symmetric_signature_key_size() const
{
  return mInner->symmetric_signature_key_size();
}

size_t FuzzSecurityPolicy::symmetric_encryption_key_size() const
{
  return mInner->symmetric_encryption_key_size();
}

size_t FuzzSecurityPolicy::symmetric_iv_size() const
{
  return mInner->symmetric_iv_size();
}

size_t FuzzSecurityPolicy::min_asymmetric_key_length() const
{
  return mInner->min_asymmetric_key_length();
}

size_t FuzzSecurityPolicy::max_asymmetric_key_length() const
{
  return mInner->max_asymmetric_key_length();
}

ua::AsymmetricEncryptionAlgorithm FuzzSecurityPolicy::asymmetric_encryption_algorithm() const
{
  return mInner->asymmetric_encryption_algorithm();
}

ua::AsymmetricSignatureAlgorithm FuzzSecurityPolicy::asymmetric_signature_algorithm() const
{
  return mInner->asymmetric_signature_algorithm();
}

ua::String FuzzSecurityPolicy::asymmetric_signature_algorithm_uri() const
{
  return mInner->asymmetric_signature_algorithm_uri();
}

ua::SymmetricEncryptionAlgorithm FuzzSecurityPolicy::symmetric_encryption_algorithm() const
{
  return mInner->symmetric_encryption_algorithm();
}

ua::SymmetricSignatureAlgorithm FuzzSecurityPolicy::symmetric_signature_algorithm() const
{
  return mInner->symmetric_signature_algorithm();
}

// --- Core operations ---

void FuzzSecurityPolicy::decode_message_chunk_async(std::shared_ptr<ua::SecureChannelContext> context,
  ua::ByteString messageChunk, std::function<void(ua::DecodedMessageChunkResult)> callback) const
{
  mInner->decode_message_chunk_async(std::move(context), std::move(messageChunk), std::move(callback));
}

void FuzzSecurityPolicy::encode_message_async(std::shared_ptr<ua::SecureChannelContext> context,
  uint32_t requestId, std::shared_ptr<ua::Structure> message, SendMessageChunk sendMessageChunk,
  std::function<void(ua::VoidResult)> callback) const
{
  if (mInterceptor)
  {
    auto interceptor = mInterceptor;
    auto wrappedSend = [interceptor = std::move(interceptor), sendMessageChunk = std::move(sendMessageChunk)](
                         ua::ByteString chunk)
    {
      auto mutated = interceptor(std::move(chunk));
      sendMessageChunk(std::move(mutated));
    };
    mInner->encode_message_async(
      std::move(context), requestId, std::move(message), std::move(wrappedSend), std::move(callback));
  }
  else
  {
    mInner->encode_message_async(
      std::move(context), requestId, std::move(message), std::move(sendMessageChunk), std::move(callback));
  }
}

void FuzzSecurityPolicy::derive_symmetric_keys_async(std::shared_ptr<ua::SecureChannelContext> context,
  ua::ByteString localNonce, ua::ByteString remoteNonce, ua::ChannelRole role,
  std::function<void(ua::SecurityPolicy::DeriveSymmetricKeysResult)> callback) const
{
  mInner->derive_symmetric_keys_async(
    std::move(context), std::move(localNonce), std::move(remoteNonce), role, std::move(callback));
}

}  // namespace opcua_fuzzer
