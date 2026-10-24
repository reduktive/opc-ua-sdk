// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_async_security_policy.h"

#include <stdexcept>
#include <string>
#include <utility>

namespace ua::test_helpers
{

std::shared_ptr<FakeAsyncSecurityPolicy> FakeAsyncSecurityPolicy::create()
{
  return std::shared_ptr<FakeAsyncSecurityPolicy>(new FakeAsyncSecurityPolicy());
}

FakeAsyncSecurityPolicy::FakeAsyncSecurityPolicy()
  : mUnderlying(ua::SecurityPolicy::create(ua::SecurityPolicyId::None))
{}

// ---------------------------------------------------------------------------
// Async overrides - park the callback for the test to fire.
// ---------------------------------------------------------------------------

void FakeAsyncSecurityPolicy::decode_message_chunk_async(
  std::shared_ptr<ua::SecureChannelContext> /*context*/, ua::ByteString /*messageChunk*/,
  std::function<void(ua::DecodedMessageChunkResult)> callback) const
{
  std::lock_guard<std::mutex> lock(mMutex);
  mDecodeMessageChunk.push_back(std::move(callback));
}

void FakeAsyncSecurityPolicy::encode_message_async(std::shared_ptr<ua::SecureChannelContext> /*context*/,
  std::uint32_t /*requestId*/, std::shared_ptr<ua::Structure> /*message*/,
  SendMessageChunk /*sendMessageChunk*/, std::function<void(ua::VoidResult)> callback) const
{
  std::lock_guard<std::mutex> lock(mMutex);
  mEncodeMessage.push_back(std::move(callback));
}

void FakeAsyncSecurityPolicy::derive_symmetric_keys_async(
  std::shared_ptr<ua::SecureChannelContext> /*context*/, ua::ByteString /*localNonce*/,
  ua::ByteString /*remoteNonce*/, ua::ChannelRole /*role*/,
  std::function<void(ua::SecurityPolicy::DeriveSymmetricKeysResult)> callback) const
{
  std::lock_guard<std::mutex> lock(mMutex);
  mDeriveSymmetricKeys.push_back(std::move(callback));
}

// ---------------------------------------------------------------------------
// Sync overrides - forward to underlying real policy.
// ---------------------------------------------------------------------------

ua::SecurityPolicyId FakeAsyncSecurityPolicy::id() const
{
  return mUnderlying->id();
}

ua::String FakeAsyncSecurityPolicy::uri() const
{
  return mUnderlying->uri();
}

ua::CertificateType FakeAsyncSecurityPolicy::certificate_type() const
{
  return mUnderlying->certificate_type();
}

bool FakeAsyncSecurityPolicy::is_authenticated() const
{
  return mUnderlying->is_authenticated();
}

bool FakeAsyncSecurityPolicy::is_rsa() const
{
  return mUnderlying->is_rsa();
}

bool FakeAsyncSecurityPolicy::is_ecc() const
{
  return mUnderlying->is_ecc();
}

std::size_t FakeAsyncSecurityPolicy::nonce_length() const
{
  return mUnderlying->nonce_length();
}

std::size_t FakeAsyncSecurityPolicy::symmetric_plaintext_block_size() const
{
  return mUnderlying->symmetric_plaintext_block_size();
}

std::size_t FakeAsyncSecurityPolicy::asymmetric_plaintext_block_size(
  const ua::X509Certificate* certificate) const
{
  return mUnderlying->asymmetric_plaintext_block_size(certificate);
}

std::size_t FakeAsyncSecurityPolicy::symmetric_ciphertext_block_size() const
{
  return mUnderlying->symmetric_ciphertext_block_size();
}

std::size_t FakeAsyncSecurityPolicy::asymmetric_ciphertext_block_size(
  const ua::X509Certificate* certificate) const
{
  return mUnderlying->asymmetric_ciphertext_block_size(certificate);
}

std::size_t FakeAsyncSecurityPolicy::symmetric_signature_size() const
{
  return mUnderlying->symmetric_signature_size();
}

std::size_t FakeAsyncSecurityPolicy::asymmetric_signature_size(const ua::X509Certificate* certificate) const
{
  return mUnderlying->asymmetric_signature_size(certificate);
}

std::size_t FakeAsyncSecurityPolicy::symmetric_signature_key_size() const
{
  return mUnderlying->symmetric_signature_key_size();
}

std::size_t FakeAsyncSecurityPolicy::symmetric_encryption_key_size() const
{
  return mUnderlying->symmetric_encryption_key_size();
}

std::size_t FakeAsyncSecurityPolicy::symmetric_iv_size() const
{
  return mUnderlying->symmetric_iv_size();
}

std::size_t FakeAsyncSecurityPolicy::min_asymmetric_key_length() const
{
  return mUnderlying->min_asymmetric_key_length();
}

std::size_t FakeAsyncSecurityPolicy::max_asymmetric_key_length() const
{
  return mUnderlying->max_asymmetric_key_length();
}

ua::AsymmetricEncryptionAlgorithm FakeAsyncSecurityPolicy::asymmetric_encryption_algorithm() const
{
  return mUnderlying->asymmetric_encryption_algorithm();
}

ua::AsymmetricSignatureAlgorithm FakeAsyncSecurityPolicy::asymmetric_signature_algorithm() const
{
  return mUnderlying->asymmetric_signature_algorithm();
}

ua::String FakeAsyncSecurityPolicy::asymmetric_signature_algorithm_uri() const
{
  return mUnderlying->asymmetric_signature_algorithm_uri();
}

ua::SymmetricEncryptionAlgorithm FakeAsyncSecurityPolicy::symmetric_encryption_algorithm() const
{
  return mUnderlying->symmetric_encryption_algorithm();
}

ua::SymmetricSignatureAlgorithm FakeAsyncSecurityPolicy::symmetric_signature_algorithm() const
{
  return mUnderlying->symmetric_signature_algorithm();
}

// ---------------------------------------------------------------------------
// Pending-completion API.
// ---------------------------------------------------------------------------

std::size_t FakeAsyncSecurityPolicy::pending_decode_message_chunk_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDecodeMessageChunk.size();
}

std::size_t FakeAsyncSecurityPolicy::pending_encode_message_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mEncodeMessage.size();
}

std::size_t FakeAsyncSecurityPolicy::pending_derive_symmetric_keys_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDeriveSymmetricKeys.size();
}

void FakeAsyncSecurityPolicy::complete_pending_decode_message_chunk(std::size_t idx, DecodedChunk value)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mDecodeMessageChunk.size())
    throw std::out_of_range("FakeAsyncSecurityPolicy: pending decode_message_chunk index out of range");
  auto cb = std::move(mDecodeMessageChunk[idx]);
  mDecodeMessageChunk.erase(mDecodeMessageChunk.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  cb(ua::DecodedMessageChunkResult{std::move(value)});
}

void FakeAsyncSecurityPolicy::complete_pending_encode_message(std::size_t idx)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mEncodeMessage.size())
    throw std::out_of_range("FakeAsyncSecurityPolicy: pending encode_message index out of range");
  auto cb = std::move(mEncodeMessage[idx]);
  mEncodeMessage.erase(mEncodeMessage.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  cb(ua::VoidResult{});
}

void FakeAsyncSecurityPolicy::fail_pending_encode_message(
  std::size_t idx, ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mEncodeMessage.size())
    throw std::out_of_range("FakeAsyncSecurityPolicy: pending encode_message index out of range");
  auto cb = std::move(mEncodeMessage[idx]);
  mEncodeMessage.erase(mEncodeMessage.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  cb(ua::VoidResult{status, std::move(detail)});
}

void FakeAsyncSecurityPolicy::complete_pending_derive_symmetric_keys(std::size_t idx, DerivedKeysPair value)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mDeriveSymmetricKeys.size())
    throw std::out_of_range("FakeAsyncSecurityPolicy: pending derive_symmetric_keys index out of range");
  auto cb = std::move(mDeriveSymmetricKeys[idx]);
  mDeriveSymmetricKeys.erase(mDeriveSymmetricKeys.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  cb(ua::SecurityPolicy::DeriveSymmetricKeysResult{std::move(value)});
}

}  // namespace ua::test_helpers
