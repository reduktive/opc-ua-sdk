// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_FAKE_ASYNC_SECURITY_POLICY_H
#define UA_TEST_HELPERS_FAKE_ASYNC_SECURITY_POLICY_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "ua_byte_string.h"
#include "ua_crypto_types.h"
#include "ua_security_policy.h"
#include "ua_status_code.h"

namespace ua::test_helpers
{

/// Parked-callback variant of `SecurityPolicy`.
///
/// Each of the three async operations parks the user callback in an internal
/// queue. The test then fires `complete_pending_<op>(idx, value)` to invoke
/// the parked callback with the supplied value.
///
/// Sync getters forward to a real `SecurityPolicy::create(SecurityPolicyId::None)`
/// underlying.
class FakeAsyncSecurityPolicy final : public ua::SecurityPolicy
{
public:
  using DecodedChunk = ua::optional<std::pair<std::uint32_t, ua::ByteString>>;
  using DerivedKeysPair = std::pair<ua::SecurityToken::Keys, ua::SecurityToken::Keys>;

  static std::shared_ptr<FakeAsyncSecurityPolicy> create();

  // --- Async overrides - parked ---

  void decode_message_chunk_async(std::shared_ptr<ua::SecureChannelContext> context,
    ua::ByteString messageChunk, std::function<void(ua::DecodedMessageChunkResult)> callback) const override;

  void encode_message_async(std::shared_ptr<ua::SecureChannelContext> context, std::uint32_t requestId,
    std::shared_ptr<ua::Structure> message, SendMessageChunk sendMessageChunk,
    std::function<void(ua::VoidResult)> callback) const override;

  void derive_symmetric_keys_async(std::shared_ptr<ua::SecureChannelContext> context,
    ua::ByteString localNonce, ua::ByteString remoteNonce, ua::ChannelRole role,
    std::function<void(ua::SecurityPolicy::DeriveSymmetricKeysResult)> callback) const override;

  // --- Sync getters - forward to underlying ---

  ua::SecurityPolicyId id() const override;
  ua::String uri() const override;
  ua::CertificateType certificate_type() const override;
  bool is_authenticated() const override;
  bool is_rsa() const override;
  bool is_ecc() const override;

  // A fake places no requirement on a certificate (the None policy's answer).
  ua::VoidResult check_certificate_compliance(
    const ua::X509Certificate&, const ua::X509Certificate&, ua::CertificateChainPosition) const override
  {
    return {};
  }

  std::size_t nonce_length() const override;
  std::size_t symmetric_plaintext_block_size() const override;
  std::size_t asymmetric_plaintext_block_size(const ua::X509Certificate* certificate) const override;
  std::size_t symmetric_ciphertext_block_size() const override;
  std::size_t asymmetric_ciphertext_block_size(const ua::X509Certificate* certificate) const override;
  std::size_t symmetric_signature_size() const override;
  std::size_t asymmetric_signature_size(const ua::X509Certificate* certificate) const override;
  std::size_t symmetric_signature_key_size() const override;
  std::size_t symmetric_encryption_key_size() const override;
  std::size_t symmetric_iv_size() const override;
  std::size_t min_asymmetric_key_length() const override;
  std::size_t max_asymmetric_key_length() const override;
  ua::AsymmetricEncryptionAlgorithm asymmetric_encryption_algorithm() const override;
  ua::AsymmetricSignatureAlgorithm asymmetric_signature_algorithm() const override;
  ua::String asymmetric_signature_algorithm_uri() const override;
  ua::SymmetricEncryptionAlgorithm symmetric_encryption_algorithm() const override;
  ua::SymmetricSignatureAlgorithm symmetric_signature_algorithm() const override;

  // --- Pending-completion API ---

  std::size_t pending_decode_message_chunk_count() const;
  std::size_t pending_encode_message_count() const;
  std::size_t pending_derive_symmetric_keys_count() const;

  /// Resume the idx-th parked decode_message_chunk Task with the given value.
  void complete_pending_decode_message_chunk(std::size_t idx, DecodedChunk value);

  /// Resume the idx-th parked encode_message Task. The Task return type is
  /// `Task<void>`, so completion takes no value.
  void complete_pending_encode_message(std::size_t idx);

  /// Resume the idx-th parked encode_message Task with a BAD VoidResult carrying the given StatusCode
  /// and ErrorDetail. Models a client-side message-encode failure so tests can drive
  /// SecureChannelImpl::on_message_encoded's failure branch (CL-UASC-020) deterministically.
  void fail_pending_encode_message(
    std::size_t idx, ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail);

  /// Resume the idx-th parked derive_symmetric_keys Task with the given pair.
  void complete_pending_derive_symmetric_keys(std::size_t idx, DerivedKeysPair value);

private:
  FakeAsyncSecurityPolicy();

  using DecodeCompletion = std::function<void(ua::DecodedMessageChunkResult)>;
  using EncodeCompletion = std::function<void(ua::VoidResult)>;
  using DeriveCompletion = std::function<void(ua::SecurityPolicy::DeriveSymmetricKeysResult)>;

  std::shared_ptr<ua::SecurityPolicy> mUnderlying;
  mutable std::mutex mMutex;
  mutable std::vector<DecodeCompletion> mDecodeMessageChunk;
  mutable std::vector<EncodeCompletion> mEncodeMessage;
  mutable std::vector<DeriveCompletion> mDeriveSymmetricKeys;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_FAKE_ASYNC_SECURITY_POLICY_H
