// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_security_policy.h"
#include "ua_certificate_validation_paths.h"
#include "ua_callback_safety.h"
#include "ua_security_policy_internal.h"
#include "ua_security_policy_test_access.h"
#include "ua_error_detail.h"
#include "ua_to_result.h"
#include "ua_sec_pol_basic128_rsa15.h"
#include "ua_sec_pol_basic256.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_sec_pol_aes128_sha256_rsa_oaep.h"
#include "ua_sec_pol_aes256_sha256_rsa_pss.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "ua_connection_protocol_limits.h"
#include "ua_application_configuration.h"
#include "ua_close_secure_channel_request.h"
#include "ua_memory_stream.h"
#include "ua_null_stream.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_sec_pol_none.h"
#include "ua_secure_channel_context.h"
#include "ua_structure_factory.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include "fmt/format.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

namespace ua
{

using namespace stack_utils;

namespace
{

constexpr std::array supportedPolicyIds{SecurityPolicyId::None,
  SecurityPolicyId::Basic128Rsa15,
  SecurityPolicyId::Basic256,
  SecurityPolicyId::Basic256Sha256,
  SecurityPolicyId::Aes128Sha256RsaOaep,
  SecurityPolicyId::Aes256Sha256RsaPss,
  SecurityPolicyId::EccNistP256AesGcm,
  SecurityPolicyId::EccNistP256ChaChaPoly,
  SecurityPolicyId::EccNistP384AesGcm,
  SecurityPolicyId::EccNistP384ChaChaPoly,
  SecurityPolicyId::EccBrainpoolP256r1AesGcm,
  SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
  SecurityPolicyId::EccBrainpoolP384r1AesGcm,
  SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
  SecurityPolicyId::EccCurve25519AesGcm,
  SecurityPolicyId::EccCurve25519ChaChaPoly,
  SecurityPolicyId::EccCurve448AesGcm,
  SecurityPolicyId::EccCurve448ChaChaPoly,
  SecurityPolicyId::RsaDhAesGcm,
  SecurityPolicyId::RsaDhChaChaPoly};

}  // namespace

bool SecurityPolicy::uses_legacy_sequence_no() const
{
  return false;
}

bool SecurityPolicy::is_deprecated() const
{
  return false;
}

EphemeralKeyAlgorithm SecurityPolicy::ephemeral_key_algorithm() const
{
  return EphemeralKeyAlgorithm::Invalid;
}

bool SecurityPolicy::secure_channel_enhancements() const
{
  return false;
}

HashAlgorithm SecurityPolicy::certificate_thumbprint_algorithm() const
{
  return HashAlgorithm::Invalid;
}

shared_ptr<SecurityPolicy> SecurityPolicy::create(SecurityPolicyId id)
{
  switch (id)
  {
  case SecurityPolicyId::None:
    return make_shared<SecPolNone>();

  case SecurityPolicyId::Basic128Rsa15:
    return make_unique<SecPolBasic128Rsa15>();

  case SecurityPolicyId::Basic256:
    return make_unique<SecPolBasic256>();

  case SecurityPolicyId::Basic256Sha256:
    return make_shared<SecPolBasic256Sha256>();

  case SecurityPolicyId::Aes128Sha256RsaOaep:
    return make_unique<SecPolAes128Sha256RsaOaep>();

  case SecurityPolicyId::Aes256Sha256RsaPss:
    return make_unique<SecPolAes256Sha256RsaPss>();

  default:
    if (const auto* row = find_ephemeral_key_policy(id))
    {
      return make_shared<SecPolEphemeralKey>(*row);
    }
    throw UaException{Status::BadInvalidArgument,
      make_error_detail("InvalidSecurityPolicy", "Invalid SecurityPolicyId", "SecurityPolicy")};
  }
}

span<const SecurityPolicyId> SecurityPolicy::supported_policy_ids() noexcept
{
  return supportedPolicyIds;
}

int security_policy_tier(SecurityPolicyId id) noexcept
{
  // Exhaustive and without a default, so GCC and Clang (-Wswitch) flag a policy id that is not ranked.
  switch (id)
  {
  case SecurityPolicyId::Invalid:
  case SecurityPolicyId::None:
  case SecurityPolicyId::Basic128Rsa15:
  case SecurityPolicyId::Basic256:
  case SecurityPolicyId::PubSubAes128Ctr:
  case SecurityPolicyId::PubSubAes256Ctr:
    return 0;
  case SecurityPolicyId::Basic256Sha256:
    return 1;
  case SecurityPolicyId::Aes128Sha256RsaOaep:
    return 2;
  case SecurityPolicyId::Aes256Sha256RsaPss:
    return 3;
  case SecurityPolicyId::EccNistP256AesGcm:
  case SecurityPolicyId::EccNistP256ChaChaPoly:
    return 4;
  case SecurityPolicyId::EccBrainpoolP256r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly:
  case SecurityPolicyId::RsaDhAesGcm:
  case SecurityPolicyId::RsaDhChaChaPoly:
    return 5;
  case SecurityPolicyId::EccCurve25519AesGcm:
  case SecurityPolicyId::EccCurve25519ChaChaPoly:
    return 6;
  case SecurityPolicyId::EccNistP384AesGcm:
  case SecurityPolicyId::EccNistP384ChaChaPoly:
    return 7;
  case SecurityPolicyId::EccBrainpoolP384r1AesGcm:
  case SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly:
    return 8;
  case SecurityPolicyId::EccCurve448AesGcm:
  case SecurityPolicyId::EccCurve448ChaChaPoly:
    return 9;
  }
  return 0;
}

uint8_t compute_security_level(MessageSecurityMode mode, SecurityPolicyId policy)
{
  if (mode != MessageSecurityMode::Sign && mode != MessageSecurityMode::SignAndEncrypt)
    return 0;
  const int tier = security_policy_tier(policy);
  if (tier == 0)
    return 0;
  // Sign: 5 + 5 * tier (10 to 50); SignAndEncrypt: 50 + 5 * tier (55 to 95). Every SignAndEncrypt endpoint
  // outranks every Sign endpoint.
  const int base = mode == MessageSecurityMode::SignAndEncrypt ? 50 : 5;
  return numeric_cast<uint8_t>(base + 5 * tier);
}

shared_ptr<SecurityPolicy> SecurityPolicy::create(string_view uri)
{
  const String input{uri};

  if (input == SecPolNone{}.uri())
  {
    return make_shared<SecPolNone>();
  }
  else if (input == SecPolBasic128Rsa15{}.uri())
  {
    return make_unique<SecPolBasic128Rsa15>();
  }
  else if (input == SecPolBasic256{}.uri())
  {
    return make_unique<SecPolBasic256>();
  }
  else if (input == SecPolBasic256Sha256{}.uri())
  {
    return make_shared<SecPolBasic256Sha256>();
  }
  else if (input == SecPolAes128Sha256RsaOaep{}.uri())
  {
    return make_unique<SecPolAes128Sha256RsaOaep>();
  }
  else if (input == SecPolAes256Sha256RsaPss{}.uri())
  {
    return make_unique<SecPolAes256Sha256RsaPss>();
  }
  else if (const auto* row = find_ephemeral_key_policy(uri))
  {
    return make_shared<SecPolEphemeralKey>(*row);
  }
  else
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidSecurityPolicy", "Unrecognized security policy URI", "SecurityPolicy")
        .context(ua::ContextKeys::uri, std::string{uri})};
  }
}

namespace
{

class AsymmetricDecryptOperation final : public ua::async::SelfOwningOperation<AsymmetricDecryptOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> cipherText, ByteString plainTextBuffer, size_t blockSize, size_t iterations,
    size_t headerSize, std::function<void(ByteStringResult)> callback)
  {
    launch(std::make_shared<AsymmetricDecryptOperation>(std::move(policy),
      context,
      cipherText,
      std::move(plainTextBuffer),
      blockSize,
      iterations,
      headerSize,
      std::move(callback)));
  }

  AsymmetricDecryptOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> cipherText, ByteString plainTextBuffer, size_t blockSize, size_t iterations,
    size_t headerSize, std::function<void(ByteStringResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mCipherText(cipherText), mPlainTextBuffer(std::move(plainTextBuffer)), mCiphertextBlockSize(blockSize),
      mIterations(iterations), mPlaintextOffset(headerSize), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<AsymmetricDecryptOperation>;

  /// One RSA block at a time, in a loop. The chain this replaces recursed - the completion of block
  /// i called the start of block i+1 directly, with no post between them - so a message of N blocks
  /// grew the stack N frames deep on whatever thread the crypto answered on. `await_step` posts, so
  /// each block is now its own strand turn: bounded stack and a bounded turn (R4, R18).
  ua::async::Task<> run()
  {
    try
    {
      for (size_t i = 0; i < mIterations; ++i)
      {
        auto blockResult = co_await await_step<Crypto::ByteSpanResult>(
          [this, i](auto completion)
          {
            mContext.crypto->asymmetric_decrypt_async(mPolicy,
              mPolicy->asymmetric_encryption_algorithm(),
              mContext.localKeyPair,
              utils::safe_sub_span(mCipherText, mCiphertextBlockSize * i, mCiphertextBlockSize),
              utils::safe_sub_span(span<byte>{mPlainTextBuffer}, mPlaintextOffset, mCiphertextBlockSize),
              std::move(completion));
          });
        // One code for every asymmetric decrypt failure (B2-4), an Uncertain answer included: the
        // primitive's own status would tell the peer which step refused it. The detail keeps the cause
        // for the log.
        if (blockResult.is_uncertain())
        {
          answer(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed,
            ua::security_internal::uncertain_answer_detail(blockResult.status_code(), "SecurityPolicy")}});
          co_return;
        }
        if (!blockResult.is_good())
        {
          answer(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
            ErrorDetail::build("CryptoOperationFailed", "Asymmetric decrypt failed", "SecurityPolicy")
              .context(ua::ContextKeys::index, std::to_string(i + 1))
              .context(ua::ContextKeys::countTotal, std::to_string(mIterations))
              .cause(blockResult.status_code())});
          co_return;
        }
        mPlaintextOffset += blockResult.value().size();
      }

      mPlainTextBuffer.resize(mPlaintextOffset);
      answer(ByteStringResult{std::move(mPlainTextBuffer)});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      // As above: whatever the primitive threw, the peer sees Bad_SecurityChecksFailed (B2-4).
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger,
        [&]
        {
          answer(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
            ErrorDetail::build("CryptoOperationFailed", "Asymmetric decrypt failed", "SecurityPolicy")
              .cause(failure)});
        })();
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(ByteStringResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(ByteStringResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;  // caller-owned; outlives the operation per contract
  span<const byte> mCipherText;  // view into the caller-owned messageChunk
  ByteString mPlainTextBuffer;  // owns output storage, moved into the final Result
  size_t mCiphertextBlockSize;
  size_t mIterations;
  size_t mPlaintextOffset;  // grows as blocks decrypt
  std::function<void(ByteStringResult)> mCallback;
};

}  // namespace

void SecurityPolicy::asymmetric_decrypt_async(SecureChannelContext& context, span<const byte> messageChunk,
  size_t sequenceHeaderOffset, std::function<void(ByteStringResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    const span<const byte> chunk{messageChunk};
    const span<const byte> header = utils::safe_sub_span(chunk, 0, sequenceHeaderOffset);
    const span<const byte> cipherText =
      utils::safe_sub_span(chunk, sequenceHeaderOffset, chunk.size() - header.size());

    auto ciphertextBlockSize = asymmetric_ciphertext_block_size(context.localCertificate.get());
    if (cipherText.size() % ciphertextBlockSize)
    {
      callback(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
        ErrorDetail::build("CryptoOperationFailed",
          "Asymmetric ciphertext size is not a multiple of block size",
          "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(cipherText.size()))
          .context(ua::ContextKeys::sizeBlock, std::to_string(ciphertextBlockSize))});
      return;
    }
    auto iterations = cipherText.size() / ciphertextBlockSize;

    ByteString plainTextBuffer;
    plainTextBuffer.resize(header.size() + ciphertextBlockSize * iterations);
    std::memcpy(plainTextBuffer.data(), header.data(), header.size());

    if (iterations == 0)
    {
      // No ciphertext blocks: return only the (already-copied) header bytes.
      plainTextBuffer.resize(header.size());
      callback(ByteStringResult{std::move(plainTextBuffer)});
      return;
    }

    started = true;
    AsymmetricDecryptOperation::start(shared_from_this(),
      context,
      cipherText,
      std::move(plainTextBuffer),
      ciphertextBlockSize,
      iterations,
      header.size(),
      std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(ByteStringResult{er, er.shared_detail()});
    }
  }
}

namespace
{

class AsymmetricEncryptOperation final : public ua::async::SelfOwningOperation<AsymmetricEncryptOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> plaintext, span<byte> ciphertext, size_t plaintextBlockSize, size_t ciphertextBlockSize,
    size_t iterations, std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<AsymmetricEncryptOperation>(std::move(policy),
      context,
      plaintext,
      ciphertext,
      plaintextBlockSize,
      ciphertextBlockSize,
      iterations,
      std::move(callback)));
  }

  AsymmetricEncryptOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> plaintext, span<byte> ciphertext, size_t plaintextBlockSize, size_t ciphertextBlockSize,
    size_t iterations, std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mPlaintext(plaintext), mCiphertext(ciphertext), mPlaintextBlockSize(plaintextBlockSize),
      mCiphertextBlockSize(ciphertextBlockSize), mIterations(iterations), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<AsymmetricEncryptOperation>;

  /// The encrypt twin of @ref AsymmetricDecryptOperation, and the same shape: one RSA block per
  /// turn, in a loop, where the chain recursed from each completion into the next start with no
  /// post between them.
  ua::async::Task<> run()
  {
    try
    {
      for (size_t i = 0; i < mIterations; ++i)
      {
        auto blockResult = co_await await_step<VoidResult>(
          [this, i](auto completion)
          {
            mContext.crypto->asymmetric_encrypt_async(mPolicy,
              mPolicy->asymmetric_encryption_algorithm(),
              mContext.remoteCertificate->public_key(),
              utils::safe_sub_span(mPlaintext, mPlaintextBlockSize * i, mPlaintextBlockSize),
              utils::safe_sub_span(mCiphertext, mCiphertextBlockSize * i, mCiphertextBlockSize),
              std::move(completion));
          });
        if (blockResult.is_uncertain())
        {
          answer(VoidResult{StatusCode{Status::BadInternalError,
            ua::security_internal::uncertain_answer_detail(blockResult.status_code(), "SecurityPolicy")}});
          co_return;
        }
        if (!blockResult.is_good())
        {
          answer(VoidResult{blockResult.status_code(),
            ErrorDetail::build("EncryptionFailed", "Asymmetric encryption failed", "SecurityPolicy")
              .context(ua::ContextKeys::index, std::to_string(i + 1))
              .context(ua::ContextKeys::countTotal, std::to_string(mIterations))
              .cause(blockResult.status_code())});
          co_return;
        }
      }

      answer(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(VoidResult{failure, failure.shared_detail()}); })();
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(VoidResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;  // caller-owned; outlives the operation per contract
  span<const byte> mPlaintext;  // caller-owned view
  span<byte> mCiphertext;  // caller-owned view (output buffer)
  size_t mPlaintextBlockSize;
  size_t mCiphertextBlockSize;
  size_t mIterations;
  std::function<void(VoidResult)> mCallback;
};

}  // namespace

void SecurityPolicy::asymmetric_encrypt_async(SecureChannelContext& context, span<const byte> plaintext,
  span<byte> ciphertext, std::function<void(VoidResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    check_true(!plaintext.empty(), Status::BadInvalidArgument);
    check_true(!ciphertext.empty(), Status::BadInvalidArgument);

    auto plaintextBlockSize = asymmetric_plaintext_block_size(context.remoteCertificate.get());
    auto ciphertextBlockSize = asymmetric_ciphertext_block_size(context.remoteCertificate.get());

    check_true((plaintext.size() % plaintextBlockSize == 0), Status::BadInvalidArgument);
    check_true((ciphertext.size() % ciphertextBlockSize == 0), Status::BadInvalidArgument);

    auto iterations = plaintext.size() / plaintextBlockSize;

    started = true;
    AsymmetricEncryptOperation::start(shared_from_this(),
      context,
      plaintext,
      ciphertext,
      plaintextBlockSize,
      ciphertextBlockSize,
      iterations,
      std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

void SecurityPolicy::symmetric_decrypt_async(SecureChannelContext& context, const SecurityToken::Keys& keys,
  span<const byte> messageChunk, size_t sequenceHeaderOffset,
  std::function<void(ByteStringResult)> callback) const
{
  try
  {
    const span<const byte> chunk{messageChunk};
    const span<const byte> header = utils::safe_sub_span(chunk, 0, sequenceHeaderOffset);
    const span<const byte> cipherText =
      utils::safe_sub_span(chunk, header.size(), chunk.size() - header.size());

    auto ciphertextBlockSize = symmetric_ciphertext_block_size();
    if (cipherText.size() % ciphertextBlockSize)
    {
      callback(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
        ErrorDetail::build("CryptoOperationFailed",
          "Symmetric ciphertext size is not a multiple of block size",
          "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(cipherText.size()))
          .context(ua::ContextKeys::sizeBlock, std::to_string(ciphertextBlockSize))});
      return;
    }

    ByteString plainTextBuffer;
    plainTextBuffer.resize(messageChunk.size());
    std::memcpy(plainTextBuffer.data(), header.data(), header.size());

    auto& iv = keys.initializationVector;
    auto& key = keys.encryptingKey;

    const span<byte> plainText = plainTextBuffer;
    auto output = utils::safe_sub_span(plainText, header.size(), cipherText.size());

    auto self = shared_from_this();
    auto algorithm = symmetric_encryption_algorithm();

    context.crypto->symmetric_decrypt_async(self,
      algorithm,
      iv,
      key,
      cipherText,
      output,
      [self, plainTextBuffer = std::move(plainTextBuffer), callback = std::move(callback)](
        VoidResult result) mutable
      {
        if (result.is_uncertain())
        {
          callback(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed,
            ua::security_internal::uncertain_answer_detail(result.status_code(), "SecurityPolicy")}});
          return;
        }
        if (!result.is_good())
        {
          callback(ByteStringResult{result.status_code(),
            ErrorDetail::build("CryptoOperationFailed", "Symmetric decrypt failed", "SecurityPolicy")
              .cause(result.status_code())});
          return;
        }
        callback(ByteStringResult{std::move(plainTextBuffer)});
      });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(ByteStringResult{er, er.shared_detail()});
  }
}

void SecurityPolicy::symmetric_encrypt_async(SecureChannelContext& context, span<const byte> plaintext,
  span<byte> ciphertext, std::function<void(VoidResult)> callback) const
{
  try
  {
    check_true(!plaintext.empty(), Status::BadInvalidArgument);
    check_true(!ciphertext.empty(), Status::BadInvalidArgument);

    check_true((plaintext.size() % symmetric_plaintext_block_size() == 0), Status::BadInvalidArgument);
    check_true((ciphertext.size() % symmetric_ciphertext_block_size() == 0), Status::BadInvalidArgument);

    check(context.activeSecurityToken);
    auto& keys = context.activeSecurityToken->local_keys();
    auto& iv = keys.initializationVector;
    auto& key = keys.encryptingKey;

    auto self = shared_from_this();
    auto algorithm = symmetric_encryption_algorithm();

    context.crypto->symmetric_encrypt_async(self,
      algorithm,
      iv,
      key,
      plaintext,
      ciphertext,
      [self, callback = std::move(callback)](VoidResult result) mutable
      {
        if (result.is_uncertain())
        {
          callback(VoidResult{StatusCode{Status::BadInternalError,
            ua::security_internal::uncertain_answer_detail(result.status_code(), "SecurityPolicy")}});
          return;
        }
        if (!result.is_good())
        {
          callback(VoidResult{result.status_code(),
            ErrorDetail::build(
              "EncryptionFailed", "Symmetric encryption failed for message response", "SecurityPolicy")
              .cause(result.status_code())});
          return;
        }
        callback(VoidResult{});
      });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(VoidResult{er, er.shared_detail()});
  }
}

size_t SecurityPolicy::append_padding(const EncodingLimits& limits, UaBinaryEncoder& encoder,
  size_t keyLengthInBits, size_t headerSize, size_t signatureSize, size_t plaintextBlockSize,
  size_t ciphertextBlockSize) const
{
  static constexpr size_t extraPaddingLimit{2048};
  const auto& stream = encoder.stream();

  size_t plaintextSize = stream.get_position() - headerSize + signatureSize + 1;
  bool extraPadding{false};
  if (keyLengthInBits > extraPaddingLimit)
  {
    plaintextSize++;
    extraPadding = true;
  }

  uint16_t padding{0};
  if (plaintextSize % plaintextBlockSize != 0)
  {
    padding = numeric_cast<uint16_t>(plaintextBlockSize - (plaintextSize % plaintextBlockSize));
  }

  const uint8_t paddingSize = numeric_cast<uint8_t>(padding);
  const uint8_t extraPaddingSize = numeric_cast<uint8_t>(padding >> 8);

  const StackDepth limit = limits.stack_depth();

  encoder.encode(limit, paddingSize);
  for (size_t i = 0; i < padding; ++i)
  {
    encoder.encode(limit, paddingSize);
  }

  if (extraPadding)
  {
    encoder.encode(limit, extraPaddingSize);
  }

  plaintextSize = stream.get_position() - headerSize + signatureSize;
  const size_t encryptedBlocks = plaintextSize / plaintextBlockSize;
  const uint32_t ciphertextSize = numeric_cast<uint32_t>(encryptedBlocks * ciphertextBlockSize);

  return ciphertextSize;
}

bool SecurityPolicy::is_encrypted(const SecureChannelContext& context) const
{
  return (context.messageSecurityMode == MessageSecurityMode::SignAndEncrypt);
}

namespace
{

/// The OPN receive path: validate the peer certificate, decrypt, verify, strip padding, decode.
///
/// The order matters and is now visible as three awaits in sequence: nothing is decrypted before the
/// certificate that signed it has been validated, and nothing is trusted before the signature over
/// it has been verified.
class DecodeAsymmetricOperation final : public ua::async::SelfOwningOperation<DecodeAsymmetricOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> messageChunk, UaScMessageHeader header, size_t cipherTextDecoderPosition,
    std::function<void(DecodedMessageChunkResult)> callback)
  {
    launch(std::make_shared<DecodeAsymmetricOperation>(
      std::move(policy), context, messageChunk, header, cipherTextDecoderPosition, std::move(callback)));
  }

  DecodeAsymmetricOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    span<const byte> messageChunk, UaScMessageHeader header, size_t cipherTextDecoderPosition,
    std::function<void(DecodedMessageChunkResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mMessageChunk(messageChunk), mHeader(header), mCipherTextDecoderPosition(cipherTextDecoderPosition),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecodeAsymmetricOperation>;

  ua::async::Task<> run()
  {
    try
    {
      if (!mPolicy->is_authenticated())
      {
        // Nothing to validate, decrypt or verify; the chunk is its own plaintext.
        mPlainTextBuffer.resize(mMessageChunk.size());
        std::memcpy(mPlainTextBuffer.data(), mMessageChunk.data(), mMessageChunk.size());
        mPlainText = mPlainTextBuffer;
        finalize();
        co_return;
      }

      auto validateResult = co_await await_step<VoidResult>(
        [this](auto completion) { mPolicy->validate_certificate_async(mContext, std::move(completion)); });
      if (validateResult.is_uncertain())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed,
          ua::security_internal::uncertain_answer_detail(validateResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!validateResult.is_good())
      {
        answer(DecodedMessageChunkResult{validateResult.status_code(),
          ErrorDetail::build("InvalidCertificate", "Remote certificate validation failed", "SecurityPolicy")
            .cause(validateResult.status_code())});
        co_return;
      }

      auto decryptResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mPolicy->asymmetric_decrypt_async(
            mContext, mMessageChunk, mCipherTextDecoderPosition, std::move(completion));
        });
      if (!decryptResult.is_good())
      {
        // The decrypt operation answers Bad_SecurityChecksFailed for every failure (B2-4); passed
        // through unchanged.
        answer(DecodedMessageChunkResult{ua::security_internal::not_good_answer(
          decryptResult.status_code(), Status::BadSecurityChecksFailed, "SecurityPolicy")});
        co_return;
      }
      mPlainTextBuffer = std::move(decryptResult).value();
      mPlainText = mPlainTextBuffer;

      // Strip the signature off the plaintext, then verify it over what is left.
      const auto signatureSize = mPolicy->asymmetric_signature_size(mContext.remoteCertificate.get());
      const span<const byte> signature =
        utils::safe_sub_span(mPlainText, mPlainText.size() - signatureSize, signatureSize);
      mPlainText = utils::safe_sub_span(mPlainText, 0, mPlainText.size() - signatureSize);

      auto verifyResult = co_await await_step<VoidResult>(
        [this, signature](auto completion)
        {
          mContext.crypto->asymmetric_verify_async(mPolicy,
            mPolicy->asymmetric_signature_algorithm(),
            mContext.remoteCertificate->public_key(),
            mPlainText,
            signature,
            std::move(completion));
        });
      if (verifyResult.is_uncertain())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadApplicationSignatureInvalid,
          ua::security_internal::uncertain_answer_detail(verifyResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!verifyResult.is_good())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadApplicationSignatureInvalid},
          ErrorDetail::build("CryptoOperationFailed",
            "Asymmetric signature verification failed in OPN message",
            "SecurityPolicy")
            .cause(verifyResult.status_code())});
        co_return;
      }

      // Strip padding (Part 6 6.7.2.5). After signature removal, plainText ends with:
      // ... [Body] [PaddingSize(1)] [Padding(PaddingSize bytes)] [ExtraPaddingSize if key>2048 bits]
      // The padding bytes are attacker-controlled on a forged/edge-case OPN, so validate the length
      // against the plaintext before indexing or subtracting - otherwise a bogus padding size makes the
      // size_t subtraction below underflow to a huge span length, which throws out of this strand handler
      // and terminates the server (a DoS-class bug; surfaced by the CTT Security CUs).
      // ExtraPaddingSize is present when the key the message was encrypted with exceeds 2048 bits (Part 6
      // 6.7.2.5). The sender encrypted to OUR public key, so it is our certificate's key that decides -
      // the sender's key size says nothing about it.
      const bool hasExtraPadding =
        mContext.localCertificate && mContext.localCertificate->public_key_bit_length() > 2048;
      const size_t paddingMetaBytes = hasExtraPadding ? 2 : 1;
      if (mPlainText.size() < paddingMetaBytes)
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build(
            "InvalidPadding", "Asymmetric plaintext too short to contain padding metadata", "SecurityPolicy")
            .context(ua::ContextKeys::sizeActual, std::to_string(mPlainText.size()))
            .context(ua::ContextKeys::sizeMin, std::to_string(paddingMetaBytes))});
        co_return;
      }

      uint16_t paddingSize{0};
      if (hasExtraPadding)
      {
        const auto extraPaddingByte = static_cast<uint8_t>(mPlainText[mPlainText.size() - 1]);
        const auto paddingSizeByte = static_cast<uint8_t>(mPlainText[mPlainText.size() - 2]);
        paddingSize = numeric_cast<uint16_t>((extraPaddingByte << 8) | paddingSizeByte);
      }
      else
      {
        paddingSize = static_cast<uint8_t>(mPlainText.back());
      }

      const auto totalPaddingOverhead = numeric_cast<size_t>(paddingSize) + 1 + (hasExtraPadding ? 1 : 0);
      if (totalPaddingOverhead > mPlainText.size())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build(
            "InvalidPadding", "Asymmetric padding size exceeds plaintext length", "SecurityPolicy")
            .context(ua::ContextKeys::sizeActual, std::to_string(totalPaddingOverhead))
            .context(ua::ContextKeys::sizeMax, std::to_string(mPlainText.size()))});
        co_return;
      }
      mPlainText = utils::safe_sub_span(mPlainText, 0, mPlainText.size() - totalPaddingOverhead);
      mPlainTextBuffer.resize(mPlainText.size());

      finalize();
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(
        mLogger, [&] { answer(DecodedMessageChunkResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Decode the sequence header, append this chunk's body, and answer once the message is whole.
  /// Throws on a decode failure; the body's own handler turns that into the caller's answer.
  void finalize()
  {
    optional<std::pair<uint32_t, ByteString>> result;

    memory_stream_device::ExternalReadOnly streamDevice{mPlainText};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder plainTextDecoder(StructureResolver{}, stream, mContext.encodingLimits);
    plainTextDecoder.stream().seek_from_start(mCipherTextDecoderPosition);

    SequenceHeader sequenceHeader;
    sequenceHeader.decode(mContext.encodingLimits, plainTextDecoder);
    mPolicy->check_sequence_header(mContext, sequenceHeader);

    mPolicy->copy_message_body(mContext, plainTextDecoder);

    if (mHeader.isFinal == UaScMessageHeader::IsFinal::Final)
    {
      result = std::make_pair(sequenceHeader.requestId, std::move(mContext.receivedMessageBody));
      mContext.receivedMessageBody.clear();
      mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
    }

    answer(DecodedMessageChunkResult{std::move(result)});
  }

  void fail_to_start(StatusCode status)
  {
    answer(DecodedMessageChunkResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(DecodedMessageChunkResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;  // caller-owned; outlives the operation per contract
  span<const byte> mMessageChunk;  // caller-owned view
  UaScMessageHeader mHeader;  // copy
  size_t mCipherTextDecoderPosition{0};  // captured after the security header decode
  ByteString mPlainTextBuffer;  // owned (used only when authenticated)
  span<const byte> mPlainText;  // view into mPlainTextBuffer or mMessageChunk
  std::function<void(DecodedMessageChunkResult)> mCallback;
};

}  // namespace

// decode_asymmetric_message_chunk flow:
//   decode_asymmetric_message_chunk_async
//     -> [!is_authenticated()] finalize_decode_asymmetric  (shortcut)
//     -> validate_certificate_async
//     -> on_decode_asymmetric_validate_cert_complete  [strand-guarded]
//     -> start_decode_asymmetric_decrypt
//     -> on_decode_asymmetric_decrypt_complete        [strand-guarded]
//     -> start_decode_asymmetric_verify
//     -> on_decode_asymmetric_verify_complete         [strand-guarded]
//     -> finalize_decode_asymmetric
//     -> complete_decode_asymmetric  |  fail_decode_asymmetric
//
// On any failure (cert validate, decrypt, verify, decode/padding): fail_decode_asymmetric.
void SecurityPolicy::decode_asymmetric_message_chunk_async(SecureChannelContext& context,
  UaBinaryDecoder& cipherTextDecoder, span<const byte> messageChunk,
  const stack_utils::UaScMessageHeader& header, std::function<void(DecodedMessageChunkResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    // An OpenSecureChannel message is one request with nothing to abort into; an OPN chunk marked
    // Abort is refused before the security header is decoded and before any certificate or key
    // work (B2-7). Appending its body silently and leaving the reassembly state behind was the
    // defect.
    if (header.isFinal == UaScMessageHeader::IsFinal::Aborted)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        make_error_detail("AbortChunkInOpenSecureChannel",
          "An OpenSecureChannel chunk marked Abort is not accepted",
          "SecurityPolicy")};
    }
    AsymmetricSecurityHeader securityHeader;
    // Part 6 section 6.7.2.3: the SenderCertificate with its chain fits one chunk; checked by the decode
    // before the chain is parsed.
    securityHeader.decode(context.encodingLimits,
      cipherTextDecoder,
      *context.crypto,
      size_t{context.negotiatedLimits.receiveBufferSize});

    if (String{securityHeader.securityPolicyUri} != uri())
    {
      callback(DecodedMessageChunkResult{StatusCode{Status::BadSecurityPolicyRejected},
        ErrorDetail::build(
          "InvalidSecurityPolicy", "Security policy URI does not match expected", "SecurityPolicy")
          .context(ua::ContextKeys::actual, std::string{securityHeader.securityPolicyUri})
          .context(ua::ContextKeys::expected, std::string{uri()})});
      return;
    }

    const size_t cipherTextDecoderPosition = cipherTextDecoder.stream().get_position();

    // Every check below is synchronous and reads `securityHeader`, a local of this function, so it
    // stays here rather than moving into the body - and answers through `callback`, which this
    // function still owns because the operation has not been started yet.
    if (is_authenticated())
    {
      if (!securityHeader.senderCertificate)
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadCertificateInvalid},
          make_error_detail("InvalidCertificate",
            "Sender certificate expected in authenticated security header",
            "SecurityPolicy")});
        return;
      }

      check(context.localCertificate);
      if (securityHeader.receiverCertificateThumbprint != context.localCertificate->thumbprint())
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadCertificateInvalid},
          // Part 6 6.7.6: "report a Bad_CertificateInvalid error if it does not recognize it". Its own code:
          // the server reports this refusal unmasked (owner decision D-d), unlike the other certificate
          // faults.
          ErrorDetail::build("ReceiverCertificateThumbprintUnknown",
            "Receiver certificate thumbprint does not match local certificate",
            "SecurityPolicy")
            .context(ua::ContextKeys::certificateThumbprint,
              utils::bytes_to_hex_string(context.localCertificate->thumbprint()))});
        return;
      }

      // Part 6 6.7.4: if the peer certificate is already known - the Client fixed it from GetEndpoints and
      // encrypted its OPN request to it (CL-SC-011), or a previous OPN established it - the certificate that
      // signed THIS chunk must match it. Only adopt the sender certificate when none is known yet (e.g. a
      // Server accepting a first OPN from an as-yet-unknown Client). Gating on the *presence* of a known
      // certificate rather than on channel state is essential: on the client's first OPN the channel is still
      // Uninitialised, yet the server certificate is already fixed, so a mismatched response signer must be
      // rejected rather than silently adopted.
      if (!context.remoteCertificate)
      {
        context.remoteCertificate = securityHeader.senderCertificate;
      }
      else if (!utils::compare(context.remoteCertificate, securityHeader.senderCertificate))
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadCertificateInvalid},
          make_error_detail("InvalidCertificate",
            "Certificate that signed the response does not match the expected peer certificate",
            "SecurityPolicy")});
        return;
      }
      // The chain the peer presented with this certificate (OPC 10000-6 6.2.6; decision 24) - also when
      // the certificate itself was already known, as on the client, which fixed it from GetEndpoints.
      context.remoteIssuerCertificates = std::move(securityHeader.issuerCertificates);
    }

    started = true;
    DecodeAsymmetricOperation::start(
      shared_from_this(), context, messageChunk, header, cipherTextDecoderPosition, std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DecodedMessageChunkResult{er, er.shared_detail()});
    }
  }
}

namespace
{

class DecodeSymmetricOperation final : public ua::async::SelfOwningOperation<DecodeSymmetricOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context, uint32_t tokenId,
    span<const byte> messageChunk, UaScMessageHeader header, size_t headerSize,
    std::function<void(DecodedMessageChunkResult)> callback)
  {
    launch(std::make_shared<DecodeSymmetricOperation>(
      std::move(policy), context, tokenId, messageChunk, header, headerSize, std::move(callback)));
  }

  DecodeSymmetricOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t tokenId, span<const byte> messageChunk, UaScMessageHeader header, size_t headerSize,
    std::function<void(DecodedMessageChunkResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mTokenId(tokenId), mMessageChunk(messageChunk), mHeader(header), mHeaderSize(headerSize),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecodeSymmetricOperation>;

  /// Decrypt (when encrypted), verify, strip padding, decode. The three channel shapes -
  /// unauthenticated, signed, signed-and-encrypted - are now one path with two conditionals rather
  /// than three entry points into the same chain.
  ua::async::Task<> run()
  {
    try
    {
      if (!mPolicy->is_authenticated())
      {
        // Nothing to decrypt and nothing to verify.
        mPlainText = mMessageChunk;
        finalize();
        co_return;
      }

      if (mPolicy->is_encrypted(mContext))
      {
        const auto* token = selected_token();
        if (!token)
        {
          answer_token_retired();
          co_return;
        }
        auto decryptResult = co_await await_step<ByteStringResult>(
          [this, token](auto completion)
          {
            mPolicy->symmetric_decrypt_async(
              mContext, token->remote_keys(), mMessageChunk, mHeaderSize, std::move(completion));
          });
        if (!decryptResult.is_good())
        {
          answer(DecodedMessageChunkResult{ua::security_internal::not_good_answer(
            decryptResult.status_code(), Status::BadSecurityChecksFailed, "SecurityPolicy")});
          co_return;
        }
        mPlainTextBuffer = std::move(decryptResult).value();
        mPlainText = mPlainTextBuffer;
      }
      else
      {
        mPlainText = mMessageChunk;
      }

      // Strip the signature off the plaintext, then verify it over what is left.
      const auto signatureSize = mPolicy->symmetric_signature_size();
      const span<const byte> signature =
        utils::safe_sub_span(mPlainText, mPlainText.size() - signatureSize, signatureSize);
      mPlainText = utils::safe_sub_span(mPlainText, 0, mPlainText.size() - signatureSize);

      // The keys are those of the token the chunk's TokenId selected, looked up again after the decrypt
      // suspension: a renewal may have moved it between active and pending, or retired it.
      const auto* token = selected_token();
      if (!token)
      {
        answer_token_retired();
        co_return;
      }

      auto verifyResult = co_await await_step<VoidResult>(
        [this, signature, token](auto completion)
        {
          mContext.crypto->symmetric_verify_async(mPolicy,
            mPolicy->symmetric_signature_algorithm(),
            token->remote_keys().signingKey,
            mPlainText,
            signature,
            std::move(completion));
        });
      if (verifyResult.is_uncertain())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadApplicationSignatureInvalid,
          ua::security_internal::uncertain_answer_detail(verifyResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!verifyResult.is_good())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadApplicationSignatureInvalid},
          ErrorDetail::build("CryptoOperationFailed",
            "Symmetric signature verification failed in MSG message",
            "SecurityPolicy")
            .cause(verifyResult.status_code())});
        co_return;
      }

      // Strip padding (Part 6 6.7.2.5). After signature removal, plainText ends with:
      // ... [Body] [PaddingSize(1)] [Padding(PaddingSize bytes)]
      // For symmetric, key length is always <= 2048 bits (AES-256 = 256 bits), so no ExtraPaddingSize.
      if (mPolicy->is_encrypted(mContext))
      {
        // The padding bytes are attacker-controlled on a forged/edge-case MSG, so validate lengths
        // against the plaintext BEFORE indexing or subtracting. The minimum-size guard makes .back()
        // safe and keeps the body-region arithmetic from underflowing: the original
        // `size() - headerSize - sizeInBytes` is an unchecked size_t subtraction that wraps to a huge
        // value for a too-short chunk, defeating the bounds check, then the safe_sub_span subtraction
        // below underflows and throws out of this strand handler - terminating the server. This is the
        // sibling of the asymmetric DoS hardened on 2026-06-08 (CTT Security CUs); same discipline here.
        const size_t minPlainText = mHeaderSize + SequenceHeader::sizeInBytes + 1;
        if (mPlainText.size() < minPlainText)
        {
          answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed},
            ErrorDetail::build(
              "InvalidPadding", "Symmetric plaintext too short to contain header + padding", "SecurityPolicy")
              .context(ua::ContextKeys::sizeActual, std::to_string(mPlainText.size()))
              .context(ua::ContextKeys::sizeMin, std::to_string(minPlainText))});
          co_return;
        }
        const auto paddingSize = numeric_cast<size_t>(static_cast<uint8_t>(mPlainText.back()));
        const auto totalPaddingOverhead = paddingSize + 1;  // +1 for the PaddingSize byte itself
        // Addition form (no size_t subtraction): the padding must fit AFTER the security + sequence
        // headers, i.e. headerSize + sizeInBytes + overhead <= plainText.size().
        if (mHeaderSize + SequenceHeader::sizeInBytes + totalPaddingOverhead > mPlainText.size())
        {
          answer(DecodedMessageChunkResult{StatusCode{Status::BadDecodingError},
            ErrorDetail::build("InvalidPadding", "Padding size exceeds available data", "SecurityPolicy")
              .context(ua::ContextKeys::sizeActual, std::to_string(paddingSize))
              .context(ua::ContextKeys::sizeMax, std::to_string(mPlainText.size()))});
          co_return;
        }
        mPlainText = utils::safe_sub_span(mPlainText, 0, mPlainText.size() - totalPaddingOverhead);
      }

      finalize();
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(
        mLogger, [&] { answer(DecodedMessageChunkResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Decode the sequence header, append this chunk's body, and answer once the message is whole.
  /// Throws on a decode failure; the body's own handler turns that into the caller's answer.
  void finalize()
  {
    optional<std::pair<uint32_t, ByteString>> result;

    memory_stream_device::ExternalReadOnly streamDevice{mPlainText};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder plainTextDecoder(StructureResolver{}, stream, mContext.encodingLimits);
    plainTextDecoder.stream().seek_from_start(mHeaderSize);

    SequenceHeader sequenceHeader;
    sequenceHeader.decode(mContext.encodingLimits, plainTextDecoder);
    mPolicy->check_sequence_header(mContext, sequenceHeader);
    // Recorded under the token this chunk selected, not whichever token is active by now: a renewal may
    // have replaced it while the verification was in flight.
    if (!SecureChannelContext::note_sequence_number_under_token(
          mContext.rxUseUnderToken, mTokenId, sequenceHeader.sequenceNumber))
    {
      // CRY-4 / Part 6 6.7.2.4: a sequence number reused under one token is a transport error.
      throw UaException{Status::BadSequenceNumberInvalid,
        make_error_detail("SequenceNumberReusedUnderToken",
          "The sequence number was reused under the current security token",
          "SecurityPolicy")};
    }

    // Offset at which THIS chunk's body starts within the accumulated buffer. For an abort chunk the
    // Error must be decoded from the abort chunk's OWN body (Part 6 6.7.3 - previous chunks are
    // discarded), not from the accumulated intermediate bytes.
    const size_t chunkBodyOffset = mContext.receivedMessageBody.size();
    mPolicy->copy_message_body(mContext, plainTextDecoder);

    if (mHeader.isFinal == UaScMessageHeader::IsFinal::Final)
    {
      result = std::make_pair(sequenceHeader.requestId, std::move(mContext.receivedMessageBody));
      mContext.receivedMessageBody.clear();
      mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
    }
    else if (mHeader.isFinal == UaScMessageHeader::IsFinal::Aborted)
    {
      // ABORT chunk (Part 6 6.7.3): the body carries {Error StatusCode, Reason}. Report the Error -
      // decoded from the abort chunk's OWN body (the bytes appended just now, from chunkBodyOffset) -
      // to the single request this abort targets via the channel context side-channel, DISCARD the
      // buffered message, and leave `result` EMPTY so the channel stays open (a bad Result would tear
      // the whole channel down, but the spec requires the abort to fail only the one request).
      const ua::span<const ua::byte> abortBody =
        ua::span<const ua::byte>{mContext.receivedMessageBody}.subspan(chunkBodyOffset);
      mContext.receivedAbort = std::make_pair(
        sequenceHeader.requestId, security_internal::decode_abort_error(abortBody, mContext.encodingLimits));
      mContext.receivedMessageBody.clear();
      mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
    }

    answer(DecodedMessageChunkResult{std::move(result)});
  }

  void fail_to_start(StatusCode status)
  {
    answer(DecodedMessageChunkResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(DecodedMessageChunkResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  /// The token the chunk's TokenId selected, wherever a renewal has moved it since: active, pending, or
  /// (client) the retired token still accepted for receiving. Null once it is gone. Three id comparisons;
  /// nothing is copied.
  const SecurityToken* selected_token() const
  {
    if (mContext.activeSecurityToken && mContext.activeSecurityToken->id() == mTokenId)
      return mContext.activeSecurityToken.get();
    if (mContext.pendingSecurityToken && mContext.pendingSecurityToken->id() == mTokenId)
      return mContext.pendingSecurityToken.get();
    if (mContext.retiredSecurityToken && mContext.retiredSecurityToken->id() == mTokenId)
      return mContext.retiredSecurityToken.get();
    return nullptr;
  }

  void answer_token_retired()
  {
    answer(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelTokenUnknown},
      ErrorDetail::build("TokenRetired",
        "The security token the chunk selected was retired before the chunk was verified",
        "SecurityPolicy")
        .context(ua::ContextKeys::securityTokenId, std::to_string(mTokenId))});
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;  // caller-owned; outlives the operation per contract
  uint32_t mTokenId{0};  // the TokenId on the wire, which selected the keys
  span<const byte> mMessageChunk;  // caller-owned view
  UaScMessageHeader mHeader;  // copy - the original const& may not outlive the operation
  size_t mHeaderSize{0};  // captured after the security header decode
  ByteString mPlainTextBuffer;  // owned (used only when encrypted)
  span<const byte> mPlainText;  // view into mPlainTextBuffer or mMessageChunk
  std::function<void(DecodedMessageChunkResult)> mCallback;
};

}  // namespace

// decode_symmetric_message_chunk: the token selection happens here (a chunk under the pending token tries
// it, and it becomes active only if the chunk is accepted); DecodeSymmetricOperation then decrypts when
// encrypted, verifies the signature with the selected token's keys, strips the padding, checks the
// sequence number under the selected token and accumulates the body. Every failure answers the callback
// once with its status and ErrorDetail.
void SecurityPolicy::decode_symmetric_message_chunk_async(SecureChannelContext& context,
  UaBinaryDecoder& cipherTextDecoder, span<const byte> messageChunk,
  const stack_utils::UaScMessageHeader& header, std::function<void(DecodedMessageChunkResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    SymmetricSecurityHeader securityHeader;
    securityHeader.decode(context.encodingLimits, cipherTextDecoder);
    auto headerSize = cipherTextDecoder.stream().get_position();

    auto& activeToken = context.activeSecurityToken;
    auto& pendingToken = context.pendingSecurityToken;

    if (!activeToken)
    {
      callback(DecodedMessageChunkResult{StatusCode{Status::BadInvalidState},
        make_error_detail("PolicyConfigError",
          "No active security token available for symmetric message decoding",
          "SecurityPolicy")});
      return;
    }

    auto& retiredToken = context.retiredSecurityToken;
    if (securityHeader.tokenId == activeToken->id())
    {
      if (retiredToken)
      {
        // OPC 10000-6 6.7.4 (1.05.06): the first chunk accepted under the new token ends the client's
        // acceptance of the token the renew response replaced - that token only: a renewal completing while
        // this chunk is verified may have retired another since.
        callback = [&context, retiredId = retiredToken->id(), inner = std::move(callback)](
                     DecodedMessageChunkResult result) mutable
        {
          if (result.is_good() && context.retiredSecurityToken &&
              context.retiredSecurityToken->id() == retiredId)
            context.retiredSecurityToken.reset();
          inner(std::move(result));
        };
      }
    }
    else if (retiredToken && securityHeader.tokenId == retiredToken->id())
    {
      if (retiredToken->has_expired())
      {
        // "until it expires" (6.7.4): its keys are released here.
        retiredToken.reset();
        callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelTokenUnknown},
          ErrorDetail::build("RetiredTokenExpired",
            "Received token ID names the security token the renewal replaced, and that token has expired",
            "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))});
        return;
      }
      // OPC 10000-6 6.7.4 (1.05.06): a chunk the Server secured with the replaced token before it received a
      // message under the new one; the operation selects the retired token's keys by the TokenId.
    }
    else if (pendingToken && securityHeader.tokenId == pendingToken->id() &&
             context.role == ChannelRole::Client)
    {
      // Only a Server activates a renewed token on the peer's first chunk under it; the client activates its
      // own on the renew response, so a chunk under a renewed token it has not activated yet is refused.
      callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelTokenUnknown},
        ErrorDetail::build("PolicyConfigError",
          "Received token ID names a renewed token this client has not activated",
          "SecurityPolicy")
          .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))});
      return;
    }
    else
    {
      if (!pendingToken)
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelTokenUnknown},
          ErrorDetail::build("PolicyConfigError",
            "Token ID does not match active token and no pending token exists",
            "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))});
        return;
      }
      else if (securityHeader.tokenId != pendingToken->id())
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelTokenUnknown},
          ErrorDetail::build(
            "PolicyConfigError", "Token ID does not match active or pending token", "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))
            .context(ua::ContextKeys::securityTokenActiveId, std::to_string(activeToken->id()))
            .context(ua::ContextKeys::securityTokenPendingId, std::to_string(pendingToken->id()))});
        return;
      }
      else
      {
        // H-D5 (B2-6): the pending token is tried for this chunk and becomes active only once the
        // chunk has been accepted (MAC verified, sequence checked); a chunk that fails leaves the
        // tokens as they were, so no state changes on unauthenticated input.
        std::swap(activeToken, pendingToken);
        callback = [&context, inner = std::move(callback)](DecodedMessageChunkResult result) mutable
        {
          if (result.is_bad())
            std::swap(context.activeSecurityToken, context.pendingSecurityToken);
          else
            context.pendingSecurityToken.reset();  // the previous token is retired
          inner(std::move(result));
        };
      }
    }

    started = true;
    DecodeSymmetricOperation::start(shared_from_this(),
      context,
      securityHeader.tokenId,
      messageChunk,
      header,
      headerSize,
      std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DecodedMessageChunkResult{er, er.shared_detail()});
    }
  }
}

void SecurityPolicy::decode_unknown_message_chunk_async(SecureChannelContext& context,
  span<const byte> messageChunk, std::function<void(DecodedMessageChunkResult)> callback) const
{
  try
  {
    if (messageChunk.size() <= ua::connection_protocol::headerSize)
    {
      callback(DecodedMessageChunkResult{StatusCode{Status::BadDecodingError},
        ErrorDetail::build("CryptoOperationFailed", "Message chunk size is too small", "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(messageChunk.size()))
          .context(ua::ContextKeys::sizeMin, std::to_string(ua::connection_protocol::headerSize + 1))});
      return;
    }

    memory_stream_device::ExternalReadOnly streamDevice{messageChunk};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder decoder(StructureResolver{}, stream, context.encodingLimits);

    UaScMessageHeader header;
    header.decode(context.encodingLimits, decoder);

    if (context.is_open())
    {
      if (header.secureChannelId != context.secureChannelId)
      {
        callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelIdInvalid},
          ErrorDetail::build(
            "PolicyConfigError", "Secure channel ID does not match expected", "SecurityPolicy")
            .context(ua::ContextKeys::actual, std::to_string(header.secureChannelId))
            .context(ua::ContextKeys::expected, std::to_string(context.secureChannelId))});
        return;
      }
    }
    else if (header.secureChannelId != 0 && header.messageType != UaScMessageHeader::MessageType::Open)
    {
      callback(DecodedMessageChunkResult{StatusCode{Status::BadSecureChannelIdInvalid},
        ErrorDetail::build("PolicyConfigError",
          "Secure channel ID is expected to be zero for unopened channel",
          "SecurityPolicy")
          .context(ua::ContextKeys::actual, std::to_string(header.secureChannelId))
          .context(ua::ContextKeys::expected, "0")});
      return;
    }

    if (header.messageType == UaScMessageHeader::MessageType::Open)
    {
      decode_asymmetric_message_chunk_async(context, decoder, messageChunk, header, std::move(callback));
      return;
    }
    if (header.messageType == UaScMessageHeader::MessageType::Message ||
        header.messageType == UaScMessageHeader::MessageType::Close)
    {
      decode_symmetric_message_chunk_async(context, decoder, messageChunk, header, std::move(callback));
      return;
    }

    callback(DecodedMessageChunkResult{StatusCode{Status::BadDecodingError},
      make_error_detail("CryptoOperationFailed",
        "Secure Conversation Message type is invalid (not Open, Message, or Close)",
        "SecurityPolicy")});
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(DecodedMessageChunkResult{er, er.shared_detail()});
  }
}

namespace
{

}  // namespace

void SecurityPolicy::encode_unknown_message_async(SecureChannelContext& context, uint32_t requestId,
  shared_ptr<const Structure> message, SendMessageChunk sendMessageChunk,
  std::function<void(VoidResult)> callback) const
{
  // Zero-copy hoist: this is a per-message hot path, so `callback` is moved exactly once (into the flow)
  // after the prologue try/catch. The prologue computes the encoded body into `encodedBody`. The local
  // `callback` (still un-moved) fires in exactly two places, neither inside the try BODY, so a throwing
  // callback can never be caught and re-fired: the prologue catch (serialization error) and the
  // size-ceiling rejection branch immediately after the try.
  ByteString encodedBody;
  // Set by the prologue when the serialized message exceeds the outgoing size ceiling; the rejection
  // callback is fired after the try/catch (never inside the try) to keep the single-fire invariant.
  bool exceedsSizeCeiling = false;
  std::size_t encodedMessageSize = 0;
  uint32_t appliedSizeCeiling = 0;

  // The encode buffer holds the ENTIRE message before it is split into chunks, so it must be sized to the
  // whole (possibly multi-chunk) message  -  never to a single send buffer. sendBufferSize is one CHUNK;
  // the previous max(sendBufferSize, sendMaxMessageSize, 1024) collapsed to that single chunk whenever
  // the peer advertised sendMaxMessageSize == 0 ("no limit"  -  the common case), so every multi-chunk
  // message failed to serialize with StreamCapacityExceeded (BadUnexpectedError) before the size checks in
  // encode_symmetric_message_async could ever run. Ceiling precedence: the peer's MaxMessageSize when it
  // set one; else our own configured max message size (recvMaxMessageSize  -  a receive-direction limit
  // reused as a send-side self-protection cap, since both derive from the same local config); else the
  // protocol default (16 MB). A configured value of 0 ("no limit") deliberately degrades to that bounded
  // default rather than an unbounded buffer. One send buffer of headroom lets a message just over the
  // ceiling serialize fully so it is rejected below with a meaningful BadResponseTooLarge instead of
  // throwing StreamCapacityExceeded mid-encode. Hoisted out of the try so the catch can re-measure an
  // over-cap message against the same ceiling (see the catch).
  uint32_t messageSizeCeiling = context.negotiatedLimits.sendMaxMessageSize;
  if (messageSizeCeiling == 0)
  {
    messageSizeCeiling = context.negotiatedLimits.recvMaxMessageSize;
  }
  if (messageSizeCeiling == 0)
  {
    messageSizeCeiling = connection_protocol::Limits::defaultMaxMessageSize;
  }

  try
  {
    check(message);
    check(context.namespaceIndexCallback);

    const uint32_t sendBufferHeadroom = std::max<uint32_t>(context.negotiatedLimits.sendBufferSize, 1024u);
    const auto encodeBufferSize =
      static_cast<std::size_t>(std::min<uint64_t>(uint64_t{messageSizeCeiling} + uint64_t{sendBufferHeadroom},
        static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())));
    // Grow on demand up to the ceiling (reserve=false): a small message must not eagerly allocate the full
    // (up to 16 MB) ceiling on this per-message hot path.
    memory_stream_device::Dynamic streamDevice{encodeBufferSize, false};
    MemoryStream stream{streamDevice};
    const CodecNamespaceContext nsConfig{context.namespaceIndexCallback};
    UaBinaryEncoder binaryEncoder{nsConfig, stream};

    const StackDepth limit = context.encodingLimits.stack_depth();
    Encoder encoder{binaryEncoder};
    message->encode_id(limit, nsConfig, encoder);
    binaryEncoder.encode(limit, *message);
    const auto messageSize = stream.get_length();

    // Enforce the outgoing message-size ceiling. encode_symmetric_message_async only checks
    // sendMaxMessageSize when it is non-zero, so for an unlimited peer (sendMaxMessageSize==0) this is the
    // ONLY outgoing size bound. Record the rejection here (inside the try, where the sizes are known) but
    // fire the callback after the try/catch so a throwing callback cannot be re-entered by the catch.
    if (messageSize > messageSizeCeiling)
    {
      exceedsSizeCeiling = true;
      encodedMessageSize = messageSize;
      appliedSizeCeiling = messageSizeCeiling;
    }
    else
    {
      // Move the dynamic buffer's storage into an owning ByteString that the flow holds for the
      // duration of the inner encode_*_message_async chain (which keeps the body as span views
      // across multiple async chunks).
      auto bodyVec = streamDevice.move_storage_out();
      bodyVec.resize(messageSize);
      encodedBody = ByteString{std::move(bodyVec)};
    }
  }
  catch (...)
  {
    // The encode buffer is capped at (ceiling + one send buffer). A message  -  or even a single field  -
    // larger than that cap makes the MemoryStream throw a generic StreamCapacityExceeded
    // (BadUnexpectedError) before the clean `messageSize > ceiling` check below can run, so a too-large
    // outbound request on a small-buffer channel would mis-report as an internal error and tear the channel
    // down. Re-measure the TRUE encoded size with a non-allocating NullStream (error path only, so no
    // hot-path cost): a size over the ceiling is a too-large outbound request and must surface the same
    // BadResponseTooLarge as the in-buffer path; anything else is a genuine encode fault reported as-is.
    auto originalError = std::current_exception();
    std::optional<std::size_t> measuredSize;
    try
    {
      NullStream counting;
      const CodecNamespaceContext measureNsConfig{context.namespaceIndexCallback};
      UaBinaryEncoder measureBinaryEncoder{measureNsConfig, counting};
      const StackDepth measureLimit = context.encodingLimits.stack_depth();
      Encoder measureEncoder{measureBinaryEncoder};
      message->encode_id(measureLimit, measureNsConfig, measureEncoder);
      measureBinaryEncoder.encode(measureLimit, *message);
      measuredSize = counting.get_position();
      if (*measuredSize > messageSizeCeiling)
      {
        exceedsSizeCeiling = true;
        encodedMessageSize = *measuredSize;
        appliedSizeCeiling = messageSizeCeiling;
      }
    }
    catch (...)
    {
      // Re-measurement itself failed  -  an empty optional reports the original error unchanged below.
      measuredSize.reset();
    }

    if (!exceedsSizeCeiling)
    {
      auto er = ua::exception_to_status_code(originalError);
      callback(VoidResult{er, er.shared_detail()});
      return;
    }
    // else: fall through to the exceedsSizeCeiling branch below, which fires BadResponseTooLarge once.
  }

  // Size-ceiling rejection, fired outside the prologue try/catch (so a throwing callback is not caught and
  // re-fired). The status DEPENDS ON THE DIRECTION: OPC 10000-4 section 5.3 gives the server
  // Bad_ResponseTooLarge for an oversized response and the client stack Bad_RequestTooLarge before it
  // sends an oversized request. This check is shared by both sides, so it must ask which side it is on -
  // it previously reported Bad_ResponseTooLarge both ways, and a caller whose REQUEST was too large was
  // told "response too large" and looked in the wrong place.
  if (exceedsSizeCeiling)
  {
    callback(VoidResult{StatusCode{outgoing_too_large_status(context.role)},
      ErrorDetail::build(
        "MessageTooLarge", "Encoded message exceeds the maximum outgoing message size", "SecurityPolicy")
        .context(ua::ContextKeys::sizeActual, std::to_string(encodedMessageSize))
        .context(ua::ContextKeys::sizeMax, std::to_string(appliedSizeCeiling))});
    return;
  }

  // The encoded body has to outlive the inner `encode_*_message_async` call, which takes a view over
  // it and answers later. That is the ONLY thing the flow struct here ever did - it had no step, no
  // chain and nothing to remember between steps - so it is a shared owner of the bytes plus a
  // capture, which is what it was standing in for.
  //
  // `callback` is moved exactly once here, outside any catch that references it.
  auto encodedBodyOwner = std::make_shared<ByteString>(std::move(encodedBody));
  auto pendingCallback = std::make_shared<std::function<void(VoidResult)>>(std::move(callback));

  auto innerCallback = [encodedBodyOwner, pendingCallback](VoidResult result) mutable
  {
    auto cb = std::move(*pendingCallback);
    cb(std::move(result));
  };

  // `callback` is now owned by `pendingCallback`. A synchronous throw out of the dispatch below must
  // report through that still-owned callback.
  try
  {
    if (dynamic_cast<const OpenSecureChannelRequest*>(message.get()) ||
        dynamic_cast<const OpenSecureChannelResponse*>(message.get()))
    {
      encode_asymmetric_message_async(context,
        requestId,
        span<const byte>{*encodedBodyOwner},
        std::move(sendMessageChunk),
        std::move(innerCallback));
    }
    else
    {
      // The CloseSecureChannel request is framed as CLO (OPC 10000-6 6.7.2.2 Table 50).
      // Request-only: 7.1.4 states the Server sends no CloseSecureChannel response, so there is
      // no CLO response on the wire. All other symmetric traffic keeps the default
      // MessageType::Message (MSG).
      auto messageType = UaScMessageHeader::MessageType::Message;
      if (dynamic_cast<const CloseSecureChannelRequest*>(message.get()))
      {
        messageType = UaScMessageHeader::MessageType::Close;
      }

      encode_symmetric_message_async(context,
        requestId,
        span<const byte>{*encodedBodyOwner},
        std::move(sendMessageChunk),
        std::move(innerCallback),
        messageType);
    }
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    auto cb = std::move(*pendingCallback);
    if (cb)
    {
      cb(VoidResult{er, er.shared_detail()});
    }
  }
}

namespace
{

/// The OPN send path: chunk the body, and for an authenticated channel sign then encrypt each chunk
/// before it goes to the transport.
///
/// The stream, its device and the encoder stay members for the same reason as in
/// @ref EncodeSymmetricAbortOperation: the signature is written to the very stream that encoded the
/// headers, on the far side of a suspension, so they need stable addresses.
class EncodeAsymmetricOperation final : public ua::async::SelfOwningOperation<EncodeAsymmetricOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, span<const byte> messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncodeAsymmetricOperation>(
      std::move(policy), context, requestId, messageBody, std::move(sendMessageChunk), std::move(callback)));
  }

  EncodeAsymmetricOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, span<const byte> messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mRequestId(requestId), mBodyRemaining(messageBody), mSendMessageChunk(std::move(sendMessageChunk)),
      mNsConfig(context.namespaceIndexCallback), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncodeAsymmetricOperation>;

  ua::async::Task<> run()
  {
    try
    {
      const StackDepth limit = mContext.encodingLimits.stack_depth();

      mSecurityHeader.securityPolicyUri = mPolicy->uri();
      if (mPolicy->is_authenticated())
      {
        // An authenticated policy requires the remote (receiver) certificate to encrypt the
        // asymmetric OPN. A missing remote certificate is a caller error (e.g. opening a secured
        // channel without supplying the server certificate); fail rather than dereference null.
        if (!mContext.remoteCertificate)
        {
          answer(VoidResult{StatusCode{Status::BadCertificateInvalid}});
          co_return;
        }
        mSecurityHeader.senderCertificate = mContext.localCertificate;
        // Decision 24: the own issuer chain follows the leaf (OPC 10000-6 section 6.2.6).
        mSecurityHeader.issuerCertificates = mContext.localIssuerCertificates;
        mSecurityHeader.receiverCertificateThumbprint = mContext.remoteCertificate->thumbprint();
      }

      size_t securityHeaderSize{0};
      {
        NullStream nullStream;
        UaBinaryEncoder binaryEncoder{mNsConfig, nullStream};
        mSecurityHeader.encode(mContext.encodingLimits, binaryEncoder);
        securityHeaderSize = binaryEncoder.stream().get_position();
      }

      // Part 6 6.7.2.5: MaxBodySize for asymmetric encrypted+signed chunks.
      mHeaderSize = UaScMessageHeader::sizeInBytes + securityHeaderSize;
      mCiphertextBlockSize = mPolicy->asymmetric_ciphertext_block_size(mContext.remoteCertificate.get());
      mPlaintextBlockSize = mPolicy->asymmetric_plaintext_block_size(mContext.remoteCertificate.get());
      mSignatureSize = mPolicy->asymmetric_signature_size(mContext.localCertificate.get());
      // Part 6 6.7.2.3: the security header (the SenderCertificate with its chain) must fit one chunk with
      // room for a body block. An own chain too large for the negotiated buffer fails the open with
      // Bad_EncodingLimitsExceeded before anything is written (SDK decision; the specification names no
      // code). A zero buffer size means no limit was negotiated.
      if (const auto sendBufferSize = size_t{mContext.negotiatedLimits.sendBufferSize};
          sendBufferSize != 0 &&
          (sendBufferSize <= mHeaderSize + mSignatureSize + 1 ||
            (mCiphertextBlockSize != 0 &&
              mPlaintextBlockSize *
                  ((sendBufferSize - mHeaderSize - mSignatureSize - 1) / mCiphertextBlockSize) <=
                SequenceHeader::sizeInBytes)))
      {
        answer(VoidResult{StatusCode{Status::BadEncodingLimitsExceeded},
          make_error_detail("SecurityHeaderExceedsChunk",
            "The OPN security header (own certificate chain) does not fit the negotiated send buffer",
            "SecurityPolicy")});
        co_return;
      }
      mMaxBodySize =
        mPlaintextBlockSize * ((mContext.negotiatedLimits.sendBufferSize - mHeaderSize - mSignatureSize - 1) /
                                mCiphertextBlockSize) -
        SequenceHeader::sizeInBytes;

      while (!mBodyRemaining.empty())
      {
        UaScMessageHeader messageHeader;
        messageHeader.messageType = UaScMessageHeader::MessageType::Open;
        messageHeader.secureChannelId = mContext.secureChannelId;

        // `bytesToWrite` is a LOCAL that lives across both awaits below. The chain could not keep it,
        // so its last handler RE-DERIVED it as `min(bodyRemaining.size(), maxBodySize)` and relied on
        // that reproducing the original computation exactly. Nothing enforced that agreement.
        auto bytesToWrite = mBodyRemaining.size();
        if (bytesToWrite > mMaxBodySize)
        {
          bytesToWrite = mMaxBodySize;
          messageHeader.isFinal = UaScMessageHeader::IsFinal::Intermediate;
        }
        else
        {
          messageHeader.isFinal = UaScMessageHeader::IsFinal::Final;
        }
        auto bodyToWrite = utils::safe_sub_span(mBodyRemaining, 0, bytesToWrite);

        mMessageChunk = ByteString{};
        mMessageChunk.resize(mContext.negotiatedLimits.sendBufferSize);

        mEncoder.reset();
        mStream.reset();
        mStreamDevice.reset();
        auto& streamDevice = mStreamDevice.emplace(span<byte>{mMessageChunk});
        auto& stream = mStream.emplace(streamDevice);
        auto& encoder = mEncoder.emplace(mNsConfig, stream);

        messageHeader.encode(mContext.encodingLimits, encoder);
        mSecurityHeader.encode(mContext.encodingLimits, encoder);

        SequenceHeader sequenceHeader;
        sequenceHeader.sequenceNumber = mContext.next_tx_sequence_number();
        sequenceHeader.requestId = mRequestId;
        sequenceHeader.encode(mContext.encodingLimits, encoder);

        stream.write_all(bodyToWrite);

        if (!mPolicy->is_authenticated())
        {
          const uint32_t chunkSize = numeric_cast<uint32_t>(stream.get_position());
          stream.seek_from_start(4);
          encoder.encode(limit, chunkSize);
          mMessageChunk.resize(chunkSize);

          advance_and_send(bytesToWrite);
          continue;
        }

        check(mContext.localCertificate);

        mCiphertextSize = numeric_cast<uint32_t>(mPolicy->append_padding(mContext.encodingLimits,
          encoder,
          mContext.remoteCertificate->public_key_bit_length(),
          mHeaderSize,
          mSignatureSize,
          mPlaintextBlockSize,
          mCiphertextBlockSize));

        const auto signaturePosition = stream.get_position();
        stream.seek_from_start(4);
        mChunkSize = numeric_cast<uint32_t>(mHeaderSize + mCiphertextSize);
        encoder.encode(limit, mChunkSize);
        stream.seek_from_start(signaturePosition);

        check(mContext.localKeyPair);

        auto signResult = co_await await_step<ByteStringResult>(
          [this, &stream](auto completion)
          {
            mContext.crypto->asymmetric_sign_async(mPolicy,
              mPolicy->asymmetric_signature_algorithm(),
              mContext.localKeyPair,
              utils::safe_sub_span(span<const byte>{mMessageChunk}, 0, stream.get_position()),
              std::move(completion));
          });
        if (signResult.is_uncertain())
        {
          answer(VoidResult{StatusCode{Status::BadApplicationSignatureInvalid,
            ua::security_internal::uncertain_answer_detail(signResult.status_code(), "SecurityPolicy")}});
          co_return;
        }
        if (!signResult.is_good())
        {
          answer(VoidResult{StatusCode{Status::BadApplicationSignatureInvalid},
            ErrorDetail::build("CryptoOperationFailed", "Could not sign asymmetric message", "SecurityPolicy")
              .cause(signResult.status_code())});
          co_return;
        }

        // The signature goes onto the same stream the headers were encoded into.
        stream.write_all(std::move(signResult).value());

        auto plainText = utils::safe_sub_span(
          span<const byte>{mMessageChunk}, mHeaderSize, stream.get_position() - mHeaderSize);
        mCipherText = ByteString{};
        mCipherText.resize(mCiphertextSize);

        auto encryptResult = co_await await_step<VoidResult>(
          [this, plainText](auto completion) {
            mPolicy->asymmetric_encrypt_async(
              mContext, plainText, span<byte>{mCipherText}, std::move(completion));
          });
        if (!encryptResult.is_good())
        {
          answer(VoidResult{ua::security_internal::not_good_answer(
            encryptResult.status_code(), Status::BadInternalError, "SecurityPolicy")});
          co_return;
        }

        auto dest = utils::safe_sub_span(span<byte>{mMessageChunk}, mHeaderSize, mCiphertextSize);
        std::memcpy(dest.data(), mCipherText.data(), mCipherText.size());
        mMessageChunk.resize(mChunkSize);

        advance_and_send(bytesToWrite);
      }

      answer(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(VoidResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Steps the body cursor past the chunk just built and hands that chunk to the transport.
  void advance_and_send(size_t bytesWritten)
  {
    mBodyRemaining = utils::safe_sub_span(mBodyRemaining, bytesWritten, mBodyRemaining.size() - bytesWritten);
    mSendMessageChunk(std::move(mMessageChunk));
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(VoidResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mRequestId{0};
  span<const byte> mBodyRemaining;  // moves through the caller-owned message body

  SecurityPolicy::SendMessageChunk mSendMessageChunk;

  AsymmetricSecurityHeader mSecurityHeader;
  size_t mHeaderSize{0};
  size_t mCiphertextBlockSize{0};
  size_t mPlaintextBlockSize{0};
  size_t mSignatureSize{0};
  size_t mMaxBodySize{0};
  CodecNamespaceContext mNsConfig;

  // Per-chunk scratch, rebuilt each iteration.
  ByteString mMessageChunk;
  std::optional<memory_stream_device::ExternalWritable> mStreamDevice;
  std::optional<MemoryStream<memory_stream_device::ExternalWritable>> mStream;
  std::optional<UaBinaryEncoder> mEncoder;
  ByteString mCipherText;
  uint32_t mChunkSize{0};
  uint32_t mCiphertextSize{0};

  std::function<void(VoidResult)> mCallback;
};

}  // namespace

// encode_asymmetric_message flow (per chunk; loops until messageBody exhausted):
//   encode_asymmetric_message_async
//     -> start_encode_asymmetric_chunk  (compute sizes, encode headers + body, pad)
//     -> [is_authenticated()] asymmetric_sign_async
//        -> on_encode_asymmetric_sign_complete           [strand-guarded]
//     -> [is_encrypted()] asymmetric_encrypt_async
//        -> on_encode_asymmetric_encrypt_complete        [strand-guarded]
//     -> sendMessageChunk(...)
//     -> [more body remaining] start_encode_asymmetric_chunk  (next chunk)
//     -> complete_encode_asymmetric  |  fail_encode_asymmetric
//
// On any failure (sign, encrypt, send): fail_encode_asymmetric.
void SecurityPolicy::encode_asymmetric_message_async(SecureChannelContext& context, uint32_t requestId,
  span<const byte> messageBody, SendMessageChunk sendMessageChunk,
  std::function<void(VoidResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    started = true;
    EncodeAsymmetricOperation::start(
      shared_from_this(), context, requestId, messageBody, std::move(sendMessageChunk), std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here. The
    // prologue that used to run here - security header, block sizes, MaxBodySize - is now the first
    // few statements of the body, where the operation already owns the answer.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

namespace
{

/// The abort chunk: a Message chunk with IsFinal = Aborted carrying a status and a reason string,
/// signed and (when the channel is encrypted) encrypted like any other, then sent best-effort.
///
/// The stream, its device and the encoder stay members because they are written to on BOTH sides of
/// the signature await - the signature is appended to the same stream that encoded the headers - so
/// they have to keep stable addresses across the suspension.
class EncodeSymmetricAbortOperation final
  : public ua::async::SelfOwningOperation<EncodeSymmetricAbortOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, Status abortStatus, std::string reason,
    SecurityPolicy::SendMessageChunk sendMessageChunk, uint32_t maxChunkSize,
    std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncodeSymmetricAbortOperation>(std::move(policy),
      context,
      requestId,
      abortStatus,
      std::move(reason),
      std::move(sendMessageChunk),
      maxChunkSize,
      std::move(callback)));
  }

  EncodeSymmetricAbortOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, Status abortStatus, std::string reason,
    SecurityPolicy::SendMessageChunk sendMessageChunk, uint32_t maxChunkSize,
    std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mRequestId(requestId), mAbortStatus(abortStatus), mReason(std::move(reason)),
      mSendMessageChunk(std::move(sendMessageChunk)), mNsConfig(context.namespaceIndexCallback),
      mMaxChunkSize(maxChunkSize), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncodeSymmetricAbortOperation>;

  ua::async::Task<> run()
  {
    try
    {
      const StackDepth limit = mContext.encodingLimits.stack_depth();

      // Requirement: P6-67-0018 - abort reason string should not exceed 4096 bytes.
      if (mReason.size() > 4096)
      {
        mReason.resize(4096);
      }

      // ...and it must also fit the negotiated chunk size.
      {
        const size_t fixedBodyOverhead = sizeof(uint32_t) + sizeof(int32_t);
        const size_t headerOverhead =
          UaScMessageHeader::sizeInBytes + SymmetricSecurityHeader::sizeInBytes + SequenceHeader::sizeInBytes;
        if (mMaxChunkSize > headerOverhead + fixedBodyOverhead)
        {
          const size_t maxReasonBytes = mMaxChunkSize - headerOverhead - fixedBodyOverhead;
          if (mReason.size() > maxReasonBytes)
          {
            mReason.resize(maxReasonBytes);
          }
        }
        else
        {
          mReason.clear();
        }
      }

      // Build the abort body.
      memory_stream_device::Dynamic abortBodyDev{1024 + mReason.size(), true};
      MemoryStream<memory_stream_device::Dynamic> abortBodyStream{abortBodyDev};
      UaBinaryEncoder abortBodyEnc{mNsConfig, abortBodyStream};
      abortBodyEnc.encode(limit, utils::to_underlying(mAbortStatus));
      abortBodyEnc.encode(limit, String{mReason});
      auto abortBody = abortBodyDev.move_storage_out();
      abortBody.resize(abortBodyStream.get_position());

      UaScMessageHeader abortHeader;
      abortHeader.messageType = UaScMessageHeader::MessageType::Message;
      abortHeader.isFinal = UaScMessageHeader::IsFinal::Aborted;
      abortHeader.secureChannelId = mContext.secureChannelId;

      mAbortChunk = ByteString{};
      mAbortChunk.resize(mMaxChunkSize);

      auto& streamDevice = mStreamDevice.emplace(span<byte>{mAbortChunk});
      auto& stream = mStream.emplace(streamDevice);
      auto& encoder = mEncoder.emplace(mNsConfig, stream);

      abortHeader.encode(mContext.encodingLimits, encoder);

      SymmetricSecurityHeader abortSecHeader;
      check(mContext.activeSecurityToken);
      abortSecHeader.tokenId = mContext.activeSecurityToken->id();
      abortSecHeader.encode(mContext.encodingLimits, encoder);

      mHeaderSize = stream.get_position();

      SequenceHeader abortSeq;
      abortSeq.sequenceNumber = mContext.next_tx_sequence_number();
      if (!SecureChannelContext::note_sequence_number_under_token(
            mContext.txUseUnderToken, abortSecHeader.tokenId, abortSeq.sequenceNumber))
      {
        // CRY-4 / Part 6 6.7.2.4: refusing to produce the reuse closes the channel, the reconnect
        // the rule asks for.
        throw UaException{Status::BadSequenceNumberInvalid,
          make_error_detail("SequenceNumberReusedUnderToken",
            "The sequence number would be reused under the current security token",
            "SecurityPolicy")};
      }
      abortSeq.requestId = mRequestId;
      abortSeq.encode(mContext.encodingLimits, encoder);

      stream.write_all(abortBody);

      // An unauthenticated channel signs nothing and encrypts nothing.
      if (!mPolicy->is_authenticated())
      {
        const uint32_t chunkSize = numeric_cast<uint32_t>(stream.get_position());
        stream.seek_from_start(4);
        encoder.encode(limit, chunkSize);
        mAbortChunk.resize(chunkSize);
        send_and_answer();
        co_return;
      }

      const auto signatureSize = mPolicy->symmetric_signature_size();
      mChunkSize = numeric_cast<uint32_t>(stream.get_position() + signatureSize);
      mCiphertextSize = 0;

      if (mPolicy->is_encrypted(mContext))
      {
        const auto plaintextBlockSize = mPolicy->symmetric_plaintext_block_size();
        const auto ciphertextBlockSize = mPolicy->symmetric_ciphertext_block_size();

        mCiphertextSize = numeric_cast<uint32_t>(mPolicy->append_padding(mContext.encodingLimits,
          encoder,
          signatureSize * CHAR_BIT,
          mHeaderSize,
          signatureSize,
          plaintextBlockSize,
          ciphertextBlockSize));
        mChunkSize = numeric_cast<uint32_t>(mHeaderSize + mCiphertextSize);
      }

      const auto signaturePosition = stream.get_position();
      stream.seek_from_start(4);
      encoder.encode(limit, mChunkSize);
      stream.seek_from_start(signaturePosition);

      auto signResult = co_await await_step<ByteStringResult>(
        [this, &stream](auto completion)
        {
          mContext.crypto->symmetric_sign_async(mPolicy,
            mPolicy->symmetric_signature_algorithm(),
            mContext.activeSecurityToken->local_keys().signingKey,
            utils::safe_sub_span(span<const byte>{mAbortChunk}, 0, stream.get_position()),
            std::move(completion));
        });
      if (signResult.is_uncertain())
      {
        answer(VoidResult{StatusCode{Status::BadApplicationSignatureInvalid,
          ua::security_internal::uncertain_answer_detail(signResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!signResult.is_good())
      {
        answer(VoidResult{StatusCode{Status::BadApplicationSignatureInvalid},
          ErrorDetail::build(
            "CryptoOperationFailed", "Could not sign symmetric abort chunk", "SecurityPolicy")
            .cause(signResult.status_code())});
        co_return;
      }

      // The signature goes onto the same stream the headers were encoded into.
      stream.write_all(std::move(signResult).value());

      if (!mPolicy->is_encrypted(mContext))
      {
        mAbortChunk.resize(mChunkSize);
        send_and_answer();
        co_return;
      }

      auto plainText =
        utils::safe_sub_span(span<const byte>{mAbortChunk}, mHeaderSize, stream.get_position() - mHeaderSize);
      mCipherText = ByteString{};
      mCipherText.resize(mCiphertextSize);

      auto encryptResult = co_await await_step<VoidResult>(
        [this, plainText](auto completion) {
          mPolicy->symmetric_encrypt_async(
            mContext, plainText, span<byte>{mCipherText}, std::move(completion));
        });
      if (!encryptResult.is_good())
      {
        answer(VoidResult{ua::security_internal::not_good_answer(
          encryptResult.status_code(), Status::BadInternalError, "SecurityPolicy")});
        co_return;
      }

      auto dest = utils::safe_sub_span(span<byte>{mAbortChunk}, mHeaderSize, mCiphertextSize);
      std::memcpy(dest.data(), mCipherText.data(), mCipherText.size());
      mAbortChunk.resize(mChunkSize);
      send_and_answer();
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(VoidResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Sending is best-effort: an abort that cannot be put on the wire still answers Good, because
  /// the caller's own failure is what it is really reporting.
  void send_and_answer()
  {
    try
    {
      mSendMessageChunk(std::move(mAbortChunk));
    }
    catch (...)
    {
      ua::detail::ignore_expected_exception();
    }
    answer(VoidResult{});
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(VoidResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mRequestId{0};
  Status mAbortStatus{Status::BadInternalError};
  std::string mReason;
  SecurityPolicy::SendMessageChunk mSendMessageChunk;
  CodecNamespaceContext mNsConfig;
  uint32_t mMaxChunkSize{0};

  ByteString mAbortChunk;
  std::optional<memory_stream_device::ExternalWritable> mStreamDevice;
  std::optional<MemoryStream<memory_stream_device::ExternalWritable>> mStream;
  std::optional<UaBinaryEncoder> mEncoder;
  ByteString mCipherText;
  size_t mHeaderSize{0};
  uint32_t mChunkSize{0};
  uint32_t mCiphertextSize{0};

  std::function<void(VoidResult)> mCallback;
};

/// The MSG send path: chunk the body, and for an authenticated channel sign and (when encrypted)
/// encrypt each chunk before it goes to the transport.
///
/// A failure part-way through a multi-chunk message is DEFERRED rather than reported immediately:
/// the peer has already received chunks it will otherwise wait on, so an abort chunk goes out first
/// and only then does the caller learn what went wrong (Part 6 6.7.3). That is why every failure
/// below records `mDeferredError` and leaves the loop instead of answering - and why the abort is a
/// `co_await` here, where the chain needed a whole extra Step for it.
///
/// The stream, its device and the encoder stay members: the signature is written to the very stream
/// that encoded the headers, on the far side of a suspension.
class EncodeSymmetricOperation final : public ua::async::SelfOwningOperation<EncodeSymmetricOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, span<const byte> messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    uint32_t maxChunkSize, size_t maxChunkBodySize, UaScMessageHeader::MessageType messageType,
    std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncodeSymmetricOperation>(std::move(policy),
      context,
      requestId,
      messageBody,
      std::move(sendMessageChunk),
      maxChunkSize,
      maxChunkBodySize,
      messageType,
      std::move(callback)));
  }

  EncodeSymmetricOperation(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
    uint32_t requestId, span<const byte> messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    uint32_t maxChunkSize, size_t maxChunkBodySize, UaScMessageHeader::MessageType messageType,
    std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mRequestId(requestId), mBodyRemaining(messageBody), mSendMessageChunk(std::move(sendMessageChunk)),
      mMaxChunkSize(maxChunkSize), mMaxChunkBodySize(maxChunkBodySize),
      mNsConfig(context.namespaceIndexCallback), mMessageType(messageType), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncodeSymmetricOperation>;

  ua::async::Task<> run()
  {
    try
    {
      while (!mBodyRemaining.empty() && !mDeferredError)
      {
        size_t bytesToWrite = 0;
        bool authenticated = false;

        try
        {
          bytesToWrite = encode_one_chunk();
          authenticated = mPolicy->is_authenticated();
        }
        catch (...)
        {
          // exception_to_status_code maps UaException -> its status (and bad_alloc/etc. -> the right
          // code). An encode that surfaces as Good is remapped to the direction-correct "did not fit"
          // outcome - Bad_RequestTooLarge on the client, Bad_ResponseTooLarge on the server.
          const auto er = ua::exception_to_status_code(std::current_exception());
          auto st = er.as_status();
          if (st == Status::Good)
          {
            st = outgoing_too_large_status(mContext.role);
          }
          mDeferredError = std::make_pair(st, std::string{"encode failed"});
          mDeferredCause = er.shared_detail();  // the chunk encoder's own refusal (a sequence reuse, for one)
          break;
        }

        if (authenticated)
        {
          auto signResult = co_await await_step<ByteStringResult>(
            [this](auto completion)
            {
              mContext.crypto->symmetric_sign_async(mPolicy,
                mPolicy->symmetric_signature_algorithm(),
                mContext.activeSecurityToken->local_keys().signingKey,
                utils::safe_sub_span(span<const byte>{mMessageChunk}, 0, mStream->get_position()),
                std::move(completion));
            });
          if (!signResult.is_good())
          {
            mDeferredError = std::make_pair(
              Status::BadApplicationSignatureInvalid, std::string{"Could not sign symmetric message chunk"});
            mDeferredCause =
              ua::security_internal::not_good_answer_detail(signResult.status_code(), "SecurityPolicy");
            break;
          }

          bool encrypted = false;
          try
          {
            // The signature goes onto the same stream the headers were encoded into.
            mStream->write_all(std::move(signResult).value());
            encrypted = mPolicy->is_encrypted(mContext);
            if (!encrypted)
            {
              mMessageChunk.resize(mChunkSize);
            }
            else
            {
              mCipherText = ByteString{};
              mCipherText.resize(mCiphertextSize);
            }
          }
          catch (...)
          {
            const auto er = ua::exception_to_status_code(std::current_exception());
            mDeferredError = std::make_pair(er.as_status(), std::string{"encode failed"});
            mDeferredCause = er.shared_detail();
            break;
          }

          if (encrypted)
          {
            auto plainText = utils::safe_sub_span(
              span<const byte>{mMessageChunk}, mHeaderSize, mStream->get_position() - mHeaderSize);

            auto encryptResult = co_await await_step<VoidResult>(
              [this, plainText](auto completion) {
                mPolicy->symmetric_encrypt_async(
                  mContext, plainText, span<byte>{mCipherText}, std::move(completion));
              });
            if (!encryptResult.is_good())
            {
              mDeferredError = std::make_pair(
                encryptResult.is_bad() ? encryptResult.status_code().as_status() : Status::BadInternalError,
                std::string{"Symmetric encryption failed"});
              mDeferredCause =
                ua::security_internal::not_good_answer_detail(encryptResult.status_code(), "SecurityPolicy");
              break;
            }

            try
            {
              auto dest = utils::safe_sub_span(span<byte>{mMessageChunk}, mHeaderSize, mCiphertextSize);
              std::memcpy(dest.data(), mCipherText.data(), mCipherText.size());
              mMessageChunk.resize(mChunkSize);
            }
            catch (...)
            {
              const auto er = ua::exception_to_status_code(std::current_exception());
              mDeferredError = std::make_pair(er.as_status(), std::string{"encode failed"});
              mDeferredCause = er.shared_detail();
              break;
            }
          }
        }

        try
        {
          mBodyRemaining =
            utils::safe_sub_span(mBodyRemaining, bytesToWrite, mBodyRemaining.size() - bytesToWrite);
          mSendMessageChunk(std::move(mMessageChunk));
          ++mChunksSent;
        }
        catch (...)
        {
          const auto er = ua::exception_to_status_code(std::current_exception());
          mDeferredError = std::make_pair(er.as_status(), std::string{"send failed"});
          mDeferredCause = er.shared_detail();
          break;
        }
      }

      if (!mDeferredError)
      {
        answer(VoidResult{});
        co_return;
      }

      // Chunks already on the wire leave the peer waiting, so it gets an abort chunk before the
      // caller is told anything. Its outcome is ignored: the deferred error is what the caller needs.
      if (mChunksSent > 0)
      {
        co_await await_step<VoidResult>(
          [this](auto completion)
          {
            EncodeSymmetricAbortOperation::start(mPolicy,
              mContext,
              mRequestId,
              mDeferredError->first,
              mDeferredError->second,
              mSendMessageChunk,
              mMaxChunkSize,
              std::move(completion));
          });
      }
      answer_with_deferred();
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(VoidResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Encodes one chunk's headers and body into @ref mMessageChunk and, for an authenticated channel,
  /// appends the padding and fixes up the size field ready for signing. Returns the body bytes this
  /// chunk consumed. Throws on any encoding failure; the caller defers that.
  size_t encode_one_chunk()
  {
    const StackDepth limit = mContext.encodingLimits.stack_depth();

    UaScMessageHeader messageHeader;
    messageHeader.messageType = mMessageType;
    messageHeader.secureChannelId = mContext.secureChannelId;

    auto bytesToWrite = mBodyRemaining.size();
    if (bytesToWrite > mMaxChunkBodySize)
    {
      bytesToWrite = mMaxChunkBodySize;
      messageHeader.isFinal = UaScMessageHeader::IsFinal::Intermediate;
    }
    else
    {
      messageHeader.isFinal = UaScMessageHeader::IsFinal::Final;
    }
    auto bodyToWrite = utils::safe_sub_span(mBodyRemaining, 0, bytesToWrite);

    mMessageChunk = ByteString{};
    mMessageChunk.resize(mMaxChunkSize);

    mEncoder.reset();
    mStream.reset();
    mStreamDevice.reset();
    auto& streamDevice = mStreamDevice.emplace(span<byte>{mMessageChunk});
    auto& stream = mStream.emplace(streamDevice);
    auto& encoder = mEncoder.emplace(mNsConfig, stream);

    messageHeader.encode(mContext.encodingLimits, encoder);

    SymmetricSecurityHeader securityHeader;
    if (!mContext.activeSecurityToken)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("PolicyConfigError",
          "No active security token available for symmetric message encoding",
          "SecurityPolicy")};
    }
    securityHeader.tokenId = mContext.activeSecurityToken->id();
    securityHeader.encode(mContext.encodingLimits, encoder);

    mHeaderSize = stream.get_position();

    SequenceHeader sequenceHeader;
    sequenceHeader.sequenceNumber = mContext.next_tx_sequence_number();
    if (!SecureChannelContext::note_sequence_number_under_token(
          mContext.txUseUnderToken, securityHeader.tokenId, sequenceHeader.sequenceNumber))
    {
      // CRY-4 / Part 6 6.7.2.4: refusing to produce the reuse closes the channel, the reconnect
      // the rule asks for.
      throw UaException{Status::BadSequenceNumberInvalid,
        make_error_detail("SequenceNumberReusedUnderToken",
          "The sequence number would be reused under the current security token",
          "SecurityPolicy")};
    }
    sequenceHeader.requestId = mRequestId;
    sequenceHeader.encode(mContext.encodingLimits, encoder);

    stream.write_all(bodyToWrite);

    if (!mPolicy->is_authenticated())
    {
      const uint32_t chunkSize = numeric_cast<uint32_t>(stream.get_position());
      stream.seek_from_start(4);
      encoder.encode(limit, chunkSize);
      mMessageChunk.resize(chunkSize);
      return bytesToWrite;
    }

    const auto signatureSize = mPolicy->symmetric_signature_size();
    mChunkSize = numeric_cast<uint32_t>(stream.get_position() + signatureSize);
    mCiphertextSize = 0;

    if (mPolicy->is_encrypted(mContext))
    {
      const auto plaintextBlockSize = mPolicy->symmetric_plaintext_block_size();
      const auto ciphertextBlockSize = mPolicy->symmetric_ciphertext_block_size();

      mCiphertextSize = numeric_cast<uint32_t>(mPolicy->append_padding(mContext.encodingLimits,
        encoder,
        signatureSize * CHAR_BIT,
        mHeaderSize,
        signatureSize,
        plaintextBlockSize,
        ciphertextBlockSize));
      mChunkSize = numeric_cast<uint32_t>(mHeaderSize + mCiphertextSize);
    }

    const auto signaturePosition = stream.get_position();
    stream.seek_from_start(4);
    encoder.encode(limit, mChunkSize);
    stream.seek_from_start(signaturePosition);

    check(mContext.activeSecurityToken);
    return bytesToWrite;
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{status, status.shared_detail()});
  }

  /// Answers with the deferred error, which is what the caller actually needs to know.
  void answer_with_deferred()
  {
    Status status = Status::BadInternalError;
    std::string reason;
    if (mDeferredError)
    {
      status = mDeferredError->first;
      reason = mDeferredError->second;
    }
    // The thrown detail travels as the cause, so a refusal's own code (a sequence-number reuse, a
    // sign failure's detail) reaches the caller instead of only the status and a literal.
    auto detail =
      ErrorDetail::build("CryptoOperationFailed", "Deferred crypto operation failed", "SecurityPolicy")
        .context(ua::ContextKeys::errorMessage, std::move(reason));
    if (mDeferredCause)
      detail.cause(mDeferredCause);
    answer(VoidResult{StatusCode{status}, std::move(detail)});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(VoidResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mRequestId{0};
  span<const byte> mBodyRemaining;  // moves through the caller-owned message body
  SecurityPolicy::SendMessageChunk mSendMessageChunk;

  uint32_t mMaxChunkSize{0};
  size_t mMaxChunkBodySize{0};
  CodecNamespaceContext mNsConfig;
  UaScMessageHeader::MessageType mMessageType{UaScMessageHeader::MessageType::Message};

  size_t mChunksSent{0};
  std::optional<std::pair<Status, std::string>> mDeferredError;
  std::shared_ptr<const ErrorDetail> mDeferredCause;  ///< The thrown detail behind mDeferredError, if any.

  // Per-chunk scratch, rebuilt each iteration.
  ByteString mMessageChunk;
  std::optional<memory_stream_device::ExternalWritable> mStreamDevice;
  std::optional<MemoryStream<memory_stream_device::ExternalWritable>> mStream;
  std::optional<UaBinaryEncoder> mEncoder;
  ByteString mCipherText;
  size_t mHeaderSize{0};
  uint32_t mChunkSize{0};
  uint32_t mCiphertextSize{0};

  std::function<void(VoidResult)> mCallback;
};

}  // namespace

namespace test_access
{

void start_symmetric_abort_with_reason(shared_ptr<const SecurityPolicy> policy, SecureChannelContext& context,
  uint32_t requestId, Status abortStatus, std::string reason,
  SecurityPolicy::SendMessageChunk sendMessageChunk, uint32_t maxChunkSize,
  std::function<void(VoidResult)> callback)
{
  // Enters the same abort body the deferred-error path builds, but with a caller-seeded reason so
  // the P6-67-0018 clamp is reachable.
  EncodeSymmetricAbortOperation::start(std::move(policy),
    context,
    requestId,
    abortStatus,
    std::move(reason),
    std::move(sendMessageChunk),
    maxChunkSize,
    std::move(callback));
}

}  // namespace test_access

// encode_symmetric_message flow (per chunk; loops until messageBody exhausted):
//   encode_symmetric_message_async
//     -> [size validation: BadResponseTooLarge if chunk count or message size exceeds negotiated limits]
//     -> start_encode_symmetric_chunk  (compute sizes, encode headers + body, pad)
//     -> [is_authenticated()] symmetric_sign_async
//        -> on_encode_symmetric_sign_complete         [strand-guarded]
//     -> [is_encrypted()] symmetric_encrypt_async
//        -> on_encode_symmetric_encrypt_complete      [strand-guarded]
//     -> sendMessageChunk(...)
//     -> [more body remaining] start_encode_symmetric_chunk  (next chunk)
//     -> complete_encode_symmetric  |  fail_encode_symmetric  |  fail_encode_symmetric_with_deferred
//
// Failure paths:
//   - Direct failure (sendMessageChunk error etc.): fail_encode_symmetric.
//   - Deferred failure (sign/encrypt error mid-flight) routes to EncodeSymmetricAbortOperation,
//     which emits an abort chunk to the transport before the caller learns of the error, then
//     fail_encode_symmetric_with_deferred fires the user callback with the captured deferredError.
void SecurityPolicy::encode_symmetric_message_async(SecureChannelContext& context, uint32_t requestId,
  span<const byte> messageBody, SendMessageChunk sendMessageChunk, std::function<void(VoidResult)> callback,
  UaScMessageHeader::MessageType messageType) const
{
  // Zero-copy hoist: this is a per-message hot path, so `callback` is moved exactly once (into the flow)
  // after the prologue try/catch. The prologue computes the chunk sizing; only on a prologue throw does
  // the local `callback` fire (where it has not been moved). A synchronous throw out of the start step
  // reports through the flow's own failure path (`fail_encode_symmetric`).
  uint32_t maxChunkSize{0};
  size_t maxChunkBodySize{0};
  try
  {
    maxChunkSize = context.negotiatedLimits.sendBufferSize;

    if (is_authenticated() && is_encrypted(context))
    {
      auto messageHeaderSize = UaScMessageHeader::sizeInBytes;
      auto securityHeaderSize = SymmetricSecurityHeader::sizeInBytes;
      auto signatureSize = symmetric_signature_size();
      auto plaintextBlockSize = symmetric_plaintext_block_size();
      auto ciphertextBlockSize = symmetric_ciphertext_block_size();
      maxChunkBodySize =
        plaintextBlockSize * ((maxChunkSize - messageHeaderSize - securityHeaderSize - signatureSize - 1) /
                               ciphertextBlockSize) -
        SequenceHeader::sizeInBytes;
    }
    else if (is_authenticated())
    {
      maxChunkBodySize = maxChunkSize - UaScMessageHeader::sizeInBytes -
                         SymmetricSecurityHeader::sizeInBytes - SequenceHeader::sizeInBytes -
                         symmetric_signature_size();
    }
    else
    {
      maxChunkBodySize = maxChunkSize - UaScMessageHeader::sizeInBytes -
                         SymmetricSecurityHeader::sizeInBytes - SequenceHeader::sizeInBytes;
    }

    // Guard: a send buffer too small to hold one chunk makes the per-branch maxChunkBodySize compute to
    // 0 (None path at the exact boundary) or unsigned-underflow to a huge value (authenticated paths).
    // Either would divide-by-zero / bypass the chunk-count check below and later throw
    // StreamCapacityExceeded (BadUnexpectedError). A valid maxChunkBodySize is always < maxChunkSize, so
    // catch both cases here and surface BadResponseTooLarge up-front. CL-TCP-012.
    if ((maxChunkBodySize == 0) || (maxChunkBodySize > maxChunkSize))
    {
      callback(VoidResult{StatusCode{outgoing_too_large_status(context.role)},
        ErrorDetail::build(
          "PolicyConfigError", "Negotiated send buffer too small to encode a message chunk", "SecurityPolicy")
          .context(ua::ContextKeys::max, std::to_string(maxChunkSize))});
      return;
    }

    auto requiredChunkCount = messageBody.size() / maxChunkBodySize;
    if (messageBody.size() % maxChunkBodySize)
    {
      ++requiredChunkCount;
    }

    auto maxChunkCount = context.negotiatedLimits.sendMaxChunkCount;
    if ((maxChunkCount > 0) && (maxChunkCount < requiredChunkCount))
    {
      callback(VoidResult{StatusCode{outgoing_too_large_status(context.role)},
        ErrorDetail::build(
          "PolicyConfigError", "Required chunk count exceeds maximum allowed", "SecurityPolicy")
          .context(ua::ContextKeys::actual, std::to_string(requiredChunkCount))
          .context(ua::ContextKeys::max, std::to_string(maxChunkCount))});
      return;
    }

    auto maxMessageSize = context.negotiatedLimits.sendMaxMessageSize;
    if ((maxMessageSize > 0) && (messageBody.size() > maxMessageSize))
    {
      callback(VoidResult{StatusCode{outgoing_too_large_status(context.role)},
        ErrorDetail::build(
          "PolicyConfigError", "Message body size exceeds receiver maximum message size", "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(messageBody.size()))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxMessageSize))});
      return;
    }
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(VoidResult{er, er.shared_detail()});
    return;
  }

  // The operation owns the callback from here; a throw out of `start` answers through
  // `fail_to_start`, which owns it too.
  EncodeSymmetricOperation::start(shared_from_this(),
    context,
    requestId,
    messageBody,
    std::move(sendMessageChunk),
    maxChunkSize,
    maxChunkBodySize,
    messageType,
    std::move(callback));
}

void SecurityPolicy::check_sequence_header(
  SecureChannelContext& context, const stack_utils::SequenceHeader& sequenceHeader) const
{
  if (context.lastRxSequenceNumber.has_value())
  {
    if (uses_legacy_sequence_no())
    {
      if (!legacy_test_and_set_sequence_no(
            context.lastRxSequenceNumber.value(), sequenceHeader.sequenceNumber))
      {
        // Requirement: P6-67-0038 (logging is done by SecureChannel).
        throw UaException{Status::BadSequenceNumberInvalid,
          ErrorDetail::build("PolicyConfigError", "Legacy sequence number is invalid", "SecurityPolicy")
            .context(ua::ContextKeys::actual, std::to_string(sequenceHeader.sequenceNumber))
            .context(
              ua::ContextKeys::sequenceLastSeen, std::to_string(context.lastRxSequenceNumber.value()))};
      }
    }
    else
    {
      if (!test_and_set_sequence_no(context.lastRxSequenceNumber.value(), sequenceHeader.sequenceNumber))
      {
        // Requirement: P6-67-0038 (logging is done by SecureChannel).
        throw UaException{Status::BadSequenceNumberInvalid,
          ErrorDetail::build("PolicyConfigError", "Sequence number is invalid", "SecurityPolicy")
            .context(ua::ContextKeys::actual, std::to_string(sequenceHeader.sequenceNumber))
            .context(
              ua::ContextKeys::sequenceLastSeen, std::to_string(context.lastRxSequenceNumber.value()))};
      }
    }
  }
  else
  {
    context.lastRxSequenceNumber = sequenceHeader.sequenceNumber;
  }

  if (!context.receivedMessageBody.empty() && (context.receivedRequestId != sequenceHeader.requestId))
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("RequestIdMismatch", "Request ID does not match expected", "SecurityPolicy")
        .context(ua::ContextKeys::requestId, std::to_string(sequenceHeader.requestId))
        .context(ua::ContextKeys::expected, std::to_string(context.receivedRequestId))};
  }
  context.receivedRequestId = sequenceHeader.requestId;
}

void SecurityPolicy::copy_message_body(SecureChannelContext& context, const UaBinaryDecoder& decoder) const
{
  // Defensive inbound reassembly bound (anti chunk-flood DoS). The Connection Protocol layer caps each
  // individual chunk at the negotiated ReceiveBufferSize, but the *assembled* message (sum of all
  // chunks) and the *chunk count* are otherwise unbounded - a peer streaming Intermediate ('C') chunks
  // could grow receivedMessageBody without limit. OPC 10000-6 7.1.2.3/.4 expresses MaxMessageSize /
  // MaxChunkCount as sender-side obligations; a hardened receiver must not trust the peer to honour
  // them. On violation we fail with Bad_TcpMessageTooLarge (the transport-level "too large" code,
  // consistent with the per-chunk ReceiveBufferSize check) which tears the channel down - the correct
  // response to an abusive peer. The counter resets at each message boundary (see the Final-chunk sites).
  const auto& negotiated = context.negotiatedLimits;

  ++context.receivedChunkCount;
  if (negotiated.recvMaxChunkCount > 0 && context.receivedChunkCount > negotiated.recvMaxChunkCount)
  {
    throw UaException{Status::BadTcpMessageTooLarge,
      ErrorDetail::build(
        "ChunkCountExceeded", "Inbound message exceeds the negotiated MaxChunkCount", "SecurityPolicy")
        .context(ua::ContextKeys::actual, std::to_string(context.receivedChunkCount))
        .context(ua::ContextKeys::max, std::to_string(negotiated.recvMaxChunkCount))};
  }

  auto sizeFromPreviousChunks = context.receivedMessageBody.size();
  auto sizeOfMessageBody = decoder.stream().get_length() - decoder.stream().get_position();
  if (sizeOfMessageBody == 0)
  {
    return;
  }

  if (negotiated.recvMaxMessageSize > 0 &&
      sizeFromPreviousChunks + sizeOfMessageBody > negotiated.recvMaxMessageSize)
  {
    throw UaException{Status::BadTcpMessageTooLarge,
      ErrorDetail::build(
        "MessageSizeExceeded", "Inbound message body exceeds the negotiated MaxMessageSize", "SecurityPolicy")
        .context(ua::ContextKeys::actual, std::to_string(sizeFromPreviousChunks + sizeOfMessageBody))
        .context(ua::ContextKeys::max, std::to_string(negotiated.recvMaxMessageSize))};
  }

  context.receivedMessageBody.resize(sizeFromPreviousChunks + sizeOfMessageBody);
  decoder.stream().read_all(span<byte>{
    utils::unsigned_chars_to_bytes(&context.receivedMessageBody[sizeFromPreviousChunks]), sizeOfMessageBody});
}

VoidResult SecurityPolicy::certificate_policy_refusal(std::string_view rule, std::string_view summary,
  const X509Certificate& certificate, CertificateChainPosition position) const
{
  const char* positionName = "EndEntity";
  switch (position)
  {
  case CertificateChainPosition::EndEntity:
    break;
  case CertificateChainPosition::IssuingCa:
    positionName = "IssuingCa";
    break;
  case CertificateChainPosition::HigherCa:
    positionName = "HigherCa";
    break;
  }
  return VoidResult{StatusCode{Status::BadCertificatePolicyCheckFailed,
    ErrorDetail::build(std::string{rule}, std::string{summary}, "SecurityPolicy")
      .context(ua::ContextKeys::securityPolicy, std::string{uri()})
      .context(ua::ContextKeys::certificateChainPosition, std::string{positionName})
      .context(ua::ContextKeys::certificateSubject, certificate.subject_common_name())}};
}

void SecurityPolicy::validate_certificate_async(
  SecureChannelContext& context, std::function<void(VoidResult)> callback) const
{
  try
  {
    check(context.remoteCertificate);

    // A thin wrapper (owner review item 2): the Security Policy Check is the validator's Table 106 step
    // 4, run on every certificate of the chain it builds against the policy named here, in Table 106
    // order. Nothing is checked before the chain exists.
    auto certStore = context.certStore.lock();
    if (!certStore)
    {
      callback(VoidResult{StatusCode{Status::BadInternalError},
        make_error_detail("CertStoreUnavailable",
          "Certificate store is no longer available (channel torn down during open)",
          "SecurityPolicy")});
      return;
    }

    auto endpointUrl = context.endpointUrl.empty() || context.relaxHostNameCheck
                         ? std::optional<std::string>{}
                         : std::optional{context.endpointUrl};

    // Copy (not move) `callback` into the delegated validation so the original stays valid for the
    // prologue catch below. On success the cert store owns the copy and fires it; only on a prologue
    // throw does the local `callback` fire, and the function returns (no double-fire).
    CertificateValidationRequest request;
    request.certificate = context.remoteCertificate;
    request.presentedIssuers = context.remoteIssuerCertificates;
    request.use = context.role == ChannelRole::Client ? CertificateUse::ServerApplicationInstance
                                                      : CertificateUse::ClientApplicationInstance;
    request.policyId = id();
    request.endpointUrl = std::move(endpointUrl);
    if (context.onRemoteCertificateValidated || context.onRemoteCertificateErrorsSuppressed)
    {
      // Hand the exact validated request to the channel's owner on success (client revalidation), and
      // the errors a Good verdict suppressed (decision 22.6) to its reporter.
      certStore->validate_certificate_async(request,
        [onValidated = context.onRemoteCertificateValidated,
          onSuppressed = context.onRemoteCertificateErrorsSuppressed,
          request,
          callback](VoidResult result)
        {
          if (result.is_good())
          {
            if (onValidated)
            {
              onValidated(request);
            }
            if (onSuppressed)
            {
              if (const auto suppressed = ::ua::detail::suppressed_certificate_errors(result);
                  !suppressed.empty())
              {
                onSuppressed(request, suppressed);
              }
            }
          }
          callback(std::move(result));
        });
      return;
    }
    certStore->validate_certificate_async(std::move(request), callback);
  }

  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(VoidResult{er, er.shared_detail()});
  }
}

namespace
{

using ::ua::security_internal::slice_key_material;

class DeriveSymmetricKeysPshaOperation final
  : public ua::async::SelfOwningOperation<DeriveSymmetricKeysPshaOperation>
{
public:
  static void start(shared_ptr<const SecurityPolicy> policy, shared_ptr<SecureChannelContext> context,
    SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes, ByteString localNonce,
    ByteString remoteNonce, std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> callback)
  {
    launch(std::make_shared<DeriveSymmetricKeysPshaOperation>(std::move(policy),
      std::move(context),
      algorithm,
      numberOfBytes,
      std::move(localNonce),
      std::move(remoteNonce),
      std::move(callback)));
  }

  DeriveSymmetricKeysPshaOperation(shared_ptr<const SecurityPolicy> policy,
    shared_ptr<SecureChannelContext> context, SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    ByteString localNonce, ByteString remoteNonce,
    std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> callback)
    : SelfOwningOperation(context->strand(), context->logger), mPolicy(std::move(policy)),
      mContext(std::move(context)), mAlgorithm(algorithm), mNumberOfBytes(numberOfBytes),
      mLocalNonce(std::move(localNonce)), mRemoteNonce(std::move(remoteNonce)), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DeriveSymmetricKeysPshaOperation>;

  /// Two P-SHA derivations with the nonces swapped: local keys take the remote nonce as the secret
  /// and the local nonce as the seed, and the remote keys take them the other way round. Getting the
  /// pairing backwards is the classic way to produce keys that decrypt nothing, so the two calls sit
  /// four lines apart where the swap is visible rather than in two functions two hundred apart.
  ua::async::Task<> run()
  {
    try
    {
      auto localResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mContext->crypto->derive_symmetric_keys_async(
            mAlgorithm, mNumberOfBytes, mRemoteNonce, mLocalNonce, std::move(completion));
        });
      if (localResult.is_uncertain())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(localResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!localResult.is_good())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{localResult.status_code(),
          ErrorDetail::build(
            "DeriveKeyFailed", "Failed to derive symmetric keys for local security token", "SecurityPolicy")
            .cause(localResult.status_code())});
        co_return;
      }
      auto localKeys = slice_key_material(*mPolicy, std::move(localResult).value());

      auto remoteResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mContext->crypto->derive_symmetric_keys_async(
            mAlgorithm, mNumberOfBytes, mLocalNonce, mRemoteNonce, std::move(completion));
        });
      if (remoteResult.is_uncertain())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(remoteResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!remoteResult.is_good())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{remoteResult.status_code(),
          ErrorDetail::build(
            "DeriveKeyFailed", "Failed to derive symmetric keys for remote security token", "SecurityPolicy")
            .cause(remoteResult.status_code())});
        co_return;
      }
      auto remoteKeys = slice_key_material(*mPolicy, std::move(remoteResult).value());

      answer(SecurityPolicy::DeriveSymmetricKeysResult{
        std::make_pair(std::move(localKeys), std::move(remoteKeys))});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger,
        [&] { answer(SecurityPolicy::DeriveSymmetricKeysResult{failure, failure.shared_detail()}); })();
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(SecurityPolicy::DeriveSymmetricKeysResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(SecurityPolicy::DeriveSymmetricKeysResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  shared_ptr<const SecurityPolicy> mPolicy;
  shared_ptr<SecureChannelContext> mContext;
  SymmetricKeyDerivationAlgorithm mAlgorithm{SymmetricKeyDerivationAlgorithm::Invalid};
  size_t mNumberOfBytes{0};
  ByteString mLocalNonce;
  ByteString mRemoteNonce;
  std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> mCallback;
};

}  // namespace

// derive_symmetric_keys_psha: two P-SHA derivations with the nonces swapped - local keys from
// (secret = remoteNonce, seed = localNonce), remote keys from (secret = localNonce, seed = remoteNonce).
void SecurityPolicy::derive_symmetric_keys_psha_async(SymmetricKeyDerivationAlgorithm algorithm,
  shared_ptr<SecureChannelContext> context, ByteString localNonce, ByteString remoteNonce,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    check(context);
    check(context->crypto);

    const auto numberOfBytes =
      symmetric_signature_key_size() + symmetric_encryption_key_size() + symmetric_iv_size();

    started = true;
    DeriveSymmetricKeysPshaOperation::start(shared_from_this(),
      std::move(context),
      algorithm,
      numberOfBytes,
      std::move(localNonce),
      std::move(remoteNonce),
      std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DeriveSymmetricKeysResult{er, er.shared_detail()});
    }
  }
}

void SecurityPolicy::decode_message_chunk_async(shared_ptr<SecureChannelContext> context,
  ByteString messageChunk, std::function<void(DecodedMessageChunkResult)> callback) const
{
  try
  {
    check(context);
    auto chunkOwner = std::make_shared<ByteString>(std::move(messageChunk));
    const span<const byte> chunkView{*chunkOwner};
    // Keep the SecureChannelContext alive for the whole decode. The wrapped callback is threaded
    // through every flow step (each continuation holds the flow, which holds this callback), so
    // capturing the shared_ptr here prevents a concurrent channel teardown (~SecureChannelImpl
    // destroying its own shared_ptr<SecureChannelContext>) from freeing the context - and its
    // mRemoteCertificate / mCrypto / mStrand - while a flow is mid-flight on a crypto worker.
    // Without this the borrowed `SecureChannelContext&` in the decode flows dangles (TSan UAF at
    // start_decode_asymmetric_verify).
    decode_unknown_message_chunk_async(*context,
      chunkView,
      [chunkOwner, context, callback = std::move(callback)](DecodedMessageChunkResult result) mutable
      { callback(std::move(result)); });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    callback(DecodedMessageChunkResult{er, er.shared_detail()});
  }
}

void SecurityPolicy::encode_message_async(shared_ptr<SecureChannelContext> context, uint32_t requestId,
  shared_ptr<Structure> message, SendMessageChunk sendMessageChunk,
  std::function<void(VoidResult)> callback) const
{
  // Single-fire guard. encode_unknown_message_async fires the completion SYNCHRONOUSLY on its reject/error
  // paths from inside the try below, so a callback that throws would otherwise be caught by this catch (or
  // encode_unknown's own catch) and fired a second time  -  and the plain move-into-lambda pattern would even
  // fire a moved-from `callback` from the catch. Route every completion through `fireOnce`, which owns the
  // callback via a shared_ptr, fires it at most once, and swallows a throwing callback rather than letting
  // it escape (the design specification: never throw out of an async handler).
  auto callbackOwner = std::make_shared<std::function<void(VoidResult)>>(std::move(callback));
  auto fired = std::make_shared<bool>(false);
  auto fireOnce = [callbackOwner, fired](VoidResult result)
  {
    if (*fired)
    {
      return;
    }
    *fired = true;
    (*callbackOwner)(std::move(result));
  };
  try
  {
    check(context);
    // Keep the SecureChannelContext alive for the whole encode (same rationale as
    // decode_message_chunk_async): the encode flow borrows `SecureChannelContext&` and hops to
    // crypto workers, so the entry callback must own the context until the operation completes.
    encode_unknown_message_async(*context,
      requestId,
      std::move(message),
      std::move(sendMessageChunk),
      [context, fireOnce](VoidResult result) mutable { fireOnce(std::move(result)); });
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    fireOnce(VoidResult{er, er.shared_detail()});
  }
}

}  // namespace ua
