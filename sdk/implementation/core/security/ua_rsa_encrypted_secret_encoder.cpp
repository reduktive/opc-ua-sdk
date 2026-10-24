// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_rsa_encrypted_secret_encoder.h"
#include "ua_security_policy_internal.h"

#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_security_policy.h"
#include "ua_to_result.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstring>

namespace ua
{

namespace
{

// Source tags for ErrorDetail (client.tier0.rsa_encrypted_secret.<step>).
constexpr char sourceSetup[] = "client.tier0.rsa_encrypted_secret.setup";
constexpr char sourceEntropy[] = "client.tier0.rsa_encrypted_secret.entropy";
constexpr char sourceKeyDataEncrypt[] = "client.tier0.rsa_encrypted_secret.key_data_encrypt";
constexpr char sourcePayloadEncrypt[] = "client.tier0.rsa_encrypted_secret.payload_encrypt";
constexpr char sourceSign[] = "client.tier0.rsa_encrypted_secret.sign";

/// Encode the CommonHeader: SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime).
/// For the RSA variant the Certificate carries the server certificate SHA1 thumbprint (not the DER).
ByteString encode_common_header(string_view securityPolicyUri, span<const byte> certificateThumbprint)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, securityPolicyUri);
  encoder.encode(depth, ByteString{certificateThumbprint});
  encoder.encode(depth, DateTime::now());

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Encode the plaintext KeyData: SigningKey(ByteString) | EncryptingKey(ByteString) | IV(ByteString).
/// This is the plaintext that is subsequently RSA-OAEP-encrypted as one unit.
ByteString encode_key_data_plain(
  span<const byte> signingKey, span<const byte> encryptingKey, span<const byte> iv)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, ByteString{signingKey});
  encoder.encode(depth, ByteString{encryptingKey});
  encoder.encode(depth, ByteString{iv});

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Encode the plaintext payload body: Nonce(ByteString) | Secret(ByteString) (padding added separately).
ByteString encode_payload(span<const byte> nonce, span<const byte> secret)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, ByteString{nonce});
  encoder.encode(depth, ByteString{secret});

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Encode the ExtensionObject prefix: TypeId(NodeId) | EncodingMask(Byte=0x01) | Length(Int32 LE).
ByteString encode_prefix(uint32_t bodyLength)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, NodeId{DataTypeId::RsaEncryptedSecret});
  encoder.encode(depth, static_cast<uint8_t>(0x01));
  encoder.encode(depth, numeric_cast<int32_t>(bodyLength));

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Add block-cipher padding to bring the payload to the correct block size.
/// Format: payload + paddingBytes + PayloadPaddingSize(UInt16 LE); each padding byte = (paddingSize & 0xFF).
ByteString add_padding(span<const byte> payload, size_t blockSize)
{
  // Minimum padded size: payload + 2 bytes for PayloadPaddingSize field.
  auto contentWithSizeField = payload.size() + 2;
  auto remainder = contentWithSizeField % blockSize;
  auto paddingSize = (remainder == 0) ? 0 : (blockSize - remainder);
  auto totalSize = payload.size() + paddingSize + 2;

  ByteString padded;
  padded.resize(totalSize);
  std::memcpy(padded.data(), payload.data(), payload.size());

  auto paddingByte = numeric_cast<uint8_t>(paddingSize & 0xFF);
  for (size_t i = 0; i < paddingSize; ++i)
  {
    padded[payload.size() + i] = paddingByte;
  }

  // PayloadPaddingSize (UInt16 LE) at the end.
  auto ps = numeric_cast<uint16_t>(paddingSize);
  padded[totalSize - 2] = numeric_cast<uint8_t>(ps & 0xFF);
  padded[totalSize - 1] = numeric_cast<uint8_t>((ps >> 8) & 0xFF);

  return padded;
}

// RsaEncryptedSecret encode flow. Awaits (in order):
//   1. get_entropy          -> SigningKey | EncryptingKey | IV
//   2. asymmetric_encrypt   -> encrypted KeyData (server public key, RSA-OAEP)
//   3. symmetric_encrypt    -> encrypted payload (AES-CBC, EncryptingKey/IV)
//   4. symmetric_sign       -> HMAC over CommonHeader..encryptedPayload keyed by SigningKey
class EncryptRsaSecretOperation final : public ua::async::SelfOwningOperation<EncryptRsaSecretOperation>
{
public:
  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const X509Certificate> serverCertificate, ByteString serverNonce, ByteString secret,
    std::function<void(ByteStringResult)> callback)
  {
    launch(std::make_shared<EncryptRsaSecretOperation>(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(serverCertificate),
      std::move(serverNonce),
      std::move(secret),
      std::move(callback)));
  }

  EncryptRsaSecretOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const X509Certificate> serverCertificate, ByteString serverNonce, ByteString secret,
    std::function<void(ByteStringResult)> callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mPolicy(std::move(policy)),
      mCrypto(std::move(crypto)), mServerCertificate(std::move(serverCertificate)),
      mServerNonce(std::move(serverNonce)), mSecret(std::move(secret)), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncryptRsaSecretOperation>;

  /// Encrypt-then-MAC, in the order the standard states it (Part 4 7.41.6): one entropy draw sliced
  /// into SigningKey | EncryptingKey | IV, the KeyData RSA-encrypted to the server's public key, the
  /// payload symmetrically encrypted under that IV and key, and an HMAC over everything signed.
  ///
  /// The chain this replaces wrapped each step in its own try/catch that did the same thing - fail
  /// with `exception_to_status_code` - and guarded each completion with a `Step` enum against a
  /// second delivery. One outer catch says the first; `await_step`'s fire-once completion is the
  /// second.
  ua::async::Task<> run()
  {
    try
    {
      // The CommonHeader depends only on inputs. The Certificate field carries the server
      // certificate SHA1 thumbprint, not the full DER.
      mCommonHeader =
        encode_common_header(mPolicy->uri(), span<const byte>{mServerCertificate->thumbprint()});

      // --- one entropy draw for all three keys -----------------------------------------
      const auto signKeySize = mPolicy->symmetric_signature_key_size();
      const auto encKeySize = mPolicy->symmetric_encryption_key_size();
      const auto ivSize = mPolicy->symmetric_ciphertext_block_size();
      const auto totalBytes = signKeySize + encKeySize + ivSize;

      auto entropyResult = co_await await_step<ByteStringResult>([this, totalBytes](auto completion)
        { mCrypto->get_entropy_async(totalBytes, std::move(completion)); });
      if (!entropyResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          entropyResult.status_code(), Status::BadInternalError, sourceEntropy)});
        co_return;
      }

      auto entropy = std::move(entropyResult).value();
      const span<const byte> entropySpan = entropy;
      if (entropySpan.size() < signKeySize + encKeySize + ivSize)
      {
        answer(ByteStringResult{StatusCode{Status::BadInternalError},
          make_error_detail(
            "EntropyTooShort", "get_entropy returned fewer bytes than requested", sourceEntropy)});
        co_return;
      }
      mSigningKey = ByteString{entropySpan.subspan(0, signKeySize)};
      mEncryptingKey = ByteString{entropySpan.subspan(signKeySize, encKeySize)};
      mIv = ByteString{entropySpan.subspan(signKeySize + encKeySize, ivSize)};

      // --- KeyData, RSA-encrypted to the server public key -----------------------------
      // Plaintext KeyData = SigningKey | EncryptingKey | IV (each a ByteString).
      mKeyDataPlain = encode_key_data_plain(mSigningKey, mEncryptingKey, mIv);

      // Size the ciphertext buffer per the RSA block chunking: the backend encrypts the whole
      // plaintext block-by-block into this buffer in one call.
      const auto plainTextBlockSize = mPolicy->asymmetric_plaintext_block_size(mServerCertificate.get());
      const auto cipherTextBlockSize = mPolicy->asymmetric_ciphertext_block_size(mServerCertificate.get());
      if (plainTextBlockSize == 0)
      {
        answer(ByteStringResult{StatusCode{Status::BadSecurityChecksFailed},
          make_error_detail("PlaintextBlockSizeZero",
            "Asymmetric plaintext block size is zero for the server certificate",
            sourceKeyDataEncrypt)});
        co_return;
      }
      const auto numBlocks = (mKeyDataPlain.size() + plainTextBlockSize - 1) / plainTextBlockSize;
      mEncryptedKeyData.resize(numBlocks * cipherTextBlockSize);

      auto keyDataResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          mCrypto->asymmetric_encrypt_async(nullptr,
            mPolicy->asymmetric_encryption_algorithm(),
            mServerCertificate->public_key(),
            span<const byte>{mKeyDataPlain},
            span<byte>{mEncryptedKeyData},
            std::move(completion));
        });
      if (!keyDataResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          keyDataResult.status_code(), Status::BadInternalError, sourceKeyDataEncrypt)});
        co_return;
      }
      mKeyDataLength = numeric_cast<uint16_t>(mEncryptedKeyData.size());
      mKeyDataPlain.clear();  // no longer needed once encrypted

      // --- the payload, symmetrically encrypted under that IV and key -------------------
      // Plaintext payload = Nonce | Secret, padded to the symmetric cipher block size.
      auto payloadPlain = encode_payload(mServerNonce, mSecret);
      const auto blockSize = mPolicy->symmetric_ciphertext_block_size();
      mPayloadPadded = add_padding(payloadPlain, blockSize > 0 ? blockSize : 1);
      mEncryptedPayload.resize(mPayloadPadded.size());

      auto payloadResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          mCrypto->symmetric_encrypt_async(nullptr,
            mPolicy->symmetric_encryption_algorithm(),
            span<const byte>{mIv},
            span<const byte>{mEncryptingKey},
            span<const byte>{mPayloadPadded},
            span<byte>{mEncryptedPayload},
            std::move(completion));
        });
      if (!payloadResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          payloadResult.status_code(), Status::BadInternalError, sourcePayloadEncrypt)});
        co_return;
      }
      mPayloadPadded.clear();  // no longer needed once encrypted

      // --- the MAC over everything signed ----------------------------------------------
      build_signed_data();

      // The RSA variant's Signature is a symmetric MAC (HMAC-SHA256) keyed by SigningKey, not an
      // asymmetric signature. Both spans are members, so they outlive the call.
      auto signResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mCrypto->symmetric_sign_async(nullptr,
            mPolicy->symmetric_signature_algorithm(),
            span<const byte>{mSigningKey},
            span<const byte>{mSignedData},
            std::move(completion));
        });
      if (!signResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          signResult.status_code(), Status::BadInternalError, sourceSign)});
        co_return;
      }
      mSignature = std::move(signResult).value();

      answer(ByteStringResult{assemble_blob()});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      // A root task: an escaping exception would be stored in a promise nobody reads, and the
      // caller would wait for a blob that never came.
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(mLogger, [&] { answer(ByteStringResult{failure, failure.shared_detail()}); })();
    }
  }

  /// Signed region = CommonHeader | KeyDataLength(UInt16 LE) | encryptedKeyData | encryptedPayload.
  void build_signed_data()
  {
    mSignedData.resize(mCommonHeader.size() + 2 + mEncryptedKeyData.size() + mEncryptedPayload.size());
    size_t offset = 0;
    std::memcpy(&mSignedData[offset], mCommonHeader.data(), mCommonHeader.size());
    offset += mCommonHeader.size();
    mSignedData[offset] = numeric_cast<uint8_t>(mKeyDataLength & 0xFF);
    mSignedData[offset + 1] = numeric_cast<uint8_t>((mKeyDataLength >> 8) & 0xFF);
    offset += 2;
    std::memcpy(&mSignedData[offset], mEncryptedKeyData.data(), mEncryptedKeyData.size());
    offset += mEncryptedKeyData.size();
    std::memcpy(&mSignedData[offset], mEncryptedPayload.data(), mEncryptedPayload.size());
  }

  /// Length counts everything after the Length field = signedData | signature.
  ByteString assemble_blob() const
  {
    const auto bodyLength = numeric_cast<uint32_t>(mSignedData.size() + mSignature.size());
    auto prefix = encode_prefix(bodyLength);

    ByteString blob;
    blob.resize(prefix.size() + mSignedData.size() + mSignature.size());
    size_t offset = 0;
    std::memcpy(&blob[offset], prefix.data(), prefix.size());
    offset += prefix.size();
    std::memcpy(&blob[offset], mSignedData.data(), mSignedData.size());
    offset += mSignedData.size();
    std::memcpy(&blob[offset], mSignature.data(), mSignature.size());
    return blob;
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
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
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<const X509Certificate> mServerCertificate;
  ByteString mServerNonce;
  ByteString mSecret;

  ByteString mCommonHeader;

  ByteString mSigningKey;
  ByteString mEncryptingKey;
  ByteString mIv;

  ByteString mKeyDataPlain;  // plaintext KeyData; must outlive the asymmetric_encrypt call
  ByteString mEncryptedKeyData;
  uint16_t mKeyDataLength{0};

  ByteString mPayloadPadded;  // padded plaintext payload; must outlive the symmetric_encrypt call
  ByteString mEncryptedPayload;

  ByteString mSignedData;  // CommonHeader | KeyDataLength | encryptedKeyData | encryptedPayload
  ByteString mSignature;

  std::function<void(ByteStringResult)> mCallback;
};

}  // namespace

// RsaEncryptedSecret encode (Part 4 7.41.6), encrypt-then-MAC: one entropy draw sliced into
// SigningKey | EncryptingKey | IV, the KeyData RSA-encrypted to the server's public key, the payload
// (Nonce | Secret | padding) symmetrically encrypted under that IV and key, an HMAC keyed by
// SigningKey over CommonHeader | KeyDataLength | encKeyData | encPayload, and the blob assembled as
// TypeId | EncodingMask | Length | signedData | signature.
//
// On any failure the caller gets a source-tagged ErrorDetail; never a bare status, never a silent Good.
void encrypt_rsa_encrypted_secret_async(shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const X509Certificate> serverCertificate, ByteString serverNonce, ByteString secret,
  ua::Logger logger, std::function<void(ByteStringResult)> callback)
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    if (!policy || !crypto || !serverCertificate)
    {
      callback(ByteStringResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("MissingDependency",
          "Null policy, crypto, or server certificate passed to encrypt_rsa_encrypted_secret_async",
          sourceSetup)});
      return;
    }

    started = true;
    EncryptRsaSecretOperation::start(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(serverCertificate),
      std::move(serverNonce),
      std::move(secret),
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

}  // namespace ua
