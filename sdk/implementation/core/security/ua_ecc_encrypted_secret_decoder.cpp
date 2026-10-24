// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_secure_memory.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_security_policy_internal.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"

#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_node_id.h"
#include "ua_error_detail.h"
#include "ua_memory_stream.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_resource_budgets.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace ua
{

namespace
{

/// Parse the common header fields that precede KeyData.
struct CommonHeader
{
  String securityPolicyUri;
  ByteString certificate;
  DateTime signingTime;
};

CommonHeader parse_common_header(span<const byte> data, size_t& outPosition)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{data};
  MemoryStream stream{device};
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  NodeId typeId;
  uint8_t encodingMask = 0;
  int32_t length = 0;
  decoder.decode(depth, typeId);
  decoder.decode(depth, encodingMask);
  decoder.decode(depth, length);
  if (typeId != NodeId{DataTypeId::EccEncryptedSecret} || encodingMask != 0x01)
  {
    throw UaException{Status::BadDecodingError,
      make_error_detail("InvalidEncryptedSecretType",
        "EccEncryptedSecret requires its namespace-zero TypeId and Binary encoding mask",
        "decrypt_ecc_encrypted_secret")};
  }
  const auto bodyStart = stream.get_position();
  if (length < 0 || numeric_cast<size_t>(length) != data.size() - bodyStart)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("InvalidEncryptedSecretLength",
        "EccEncryptedSecret Length does not match the bytes following the Length field",
        "decrypt_ecc_encrypted_secret")
        .context(ua::ContextKeys::sizeActual, data.size() - bodyStart)};
  }

  CommonHeader header;
  decoder.decode(depth, header.securityPolicyUri);
  decoder.decode(depth, header.certificate);
  decoder.decode(depth, header.signingTime);

  outPosition = stream.get_position();
  return header;
}

/// Parse KeyDataLength + KeyData (SenderPublicKey + ReceiverPublicKey).
struct KeyDataFields
{
  uint16_t keyDataLength{0};
  ByteString senderPublicKey;
  ByteString receiverPublicKey;
  size_t keyDataStartPosition{0};  // Position of KeyDataLength field in the blob
  size_t endPosition{0};  // Position after KeyData
};

KeyDataFields parse_key_data(span<const byte> data, size_t startPosition)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{data};
  MemoryStream stream{device};
  stream.seek_from_start(startPosition);
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  KeyDataFields fields;
  fields.keyDataStartPosition = startPosition;

  decoder.decode(depth, fields.keyDataLength);
  decoder.decode(depth, fields.senderPublicKey);
  decoder.decode(depth, fields.receiverPublicKey);

  fields.endPosition = stream.get_position();

  // Validate KeyDataLength matches actual key data size
  auto actualKeyDataSize = fields.endPosition - fields.keyDataStartPosition - sizeof(uint16_t);
  if (fields.keyDataLength != actualKeyDataSize)
  {
    throw UaException{Status::BadDecodingError, nullptr};
  }

  return fields;
}

/// Build the HKDF salt for EccEncryptedSecret key derivation.
ByteString build_secret_salt(
  size_t numberOfBytes, span<const byte> senderPublicKey, span<const byte> receiverPublicKey)
{
  static constexpr string_view secretLabel = "opcua-secret";
  auto saltSize = 2 + secretLabel.size() + senderPublicKey.size() + receiverPublicKey.size();
  ByteString salt;
  salt.resize(saltSize);

  auto lengthBytes = numeric_cast<uint16_t>(numberOfBytes);
  salt[0] = numeric_cast<uint8_t>(lengthBytes & 0xFF);
  salt[1] = numeric_cast<uint8_t>((lengthBytes >> 8) & 0xFF);

  size_t offset = 2;
  std::memcpy(&salt[offset], secretLabel.data(), secretLabel.size());
  offset += secretLabel.size();
  std::memcpy(&salt[offset], senderPublicKey.data(), senderPublicKey.size());
  offset += senderPublicKey.size();
  std::memcpy(&salt[offset], receiverPublicKey.data(), receiverPublicKey.size());

  return salt;
}

/// Strip PKCS-style padding from decrypted EccEncryptedSecret payload.
span<const byte> strip_padding(span<const byte> decrypted)
{
  if (decrypted.size() < 2)
  {
    throw UaException{Status::BadDecodingError, nullptr};
  }

  auto paddingSizeLow = static_cast<uint8_t>(decrypted[decrypted.size() - 2]);
  auto paddingSizeHigh = static_cast<uint8_t>(decrypted[decrypted.size() - 1]);
  auto paddingSize = numeric_cast<uint16_t>(paddingSizeLow | (paddingSizeHigh << 8));

  auto totalPaddingBytes = numeric_cast<size_t>(paddingSize) + 2;  // padding + 2-byte size field
  if (totalPaddingBytes > decrypted.size())
  {
    throw UaException{Status::BadDecodingError, nullptr};
  }

  // Verify all padding bytes have the expected value
  auto expectedPaddingByte = static_cast<byte>(paddingSize & 0xFF);
  auto paddingStart = decrypted.size() - totalPaddingBytes;
  for (size_t i = paddingStart; i < decrypted.size() - 2; ++i)
  {
    if (decrypted[i] != expectedPaddingByte)
    {
      throw UaException{Status::BadDecodingError, nullptr};
    }
  }

  return decrypted.subspan(0, paddingStart);
}

/// Parse Nonce and Secret from the stripped (unpadded) decrypted payload.
struct DecryptedContent
{
  ByteString nonce;
  ByteString secret;
};

DecryptedContent parse_decrypted_payload(span<const byte> payload)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{payload};
  MemoryStream stream{device};
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  DecryptedContent content;
  decoder.decode(depth, content.nonce);
  decoder.decode(depth, content.secret);

  return content;
}

// EccEncryptedSecret decode flow. Awaits (in order, conditionally):
//   1. asymmetric_verify          (Crypto, only when remoteCertificate is non-null)
//   2. calculate_shared_secret    (Crypto)
//   3. derive_symmetric_keys      (Crypto)
//   4. symmetric_verify_and_decrypt (Crypto, AEAD)
class DecryptEccSecretOperation final : public ua::async::SelfOwningOperation<DecryptEccSecretOperation>
{
public:
  DecryptEccSecretOperation(const DecryptEccSecretOperation&) = delete;
  DecryptEccSecretOperation& operator=(const DecryptEccSecretOperation&) = delete;
  DecryptEccSecretOperation(DecryptEccSecretOperation&&) = delete;
  DecryptEccSecretOperation& operator=(DecryptEccSecretOperation&&) = delete;

  /// DEF-4: the decrypted and derived secret bytes are scrubbed when the flow ends, whichever way.
  ~DecryptEccSecretOperation()
  {
    ua::security::secure_clear(mLocalEphemeralPrivateKey);
    ua::security::secure_clear(mSharedSecret);
    ua::security::secure_clear(mEncryptionKey);
    ua::security::secure_clear(mIvBytes);
    ua::security::secure_clear(mDecryptedPayload);
  }

  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    ByteString data, shared_ptr<const SecPolEphemeralKey> policy, shared_ptr<const Crypto> crypto,
    ByteString localEphemeralPrivateKey, ByteString localEphemeralPublicKey,
    shared_ptr<const X509Certificate> remoteCertificate,
    std::function<void(EccEncryptedSecretFieldsResult)>& callback)
  {
    launch(std::make_shared<DecryptEccSecretOperation>(std::move(strand),
      std::move(logger),
      std::move(data),
      std::move(policy),
      std::move(crypto),
      std::move(localEphemeralPrivateKey),
      std::move(localEphemeralPublicKey),
      std::move(remoteCertificate),
      callback));
  }

  DecryptEccSecretOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    ByteString data, shared_ptr<const SecPolEphemeralKey> policy, shared_ptr<const Crypto> crypto,
    ByteString localEphemeralPrivateKey, ByteString localEphemeralPublicKey,
    shared_ptr<const X509Certificate> remoteCertificate,
    std::function<void(EccEncryptedSecretFieldsResult)>& callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mData(std::move(data)),
      mPolicy(std::move(policy)), mCrypto(std::move(crypto)),
      mLocalEphemeralPrivateKey(std::move(localEphemeralPrivateKey)),
      mLocalEphemeralPublicKey(std::move(localEphemeralPublicKey)),
      mRemoteCertificate(std::move(remoteCertificate)), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecryptEccSecretOperation>;

  /// EccEncryptedSecret decode (Part 4 7.41.6): parse the framing, check the receiver key is ours,
  /// verify the sender's signature BEFORE decrypting anything, then ECDH, derive, decrypt and parse.
  ///
  /// The framing and validation below ran in the entry function, which had already moved the
  /// callback into the flow - so its own catch handler invoked a moved-from `std::function`. Owning
  /// the answer from construction is what makes that impossible rather than merely unlikely.
  ua::async::Task<> run()
  {
    try
    {
      const span<const byte> dataSpan{mData};

      // 1. CommonHeader.
      size_t headerEnd = 0;
      try
      {
        mCommonHeader = parse_common_header(dataSpan, headerEnd);
      }
      catch (...)
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          ErrorDetail::build("HeaderParseFailed",
            "Failed to parse EccEncryptedSecret common header",
            "decrypt_ecc_encrypted_secret")
            .cause(ua::exception_to_status_code(std::current_exception()))});
        co_return;
      }

      // 2. KeyDataLength + KeyData.
      try
      {
        mKeyData = parse_key_data(dataSpan, headerEnd);
      }
      catch (...)
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          make_error_detail("KeyDataParseFailed",
            "Failed to parse EccEncryptedSecret key data",
            "decrypt_ecc_encrypted_secret")});
        co_return;
      }

      // 3. The ReceiverPublicKey has to be the ephemeral key we published.
      if (!std::ranges::equal(
            span<const byte>{mKeyData.receiverPublicKey}, span<const byte>{mLocalEphemeralPublicKey}))
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadIdentityTokenInvalid},
          make_error_detail("ReceiverKeyMismatch",
            "ReceiverPublicKey does not match server ephemeral key",
            "decrypt_ecc_encrypted_secret")});
        co_return;
      }

      // 4. Split the encrypted payload from the signature. The signature is produced with the
      // sender's application-certificate key, whose curve may differ from the UserTokenPolicy curve
      // (Part 6 6.8.3 permits a token policy different from the SecureChannel policy), so its size is
      // the policy's signature size for that certificate: two field elements for ECDSA, the EdDSA
      // signature length, or one modulus for the RSA certificate of an RSA_DH policy. The encoder sizes
      // it the same way.
      const auto signatureSize = mPolicy->asymmetric_signature_size(mRemoteCertificate.get());
      const auto remainingBytes = mData.size() - mKeyData.endPosition;
      if (remainingBytes < signatureSize)
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          ErrorDetail::build("InsufficientSignatureBytes",
            "Insufficient bytes remaining for signature",
            "decrypt_ecc_encrypted_secret")
            .context(ua::ContextKeys::sizeActual, std::to_string(remainingBytes))
            .context(ua::ContextKeys::sizeMin, std::to_string(signatureSize))});
        co_return;
      }

      mEncryptedPayloadSize = remainingBytes - signatureSize;
      mEncryptedPayloadStart = mKeyData.endPosition;
      mSignatureBytes =
        ByteString{dataSpan.subspan(mEncryptedPayloadStart + mEncryptedPayloadSize, signatureSize)};

      // 5. Verify before decrypting, when a remote certificate is available to verify against.
      if (mRemoteCertificate)
      {
        auto verifyResult = co_await await_step<VoidResult>(
          [this](auto completion)
          {
            const span<const byte> data{mData};
            const auto signedDataSize = mEncryptedPayloadStart + mEncryptedPayloadSize;
            mCrypto->asymmetric_verify_async(nullptr,
              mPolicy->asymmetric_signature_algorithm(),
              mRemoteCertificate->public_key(),
              data.first(signedDataSize),
              data.subspan(mEncryptedPayloadStart + mEncryptedPayloadSize, mSignatureBytes.size()),
              std::move(completion));
          },
          [](DecryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
        if (!verifyResult.is_good())
        {
          answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadSecurityChecksFailed},
            ua::security_internal::not_good_answer_detail(
              verifyResult.status_code(), "decrypt_ecc_encrypted_secret")});
          co_return;
        }
      }

      // --- ECDH against the sender's ephemeral public key -------------------------------
      auto sharedSecretResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mCrypto->calculate_shared_secret_async(mPolicy->ephemeral_key_algorithm(),
            std::move(mLocalEphemeralPrivateKey),
            mKeyData.senderPublicKey,
            std::move(completion));
        },
        [](DecryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!sharedSecretResult.is_good())
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadSecurityChecksFailed},
          ua::security_internal::not_good_answer_detail(
            sharedSecretResult.status_code(), "decrypt_ecc_encrypted_secret")});
        co_return;
      }
      mSharedSecret = std::move(sharedSecretResult).value();

      // --- derive the decryption key and IV ---------------------------------------------
      const auto encKeySize = mPolicy->symmetric_encryption_key_size();
      const auto ivSize = mPolicy->symmetric_iv_size();
      const auto numberOfBytes = encKeySize + ivSize;
      auto salt = build_secret_salt(numberOfBytes, mKeyData.senderPublicKey, mKeyData.receiverPublicKey);

      auto derivedResult = co_await await_step<ByteStringResult>(
        [this, numberOfBytes, &salt](auto completion)
        {
          mCrypto->derive_symmetric_keys_async(mPolicy->key_derivation_algorithm(),
            numberOfBytes,
            mSharedSecret,
            salt,
            salt,
            std::move(completion));
        },
        [](DecryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!derivedResult.is_good())
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadSecurityChecksFailed},
          ua::security_internal::not_good_answer_detail(
            derivedResult.status_code(), "decrypt_ecc_encrypted_secret")});
        co_return;
      }
      auto keyMaterial = std::move(derivedResult).value();
      const span<const byte> keyMaterialSpan = keyMaterial;
      mEncryptionKey = ByteString{keyMaterialSpan.subspan(0, encKeySize)};
      mIvBytes = ByteString{keyMaterialSpan.subspan(encKeySize, ivSize)};
      ua::security::secure_clear(keyMaterial);  // DEF-4: the derived block outlives its slices otherwise

      // --- decrypt the payload ----------------------------------------------------------
      const auto encryptedPayload = dataSpan.subspan(mEncryptedPayloadStart, mEncryptedPayloadSize);
      const auto aeadTagSize = mPolicy->symmetric_signature_size();
      if (encryptedPayload.size() < aeadTagSize)
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          ErrorDetail::build("AeadPayloadTooSmall",
            "Encrypted payload too small for AEAD authentication tag",
            "decrypt_ecc_encrypted_secret")
            .context(ua::ContextKeys::sizeActual, std::to_string(encryptedPayload.size()))
            .context(ua::ContextKeys::sizeMin, std::to_string(aeadTagSize))});
        co_return;
      }
      const auto cipherTextSize = encryptedPayload.size() - aeadTagSize;
      mDecryptedPayload.resize(cipherTextSize);

      ByteString cipherTextOwned{encryptedPayload.subspan(0, cipherTextSize)};
      const span<const byte> cipherTextSpan{cipherTextOwned};
      const span<byte> plainTextSpan{mDecryptedPayload};

      auto aeadResult = co_await await_step<Crypto::SymmetricVerifyAndDecryptOutputResult>(
        [this,
          &cipherTextOwned,
          cipherTextSpan,
          plainTextSpan,
          encryptedPayload,
          cipherTextSize,
          aeadTagSize](auto completion)
        {
          // Part 6 6.8.3: the associated data is every header of the EncryptedSecret, TypeId through KeyData,
          // so a header the signature did not cover (no certificate to verify it with) still fails the tag.
          mCrypto->symmetric_verify_and_decrypt_async(mPolicy->symmetric_encryption_algorithm(),
            ByteString{mIvBytes},
            ByteString{mEncryptionKey},
            std::move(cipherTextOwned),
            cipherTextSpan,
            span<const byte>{mData}.first(mEncryptedPayloadStart),
            encryptedPayload.subspan(cipherTextSize, aeadTagSize),
            std::move(mDecryptedPayload),
            plainTextSpan,
            std::move(completion));
        },
        [](DecryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!aeadResult.is_good())
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadIdentityTokenInvalid},
          ua::security_internal::not_good_answer_detail(
            aeadResult.status_code(), "decrypt_ecc_encrypted_secret")});
        co_return;
      }
      mDecryptedPayload = std::move(aeadResult).value().plainTextBuffer.value_or(ByteString{});

      // --- the CommonHeader must name the policy that decrypted it (SESS-7(e)) ------------
      // OPC 10000-4 7.41.2.3: the SecurityPolicyUri is "used to determine what algorithms were used to
      // encrypt and sign the data", so a secret claiming a policy other than the one it was decrypted
      // with was not produced for that decryption. The Certificate is the Client's signing Certificate
      // and "may be null or empty if the SigningCertificate is known to the receiver" (Table 190); the
      // signature is verified with the channel's Client certificate, so the field is not compared.
      // SigningTime states no acceptance window (Table 187); freshness is the caller's Nonce check.
      // Checked once the whole secret has been verified and decrypted, so a refused header costs the
      // same work as an accepted one. Cost: one string comparison per secret.
      if (const String decryptingPolicyUri = mPolicy->uri();
          std::string_view{mCommonHeader.securityPolicyUri} != std::string_view{decryptingPolicyUri})
      {
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadIdentityTokenInvalid,
          ErrorDetail::build("EncryptedSecretPolicyMismatch",
            "The EncryptedSecret names a SecurityPolicy other than the one the Server decrypts it with",
            "decrypt_ecc_encrypted_secret")
            .context(ua::ContextKeys::securityPolicy, std::string{std::string_view{decryptingPolicyUri}})}});
        co_return;
      }

      // --- strip the padding and parse Nonce | Secret -----------------------------------
      EccEncryptedSecretFields fields;
      try
      {
        auto content = parse_decrypted_payload(strip_padding(mDecryptedPayload));

        fields.securityPolicyUri = std::move(mCommonHeader.securityPolicyUri);
        fields.certificate = std::move(mCommonHeader.certificate);
        fields.signingTime = mCommonHeader.signingTime;
        fields.senderPublicKey = std::move(mKeyData.senderPublicKey);
        fields.receiverPublicKey = std::move(mKeyData.receiverPublicKey);
        fields.signature = std::move(mSignatureBytes);
        fields.nonce = std::move(content.nonce);
        fields.secret = std::move(content.secret);
      }
      catch (const UaException&)
      {
        // A UaException here means the plaintext is not the expected shape, which is a decoding
        // error naming the parse - not whatever exception_to_status_code would make of it.
        answer(EccEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          make_error_detail("PayloadParseFailed",
            "Failed to strip padding or parse decrypted payload",
            "decrypt_ecc_encrypted_secret")});
        co_return;
      }
      answer(EccEncryptedSecretFieldsResult{std::move(fields)});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      answer(EccEncryptedSecretFieldsResult{failure, failure.shared_detail()});
    }
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(EccEncryptedSecretFieldsResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(EccEncryptedSecretFieldsResult result) noexcept
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      ::ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
    }
  }

  ByteString mData;  // owns the input blob for the operation's lifetime
  shared_ptr<const SecPolEphemeralKey> mPolicy;
  shared_ptr<const Crypto> mCrypto;
  ByteString mLocalEphemeralPrivateKey;  // consumed for ECDH
  ByteString mLocalEphemeralPublicKey;
  shared_ptr<const X509Certificate> mRemoteCertificate;

  CommonHeader mCommonHeader;
  KeyDataFields mKeyData;
  size_t mEncryptedPayloadStart{0};
  size_t mEncryptedPayloadSize{0};
  ByteString mSignatureBytes;  // owned signature copy for the result struct

  ByteString mSharedSecret;
  ByteString mEncryptionKey;
  ByteString mIvBytes;
  ByteString mDecryptedPayload;

  std::function<void(EccEncryptedSecretFieldsResult)> mCallback;
};

}  // namespace

// decrypt_ecc_encrypted_secret_async starts DecryptEccSecretOperation, which parses the CommonHeader and the
// KeyData, checks the ReceiverPublicKey and the lengths, verifies the signature (when a remote certificate is
// given), agrees the shared secret, derives the key and IV, opens the payload with the policy's AEAD cipher
// and parses the nonce and secret. Every failure answers the callback once with its status and ErrorDetail.
void decrypt_ecc_encrypted_secret_async(ByteString data, shared_ptr<const SecPolEphemeralKey> eccPolicy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ByteString localEphemeralPrivateKey, ByteString localEphemeralPublicKey,
  shared_ptr<const X509Certificate> remoteCertificate, ua::Logger logger,
  std::function<void(EccEncryptedSecretFieldsResult)> callback)
{
  // Construction borrows the callback until its final, non-throwing member initialization.
  try
  {
    if (!eccPolicy || !crypto)
    {
      ::ua::detail::invoke_user_callback(logger,
        callback,
        EccEncryptedSecretFieldsResult{StatusCode{Status::BadInvalidArgument},
          make_error_detail("MissingDependency",
            "Null policy or crypto passed to decrypt_ecc_encrypted_secret_async",
            "decrypt_ecc_encrypted_secret")});
      return;
    }

    DecryptEccSecretOperation::start(std::move(strand),
      logger,
      std::move(data),
      std::move(eccPolicy),
      std::move(crypto),
      std::move(localEphemeralPrivateKey),
      std::move(localEphemeralPublicKey),
      std::move(remoteCertificate),
      callback);
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(logger,
      callback,
      EccEncryptedSecretFieldsResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua
