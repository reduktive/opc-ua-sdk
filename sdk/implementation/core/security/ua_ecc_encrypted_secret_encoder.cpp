// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_secure_memory.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_ecc_encrypted_secret_encoder.h"
#include "ua_security_policy_internal.h"

#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_node_id.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_memory_stream.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_to_result.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace ua
{

namespace
{

/// Build the HKDF salt for EccEncryptedSecret key derivation.
/// Salt = L(2 LE) | "opcua-secret" | SenderPublicKey | ReceiverPublicKey
/// L is the derived key material length in bytes (Part 6 section 6.8.4).
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

/// Encode the CommonHeader: SecurityPolicyUri(String) | Certificate(ByteString) | SigningTime(DateTime)
ByteString encode_common_header(string_view securityPolicyUri, span<const byte> certificate)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, securityPolicyUri);
  encoder.encode(depth, ByteString{certificate});
  encoder.encode(depth, DateTime::now());

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Encode KeyData: SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
/// Returns the encoded bytes (without the KeyDataLength prefix - caller adds it).
ByteString encode_key_data_body(span<const byte> senderPublicKey, span<const byte> receiverPublicKey)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  const CodecNamespaceContext nsConfig;
  UaBinaryEncoder encoder{nsConfig, stream};
  const StackDepth depth{1024};

  encoder.encode(depth, ByteString{senderPublicKey});
  encoder.encode(depth, ByteString{receiverPublicKey});

  auto data = device.move_storage_out();
  return ByteString{span<const byte>{data}};
}

/// Encode the payload: Nonce(ByteString) | Secret(ByteString)
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

/// Append PayloadPadding and PayloadPaddingSize(UInt16 LE) to the encoded Nonce | Secret (Part 6 6.8.3).
/// Every ephemeral-key policy seals with an AEAD cipher, for which BlockSize is 16: the padded payload is a
/// multiple of 16 bytes, and a padding that would leave the secret and its padding under one block gets a
/// block more, so a short secret's length is hidden. Each padding byte is the low byte of the padding size.
ByteString add_padding(span<const byte> payload, size_t secretLength)
{
  constexpr size_t blockSize = 16;
  const auto dataLength = payload.size() + 2;  // the encoded Nonce and Secret, then PayloadPaddingSize
  auto paddingSize = (dataLength % blockSize == 0) ? 0 : (blockSize - dataLength % blockSize);
  if (paddingSize + secretLength < blockSize)
    paddingSize += blockSize;
  auto totalSize = payload.size() + paddingSize + 2;

  ByteString padded;
  padded.resize(totalSize);
  std::memcpy(padded.data(), payload.data(), payload.size());

  auto paddingByte = numeric_cast<uint8_t>(paddingSize & 0xFF);
  for (size_t i = 0; i < paddingSize; ++i)
  {
    padded[payload.size() + i] = paddingByte;
  }

  // PayloadPaddingSize (UInt16 LE) at the end
  auto ps = numeric_cast<uint16_t>(paddingSize);
  padded[totalSize - 2] = numeric_cast<uint8_t>(ps & 0xFF);
  padded[totalSize - 1] = numeric_cast<uint8_t>((ps >> 8) & 0xFF);

  return padded;
}

// EccEncryptedSecret encode flow. Awaits (in order):
//   1. create_ephemeral_keys      (Crypto)
//   2. calculate_shared_secret    (Crypto)
//   3. derive_symmetric_keys      (Crypto)
//   4. symmetric_encrypt_and_sign (Crypto, AEAD)
//   5. asymmetric_sign            (Crypto, only when clientKeyPair is non-null)
class EncryptEccSecretOperation final : public ua::async::SelfOwningOperation<EncryptEccSecretOperation>
{
public:
  EncryptEccSecretOperation(const EncryptEccSecretOperation&) = delete;
  EncryptEccSecretOperation& operator=(const EncryptEccSecretOperation&) = delete;
  EncryptEccSecretOperation(EncryptEccSecretOperation&&) = delete;
  EncryptEccSecretOperation& operator=(EncryptEccSecretOperation&&) = delete;

  /// The secret, the ephemeral private key and the bytes derived from them are scrubbed when the flow ends,
  /// whichever way, as the decoder does.
  ~EncryptEccSecretOperation()
  {
    ua::security::secure_clear(mSecret);
    ua::security::secure_clear(mClientEphemeralPrivateKey);
    ua::security::secure_clear(mSharedSecret);
    ua::security::secure_clear(mEncryptionKey);
    ua::security::secure_clear(mIv);
  }

  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecPolEphemeralKey> policy, shared_ptr<const Crypto> crypto,
    ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
    shared_ptr<const AsymmetricKeyPair> clientKeyPair, ByteString serverNonce, ByteString secret,
    std::function<void(ByteStringResult)>& callback)
  {
    launch(std::make_shared<EncryptEccSecretOperation>(std::move(strand),
      std::move(logger),
      std::move(policy),
      std::move(crypto),
      std::move(serverEphemeralPublicKey),
      std::move(clientCertificate),
      std::move(clientKeyPair),
      std::move(serverNonce),
      std::move(secret),
      callback));
  }

  EncryptEccSecretOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    shared_ptr<const SecPolEphemeralKey> policy, shared_ptr<const Crypto> crypto,
    ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
    shared_ptr<const AsymmetricKeyPair> clientKeyPair, ByteString serverNonce, ByteString secret,
    std::function<void(ByteStringResult)>& callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mPolicy(std::move(policy)),
      mCrypto(std::move(crypto)), mServerEphemeralPublicKey(std::move(serverEphemeralPublicKey)),
      mClientCertificate(std::move(clientCertificate)), mClientKeyPair(std::move(clientKeyPair)),
      mServerNonce(std::move(serverNonce)), mSecret(std::move(secret)), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncryptEccSecretOperation>;

  /// EccEncryptedSecret encode (Part 4 7.41.6): an ephemeral key pair, ECDH against the server's
  /// ephemeral public key, keys derived from that shared secret, the payload encrypted under them,
  /// and - when a client key pair was supplied - an ECDSA signature over the signed region.
  ua::async::Task<> run()
  {
    try
    {
      // The CommonHeader depends only on inputs.
      auto clientCertDer = mClientCertificate ? mClientCertificate->der_encoding() : ByteString{};
      mCommonHeader = encode_common_header(mPolicy->uri(), clientCertDer);

      // --- the client's ephemeral key pair ----------------------------------------------
      auto ephemeralResult = co_await await_step<Crypto::EphemeralKeyPairResult>([this](auto completion)
        { mCrypto->create_ephemeral_keys_async(mPolicy->ephemeral_key_algorithm(), std::move(completion)); },
        [](EncryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!ephemeralResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          ephemeralResult.status_code(), Status::BadInternalError, "encrypt_ecc_encrypted_secret")});
        co_return;
      }
      auto ephemeral = std::move(ephemeralResult).value();
      mClientEphemeralPublicKey = std::move(ephemeral.publicKey);
      mClientEphemeralPrivateKey = std::move(ephemeral.privateKey);

      // The KeyData body can be encoded once the client's ephemeral public key exists.
      mKeyDataBody = encode_key_data_body(mClientEphemeralPublicKey, mServerEphemeralPublicKey);
      mKeyDataLength = numeric_cast<uint16_t>(mKeyDataBody.size());

      // --- ECDH against the server's ephemeral public key -------------------------------
      auto sharedSecretResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mCrypto->calculate_shared_secret_async(mPolicy->ephemeral_key_algorithm(),
            mClientEphemeralPrivateKey,
            mServerEphemeralPublicKey,
            std::move(completion));
        },
        [](EncryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!sharedSecretResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          sharedSecretResult.status_code(), Status::BadInternalError, "encrypt_ecc_encrypted_secret")});
        co_return;
      }
      mSharedSecret = std::move(sharedSecretResult).value();

      // --- derive the encryption key and IV from it -------------------------------------
      const auto encKeySize = mPolicy->symmetric_encryption_key_size();
      const auto ivSize = mPolicy->symmetric_iv_size();
      const auto numberOfBytes = encKeySize + ivSize;
      auto salt = build_secret_salt(numberOfBytes, mClientEphemeralPublicKey, mServerEphemeralPublicKey);

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
        [](EncryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!derivedResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          derivedResult.status_code(), Status::BadInternalError, "encrypt_ecc_encrypted_secret")});
        co_return;
      }
      auto keyMaterial = std::move(derivedResult).value();
      const span<const byte> keyMaterialSpan = keyMaterial;
      mEncryptionKey = ByteString{keyMaterialSpan.subspan(0, encKeySize)};
      mIv = ByteString{keyMaterialSpan.subspan(encKeySize, ivSize)};
      ua::security::secure_clear(keyMaterial);  // the derived block outlives its slices otherwise

      // --- the headers, which the AEAD tag covers ---------------------------------------
      // Plaintext payload = Nonce(ByteString) | Secret(ByteString) | PayloadPadding | PayloadPaddingSize.
      // `paddedPayload` is a local of this frame, so it stays alive across the await.
      auto paddedPayload = add_padding(encode_payload(mServerNonce, mSecret), mSecret.size());

      // Part 4 Table 183: Length counts every byte after it, the signature included. It is one of the headers
      // the associated data covers (Part 6 6.8.3), so it is written before the payload is sealed: the
      // ciphertext is as long as the plaintext, and the tag follows it.
      size_t signatureSize = 0;
      if (mClientKeyPair != nullptr)
        signatureSize = mPolicy->asymmetric_signature_size(mClientCertificate.get());
      const auto bodyLength =
        numeric_cast<int32_t>(mCommonHeader.size() + 2 + mKeyDataBody.size() + paddedPayload.size() +
                              mPolicy->symmetric_signature_size() + signatureSize);
      memory_stream_device::Dynamic prefixDevice;
      MemoryStream prefixStream{prefixDevice};
      const CodecNamespaceContext namespaceContext;
      UaBinaryEncoder prefixEncoder{namespaceContext, prefixStream};
      const StackDepth depth{1024};
      prefixEncoder.encode(depth, NodeId{DataTypeId::EccEncryptedSecret});
      prefixEncoder.encode(depth, uint8_t{0x01});
      prefixEncoder.encode(depth, bodyLength);
      const auto prefix = prefixDevice.move_storage_out();

      // The headers: TypeId through KeyData. They are the associated data of the payload, and the start of
      // the bytes Figure 39 signs.
      mHeader.resize(prefix.size() + mCommonHeader.size() + 2 + mKeyDataBody.size());
      size_t offset = 0;
      std::memcpy(mHeader.data(), prefix.data(), prefix.size());
      offset += prefix.size();
      std::memcpy(mHeader.data() + offset, mCommonHeader.data(), mCommonHeader.size());
      offset += mCommonHeader.size();
      mHeader[offset] = numeric_cast<uint8_t>(mKeyDataLength & 0xFF);
      mHeader[offset + 1] = numeric_cast<uint8_t>((mKeyDataLength >> 8) & 0xFF);
      offset += 2;
      std::memcpy(mHeader.data() + offset, mKeyDataBody.data(), mKeyDataBody.size());

      // --- seal the payload --------------------------------------------------------------
      // AEAD encrypt: ciphertext (same size) plus an authentication tag.
      ByteString cipherText;
      cipherText.resize(paddedPayload.size());
      const span<const byte> plainTextSpan{paddedPayload};
      const span<byte> cipherTextSpan{cipherText};

      auto aeadResult = co_await await_step<Crypto::SymmetricEncryptAndSignOutputResult>(
        [this, &paddedPayload, &cipherText, plainTextSpan, cipherTextSpan](auto completion)
        {
          mCrypto->symmetric_encrypt_and_sign_async(mPolicy->symmetric_encryption_algorithm(),
            ByteString{mIv},
            ByteString{mEncryptionKey},
            std::move(paddedPayload),
            plainTextSpan,
            span<const byte>{mHeader},
            std::move(cipherText),
            cipherTextSpan,
            std::move(completion));
        },
        [](EncryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
      if (!aeadResult.is_good())
      {
        answer(ByteStringResult{ua::security_internal::not_good_answer(
          aeadResult.status_code(), Status::BadInternalError, "encrypt_ecc_encrypted_secret")});
        co_return;
      }
      auto output = std::move(aeadResult).value();
      if (!output.cipherTextBuffer.has_value())
      {
        answer(ByteStringResult{StatusCode{Status::BadInternalError},
          make_error_detail("AeadOutputMissing",
            "AEAD encrypt produced no ciphertext buffer",
            "encrypt_ecc_encrypted_secret")});
        co_return;
      }
      const auto& ct = output.cipherTextBuffer.value();
      const auto& tag = output.signature;

      // Figure 39 signs every byte before the Signature: the headers, the ciphertext and the tag after it.
      mSignedData.resize(mHeader.size() + ct.size() + tag.size());
      std::memcpy(mSignedData.data(), mHeader.data(), mHeader.size());
      std::memcpy(mSignedData.data() + mHeader.size(), ct.data(), ct.size());
      std::memcpy(mSignedData.data() + mHeader.size() + ct.size(), tag.data(), tag.size());

      if (mClientKeyPair != nullptr)
      {
        auto signResult = co_await await_step<ByteStringResult>(
          [this](auto completion)
          {
            mCrypto->asymmetric_sign_async(nullptr,
              mPolicy->asymmetric_signature_algorithm(),
              mClientKeyPair,
              span<const byte>{mSignedData},
              std::move(completion));
          },
          [](EncryptEccSecretOperation& self, StatusCode status) { self.fail_to_start(std::move(status)); });
        if (!signResult.is_good())
        {
          answer(ByteStringResult{ua::security_internal::not_good_answer(
            signResult.status_code(), Status::BadInternalError, "encrypt_ecc_encrypted_secret")});
          co_return;
        }
        mSignature = std::move(signResult).value();
      }
      // No client key pair means no signing was requested; the signature stays empty.

      // Append the signature to the complete signed envelope.
      ByteString blob;
      blob.resize(mSignedData.size() + mSignature.size());
      std::memcpy(blob.data(), mSignedData.data(), mSignedData.size());
      std::memcpy(blob.data() + mSignedData.size(), mSignature.data(), mSignature.size());
      answer(ByteStringResult{std::move(blob)});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      auto failure = ua::exception_to_status_code(std::current_exception());
      answer(ByteStringResult{failure, failure.shared_detail()});
    }
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(ByteStringResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(ByteStringResult result) noexcept
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      ::ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
    }
  }

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  shared_ptr<const Crypto> mCrypto;
  ByteString mServerEphemeralPublicKey;
  shared_ptr<const X509Certificate> mClientCertificate;
  shared_ptr<const AsymmetricKeyPair> mClientKeyPair;
  ByteString mServerNonce;
  ByteString mSecret;

  ByteString mCommonHeader;

  ByteString mClientEphemeralPublicKey;
  ByteString mClientEphemeralPrivateKey;
  ByteString mKeyDataBody;
  uint16_t mKeyDataLength{0};
  ByteString mSharedSecret;
  ByteString mEncryptionKey;
  ByteString mIv;
  ByteString mHeader;
  ByteString mSignedData;
  ByteString mSignature;

  std::function<void(ByteStringResult)> mCallback;
};

}  // namespace

// encrypt_ecc_encrypted_secret_async starts EncryptEccSecretOperation, which encodes the CommonHeader,
// creates the ephemeral key pair, agrees the shared secret, derives the key and IV, seals the payload with
// the policy's AEAD cipher and, when a client key pair is given, signs the envelope. Every failure answers
// the callback once with its status and ErrorDetail.
void encrypt_ecc_encrypted_secret_async(shared_ptr<const SecPolEphemeralKey> eccPolicy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  ByteString serverEphemeralPublicKey, shared_ptr<const X509Certificate> clientCertificate,
  shared_ptr<const AsymmetricKeyPair> clientKeyPair, ByteString serverNonce, ByteString secret,
  ua::Logger logger, std::function<void(ByteStringResult)> callback)
{
  // Construction borrows the callback until its final, non-throwing member initialization.
  try
  {
    if (!eccPolicy || !crypto)
    {
      ::ua::detail::invoke_user_callback(logger,
        callback,
        ByteStringResult{StatusCode{Status::BadInvalidArgument},
          make_error_detail("MissingDependency",
            "Null policy or crypto passed to encrypt_ecc_encrypted_secret_async",
            "encrypt_ecc_encrypted_secret")});
      return;
    }

    EncryptEccSecretOperation::start(std::move(strand),
      logger,
      std::move(eccPolicy),
      std::move(crypto),
      std::move(serverEphemeralPublicKey),
      std::move(clientCertificate),
      std::move(clientKeyPair),
      std::move(serverNonce),
      std::move(secret),
      callback);
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      logger, callback, ByteStringResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua
