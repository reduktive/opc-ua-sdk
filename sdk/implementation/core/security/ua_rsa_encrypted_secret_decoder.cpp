// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_secure_memory.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_rsa_encrypted_secret_decoder.h"

#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_security_policy.h"
#include "ua_security_policy_internal.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_x509_certificate.h"

#include <algorithm>

#include <cstring>

namespace ua
{

namespace
{

// Source tags for ErrorDetail (server.tier0.rsa_encrypted_secret.<step>).
constexpr char sourceSetup[] = "server.tier0.rsa_encrypted_secret.setup";
constexpr char sourceParse[] = "server.tier0.rsa_encrypted_secret.parse";
constexpr char sourceKeyDataDecrypt[] = "server.tier0.rsa_encrypted_secret.key_data_decrypt";
constexpr char sourceKeyDataParse[] = "server.tier0.rsa_encrypted_secret.key_data_parse";
constexpr char sourceVerify[] = "server.tier0.rsa_encrypted_secret.verify";
constexpr char sourcePayloadDecrypt[] = "server.tier0.rsa_encrypted_secret.payload_decrypt";
constexpr char sourcePayloadParse[] = "server.tier0.rsa_encrypted_secret.payload_parse";
constexpr char sourceHeader[] = "server.tier0.rsa_encrypted_secret.header";

/// The framing and region layout recovered by the synchronous pre-await parse. All positions and sizes are
/// byte offsets into the owning blob; nothing here has been decrypted yet.
struct ParsedFraming
{
  String securityPolicyUri;
  ByteString certificateThumbprint;
  DateTime signingTime;

  // Signed region = CommonHeader | KeyDataLength | encryptedKeyData | encryptedPayload (everything after
  // the Length field and before the trailing Signature).
  size_t signedRegionStart{0};
  size_t signedRegionSize{0};

  size_t encKeyDataStart{0};
  size_t encKeyDataSize{0};

  size_t encPayloadStart{0};
  size_t encPayloadSize{0};

  size_t signatureStart{0};
  size_t signatureSize{0};
};

/// Parse the ExtensionObject framing, CommonHeader, and KeyDataLength, and compute every region boundary.
/// Throws UaException{Bad_DecodingError} on any framing/bounds violation so the caller can source-tag a
/// single failure. Every read is bounds-guarded by the decoder or by the explicit checks here.
ParsedFraming parse_framing(span<const byte> blob, size_t signatureSize)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{blob};
  MemoryStream stream{device};
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  // 1. TypeId | EncodingMask | Length, then validate the ExtensionObject framing.
  NodeId typeId;
  uint8_t encodingMask = 0;
  int32_t length = 0;
  decoder.decode(depth, typeId);
  decoder.decode(depth, encodingMask);
  decoder.decode(depth, length);

  const size_t afterLength = stream.get_position();

  if (typeId != NodeId{DataTypeId::RsaEncryptedSecret})
  {
    throw UaException{Status::BadDecodingError,
      make_error_detail(
        "BadTypeId", "RsaEncryptedSecret blob has an unexpected ExtensionObject TypeId", sourceParse)};
  }
  if (encodingMask != 0x01)
  {
    throw UaException{Status::BadDecodingError,
      make_error_detail("BadEncodingMask",
        "RsaEncryptedSecret ExtensionObject EncodingMask is not 0x01 (ByteString body)",
        sourceParse)};
  }
  if (length < 0 || static_cast<size_t>(length) != blob.size() - afterLength)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("BadLength",
        "RsaEncryptedSecret Length does not equal the byte count following the Length field",
        sourceParse)
        .context(ua::ContextKeys::sizeActual, std::to_string(blob.size() - afterLength))
        .context(ua::ContextKeys::sizeMin, std::to_string(length < 0 ? 0 : length))};
  }

  ParsedFraming parsed;

  // 2. CommonHeader: SecurityPolicyUri | Certificate(thumbprint) | SigningTime. The signed region starts
  // here (immediately after the Length field).
  parsed.signedRegionStart = afterLength;
  decoder.decode(depth, parsed.securityPolicyUri);
  decoder.decode(depth, parsed.certificateThumbprint);
  decoder.decode(depth, parsed.signingTime);

  // 3. KeyDataLength(UInt16) then the raw encrypted KeyData ciphertext (no inner length prefix).
  uint16_t keyDataLength = 0;
  decoder.decode(depth, keyDataLength);
  const size_t encKeyDataStart = stream.get_position();

  // The Signature is the trailing symmetric-signature-size bytes; everything before it (after the Length
  // field) is signed. Validate every region fits inside the blob before slicing.
  if (blob.size() < afterLength + signatureSize)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("BadSignatureRegion",
        "RsaEncryptedSecret blob is too small to contain the CommonHeader and trailing Signature",
        sourceParse)
        .context(ua::ContextKeys::sizeActual, std::to_string(blob.size()))
        .context(ua::ContextKeys::sizeMin, std::to_string(afterLength + signatureSize))};
  }
  const size_t signedRegionEnd = blob.size() - signatureSize;

  if (encKeyDataStart > signedRegionEnd || keyDataLength > signedRegionEnd - encKeyDataStart)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build("BadKeyDataLength",
        "RsaEncryptedSecret KeyDataLength exceeds the bytes available before the Signature",
        sourceParse)
        .context(ua::ContextKeys::sizeActual, std::to_string(keyDataLength))
        .context(ua::ContextKeys::sizeMax,
          std::to_string(encKeyDataStart > signedRegionEnd ? 0 : signedRegionEnd - encKeyDataStart))};
  }

  parsed.encKeyDataStart = encKeyDataStart;
  parsed.encKeyDataSize = keyDataLength;
  parsed.encPayloadStart = encKeyDataStart + keyDataLength;
  parsed.encPayloadSize = signedRegionEnd - parsed.encPayloadStart;
  parsed.signedRegionSize = signedRegionEnd - parsed.signedRegionStart;
  parsed.signatureStart = signedRegionEnd;
  parsed.signatureSize = signatureSize;

  return parsed;
}

/// Validates the CommonHeader (OPC 10000-4 7.41.2.3 Table 187) against what decrypted the secret
/// (security review SESS-7(e)). Returns Bad_IdentityTokenInvalid naming the mismatch, or Good.
///
/// - SecurityPolicyUri: "used to determine what algorithms were used to encrypt and sign the data"
///   (7.41.2.3). The secret is decrypted with @p policy, so a secret claiming any other policy was not
///   produced for that decryption and is refused.
/// - Certificate: "The SHA1 hash of the DER form of the Certificate used to encrypt the KeyData"
///   (Table 189), so it must be the thumbprint of @p receiverCertificate, whose private key decrypted it.
///   No receiver certificate means nothing can match, and the secret is refused.
/// - SigningTime: Table 187 says only "When the Signature was created" and states no acceptance window;
///   freshness is carried by the Nonce, which the caller compares with its last serverNonce. Not checking
///   it is spec-permitted, and no window is invented here.
///
/// Run after the HMAC has authenticated the header. Cost: one string comparison and one certificate
/// thumbprint per secret.
StatusCode check_common_header(
  const ParsedFraming& framing, const SecurityPolicy& policy, const X509Certificate* receiverCertificate)
{
  const String decryptingPolicyUri = policy.uri();
  if (std::string_view{framing.securityPolicyUri} != std::string_view{decryptingPolicyUri})
  {
    return StatusCode{Status::BadIdentityTokenInvalid,
      ErrorDetail::build("EncryptedSecretPolicyMismatch",
        "The EncryptedSecret names a SecurityPolicy other than the one the Server decrypts it with",
        sourceHeader)
        .context(ua::ContextKeys::securityPolicy, std::string{std::string_view{decryptingPolicyUri}})};
  }
  const ByteString expected = receiverCertificate ? receiverCertificate->thumbprint() : ByteString{};
  if (expected.empty() ||
      !std::ranges::equal(span<const byte>{framing.certificateThumbprint}, span<const byte>{expected}))
  {
    return StatusCode{Status::BadIdentityTokenInvalid,
      make_error_detail("EncryptedSecretCertificateMismatch",
        "The RsaEncryptedSecret Certificate is not the thumbprint of the server certificate that decrypted "
        "it",
        sourceHeader)};
  }
  return StatusCode{Status::Good};
}

/// Slice SigningKey | EncryptingKey | IV out of the RSA-decrypted KeyData plaintext.
struct KeyMaterial
{
  ByteString signingKey;
  ByteString encryptingKey;
  ByteString iv;
};

KeyMaterial parse_key_material(span<const byte> keyDataPlain)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{keyDataPlain};
  MemoryStream stream{device};
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  KeyMaterial material;
  decoder.decode(depth, material.signingKey);
  decoder.decode(depth, material.encryptingKey);
  decoder.decode(depth, material.iv);
  return material;
}

/// Strip the trailing PayloadPadding | PayloadPaddingSize(UInt16 LE) from the decrypted payload, verifying
/// each padding byte equals (PayloadPaddingSize & 0xFF). Returns the unpadded prefix (Nonce | Secret).
RsaPayloadPrefixSizeResult validate_payload_padding(span<const byte> decrypted, bool acceptInvalidPadding)
{
  if (decrypted.size() < 2)
  {
    return RsaPayloadPrefixSizeResult{StatusCode{Status::BadDecodingError},
      make_error_detail("PayloadTooShort",
        "Decrypted RsaEncryptedSecret payload is too small to hold the PayloadPaddingSize field",
        sourcePayloadParse)};
  }

  const auto paddingSizeLow = static_cast<uint8_t>(decrypted[decrypted.size() - 2]);
  const auto paddingSizeHigh = static_cast<uint8_t>(decrypted[decrypted.size() - 1]);
  const auto paddingSize = numeric_cast<uint16_t>(paddingSizeLow | (paddingSizeHigh << 8));

  const auto totalPaddingBytes = numeric_cast<size_t>(paddingSize) + 2;  // padding + 2-byte size field
  if (totalPaddingBytes > decrypted.size())
  {
    return RsaPayloadPrefixSizeResult{StatusCode{Status::BadDecodingError},
      ErrorDetail::build("PayloadPaddingTooLarge",
        "RsaEncryptedSecret PayloadPaddingSize exceeds the decrypted payload size",
        sourcePayloadParse)
        .context(ua::ContextKeys::sizeActual, std::to_string(totalPaddingBytes))
        .context(ua::ContextKeys::sizeMax, std::to_string(decrypted.size()))};
  }

  const auto expectedPaddingByte = static_cast<byte>(paddingSize & 0xFF);
  const auto paddingStart = decrypted.size() - totalPaddingBytes;
  for (size_t i = paddingStart; !acceptInvalidPadding && i < decrypted.size() - 2; ++i)
  {
    if (decrypted[i] != expectedPaddingByte)
    {
      return RsaPayloadPrefixSizeResult{StatusCode{Status::BadDecodingError},
        make_error_detail("PayloadPaddingInconsistent",
          "RsaEncryptedSecret PayloadPadding byte does not equal (PayloadPaddingSize & 0xFF)",
          sourcePayloadParse)};
    }
  }

  return RsaPayloadPrefixSizeResult{paddingStart};
}

/// Parse Nonce | Secret from the unpadded decrypted payload prefix.
struct PayloadContent
{
  ByteString nonce;
  ByteString secret;
};

PayloadContent parse_payload_content(span<const byte> payload)
{
  const EncodingLimits limits;
  memory_stream_device::ExternalReadOnly device{payload};
  MemoryStream stream{device};
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};

  PayloadContent content;
  decoder.decode(depth, content.nonce);
  decoder.decode(depth, content.secret);
  return content;
}

// RsaEncryptedSecret decode flow. Awaits (in order):
//   1. asymmetric_decrypt   -> RSA-decrypt KeyData -> SigningKey | EncryptingKey | IV
//   2. symmetric_verify     -> HMAC over CommonHeader..encryptedPayload keyed by SigningKey (verify-then-use)
//   3. symmetric_decrypt    -> AES-CBC decrypt payload -> Nonce | Secret | padding
class DecryptRsaSecretOperation final : public ua::async::SelfOwningOperation<DecryptRsaSecretOperation>
{
public:
  DecryptRsaSecretOperation(const DecryptRsaSecretOperation&) = delete;
  DecryptRsaSecretOperation& operator=(const DecryptRsaSecretOperation&) = delete;
  DecryptRsaSecretOperation(DecryptRsaSecretOperation&&) = delete;
  DecryptRsaSecretOperation& operator=(DecryptRsaSecretOperation&&) = delete;

  /// DEF-4: the decrypted and derived secret bytes are scrubbed when the flow ends, whichever way.
  ~DecryptRsaSecretOperation()
  {
    ua::security::secure_clear(mKeyDataPlainBuffer);
    ua::security::secure_clear(mSigningKey);
    ua::security::secure_clear(mEncryptingKey);
    ua::security::secure_clear(mIv);
    ua::security::secure_clear(mDecryptedPayload);
  }

  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    ByteString data, shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const AsymmetricKeyPair> receiverKeyPair,
    shared_ptr<const X509Certificate> receiverCertificate, bool acceptInvalidPadding,
    std::function<void(RsaEncryptedSecretFieldsResult)> callback)
  {
    launch(std::make_shared<DecryptRsaSecretOperation>(std::move(strand),
      std::move(logger),
      std::move(data),
      std::move(policy),
      std::move(crypto),
      std::move(receiverKeyPair),
      std::move(receiverCertificate),
      acceptInvalidPadding,
      std::move(callback)));
  }

  DecryptRsaSecretOperation(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger,
    ByteString data, shared_ptr<const SecurityPolicy> policy, shared_ptr<const Crypto> crypto,
    shared_ptr<const AsymmetricKeyPair> receiverKeyPair,
    shared_ptr<const X509Certificate> receiverCertificate, bool acceptInvalidPadding,
    std::function<void(RsaEncryptedSecretFieldsResult)> callback)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mData(std::move(data)),
      mPolicy(std::move(policy)), mCrypto(std::move(crypto)), mReceiverKeyPair(std::move(receiverKeyPair)),
      mReceiverCertificate(std::move(receiverCertificate)), mAcceptInvalidPadding(acceptInvalidPadding),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecryptRsaSecretOperation>;

  /// Verify-then-use, in that order and for that reason: the KeyData is RSA-decrypted to recover the
  /// symmetric material, the HMAC over the signed region is checked BEFORE the payload is decrypted
  /// or trusted, and only then is the payload decrypted and parsed. A MAC mismatch fails with
  /// Bad_IdentityTokenInvalid and the payload is never AES-decrypted.
  ua::async::Task<> run()
  {
    try
    {
      // parse_framing throws UaException{Bad_DecodingError, <source-tagged detail>};
      // exception_to_status_code in the catch below preserves that rich StatusCode, so the
      // framing/bounds cause reaches the callback intact.
      mFraming = parse_framing(span<const byte>{mData}, mPolicy->symmetric_signature_size());

      // --- RSA-decrypt the KeyData with the receiver private key ------------------------
      // RSA-OAEP plaintext is never larger than the ciphertext, so sizing the output buffer to the
      // ciphertext length is always sufficient; the returned span views the actual recovered bytes.
      mKeyDataPlainBuffer.resize(mFraming.encKeyDataSize);

      auto keyDataResult = co_await await_step<Crypto::ByteSpanResult>(
        [this](auto completion)
        {
          mCrypto->asymmetric_decrypt_async(nullptr,
            mPolicy->asymmetric_encryption_algorithm(),
            mReceiverKeyPair,
            span<const byte>{mData}.subspan(mFraming.encKeyDataStart, mFraming.encKeyDataSize),
            span<byte>{mKeyDataPlainBuffer},
            std::move(completion));
        });
      // The key material is taken only from a Good answer: an Uncertain one is refused with
      // Bad_InternalError (CryptoAnswerUncertain, its code the cause), so the result holds no value either
      // way.
      if (keyDataResult.is_uncertain())
      {
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(
            keyDataResult.status_code(), sourceKeyDataDecrypt)}});
        co_return;
      }
      if (!keyDataResult.is_good())
      {
        answer(RsaEncryptedSecretFieldsResult{keyDataResult.status_code(),
          ErrorDetail::build("KeyDataDecryptFailed",
            "RSA decryption of the RsaEncryptedSecret KeyData failed",
            sourceKeyDataDecrypt)
            .cause(keyDataResult.status_code())});
        co_return;
      }

      // The parse has its own handler: a UaException here means malformed KeyData, which is a
      // decoding error naming the parse - not whatever exception_to_status_code would make of it.
      try
      {
        // The result span views mKeyDataPlainBuffer, which is alive for this scope.
        auto material = parse_key_material(keyDataResult.value());

        // Sanity-check the recovered key material against the policy sizes; a mismatch means
        // malformed KeyData (the RSA decrypt succeeded but the plaintext is not the expected shape).
        const auto signKeySize = mPolicy->symmetric_signature_key_size();
        const auto encKeySize = mPolicy->symmetric_encryption_key_size();
        const auto ivSize = mPolicy->symmetric_ciphertext_block_size();
        if (material.signingKey.size() != signKeySize || material.encryptingKey.size() != encKeySize ||
            material.iv.size() != ivSize)
        {
          answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
            make_error_detail("KeyMaterialSizeMismatch",
              "Recovered SigningKey/EncryptingKey/IV sizes do not match the security policy",
              sourceKeyDataParse)});
          co_return;
        }

        mSigningKey = std::move(material.signingKey);
        mEncryptingKey = std::move(material.encryptingKey);
        mIv = std::move(material.iv);
        // The RSA plaintext is no longer needed once the key material has been copied out.
        ua::security::secure_clear(mKeyDataPlainBuffer);  // DEF-4: scrubbed, not merely emptied
      }
      catch (const UaException&)
      {
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          make_error_detail("KeyDataParseFailed",
            "Failed to parse SigningKey/EncryptingKey/IV from the decrypted KeyData",
            sourceKeyDataParse)});
        co_return;
      }

      // --- verify the HMAC before the payload is decrypted or trusted -------------------
      // symmetric_verify recomputes HMAC(SigningKey, signedRegion) and constant-time-compares it to
      // the trailing Signature (CRYPTO_memcmp in the OpenSSL backend).
      auto verifyResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          const span<const byte> dataSpan{mData};
          mCrypto->symmetric_verify_async(nullptr,
            mPolicy->symmetric_signature_algorithm(),
            span<const byte>{mSigningKey},
            dataSpan.subspan(mFraming.signedRegionStart, mFraming.signedRegionSize),
            dataSpan.subspan(mFraming.signatureStart, mFraming.signatureSize),
            std::move(completion));
        });
      if (verifyResult.is_uncertain())
      {
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadIdentityTokenInvalid,
          ua::security_internal::uncertain_answer_detail(verifyResult.status_code(), sourceVerify)}});
        co_return;
      }
      if (!verifyResult.is_good())
      {
        // MAC mismatch (or verify failure): the blob was tampered with or the key material is wrong.
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadIdentityTokenInvalid},
          ErrorDetail::build("SignatureVerifyFailed",
            "RsaEncryptedSecret HMAC verification over the signed region failed",
            sourceVerify)
            .cause(verifyResult.status_code())});
        co_return;
      }

      // --- only now decrypt the payload -------------------------------------------------
      mDecryptedPayload.resize(mFraming.encPayloadSize);

      auto payloadResult = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          mCrypto->symmetric_decrypt_async(nullptr,
            mPolicy->symmetric_encryption_algorithm(),
            span<const byte>{mIv},
            span<const byte>{mEncryptingKey},
            span<const byte>{mData}.subspan(mFraming.encPayloadStart, mFraming.encPayloadSize),
            span<byte>{mDecryptedPayload},
            std::move(completion));
        });
      if (payloadResult.is_uncertain())
      {
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError,
          ua::security_internal::uncertain_answer_detail(
            payloadResult.status_code(), sourcePayloadDecrypt)}});
        co_return;
      }
      if (!payloadResult.is_good())
      {
        answer(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadDecodingError},
          ErrorDetail::build("PayloadDecryptFailed",
            "AES-CBC decryption of the RsaEncryptedSecret payload failed",
            sourcePayloadDecrypt)
            .cause(payloadResult.status_code())});
        co_return;
      }

      // --- the CommonHeader must name what decrypted it (SESS-7(e)) ------------------------
      // Checked once the whole secret has been verified and decrypted, so a refused header costs the
      // same work as an accepted one - and before the secret is parsed out of the payload, so a refusal
      // never leaves a parsed copy of the decrypted secret behind (DEF-4). The header is already
      // authenticated by the signature verified above.
      if (auto header = check_common_header(mFraming, *mPolicy, mReceiverCertificate.get()); header.is_bad())
      {
        answer(RsaEncryptedSecretFieldsResult{std::move(header)});
        co_return;
      }

      // --- strip the padding and parse Nonce | Secret -----------------------------------
      const auto prefixSize = validate_payload_padding(mDecryptedPayload, mAcceptInvalidPadding).value();
      auto content = parse_payload_content(span<const byte>{mDecryptedPayload}.first(prefixSize));

      RsaEncryptedSecretFields fields;
      fields.securityPolicyUri = std::move(mFraming.securityPolicyUri);
      fields.certificateThumbprint = std::move(mFraming.certificateThumbprint);
      fields.signingTime = mFraming.signingTime;
      fields.nonce = std::move(content.nonce);
      fields.secret = std::move(content.secret);
      answer(RsaEncryptedSecretFieldsResult{std::move(fields)});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn: whoever withdrew it answered the caller.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      // exception_to_status_code preserves a UaException's rich StatusCode (and its source-tagged
      // ErrorDetail from parse_framing / validate_payload_padding / parse_payload_content), so the
      // framing, padding and parse causes all survive.
      auto failure = ua::exception_to_status_code(std::current_exception());
      ua::async::guarded(
        mLogger, [&] { answer(RsaEncryptedSecretFieldsResult{failure, failure.shared_detail()}); })();
    }
  }

  /// The frame could not be allocated; the caller is owed its answer regardless.
  void fail_to_start(StatusCode status)
  {
    answer(RsaEncryptedSecretFieldsResult{status, status.shared_detail()});
  }

  /// Fire-once: the callback is moved out, so a second answer does nothing.
  void answer(RsaEncryptedSecretFieldsResult result)
  {
    if (auto callback = std::exchange(mCallback, nullptr))
    {
      callback(std::move(result));
    }
  }

  ByteString mData;  // owns the input blob for the operation's lifetime
  shared_ptr<const SecurityPolicy> mPolicy;
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<const AsymmetricKeyPair> mReceiverKeyPair;
  shared_ptr<const X509Certificate> mReceiverCertificate;
  bool mAcceptInvalidPadding{false};

  ParsedFraming mFraming;

  // RSA-decrypt output buffer; the recovered plaintext view returned by asymmetric_decrypt points
  // into it, so it must outlive the completion that parses the key material.
  ByteString mKeyDataPlainBuffer;

  ByteString mSigningKey;
  ByteString mEncryptingKey;
  ByteString mIv;

  ByteString mDecryptedPayload;

  std::function<void(RsaEncryptedSecretFieldsResult)> mCallback;
};

}  // namespace

RsaPayloadPrefixSizeResult validate_rsa_secret_payload_padding(
  span<const byte> decrypted, bool acceptInvalidPadding)
{
  return validate_payload_padding(decrypted, acceptInvalidPadding);
}

bool is_rsa_encrypted_secret(span<const byte> blob)
{
  // A real RsaEncryptedSecret carries a cleartext ExtensionObject prefix whose first field is the
  // TypeId NodeId; the legacy section 7.41.2.2 secret is an opaque RSA ciphertext whose leading bytes are
  // effectively random, so decoding a NodeId either throws or yields a mismatching id. Any decode
  // failure is treated as "not an RsaEncryptedSecret"  -  the caller falls back to the legacy path.
  try
  {
    const EncodingLimits limits;
    memory_stream_device::ExternalReadOnly device{blob};
    MemoryStream stream{device};
    UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
    const StackDepth depth{1024};

    NodeId typeId;
    decoder.decode(depth, typeId);
    return typeId == NodeId{DataTypeId::RsaEncryptedSecret};
  }
  catch (...)
  {
    return false;
  }
}

// RsaEncryptedSecret decode flow:
//   decrypt_rsa_encrypted_secret_async
//     -> [parse framing: TypeId | EncodingMask | Length | CommonHeader | KeyDataLength; region bounds - sync]
//     -> start_rsa_secret_key_data_decrypt         (RSA-decrypt KeyData with the receiver private key)
//     -> on_rsa_secret_key_data_decrypt_complete   [strand-guarded]  (slice + size-check
//     SigningKey|EncKey|IV)
//     -> start_rsa_secret_signature_verify         (HMAC VERIFY over the signed region - verify-then-use)
//     -> on_rsa_secret_signature_verify_complete   [strand-guarded]
//     -> start_rsa_secret_payload_decrypt          (AES-CBC decrypt Nonce | Secret | padding)
//     -> on_rsa_secret_payload_decrypt_complete    [strand-guarded]
//     -> finalize_rsa_secret                       (strip padding, parse Nonce | Secret)
//     -> complete_rsa_secret  |  fail_rsa_secret
//
// The MAC is verified BEFORE the payload is decrypted or trusted; a MAC mismatch fails with
// Bad_IdentityTokenInvalid and the payload is never AES-decrypted. On any failure (framing, RSA decrypt,
// verify, AES decrypt, padding/parse): fail_rsa_secret with a source-tagged ErrorDetail; never a bare
// status, never a silent Good.
void decrypt_rsa_encrypted_secret_async(ByteString data, shared_ptr<const SecurityPolicy> policy,
  shared_ptr<const Crypto> crypto, boost::asio::strand<boost::asio::any_io_executor> strand,
  shared_ptr<const AsymmetricKeyPair> receiverKeyPair, shared_ptr<const X509Certificate> receiverCertificate,
  bool acceptInvalidPadding, ua::Logger logger, std::function<void(RsaEncryptedSecretFieldsResult)> callback)
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    if (!policy || !crypto || !receiverKeyPair)
    {
      callback(RsaEncryptedSecretFieldsResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("MissingDependency",
          "Null policy, crypto, or receiver key pair passed to decrypt_rsa_encrypted_secret_async",
          sourceSetup)});
      return;
    }

    started = true;
    DecryptRsaSecretOperation::start(std::move(strand),
      std::move(logger),
      std::move(data),
      std::move(policy),
      std::move(crypto),
      std::move(receiverKeyPair),
      std::move(receiverCertificate),
      acceptInvalidPadding,
      std::move(callback));
  }
  catch (...)
  {
    // Once the operation exists it owns the callback and answers through `fail_to_start`, including
    // when its frame cannot be allocated. Only a throw BEFORE that leaves the callback here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(RsaEncryptedSecretFieldsResult{er, er.shared_detail()});
    }
  }
}

}  // namespace ua
