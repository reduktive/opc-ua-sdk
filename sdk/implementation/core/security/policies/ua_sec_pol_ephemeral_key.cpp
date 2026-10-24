// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_ephemeral_key.h"
#include "ua_callback_safety.h"
#include "ua_security_policy_internal.h"
#include "ua_binary_codec.h"
#include "ua_certificate_store.h"
#include "ua_connection_protocol_limits.h"
#include "ua_error_detail.h"
#include "ua_memory_stream.h"
#include "ua_null_stream.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_secure_channel_context.h"
#include "ua_secure_memory.h"
#include "ua_stack_utilities.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include "fmt/format.h"

#include <climits>
#include <variant>

namespace ua
{

using namespace stack_utils;

SecPolEphemeralKey::SecPolEphemeralKey(const EphemeralKeyPolicyParameters& parameters) noexcept
  : mParameters(&parameters)
{}

const EphemeralKeyPolicyParameters& SecPolEphemeralKey::parameters() const noexcept
{
  return *mParameters;
}

SecurityPolicyId SecPolEphemeralKey::id() const
{
  return mParameters->id;
}

String SecPolEphemeralKey::uri() const
{
  return String{mParameters->uri};
}

CertificateType SecPolEphemeralKey::certificate_type() const
{
  return mParameters->certificateType;
}

bool SecPolEphemeralKey::is_authenticated() const
{
  return true;
}

bool SecPolEphemeralKey::is_rsa() const
{
  return std::holds_alternative<RsaCertificateRules>(mParameters->certificateKeyRules);
}

bool SecPolEphemeralKey::is_ecc() const
{
  return std::holds_alternative<EccCertificateRules>(mParameters->certificateKeyRules);
}

size_t SecPolEphemeralKey::nonce_length() const
{
  // Part 6 6.8.1: zero-padded X || Y for the ECDSA curves, the RFC 7748 encoding for the Edwards curves;
  // 6.9 Table 72: the 384-byte ffdhe3072 public value.
  switch (mParameters->ephemeralKeyAlgorithm)
  {
  case EphemeralKeyAlgorithm::EccNistP256:
  case EphemeralKeyAlgorithm::EccBrainpoolP256r1:
    return 64;
  case EphemeralKeyAlgorithm::EccNistP384:
  case EphemeralKeyAlgorithm::EccBrainpoolP384r1:
    return 96;
  case EphemeralKeyAlgorithm::EccCurve25519:
    return 32;
  case EphemeralKeyAlgorithm::EccCurve448:
    return 56;
  case EphemeralKeyAlgorithm::RsaDhFfdhe3072:
    return 384;
  case EphemeralKeyAlgorithm::Invalid:
    break;
  }
  return 0;
}

size_t SecPolEphemeralKey::symmetric_plaintext_block_size() const
{
  return 1;
}

size_t SecPolEphemeralKey::asymmetric_plaintext_block_size(const X509Certificate*) const
{
  return 0;
}

size_t SecPolEphemeralKey::symmetric_ciphertext_block_size() const
{
  return 1;
}

size_t SecPolEphemeralKey::asymmetric_ciphertext_block_size(const X509Certificate*) const
{
  return 0;
}

size_t SecPolEphemeralKey::symmetric_signature_size() const
{
  return tagLength;
}

size_t SecPolEphemeralKey::asymmetric_signature_size(const X509Certificate* certificate) const
{
  if (is_rsa())
  {
    // RSA-PKCS15-SHA2-256: one modulus-sized block.
    if (!certificate)
    {
      return 0;
    }
    return certificate->public_key_bit_length() / CHAR_BIT;
  }
  // The signature is made with the certificate's key, and a policy may admit a certificate on another
  // curve than its ephemeral key (a P-256 policy admits P-384 issuers), so the certificate's curve sizes
  // the r||s pair when it is known (review CRY-12: a P-384 signature was split at 64 bytes).
  const auto curve = certificate != nullptr ? certificate->key_algorithm() : certificate_key_algorithm();
  switch (curve)
  {
  case CertificateKeyAlgorithm::EccNistP256:
  case CertificateKeyAlgorithm::EccBrainpoolP256r1:
  case CertificateKeyAlgorithm::EccCurve25519:
    return 64;
  case CertificateKeyAlgorithm::EccNistP384:
  case CertificateKeyAlgorithm::EccBrainpoolP384r1:
    return 96;
  case CertificateKeyAlgorithm::EccBrainpoolP512r1:
    return 128;
  case CertificateKeyAlgorithm::EccNistP521:
    return 132;
  case CertificateKeyAlgorithm::EccCurve448:
    return 114;
  case CertificateKeyAlgorithm::Invalid:
  case CertificateKeyAlgorithm::Rsa:
    break;
  }
  return 0;
}

size_t SecPolEphemeralKey::symmetric_signature_key_size() const
{
  return 0;
}

size_t SecPolEphemeralKey::symmetric_encryption_key_size() const
{
  return mParameters->symmetricEncryptionAlgorithm == SymmetricEncryptionAlgorithm::Aes128Gcm ? 16 : 32;
}

size_t SecPolEphemeralKey::symmetric_iv_size() const
{
  return ivLength;
}

size_t SecPolEphemeralKey::min_asymmetric_key_length() const
{
  const auto* rsa = std::get_if<RsaCertificateRules>(&mParameters->certificateKeyRules);
  return rsa != nullptr ? rsa->minKeyLength : 0;
}

size_t SecPolEphemeralKey::max_asymmetric_key_length() const
{
  const auto* rsa = std::get_if<RsaCertificateRules>(&mParameters->certificateKeyRules);
  return rsa != nullptr ? rsa->maxKeyLength : 0;
}

AsymmetricEncryptionAlgorithm SecPolEphemeralKey::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::Invalid;
}

AsymmetricSignatureAlgorithm SecPolEphemeralKey::asymmetric_signature_algorithm() const
{
  return mParameters->asymmetricSignatureAlgorithm;
}

String SecPolEphemeralKey::asymmetric_signature_algorithm_uri() const
{
  // Part 4 1.05.07 section 7.36: SignatureData.algorithm is null for these policies.
  return {};
}

SymmetricEncryptionAlgorithm SecPolEphemeralKey::symmetric_encryption_algorithm() const
{
  return mParameters->symmetricEncryptionAlgorithm;
}

SymmetricSignatureAlgorithm SecPolEphemeralKey::symmetric_signature_algorithm() const
{
  switch (mParameters->symmetricEncryptionAlgorithm)
  {
  case SymmetricEncryptionAlgorithm::Aes128Gcm:
    return SymmetricSignatureAlgorithm::Aes128Gcm;
  case SymmetricEncryptionAlgorithm::Aes256Gcm:
    return SymmetricSignatureAlgorithm::Aes256Gcm;
  case SymmetricEncryptionAlgorithm::ChaCha20Poly1305:
    return SymmetricSignatureAlgorithm::ChaCha20Poly1305;
  case SymmetricEncryptionAlgorithm::Invalid:
  case SymmetricEncryptionAlgorithm::Aes128Cbc:
  case SymmetricEncryptionAlgorithm::Aes256Cbc:
    break;
  }
  return SymmetricSignatureAlgorithm::Invalid;
}

EphemeralKeyAlgorithm SecPolEphemeralKey::ephemeral_key_algorithm() const
{
  return mParameters->ephemeralKeyAlgorithm;
}

bool SecPolEphemeralKey::secure_channel_enhancements() const
{
  return true;
}

HashAlgorithm SecPolEphemeralKey::certificate_thumbprint_algorithm() const
{
  return mParameters->certificateThumbprintAlgorithm;
}

CertificateKeyAlgorithm SecPolEphemeralKey::certificate_key_algorithm() const noexcept
{
  return end_entity_key_algorithm(mParameters->certificateKeyRules);
}

CertificateKeyAlgorithm SecPolEphemeralKey::higher_ca_certificate_key_algorithm() const noexcept
{
  const auto* ecc = std::get_if<EccCertificateRules>(&mParameters->certificateKeyRules);
  return ecc != nullptr ? ecc->higherCaCurve : CertificateKeyAlgorithm::Rsa;
}

SymmetricKeyDerivationAlgorithm SecPolEphemeralKey::key_derivation_algorithm() const noexcept
{
  return mParameters->keyDerivationAlgorithm;
}

VoidResult SecPolEphemeralKey::check_certificate_compliance(
  const X509Certificate& certificate, const X509Certificate& signer, CertificateChainPosition position) const
{
  if (const auto violation =
        check_certificate_key_rules(mParameters->certificateKeyRules, certificate, signer, position))
  {
    return certificate_policy_refusal(violation->rule, violation->summary, certificate, position);
  }
  return {};
}

namespace
{

ByteString build_salt(
  string_view label, const ByteString& firstNonce, const ByteString& secondNonce, size_t numberOfBytes)
{
  // Salt = L(2 bytes LE) | label | firstNonce | secondNonce
  auto labelBytes = as_bytes(span{label.data(), label.size()});
  auto totalSize = 2 + labelBytes.size() + firstNonce.size() + secondNonce.size();
  ByteString salt;
  salt.resize(totalSize);
  auto lengthBytes = numeric_cast<uint16_t>(numberOfBytes);
  salt[0] = numeric_cast<uint8_t>(lengthBytes & 0xFF);
  salt[1] = numeric_cast<uint8_t>((lengthBytes >> 8) & 0xFF);
  size_t offset = 2;
  std::memcpy(&salt[offset], labelBytes.data(), labelBytes.size());
  offset += labelBytes.size();
  std::memcpy(&salt[offset], firstNonce.data(), firstNonce.size());
  offset += firstNonce.size();
  std::memcpy(&salt[offset], secondNonce.data(), secondNonce.size());
  return salt;
}

/// The shared secret, then two HKDF derivations - one for the server's keys, one for the client's (Part 6
/// 6.8.1; 6.9 for RSA_DH).
///
/// Which nonce plays which part depends on the role, and the two salts differ only by their label
/// and the order of the nonces. The input keying material chains (6.8.1 Step 2): a renewal's IKM is its
/// shared secret XOR the IKM of the token before it, which the context holds. The new IKM replaces the
/// held one only after both derivations succeed, and not at all once the channel has released its secrets.
/// The ephemeral private key is single-use: the operation takes it out of the context when it starts and
/// scrubs it on every exit.
class DeriveSymmetricKeysEphemeralKeyOperation final
  : public ua::async::SelfOwningOperation<DeriveSymmetricKeysEphemeralKeyOperation>
{
public:
  static void start(shared_ptr<const SecPolEphemeralKey> policy, shared_ptr<SecureChannelContext> context,
    ByteString localNonce, ByteString remoteNonce, ChannelRole role, size_t numberOfBytes,
    std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> callback)
  {
    launch(std::make_shared<DeriveSymmetricKeysEphemeralKeyOperation>(std::move(policy),
      std::move(context),
      std::move(localNonce),
      std::move(remoteNonce),
      role,
      numberOfBytes,
      std::move(callback)));
  }

  DeriveSymmetricKeysEphemeralKeyOperation(shared_ptr<const SecPolEphemeralKey> policy,
    shared_ptr<SecureChannelContext> context, ByteString localNonce, ByteString remoteNonce, ChannelRole role,
    size_t numberOfBytes, std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> callback)
    : SelfOwningOperation(context->strand(), context->logger), mPolicy(std::move(policy)),
      mContext(std::move(context)), mLocalNonce(std::move(localNonce)), mRemoteNonce(std::move(remoteNonce)),
      mRole(role), mNumberOfBytes(numberOfBytes), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DeriveSymmetricKeysEphemeralKeyOperation>;

  ua::async::Task<> run()
  {
    try
    {
      mLocalPrivateKey = std::exchange(mContext->localEphemeralPrivateKey, ByteString{});

      // --- the shared secret; the nonces here are ephemeral public keys ------------------
      auto secretResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mContext->crypto->calculate_shared_secret_async(
            mPolicy->ephemeral_key_algorithm(), mLocalPrivateKey, mRemoteNonce, std::move(completion));
        });
      if (secretResult.is_uncertain())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(secretResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!secretResult.is_good())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{secretResult.status_code(),
          ErrorDetail::build(
            "DeriveKeyFailed", "Failed to calculate the ephemeral-key shared secret", "SecurityPolicy")
            .cause(secretResult.status_code())});
        co_return;
      }
      mIkm = std::move(secretResult).value();
      if (!mContext->keyAgreementIkm.empty())
      {
        // Same policy, same group: the secrets of one channel are all the same length.
        if (mContext->keyAgreementIkm.size() != mIkm.size())
        {
          answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError},
            ErrorDetail::build("IkmLengthMismatch",
              "The shared secret and the chained key material differ in length",
              "SecPolEphemeralKey")
              .context(ua::ContextKeys::sizeActual, mIkm.size())
              .context(ua::ContextKeys::sizeExpected, mContext->keyAgreementIkm.size())});
          co_return;
        }
        for (size_t i = 0; i < mIkm.size(); ++i)
          mIkm[i] ^= mContext->keyAgreementIkm[i];
      }

      // Which nonce is whose depends on the role (Part 6 6.8.2); the two salts then differ only by
      // label and nonce order.
      const auto& serverNonce = (mRole == ChannelRole::Server) ? mLocalNonce : mRemoteNonce;
      const auto& clientNonce = (mRole == ChannelRole::Server) ? mRemoteNonce : mLocalNonce;
      mServerSalt = build_salt("opcua-server", serverNonce, clientNonce, mNumberOfBytes);
      mClientSalt = build_salt("opcua-client", clientNonce, serverNonce, mNumberOfBytes);

      // --- the server's keys -------------------------------------------------------------
      auto serverResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mContext->crypto->derive_symmetric_keys_async(mPolicy->key_derivation_algorithm(),
            mNumberOfBytes,
            mIkm,
            mServerSalt,
            mServerSalt,
            std::move(completion));
        });
      if (serverResult.is_uncertain())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(serverResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!serverResult.is_good())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{serverResult.status_code(),
          ErrorDetail::build(
            "DeriveKeyFailed", "Failed to derive server symmetric keys via HKDF", "SecurityPolicy")
            .cause(serverResult.status_code())});
        co_return;
      }
      auto serverKeys = ua::security_internal::slice_key_material(*mPolicy, std::move(serverResult).value());

      // --- the client's keys -------------------------------------------------------------
      auto clientResult = co_await await_step<ByteStringResult>(
        [this](auto completion)
        {
          mContext->crypto->derive_symmetric_keys_async(mPolicy->key_derivation_algorithm(),
            mNumberOfBytes,
            mIkm,
            mClientSalt,
            mClientSalt,
            std::move(completion));
        });
      if (clientResult.is_uncertain())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadInternalError,
          ua::security_internal::uncertain_answer_detail(clientResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!clientResult.is_good())
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{clientResult.status_code(),
          ErrorDetail::build(
            "DeriveKeyFailed", "Failed to derive client symmetric keys via HKDF", "SecurityPolicy")
            .cause(clientResult.status_code())});
        co_return;
      }
      auto clientKeys = ua::security_internal::slice_key_material(*mPolicy, std::move(clientResult).value());

      // A channel that closed while the keys were derived has released its secrets; this token's IKM must
      // not outlive that scrub in the context.
      if (mContext->keyAgreementReleased)
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{StatusCode{Status::BadSecureChannelClosed},
          make_error_detail("KeyAgreementReleased",
            "The channel released its key-agreement secrets while the keys were derived",
            "SecPolEphemeralKey")});
        co_return;
      }
      // The next renewal chains from this token's IKM.
      security::secure_clear(mContext->keyAgreementIkm);
      mContext->keyAgreementIkm = std::move(mIkm);

      // Map server/client back onto local/remote for this end of the channel.
      if (mRole == ChannelRole::Server)
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{
          std::make_pair(std::move(serverKeys), std::move(clientKeys))});
      }
      else
      {
        answer(SecurityPolicy::DeriveSymmetricKeysResult{
          std::make_pair(std::move(clientKeys), std::move(serverKeys))});
      }
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

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  shared_ptr<SecureChannelContext> mContext;
  ByteString mLocalNonce;
  ByteString mRemoteNonce;
  ChannelRole mRole{ChannelRole::Server};
  size_t mNumberOfBytes{0};
  ByteString mLocalPrivateKey;  // taken from the context when the operation starts
  security::ScrubOnExit mScrubLocalPrivateKey{mLocalPrivateKey};  // declared after it: scrubs it on any exit
  ByteString mIkm;  // this token's input keying material until it moves into the context
  security::ScrubOnExit mScrubIkm{mIkm};  // declared after mIkm: scrubs it on any exit before the move
  ByteString mServerSalt;
  ByteString mClientSalt;
  std::function<void(SecurityPolicy::DeriveSymmetricKeysResult)> mCallback;
};

}  // namespace

void SecPolEphemeralKey::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context,
  ByteString localNonce, ByteString remoteNonce, ChannelRole role,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    check(context);
    check(context->crypto);

    // L = EncryptionKeyLength + InitializationVectorLength in both modes: the AEAD tag is computed with the
    // encrypting key, so no signing key is derived (Part 6 6.8.1).
    const auto numberOfBytes = symmetric_encryption_key_size() + symmetric_iv_size();

    // The callback is MOVED, where the chain seeded the flow with a COPY so the original stayed
    // valid for the setup-failure path. The operation owns the answer and fires it once.
    started = true;
    DeriveSymmetricKeysEphemeralKeyOperation::start(
      std::static_pointer_cast<const SecPolEphemeralKey>(shared_from_this()),
      std::move(context),
      std::move(localNonce),
      std::move(remoteNonce),
      role,
      numberOfBytes,
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DeriveSymmetricKeysResult{er, er.shared_detail()});
    }
  }
}

namespace
{

/// Part 6 6.7.5: whether an OpenSecureChannel Signature made or checked now belongs to the first exchange,
/// whose response Signature also covers the request Signature. A renewal leaves the ChannelThumbprint set.
bool binds_to_first_request(const SecPolEphemeralKey& policy, const SecureChannelContext& context)
{
  return policy.secure_channel_enhancements() && context.channelThumbprint.empty();
}

/// The bytes a first OpenSecureChannel response is signed over: its own bytes up to the Signature,
/// followed by the Signature of the first request, which is not sent (Part 6 6.7.5, Figure 14).
ByteString response_bound_to_request(span<const byte> responseBytes, const ByteString& requestSignature)
{
  ByteString signedData;
  signedData.resize(responseBytes.size() + requestSignature.size());
  std::memcpy(signedData.data(), responseBytes.data(), responseBytes.size());
  std::memcpy(signedData.data() + responseBytes.size(), requestSignature.data(), requestSignature.size());
  return signedData;
}

/// Asymmetric decode (sign-only): validate the peer certificate, verify the signature, then
/// decode. Nothing is decrypted because this policy signs without encrypting, so the ordering that
/// matters is simply that nothing is trusted before its signature has been checked.
class DecodeAsymmetricEphemeralKeyOperation final
  : public ua::async::SelfOwningOperation<DecodeAsymmetricEphemeralKeyOperation>
{
public:
  static void start(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    ByteString messageChunk, size_t cipherTextOffset, const stack_utils::UaScMessageHeader& messageHeader,
    std::function<void(DecodedMessageChunkResult)> callback)
  {
    launch(std::make_shared<DecodeAsymmetricEphemeralKeyOperation>(std::move(policy),
      context,
      std::move(messageChunk),
      cipherTextOffset,
      messageHeader,
      std::move(callback)));
  }

  DecodeAsymmetricEphemeralKeyOperation(shared_ptr<const SecPolEphemeralKey> policy,
    SecureChannelContext& context, ByteString messageChunk, size_t cipherTextOffset,
    const stack_utils::UaScMessageHeader& messageHeader,
    std::function<void(DecodedMessageChunkResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mMessageChunkOwned(std::move(messageChunk)), mCipherTextOffset(cipherTextOffset),
      mMessageHeader(messageHeader), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecodeAsymmetricEphemeralKeyOperation>;

  ua::async::Task<> run()
  {
    try
    {
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

      const span<const byte> messageChunk = mMessageChunkOwned;
      const auto signatureSize = mPolicy->asymmetric_signature_size(mContext.remoteCertificate.get());

      // The chunk must carry its security header, the sequence header and the trailing signature in
      // full. Below that length the unsigned arithmetic for `dataEnd` and the body size would wrap.
      if (messageChunk.size() < mCipherTextOffset + SequenceHeader::sizeInBytes + signatureSize)
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build(
            "ChunkTooShort", "OPN chunk is shorter than its headers and signature", "SecPolEphemeralKey")
            .context(ua::ContextKeys::sizeActual, std::to_string(messageChunk.size()))
            .context(ua::ContextKeys::sizeMin,
              std::to_string(mCipherTextOffset + SequenceHeader::sizeInBytes + signatureSize))});
        co_return;
      }
      const auto dataEnd = messageChunk.size() - signatureSize;
      const auto signature = utils::safe_sub_span(messageChunk, dataEnd, signatureSize);

      // Part 6 6.7.5: the client checks the first response over its bytes followed by the Signature of its
      // first request. A request, and a renewal response, is signed over its own bytes.
      const bool boundToRequest =
        mContext.role == ChannelRole::Client && binds_to_first_request(*mPolicy, mContext);
      if (boundToRequest)
      {
        if (mContext.openSecureChannelRequestSignature.empty())
        {
          answer(DecodedMessageChunkResult{StatusCode{Status::BadInternalError},
            make_error_detail("NoRequestSignature",
              "No OpenSecureChannel request Signature is recorded to check the first response against",
              "SecPolEphemeralKey")});
          co_return;
        }
        mSignedData = response_bound_to_request(
          utils::safe_sub_span(messageChunk, 0, dataEnd), mContext.openSecureChannelRequestSignature);
      }
      const span<const byte> signedData =
        boundToRequest ? span<const byte>{mSignedData} : utils::safe_sub_span(messageChunk, 0, dataEnd);

      auto verifyResult = co_await await_step<VoidResult>(
        [this, signedData, signature](auto completion)
        {
          mContext.crypto->asymmetric_verify_async(mPolicy,
            mPolicy->asymmetric_signature_algorithm(),
            mContext.remoteCertificate->public_key(),
            signedData,
            signature,
            std::move(completion));
        });
      if (verifyResult.is_uncertain())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed,
          ua::security_internal::uncertain_answer_detail(verifyResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!verifyResult.is_good())
      {
        // Part 6 6.7.6: a Signature that does not verify is reported as Bad_SecurityChecksFailed.
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed},
          ErrorDetail::build(boundToRequest ? "FirstResponseSignatureInvalid" : "CryptoOperationFailed",
            boundToRequest ? "The Signature of the first OpenSecureChannel response does not verify over the "
                             "response and the "
                             "request Signature"
                           : "Asymmetric signature verification failed in OPN message",
            "SecurityPolicy")
            .cause(verifyResult.status_code())});
        co_return;
      }
      // The server keeps the Signature of the first request: its first response signs over it.
      if (mContext.role == ChannelRole::Server && binds_to_first_request(*mPolicy, mContext))
      {
        mContext.openSecureChannelRequestSignature = ByteString{signature};
      }

      // Decode the sequence header from the signed plaintext only: the stream ends where the
      // signature begins, so the header can never be read out of the signature bytes.
      const span<const byte> signedPlainText = utils::safe_sub_span(messageChunk, 0, dataEnd);
      memory_stream_device::ExternalReadOnly streamDevice{signedPlainText};
      MemoryStream stream{streamDevice};
      UaBinaryDecoder plainTextDecoder(StructureResolver{}, stream, mContext.encodingLimits);
      plainTextDecoder.stream().seek_from_start(mCipherTextOffset);

      SequenceHeader sequenceHeader;
      sequenceHeader.decode(mContext.encodingLimits, plainTextDecoder);
      mPolicy->check_sequence_header(mContext, sequenceHeader);

      // Copy the body (up to the signature). The sign-only OPN path accumulates the assembled
      // body itself rather than calling SecurityPolicy::copy_message_body, so it must replicate that
      // path's anti chunk-flood reassembly bounds: without them, an unauthenticated peer can stream
      // Intermediate ('C') OPN chunks (each validly self-signed with its own sender cert) to grow
      // receivedMessageBody without limit - a pre-auth resource-exhaustion DoS. Enforce the
      // negotiated MaxChunkCount and MaxMessageSize, failing with Bad_TcpMessageTooLarge (which tears
      // the channel down); the counter resets at the Final-chunk boundary below.
      // (OPC 10000-6 7.1.2.3/.4.)
      const auto& negotiated = mContext.negotiatedLimits;
      ++mContext.receivedChunkCount;
      if (negotiated.recvMaxChunkCount > 0 && mContext.receivedChunkCount > negotiated.recvMaxChunkCount)
      {
        throw UaException{Status::BadTcpMessageTooLarge,
          ErrorDetail::build("ChunkCountExceeded",
            "Inbound OPN message exceeds the negotiated MaxChunkCount",
            "SecPolEphemeralKey")
            .context(ua::ContextKeys::actual, std::to_string(mContext.receivedChunkCount))
            .context(ua::ContextKeys::max, std::to_string(negotiated.recvMaxChunkCount))};
      }

      const auto bodyEnd = dataEnd;
      const auto bodyStart = plainTextDecoder.stream().get_position();
      const auto bodySize = bodyEnd - bodyStart;
      const auto sizeFromPreviousChunks = mContext.receivedMessageBody.size();
      if (negotiated.recvMaxMessageSize > 0 &&
          (bodySize > negotiated.recvMaxMessageSize ||
            sizeFromPreviousChunks > negotiated.recvMaxMessageSize - bodySize))
      {
        throw UaException{Status::BadTcpMessageTooLarge,
          ErrorDetail::build("MessageSizeExceeded",
            "Inbound OPN message body exceeds the negotiated MaxMessageSize",
            "SecPolEphemeralKey")
            .context(ua::ContextKeys::actual, std::to_string(sizeFromPreviousChunks + bodySize))
            .context(ua::ContextKeys::max, std::to_string(negotiated.recvMaxMessageSize))};
      }
      mContext.receivedMessageBody.resize(sizeFromPreviousChunks + bodySize);
      std::memcpy(&mContext.receivedMessageBody[sizeFromPreviousChunks], &messageChunk[bodyStart], bodySize);

      optional<std::pair<uint32_t, ByteString>> decodeResult;
      if (mMessageHeader.isFinal == UaScMessageHeader::IsFinal::Final)
      {
        decodeResult = std::make_pair(sequenceHeader.requestId, std::move(mContext.receivedMessageBody));
        mContext.receivedMessageBody.clear();
        mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
        // The Signature of the first response, checked over the request Signature, is the ChannelThumbprint.
        if (boundToRequest)
        {
          mContext.channelThumbprint = ByteString{signature};
        }
      }

      answer(DecodedMessageChunkResult{std::move(decodeResult)});
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

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  SecureChannelContext& mContext;
  ByteString mMessageChunkOwned;  // owns the chunk for the operation's lifetime
  ByteString mSignedData;  // a first response followed by the request Signature, while it is verified
  size_t mCipherTextOffset{0};  // where the plaintext body begins
  stack_utils::UaScMessageHeader mMessageHeader;
  std::function<void(DecodedMessageChunkResult)> mCallback;
};

}  // namespace

// decode_asymmetric_message_chunk (sign-only): the synchronous checks below (Abort chunk, policy URI,
// sender certificate, recipient, adoption of the peer certificate), then
// DecodeAsymmetricEphemeralKeyOperation: validate the certificate, verify the signature, decode the sequence
// header and accumulate the body. Every failure answers the callback once with its status and ErrorDetail.
void SecPolEphemeralKey::decode_asymmetric_message_chunk_async(SecureChannelContext& context,
  UaBinaryDecoder& cipherTextDecoder, span<const byte> messageChunk,
  const stack_utils::UaScMessageHeader& header, std::function<void(DecodedMessageChunkResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    // An OpenSecureChannel message is one request with nothing to abort into; an OPN chunk marked
    // Abort is refused before the security header is decoded and before any certificate or
    // signature work (B2-7). Appending its body silently and leaving the reassembly state behind
    // was the defect.
    if (header.isFinal == stack_utils::UaScMessageHeader::IsFinal::Aborted)
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
      throw UaException{Status::BadSecurityPolicyRejected,
        ErrorDetail::build("InvalidSecurityPolicy",
          "Security policy URI does not match the policy's expected URI",
          "SecurityPolicy")
          .context(ua::ContextKeys::securityPolicy, std::string{securityHeader.securityPolicyUri})
          .context(ua::ContextKeys::expected, std::string{uri()})};
    }

    if (!securityHeader.senderCertificate)
    {
      throw UaException{Status::BadCertificateInvalid,
        make_error_detail("InvalidCertificate",
          "Sender certificate expected in the asymmetric security header",
          "SecurityPolicy")};
    }

    // Part 6 1.05.07 section 6.7.2.3 Table 58: ECC and RSA-DH identify the intended recipient,
    // even though OpenSecureChannel uses signatures rather than asymmetric encryption.
    if (!context.localCertificate)
    {
      throw UaException{Status::BadCertificateInvalid,
        make_error_detail("MissingReceiverCertificate",
          "Local certificate is unavailable for recipient validation",
          "SecurityPolicy")};
    }
    if (securityHeader.receiverCertificateThumbprint.size() != 20 ||
        securityHeader.receiverCertificateThumbprint != context.localCertificate->thumbprint())
    {
      // Part 6 6.7.6: "report a Bad_CertificateInvalid error if it does not recognize it". The code of the
      // RSA path: the server reports this refusal unmasked (owner decision D-d), unlike the other certificate
      // faults, whatever the policy.
      throw UaException{Status::BadCertificateInvalid,
        ErrorDetail::build("ReceiverCertificateThumbprintUnknown",
          "Receiver certificate thumbprint does not match local certificate",
          "SecurityPolicy")
          .context(ua::ContextKeys::certificateThumbprint,
            utils::bytes_to_hex_string(context.localCertificate->thumbprint()))};
    }

    // As the RSA path (Part 6 6.7.4): a peer certificate already known - the client fixed it from
    // GetEndpoints, or an earlier OPN established it - must be the one that signed this chunk; it is
    // adopted only when none is known. Gating on channel state instead would let a client's first OPN
    // response replace the certificate the client chose the endpoint by.
    if (!context.remoteCertificate)
    {
      context.remoteCertificate = securityHeader.senderCertificate;
    }
    else if (!utils::compare(context.remoteCertificate, securityHeader.senderCertificate))
    {
      throw UaException{Status::BadCertificateInvalid,
        make_error_detail("InvalidCertificate",
          "Certificate that signed the response does not match the expected peer certificate",
          "SecurityPolicy")};
    }
    // The chain the peer presented with this certificate (OPC 10000-6 6.2.6; decision 24).
    context.remoteIssuerCertificates = std::move(securityHeader.issuerCertificates);

    // The end-entity curve rule is the validator's Security Policy Check (Table 106 step 4), run by
    // DecodeAsymmetricEphemeralKeyOperation before any key agreement uses the certificate; it is not repeated
    // here.

    // The callback is MOVED, where the chain seeded the flow with a COPY so the original stayed
    // valid for the setup-failure path. The operation owns the answer and fires it once.
    started = true;
    DecodeAsymmetricEphemeralKeyOperation::start(
      std::static_pointer_cast<const SecPolEphemeralKey>(shared_from_this()),
      context,
      ByteString{messageChunk},
      cipherTextDecoder.stream().get_position(),
      header,
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DecodedMessageChunkResult{er, er.shared_detail()});
    }
  }
}

namespace
{

/// Asymmetric encode (sign-only): chunk the body and sign each chunk. No padding and no
/// encryption, so the chunk size is just the encoded length plus the signature.
///
/// The stream and encoder stay members: the signature is written into the same stream that encoded
/// the headers, on the far side of the suspension.
class EncodeAsymmetricEphemeralKeyOperation final
  : public ua::async::SelfOwningOperation<EncodeAsymmetricEphemeralKeyOperation>
{
public:
  static void start(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    uint32_t requestId, ByteString messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncodeAsymmetricEphemeralKeyOperation>(std::move(policy),
      context,
      requestId,
      std::move(messageBody),
      std::move(sendMessageChunk),
      std::move(callback)));
  }

  EncodeAsymmetricEphemeralKeyOperation(shared_ptr<const SecPolEphemeralKey> policy,
    SecureChannelContext& context, uint32_t requestId, ByteString messageBody,
    SecurityPolicy::SendMessageChunk sendMessageChunk, std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mRequestId(requestId), mMessageBodyOwned(std::move(messageBody)),
      mBodyRemaining(span<const byte>{mMessageBodyOwned}), mSendMessageChunk(std::move(sendMessageChunk)),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncodeAsymmetricEphemeralKeyOperation>;

  ua::async::Task<> run()
  {
    try
    {
      mSecurityHeader.securityPolicyUri = mPolicy->uri();
      mSecurityHeader.senderCertificate = mContext.localCertificate;
      // Decision 24: the own issuer chain follows the leaf (OPC 10000-6 section 6.2.6).
      mSecurityHeader.issuerCertificates = mContext.localIssuerCertificates;
      // Part 6 1.05.07 section 6.7.2.3 Table 58: identify the recipient for both modes.
      if (!mContext.remoteCertificate)
      {
        answer(VoidResult{StatusCode{Status::BadCertificateInvalid},
          make_error_detail("MissingReceiverCertificate",
            "Remote certificate is unavailable for recipient encoding",
            "SecurityPolicy")});
        co_return;
      }
      mSecurityHeader.receiverCertificateThumbprint = mContext.remoteCertificate->thumbprint();

      size_t securityHeaderSize{0};
      {
        NullStream nullStream;
        UaBinaryEncoder binaryEncoder{CodecNamespaceContext{mContext.namespaceIndexCallback}, nullStream};
        mSecurityHeader.encode(mContext.encodingLimits, binaryEncoder);
        securityHeaderSize = binaryEncoder.stream().get_position();
      }

      mHeaderSize = UaScMessageHeader::sizeInBytes + securityHeaderSize;
      mSignatureSize = mPolicy->asymmetric_signature_size(mContext.localCertificate.get());
      // Part 6 6.7.2.3: the security header (the SenderCertificate with its chain) must fit one chunk with
      // room for a body. Too large -> Bad_EncodingLimitsExceeded before anything is written. A zero buffer
      // size means no limit was negotiated.
      if (const auto sendBufferSize = size_t{mContext.negotiatedLimits.sendBufferSize};
          sendBufferSize != 0 && sendBufferSize <= mHeaderSize + SequenceHeader::sizeInBytes + mSignatureSize)
      {
        answer(VoidResult{StatusCode{Status::BadEncodingLimitsExceeded},
          make_error_detail("SecurityHeaderExceedsChunk",
            "The OPN security header (own certificate chain) does not fit the negotiated send buffer",
            "SecPolEphemeralKey")});
        co_return;
      }
      // No block encryption, so the max body is a simple subtraction.
      mMaxBodySize =
        mContext.negotiatedLimits.sendBufferSize - mHeaderSize - SequenceHeader::sizeInBytes - mSignatureSize;

      // Part 6 6.7.5: the server signs the first response over its bytes followed by the Signature of the
      // first request. A renewal response, and every request, is signed over its own bytes.
      const bool bindToRequest =
        mContext.role == ChannelRole::Server && binds_to_first_request(*mPolicy, mContext);
      if (bindToRequest && mContext.openSecureChannelRequestSignature.empty())
      {
        answer(VoidResult{StatusCode{Status::BadInternalError},
          make_error_detail("NoRequestSignature",
            "No OpenSecureChannel request Signature is recorded to sign the first response over",
            "SecPolEphemeralKey")});
        co_return;
      }

      while (!mBodyRemaining.empty())
      {
        const size_t bytesToWrite = encode_one_chunk();
        const bool finalChunk = bytesToWrite == mBodyRemaining.size();
        const auto chunkBytes =
          utils::safe_sub_span(span<const byte>(mMessageChunk), 0, mStream->get_position());
        if (bindToRequest)
        {
          mSignedData = response_bound_to_request(chunkBytes, mContext.openSecureChannelRequestSignature);
        }
        const span<const byte> signedData = bindToRequest ? span<const byte>{mSignedData} : chunkBytes;

        auto signResult = co_await await_step<ByteStringResult>(
          [this, signedData](auto completion)
          {
            mContext.crypto->asymmetric_sign_async(mPolicy,
              mPolicy->asymmetric_signature_algorithm(),
              mContext.localKeyPair,
              signedData,
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
              "CryptoOperationFailed", "Could not sign the asymmetric message", "SecurityPolicy")
              .cause(signResult.status_code())});
          co_return;
        }

        auto signature = std::move(signResult).value();
        // The first response's Signature is the ChannelThumbprint; the client keeps the Signature of the
        // first request it sends, because the first response is checked over it.
        if (bindToRequest && finalChunk)
        {
          mContext.channelThumbprint = signature;
        }
        if (mContext.role == ChannelRole::Client && binds_to_first_request(*mPolicy, mContext))
        {
          mContext.openSecureChannelRequestSignature = signature;
        }

        // The signature goes onto the same stream the headers were encoded into.
        mStream->write_all(signature);
        mMessageChunk.resize(mChunkSize);

        mBodyRemaining =
          utils::safe_sub_span(mBodyRemaining, bytesToWrite, mBodyRemaining.size() - bytesToWrite);
        mSendMessageChunk(std::move(mMessageChunk));
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

  /// Encodes one chunk's headers and body and positions the stream where the signature goes.
  /// Returns the body bytes this chunk consumed.
  size_t encode_one_chunk()
  {
    const StackDepth limit = mContext.encodingLimits.stack_depth();

    UaScMessageHeader messageHeader;
    messageHeader.messageType = UaScMessageHeader::MessageType::Open;
    messageHeader.secureChannelId = mContext.secureChannelId;

    size_t bytesToWrite = mBodyRemaining.size();
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
    auto& encoder = mEncoder.emplace(CodecNamespaceContext{mContext.namespaceIndexCallback}, stream);

    messageHeader.encode(mContext.encodingLimits, encoder);
    mSecurityHeader.encode(mContext.encodingLimits, encoder);

    SequenceHeader sequenceHeader;
    sequenceHeader.sequenceNumber = mContext.next_tx_sequence_number();
    sequenceHeader.requestId = mRequestId;
    sequenceHeader.encode(mContext.encodingLimits, encoder);

    stream.write_all(bodyToWrite);

    // No padding, no encryption - just sign.
    mChunkSize = numeric_cast<uint32_t>(stream.get_position() + mSignatureSize);
    stream.seek_from_start(4);
    encoder.encode(limit, mChunkSize);
    stream.seek_from_start(mChunkSize - mSignatureSize);

    check(mContext.localKeyPair);
    return bytesToWrite;
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

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mRequestId{0};
  ByteString mMessageBodyOwned;
  span<const byte> mBodyRemaining;  // views mMessageBodyOwned; declared after it on purpose
  SecurityPolicy::SendMessageChunk mSendMessageChunk;
  AsymmetricSecurityHeader mSecurityHeader;
  size_t mHeaderSize{0};
  size_t mSignatureSize{0};
  size_t mMaxBodySize{0};

  // Per-chunk scratch.
  ByteString mMessageChunk;
  ByteString mSignedData;  // a first response chunk followed by the request Signature, while it is signed
  std::optional<memory_stream_device::ExternalWritable> mStreamDevice;
  std::optional<MemoryStream<memory_stream_device::ExternalWritable>> mStream;
  std::optional<UaBinaryEncoder> mEncoder;
  uint32_t mChunkSize{0};

  std::function<void(VoidResult)> mCallback;
};

}  // namespace

// encode_asymmetric_message (sign-only): EncodeAsymmetricEphemeralKeyOperation encodes and signs one chunk
// at a time until the body is exhausted, handing each signed chunk to sendMessageChunk. Every failure
// answers the callback once with its status and ErrorDetail.
void SecPolEphemeralKey::encode_asymmetric_message_async(SecureChannelContext& context, uint32_t requestId,
  span<const byte> messageBody, SendMessageChunk sendMessageChunk,
  std::function<void(VoidResult)> callback) const
{
  // The operation owns the callback once it is started; until then this function does. The chain
  // seeded its flow with a COPY so the original stayed valid for the setup-failure path; the
  // operation owns the answer and fires it once, so a move is enough.
  bool started = false;
  try
  {
    started = true;
    EncodeAsymmetricEphemeralKeyOperation::start(
      std::static_pointer_cast<const SecPolEphemeralKey>(shared_from_this()),
      context,
      requestId,
      ByteString{messageBody},
      std::move(sendMessageChunk),
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

ByteString SecPolEphemeralKey::construct_per_message_iv(
  span<const byte> baseIv, uint32_t tokenId, uint32_t lastSequenceNumber)
{
  ByteString iv{baseIv};

  // Part 6 6.8.1 Table 69: the first 8 bytes are XORed with TokenId (UInt32 LE) and LastSequenceNumber
  // (UInt32 LE), the number of the previous chunk sent in the same direction.
  if (iv.size() >= 8)
  {
    for (size_t i = 0; i < 4; ++i)
    {
      iv[i] ^= numeric_cast<uint8_t>((tokenId >> (8 * i)) & 0xFF);
      iv[4 + i] ^= numeric_cast<uint8_t>((lastSequenceNumber >> (8 * i)) & 0xFF);
    }
  }

  return iv;
}

namespace
{

// AEAD symmetric decode: single symmetric_verify_and_decrypt await per chunk.
/// One AEAD verify-and-decrypt, then the decoded chunk.
///
/// The AAD (the header bytes) and the authentication tag are MEMBERS because the crypto call takes
/// spans over them and those spans have to stay valid until it answers.
class DecodeSymmetricAeadOperation final : public ua::async::SelfOwningOperation<DecodeSymmetricAeadOperation>
{
public:
  static void start(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    uint32_t tokenId, size_t headerSize, size_t payloadSize, ByteString aad, bool finalChunk, bool abortChunk,
    ByteString perMessageIv, ByteString key, ByteString cipherTextBuffer, ByteString signature,
    ByteString plainTextStorage, std::function<void(DecodedMessageChunkResult)> callback)
  {
    launch(std::make_shared<DecodeSymmetricAeadOperation>(std::move(policy),
      context,
      tokenId,
      headerSize,
      payloadSize,
      std::move(aad),
      finalChunk,
      abortChunk,
      std::move(perMessageIv),
      std::move(key),
      std::move(cipherTextBuffer),
      std::move(signature),
      std::move(plainTextStorage),
      std::move(callback)));
  }

  DecodeSymmetricAeadOperation(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    uint32_t tokenId, size_t headerSize, size_t payloadSize, ByteString aad, bool finalChunk, bool abortChunk,
    ByteString perMessageIv, ByteString key, ByteString cipherTextBuffer, ByteString signature,
    ByteString plainTextStorage, std::function<void(DecodedMessageChunkResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mTokenId(tokenId), mHeaderSize(headerSize), mPayloadSize(payloadSize), mAad(std::move(aad)),
      mSignature(std::move(signature)), mFinalChunk(finalChunk), mAbortChunk(abortChunk),
      mPerMessageIv(std::move(perMessageIv)), mKey(std::move(key)),
      mCipherTextBuffer(std::move(cipherTextBuffer)), mPlainTextStorage(std::move(plainTextStorage)),
      mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<DecodeSymmetricAeadOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto decryptResult = co_await await_step<Crypto::SymmetricVerifyAndDecryptOutputResult>(
        [this](auto completion)
        {
          // Bind the cipherText / plainText views before moving the owning buffers: the vectors'
          // heap data is stable across a move, so the spans stay valid through the call.
          const span<const byte> cipherTextSpan{mCipherTextBuffer};
          const span<byte> plainTextSpan{mPlainTextStorage};

          mContext.crypto->symmetric_verify_and_decrypt_async(mPolicy->symmetric_encryption_algorithm(),
            std::move(mPerMessageIv),
            std::move(mKey),
            std::move(mCipherTextBuffer),
            cipherTextSpan,
            span<const byte>{mAad},
            span<const byte>{mSignature},
            std::move(mPlainTextStorage),
            plainTextSpan,
            std::move(completion));
        });
      if (decryptResult.is_uncertain())
      {
        answer(DecodedMessageChunkResult{StatusCode{Status::BadSecurityChecksFailed,
          ua::security_internal::uncertain_answer_detail(decryptResult.status_code(), "SecurityPolicy")}});
        co_return;
      }
      if (!decryptResult.is_good())
      {
        answer(DecodedMessageChunkResult{decryptResult.status_code(),
          ErrorDetail::build("CryptoOperationFailed", "AEAD verify-and-decrypt failed", "SecurityPolicy")
            .cause(decryptResult.status_code())});
        co_return;
      }

      auto output = std::move(decryptResult).value();
      if (!output.plainTextBuffer)
      {
        throw UaException{Status::BadInternalError,
          make_error_detail(
            "CryptoOperationFailed", "AEAD decrypt did not return a plaintext buffer", "SecurityPolicy")};
      }

      // The SequenceHeader is decoded at its original offset after the headers. In Sign mode the
      // associated data already holds the verified sequence header and body in the clear; in
      // SignAndEncrypt they are the decrypted payload, placed after the header bytes.
      ByteString plainTextBuffer;
      if (mAad.size() > mHeaderSize)
      {
        plainTextBuffer = std::move(mAad);
      }
      else
      {
        plainTextBuffer.resize(mHeaderSize + mPayloadSize);
        std::memcpy(plainTextBuffer.data(), mAad.data(), mHeaderSize);
        std::memcpy(plainTextBuffer.data() + mHeaderSize, output.plainTextBuffer->data(), mPayloadSize);
      }

      memory_stream_device::ExternalReadOnly streamDevice{plainTextBuffer};
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

      // Offset at which THIS chunk's body starts within the accumulated buffer - the abort Error must
      // be decoded from the abort chunk's OWN body (Part 6 6.7.3 discards previous chunks), not the
      // accumulation.
      const size_t chunkBodyOffset = mContext.receivedMessageBody.size();
      mPolicy->copy_message_body(mContext, plainTextDecoder);

      optional<std::pair<uint32_t, ByteString>> finalResult;
      if (mFinalChunk)
      {
        finalResult = std::make_pair(sequenceHeader.requestId, std::move(mContext.receivedMessageBody));
        mContext.receivedMessageBody.clear();
        mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
      }
      else if (mAbortChunk)
      {
        // ABORT chunk (Part 6 6.7.3): the body carries {Error StatusCode, Reason}. Report the Error -
        // decoded from the abort chunk's OWN body (the bytes appended just now) - to the single
        // request this abort targets via the channel context side-channel, DISCARD the buffered
        // message, and leave `finalResult` EMPTY so the channel stays open (a bad Result would tear
        // the whole channel down, but the abort must fail only the one request).
        const ua::span<const ua::byte> abortBody =
          ua::span<const ua::byte>{mContext.receivedMessageBody}.subspan(chunkBodyOffset);
        mContext.receivedAbort = std::make_pair(sequenceHeader.requestId,
          security_internal::decode_abort_error(abortBody, mContext.encodingLimits));
        mContext.receivedMessageBody.clear();
        mContext.receivedChunkCount = 0;  // message boundary - reset the per-message chunk counter
      }

      answer(DecodedMessageChunkResult{std::move(finalResult)});
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

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mTokenId{0};  // the TokenId on the wire, which selected the keys
  size_t mHeaderSize{0};
  size_t mPayloadSize{0};  // sequence header and body
  ByteString mAad;  // associated data; the crypto call holds a span over this
  ByteString mSignature;  // auth tag bytes; likewise
  bool mFinalChunk{false};
  bool mAbortChunk{false};  // IsFinal='A' (Part 6 6.7.3); mutually exclusive with mFinalChunk

  ByteString mPerMessageIv;
  ByteString mKey;
  ByteString mCipherTextBuffer;
  ByteString mPlainTextStorage;

  std::function<void(DecodedMessageChunkResult)> mCallback;
};

}  // namespace

// decode_symmetric_message_chunk (AEAD): the token selection (a chunk under the pending token tries it, and
// it becomes active only if the chunk is accepted), the per-chunk IV and the split into associated data,
// ciphertext and tag happen here; DecodeSymmetricAeadOperation then verifies and decrypts, checks the
// sequence number under the selected token and accumulates the body. Every failure answers the callback
// once with its status and ErrorDetail.
void SecPolEphemeralKey::decode_symmetric_message_chunk_async(SecureChannelContext& context,
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
      throw UaException{Status::BadInvalidState,
        make_error_detail("PolicyConfigError",
          "No active security token available for symmetric message decoding",
          "SecurityPolicy")};
    }

    // The token whose keys open this chunk: the active one unless the TokenId selects another below.
    const SecurityToken* receiveToken = activeToken.get();
    auto& retiredToken = context.retiredSecurityToken;
    if (securityHeader.tokenId == activeToken->id())
    {
      if (retiredToken)
      {
        // OPC 10000-6 6.7.4 (1.05.06): the first chunk accepted under the new token ends the client's
        // acceptance of the token the renew response replaced - that token only: a renewal completing while
        // this chunk is decrypted may have retired another since.
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
        throw UaException{Status::BadSecureChannelTokenUnknown,
          ErrorDetail::build("RetiredTokenExpired",
            "Received token ID names the security token the renewal replaced, and that token has expired",
            "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))};
      }
      // OPC 10000-6 6.7.4 (1.05.06): a chunk the Server secured with the replaced token before it received a
      // message under the new one.
      receiveToken = retiredToken.get();
    }
    else if (pendingToken && securityHeader.tokenId == pendingToken->id() &&
             context.role == ChannelRole::Client)
    {
      // Only a Server activates a renewed token on the peer's first chunk under it; the client activates its
      // own on the renew response, so a chunk under a renewed token it has not activated yet is refused.
      throw UaException{Status::BadSecureChannelTokenUnknown,
        ErrorDetail::build("PolicyConfigError",
          "Received token ID names a renewed token this client has not activated",
          "SecurityPolicy")
          .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))};
    }
    else
    {
      if (!pendingToken)
      {
        throw UaException{Status::BadSecureChannelTokenUnknown,
          ErrorDetail::build("PolicyConfigError",
            "Received token ID does not match active token and no pending token exists",
            "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))
            .context(ua::ContextKeys::securityTokenActiveId, std::to_string(activeToken->id()))};
      }
      else if (securityHeader.tokenId != pendingToken->id())
      {
        throw UaException{Status::BadSecureChannelTokenUnknown,
          ErrorDetail::build("PolicyConfigError",
            "Received token ID matches neither the active nor the pending token",
            "SecurityPolicy")
            .context(ua::ContextKeys::securityTokenId, std::to_string(securityHeader.tokenId))
            .context(ua::ContextKeys::securityTokenActiveId, std::to_string(activeToken->id()))
            .context(ua::ContextKeys::securityTokenPendingId, std::to_string(pendingToken->id()))};
      }
      else
      {
        // H-D5 (B2-6): the pending token is tried for this chunk and becomes active only once the
        // chunk has been accepted; a chunk that fails leaves the tokens as they were.
        std::swap(activeToken, pendingToken);
        callback = [&context, inner = std::move(callback)](DecodedMessageChunkResult result) mutable
        {
          if (result.is_bad())
            std::swap(context.activeSecurityToken, context.pendingSecurityToken);
          else
            context.pendingSecurityToken.reset();  // the previous token is retired
          inner(std::move(result));
        };
        receiveToken = activeToken.get();
      }
    }

    // Part 6 6.8.1 Table 69: the IV takes the number of the previous chunk received in this direction,
    // which is the last one verified.
    const uint32_t lastSequenceNumber = context.lastRxSequenceNumber.value_or(0);
    auto perMessageIv = ByteString{construct_per_message_iv(
      receiveToken->remote_keys().initializationVector, securityHeader.tokenId, lastSequenceNumber)};

    auto signatureSize = symmetric_signature_size();  // the 16-byte AEAD tag

    // The sequence header, the body and the tag follow the headers.
    auto cipherAndTag = utils::safe_sub_span(messageChunk, headerSize, messageChunk.size() - headerSize);
    if (cipherAndTag.size() < signatureSize)
    {
      throw UaException{Status::BadSecurityChecksFailed,
        ErrorDetail::build(
          "CryptoOperationFailed", "AEAD message too short to contain authentication tag", "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(cipherAndTag.size()))
          .context(ua::ContextKeys::sizeMin, std::to_string(signatureSize))};
    }

    const auto payloadSize = cipherAndTag.size() - signatureSize;

    // Part 6 6.7.2.1 Figure 12. SignAndEncrypt: the headers are associated data and the sequence header
    // and body are encrypted. Sign: everything before the tag is associated data and nothing is
    // encrypted. Both modes use the encrypting key; these policies derive no signing key.
    const bool encrypted = is_encrypted(context);
    const span<const byte> associatedData =
      utils::safe_sub_span(messageChunk, 0, encrypted ? headerSize : headerSize + payloadSize);
    const span<const byte> cipherText =
      encrypted ? utils::safe_sub_span(cipherAndTag, 0, payloadSize) : span<const byte>{};
    ByteString key{receiveToken->remote_keys().encryptingKey};

    // The async API takes owning ByteString buffers for cipher and (optional) plain. Allocate
    // a plainTextStorage that owns storage; the API decrypts into it and returns via the result.
    ByteString cipherTextBuffer{cipherText};
    ByteString signatureBuffer{utils::safe_sub_span(cipherAndTag, payloadSize, signatureSize)};
    ByteString plainTextStorage;
    plainTextStorage.resize(cipherText.size());

    // associatedData is a span into the caller-owned messageChunk; copy it because the async call
    // outlives this synchronous prologue.
    //
    // The callback is MOVED, where the chain had to copy it: it passed a copy so its own catch could
    // still report a setup failure, because moving would have left the outer one empty and thrown
    // std::bad_function_call from the handler. The operation owns the answer from construction and
    // fires it once, so the catch below simply does not run once `started` is set.
    started = true;
    DecodeSymmetricAeadOperation::start(
      std::static_pointer_cast<const SecPolEphemeralKey>(shared_from_this()),
      context,
      securityHeader.tokenId,
      headerSize,
      payloadSize,
      ByteString{associatedData},
      header.isFinal == UaScMessageHeader::IsFinal::Final,
      header.isFinal == UaScMessageHeader::IsFinal::Aborted,
      std::move(perMessageIv),
      std::move(key),
      std::move(cipherTextBuffer),
      std::move(signatureBuffer),
      std::move(plainTextStorage),
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(DecodedMessageChunkResult{er, er.shared_detail()});
    }
  }
}

namespace
{

/// The AEAD send path: one `symmetric_encrypt_and_sign` per chunk, in a loop.
///
/// The AAD, the ciphertext buffer and the stream stay members: the crypto call holds spans over the
/// first two, and the chunk size is written into the stream BEFORE the AAD is snapshotted, because
/// AEAD authenticates the header - bytes 4..7 must already say what the receiver will see.
class EncodeSymmetricAeadOperation final : public ua::async::SelfOwningOperation<EncodeSymmetricAeadOperation>
{
public:
  static void start(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    uint32_t requestId, ByteString messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    size_t signatureSize, size_t maxChunkSize, size_t maxChunkBodySize,
    UaScMessageHeader::MessageType messageType, std::function<void(VoidResult)> callback)
  {
    launch(std::make_shared<EncodeSymmetricAeadOperation>(std::move(policy),
      context,
      requestId,
      std::move(messageBody),
      std::move(sendMessageChunk),
      signatureSize,
      maxChunkSize,
      maxChunkBodySize,
      messageType,
      std::move(callback)));
  }

  EncodeSymmetricAeadOperation(shared_ptr<const SecPolEphemeralKey> policy, SecureChannelContext& context,
    uint32_t requestId, ByteString messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    size_t signatureSize, size_t maxChunkSize, size_t maxChunkBodySize,
    UaScMessageHeader::MessageType messageType, std::function<void(VoidResult)> callback)
    : SelfOwningOperation(context.strand(), context.logger), mPolicy(std::move(policy)), mContext(context),
      mRequestId(requestId), mMessageBodyOwned(std::move(messageBody)),
      mBodyRemaining(span<const byte>{mMessageBodyOwned}), mSendMessageChunk(std::move(sendMessageChunk)),
      mSignatureSize(signatureSize), mMaxChunkSize(maxChunkSize), mMaxChunkBodySize(maxChunkBodySize),
      mMessageType(messageType), mCallback(std::move(callback))
  {}

private:
  friend class ua::async::SelfOwningOperation<EncodeSymmetricAeadOperation>;

  ua::async::Task<> run()
  {
    try
    {
      while (!mBodyRemaining.empty())
      {
        const size_t bytesToWrite = encode_one_chunk();

        auto aeadResult = co_await await_step<Crypto::SymmetricEncryptAndSignOutputResult>(
          [this](auto completion)
          {
            // Per the crypto API contract: bind the plainText view before moving the owning buffer.
            // The vector's heap data is stable across the move, so the span stays valid.
            const span<const byte> plainTextSpan{mPlainTextOwned};

            mContext.crypto->symmetric_encrypt_and_sign_async(mPolicy->symmetric_encryption_algorithm(),
              std::move(mPerMessageIv),
              std::move(mKey),
              std::move(mPlainTextOwned),
              plainTextSpan,
              span<const byte>{mAadOwned},
              std::nullopt,
              span<byte>{mCipherTextStorage},
              std::move(completion));
          });
        if (aeadResult.is_uncertain())
        {
          answer(VoidResult{StatusCode{Status::BadInternalError,
            ua::security_internal::uncertain_answer_detail(aeadResult.status_code(), "SecurityPolicy")}});
          co_return;
        }
        if (!aeadResult.is_good())
        {
          answer(VoidResult{aeadResult.status_code(),
            ErrorDetail::build("CryptoOperationFailed", "AEAD encrypt-and-sign failed", "SecurityPolicy")
              .cause(aeadResult.status_code())});
          co_return;
        }
        auto output = std::move(aeadResult).value();

        // The ciphertext replaces the payload after the headers (nothing in Sign mode); the tag follows.
        if (!mCipherTextStorage.empty())
        {
          auto dest = utils::safe_sub_span(span<byte>{mMessageChunk}, mHeaderSize, mCipherTextStorage.size());
          std::memcpy(dest.data(), mCipherTextStorage.data(), mCipherTextStorage.size());
        }

        auto tagDest = utils::safe_sub_span(
          span<byte>{mMessageChunk}, mHeaderSize + mPlainTextSize, output.signature.size());
        std::memcpy(tagDest.data(), output.signature.data(), output.signature.size());

        mMessageChunk.resize(mChunkSize);
        mBodyRemaining =
          utils::safe_sub_span(mBodyRemaining, bytesToWrite, mBodyRemaining.size() - bytesToWrite);
        mSendMessageChunk(std::move(mMessageChunk));
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

  /// Encodes one chunk's headers and body, fixes the size field, and snapshots the AAD and plaintext
  /// ready for the AEAD call. Returns the body bytes this chunk consumed.
  size_t encode_one_chunk()
  {
    const StackDepth limit = mContext.encodingLimits.stack_depth();

    UaScMessageHeader messageHeader;
    messageHeader.messageType = mMessageType;
    messageHeader.secureChannelId = mContext.secureChannelId;

    size_t bytesToWrite = mBodyRemaining.size();
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
    auto& encoder = mEncoder.emplace(CodecNamespaceContext{mContext.namespaceIndexCallback}, stream);

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
    // Part 6 6.8.1 Table 69: the IV takes the number of the previous chunk sent in this direction.
    const uint32_t lastSequenceNumber = mContext.last_tx_sequence_number();
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

    const auto bodyEndPosition = stream.get_position();
    mPlainTextSize = bodyEndPosition - mHeaderSize;

    // The chunk size is written BEFORE the AAD is snapshotted: AEAD authenticates the header, so
    // bytes 4..7 have to already match what the receiver will see.
    mChunkSize = numeric_cast<uint32_t>(mHeaderSize + mPlainTextSize + mSignatureSize);
    stream.seek_from_start(4);
    encoder.encode(limit, mChunkSize);

    mPerMessageIv = ByteString{
      mPolicy->construct_per_message_iv(mContext.activeSecurityToken->local_keys().initializationVector,
        securityHeader.tokenId,
        lastSequenceNumber)};

    // Part 6 6.7.2.1 Figure 12. SignAndEncrypt: the headers are associated data and the sequence header
    // and body are encrypted. Sign: everything before the tag is associated data, nothing is encrypted
    // and the body stays in the clear. Both modes use the encrypting key.
    mKey = ByteString{mContext.activeSecurityToken->local_keys().encryptingKey};
    const bool encrypted = mPolicy->is_encrypted(mContext);
    mAadOwned = ByteString{utils::safe_sub_span(
      span<const byte>{mMessageChunk}, 0, encrypted ? mHeaderSize : mHeaderSize + mPlainTextSize)};
    mPlainTextOwned =
      encrypted
        ? ByteString{utils::safe_sub_span(span<const byte>{mMessageChunk}, mHeaderSize, mPlainTextSize)}
        : ByteString{};

    mCipherTextStorage = ByteString{};
    mCipherTextStorage.resize(mPlainTextOwned.size());

    return bytesToWrite;
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

  shared_ptr<const SecPolEphemeralKey> mPolicy;
  SecureChannelContext& mContext;
  uint32_t mRequestId{0};
  ByteString mMessageBodyOwned;
  span<const byte> mBodyRemaining;  // views mMessageBodyOwned; declared after it on purpose
  SecurityPolicy::SendMessageChunk mSendMessageChunk;
  size_t mSignatureSize{0};
  size_t mMaxChunkSize{0};
  size_t mMaxChunkBodySize{0};
  UaScMessageHeader::MessageType mMessageType{UaScMessageHeader::MessageType::Message};

  // Per-chunk scratch.
  ByteString mMessageChunk;
  std::optional<memory_stream_device::ExternalWritable> mStreamDevice;
  std::optional<MemoryStream<memory_stream_device::ExternalWritable>> mStream;
  std::optional<UaBinaryEncoder> mEncoder;
  size_t mHeaderSize{0};
  uint32_t mChunkSize{0};
  size_t mPlainTextSize{0};
  ByteString mAadOwned;
  ByteString mPlainTextOwned;
  ByteString mPerMessageIv;
  ByteString mKey;
  ByteString mCipherTextStorage;

  std::function<void(VoidResult)> mCallback;
};

}  // namespace

// encode_symmetric_message (AEAD): the message size and chunk count are checked here (the role's
// Bad_RequestTooLarge or Bad_ResponseTooLarge); EncodeSymmetricAeadOperation then encodes and seals one chunk
// at a time with the active token's encrypting key and per-chunk IV, handing each to sendMessageChunk. Every
// failure answers the callback once with its status and ErrorDetail.
void SecPolEphemeralKey::encode_symmetric_message_async(SecureChannelContext& context, uint32_t requestId,
  span<const byte> messageBody, SendMessageChunk sendMessageChunk, std::function<void(VoidResult)> callback,
  UaScMessageHeader::MessageType messageType) const
{
  // The operation owns the callback once it is started; until then this function does.
  bool started = false;
  try
  {
    auto signatureSize = symmetric_signature_size();  // the 16-byte AEAD tag
    auto maxChunkSize = context.negotiatedLimits.sendBufferSize;
    // AEAD: no block padding (stream cipher), so body max is simpler.
    auto maxChunkBodySize = maxChunkSize - UaScMessageHeader::sizeInBytes -
                            SymmetricSecurityHeader::sizeInBytes - SequenceHeader::sizeInBytes -
                            signatureSize;

    auto requiredChunkCount = messageBody.size() / maxChunkBodySize;
    if (messageBody.size() % maxChunkBodySize)
    {
      ++requiredChunkCount;
    }

    auto maxChunkCount = context.negotiatedLimits.sendMaxChunkCount;
    if ((maxChunkCount > 0) && (maxChunkCount < requiredChunkCount))
    {
      throw UaException{outgoing_too_large_status(context.role),
        ErrorDetail::build(
          "PolicyConfigError", "Required chunk count exceeds negotiated maximum", "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(requiredChunkCount))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxChunkCount))};
    }

    auto maxMessageSize = context.negotiatedLimits.sendMaxMessageSize;
    if ((maxMessageSize > 0) && (messageBody.size() > maxMessageSize))
    {
      throw UaException{outgoing_too_large_status(context.role),
        ErrorDetail::build(
          "PolicyConfigError", "Message body size exceeds receiver maximum message size", "SecurityPolicy")
          .context(ua::ContextKeys::sizeActual, std::to_string(messageBody.size()))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxMessageSize))};
    }

    // The callback is MOVED, where the chain had to copy it so its own catch could still report a
    // setup failure. The operation owns the answer from construction and fires it once.
    started = true;
    EncodeSymmetricAeadOperation::start(
      std::static_pointer_cast<const SecPolEphemeralKey>(shared_from_this()),
      context,
      requestId,
      ByteString{messageBody},
      std::move(sendMessageChunk),
      signatureSize,
      maxChunkSize,
      maxChunkBodySize,
      messageType,
      std::move(callback));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (!started && callback)
    {
      callback(VoidResult{er, er.shared_detail()});
    }
  }
}

}  // namespace ua
