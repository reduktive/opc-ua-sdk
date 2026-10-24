// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_async_crypto.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "ua_error_detail.h"
#include "test_components.h"

namespace ua::test_helpers
{

std::shared_ptr<FakeAsyncCrypto> FakeAsyncCrypto::create()
{
  return std::shared_ptr<FakeAsyncCrypto>(new FakeAsyncCrypto());
}

// The shared test provider: the SDK default with a private-key credential, so a fake-backed Session can
// create and hold key pairs (there is no default provider with one, security review B3-8).
FakeAsyncCrypto::FakeAsyncCrypto() : mUnderlying(ua::test_helpers::test_crypto())
{}

void FakeAsyncCrypto::set_asymmetric_sign_failure(ua::StatusCode status)
{
  mAsymmetricSignFailure.store(status.is_good() ? ua::StatusCodeValue{0} : status.value());
}

void FakeAsyncCrypto::set_asymmetric_verify_answer(ua::StatusCode status)
{
  mAsymmetricVerifyAnswer.store(status.is_good() ? ua::StatusCodeValue{0} : status.value());
}

void FakeAsyncCrypto::set_entropy_answer(ua::StatusCode status, bool holdingBytes)
{
  mEntropyAnswerHoldsBytes.store(holdingBytes);
  mEntropyAnswer.store(status.is_good() ? ua::StatusCodeValue{0} : status.value());
}

void FakeAsyncCrypto::set_ephemeral_keys_answer(ua::StatusCode status)
{
  mEphemeralKeysAnswer.store(status.is_good() ? ua::StatusCodeValue{0} : status.value());
}

void FakeAsyncCrypto::set_park_async(bool park)
{
  mParkAsync.store(park);
}

bool FakeAsyncCrypto::park_async() const
{
  return mParkAsync.load();
}

void FakeAsyncCrypto::fail_nth_symmetric_sign(std::size_t callIndex, ua::StatusCode status)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mFailSymmetricSignIndex = callIndex;
  mFailSymmetricSignStatus = std::move(status);
}

void FakeAsyncCrypto::fail_nth_symmetric_encrypt(std::size_t callIndex, ua::StatusCode status)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mFailSymmetricEncryptIndex = callIndex;
  mFailSymmetricEncryptStatus = std::move(status);
}

void FakeAsyncCrypto::corrupt_next_rsa_secret_payload_padding()
{
  std::lock_guard<std::mutex> lock(mMutex);
  mCorruptNextRsaSecretPayloadPadding = true;
}

std::size_t FakeAsyncCrypto::corrupted_rsa_secret_payload_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mCorruptedRsaSecretPayloadCount;
}

// ---------------------------------------------------------------------------
// Async overrides - park if `mParkAsync` is set, else forward to underlying.
// ---------------------------------------------------------------------------

void FakeAsyncCrypto::get_entropy_async(
  std::size_t numberOfBytes, GetEntropyCompleteCallback callback) const noexcept
{
  if (park_async())
    push(mGetEntropy, std::move(callback));
  else if (const auto answer = mEntropyAnswer.load(); answer != 0 && mEntropyAnswerHoldsBytes.load())
    mUnderlying->get_entropy_async(numberOfBytes,
      [answer, callback = std::move(callback)](ua::ByteStringResult generated) mutable
      {
        if (generated.has_value())
          callback(ua::ByteStringResult{std::move(generated).value(), ua::StatusCode{answer}});
        else
          callback(std::move(generated));
      });
  else if (answer != 0)
    callback(ua::ByteStringResult{ua::StatusCode{answer}});
  else
    mUnderlying->get_entropy_async(numberOfBytes, std::move(callback));
}

void FakeAsyncCrypto::calculate_digest_async(ua::HashAlgorithm algorithm, ua::ByteString inputBuffer,
  ua::span<const ua::byte> input, CalculateDigestCompleteCallback callback) const noexcept
{
  if (park_async())
    push(mCalculateDigest, std::move(callback));
  else
    mUnderlying->calculate_digest_async(algorithm, std::move(inputBuffer), input, std::move(callback));
}

void FakeAsyncCrypto::derive_symmetric_keys_async(ua::SymmetricKeyDerivationAlgorithm algorithm,
  std::size_t numberOfBytes, ua::ByteString secret, ua::ByteString seed,
  DeriveSymmetricKeysCompleteCallback callback) const noexcept
{
  if (park_async())
    push(mDeriveSymmetricKeys, std::move(callback));
  else
    mUnderlying->derive_symmetric_keys_async(
      algorithm, numberOfBytes, std::move(secret), std::move(seed), std::move(callback));
}

void FakeAsyncCrypto::derive_symmetric_keys_async(ua::SymmetricKeyDerivationAlgorithm algorithm,
  std::size_t numberOfBytes, ua::ByteString secret, ua::ByteString salt, ua::ByteString info,
  DeriveSymmetricKeysCompleteCallback callback) const noexcept
{
  if (park_async())
    push(mDeriveSymmetricKeys, std::move(callback));
  else
    mUnderlying->derive_symmetric_keys_async(
      algorithm, numberOfBytes, std::move(secret), std::move(salt), std::move(info), std::move(callback));
}

void FakeAsyncCrypto::symmetric_encrypt_async(std::shared_ptr<const void> resource,
  ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv, ua::span<const ua::byte> key,
  ua::span<const ua::byte> plainText, ua::span<ua::byte> cipherText,
  SymmetricEncryptCompleteCallback callback) const noexcept
{
  if (park_async())
  {
    push(mSymmetricEncrypt, std::move(callback));
    return;
  }

  std::optional<ua::StatusCode> failStatus;
  bool corruptPadding = false;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mFailSymmetricEncryptIndex.has_value() && mSymmetricEncryptCallCount == *mFailSymmetricEncryptIndex)
      failStatus = mFailSymmetricEncryptStatus;
    ++mSymmetricEncryptCallCount;
    if (mCorruptNextRsaSecretPayloadPadding)
    {
      mCorruptNextRsaSecretPayloadPadding = false;
      corruptPadding = true;
    }
  }
  if (failStatus.has_value())
  {
    callback(ua::VoidResult{*failStatus,
      ua::make_error_detail(
        "ScriptedFailure", "FakeAsyncCrypto scripted symmetric_encrypt failure", "FakeAsyncCrypto")});
    return;
  }

  if (corruptPadding)
  {
    auto mutated = std::make_shared<ua::ByteString>(plainText);
    if (mutated->size() >= 3)
    {
      const auto paddingSize = static_cast<std::size_t>((*mutated)[mutated->size() - 2]) |
                               (static_cast<std::size_t>((*mutated)[mutated->size() - 1]) << 8);
      if (paddingSize > 0 && paddingSize + 2 <= mutated->size())
      {
        (*mutated)[mutated->size() - paddingSize - 2] ^= 0x01;
        {
          std::lock_guard<std::mutex> lock(mMutex);
          ++mCorruptedRsaSecretPayloadCount;
        }
        mUnderlying->symmetric_encrypt_async(
          mutated, algorithm, iv, key, *mutated, cipherText, std::move(callback));
        return;
      }
    }
  }

  mUnderlying->symmetric_encrypt_async(
    std::move(resource), algorithm, iv, key, plainText, cipherText, std::move(callback));
}

void FakeAsyncCrypto::symmetric_decrypt_async(std::shared_ptr<const void> resource,
  ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv, ua::span<const ua::byte> key,
  ua::span<const ua::byte> cipherText, ua::span<ua::byte> plainText,
  SymmetricDecryptCompleteCallback callback) const noexcept
{
  if (park_async())
    push(mSymmetricDecrypt, std::move(callback));
  else
    mUnderlying->symmetric_decrypt_async(
      std::move(resource), algorithm, iv, key, cipherText, plainText, std::move(callback));
}

void FakeAsyncCrypto::symmetric_encrypt_and_sign_async(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::ByteString iv, ua::ByteString key, ua::ByteString plainTextBuffer, ua::span<const ua::byte> plainText,
  ua::span<const ua::byte> additionalData, ua::optional<ua::ByteString> cipherTextBuffer,
  ua::span<ua::byte> cipherText, SymmetricEncryptAndSignCompleteCallback callback) const
{
  if (park_async())
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mSymmetricEncryptAndSignInputs.push_back(AeadKeyInputs{iv, key});
    }
    push(mSymmetricEncryptAndSign, std::move(callback));
  }
  else
    mUnderlying->symmetric_encrypt_and_sign_async(algorithm,
      std::move(iv),
      std::move(key),
      std::move(plainTextBuffer),
      plainText,
      additionalData,
      std::move(cipherTextBuffer),
      cipherText,
      std::move(callback));
}

void FakeAsyncCrypto::symmetric_verify_and_decrypt_async(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::ByteString iv, ua::ByteString key, ua::ByteString cipherTextBuffer, ua::span<const ua::byte> cipherText,
  ua::span<const ua::byte> additionalData, ua::span<const ua::byte> signature,
  ua::optional<ua::ByteString> plainTextBuffer, ua::span<ua::byte> plainText,
  SymmetricVerifyAndDecryptCompleteCallback callback) const
{
  if (park_async())
    push(mSymmetricVerifyAndDecrypt, std::move(callback));
  else
    mUnderlying->symmetric_verify_and_decrypt_async(algorithm,
      std::move(iv),
      std::move(key),
      std::move(cipherTextBuffer),
      cipherText,
      additionalData,
      signature,
      std::move(plainTextBuffer),
      plainText,
      std::move(callback));
}

void FakeAsyncCrypto::symmetric_sign_async(std::shared_ptr<const void> resource,
  ua::SymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> key, ua::span<const ua::byte> input,
  SymmetricSignCompleteCallback callback) const
{
  if (park_async())
  {
    push(mSymmetricSign, std::move(callback));
    return;
  }

  std::optional<ua::StatusCode> failStatus;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mFailSymmetricSignIndex.has_value() && mSymmetricSignCallCount == *mFailSymmetricSignIndex)
      failStatus = mFailSymmetricSignStatus;
    ++mSymmetricSignCallCount;
  }
  if (failStatus.has_value())
  {
    callback(ua::ByteStringResult{*failStatus,
      ua::make_error_detail(
        "ScriptedFailure", "FakeAsyncCrypto scripted symmetric_sign failure", "FakeAsyncCrypto")});
    return;
  }

  mUnderlying->symmetric_sign_async(std::move(resource), algorithm, key, input, std::move(callback));
}

void FakeAsyncCrypto::symmetric_verify_async(std::shared_ptr<const void> resource,
  ua::SymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> key, ua::span<const ua::byte> input,
  ua::span<const ua::byte> signature, SymmetricVerifyCompleteCallback callback) const
{
  if (park_async())
    push(mSymmetricVerify, std::move(callback));
  else
    mUnderlying->symmetric_verify_async(
      std::move(resource), algorithm, key, input, signature, std::move(callback));
}

void FakeAsyncCrypto::asymmetric_encrypt_async(std::shared_ptr<const void> resource,
  ua::AsymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> publicKey,
  ua::span<const ua::byte> plainText, ua::span<ua::byte> cipherText,
  AsymmetricEncryptCompleteCallback callback) const
{
  if (park_async())
    push(mAsymmetricEncrypt, std::move(callback));
  else
    mUnderlying->asymmetric_encrypt_async(
      std::move(resource), algorithm, publicKey, plainText, cipherText, std::move(callback));
}

void FakeAsyncCrypto::asymmetric_decrypt_async(std::shared_ptr<const void> resource,
  ua::AsymmetricEncryptionAlgorithm algorithm, std::shared_ptr<const ua::AsymmetricKeyPair> privateKey,
  ua::span<const ua::byte> cipherText, ua::span<ua::byte> plainText,
  AsymmetricDecryptCompleteCallback callback) const
{
  if (park_async())
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mAsymmetricDecrypt.push_back(ParkedAsymmetricDecrypt{std::move(callback), plainText});
  }
  else
    mUnderlying->asymmetric_decrypt_async(
      std::move(resource), algorithm, std::move(privateKey), cipherText, plainText, std::move(callback));
}

void FakeAsyncCrypto::asymmetric_sign_async(std::shared_ptr<const void> resource,
  ua::AsymmetricSignatureAlgorithm algorithm, std::shared_ptr<const ua::AsymmetricKeyPair> privateKey,
  ua::span<const ua::byte> input, AsymmetricSignCompleteCallback callback) const
{
  if (park_async())
    push(mAsymmetricSign, std::move(callback));
  else if (const auto failure = mAsymmetricSignFailure.load(); failure != 0)
    callback(ua::ByteStringResult{ua::StatusCode{failure}});
  else
    mUnderlying->asymmetric_sign_async(
      std::move(resource), algorithm, std::move(privateKey), input, std::move(callback));
}

void FakeAsyncCrypto::asymmetric_verify_async(std::shared_ptr<const void> resource,
  ua::AsymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> publicKey,
  ua::span<const ua::byte> input, ua::span<const ua::byte> signature,
  AsymmetricVerifyCompleteCallback callback) const
{
  if (park_async())
    push(mAsymmetricVerify, std::move(callback));
  else if (const auto answer = mAsymmetricVerifyAnswer.load(); answer != 0)
    callback(ua::VoidResult{ua::StatusCode{answer}});
  else
    mUnderlying->asymmetric_verify_async(
      std::move(resource), algorithm, publicKey, input, signature, std::move(callback));
}

void FakeAsyncCrypto::create_asymmetric_key_pair_async(ua::CertificateKeyAlgorithm algorithm,
  ua::optional<std::size_t> keyLengthInBits, CreateAsymmetricKeyPairCompleteCallback callback) const
{
  if (park_async())
    push(mCreateAsymmetricKeyPair, std::move(callback));
  else
    mUnderlying->create_asymmetric_key_pair_async(algorithm, keyLengthInBits, std::move(callback));
}

void FakeAsyncCrypto::create_ephemeral_keys_async(
  ua::EphemeralKeyAlgorithm algorithm, CreateEphemeralKeysCompleteCallback callback) const
{
  if (park_async())
    push(mCreateEphemeralKeys, std::move(callback));
  else if (const auto answer = mEphemeralKeysAnswer.load(); answer != 0)
    callback(ua::Crypto::EphemeralKeyPairResult{ua::StatusCode{answer}});
  else
    mUnderlying->create_ephemeral_keys_async(algorithm, std::move(callback));
}

void FakeAsyncCrypto::calculate_shared_secret_async(ua::EphemeralKeyAlgorithm algorithm,
  ua::ByteString localPrivateKey, ua::ByteString remotePublicKey,
  CalculateSharedSecretCompleteCallback callback) const
{
  if (park_async())
    push(mCalculateSharedSecret, std::move(callback));
  else
    mUnderlying->calculate_shared_secret_async(
      algorithm, std::move(localPrivateKey), std::move(remotePublicKey), std::move(callback));
}

void FakeAsyncCrypto::create_certificate_async(
  const CreateCertificateConfig& parameters, CreateCertificateCompleteCallback callback) const
{
  if (park_async())
    push(mCreateCertificate, std::move(callback));
  else
    mUnderlying->create_certificate_async(parameters, std::move(callback));
}

void FakeAsyncCrypto::create_certificate_signing_request_async(
  const CreateCsrConfig& parameters, CreateCertificateSigningRequestCompleteCallback callback) const
{
  if (park_async())
    push(mCreateCertificateSigningRequest, std::move(callback));
  else
    mUnderlying->create_certificate_signing_request_async(parameters, std::move(callback));
}

void FakeAsyncCrypto::sign_certificate_request_async(
  const SignCsrConfig& parameters, SignCsrCompleteCallback callback) const
{
  if (park_async())
    push(mSignCertificateRequest, std::move(callback));
  else
    mUnderlying->sign_certificate_request_async(parameters, std::move(callback));
}

void FakeAsyncCrypto::create_crl_async(std::shared_ptr<const ua::X509Certificate> issuer,
  std::shared_ptr<const ua::AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers,
  CreateCrlCompleteCallback callback) const
{
  if (park_async())
    push(mCreateCrl, std::move(callback));
  else
    mUnderlying->create_crl_async(
      std::move(issuer), std::move(issuerKeys), std::move(revokedSerialNumbers), std::move(callback));
}

void FakeAsyncCrypto::validate_certificate_async(const ua::CertificateValidationRequest& request,
  ua::CertificateValidationMaterial material, CertificateValidationCompleteCallback callback) const
{
  if (park_async())
    push(mValidateCertificate, std::move(callback));
  else
    mUnderlying->validate_certificate_async(request, std::move(material), std::move(callback));
}

void FakeAsyncCrypto::validate_crl_async(ua::TrustListValidationOptions validationOptions,
  std::shared_ptr<const ua::X509Crl> crl,
  std::vector<std::shared_ptr<const ua::X509Certificate>> issuerCandidates,
  CrlValidationCompleteCallback callback) const
{
  CrlAnswer answer;
  {
    std::lock_guard lock(mMutex);
    mCrlValidationOptions.push_back(validationOptions);
    answer = mCrlAnswer;
    if (answer == CrlAnswer::Hold)
    {
      mHeldCrlValidations.push_back(
        {validationOptions, std::move(crl), std::move(issuerCandidates), std::move(callback)});
      return;
    }
  }
  if (answer == CrlAnswer::Drop)
    return;  // the callback is destroyed unanswered
  if (answer == CrlAnswer::Twice)
  {
    // The real answer, then a second (contradicting) one.
    auto shared = std::make_shared<CrlValidationCompleteCallback>(std::move(callback));
    mUnderlying->validate_crl_async(validationOptions,
      std::move(crl),
      std::move(issuerCandidates),
      [shared](ua::VoidResult result)
      {
        const bool good = result.is_good();
        (*shared)(std::move(result));
        (*shared)(
          good ? ua::VoidResult{ua::StatusCode{ua::Status::BadSecurityChecksFailed}} : ua::VoidResult{});
      });
    return;
  }
  mUnderlying->validate_crl_async(
    validationOptions, std::move(crl), std::move(issuerCandidates), std::move(callback));
}

void FakeAsyncCrypto::set_crl_answer(CrlAnswer answer)
{
  std::lock_guard lock(mMutex);
  mCrlAnswer = answer;
}

std::vector<ua::TrustListValidationOptions> FakeAsyncCrypto::crl_validation_options() const
{
  std::lock_guard lock(mMutex);
  return mCrlValidationOptions;
}

std::size_t FakeAsyncCrypto::held_crl_validation_count() const
{
  std::lock_guard lock(mMutex);
  return mHeldCrlValidations.size();
}

void FakeAsyncCrypto::release_held_crl_validations()
{
  std::vector<HeldCrlValidation> held;
  {
    std::lock_guard lock(mMutex);
    held.swap(mHeldCrlValidations);
    mCrlAnswer = CrlAnswer::Forward;  // later calls are answered at once
  }
  for (auto& call : held)
    mUnderlying->validate_crl_async(
      call.options, std::move(call.crl), std::move(call.candidates), std::move(call.callback));
}

// ---------------------------------------------------------------------------
// Sync overrides - forward to underlying real Crypto.
// ---------------------------------------------------------------------------

bool FakeAsyncCrypto::has_secure_element() const
{
  return mUnderlying->has_secure_element();
}

ua::ByteString FakeAsyncCrypto::get_entropy_sync(std::size_t numberOfBytes) const
{
  return mUnderlying->get_entropy_sync(numberOfBytes);
}

ua::ByteString FakeAsyncCrypto::calculate_digest_sync(
  ua::HashAlgorithm algorithm, ua::span<const ua::byte> input) const
{
  return mUnderlying->calculate_digest_sync(algorithm, input);
}

ua::ByteString FakeAsyncCrypto::derive_symmetric_keys_sync(ua::SymmetricKeyDerivationAlgorithm algorithm,
  std::size_t numberOfBytes, ua::span<const ua::byte> secret, ua::span<const ua::byte> seed) const
{
  return mUnderlying->derive_symmetric_keys_sync(algorithm, numberOfBytes, secret, seed);
}

ua::ByteString FakeAsyncCrypto::derive_symmetric_keys_sync(ua::SymmetricKeyDerivationAlgorithm algorithm,
  std::size_t numberOfBytes, ua::span<const ua::byte> secret, ua::span<const ua::byte> salt,
  ua::span<const ua::byte> info) const
{
  return mUnderlying->derive_symmetric_keys_sync(algorithm, numberOfBytes, secret, salt, info);
}

void FakeAsyncCrypto::symmetric_encrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> plainText,
  ua::span<ua::byte> cipherText) const
{
  mUnderlying->symmetric_encrypt_sync(algorithm, iv, key, plainText, cipherText);
}

void FakeAsyncCrypto::symmetric_decrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> cipherText,
  ua::span<ua::byte> plainText) const
{
  mUnderlying->symmetric_decrypt_sync(algorithm, iv, key, cipherText, plainText);
}

ua::ByteString FakeAsyncCrypto::symmetric_encrypt_and_sign_sync(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> plainText,
  ua::span<const ua::byte> additionalData, ua::span<ua::byte> cipherText) const
{
  return mUnderlying->symmetric_encrypt_and_sign_sync(
    algorithm, iv, key, plainText, additionalData, cipherText);
}

void FakeAsyncCrypto::symmetric_verify_and_decrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm,
  ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> cipherText,
  ua::span<const ua::byte> additionalData, ua::span<const ua::byte> signature,
  ua::span<ua::byte> plainText) const
{
  mUnderlying->symmetric_verify_and_decrypt_sync(
    algorithm, iv, key, cipherText, additionalData, signature, plainText);
}

ua::ByteString FakeAsyncCrypto::symmetric_sign_sync(ua::SymmetricSignatureAlgorithm algorithm,
  ua::span<const ua::byte> key, ua::span<const ua::byte> input) const
{
  return mUnderlying->symmetric_sign_sync(algorithm, key, input);
}

void FakeAsyncCrypto::symmetric_verify_sync(ua::SymmetricSignatureAlgorithm algorithm,
  ua::span<const ua::byte> key, ua::span<const ua::byte> input, ua::span<const ua::byte> signature) const
{
  mUnderlying->symmetric_verify_sync(algorithm, key, input, signature);
}

void FakeAsyncCrypto::asymmetric_encrypt_sync(ua::AsymmetricEncryptionAlgorithm algorithm,
  ua::span<const ua::byte> publicKey, ua::span<const ua::byte> plainText, ua::span<ua::byte> cipherText) const
{
  mUnderlying->asymmetric_encrypt_sync(algorithm, publicKey, plainText, cipherText);
}

ua::span<const ua::byte> FakeAsyncCrypto::asymmetric_decrypt_sync(ua::AsymmetricEncryptionAlgorithm algorithm,
  std::shared_ptr<const ua::AsymmetricKeyPair> privateKey, ua::span<const ua::byte> cipherText,
  ua::span<ua::byte> plainText) const
{
  return mUnderlying->asymmetric_decrypt_sync(algorithm, privateKey, cipherText, plainText);
}

ua::ByteString FakeAsyncCrypto::asymmetric_sign_sync(ua::AsymmetricSignatureAlgorithm algorithm,
  std::shared_ptr<const ua::AsymmetricKeyPair> privateKey, ua::span<const ua::byte> input) const
{
  return mUnderlying->asymmetric_sign_sync(algorithm, privateKey, input);
}

void FakeAsyncCrypto::asymmetric_verify_sync(ua::AsymmetricSignatureAlgorithm algorithm,
  ua::span<const ua::byte> publicKey, ua::span<const ua::byte> input,
  ua::span<const ua::byte> signature) const
{
  mUnderlying->asymmetric_verify_sync(algorithm, publicKey, input, signature);
}

std::shared_ptr<const ua::AsymmetricKeyPair> FakeAsyncCrypto::create_asymmetric_key_pair_sync(
  ua::CertificateKeyAlgorithm algorithm, ua::optional<std::size_t> keyLengthInBits) const
{
  return mUnderlying->create_asymmetric_key_pair_sync(algorithm, keyLengthInBits);
}

ua::Crypto::EphemeralKeyPair FakeAsyncCrypto::create_ephemeral_keys_sync(
  ua::EphemeralKeyAlgorithm algorithm) const
{
  return mUnderlying->create_ephemeral_keys_sync(algorithm);
}

ua::ByteString FakeAsyncCrypto::calculate_shared_secret_sync(ua::EphemeralKeyAlgorithm algorithm,
  ua::span<const ua::byte> localPrivateKey, ua::span<const ua::byte> remotePublicKey) const
{
  return mUnderlying->calculate_shared_secret_sync(algorithm, localPrivateKey, remotePublicKey);
}

std::shared_ptr<const ua::X509Certificate> FakeAsyncCrypto::read_certificate_from_der(
  ua::span<const ua::byte> der) const
{
  return mUnderlying->read_certificate_from_der(der);
}

std::vector<std::shared_ptr<const ua::X509Certificate>> FakeAsyncCrypto::read_certificates_from_der(
  ua::span<const ua::byte> der) const
{
  return mUnderlying->read_certificates_from_der(der);
}

std::shared_ptr<const ua::X509Crl> FakeAsyncCrypto::read_crl_from_der(ua::span<const ua::byte> der) const
{
  return mUnderlying->read_crl_from_der(der);
}

std::vector<std::shared_ptr<const ua::X509Crl>> FakeAsyncCrypto::read_crls_from_der(
  ua::span<const ua::byte> der) const
{
  return mUnderlying->read_crls_from_der(der);
}

std::shared_ptr<const ua::AsymmetricKeyPair> FakeAsyncCrypto::get_private_key_from_pem(
  ua::CertificateKeyAlgorithm keyAlgorithm, ua::span<ua::byte> pem) const
{
  return mUnderlying->get_private_key_from_pem(keyAlgorithm, pem);
}

std::shared_ptr<const ua::AsymmetricKeyPair> FakeAsyncCrypto::get_public_key_from_der(
  ua::CertificateKeyAlgorithm keyAlgorithm, ua::span<const ua::byte> der) const
{
  return mUnderlying->get_public_key_from_der(keyAlgorithm, der);
}

// ---------------------------------------------------------------------------
// Pending-completion API.
// ---------------------------------------------------------------------------

std::size_t FakeAsyncCrypto::pending_get_entropy_count() const
{
  return count(mGetEntropy);
}

std::size_t FakeAsyncCrypto::pending_calculate_digest_count() const
{
  return count(mCalculateDigest);
}

std::size_t FakeAsyncCrypto::pending_derive_symmetric_keys_count() const
{
  return count(mDeriveSymmetricKeys);
}

std::size_t FakeAsyncCrypto::pending_symmetric_encrypt_count() const
{
  return count(mSymmetricEncrypt);
}

std::size_t FakeAsyncCrypto::pending_symmetric_decrypt_count() const
{
  return count(mSymmetricDecrypt);
}

std::size_t FakeAsyncCrypto::pending_symmetric_encrypt_and_sign_count() const
{
  return count(mSymmetricEncryptAndSign);
}

FakeAsyncCrypto::AeadKeyInputs FakeAsyncCrypto::parked_symmetric_encrypt_and_sign_inputs(
  std::size_t parkIndex) const
{
  std::lock_guard<std::mutex> lock(mMutex);
  if (parkIndex >= mSymmetricEncryptAndSignInputs.size())
    throw std::out_of_range{"no parked symmetric_encrypt_and_sign call at this index"};
  return mSymmetricEncryptAndSignInputs[parkIndex];
}

std::size_t FakeAsyncCrypto::pending_symmetric_verify_and_decrypt_count() const
{
  return count(mSymmetricVerifyAndDecrypt);
}

std::size_t FakeAsyncCrypto::pending_symmetric_sign_count() const
{
  return count(mSymmetricSign);
}

std::size_t FakeAsyncCrypto::pending_symmetric_verify_count() const
{
  return count(mSymmetricVerify);
}

std::size_t FakeAsyncCrypto::pending_asymmetric_encrypt_count() const
{
  return count(mAsymmetricEncrypt);
}

std::size_t FakeAsyncCrypto::pending_asymmetric_decrypt_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mAsymmetricDecrypt.size();
}

std::size_t FakeAsyncCrypto::pending_asymmetric_sign_count() const
{
  return count(mAsymmetricSign);
}

std::size_t FakeAsyncCrypto::pending_asymmetric_verify_count() const
{
  return count(mAsymmetricVerify);
}

std::size_t FakeAsyncCrypto::pending_create_asymmetric_key_pair_count() const
{
  return count(mCreateAsymmetricKeyPair);
}

std::size_t FakeAsyncCrypto::pending_create_ephemeral_keys_count() const
{
  return count(mCreateEphemeralKeys);
}

std::size_t FakeAsyncCrypto::pending_calculate_shared_secret_count() const
{
  return count(mCalculateSharedSecret);
}

std::size_t FakeAsyncCrypto::pending_create_certificate_count() const
{
  return count(mCreateCertificate);
}

std::size_t FakeAsyncCrypto::pending_create_certificate_signing_request_count() const
{
  return count(mCreateCertificateSigningRequest);
}

std::size_t FakeAsyncCrypto::pending_sign_certificate_request_count() const
{
  return count(mSignCertificateRequest);
}

std::size_t FakeAsyncCrypto::pending_create_crl_count() const
{
  return count(mCreateCrl);
}

std::size_t FakeAsyncCrypto::pending_validate_certificate_count() const
{
  return count(mValidateCertificate);
}

void FakeAsyncCrypto::complete_pending_get_entropy(std::size_t idx, ua::ByteStringResult result)
{
  fire(mGetEntropy, idx, std::move(result), "get_entropy");
}

void FakeAsyncCrypto::complete_pending_calculate_digest(std::size_t idx, CalculateDigestOutputResult result)
{
  fire(mCalculateDigest, idx, std::move(result), "calculate_digest");
}

void FakeAsyncCrypto::complete_pending_derive_symmetric_keys(std::size_t idx, ua::ByteStringResult result)
{
  fire(mDeriveSymmetricKeys, idx, std::move(result), "derive_symmetric_keys");
}

void FakeAsyncCrypto::complete_pending_symmetric_encrypt(std::size_t idx, ua::VoidResult result)
{
  fire(mSymmetricEncrypt, idx, std::move(result), "symmetric_encrypt");
}

void FakeAsyncCrypto::complete_pending_symmetric_decrypt(std::size_t idx, ua::VoidResult result)
{
  fire(mSymmetricDecrypt, idx, std::move(result), "symmetric_decrypt");
}

void FakeAsyncCrypto::complete_pending_symmetric_encrypt_and_sign(
  std::size_t idx, SymmetricEncryptAndSignOutputResult result)
{
  fire(mSymmetricEncryptAndSign, idx, std::move(result), "symmetric_encrypt_and_sign");
}

void FakeAsyncCrypto::complete_pending_symmetric_verify_and_decrypt(
  std::size_t idx, SymmetricVerifyAndDecryptOutputResult result)
{
  fire(mSymmetricVerifyAndDecrypt, idx, std::move(result), "symmetric_verify_and_decrypt");
}

void FakeAsyncCrypto::complete_pending_symmetric_sign(std::size_t idx, ua::ByteStringResult result)
{
  fire(mSymmetricSign, idx, std::move(result), "symmetric_sign");
}

void FakeAsyncCrypto::complete_pending_symmetric_verify(std::size_t idx, ua::VoidResult result)
{
  fire(mSymmetricVerify, idx, std::move(result), "symmetric_verify");
}

void FakeAsyncCrypto::complete_pending_asymmetric_encrypt(std::size_t idx, ua::VoidResult result)
{
  fire(mAsymmetricEncrypt, idx, std::move(result), "asymmetric_encrypt");
}

void FakeAsyncCrypto::complete_pending_asymmetric_decrypt(std::size_t idx, ByteSpanResult result)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mAsymmetricDecrypt.size())
    throw std::out_of_range("FakeAsyncCrypto: pending asymmetric_decrypt index out of range");
  auto cb = std::move(mAsymmetricDecrypt[idx].callback);
  mAsymmetricDecrypt.erase(mAsymmetricDecrypt.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();
  cb(std::move(result));
}

void FakeAsyncCrypto::complete_pending_asymmetric_decrypt_with_fill(
  std::size_t idx, ua::byte fillByte, std::size_t length)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (idx >= mAsymmetricDecrypt.size())
    throw std::out_of_range("FakeAsyncCrypto: pending asymmetric_decrypt index out of range");
  auto parked = std::move(mAsymmetricDecrypt[idx]);
  mAsymmetricDecrypt.erase(mAsymmetricDecrypt.begin() + static_cast<std::ptrdiff_t>(idx));
  lock.unlock();

  const std::size_t written = std::min(length, parked.output.size());
  for (std::size_t i = 0; i < written; ++i)
    parked.output[i] = fillByte;
  parked.callback(ByteSpanResult{ua::span<const ua::byte>{parked.output.data(), written}});
}

void FakeAsyncCrypto::complete_pending_asymmetric_sign(std::size_t idx, ua::ByteStringResult result)
{
  fire(mAsymmetricSign, idx, std::move(result), "asymmetric_sign");
}

void FakeAsyncCrypto::complete_pending_asymmetric_verify(std::size_t idx, ua::VoidResult result)
{
  fire(mAsymmetricVerify, idx, std::move(result), "asymmetric_verify");
}

void FakeAsyncCrypto::complete_pending_create_asymmetric_key_pair(std::size_t idx, ua::KeyPairResult result)
{
  fire(mCreateAsymmetricKeyPair, idx, std::move(result), "create_asymmetric_key_pair");
}

void FakeAsyncCrypto::complete_pending_create_ephemeral_keys(std::size_t idx, EphemeralKeyPairResult result)
{
  fire(mCreateEphemeralKeys, idx, std::move(result), "create_ephemeral_keys");
}

void FakeAsyncCrypto::complete_pending_calculate_shared_secret(std::size_t idx, ua::ByteStringResult result)
{
  fire(mCalculateSharedSecret, idx, std::move(result), "calculate_shared_secret");
}

void FakeAsyncCrypto::complete_pending_create_certificate(std::size_t idx, ua::CertificateResult result)
{
  fire(mCreateCertificate, idx, std::move(result), "create_certificate");
}

void FakeAsyncCrypto::complete_pending_create_certificate_signing_request(
  std::size_t idx, ua::ByteStringResult result)
{
  fire(mCreateCertificateSigningRequest, idx, std::move(result), "create_certificate_signing_request");
}

void FakeAsyncCrypto::complete_pending_sign_certificate_request(std::size_t idx, ua::CertificateResult result)
{
  fire(mSignCertificateRequest, idx, std::move(result), "sign_certificate_request");
}

void FakeAsyncCrypto::complete_pending_create_crl(std::size_t idx, ua::CrlResult result)
{
  fire(mCreateCrl, idx, std::move(result), "create_crl");
}

void FakeAsyncCrypto::complete_pending_validate_certificate(std::size_t idx, ua::VoidResult result)
{
  fire(mValidateCertificate, idx, std::move(result), "validate_certificate");
}

void FakeAsyncCrypto::drop_pending_validate_certificate()
{
  std::vector<CertificateValidationCompleteCallback> dropped;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    dropped.swap(mValidateCertificate);
  }
  // Destroyed here, outside the lock: a destroyed continuation may run code that calls back into this fake.
}

}  // namespace ua::test_helpers
