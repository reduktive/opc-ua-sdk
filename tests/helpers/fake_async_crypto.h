// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_FAKE_ASYNC_CRYPTO_H
#define UA_TEST_HELPERS_FAKE_ASYNC_CRYPTO_H

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <vector>

#include "ua_crypto.h"
#include "ua_status_code.h"

namespace ua::test_helpers
{

/// Test wrapper around `Crypto` with optional parking semantics.
///
/// Default mode (`set_park_async(false)`, factory default): every `*_async`
/// method forwards to a real OpenSSL-backed underlying `Crypto`. This is the
/// happy-path mode for tests that need a working crypto provider but don't
/// care about observing the in-flight crypto call (e.g. server-session
/// nonce generation, OPN signing).
///
/// Parking mode (`set_park_async(true)`): every `*_async` call queues its
/// completion callback instead of forwarding. Tests drive completion via
/// `complete_pending_<op>(idx, Result)` to inject good or bad results
/// (e.g. 4.7 OF-K bad-entropy injection, 4.11 in-flight observation).
///
/// Sync methods and non-async getters always forward to the underlying.
///
/// Used by 4.3 (DA/ES/DK), 4.7 (OF-K entropy injection), 4.8 (OPN paths),
/// 4.9 (nonce generation), 4.10 (signing).
class FakeAsyncCrypto final : public ua::Crypto
{
public:
  static std::shared_ptr<FakeAsyncCrypto> create();

  /// Globally enable / disable parking of `*_async` calls. Default is
  /// `false` (forward to underlying real Crypto).
  void set_park_async(bool park);

  /// When @p status is not Good, every later asymmetric_sign_async that is not parked answers it, holding no
  /// signature, instead of signing (Good restores forwarding): a provider whose sign answer is Bad or
  /// Uncertain in the middle of an otherwise real flow.
  void set_asymmetric_sign_failure(ua::StatusCode status);

  /// When @p status is not Good, every later asymmetric_verify_async that is not parked answers it instead of
  /// verifying (Good restores forwarding): a provider whose verify answer is Bad or Uncertain in the middle
  /// of an otherwise real flow.
  void set_asymmetric_verify_answer(ua::StatusCode status);

  /// When @p status is not Good, every later get_entropy_async that is not parked answers it, holding no
  /// bytes, instead of generating (Good restores forwarding): a provider whose entropy answer is Bad or
  /// Uncertain in the middle of an otherwise real flow.
  /// With @p holdingBytes, the answer holds the entropy the real provider generated, with @p status as its
  /// code.
  void set_entropy_answer(ua::StatusCode status, bool holdingBytes = false);

  /// When @p status is not Good, every later create_ephemeral_keys_async that is not parked answers it,
  /// holding no key pair, instead of generating (Good restores forwarding).
  void set_ephemeral_keys_answer(ua::StatusCode status);
  bool park_async() const;

  // --- Async overrides (parked) ---

  void get_entropy_async(
    std::size_t numberOfBytes, GetEntropyCompleteCallback callback) const noexcept override;

  void calculate_digest_async(ua::HashAlgorithm algorithm, ua::ByteString inputBuffer,
    ua::span<const ua::byte> input, CalculateDigestCompleteCallback callback) const noexcept override;

  void derive_symmetric_keys_async(ua::SymmetricKeyDerivationAlgorithm algorithm, std::size_t numberOfBytes,
    ua::ByteString secret, ua::ByteString seed,
    DeriveSymmetricKeysCompleteCallback callback) const noexcept override;

  void derive_symmetric_keys_async(ua::SymmetricKeyDerivationAlgorithm algorithm, std::size_t numberOfBytes,
    ua::ByteString secret, ua::ByteString salt, ua::ByteString info,
    DeriveSymmetricKeysCompleteCallback callback) const noexcept override;

  void symmetric_encrypt_async(std::shared_ptr<const void> resource,
    ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv, ua::span<const ua::byte> key,
    ua::span<const ua::byte> plainText, ua::span<ua::byte> cipherText,
    SymmetricEncryptCompleteCallback callback) const noexcept override;

  void symmetric_decrypt_async(std::shared_ptr<const void> resource,
    ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv, ua::span<const ua::byte> key,
    ua::span<const ua::byte> cipherText, ua::span<ua::byte> plainText,
    SymmetricDecryptCompleteCallback callback) const noexcept override;

  void symmetric_encrypt_and_sign_async(ua::SymmetricEncryptionAlgorithm algorithm, ua::ByteString iv,
    ua::ByteString key, ua::ByteString plainTextBuffer, ua::span<const ua::byte> plainText,
    ua::span<const ua::byte> additionalData, ua::optional<ua::ByteString> cipherTextBuffer,
    ua::span<ua::byte> cipherText, SymmetricEncryptAndSignCompleteCallback callback) const override;

  void symmetric_verify_and_decrypt_async(ua::SymmetricEncryptionAlgorithm algorithm, ua::ByteString iv,
    ua::ByteString key, ua::ByteString cipherTextBuffer, ua::span<const ua::byte> cipherText,
    ua::span<const ua::byte> additionalData, ua::span<const ua::byte> signature,
    ua::optional<ua::ByteString> plainTextBuffer, ua::span<ua::byte> plainText,
    SymmetricVerifyAndDecryptCompleteCallback callback) const override;

  void symmetric_sign_async(std::shared_ptr<const void> resource, ua::SymmetricSignatureAlgorithm algorithm,
    ua::span<const ua::byte> key, ua::span<const ua::byte> input,
    SymmetricSignCompleteCallback callback) const override;

  void symmetric_verify_async(std::shared_ptr<const void> resource, ua::SymmetricSignatureAlgorithm algorithm,
    ua::span<const ua::byte> key, ua::span<const ua::byte> input, ua::span<const ua::byte> signature,
    SymmetricVerifyCompleteCallback callback) const override;

  void asymmetric_encrypt_async(std::shared_ptr<const void> resource,
    ua::AsymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> publicKey,
    ua::span<const ua::byte> plainText, ua::span<ua::byte> cipherText,
    AsymmetricEncryptCompleteCallback callback) const override;

  void asymmetric_decrypt_async(std::shared_ptr<const void> resource,
    ua::AsymmetricEncryptionAlgorithm algorithm, std::shared_ptr<const ua::AsymmetricKeyPair> privateKey,
    ua::span<const ua::byte> cipherText, ua::span<ua::byte> plainText,
    AsymmetricDecryptCompleteCallback callback) const override;

  void asymmetric_sign_async(std::shared_ptr<const void> resource, ua::AsymmetricSignatureAlgorithm algorithm,
    std::shared_ptr<const ua::AsymmetricKeyPair> privateKey, ua::span<const ua::byte> input,
    AsymmetricSignCompleteCallback callback) const override;

  void asymmetric_verify_async(std::shared_ptr<const void> resource,
    ua::AsymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> publicKey,
    ua::span<const ua::byte> input, ua::span<const ua::byte> signature,
    AsymmetricVerifyCompleteCallback callback) const override;

  void create_asymmetric_key_pair_async(ua::CertificateKeyAlgorithm algorithm,
    ua::optional<std::size_t> keyLengthInBits,
    CreateAsymmetricKeyPairCompleteCallback callback) const override;

  void create_ephemeral_keys_async(
    ua::EphemeralKeyAlgorithm algorithm, CreateEphemeralKeysCompleteCallback callback) const override;

  void calculate_shared_secret_async(ua::EphemeralKeyAlgorithm algorithm, ua::ByteString localPrivateKey,
    ua::ByteString remotePublicKey, CalculateSharedSecretCompleteCallback callback) const override;

  void create_certificate_async(
    const CreateCertificateConfig& parameters, CreateCertificateCompleteCallback callback) const override;

  void create_certificate_signing_request_async(const CreateCsrConfig& parameters,
    CreateCertificateSigningRequestCompleteCallback callback) const override;

  void sign_certificate_request_async(
    const SignCsrConfig& parameters, SignCsrCompleteCallback callback) const override;

  void create_crl_async(std::shared_ptr<const ua::X509Certificate> issuer,
    std::shared_ptr<const ua::AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers,
    CreateCrlCompleteCallback callback) const override;

  void validate_certificate_async(const ua::CertificateValidationRequest& request,
    ua::CertificateValidationMaterial material,
    CertificateValidationCompleteCallback callback) const override;

  /// Forwards to the underlying crypto, unless one of the CRL controls below is set. Every call's options
  /// are recorded.
  void validate_crl_async(ua::TrustListValidationOptions validationOptions,
    std::shared_ptr<const ua::X509Crl> crl,
    std::vector<std::shared_ptr<const ua::X509Certificate>> issuerCandidates,
    CrlValidationCompleteCallback callback) const override;

  // --- CRL validation controls ---

  /// How validate_crl_async answers: forwarded (default), held until release_held_crl_validations(),
  /// forwarded and then answered a second time, or dropped (the callback destroyed unanswered).
  enum class CrlAnswer
  {
    Forward,
    Hold,
    Twice,
    Drop
  };
  void set_crl_answer(CrlAnswer answer);
  /// The options of every validate_crl_async call so far.
  std::vector<ua::TrustListValidationOptions> crl_validation_options() const;
  std::size_t held_crl_validation_count() const;
  /// Forwards every held call to the underlying crypto (answering them), oldest first.
  void release_held_crl_validations();

  // --- Sync overrides (forward to underlying) ---

  bool has_secure_element() const override;

  ua::ByteString get_entropy_sync(std::size_t numberOfBytes) const override;

  ua::ByteString calculate_digest_sync(
    ua::HashAlgorithm algorithm, ua::span<const ua::byte> input) const override;

  ua::ByteString derive_symmetric_keys_sync(ua::SymmetricKeyDerivationAlgorithm algorithm,
    std::size_t numberOfBytes, ua::span<const ua::byte> secret, ua::span<const ua::byte> seed) const override;

  ua::ByteString derive_symmetric_keys_sync(ua::SymmetricKeyDerivationAlgorithm algorithm,
    std::size_t numberOfBytes, ua::span<const ua::byte> secret, ua::span<const ua::byte> salt,
    ua::span<const ua::byte> info) const override;

  void symmetric_encrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv,
    ua::span<const ua::byte> key, ua::span<const ua::byte> plainText,
    ua::span<ua::byte> cipherText) const override;

  void symmetric_decrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm, ua::span<const ua::byte> iv,
    ua::span<const ua::byte> key, ua::span<const ua::byte> cipherText,
    ua::span<ua::byte> plainText) const override;

  ua::ByteString symmetric_encrypt_and_sign_sync(ua::SymmetricEncryptionAlgorithm algorithm,
    ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> plainText,
    ua::span<const ua::byte> additionalData, ua::span<ua::byte> cipherText) const override;

  void symmetric_verify_and_decrypt_sync(ua::SymmetricEncryptionAlgorithm algorithm,
    ua::span<const ua::byte> iv, ua::span<const ua::byte> key, ua::span<const ua::byte> cipherText,
    ua::span<const ua::byte> additionalData, ua::span<const ua::byte> signature,
    ua::span<ua::byte> plainText) const override;

  ua::ByteString symmetric_sign_sync(ua::SymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> key,
    ua::span<const ua::byte> input) const override;

  void symmetric_verify_sync(ua::SymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> key,
    ua::span<const ua::byte> input, ua::span<const ua::byte> signature) const override;

  void asymmetric_encrypt_sync(ua::AsymmetricEncryptionAlgorithm algorithm,
    ua::span<const ua::byte> publicKey, ua::span<const ua::byte> plainText,
    ua::span<ua::byte> cipherText) const override;

  ua::span<const ua::byte> asymmetric_decrypt_sync(ua::AsymmetricEncryptionAlgorithm algorithm,
    std::shared_ptr<const ua::AsymmetricKeyPair> privateKey, ua::span<const ua::byte> cipherText,
    ua::span<ua::byte> plainText) const override;

  ua::ByteString asymmetric_sign_sync(ua::AsymmetricSignatureAlgorithm algorithm,
    std::shared_ptr<const ua::AsymmetricKeyPair> privateKey, ua::span<const ua::byte> input) const override;

  void asymmetric_verify_sync(ua::AsymmetricSignatureAlgorithm algorithm, ua::span<const ua::byte> publicKey,
    ua::span<const ua::byte> input, ua::span<const ua::byte> signature) const override;

  std::shared_ptr<const ua::AsymmetricKeyPair> create_asymmetric_key_pair_sync(
    ua::CertificateKeyAlgorithm algorithm, ua::optional<std::size_t> keyLengthInBits) const override;

  EphemeralKeyPair create_ephemeral_keys_sync(ua::EphemeralKeyAlgorithm algorithm) const override;

  ua::ByteString calculate_shared_secret_sync(ua::EphemeralKeyAlgorithm algorithm,
    ua::span<const ua::byte> localPrivateKey, ua::span<const ua::byte> remotePublicKey) const override;

  std::shared_ptr<const ua::X509Certificate> read_certificate_from_der(
    ua::span<const ua::byte> der) const override;

  std::vector<std::shared_ptr<const ua::X509Certificate>> read_certificates_from_der(
    ua::span<const ua::byte> der) const override;

  std::shared_ptr<const ua::X509Crl> read_crl_from_der(ua::span<const ua::byte> der) const override;

  std::vector<std::shared_ptr<const ua::X509Crl>> read_crls_from_der(
    ua::span<const ua::byte> der) const override;

  std::shared_ptr<const ua::AsymmetricKeyPair> get_private_key_from_pem(
    ua::CertificateKeyAlgorithm keyAlgorithm, ua::span<ua::byte> pem) const override;

  std::shared_ptr<const ua::AsymmetricKeyPair> get_public_key_from_der(
    ua::CertificateKeyAlgorithm keyAlgorithm, ua::span<const ua::byte> der) const override;

  // --- Scripted mid-message failure API (non-parking mode) ---

  /// Scripted-failure mode: fail the `callIndex`-th (0-based) forwarded
  /// `symmetric_sign_async` call with `status`, forwarding every other call to the
  /// real underlying crypto so earlier chunks sign successfully and one later chunk
  /// fails. This drives the SecurityPolicy symmetric-encode abort path (a mid-stream
  /// sign failure with chunksSent > 0). Only takes effect while parking is disabled;
  /// the default (unset) behaviour forwards all calls unchanged.
  void fail_nth_symmetric_sign(std::size_t callIndex, ua::StatusCode status);

  /// As @ref fail_nth_symmetric_sign, but for `symmetric_encrypt_async`.
  void fail_nth_symmetric_encrypt(std::size_t callIndex, ua::StatusCode status);

  /// Corrupt exactly one padding byte in the next forwarded symmetric-encrypt plaintext.
  /// The RsaEncryptedSecret encoder then authenticates the resulting ciphertext normally, allowing
  /// integration tests to model a non-conforming peer without bypassing the wire protocol.
  void corrupt_next_rsa_secret_payload_padding();
  std::size_t corrupted_rsa_secret_payload_count() const;

  // --- Pending-completion API ---

  std::size_t pending_get_entropy_count() const;
  std::size_t pending_calculate_digest_count() const;
  std::size_t pending_derive_symmetric_keys_count() const;
  std::size_t pending_symmetric_encrypt_count() const;
  std::size_t pending_symmetric_decrypt_count() const;
  std::size_t pending_symmetric_encrypt_and_sign_count() const;

  /// The IV and key a parked `symmetric_encrypt_and_sign_async` was called with.
  struct AeadKeyInputs
  {
    ua::ByteString iv;
    ua::ByteString key;
  };

  /// The IV and key of the @p parkIndex-th parked `symmetric_encrypt_and_sign_async`, in the order the calls
  /// were parked; an entry remains after its call is completed.
  AeadKeyInputs parked_symmetric_encrypt_and_sign_inputs(std::size_t parkIndex) const;
  std::size_t pending_symmetric_verify_and_decrypt_count() const;
  std::size_t pending_symmetric_sign_count() const;
  std::size_t pending_symmetric_verify_count() const;
  std::size_t pending_asymmetric_encrypt_count() const;
  std::size_t pending_asymmetric_decrypt_count() const;
  std::size_t pending_asymmetric_sign_count() const;
  std::size_t pending_asymmetric_verify_count() const;
  std::size_t pending_create_asymmetric_key_pair_count() const;
  std::size_t pending_create_ephemeral_keys_count() const;
  std::size_t pending_calculate_shared_secret_count() const;
  std::size_t pending_create_certificate_count() const;
  std::size_t pending_create_certificate_signing_request_count() const;
  std::size_t pending_sign_certificate_request_count() const;
  std::size_t pending_create_crl_count() const;
  std::size_t pending_validate_certificate_count() const;

  void complete_pending_get_entropy(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_calculate_digest(std::size_t idx, CalculateDigestOutputResult result);
  void complete_pending_derive_symmetric_keys(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_symmetric_encrypt(std::size_t idx, ua::VoidResult result);
  void complete_pending_symmetric_decrypt(std::size_t idx, ua::VoidResult result);
  void complete_pending_symmetric_encrypt_and_sign(
    std::size_t idx, SymmetricEncryptAndSignOutputResult result);
  void complete_pending_symmetric_verify_and_decrypt(
    std::size_t idx, SymmetricVerifyAndDecryptOutputResult result);
  void complete_pending_symmetric_sign(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_symmetric_verify(std::size_t idx, ua::VoidResult result);
  void complete_pending_asymmetric_encrypt(std::size_t idx, ua::VoidResult result);
  void complete_pending_asymmetric_decrypt(std::size_t idx, ByteSpanResult result);

  /// Completes a parked `asymmetric_decrypt_async` by writing `fillByte` into the
  /// first `length` bytes of the caller's output buffer (clamped to its size) and
  /// invoking the callback with a span over those written bytes. This mirrors the
  /// real `asymmetric_decrypt` contract (the recovered plaintext is written into the
  /// caller-supplied output span and the callback receives a view of it), letting a
  /// test inject attacker-controlled post-decrypt plaintext.
  void complete_pending_asymmetric_decrypt_with_fill(std::size_t idx, ua::byte fillByte, std::size_t length);
  void complete_pending_asymmetric_sign(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_asymmetric_verify(std::size_t idx, ua::VoidResult result);
  void complete_pending_create_asymmetric_key_pair(std::size_t idx, ua::KeyPairResult result);
  void complete_pending_create_ephemeral_keys(std::size_t idx, EphemeralKeyPairResult result);
  void complete_pending_calculate_shared_secret(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_create_certificate(std::size_t idx, ua::CertificateResult result);
  void complete_pending_create_certificate_signing_request(std::size_t idx, ua::ByteStringResult result);
  void complete_pending_sign_certificate_request(std::size_t idx, ua::CertificateResult result);
  void complete_pending_create_crl(std::size_t idx, ua::CrlResult result);
  void complete_pending_validate_certificate(std::size_t idx, ua::VoidResult result);
  /// Destroys every parked validate_certificate_async callback unanswered: a validation that is lost.
  void drop_pending_validate_certificate();

private:
  FakeAsyncCrypto();

  template<typename CallbackT>
  std::size_t push(std::vector<CallbackT>& vec, CallbackT cb) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    vec.push_back(std::move(cb));
    return vec.size() - 1;
  }

  template<typename CallbackT>
  std::size_t count(const std::vector<CallbackT>& vec) const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return vec.size();
  }

  template<typename CallbackT, typename Result>
  void fire(std::vector<CallbackT>& vec, std::size_t idx, Result result, const char* label)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    if (idx >= vec.size())
      throw std::out_of_range(std::string("FakeAsyncCrypto: pending ") + label + " index out of range");
    auto cb = std::move(vec[idx]);
    vec.erase(vec.begin() + static_cast<std::ptrdiff_t>(idx));
    lock.unlock();
    cb(std::move(result));
  }

  std::shared_ptr<const ua::Crypto> mUnderlying;
  mutable std::mutex mMutex;
  CrlAnswer mCrlAnswer{CrlAnswer::Forward};
  mutable std::vector<ua::TrustListValidationOptions> mCrlValidationOptions;

  struct HeldCrlValidation
  {
    ua::TrustListValidationOptions options;
    std::shared_ptr<const ua::X509Crl> crl;
    std::vector<std::shared_ptr<const ua::X509Certificate>> candidates;
    CrlValidationCompleteCallback callback;
  };

  mutable std::vector<HeldCrlValidation> mHeldCrlValidations;
  mutable std::atomic<bool> mParkAsync{false};
  std::atomic<ua::StatusCodeValue> mAsymmetricSignFailure{0};
  std::atomic<ua::StatusCodeValue> mAsymmetricVerifyAnswer{0};
  std::atomic<ua::StatusCodeValue> mEntropyAnswer{0};
  std::atomic<bool> mEntropyAnswerHoldsBytes{false};
  std::atomic<ua::StatusCodeValue> mEphemeralKeysAnswer{0};

  // Scripted mid-message failure state (guarded by mMutex). The call counters advance
  // on every non-parked forward so a specific Nth call can be singled out to fail.
  mutable std::size_t mSymmetricSignCallCount{0};
  std::optional<std::size_t> mFailSymmetricSignIndex;
  ua::StatusCode mFailSymmetricSignStatus;
  mutable std::size_t mSymmetricEncryptCallCount{0};
  std::optional<std::size_t> mFailSymmetricEncryptIndex;
  ua::StatusCode mFailSymmetricEncryptStatus;
  mutable bool mCorruptNextRsaSecretPayloadPadding{false};
  mutable std::size_t mCorruptedRsaSecretPayloadCount{0};

  mutable std::vector<GetEntropyCompleteCallback> mGetEntropy;
  mutable std::vector<CalculateDigestCompleteCallback> mCalculateDigest;
  mutable std::vector<DeriveSymmetricKeysCompleteCallback> mDeriveSymmetricKeys;
  mutable std::vector<SymmetricEncryptCompleteCallback> mSymmetricEncrypt;
  mutable std::vector<SymmetricDecryptCompleteCallback> mSymmetricDecrypt;
  mutable std::vector<SymmetricEncryptAndSignCompleteCallback> mSymmetricEncryptAndSign;
  mutable std::vector<AeadKeyInputs> mSymmetricEncryptAndSignInputs;  // every parked call, never erased
  mutable std::vector<SymmetricVerifyAndDecryptCompleteCallback> mSymmetricVerifyAndDecrypt;
  mutable std::vector<SymmetricSignCompleteCallback> mSymmetricSign;
  mutable std::vector<SymmetricVerifyCompleteCallback> mSymmetricVerify;
  mutable std::vector<AsymmetricEncryptCompleteCallback> mAsymmetricEncrypt;

  // Asymmetric decrypt parks both the completion callback and the caller's output
  // span, so a test can write recovered plaintext into the output buffer exactly as
  // the real provider would before completing.
  struct ParkedAsymmetricDecrypt
  {
    AsymmetricDecryptCompleteCallback callback;
    ua::span<ua::byte> output;
  };

  mutable std::vector<ParkedAsymmetricDecrypt> mAsymmetricDecrypt;
  mutable std::vector<AsymmetricSignCompleteCallback> mAsymmetricSign;
  mutable std::vector<AsymmetricVerifyCompleteCallback> mAsymmetricVerify;
  mutable std::vector<CreateAsymmetricKeyPairCompleteCallback> mCreateAsymmetricKeyPair;
  mutable std::vector<CreateEphemeralKeysCompleteCallback> mCreateEphemeralKeys;
  mutable std::vector<CalculateSharedSecretCompleteCallback> mCalculateSharedSecret;
  mutable std::vector<CreateCertificateCompleteCallback> mCreateCertificate;
  mutable std::vector<CreateCertificateSigningRequestCompleteCallback> mCreateCertificateSigningRequest;
  mutable std::vector<SignCsrCompleteCallback> mSignCertificateRequest;
  mutable std::vector<CreateCrlCompleteCallback> mCreateCrl;
  mutable std::vector<CertificateValidationCompleteCallback> mValidateCertificate;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_FAKE_ASYNC_CRYPTO_H
