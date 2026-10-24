// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CRYPTO_OPENSSL_H
#define UA_CRYPTO_OPENSSL_H

#include <openssl/x509.h>
#include "ua_crypto.h"

namespace ua
{

class CryptoOpenSsl : public Crypto
{
public:
  bool has_secure_element() const override
  {
    return false;
  }

  ByteString get_entropy_sync(size_t numberOfBytes) const override;

  void get_entropy_async(size_t numberOfBytes, GetEntropyCompleteCallback callback) const noexcept override;

  ByteString calculate_digest_sync(HashAlgorithm algorithm, span<const byte> input) const override;

  void calculate_digest_async(HashAlgorithm algorithm, ByteString inputBuffer, span<const byte> input,
    CalculateDigestCompleteCallback callback) const noexcept override;

  ByteString derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    span<const byte> secret, span<const byte> seed) const override;

  void derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    ByteString secret, ByteString seed, DeriveSymmetricKeysCompleteCallback callback) const noexcept override;

  ByteString derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    span<const byte> secret, span<const byte> salt, span<const byte> info) const override;

  void derive_symmetric_keys_async(SymmetricKeyDerivationAlgorithm algorithm, size_t numberOfBytes,
    ByteString secret, ByteString salt, ByteString info,
    DeriveSymmetricKeysCompleteCallback callback) const noexcept override;

  void symmetric_encrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> plainText, span<byte> cipherText) const override;

  void symmetric_encrypt_async(shared_ptr<const void> resource, SymmetricEncryptionAlgorithm algorithm,
    span<const byte> iv, span<const byte> key, span<const byte> plainText, span<byte> cipherText,
    SymmetricEncryptCompleteCallback callback) const noexcept override;

  void symmetric_decrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> cipherText, span<byte> plainText) const override;

  void symmetric_decrypt_async(shared_ptr<const void> resource, SymmetricEncryptionAlgorithm algorithm,
    span<const byte> iv, span<const byte> key, span<const byte> cipherText, span<byte> plainText,
    SymmetricDecryptCompleteCallback callback) const noexcept override;

  ByteString symmetric_encrypt_and_sign_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> plainText, span<const byte> additionalData,
    span<byte> cipherText) const override;

  void symmetric_encrypt_and_sign_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv, ByteString key,
    ByteString plainTextBuffer, span<const byte> plainText, span<const byte> additionalData,
    optional<ByteString> cipherTextBuffer, span<byte> cipherText,
    SymmetricEncryptAndSignCompleteCallback callback) const noexcept override;

  void symmetric_verify_and_decrypt_sync(SymmetricEncryptionAlgorithm algorithm, span<const byte> iv,
    span<const byte> key, span<const byte> cipherText, span<const byte> additionalData,
    span<const byte> signature, span<byte> plainText) const override;

  void symmetric_verify_and_decrypt_async(SymmetricEncryptionAlgorithm algorithm, ByteString iv,
    ByteString key, ByteString cipherTextBuffer, span<const byte> cipherText, span<const byte> additionalData,
    span<const byte> signature, optional<ByteString> plainTextBuffer, span<byte> plainText,
    SymmetricVerifyAndDecryptCompleteCallback callback) const noexcept override;

  ByteString symmetric_sign_sync(
    SymmetricSignatureAlgorithm algorithm, span<const byte> key, span<const byte> data) const override;

  void symmetric_sign_async(shared_ptr<const void> resource, SymmetricSignatureAlgorithm algorithm,
    span<const byte> key, span<const byte> input,
    SymmetricSignCompleteCallback callback) const noexcept override;

  void symmetric_verify_sync(SymmetricSignatureAlgorithm algorithm, span<const byte> key,
    span<const byte> data, span<const byte> signature) const override;

  void symmetric_verify_async(shared_ptr<const void> resource, SymmetricSignatureAlgorithm algorithm,
    span<const byte> key, span<const byte> input, span<const byte> signature,
    SymmetricVerifyCompleteCallback callback) const noexcept override;

  void asymmetric_encrypt_sync(AsymmetricEncryptionAlgorithm algorithm, span<const byte> publicKey,
    span<const byte> plainText, span<byte> cipherText) const override;

  void asymmetric_encrypt_async(shared_ptr<const void> resource, AsymmetricEncryptionAlgorithm algorithm,
    span<const byte> publicKey, span<const byte> plainText, span<byte> cipherText,
    AsymmetricEncryptCompleteCallback callback) const noexcept override;

  span<const byte> asymmetric_decrypt_sync(AsymmetricEncryptionAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> cipherText,
    span<byte> plainText) const override;

  void asymmetric_decrypt_async(shared_ptr<const void> resource, AsymmetricEncryptionAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> cipherText, span<byte> plainText,
    AsymmetricDecryptCompleteCallback callback) const noexcept override;

  ByteString asymmetric_sign_sync(AsymmetricSignatureAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> input) const override;

  void asymmetric_sign_async(shared_ptr<const void> resource, AsymmetricSignatureAlgorithm algorithm,
    shared_ptr<const AsymmetricKeyPair> privateKey, span<const byte> input,
    AsymmetricSignCompleteCallback callback) const noexcept override;

  void asymmetric_verify_sync(AsymmetricSignatureAlgorithm algorithm, span<const byte> publicKey,
    span<const byte> data, span<const byte> signature) const override;

  void asymmetric_verify_async(shared_ptr<const void> resource, AsymmetricSignatureAlgorithm algorithm,
    span<const byte> publicKey, span<const byte> input, span<const byte> signature,
    AsymmetricVerifyCompleteCallback callback) const noexcept override;

  shared_ptr<const AsymmetricKeyPair> create_asymmetric_key_pair_sync(
    CertificateKeyAlgorithm algorithm, optional<size_t> keyLengthInBytes) const override;

  void create_asymmetric_key_pair_async(CertificateKeyAlgorithm algorithm, optional<size_t> keyLengthInBits,
    CreateAsymmetricKeyPairCompleteCallback callback) const noexcept override;

  EphemeralKeyPair create_ephemeral_keys_sync(EphemeralKeyAlgorithm algorithm) const override;

  void create_ephemeral_keys_async(
    EphemeralKeyAlgorithm algorithm, CreateEphemeralKeysCompleteCallback callback) const noexcept override;

  ByteString calculate_shared_secret_sync(EphemeralKeyAlgorithm algorithm, span<const byte> localPrivateKey,
    span<const byte> remotePublicKey) const override;

  void calculate_shared_secret_async(EphemeralKeyAlgorithm algorithm, ByteString localPrivateKey,
    ByteString remotePublicKey, CalculateSharedSecretCompleteCallback callback) const noexcept override;

  shared_ptr<const X509Certificate> read_certificate_from_der(span<const byte> der) const override;

  std::vector<shared_ptr<const X509Certificate>> read_certificates_from_der(
    span<const byte> der) const override;

  shared_ptr<const X509Crl> read_crl_from_der(span<const byte> der) const override;

  std::vector<shared_ptr<const X509Crl>> read_crls_from_der(span<const byte> der) const override;

  shared_ptr<const AsymmetricKeyPair> get_private_key_from_pem(
    CertificateKeyAlgorithm keyAlgorithm, span<byte> pem) const override;

  void create_certificate_async(const CreateCertificateConfig& parameters,
    CreateCertificateCompleteCallback callback) const noexcept override;

  shared_ptr<const X509Certificate> create_certificate_sync(const CreateCertificateConfig& parameters) const;

  void create_certificate_signing_request_async(const CreateCsrConfig& parameters,
    CreateCertificateSigningRequestCompleteCallback callback) const noexcept override;

  shared_ptr<const AsymmetricKeyPair> get_public_key_from_der(
    CertificateKeyAlgorithm keyAlgorithm, span<const byte> der) const override;

  void sign_certificate_request_async(
    const SignCsrConfig& parameters, SignCsrCompleteCallback callback) const noexcept override;

  shared_ptr<const X509Certificate> sign_certificate_request_sync(const SignCsrConfig& parameters) const;

  void create_crl_async(shared_ptr<const X509Certificate> issuer,
    shared_ptr<const AsymmetricKeyPair> issuerKeys, std::vector<std::string> revokedSerialNumbers,
    CreateCrlCompleteCallback callback) const noexcept override;

  shared_ptr<const X509Crl> create_crl_sync(shared_ptr<const X509Certificate> issuer,
    shared_ptr<const AsymmetricKeyPair> issuerKeys,
    const std::vector<std::string>& revokedSerialNumbers) const;

  void validate_certificate_async(const CertificateValidationRequest& request,
    CertificateValidationMaterial material,
    CertificateValidationCompleteCallback callback) const noexcept override;

  void validate_crl_async(TrustListValidationOptions validationOptions, shared_ptr<const X509Crl> crl,
    std::vector<shared_ptr<const X509Certificate>> issuerCandidates,
    CrlValidationCompleteCallback callback) const noexcept override;

  static shared_ptr<const CryptoOpenSsl> create();

  static shared_ptr<const CryptoOpenSsl> create(
    const PrivateKeyCredentialCallback privateKeyCredentialCallback);

protected:
  CryptoOpenSsl();
  explicit CryptoOpenSsl(PrivateKeyCredentialCallback privateKeyCredentialCallback);

private:
  const PrivateKeyCredentialCallback mPrivateKeyCredentialCallback;

  /// Validates per Part 4 Table 106; throws the deciding fault. @return The suppressed faults as an
  /// ErrorDetail chain (null when nothing was suppressed).
  shared_ptr<const ErrorDetail> validate_certificate_impl(
    const CertificateValidationRequest& request, const CertificateValidationMaterial& material) const;

  void validate_crl_impl(const TrustListValidationOptions& validationOptions,
    const shared_ptr<const X509Crl>& crl,
    const std::vector<shared_ptr<const X509Certificate>>& issuerCandidates) const;

  ByteString calculate_hmac(HashAlgorithm algorithm, span<const byte> key, span<const byte> data) const;

  ByteString calculate_psha(
    HashAlgorithm algorithm, span<const byte> secret, span<const byte> seed, size_t noOfBytes) const;

  ByteString calculate_hkdf(HashAlgorithm algorithm, span<const byte> secret, span<const byte> salt,
    span<const byte> info, size_t noOfBytes) const;
};

}  // namespace ua

#endif  //! UA_CRYPTO_OPENSSL_H
