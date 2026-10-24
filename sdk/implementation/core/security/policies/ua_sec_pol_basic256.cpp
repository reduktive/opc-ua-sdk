// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_basic256.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_secure_channel_context.h"

namespace ua
{
SecurityPolicyId SecPolBasic256::id() const
{
  return SecurityPolicyId::Basic256;
}

String SecPolBasic256::uri() const
{
  static constexpr char uri[] = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
  return String{uri};
}

CertificateType SecPolBasic256::certificate_type() const
{
  return CertificateType::RsaMinApplication;
}

bool SecPolBasic256::is_authenticated() const
{
  return true;
}

bool SecPolBasic256::uses_legacy_sequence_no() const
{
  return true;
}

bool SecPolBasic256::is_deprecated() const
{
  return true;
}

size_t SecPolBasic256::nonce_length() const
{
  return 32;
}

size_t SecPolBasic256::symmetric_plaintext_block_size() const
{
  return 16;
}

size_t SecPolBasic256::asymmetric_plaintext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT - sOaepSha1PaddingOverhead;
}

size_t SecPolBasic256::symmetric_ciphertext_block_size() const
{
  return 16;
}

size_t SecPolBasic256::asymmetric_ciphertext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolBasic256::symmetric_signature_size() const
{
  return 20;
}

size_t SecPolBasic256::asymmetric_signature_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolBasic256::symmetric_signature_key_size() const
{
  return 24;
}

size_t SecPolBasic256::symmetric_encryption_key_size() const
{
  return 32;
}

size_t SecPolBasic256::symmetric_iv_size() const
{
  return 16;
}

size_t SecPolBasic256::min_asymmetric_key_length() const
{
  return 1024;
}

size_t SecPolBasic256::max_asymmetric_key_length() const
{
  return 2048;
}

AsymmetricEncryptionAlgorithm SecPolBasic256::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::RsaOaepSha1;
}

AsymmetricSignatureAlgorithm SecPolBasic256::asymmetric_signature_algorithm() const
{
  return AsymmetricSignatureAlgorithm::RsaPkcs15Sha1;
}

String SecPolBasic256::asymmetric_signature_algorithm_uri() const
{
  // RSA PKCS #1 v1.5 with SHA-1, as for Basic128Rsa15. RSA-OAEP is the policy's asymmetric encryption
  // algorithm, not its signature algorithm.
  static constexpr char algorithmUri[] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  return String{algorithmUri};
}

SymmetricEncryptionAlgorithm SecPolBasic256::symmetric_encryption_algorithm() const
{
  return SymmetricEncryptionAlgorithm::Aes256Cbc;
}

SymmetricSignatureAlgorithm SecPolBasic256::symmetric_signature_algorithm() const
{
  return SymmetricSignatureAlgorithm::HmacSha1;
}

void SecPolBasic256::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context,
  ByteString localNonce, ByteString remoteNonce, ChannelRole /*role*/,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  derive_symmetric_keys_psha_async(SymmetricKeyDerivationAlgorithm::PSha1,
    std::move(context),
    std::move(localNonce),
    std::move(remoteNonce),
    std::move(callback));
}

std::span<const CertificateSignatureAlgorithm> SecPolBasic256::certificate_signature_algorithms() const
{
  static constexpr CertificateSignatureAlgorithm permitted[] = {CertificateSignatureAlgorithm::RsaPkcs15Sha1,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2224,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2384,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2512};
  return permitted;
}

}  // namespace ua
