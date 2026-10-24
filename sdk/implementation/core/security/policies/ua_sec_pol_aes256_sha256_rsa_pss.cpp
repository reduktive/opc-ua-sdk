// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_aes256_sha256_rsa_pss.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_secure_channel_context.h"
#include "ua_x509_certificate.h"

namespace ua
{
SecurityPolicyId SecPolAes256Sha256RsaPss::id() const
{
  return SecurityPolicyId::Aes256Sha256RsaPss;
}

String SecPolAes256Sha256RsaPss::uri() const
{
  static constexpr char uri[] = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
  return String{uri};
}

CertificateType SecPolAes256Sha256RsaPss::certificate_type() const
{
  return CertificateType::RsaSha256Application;
}

bool SecPolAes256Sha256RsaPss::is_authenticated() const
{
  return true;
}

bool SecPolAes256Sha256RsaPss::is_rsa() const
{
  return true;
}

bool SecPolAes256Sha256RsaPss::is_ecc() const
{
  return false;
}

bool SecPolAes256Sha256RsaPss::uses_legacy_sequence_no() const
{
  return false;
}

size_t SecPolAes256Sha256RsaPss::nonce_length() const
{
  return 32;
}

size_t SecPolAes256Sha256RsaPss::symmetric_plaintext_block_size() const
{
  return 16;
}

size_t SecPolAes256Sha256RsaPss::asymmetric_plaintext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT - sOaepSha256PaddingOverhead;
}

size_t SecPolAes256Sha256RsaPss::symmetric_ciphertext_block_size() const
{
  return 16;
}

size_t SecPolAes256Sha256RsaPss::asymmetric_ciphertext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolAes256Sha256RsaPss::symmetric_signature_size() const
{
  return 32;
}

size_t SecPolAes256Sha256RsaPss::asymmetric_signature_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolAes256Sha256RsaPss::symmetric_signature_key_size() const
{
  return 32;
}

size_t SecPolAes256Sha256RsaPss::symmetric_encryption_key_size() const
{
  return 32;
}

size_t SecPolAes256Sha256RsaPss::symmetric_iv_size() const
{
  return 16;
}

size_t SecPolAes256Sha256RsaPss::min_asymmetric_key_length() const
{
  return 2048;
}

size_t SecPolAes256Sha256RsaPss::max_asymmetric_key_length() const
{
  return 4096;
}

AsymmetricEncryptionAlgorithm SecPolAes256Sha256RsaPss::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::RsaOaepSha2256;
}

AsymmetricSignatureAlgorithm SecPolAes256Sha256RsaPss::asymmetric_signature_algorithm() const
{
  return AsymmetricSignatureAlgorithm::RsaPssSha2256;
}

String SecPolAes256Sha256RsaPss::asymmetric_signature_algorithm_uri() const
{
  static constexpr char signatureAlgorithmUri[] = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256";
  return String{signatureAlgorithmUri};
}

SymmetricEncryptionAlgorithm SecPolAes256Sha256RsaPss::symmetric_encryption_algorithm() const
{
  return SymmetricEncryptionAlgorithm::Aes256Cbc;
}

SymmetricSignatureAlgorithm SecPolAes256Sha256RsaPss::symmetric_signature_algorithm() const
{
  return SymmetricSignatureAlgorithm::HmacSha2256;
}

void SecPolAes256Sha256RsaPss::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context,
  ByteString localNonce, ByteString remoteNonce, ChannelRole /*role*/,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  derive_symmetric_keys_psha_async(SymmetricKeyDerivationAlgorithm::PSha2256,
    std::move(context),
    std::move(localNonce),
    std::move(remoteNonce),
    std::move(callback));
}

std::span<const CertificateSignatureAlgorithm>
  SecPolAes256Sha256RsaPss::certificate_signature_algorithms() const
{
  static constexpr CertificateSignatureAlgorithm permitted[] = {
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2384,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2512};
  return permitted;
}

}  // namespace ua
