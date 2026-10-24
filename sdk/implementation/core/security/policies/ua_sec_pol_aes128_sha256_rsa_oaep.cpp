// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_aes128_sha256_rsa_oaep.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_secure_channel_context.h"
#include "ua_x509_certificate.h"

namespace ua
{
SecurityPolicyId SecPolAes128Sha256RsaOaep::id() const
{
  return SecurityPolicyId::Aes128Sha256RsaOaep;
}

String SecPolAes128Sha256RsaOaep::uri() const
{
  static constexpr char uri[] = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";
  return String{uri};
}

CertificateType SecPolAes128Sha256RsaOaep::certificate_type() const
{
  return CertificateType::RsaSha256Application;
}

bool SecPolAes128Sha256RsaOaep::is_authenticated() const
{
  return true;
}

bool SecPolAes128Sha256RsaOaep::is_rsa() const
{
  return true;
}

bool SecPolAes128Sha256RsaOaep::is_ecc() const
{
  return false;
}

bool SecPolAes128Sha256RsaOaep::uses_legacy_sequence_no() const
{
  return false;
}

size_t SecPolAes128Sha256RsaOaep::nonce_length() const
{
  return 32;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_plaintext_block_size() const
{
  return 16;
}

size_t SecPolAes128Sha256RsaOaep::asymmetric_plaintext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT - sOaepSha1PaddingOverhead;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_ciphertext_block_size() const
{
  return 16;
}

size_t SecPolAes128Sha256RsaOaep::asymmetric_ciphertext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_signature_size() const
{
  return 32;
}

size_t SecPolAes128Sha256RsaOaep::asymmetric_signature_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_signature_key_size() const
{
  return 32;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_encryption_key_size() const
{
  return 16;
}

size_t SecPolAes128Sha256RsaOaep::symmetric_iv_size() const
{
  return 16;
}

size_t SecPolAes128Sha256RsaOaep::min_asymmetric_key_length() const
{
  return 2048;
}

size_t SecPolAes128Sha256RsaOaep::max_asymmetric_key_length() const
{
  return 4096;
}

AsymmetricEncryptionAlgorithm SecPolAes128Sha256RsaOaep::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::RsaOaepSha1;
}

AsymmetricSignatureAlgorithm SecPolAes128Sha256RsaOaep::asymmetric_signature_algorithm() const
{
  return AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256;
}

String SecPolAes128Sha256RsaOaep::asymmetric_signature_algorithm_uri() const
{
  static constexpr char signatureAlgorithmUri[] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  return String{signatureAlgorithmUri};
}

SymmetricEncryptionAlgorithm SecPolAes128Sha256RsaOaep::symmetric_encryption_algorithm() const
{
  return SymmetricEncryptionAlgorithm::Aes128Cbc;
}

SymmetricSignatureAlgorithm SecPolAes128Sha256RsaOaep::symmetric_signature_algorithm() const
{
  return SymmetricSignatureAlgorithm::HmacSha2256;
}

void SecPolAes128Sha256RsaOaep::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context,
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
  SecPolAes128Sha256RsaOaep::certificate_signature_algorithms() const
{
  static constexpr CertificateSignatureAlgorithm permitted[] = {
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2384,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2512};
  return permitted;
}

}  // namespace ua
