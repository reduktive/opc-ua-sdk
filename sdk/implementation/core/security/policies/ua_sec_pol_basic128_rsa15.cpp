// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_basic128_rsa15.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_secure_channel_context.h"

namespace ua
{
SecurityPolicyId SecPolBasic128Rsa15::id() const
{
  return SecurityPolicyId::Basic128Rsa15;
}

String SecPolBasic128Rsa15::uri() const
{
  static constexpr char uri[] = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
  return String{uri};
}

CertificateType SecPolBasic128Rsa15::certificate_type() const
{
  return CertificateType::RsaMinApplication;
}

bool SecPolBasic128Rsa15::is_authenticated() const
{
  return true;
}

bool SecPolBasic128Rsa15::uses_legacy_sequence_no() const
{
  return true;
}

bool SecPolBasic128Rsa15::is_deprecated() const
{
  return true;
}

size_t SecPolBasic128Rsa15::nonce_length() const
{
  // SecureChannelNonceLength 16 (OPC 10000-7 Basic128Rsa15_Limits). Part 4 5.5.2.2 requires the
  // nonce to have exactly this length; Part 4 Table 12's general 32-byte minimum contradicts that
  // for this one policy, and the policy-specific length wins, as the OPC Foundation .NET stack reads
  // it ("Basic128Rsa15 is the only RSA based security policy that allows nonces with a length less
  // than 32 bytes"). With 32 the SDK could not open a Basic128Rsa15 channel to that stack in either
  // direction (owner decision 11, security review H-D4 residual).
  return 16;
}

size_t SecPolBasic128Rsa15::symmetric_plaintext_block_size() const
{
  return 16;
}

size_t SecPolBasic128Rsa15::asymmetric_plaintext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT - sPkcs1PaddingOverhead;
}

size_t SecPolBasic128Rsa15::symmetric_ciphertext_block_size() const
{
  return 16;
}

size_t SecPolBasic128Rsa15::asymmetric_ciphertext_block_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolBasic128Rsa15::symmetric_signature_size() const
{
  return 20;
}

size_t SecPolBasic128Rsa15::asymmetric_signature_size(const X509Certificate* certificate) const
{
  check(certificate);
  return certificate->public_key_bit_length() / CHAR_BIT;
}

size_t SecPolBasic128Rsa15::symmetric_signature_key_size() const
{
  return 16;
}

size_t SecPolBasic128Rsa15::symmetric_encryption_key_size() const
{
  return 16;
}

size_t SecPolBasic128Rsa15::symmetric_iv_size() const
{
  return 16;
}

size_t SecPolBasic128Rsa15::min_asymmetric_key_length() const
{
  return 1024;
}

size_t SecPolBasic128Rsa15::max_asymmetric_key_length() const
{
  return 2048;
}

AsymmetricEncryptionAlgorithm SecPolBasic128Rsa15::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::RsaPkcs15;
}

AsymmetricSignatureAlgorithm SecPolBasic128Rsa15::asymmetric_signature_algorithm() const
{
  return AsymmetricSignatureAlgorithm::RsaPkcs15Sha1;
}

String SecPolBasic128Rsa15::asymmetric_signature_algorithm_uri() const
{
  static constexpr char signatureAlgorithmUri[] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  return String{signatureAlgorithmUri};
}

SymmetricEncryptionAlgorithm SecPolBasic128Rsa15::symmetric_encryption_algorithm() const
{
  return SymmetricEncryptionAlgorithm::Aes128Cbc;
}

SymmetricSignatureAlgorithm SecPolBasic128Rsa15::symmetric_signature_algorithm() const
{
  return SymmetricSignatureAlgorithm::HmacSha1;
}

void SecPolBasic128Rsa15::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> context,
  ByteString localNonce, ByteString remoteNonce, ChannelRole /*role*/,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  derive_symmetric_keys_psha_async(SymmetricKeyDerivationAlgorithm::PSha1,
    std::move(context),
    std::move(localNonce),
    std::move(remoteNonce),
    std::move(callback));
}

std::span<const CertificateSignatureAlgorithm> SecPolBasic128Rsa15::certificate_signature_algorithms() const
{
  static constexpr CertificateSignatureAlgorithm permitted[] = {CertificateSignatureAlgorithm::RsaPkcs15Sha1,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2224,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2384,
    CertificateSignatureAlgorithm::RsaPkcs15Sha2512};
  return permitted;
}

}  // namespace ua
