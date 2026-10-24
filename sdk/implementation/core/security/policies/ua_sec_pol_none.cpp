// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sec_pol_none.h"

#include "ua_certificate_store.h"
#include "ua_secure_channel_context.h"

namespace ua
{
SecurityPolicyId SecPolNone::id() const
{
  return SecurityPolicyId::None;
}

String SecPolNone::uri() const
{
  static constexpr char uri[] = "http://opcfoundation.org/UA/SecurityPolicy#None";
  return String{uri};
}

CertificateType SecPolNone::certificate_type() const
{
  return CertificateType::Invalid;
}

bool SecPolNone::is_authenticated() const
{
  return false;
}

bool SecPolNone::is_rsa() const
{
  return false;
}

bool SecPolNone::is_ecc() const
{
  return false;
}

bool SecPolNone::uses_legacy_sequence_no() const
{
  return true;
}

size_t SecPolNone::nonce_length() const
{
  return 0;
}

size_t SecPolNone::symmetric_plaintext_block_size() const
{
  return 1;
}

size_t SecPolNone::asymmetric_plaintext_block_size(const X509Certificate* certificate) const
{
  UA_UNUSED(certificate);
  return 1;
}

size_t SecPolNone::symmetric_ciphertext_block_size() const
{
  return 1;
}

size_t SecPolNone::asymmetric_ciphertext_block_size(const X509Certificate* certificate) const
{
  UA_UNUSED(certificate);
  return 1;
}

size_t SecPolNone::symmetric_signature_size() const
{
  return 0;
}

size_t SecPolNone::asymmetric_signature_size(const X509Certificate* certificate) const
{
  UA_UNUSED(certificate);
  return 0;
}

size_t SecPolNone::symmetric_signature_key_size() const
{
  return 0;
}

size_t SecPolNone::symmetric_encryption_key_size() const
{
  return 0;
}

size_t SecPolNone::symmetric_iv_size() const
{
  return 0;
}

size_t SecPolNone::min_asymmetric_key_length() const
{
  return 0;
}

size_t SecPolNone::max_asymmetric_key_length() const
{
  return 0;
}

AsymmetricEncryptionAlgorithm SecPolNone::asymmetric_encryption_algorithm() const
{
  return AsymmetricEncryptionAlgorithm::Invalid;
}

AsymmetricSignatureAlgorithm SecPolNone::asymmetric_signature_algorithm() const
{
  return AsymmetricSignatureAlgorithm::Invalid;
}

String SecPolNone::asymmetric_signature_algorithm_uri() const
{
  return {};
}

SymmetricEncryptionAlgorithm SecPolNone::symmetric_encryption_algorithm() const
{
  return SymmetricEncryptionAlgorithm::Invalid;
}

SymmetricSignatureAlgorithm SecPolNone::symmetric_signature_algorithm() const
{
  return SymmetricSignatureAlgorithm::Invalid;
}

void SecPolNone::derive_symmetric_keys_async(shared_ptr<SecureChannelContext> /*context*/,
  ByteString /*localNonce*/, ByteString /*remoteNonce*/, ChannelRole /*role*/,
  std::function<void(DeriveSymmetricKeysResult)> callback) const
{
  callback(DeriveSymmetricKeysResult{std::make_pair(SecurityToken::Keys{}, SecurityToken::Keys{})});
}

VoidResult SecPolNone::check_certificate_compliance([[maybe_unused]] const X509Certificate& certificate,
  [[maybe_unused]] const X509Certificate& signer, [[maybe_unused]] CertificateChainPosition position) const
{
  return {};
}

}  // namespace ua
