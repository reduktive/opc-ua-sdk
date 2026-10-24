// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The Table 49 rows of the fourteen ephemeral-key policies of OPC UA 1.05.07, from the OPC Foundation
// profile database (profile group UACore 1.05; profile ids in the comments).

#include "ua_sec_pol_ephemeral_key.h"

#include <array>

namespace ua
{

namespace
{

using A = AsymmetricSignatureAlgorithm;
using C = CertificateKeyAlgorithm;
using E = EphemeralKeyAlgorithm;
using H = HashAlgorithm;
using K = SymmetricKeyDerivationAlgorithm;
using S = SymmetricEncryptionAlgorithm;
using T = CertificateType;

// RSA-PKCS15-SHA2-256, "SHA2 with 384 or 512 bits may be used instead" (conformance unit 2681).
constexpr CertificateSignatureAlgorithm rsaDhCertificateSignatures[] = {
  CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
  CertificateSignatureAlgorithm::RsaPkcs15Sha2384,
  CertificateSignatureAlgorithm::RsaPkcs15Sha2512};

constexpr RsaCertificateRules rsaDhRules{2048, 4096, rsaDhCertificateSignatures};

constexpr EccCertificateRules nistP256Rules{C::EccNistP256, C::EccNistP384};
// Profile 2285 names brainpoolP384r1 for ECC_nistP384_AesGcm; read as nistP384 (SD-P7-001).
constexpr EccCertificateRules nistP384Rules{C::EccNistP384, C::EccNistP521};
constexpr EccCertificateRules brainpoolP256r1Rules{C::EccBrainpoolP256r1, C::EccBrainpoolP384r1};
constexpr EccCertificateRules brainpoolP384r1Rules{C::EccBrainpoolP384r1, C::EccBrainpoolP512r1};
constexpr EccCertificateRules curve25519Rules{C::EccCurve25519, C::EccCurve25519};
constexpr EccCertificateRules curve448Rules{C::EccCurve448, C::EccCurve448};

const std::array<EphemeralKeyPolicyParameters, 14> rows{{
  // 2324
  {SecurityPolicyId::EccNistP256AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm",
    T::EccNistP256Application,
    nistP256Rules,
    E::EccNistP256,
    A::EcDsaSha2256,
    K::HkdfSha2256,
    S::Aes128Gcm,
    H::Sha2256},
  // 2325
  {SecurityPolicyId::EccNistP256ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_ChaChaPoly",
    T::EccNistP256Application,
    nistP256Rules,
    E::EccNistP256,
    A::EcDsaSha2256,
    K::HkdfSha2256,
    S::ChaCha20Poly1305,
    H::Sha2256},
  // 2285
  {SecurityPolicyId::EccNistP384AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_AesGcm",
    T::EccNistP384Application,
    nistP384Rules,
    E::EccNistP384,
    A::EcDsaSha2384,
    K::HkdfSha2384,
    S::Aes256Gcm,
    H::Sha2384},
  // 2284
  {SecurityPolicyId::EccNistP384ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_ChaChaPoly",
    T::EccNistP384Application,
    nistP384Rules,
    E::EccNistP384,
    A::EcDsaSha2384,
    K::HkdfSha2384,
    S::ChaCha20Poly1305,
    H::Sha2384},
  // 2342
  {SecurityPolicyId::EccBrainpoolP256r1AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1_AesGcm",
    T::EccBrainpoolP256r1Application,
    brainpoolP256r1Rules,
    E::EccBrainpoolP256r1,
    A::EcDsaSha2256,
    K::HkdfSha2256,
    S::Aes128Gcm,
    H::Sha2256},
  // 2280
  {SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1_ChaChaPoly",
    T::EccBrainpoolP256r1Application,
    brainpoolP256r1Rules,
    E::EccBrainpoolP256r1,
    A::EcDsaSha2256,
    K::HkdfSha2256,
    S::ChaCha20Poly1305,
    H::Sha2256},
  // 2279
  {SecurityPolicyId::EccBrainpoolP384r1AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1_AesGcm",
    T::EccBrainpoolP384r1Application,
    brainpoolP384r1Rules,
    E::EccBrainpoolP384r1,
    A::EcDsaSha2384,
    K::HkdfSha2384,
    S::Aes256Gcm,
    H::Sha2384},
  // 2281
  {SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1_ChaChaPoly",
    T::EccBrainpoolP384r1Application,
    brainpoolP384r1Rules,
    E::EccBrainpoolP384r1,
    A::EcDsaSha2384,
    K::HkdfSha2384,
    S::ChaCha20Poly1305,
    H::Sha2384},
  // 2287
  {SecurityPolicyId::EccCurve25519AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_AesGcm",
    T::EccCurve25519Application,
    curve25519Rules,
    E::EccCurve25519,
    A::PureEdDsa25519,
    K::HkdfSha2256,
    S::Aes128Gcm,
    H::Sha2256},
  // 2286
  {SecurityPolicyId::EccCurve25519ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaChaPoly",
    T::EccCurve25519Application,
    curve25519Rules,
    E::EccCurve25519,
    A::PureEdDsa25519,
    K::HkdfSha2256,
    S::ChaCha20Poly1305,
    H::Sha2256},
  // 2289
  {SecurityPolicyId::EccCurve448AesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_AesGcm",
    T::EccCurve448Application,
    curve448Rules,
    E::EccCurve448,
    A::PureEdDsa448,
    K::HkdfSha2384,
    S::Aes256Gcm,
    H::Sha2384},
  // 2288
  {SecurityPolicyId::EccCurve448ChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_ChaChaPoly",
    T::EccCurve448Application,
    curve448Rules,
    E::EccCurve448,
    A::PureEdDsa448,
    K::HkdfSha2384,
    S::ChaCha20Poly1305,
    H::Sha2384},
  // 2290
  {SecurityPolicyId::RsaDhAesGcm,
    "http://opcfoundation.org/UA/SecurityPolicy#RSA_DH_AesGcm",
    T::RsaSha256Application,
    rsaDhRules,
    E::RsaDhFfdhe3072,
    A::RsaPkcs15Sha2256,
    K::HkdfSha2256,
    S::Aes128Gcm,
    H::Sha2256},
  // 2291
  {SecurityPolicyId::RsaDhChaChaPoly,
    "http://opcfoundation.org/UA/SecurityPolicy#RSA_DH_ChaChaPoly",
    T::RsaSha256Application,
    rsaDhRules,
    E::RsaDhFfdhe3072,
    A::RsaPkcs15Sha2256,
    K::HkdfSha2256,
    S::ChaCha20Poly1305,
    H::Sha2256},
}};

}  // namespace

std::span<const EphemeralKeyPolicyParameters> ephemeral_key_policy_rows() noexcept
{
  return rows;
}

const EphemeralKeyPolicyParameters* find_ephemeral_key_policy(SecurityPolicyId id) noexcept
{
  for (const auto& row : rows)
  {
    if (row.id == id)
    {
      return &row;
    }
  }
  return nullptr;
}

const EphemeralKeyPolicyParameters* find_ephemeral_key_policy(std::string_view uri) noexcept
{
  for (const auto& row : rows)
  {
    if (row.uri == uri)
    {
      return &row;
    }
  }
  return nullptr;
}

}  // namespace ua
