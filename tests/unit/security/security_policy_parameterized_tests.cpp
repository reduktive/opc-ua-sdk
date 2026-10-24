// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Parameterized property and key derivation tests for all 20 security policies.
///
/// Consolidates per-policy constant accessor tests, factory tests, classification flag tests,
/// and key derivation cross-key symmetry tests into a single parameterized suite.

#include <gtest/gtest.h>
#include <algorithm>
#include <array>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "run_async_sync.h"
#include "stub_x509_certificate.h"
#include "test_pki_helpers.h"

#include "ua_security_policy.h"
#include "ua_secure_channel_context.h"
#include "ua_crypto.h"
#include "ua_sec_pol_ephemeral_key.h"

using namespace ua;

namespace
{

class CertificateWithKeyAlgorithm final : public ua::testing::StubX509Certificate
{
public:
  explicit CertificateWithKeyAlgorithm(CertificateKeyAlgorithm algorithm) : mAlgorithm(algorithm)
  {}

  CertificateKeyAlgorithm key_algorithm() const override
  {
    return mAlgorithm;
  }

private:
  CertificateKeyAlgorithm mAlgorithm;
};

// Every context these tests build carries the strand a bound channel always has: the SecureChannel
// constructor engages `mStrand` immediately, so a context without one is a shape production never
// produces. The crypto bodies marshal their continuations onto it, which means this pool has to be
// running for the blocking *_sync helpers to return - they wait on the answer it delivers.
boost::asio::thread_pool& crypto_pool()
{
  static boost::asio::thread_pool pool{2};
  return pool;
}

boost::asio::strand<boost::asio::any_io_executor> crypto_strand()
{
  return boost::asio::make_strand(boost::asio::any_io_executor{crypto_pool().get_executor()});
}

std::shared_ptr<SecureChannelContext> make_channel_context()
{
  auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = crypto_strand();
  return context;
}

// Local convenience: drive derive_symmetric_keys_async to completion synchronously
// and return the unwrapped pair. Mirrors the pre-flip Task<>::value() shape used
// by these tests; tests run on the gtest main thread so the promise/future bridge
// is safe (the "no blocking on pool" constraint is for pool threads).
template<typename Policy, typename... Args>
auto derive_keys_sync(const Policy& policy, Args&&... args)
{
  return ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [&](auto cb) { policy->derive_symmetric_keys_async(std::forward<Args>(args)..., std::move(cb)); });
}

// --- Parameter struct --------------------------------------------------------

struct SecurityPolicyParams
{
  SecurityPolicyId id;
  std::string uri;
  CertificateType certificateType;
  bool authenticated;
  bool rsa;
  bool ecc;
  bool legacySequenceNo;
  bool deprecated;
  size_t nonceLength;
  size_t symmetricPlaintextBlockSize;
  size_t symmetricCiphertextBlockSize;
  size_t symmetricSignatureSize;
  size_t symmetricSignatureKeySize;
  size_t symmetricEncryptionKeySize;
  size_t symmetricIvSize;
  AsymmetricEncryptionAlgorithm asymmetricEncryptionAlgorithm;
  AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm;
  std::string asymmetricSignatureAlgorithmUri;
  SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm;
  SymmetricSignatureAlgorithm symmetricSignatureAlgorithm;
  std::optional<EphemeralKeyAlgorithm> ephemeralKeyAlgorithm;  // nullopt: EphemeralKeyAlgorithm::Invalid
  bool secureChannelEnhancements;
  HashAlgorithm certificateThumbprintAlgorithm;  // Invalid where the policy defines none
  size_t asymmetricSignatureSize;  // 0 for None; curve-dependent for ECC; key_bits/8 for RSA
  size_t rsaKeyBitLength;  // RSA key size used to compute asymmetricSignatureSize (0 for non-RSA)
  std::string name;
};

std::ostream& operator<<(std::ostream& os, const SecurityPolicyParams& p)
{
  return os << p.name;
}

// --- Fixture -----------------------------------------------------------------

class SecurityPolicyParameterizedTests : public ::testing::TestWithParam<SecurityPolicyParams>
{
protected:
  void SetUp() override
  {
    mPolicy = SecurityPolicy::create(GetParam().id);
    ASSERT_NE(mPolicy, nullptr);
  }

  static std::shared_ptr<const Crypto> create_crypto()
  {
    return create_default_crypto([]() { return ua::SecureString{"password"}; });
  }

  std::shared_ptr<SecurityPolicy> mPolicy;
};

// --- All 20 policy parameter sets -------------------------------------------

// clang-format off
static std::vector<SecurityPolicyParams> all_policy_params()
{
  return {
    // -- None --
    SecurityPolicyParams{
      .id = SecurityPolicyId::None,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#None",
      .certificateType = CertificateType::Invalid,
      .authenticated = false, .rsa = false, .ecc = false,
      .legacySequenceNo = true, .deprecated = false,
      .nonceLength = 0,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 0, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 0, .symmetricIvSize = 0,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::Invalid,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Invalid,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Invalid,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 0,
      .rsaKeyBitLength = 0,
      .name = "None"
    },
    // -- Basic128Rsa15 (deprecated) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::Basic128Rsa15,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
      .certificateType = CertificateType::RsaMinApplication,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = true, .deprecated = true,
      // SecureChannelNonceLength 16 (OPC 10000-7; ratified expectation change, owner decision 11:
      // the SDK used 32 and could not open this policy's channels to the OPC Foundation .NET stack).
      .nonceLength = 16,
      .symmetricPlaintextBlockSize = 16, .symmetricCiphertextBlockSize = 16,
      .symmetricSignatureSize = 20, .symmetricSignatureKeySize = 16,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 16,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::RsaPkcs15,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha1,
      .asymmetricSignatureAlgorithmUri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Cbc,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::HmacSha1,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "Basic128Rsa15"
    },
    // -- Basic256 (deprecated) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::Basic256,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
      .certificateType = CertificateType::RsaMinApplication,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = true, .deprecated = true,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 16, .symmetricCiphertextBlockSize = 16,
      .symmetricSignatureSize = 20, .symmetricSignatureKeySize = 24,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 16,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::RsaOaepSha1,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha1,
      .asymmetricSignatureAlgorithmUri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Cbc,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::HmacSha1,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "Basic256"
    },
    // -- Basic256Sha256 --
    SecurityPolicyParams{
      .id = SecurityPolicyId::Basic256Sha256,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
      .certificateType = CertificateType::RsaSha256Application,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = true, .deprecated = false,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 16, .symmetricCiphertextBlockSize = 16,
      .symmetricSignatureSize = 32, .symmetricSignatureKeySize = 32,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 16,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::RsaOaepSha1,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
      .asymmetricSignatureAlgorithmUri = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Cbc,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::HmacSha2256,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "Basic256Sha256"
    },
    // -- Aes128Sha256RsaOaep --
    SecurityPolicyParams{
      .id = SecurityPolicyId::Aes128Sha256RsaOaep,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
      .certificateType = CertificateType::RsaSha256Application,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 16, .symmetricCiphertextBlockSize = 16,
      .symmetricSignatureSize = 32, .symmetricSignatureKeySize = 32,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 16,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::RsaOaepSha1,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
      .asymmetricSignatureAlgorithmUri = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Cbc,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::HmacSha2256,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "Aes128Sha256RsaOaep"
    },
    // -- Aes256Sha256RsaPss --
    SecurityPolicyParams{
      .id = SecurityPolicyId::Aes256Sha256RsaPss,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
      .certificateType = CertificateType::RsaSha256Application,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 16, .symmetricCiphertextBlockSize = 16,
      .symmetricSignatureSize = 32, .symmetricSignatureKeySize = 32,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 16,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::RsaOaepSha2256,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPssSha2256,
      .asymmetricSignatureAlgorithmUri = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Cbc,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::HmacSha2256,
      .ephemeralKeyAlgorithm = std::nullopt,
      .secureChannelEnhancements = false,
      .certificateThumbprintAlgorithm = HashAlgorithm::Invalid,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "Aes256Sha256RsaPss"
    },
    // The fourteen 1.05.07 policies (OPC 10000-7 profiles 2279-2291, 2324, 2325, 2342), written from the
    // profile database and the specification, not from the rows under test. All fourteen share
    // SecureChannelEnhancements TRUE, LegacySequenceNumbers FALSE, DerivedSignatureKeyLength 0, a 96-bit
    // IV and a 128-bit AEAD tag with no padding (Part 6 section 6.7.2.1 Figure 12, section 6.8.1). The
    // nonce is the ephemeral public key: x and y for NIST and Brainpool curves, the RFC 7748 encoding
    // for the Edwards curves (Part 6 section 6.8.1), the ffdhe3072 public key for RSA_DH (Table 72).
    // -- ECC_nistP256_AesGcm (profile 2324) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccNistP256AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm",
      .certificateType = CertificateType::EccNistP256Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 64,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes128Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccNistP256,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccNistP256AesGcm"
    },
    // -- ECC_nistP256_ChaChaPoly (profile 2325) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccNistP256ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_ChaChaPoly",
      .certificateType = CertificateType::EccNistP256Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 64,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccNistP256,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccNistP256ChaChaPoly"
    },
    // -- ECC_nistP384_AesGcm (profile 2285) --
    // SD-P7-001: the profile lists a brainpoolP384r1 certificate key; the SDK ruling is nistP384, the
    // curve of the ephemeral key and of every sibling policy (Part 6 section 6.8.1).
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccNistP384AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_AesGcm",
      .certificateType = CertificateType::EccNistP384Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 96,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2384,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes256Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccNistP384,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 96,
      .rsaKeyBitLength = 0,
      .name = "EccNistP384AesGcm"
    },
    // -- ECC_nistP384_ChaChaPoly (profile 2284) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccNistP384ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_ChaChaPoly",
      .certificateType = CertificateType::EccNistP384Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 96,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2384,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccNistP384,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 96,
      .rsaKeyBitLength = 0,
      .name = "EccNistP384ChaChaPoly"
    },
    // -- ECC_brainpoolP256r1_AesGcm (profile 2342) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1_AesGcm",
      .certificateType = CertificateType::EccBrainpoolP256r1Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 64,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes128Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccBrainpoolP256r1AesGcm"
    },
    // -- ECC_brainpoolP256r1_ChaChaPoly (profile 2280) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1_ChaChaPoly",
      .certificateType = CertificateType::EccBrainpoolP256r1Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 64,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccBrainpoolP256r1ChaChaPoly"
    },
    // -- ECC_brainpoolP384r1_AesGcm (profile 2279) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1_AesGcm",
      .certificateType = CertificateType::EccBrainpoolP384r1Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 96,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2384,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes256Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 96,
      .rsaKeyBitLength = 0,
      .name = "EccBrainpoolP384r1AesGcm"
    },
    // -- ECC_brainpoolP384r1_ChaChaPoly (profile 2281) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1_ChaChaPoly",
      .certificateType = CertificateType::EccBrainpoolP384r1Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 96,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::EcDsaSha2384,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 96,
      .rsaKeyBitLength = 0,
      .name = "EccBrainpoolP384r1ChaChaPoly"
    },
    // -- ECC_curve25519_AesGcm (profile 2287) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccCurve25519AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_AesGcm",
      .certificateType = CertificateType::EccCurve25519Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::PureEdDsa25519,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes128Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccCurve25519,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccCurve25519AesGcm"
    },
    // -- ECC_curve25519_ChaChaPoly (profile 2286) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccCurve25519ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaChaPoly",
      .certificateType = CertificateType::EccCurve25519Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 32,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::PureEdDsa25519,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccCurve25519,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 64,
      .rsaKeyBitLength = 0,
      .name = "EccCurve25519ChaChaPoly"
    },
    // -- ECC_curve448_AesGcm (profile 2289) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccCurve448AesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_AesGcm",
      .certificateType = CertificateType::EccCurve448Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 56,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::PureEdDsa448,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes256Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes256Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccCurve448,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 114,
      .rsaKeyBitLength = 0,
      .name = "EccCurve448AesGcm"
    },
    // -- ECC_curve448_ChaChaPoly (profile 2288) --
    SecurityPolicyParams{
      .id = SecurityPolicyId::EccCurve448ChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_ChaChaPoly",
      .certificateType = CertificateType::EccCurve448Application,
      .authenticated = true, .rsa = false, .ecc = true,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 56,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::PureEdDsa448,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::EccCurve448,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2384,
      .asymmetricSignatureSize = 114,
      .rsaKeyBitLength = 0,
      .name = "EccCurve448ChaChaPoly"
    },
    // -- RSA_DH_AesGcm (profile 2290) --
    // SD-P7-003: the profile declares RSA-OAEP-SHA2-256, but the OpenSecureChannel is signed and not
    // encrypted (Part 6 section 6.9), so no asymmetric encryption algorithm is reported. The nonce is the
    // ffdhe3072 public key (Part 6 Table 72).
    SecurityPolicyParams{
      .id = SecurityPolicyId::RsaDhAesGcm,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#RSA_DH_AesGcm",
      .certificateType = CertificateType::RsaSha256Application,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 384,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 16, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::Aes128Gcm,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::Aes128Gcm,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "RsaDhAesGcm"
    },
    // -- RSA_DH_ChaChaPoly (profile 2291) --
    // SD-P7-003, as for RSA_DH_AesGcm.
    SecurityPolicyParams{
      .id = SecurityPolicyId::RsaDhChaChaPoly,
      .uri = "http://opcfoundation.org/UA/SecurityPolicy#RSA_DH_ChaChaPoly",
      .certificateType = CertificateType::RsaSha256Application,
      .authenticated = true, .rsa = true, .ecc = false,
      .legacySequenceNo = false, .deprecated = false,
      .nonceLength = 384,
      .symmetricPlaintextBlockSize = 1, .symmetricCiphertextBlockSize = 1,
      .symmetricSignatureSize = 16, .symmetricSignatureKeySize = 0,
      .symmetricEncryptionKeySize = 32, .symmetricIvSize = 12,
      .asymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm::Invalid,
      .asymmetricSignatureAlgorithm = AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
      .asymmetricSignatureAlgorithmUri = "",
      .symmetricEncryptionAlgorithm = SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
      .symmetricSignatureAlgorithm = SymmetricSignatureAlgorithm::ChaCha20Poly1305,
      .ephemeralKeyAlgorithm = EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      .secureChannelEnhancements = true,
      .certificateThumbprintAlgorithm = HashAlgorithm::Sha2256,
      .asymmetricSignatureSize = 256,
      .rsaKeyBitLength = 2048,
      .name = "RsaDhChaChaPoly"
    }
  };
}

INSTANTIATE_TEST_SUITE_P(AllPolicies, SecurityPolicyParameterizedTests,
  ::testing::ValuesIn(all_policy_params()),
  [](const ::testing::TestParamInfo<SecurityPolicyParams>& info) { return info.param.name; }
);
// clang-format on

// --- Test cases --------------------------------------------------------------

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, FactoryByIdProducesCorrectUri)
{
  const auto& params = GetParam();
  EXPECT_EQ(mPolicy->id(), params.id);
  EXPECT_EQ(std::string{mPolicy->uri()}, params.uri);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, FactoryByUriProducesCorrectId)
{
  const auto& params = GetParam();
  auto policy = SecurityPolicy::create(params.uri);
  ASSERT_NE(policy, nullptr) << "Factory returned null for URI: " << params.uri;
  EXPECT_EQ(policy->id(), params.id);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, ClassificationFlags)
{
  const auto& params = GetParam();
  EXPECT_EQ(mPolicy->is_authenticated(), params.authenticated);
  EXPECT_EQ(mPolicy->is_rsa(), params.rsa);
  EXPECT_EQ(mPolicy->is_ecc(), params.ecc);
  EXPECT_EQ(mPolicy->uses_legacy_sequence_no(), params.legacySequenceNo);
  EXPECT_EQ(mPolicy->is_deprecated(), params.deprecated);
  EXPECT_EQ(mPolicy->certificate_type(), params.certificateType);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, NonceLength)
{
  EXPECT_EQ(mPolicy->nonce_length(), GetParam().nonceLength);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, SymmetricSizes)
{
  const auto& params = GetParam();
  EXPECT_EQ(mPolicy->symmetric_plaintext_block_size(), params.symmetricPlaintextBlockSize);
  EXPECT_EQ(mPolicy->symmetric_ciphertext_block_size(), params.symmetricCiphertextBlockSize);
  EXPECT_EQ(mPolicy->symmetric_signature_size(), params.symmetricSignatureSize);
  EXPECT_EQ(mPolicy->symmetric_signature_key_size(), params.symmetricSignatureKeySize);
  EXPECT_EQ(mPolicy->symmetric_encryption_key_size(), params.symmetricEncryptionKeySize);
  EXPECT_EQ(mPolicy->symmetric_iv_size(), params.symmetricIvSize);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, AlgorithmEnums)
{
  const auto& params = GetParam();
  EXPECT_EQ(mPolicy->asymmetric_encryption_algorithm(), params.asymmetricEncryptionAlgorithm);
  EXPECT_EQ(mPolicy->asymmetric_signature_algorithm(), params.asymmetricSignatureAlgorithm);
  EXPECT_EQ(
    std::string{mPolicy->asymmetric_signature_algorithm_uri()}, params.asymmetricSignatureAlgorithmUri);
  EXPECT_EQ(mPolicy->symmetric_encryption_algorithm(), params.symmetricEncryptionAlgorithm);
  EXPECT_EQ(mPolicy->symmetric_signature_algorithm(), params.symmetricSignatureAlgorithm);
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, AsymmetricSignatureSize)
{
  const auto& params = GetParam();
  if (params.rsa)
  {
    auto crypto = create_crypto();
    Crypto::Name subject;
    subject.commonName = "Test";
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test");
    auto [keys, cert] = crypto->create_self_signed_application_instance_certificate_sync(
      subject, UtcTime{2050, 1, 1, 0, 0, 0}, altName, params.certificateType, params.rsaKeyBitLength);
    EXPECT_EQ(mPolicy->asymmetric_signature_size(cert.get()), params.asymmetricSignatureSize);
  }
  else
  {
    EXPECT_EQ(mPolicy->asymmetric_signature_size(nullptr), params.asymmetricSignatureSize);
  }
}

// Part 6 Table 49: EphemeralKeyAlgorithm, SecureChannelEnhancements and CertificateThumbprintAlgorithm. The
// thumbprint algorithm is only specified for a policy with SecureChannelEnhancements = TRUE, so the policies
// without them report Invalid.
// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(SecurityPolicyParameterizedTests, EnhancementsAndThumbprint)
{
  const auto& params = GetParam();
  EXPECT_EQ(mPolicy->secure_channel_enhancements(), params.secureChannelEnhancements);
  EXPECT_EQ(mPolicy->certificate_thumbprint_algorithm(), params.certificateThumbprintAlgorithm);
  EXPECT_EQ(mPolicy->ephemeral_key_algorithm(),
    params.ephemeralKeyAlgorithm.value_or(EphemeralKeyAlgorithm::Invalid));
}

// --- Authenticated-only fixture (excludes None - key derivation is inapplicable) -

class AuthenticatedSecurityPolicyTests : public SecurityPolicyParameterizedTests
{};

INSTANTIATE_TEST_SUITE_P(AuthenticatedPolicies, AuthenticatedSecurityPolicyTests,
  ::testing::ValuesIn(
    []
    {
      std::vector<SecurityPolicyParams> out;
      for (const auto& p : all_policy_params())
      {
        if (p.authenticated)
          out.push_back(p);
      }
      return out;
    }()),
  [](const ::testing::TestParamInfo<SecurityPolicyParams>& info) { return info.param.name; });

// The two directions of a channel never share key material: the server and client keys are expanded from
// different salts (Part 6 section 6.8.1 Step 1) or, for the RSA policies, from swapped secret and seed
// (Part 6 section 6.7.6 Table 66). A policy with DerivedSignatureKeyLength 0 (the AEAD policies) derives no
// signing key, so its directions are compared on the encrypting key and the IV.
void expect_directions_differ(const SecurityPolicyParams& params, const SecurityToken::Keys& localKeys,
  const SecurityToken::Keys& remoteKeys)
{
  if (params.symmetricSignatureKeySize == 0)
  {
    EXPECT_NE(localKeys.encryptingKey, remoteKeys.encryptingKey);
    EXPECT_NE(localKeys.initializationVector, remoteKeys.initializationVector);
  }
  else
  {
    EXPECT_NE(localKeys.signingKey, remoteKeys.signingKey);
  }
}

// A policy with an EphemeralKeyAlgorithm (the ECC policies and RSA_DH) derives its keys from two ephemeral
// key pairs (Part 6 sections 6.8.1 and 6.9); the others from two random nonces.
// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(AuthenticatedSecurityPolicyTests, DerivedKeysSizeMatchPolicyConstants)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();

  if (params.ephemeralKeyAlgorithm.has_value())
  {
    auto serverEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);
    auto clientEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);

    auto ctx = make_channel_context();
    ctx->crypto = crypto;
    ctx->securityPolicy = mPolicy;
    ctx->localEphemeralPrivateKey = serverEphemeral.privateKey;

    auto [localKeys, remoteKeys] = derive_keys_sync(
      mPolicy, ctx, serverEphemeral.publicKey, clientEphemeral.publicKey, ChannelRole::Server)
                                     .value();

    EXPECT_EQ(localKeys.signingKey.size(), params.symmetricSignatureKeySize);
    EXPECT_EQ(localKeys.encryptingKey.size(), params.symmetricEncryptionKeySize);
    EXPECT_EQ(localKeys.initializationVector.size(), params.symmetricIvSize);
    EXPECT_EQ(remoteKeys.signingKey.size(), params.symmetricSignatureKeySize);
    EXPECT_EQ(remoteKeys.encryptingKey.size(), params.symmetricEncryptionKeySize);
    EXPECT_EQ(remoteKeys.initializationVector.size(), params.symmetricIvSize);
  }
  else
  {
    auto serverNonce = crypto->get_entropy_sync(params.nonceLength);
    auto clientNonce = crypto->get_entropy_sync(params.nonceLength);

    auto ctx = make_channel_context();
    ctx->crypto = crypto;
    ctx->securityPolicy = mPolicy;

    auto [localKeys, remoteKeys] =
      derive_keys_sync(mPolicy, ctx, serverNonce, clientNonce, ChannelRole::Server).value();

    EXPECT_EQ(localKeys.signingKey.size(), params.symmetricSignatureKeySize);
    EXPECT_EQ(localKeys.encryptingKey.size(), params.symmetricEncryptionKeySize);
    EXPECT_EQ(localKeys.initializationVector.size(), params.symmetricIvSize);
    EXPECT_EQ(remoteKeys.signingKey.size(), params.symmetricSignatureKeySize);
    EXPECT_EQ(remoteKeys.encryptingKey.size(), params.symmetricEncryptionKeySize);
    EXPECT_EQ(remoteKeys.initializationVector.size(), params.symmetricIvSize);
  }
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(AuthenticatedSecurityPolicyTests, CrossKeySymmetry)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();

  if (params.ephemeralKeyAlgorithm.has_value())
  {
    auto serverEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);
    auto clientEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);

    auto serverCtx = make_channel_context();
    serverCtx->crypto = crypto;
    serverCtx->securityPolicy = mPolicy;
    serverCtx->localEphemeralPrivateKey = serverEphemeral.privateKey;

    auto [serverLocal, serverRemote] = derive_keys_sync(
      mPolicy, serverCtx, serverEphemeral.publicKey, clientEphemeral.publicKey, ChannelRole::Server)
                                         .value();

    auto clientCtx = make_channel_context();
    clientCtx->crypto = crypto;
    clientCtx->securityPolicy = mPolicy;
    clientCtx->localEphemeralPrivateKey = clientEphemeral.privateKey;

    auto [clientLocal, clientRemote] = derive_keys_sync(
      mPolicy, clientCtx, clientEphemeral.publicKey, serverEphemeral.publicKey, ChannelRole::Client)
                                         .value();

    EXPECT_EQ(serverLocal.signingKey, clientRemote.signingKey);
    EXPECT_EQ(serverLocal.encryptingKey, clientRemote.encryptingKey);
    EXPECT_EQ(serverLocal.initializationVector, clientRemote.initializationVector);

    EXPECT_EQ(serverRemote.signingKey, clientLocal.signingKey);
    EXPECT_EQ(serverRemote.encryptingKey, clientLocal.encryptingKey);
    EXPECT_EQ(serverRemote.initializationVector, clientLocal.initializationVector);
  }
  else
  {
    auto serverNonce = crypto->get_entropy_sync(params.nonceLength);
    auto clientNonce = crypto->get_entropy_sync(params.nonceLength);

    auto serverCtx = make_channel_context();
    serverCtx->crypto = crypto;
    serverCtx->securityPolicy = mPolicy;

    auto [serverLocal, serverRemote] =
      derive_keys_sync(mPolicy, serverCtx, serverNonce, clientNonce, ChannelRole::Server).value();

    auto clientCtx = make_channel_context();
    clientCtx->crypto = crypto;
    clientCtx->securityPolicy = mPolicy;

    auto [clientLocal, clientRemote] =
      derive_keys_sync(mPolicy, clientCtx, clientNonce, serverNonce, ChannelRole::Client).value();

    EXPECT_EQ(serverLocal.signingKey, clientRemote.signingKey);
    EXPECT_EQ(serverLocal.encryptingKey, clientRemote.encryptingKey);
    EXPECT_EQ(serverLocal.initializationVector, clientRemote.initializationVector);

    EXPECT_EQ(serverRemote.signingKey, clientLocal.signingKey);
    EXPECT_EQ(serverRemote.encryptingKey, clientLocal.encryptingKey);
    EXPECT_EQ(serverRemote.initializationVector, clientLocal.initializationVector);
  }
}

// @relation(AC-COMP-SECPOL-ROWS-TABLE49, scope=function)
TEST_P(AuthenticatedSecurityPolicyTests, ServerAndClientKeysDiffer)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();

  if (params.ephemeralKeyAlgorithm.has_value())
  {
    auto serverEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);
    auto clientEphemeral = crypto->create_ephemeral_keys_sync(*params.ephemeralKeyAlgorithm);

    auto ctx = make_channel_context();
    ctx->crypto = crypto;
    ctx->securityPolicy = mPolicy;
    ctx->localEphemeralPrivateKey = serverEphemeral.privateKey;

    auto [localKeys, remoteKeys] = derive_keys_sync(
      mPolicy, ctx, serverEphemeral.publicKey, clientEphemeral.publicKey, ChannelRole::Server)
                                     .value();

    expect_directions_differ(params, localKeys, remoteKeys);
  }
  else
  {
    auto serverNonce = crypto->get_entropy_sync(params.nonceLength);
    auto clientNonce = crypto->get_entropy_sync(params.nonceLength);

    auto ctx = make_channel_context();
    ctx->crypto = crypto;
    ctx->securityPolicy = mPolicy;

    auto [localKeys, remoteKeys] =
      derive_keys_sync(mPolicy, ctx, serverNonce, clientNonce, ChannelRole::Server).value();

    expect_directions_differ(params, localKeys, remoteKeys);
  }
}

// Part 6 section 6.8.2: the certificate curve shall be in the ECC policy's permitted named-curve list.
// Owner review 2026-10-02, item 2: the curve rule is the validator's Security Policy Check (Part 4 Table 106
// step 4), SecurityPolicy::check_certificate_compliance, which the certificate store's validation calls for
// every certificate of the chain it builds; the policy no longer refuses before the store is asked, and the
// refusal is Bad_CertificatePolicyCheckFailed. The arm drives that check with real certificates: a
// self-signed Ed25519 (Curve25519) certificate on the nistP256 policy is refused, a self-signed P-256
// certificate signed with ECDSA-SHA256 complies. The U7 matrix
// (certificate_policy_and_error_matrix_tests.cpp) carries the rule through the whole validator.
// @relation(AC-SVR-ECC-006-NAMED-CURVE-VALIDATION, scope=function)
TEST(EccCertificatePolicyValidation, RejectsAnUnlistedCurveAtTheSecurityPolicyCheck)
{
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  TestPki pki{crypto};
  const auto selfSigned = [&](CertificateKeyAlgorithm key, CertificateSignatureAlgorithm algorithm)
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = crypto->create_asymmetric_key_pair_sync(key, std::nullopt);
    p.subject.commonName = "Curve Check";
    p.serialNumber = "6006";
    p.keyUsage.digitalSignature = true;
    p.certificateSignatureAlgorithm = algorithm;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{30}};
    return pki.create_cert(p);
  };

  const auto curve25519 =
    selfSigned(CertificateKeyAlgorithm::EccCurve25519, CertificateSignatureAlgorithm::PureEdDsa25519);
  const auto disallowed =
    policy->check_certificate_compliance(*curve25519, *curve25519, CertificateChainPosition::EndEntity);
  EXPECT_EQ(disallowed.status_code().as_status(), Status::BadCertificatePolicyCheckFailed);
  ASSERT_NE(disallowed.shared_detail(), nullptr);
  EXPECT_EQ(disallowed.shared_detail()->code, "CertificateKeyNotPermitted");

  const auto p256 =
    selfSigned(CertificateKeyAlgorithm::EccNistP256, CertificateSignatureAlgorithm::EcDsaSha2256);
  const auto permitted =
    policy->check_certificate_compliance(*p256, *p256, CertificateChainPosition::EndEntity);
  EXPECT_TRUE(permitted.is_good()) << std::hex << permitted.status_code().as_uint32();
}

// The asymmetric signature is made with the certificate's key, and the P-256 policy admits a P-384
// certificate, so the signature's size follows the certificate's curve (96 bytes for P-384); without a
// certificate the policy's own curve decides (review CRY-12).
// @verifies AC-SVR-ECC-006-A-SIGNATURE-IS-SIZED-BY-THE-SIGNING-CERTIFICATE
TEST(EccCertificatePolicyValidation, TheSignatureSizeFollowsTheCertificateCurve)
{
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const CertificateWithKeyAlgorithm p384{CertificateKeyAlgorithm::EccNistP384};
  const CertificateWithKeyAlgorithm p256{CertificateKeyAlgorithm::EccNistP256};
  EXPECT_EQ(policy->asymmetric_signature_size(&p384), 96u);
  EXPECT_EQ(policy->asymmetric_signature_size(&p256), 64u);
  EXPECT_EQ(policy->asymmetric_signature_size(nullptr), 64u);
}

// @relation(AC-SVR-UASC-014-SEQWRAP, scope=function)
TEST(SecureChannelContextSequenceNumbers, InitialStateMatchesTheNegotiatedLegacyMode)
{
  SecureChannelContext context;

  context.initialise_sequence_numbers(true);
  EXPECT_EQ(context.lastTxSequenceNumber, 0u);
  ASSERT_TRUE(context.lastRxSequenceNumber.has_value());
  EXPECT_EQ(*context.lastRxSequenceNumber, 0u);

  context.initialise_sequence_numbers(false);
  EXPECT_EQ(context.lastTxSequenceNumber, std::numeric_limits<uint32_t>::max());
  EXPECT_FALSE(context.lastRxSequenceNumber.has_value());
}

}  // namespace
