// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <type_traits>
#include <algorithm>
#include <cstring>
#include <array>
#include <functional>
#include <atomic>
#include <vector>
#include <tuple>
#include <memory>
#include <chrono>
#include <future>
#include <stdexcept>
#include "certificate_validation_request_helpers.h"
#include "ua_certificate_validation_paths.h"
#include "ua_crypto.h"
#include "ua_secure_string.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_x509_certificate.h"
#include "ua_x509_crl.h"
#include "fake_async_crypto.h"
#include "test_pki_helpers.h"
#include "test_key_cache.h"
#include "run_async_sync.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using namespace ua;

template<typename TCryptoBackend>
struct CryptoTestBackend
{
  static std::shared_ptr<const Crypto> create_crypto()
  {
    return TCryptoBackend::create_crypto();
  }
};

struct OpenSslBackend
{
  static std::shared_ptr<const Crypto> create_crypto()
  {
    return create_default_crypto([]() { return ua::SecureString{"password"}; });
  }
};

using CryptoBackends = ::testing::Types<OpenSslBackend>;

template<typename TBackend>
class CryptoGenericTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = TBackend::create_crypto();
  }

  std::shared_ptr<const Crypto> mCrypto;
};

TYPED_TEST_SUITE(CryptoGenericTests, CryptoBackends);

// --- Entropy ---

TYPED_TEST(CryptoGenericTests, EntropySync)
{
  size_t size = 32;
  ByteString entropy = this->mCrypto->get_entropy_sync(size);
  EXPECT_EQ(entropy.size(), size);

  ByteString entropy2 = this->mCrypto->get_entropy_sync(size);
  EXPECT_EQ(entropy2.size(), size);
  EXPECT_NE(entropy, entropy2);
}

TYPED_TEST(CryptoGenericTests, EntropyAsync)
{
  size_t size = 32;
  std::promise<ByteStringResult> p;
  this->mCrypto->get_entropy_async(size, [&p](ByteStringResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.value().size(), size);
}

// --- Hashing ---

void test_hash(const Crypto& crypto, HashAlgorithm alg, size_t expectedSize)
{
  std::string data = "Hello, OPC UA!";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(data.data()), data.size());

  // Sync
  ByteString hash = crypto.calculate_digest_sync(alg, input);
  EXPECT_EQ(hash.size(), expectedSize);

  // Async
  std::promise<Crypto::CalculateDigestOutputResult> p;
  crypto.calculate_digest_async(
    alg, {}, input, [&p](Crypto::CalculateDigestOutputResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.value().digest, hash);
}

TYPED_TEST(CryptoGenericTests, HashSha1)
{
  test_hash(*this->mCrypto, HashAlgorithm::Sha1, 20);
}

TYPED_TEST(CryptoGenericTests, HashSha2_256)
{
  test_hash(*this->mCrypto, HashAlgorithm::Sha2256, 32);
}

TYPED_TEST(CryptoGenericTests, HashSha2_384)
{
  test_hash(*this->mCrypto, HashAlgorithm::Sha2384, 48);
}

// --- Symmetric Encryption (CBC) ---

void test_symmetric_cbc(const Crypto& crypto, SymmetricEncryptionAlgorithm alg, size_t keySize)
{
  std::string plaintextStr = "This is a secret message that needs to be encrypted.";
  while (plaintextStr.size() % 16 != 0)
    plaintextStr += ' ';
  span<const std::byte> plaintext(
    reinterpret_cast<const std::byte*>(plaintextStr.data()), plaintextStr.size());

  ByteString key = crypto.get_entropy_sync(keySize);
  ByteString iv = crypto.get_entropy_sync(16);

  std::vector<std::byte> ciphertext(plaintext.size());
  crypto.symmetric_encrypt_sync(alg, iv, key, plaintext, ciphertext);

  std::vector<std::byte> decrypted(ciphertext.size());
  crypto.symmetric_decrypt_sync(alg, iv, key, ciphertext, decrypted);

  EXPECT_EQ(plaintext.size(), decrypted.size());
  EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()));

  // Async
  std::promise<VoidResult> pEnc;
  crypto.symmetric_encrypt_async(
    nullptr, alg, iv, key, plaintext, ciphertext, [&pEnc](VoidResult r) { pEnc.set_value(std::move(r)); });
  EXPECT_TRUE(pEnc.get_future().get().is_good());

  std::promise<VoidResult> pDec;
  crypto.symmetric_decrypt_async(
    nullptr, alg, iv, key, ciphertext, decrypted, [&pDec](VoidResult r) { pDec.set_value(std::move(r)); });
  EXPECT_TRUE(pDec.get_future().get().is_good());
  EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()));
}

TYPED_TEST(CryptoGenericTests, SymmetricAes128Cbc)
{
  test_symmetric_cbc(*this->mCrypto, SymmetricEncryptionAlgorithm::Aes128Cbc, 16);
}

TYPED_TEST(CryptoGenericTests, SymmetricAes256Cbc)
{
  test_symmetric_cbc(*this->mCrypto, SymmetricEncryptionAlgorithm::Aes256Cbc, 32);
}

// --- Symmetric AEAD (ChaCha20Poly1305) ---

TYPED_TEST(CryptoGenericTests, SymmetricChaCha20Poly1305)
{
  std::string plaintextStr = "ChaCha20Poly1305 message";
  span<const std::byte> plaintext(
    reinterpret_cast<const std::byte*>(plaintextStr.data()), plaintextStr.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  ByteString iv = this->mCrypto->get_entropy_sync(12);
  ByteString aad = this->mCrypto->get_entropy_sync(16);

  std::vector<std::byte> ciphertext(plaintext.size());
  ByteString tag = this->mCrypto->symmetric_encrypt_and_sign_sync(
    SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, plaintext, aad, ciphertext);
  EXPECT_EQ(tag.size(), 16);

  std::vector<std::byte> decrypted(plaintext.size());
  EXPECT_NO_THROW(this->mCrypto->symmetric_verify_and_decrypt_sync(
    SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, ciphertext, aad, tag, decrypted));
  EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()));

  // Tamper
  tag[0] ^= uint8_t{0xFF};
  EXPECT_THROW(this->mCrypto->symmetric_verify_and_decrypt_sync(
                 SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, ciphertext, aad, tag, decrypted),
    UaException);
}

// The tag length is the algorithm's, never the input's: OpenSSL accepts a Poly1305 tag of 1..16
// bytes and compares only that many, so a truncated tag would authenticate with a truncated check.
// @verifies AC-SVR-SC-007-SYMMETRIC-MAC-AND-AEAD-TAG-LENGTHS-ARE-THE-ALGORITHMS
TYPED_TEST(CryptoGenericTests, ChaCha20Poly1305RefusesATagShorterThanSixteenBytes)
{
  std::string plaintextStr = "ChaCha20Poly1305 message";
  span<const std::byte> plaintext(
    reinterpret_cast<const std::byte*>(plaintextStr.data()), plaintextStr.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  ByteString iv = this->mCrypto->get_entropy_sync(12);
  ByteString aad = this->mCrypto->get_entropy_sync(16);
  std::vector<std::byte> ciphertext(plaintext.size());
  ByteString tag = this->mCrypto->symmetric_encrypt_and_sign_sync(
    SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, plaintext, aad, ciphertext);
  ASSERT_EQ(tag.size(), 16u);

  // Control: the whole 16-byte tag authenticates.
  std::vector<std::byte> decrypted(plaintext.size());
  EXPECT_NO_THROW(this->mCrypto->symmetric_verify_and_decrypt_sync(
    SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, ciphertext, aad, tag, decrypted));

  ByteString truncated{span<const byte>{tag}.subspan(0, 12)};
  try
  {
    this->mCrypto->symmetric_verify_and_decrypt_sync(
      SymmetricEncryptionAlgorithm::ChaCha20Poly1305, iv, key, ciphertext, aad, truncated, decrypted);
    FAIL() << "a 12-byte tag must not authenticate the message";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadSecurityChecksFailed);
  }
}

// @verifies AC-SVR-SC-007-SYMMETRIC-MAC-AND-AEAD-TAG-LENGTHS-ARE-THE-ALGORITHMS
TYPED_TEST(CryptoGenericTests, SymmetricVerifyRefusesAPrefixOfTheMac)
{
  std::string message = "Message to sign";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  const auto alg = SymmetricSignatureAlgorithm::HmacSha2256;
  ByteString signature = this->mCrypto->symmetric_sign_sync(alg, key, input);
  ASSERT_EQ(signature.size(), 32u);
  EXPECT_NO_THROW(this->mCrypto->symmetric_verify_sync(alg, key, input, signature));

  // A prefix of the real MAC: byte-for-byte correct as far as it goes, and refused for its length.
  ByteString prefix{span<const byte>{signature}.subspan(0, 16)};
  try
  {
    this->mCrypto->symmetric_verify_sync(alg, key, input, prefix);
    FAIL() << "a truncated MAC must not verify";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadSecurityChecksFailed);
  }
}

// @verifies AC-SVR-SC-007-SYMMETRIC-MAC-AND-AEAD-TAG-LENGTHS-ARE-THE-ALGORITHMS
TYPED_TEST(CryptoGenericTests, SymmetricVerifyRefusesASignatureLongerThanTheMac)
{
  std::string message = "Message to sign";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  const auto alg = SymmetricSignatureAlgorithm::HmacSha2256;
  ByteString signature = this->mCrypto->symmetric_sign_sync(alg, key, input);
  ASSERT_EQ(signature.size(), 32u);

  // The real MAC with bytes appended: comparing at the input's length would read past the
  // calculated MAC (undefined behaviour without the length pin, which is why this is its own arm).
  ByteString longer = signature;
  longer.resize(40, uint8_t{0x00});
  try
  {
    this->mCrypto->symmetric_verify_sync(alg, key, input, longer);
    FAIL() << "an over-long signature must not verify";
  }
  catch (const UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), Status::BadSecurityChecksFailed);
    // The length refusal names both sizes; a compare that over-read past the MAC would not.
    ASSERT_NE(ex.detail(), nullptr);
    bool sawExpected = false;
    for (const auto& item : ex.detail()->context)
      sawExpected = sawExpected || (item.key == "size.expected" && item.value == "32");
    EXPECT_TRUE(sawExpected) << "the refusal must be the length pin's, not a mismatching over-read";
  }
}

// --- Symmetric Signing (MAC) ---

void test_symmetric_mac(const Crypto& crypto, SymmetricSignatureAlgorithm alg, size_t keySize)
{
  std::string message = "Message to sign";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());
  ByteString key = crypto.get_entropy_sync(keySize);

  ByteString signature = crypto.symmetric_sign_sync(alg, key, input);
  EXPECT_FALSE(signature.empty());

  EXPECT_NO_THROW(crypto.symmetric_verify_sync(alg, key, input, signature));

  // Async
  std::promise<ByteStringResult> pSign;
  crypto.symmetric_sign_async(
    nullptr, alg, key, input, [&pSign](ByteStringResult r) { pSign.set_value(std::move(r)); });
  auto signResult = pSign.get_future().get();
  EXPECT_TRUE(signResult.is_good());
  EXPECT_EQ(signResult.value(), signature);

  std::promise<VoidResult> pVerify;
  crypto.symmetric_verify_async(
    nullptr, alg, key, input, signature, [&pVerify](VoidResult r) { pVerify.set_value(std::move(r)); });
  EXPECT_TRUE(pVerify.get_future().get().is_good());
}

TYPED_TEST(CryptoGenericTests, SymmetricHmacSha1)
{
  test_symmetric_mac(*this->mCrypto, SymmetricSignatureAlgorithm::HmacSha1, 20);
}

TYPED_TEST(CryptoGenericTests, SymmetricHmacSha2_256)
{
  test_symmetric_mac(*this->mCrypto, SymmetricSignatureAlgorithm::HmacSha2256, 32);
}

TYPED_TEST(CryptoGenericTests, SymmetricHmacSha2_384)
{
  test_symmetric_mac(*this->mCrypto, SymmetricSignatureAlgorithm::HmacSha2384, 48);
}

// An AEAD tag (ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM) is produced by the AEAD encryption with the
// encrypting key; it is not a standalone keyed MAC over a raw key. The AEAD policies route through the
// encrypt/sign + verify/decrypt path, so these algorithms must never reach the generic symmetric MAC
// surface. Requesting one there must be rejected with a clean error rather than silently computing a
// non-conformant tag.
// @relation(AC-COMP-CRYPTO-SCE-AEAD-NOT-A-MAC, scope=function)
TYPED_TEST(CryptoGenericTests, SymmetricAeadTagAlgorithmsAreRejectedAsAMac)
{
  std::string message = "Message to sign";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  ByteString signature = this->mCrypto->get_entropy_sync(16);

  for (const auto algorithm : {SymmetricSignatureAlgorithm::ChaCha20Poly1305,
         SymmetricSignatureAlgorithm::Aes128Gcm,
         SymmetricSignatureAlgorithm::Aes256Gcm})
  {
    SCOPED_TRACE(static_cast<int>(algorithm));
    // Sync surface throws UaException (default case -> BadInvalidArgument).
    EXPECT_THROW(this->mCrypto->symmetric_sign_sync(algorithm, key, input), UaException);
    EXPECT_THROW(this->mCrypto->symmetric_verify_sync(algorithm, key, input, signature), UaException);
    try
    {
      (void)this->mCrypto->symmetric_sign_sync(algorithm, key, input);
    }
    catch (const UaException& e)
    {
      EXPECT_EQ(e.status(), Status::BadInvalidArgument);
    }
    try
    {
      this->mCrypto->symmetric_verify_sync(algorithm, key, input, signature);
    }
    catch (const UaException& e)
    {
      EXPECT_EQ(e.status(), Status::BadInvalidArgument);
    }

    // Async surface surfaces the error as a bad Result, not a (wrong) good tag.
    std::promise<ByteStringResult> pSign;
    this->mCrypto->symmetric_sign_async(
      nullptr, algorithm, key, input, [&pSign](ByteStringResult r) { pSign.set_value(std::move(r)); });
    auto signResult = pSign.get_future().get();
    EXPECT_TRUE(signResult.is_bad());
    EXPECT_EQ(signResult.status_code().as_status(), Status::BadInvalidArgument);

    std::promise<VoidResult> pVerify;
    this->mCrypto->symmetric_verify_async(nullptr,
      algorithm,
      key,
      input,
      signature,
      [&pVerify](VoidResult r) { pVerify.set_value(std::move(r)); });
    auto verifyResult = pVerify.get_future().get();
    EXPECT_TRUE(verifyResult.is_bad());
    EXPECT_EQ(verifyResult.status_code().as_status(), Status::BadInvalidArgument);
  }
}

// --- Key Derivation ---

TYPED_TEST(CryptoGenericTests, KdfPSha1)
{
  ByteString secret = this->mCrypto->get_entropy_sync(20);
  ByteString seed = this->mCrypto->get_entropy_sync(20);
  size_t length = 32;
  ByteString key1 =
    this->mCrypto->derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm::PSha1, length, secret, seed);
  EXPECT_EQ(key1.size(), length);
  ByteString key2 =
    this->mCrypto->derive_symmetric_keys_sync(SymmetricKeyDerivationAlgorithm::PSha1, length, secret, seed);
  EXPECT_EQ(key1, key2);
}

TYPED_TEST(CryptoGenericTests, KdfPSha2_256)
{
  ByteString secret = this->mCrypto->get_entropy_sync(32);
  ByteString seed = this->mCrypto->get_entropy_sync(32);
  size_t length = 64;
  ByteString key1 = this->mCrypto->derive_symmetric_keys_sync(
    SymmetricKeyDerivationAlgorithm::PSha2256, length, secret, seed);
  EXPECT_EQ(key1.size(), length);
}

TYPED_TEST(CryptoGenericTests, KdfHkdfSha2_256)
{
  ByteString secret = this->mCrypto->get_entropy_sync(32);
  ByteString salt = this->mCrypto->get_entropy_sync(32);
  ByteString info = this->mCrypto->get_entropy_sync(16);
  size_t length = 32;
  ByteString key = this->mCrypto->derive_symmetric_keys_sync(
    SymmetricKeyDerivationAlgorithm::HkdfSha2256, length, secret, salt, info);
  EXPECT_EQ(key.size(), length);
}

TYPED_TEST(CryptoGenericTests, KdfHkdfSha2_384)
{
  ByteString secret = this->mCrypto->get_entropy_sync(48);
  ByteString salt = this->mCrypto->get_entropy_sync(48);
  ByteString info = this->mCrypto->get_entropy_sync(16);
  size_t length = 48;
  ByteString key = this->mCrypto->derive_symmetric_keys_sync(
    SymmetricKeyDerivationAlgorithm::HkdfSha2384, length, secret, salt, info);
  EXPECT_EQ(key.size(), length);
}

// --- Asymmetric Encryption ---

void test_asymmetric_encrypt(const Crypto& crypto, AsymmetricEncryptionAlgorithm alg, size_t keyBits)
{
  auto keys = crypto.create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, keyBits);
  ASSERT_NE(keys, nullptr);

  std::string plaintextStr = "Secret RSA message";
  span<const std::byte> plaintext(
    reinterpret_cast<const std::byte*>(plaintextStr.data()), plaintextStr.size());

  std::vector<std::byte> ciphertext(keyBits / 8);
  crypto.asymmetric_encrypt_sync(alg, keys->public_key_der(), plaintext, ciphertext);

  std::vector<std::byte> decryptedBuf(keyBits / 8);
  span<const std::byte> decrypted = crypto.asymmetric_decrypt_sync(alg, keys, ciphertext, decryptedBuf);

  EXPECT_EQ(plaintext.size(), decrypted.size());
  EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), decrypted.begin()));
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaPkcs15_2048)
{
  test_asymmetric_encrypt(*this->mCrypto, AsymmetricEncryptionAlgorithm::RsaPkcs15, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaOaepSha1_2048)
{
  test_asymmetric_encrypt(*this->mCrypto, AsymmetricEncryptionAlgorithm::RsaOaepSha1, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaOaepSha2_256_2048)
{
  test_asymmetric_encrypt(*this->mCrypto, AsymmetricEncryptionAlgorithm::RsaOaepSha2256, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaOaepSha2_256_3072)
{
  test_asymmetric_encrypt(*this->mCrypto, AsymmetricEncryptionAlgorithm::RsaOaepSha2256, 3072);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaOaepSha2_256_4096)
{
  test_asymmetric_encrypt(*this->mCrypto, AsymmetricEncryptionAlgorithm::RsaOaepSha2256, 4096);
}

// --- Asymmetric Signing ---

void test_asymmetric_sign(const Crypto& crypto, AsymmetricSignatureAlgorithm alg,
  CertificateKeyAlgorithm keyAlg, optional<size_t> keyBits = std::nullopt)
{
  auto keys = crypto.create_asymmetric_key_pair_sync(keyAlg, keyBits);
  ASSERT_NE(keys, nullptr);

  std::string message = "Message to sign";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());

  ByteString signature = crypto.asymmetric_sign_sync(alg, keys, input);
  EXPECT_FALSE(signature.empty());

  EXPECT_NO_THROW(crypto.asymmetric_verify_sync(alg, keys->public_key_der(), input, signature));
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaPkcs15Sha1_2048)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::RsaPkcs15Sha1, CertificateKeyAlgorithm::Rsa, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaPkcs15Sha2_256_2048)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256, CertificateKeyAlgorithm::Rsa, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricRsaPssSha2_256_2048)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::RsaPssSha2256, CertificateKeyAlgorithm::Rsa, 2048);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_256_NistP256)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2256, CertificateKeyAlgorithm::EccNistP256);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_384_NistP384)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2384, CertificateKeyAlgorithm::EccNistP384);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_512_NistP521)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2512, CertificateKeyAlgorithm::EccNistP521);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_256_BrainpoolP256r1)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2256, CertificateKeyAlgorithm::EccBrainpoolP256r1);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_384_BrainpoolP384r1)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2384, CertificateKeyAlgorithm::EccBrainpoolP384r1);
}

TYPED_TEST(CryptoGenericTests, AsymmetricEcDsaSha2_512_BrainpoolP512r1)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::EcDsaSha2512, CertificateKeyAlgorithm::EccBrainpoolP512r1);
}

TYPED_TEST(CryptoGenericTests, AsymmetricPureEdDsa25519)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::PureEdDsa25519, CertificateKeyAlgorithm::EccCurve25519);
}

TYPED_TEST(CryptoGenericTests, AsymmetricPureEdDsa448)
{
  test_asymmetric_sign(
    *this->mCrypto, AsymmetricSignatureAlgorithm::PureEdDsa448, CertificateKeyAlgorithm::EccCurve448);
}

// --- Ephemeral Key Exchange ---

void test_key_exchange(const Crypto& crypto, EphemeralKeyAlgorithm alg)
{
  auto keysA = crypto.create_ephemeral_keys_sync(alg);
  auto keysB = crypto.create_ephemeral_keys_sync(alg);

  ByteString secretA = crypto.calculate_shared_secret_sync(alg, keysA.privateKey, keysB.publicKey);
  ByteString secretB = crypto.calculate_shared_secret_sync(alg, keysB.privateKey, keysA.publicKey);

  EXPECT_FALSE(secretA.empty());
  EXPECT_EQ(secretA, secretB);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeNistP256)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccNistP256);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeNistP384)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccNistP384);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeBrainpoolP256r1)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccBrainpoolP256r1);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeBrainpoolP384r1)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccBrainpoolP384r1);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeX25519)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccCurve25519);
}

TYPED_TEST(CryptoGenericTests, KeyExchangeX448)
{
  test_key_exchange(*this->mCrypto, EphemeralKeyAlgorithm::EccCurve448);
}

// --- Certificate & CRL Management ---

TYPED_TEST(CryptoGenericTests, CertificateLifecycle)
{
  TestPki pki(this->mCrypto);
  auto caKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  // Validated below as an ApplicationInstance Certificate, so it carries the Part 6 Table 43 bits.
  auto caCert = pki.create_self_signed_application_root(caKeys);

  // Read from DER
  ByteString der = caCert->der_encoding();
  auto readCert = this->mCrypto->read_certificate_from_der(der);
  EXPECT_EQ(readCert->thumbprint(), caCert->thumbprint());

  // CSR
  Crypto::CreateCsrConfig csrParams;
  auto subjectKeys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  csrParams.subjectKeys = subjectKeys;
  csrParams.subject.commonName = "Test CSR";
  std::promise<ByteStringResult> pCsr;
  this->mCrypto->create_certificate_signing_request_async(
    csrParams, [&pCsr](ByteStringResult r) { pCsr.set_value(std::move(r)); });
  auto csrResult = pCsr.get_future().get();
  EXPECT_TRUE(csrResult.is_good());
  auto csrDer = std::move(csrResult).value();
  EXPECT_FALSE(csrDer.empty());

  // Validation
  TrustListValidationOptions options{{TrustListValidationOptions::Bit::CheckRevocationStatusOffline}};
  auto crl = this->mCrypto->create_crl_sync(caCert, caKeys, {});
  std::promise<VoidResult> pVal;
  this->mCrypto->validate_certificate_async(
    ua::test::make_crypto_request(caCert, std::nullopt, std::nullopt, CertificateUse::ApplicationInstance),
    ua::test::make_validation_material(options, {caCert}, {crl}, {}, {}),
    [&pVal](VoidResult r) { pVal.set_value(std::move(r)); });
  EXPECT_TRUE(pVal.get_future().get().is_good());
}

// A self-signed end-entity certificate (CA:FALSE) placed directly in the trust list is its own trust
// anchor and must validate - the shape of the CTT application-instance certs (Part 4 section 6.1.3: trust
// by direct inclusion). It is validated as an ApplicationInstance Certificate, so it carries the RSA
// keyUsage and extendedKeyUsage of OPC 10000-6 Table 43.
TYPED_TEST(CryptoGenericTests, SelfSignedLeafInTrustListValidates)
{
  auto keys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  Crypto::CreateCertificateConfig p;
  p.subjectKeys = p.issuerKeys = keys;  // self-signed
  p.subject.commonName = "ctt_usrT_like";
  p.serialNumber = "200";
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.basicConstraint.cA = false;  // end-entity, not a CA
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{365}};

  TestPki pki(this->mCrypto);
  auto leaf = pki.create_cert(p);

  TrustListValidationOptions options;  // defaults: no revocation/host/uri checks
  std::promise<VoidResult> pVal;
  this->mCrypto->validate_certificate_async(
    ua::test::make_crypto_request(leaf, std::nullopt, std::nullopt, CertificateUse::ApplicationInstance),
    ua::test::make_validation_material(options,
      {leaf},  // the leaf is in the trusted list - its own anchor
      {},
      {},
      {}),
    [&pVal](VoidResult r) { pVal.set_value(std::move(r)); });
  auto result = pVal.get_future().get();
  EXPECT_TRUE(result.is_good()) << "status=0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().as_status());
}

// A certificate whose signature is invalid is refused even when that same certificate is in the trust
// list (OPC 10000-4 6.1.3: an invalid signature is never suppressible). Being a trust anchor makes the
// certificate trusted; it does not make a forged self-signature genuine. The control is the same
// certificate with its signature intact.
TYPED_TEST(CryptoGenericTests, TrustedSelfSignedCertificateWithAnInvalidSignatureIsRefused)
{
  auto keys = this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = keys;
  p.subject.commonName = "forged_self_signature";
  p.serialNumber = "201";
  p.keyUsage.digitalSignature = true;
  p.basicConstraint.cA = false;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{365}};
  TestPki pki(this->mCrypto);
  auto genuine = pki.create_cert(p);

  // The signature is the last element of the DER encoding, so its final byte belongs to it.
  auto der = genuine->der_encoding();
  std::vector<uint8_t> bytes(der.begin(), der.end());
  ASSERT_FALSE(bytes.empty());
  bytes.back() ^= uint8_t{0x5a};
  auto forged = this->mCrypto->read_certificate_from_der(ByteString{bytes});

  const auto validate = [this](const std::shared_ptr<const X509Certificate>& certificate)
  {
    std::promise<VoidResult> done;
    // Validated for the User use: the certificate carries digitalSignature alone (Table 44), so the only
    // thing that can refuse it is its signature.
    this->mCrypto->validate_certificate_async(
      ua::test::make_crypto_request(certificate, std::nullopt, std::nullopt, CertificateUse::User),
      ua::test::make_validation_material(TrustListValidationOptions{}, {certificate}, {}, {}, {}),
      [&done](VoidResult r) { done.set_value(std::move(r)); });
    return done.get_future().get();
  };

  EXPECT_TRUE(validate(genuine).is_good()) << "control: the intact certificate must validate";
  const auto refused = validate(forged);
  EXPECT_TRUE(refused.is_bad()) << "a trusted certificate with an invalid self-signature was accepted";
}

// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-02-THROWING-CALLBACK-ONCE, scope=function)
TEST(CryptoOpenSslCallbackSafety, ThrowingValidationCallbackIsContainedAndInvokedOnce)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto certificate = pki.create_root_ca(keys);
  std::atomic<std::size_t> callbackCalls{0};

  crypto->validate_certificate_async(
    ua::test::make_crypto_request(
      certificate, std::nullopt, std::nullopt, CertificateUse::ApplicationInstance),
    ua::test::make_validation_material(TrustListValidationOptions{}, {certificate}, {}, {}, {}),
    [&callbackCalls](VoidResult)
    {
      if (callbackCalls.fetch_add(1, std::memory_order_relaxed) == 0)
      {
        throw std::runtime_error{"validation callback failure"};
      }
    });

  EXPECT_EQ(callbackCalls.load(std::memory_order_relaxed), 1U)
    << "a callback exception belongs to the user boundary and must not be retried as validation failure";
}

// --- Negative Tests ---

TYPED_TEST(CryptoGenericTests, NegativeInvalidAlgorithm)
{
  std::string data = "test";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(data.data()), data.size());
  EXPECT_THROW(this->mCrypto->calculate_digest_sync(HashAlgorithm::Invalid, input), UaException);
}

TYPED_TEST(CryptoGenericTests, NegativeInvalidKeySize)
{
  std::string data = "1234567890123456";  // 16 bytes
  span<const std::byte> plaintext(reinterpret_cast<const std::byte*>(data.data()), data.size());
  ByteString key = this->mCrypto->get_entropy_sync(15);  // Invalid for AES-128
  ByteString iv = this->mCrypto->get_entropy_sync(16);
  std::vector<std::byte> ciphertext(16);

  EXPECT_THROW(this->mCrypto->symmetric_encrypt_sync(
                 SymmetricEncryptionAlgorithm::Aes128Cbc, iv, key, plaintext, ciphertext),
    UaException);
}

TYPED_TEST(CryptoGenericTests, NegativeTamperedSignature)
{
  std::string message = "Message";
  span<const std::byte> input(reinterpret_cast<const std::byte*>(message.data()), message.size());
  ByteString key = this->mCrypto->get_entropy_sync(32);
  ByteString signature =
    this->mCrypto->symmetric_sign_sync(SymmetricSignatureAlgorithm::HmacSha2256, key, input);

  signature[0] ^= uint8_t{0xFF};
  EXPECT_THROW(
    this->mCrypto->symmetric_verify_sync(SymmetricSignatureAlgorithm::HmacSha2256, key, input, signature),
    UaException);
}

// --- Certificates whose public key does not decode ---

namespace
{

struct CurveFixture
{
  ByteString original;  ///< the certificate as issued
  ByteString altered;  ///< the same bytes with the curve OID re-labelled to one no provider knows
};

/// An EC certificate, and a copy whose SubjectPublicKeyInfo names a curve no provider knows.
/// d2i_X509 still parses the copy (the key decode is opportunistic), so it is the input the parser
/// must refuse where DER enters; the original is the control.
CurveFixture certificate_with_unknown_curve(const std::shared_ptr<const Crypto>& crypto)
{
  TestPki pki(crypto);
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto cert = pki.create_root_ca(keys, "Undecodable Key", "901");
  CurveFixture fixture;
  fixture.original = cert->der_encoding();
  fixture.altered = fixture.original;
  const std::array<uint8_t, 10> prime256v1{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  auto it = std::search(fixture.altered.begin(), fixture.altered.end(), prime256v1.begin(), prime256v1.end());
  if (it == fixture.altered.end())
  {
    return {};
  }
  *(it + 9) = 0x7F;  // still a well-formed OID, but not a curve
  return fixture;
}

Status status_of(const std::function<void()>& fn)
{
  try
  {
    fn();
  }
  catch (const UaException& exception)
  {
    return exception.status();
  }
  return Status::Good;
}

}  // namespace

// @relation(AC-SVR-SECADMIN-004-CERTIFICATE-WITHOUT-DECODABLE-KEY-IS-REFUSED, scope=function)
TYPED_TEST(CryptoGenericTests, CertificateWhoseKeyDoesNotDecodeIsRefusedAtParse)
{
  const ByteString der = certificate_with_unknown_curve(this->mCrypto).altered;
  ASSERT_FALSE(der.empty()) << "fixture: the curve OID must be present in the DER";

  EXPECT_EQ(
    status_of([&] { (void)this->mCrypto->read_certificate_from_der(der); }), Status::BadCertificateInvalid)
    << "a certificate whose SubjectPublicKeyInfo does not decode must be refused by the single-certificate "
       "parser";
  EXPECT_EQ(
    status_of([&] { (void)this->mCrypto->read_certificates_from_der(der); }), Status::BadCertificateInvalid)
    << "a certificate whose SubjectPublicKeyInfo does not decode must be refused by the chain parser";
}

// control: the same certificate before the OID is altered parses, through both parsers, and reports
// its curve.
// @relation(AC-SVR-SECADMIN-004-CERTIFICATE-WITHOUT-DECODABLE-KEY-IS-REFUSED, scope=function)
TYPED_TEST(CryptoGenericTests, CertificateWithADecodableKeyParsesAndReportsItsAlgorithm)
{
  const ByteString der = certificate_with_unknown_curve(this->mCrypto).original;
  ASSERT_FALSE(der.empty());

  auto single = this->mCrypto->read_certificate_from_der(der);
  ASSERT_NE(single, nullptr);
  auto chain = this->mCrypto->read_certificates_from_der(der);
  ASSERT_EQ(chain.size(), 1u);
  for (const auto& parsed : {single, chain.front()})
  {
    EXPECT_EQ(parsed->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);
    EXPECT_GT(parsed->public_key_bit_length(), 0u);
    EXPECT_FALSE(parsed->public_key().empty());
  }
}

// --- Verification with a key of another type ---

// A public key whose type does not match the signature algorithm is refused. The parsed key is owned
// before that check, so a peer that repeats the mismatch cannot grow the process (LeakSanitizer arm:
// run this test under the gcc-asan preset).
// @relation(AC-SVR-SC-007-VERIFY-WITH-MISMATCHED-KEY-TYPE-IS-REFUSED-WITHOUT-LEAK, scope=function)
TYPED_TEST(CryptoGenericTests, VerifyWithAKeyOfAnotherTypeIsRefusedEveryTime)
{
  auto ecKeys =
    this->mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  const ByteString ecPublicKey = ecKeys->public_key_der();
  const ByteString input(32, uint8_t{0x11});
  const ByteString signature(256, uint8_t{0x22});

  for (int attempt = 0; attempt < 64; ++attempt)
  {
    EXPECT_EQ(status_of(
                [&]
                {
                  this->mCrypto->asymmetric_verify_sync(
                    AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256, ecPublicKey, input, signature);
                }),
      Status::BadSecurityChecksFailed)
      << "attempt " << attempt;
  }
}

// --- Certificate use, missing issuer and CRL validation (OPC 10000-4 6.1.3 Table 106) ---

namespace
{

VoidResult validate_for_use(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const X509Certificate>& certificate,
  std::vector<std::shared_ptr<const X509Certificate>> trusted, CertificateUse use)
{
  std::promise<VoidResult> p;
  crypto->validate_certificate_async(
    ua::test::make_crypto_request(certificate, std::nullopt, std::nullopt, use),
    ua::test::make_validation_material(TrustListValidationOptions{}, std::move(trusted), {}, {}, {}),
    [&p](VoidResult r) { p.set_value(std::move(r)); });
  return p.get_future().get();
}

VoidResult validate_crl(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const X509Crl>& crl, std::vector<std::shared_ptr<const X509Certificate>> candidates,
  TrustListValidationOptions options = TrustListValidationOptions{})
{
  std::promise<VoidResult> p;
  crypto->validate_crl_async(
    options, crl, std::move(candidates), [&p](VoidResult r) { p.set_value(std::move(r)); });
  return p.get_future().get();
}

/// A CRL by @p issuer whose validity window lies wholly in the past (thisUpdate two days ago, nextUpdate
/// one day ago), re-signed with @p issuerKeys: the SDK's CRL factory issues only current CRLs.
std::shared_ptr<const X509Crl> make_out_of_date_crl(const std::shared_ptr<const Crypto>& crypto, TestPki& pki,
  const std::shared_ptr<const X509Certificate>& issuer,
  const std::shared_ptr<const AsymmetricKeyPair>& issuerKeys)
{
  const auto current = pki.create_crl(issuer, issuerKeys, {"1"});
  const auto der = current->der_encoding();
  const unsigned char* in = der.data();
  std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl{
    d2i_X509_CRL(nullptr, &in, static_cast<long>(der.size())), &X509_CRL_free};
  if (!crl)
    throw std::runtime_error{"d2i_X509_CRL failed"};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> thisUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> nextUpdate{ASN1_TIME_new(), &ASN1_TIME_free};
  X509_gmtime_adj(thisUpdate.get(), -2L * 24 * 60 * 60);
  X509_gmtime_adj(nextUpdate.get(), -1L * 24 * 60 * 60);
  X509_CRL_set1_lastUpdate(crl.get(), thisUpdate.get());
  X509_CRL_set1_nextUpdate(crl.get(), nextUpdate.get());

  const auto pem = issuerKeys->private_key_pem();
  std::unique_ptr<BIO, decltype(&BIO_free)> bio{
    BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
  char passphrase[] = "password";
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
    PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, passphrase), &EVP_PKEY_free};
  if (!key || X509_CRL_sign(crl.get(), key.get(), EVP_sha256()) <= 0)
    throw std::runtime_error{"re-signing the out-of-date CRL failed"};

  unsigned char* out = nullptr;
  const int length = i2d_X509_CRL(crl.get(), &out);
  if (length <= 0)
    throw std::runtime_error{"i2d_X509_CRL failed"};
  std::vector<byte> bytes(reinterpret_cast<const byte*>(out), reinterpret_cast<const byte*>(out) + length);
  OPENSSL_free(out);
  return crypto->read_crl_from_der(span<const byte>{bytes});
}

std::shared_ptr<const X509Certificate> make_intermediate_ca(TestPki& pki,
  const std::shared_ptr<const AsymmetricKeyPair>& keys,
  const std::shared_ptr<const AsymmetricKeyPair>& rootKeys,
  const std::shared_ptr<const X509Certificate>& root, optional<DateTime> from = std::nullopt,
  optional<DateTime> to = std::nullopt)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = keys;
  p.issuerKeys = rootKeys;
  p.issuer = root;
  p.subject.commonName = "Use Intermediate CA";
  p.serialNumber = "8101";
  p.basicConstraint.cA = true;
  p.keyUsage.keyCertSign = true;
  p.keyUsage.crlSign = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = from.value_or(DateTime::now());
  p.to = to.value_or(DateTime{p.from.value() + std::chrono::days{30}});
  return pki.create_cert(p);
}

std::shared_ptr<const X509Certificate> make_self_signed_end_entity(
  TestPki& pki, const std::shared_ptr<const AsymmetricKeyPair>& keys)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = p.issuerKeys = keys;
  p.subject.commonName = "Use Self-Signed End Entity";
  p.serialNumber = "8102";
  p.basicConstraint.cA = false;
  // The control validates it as an ApplicationInstance Certificate: OPC 10000-6 Table 43 RSA bits.
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{30}};
  return pki.create_cert(p);
}

std::string context_of(const VoidResult& result, std::string_view key)
{
  const auto& detail = result.shared_detail();
  if (!detail)
    return {};
  for (const auto& entry : detail->context)
    if (entry.key == key)
      return entry.value;
  return {};
}

}  // namespace

// An intermediate CA chaining to a trusted root is accepted for the CA use; the control validates the same
// certificate as an end-entity certificate, where a CA-issued certificate declaring cA TRUE is refused.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-03-CERTIFICATE-USE, scope=function)
TEST(CryptoOpenSslCertificateUse, AnIntermediateCaIsAcceptedForTheCaUse)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto root = pki.create_root_ca(rootKeys, "Use Root CA", "8100");
  const auto intermediateKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto intermediate = make_intermediate_ca(pki, intermediateKeys, rootKeys, root);

  const auto asCa = validate_for_use(crypto, intermediate, {root}, CertificateUse::CertificateAuthority);
  EXPECT_TRUE(asCa.is_good()) << std::hex << asCa.status_code().as_uint32();

  const auto asEndEntity =
    validate_for_use(crypto, intermediate, {root}, CertificateUse::ApplicationInstance);
  EXPECT_EQ(asEndEntity.status_code().as_status(), Status::BadCertificateUseNotAllowed)
    << "control: the end-entity rules still refuse a CA-issued certificate with cA TRUE";
}

// A certificate requested as a CA certificate that does not declare cA TRUE is refused with
// Bad_CertificateIssuerUseNotAllowed; the control accepts the same certificate as an end-entity one.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-03-CERTIFICATE-USE, scope=function)
TEST(CryptoOpenSslCertificateUse, ACertificateWithoutTheCaFlagIsRefusedForTheCaUse)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto endEntity = make_self_signed_end_entity(pki, keys);

  const auto asCa = validate_for_use(crypto, endEntity, {endEntity}, CertificateUse::CertificateAuthority);
  // The certificate under test is the one that may not be used as a CA, so it is UseNotAllowed; the issuer
  // variant is for an issuer certificate (Table 182; owner decision 22.4).
  EXPECT_EQ(asCa.status_code().as_status(), Status::BadCertificateUseNotAllowed);
  ASSERT_NE(asCa.shared_detail(), nullptr);
  EXPECT_EQ(asCa.shared_detail()->code, "CertificateIsNotACa");

  const auto asEndEntity =
    validate_for_use(crypto, endEntity, {endEntity}, CertificateUse::ApplicationInstance);
  EXPECT_TRUE(asEndEntity.is_good()) << "control: " << std::hex << asEndEntity.status_code().as_uint32();
}

// A self-signed root is accepted for the CA use, and - Part 6 Table 43 accepts cA TRUE on a self-signed
// certificate for backward interoperability - for the end-entity use too.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-03-CERTIFICATE-USE, scope=function)
TEST(CryptoOpenSslCertificateUse, ASelfSignedRootIsAcceptedForBothUses)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  // Validated as an ApplicationInstance Certificate too, so it carries the Table 43 bits (and keyCertSign).
  const auto root = pki.create_self_signed_application_root(keys, "Use Self-Signed Root", "8103");

  const auto asCa = validate_for_use(crypto, root, {root}, CertificateUse::CertificateAuthority);
  EXPECT_TRUE(asCa.is_good()) << std::hex << asCa.status_code().as_uint32();
  const auto asEndEntity = validate_for_use(crypto, root, {root}, CertificateUse::ApplicationInstance);
  EXPECT_TRUE(asEndEntity.is_good()) << std::hex << asEndEntity.status_code().as_uint32();
}

// Part 4 Table 106, Build Certificate Chain: a certificate whose issuer is in neither list reports
// Bad_CertificateChainIncomplete; the control supplies the issuer and validates.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-05-MISSING-ISSUER-CHAIN-INCOMPLETE, scope=function)
TEST(CryptoOpenSslCertificateUse, AMissingIssuerReportsChainIncomplete)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto root = pki.create_root_ca(rootKeys, "Absent Root CA", "8104");
  const auto leafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto leaf = pki.create_leaf_cert(
    leafKeys, rootKeys, root, DateTime::now(), DateTime{DateTime::now().value() + std::chrono::days{10}});

  const auto missing = validate_for_use(crypto, leaf, {}, CertificateUse::ApplicationInstance);
  EXPECT_EQ(missing.status_code().as_status(), Status::BadCertificateChainIncomplete);

  const auto present = validate_for_use(crypto, leaf, {root}, CertificateUse::ApplicationInstance);
  EXPECT_TRUE(present.is_good()) << "control: " << std::hex << present.status_code().as_uint32();
}

// A CRL signed by its issuer is valid; one carrying the issuer's name but signed by an unrelated key, and
// one whose issuer is not among the candidates, are refused with the specific cause, naming the issuer.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-04-CRL-VALIDATION, scope=function)
TEST(CryptoOpenSslCrlValidation, OnlyACrlSignedByACandidateIssuerIsValid)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto root = pki.create_root_ca(rootKeys, "Crl Root CA", "8105");
  const auto otherKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto otherCa = pki.create_root_ca(otherKeys, "Crl Other CA", "8106");

  const auto valid = validate_crl(crypto, pki.create_crl(root, rootKeys, {"1"}), {root});
  EXPECT_TRUE(valid.is_good()) << "control: " << std::hex << valid.status_code().as_uint32();

  const auto forged = validate_crl(crypto, pki.create_crl(root, otherKeys, {"1"}), {root});
  EXPECT_EQ(forged.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(forged.shared_detail(), nullptr);
  EXPECT_EQ(forged.shared_detail()->code, "CrlSignatureInvalid");
  EXPECT_NE(context_of(forged, ContextKeys::crlIssuer.value()).find("Crl Root CA"), std::string::npos)
    << "the refusal names the CRL's issuer";

  const auto orphan = validate_crl(crypto, pki.create_crl(otherCa, otherKeys, {"1"}), {root});
  EXPECT_EQ(orphan.status_code().as_status(), Status::BadCertificateChainIncomplete);
  ASSERT_NE(orphan.shared_detail(), nullptr);
  EXPECT_EQ(orphan.shared_detail()->code, "CrlIssuerNotFound");
  EXPECT_NE(context_of(orphan, ContextKeys::crlIssuer.value()).find("Crl Other CA"), std::string::npos);
}

// RFC 5280 bounds a commonName to 64 characters (ub-common-name). A longer one is refused with
// Bad_InvalidArgument naming the attribute; it is never dropped, which would leave the subject empty.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-06-NAME-BOUNDS, scope=function)
TEST(CryptoOpenSslCertificateNames, ACommonNameLongerThan64CharactersIsRefused)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto create = [&](std::size_t length)
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = std::string(length, 'n');
    p.serialNumber = "8130";
    p.keyUsage.digitalSignature = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{1}};
    std::promise<CertificateResult> promise;
    crypto->create_certificate_async(p, [&promise](CertificateResult r) { promise.set_value(std::move(r)); });
    return promise.get_future().get();
  };

  const auto atBound = create(64);
  ASSERT_TRUE(atBound.is_good()) << "control: 64 characters is within the bound";
  EXPECT_EQ(atBound.value()->subject_common_name(), std::string(64, 'n'));

  const auto overBound = create(65);
  EXPECT_EQ(overBound.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(overBound.shared_detail(), nullptr);
  EXPECT_EQ(overBound.shared_detail()->code, "CertificateNameFieldInvalid");
}

// An EdDSA CA issues CRLs: Ed25519 and Ed448 sign the message itself, with no separate digest (RFC 8032),
// and the CRL validates against its issuer. The RSA control is the test above.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-04-CRL-VALIDATION, scope=function)
TEST(CryptoOpenSslCrlValidation, AnEdDsaIssuerSignsAValidCrl)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  for (const auto& [algorithm, signature, name] :
    {std::tuple{
       CertificateKeyAlgorithm::EccCurve25519, CertificateSignatureAlgorithm::PureEdDsa25519, "Ed25519"},
      std::tuple{CertificateKeyAlgorithm::EccCurve448, CertificateSignatureAlgorithm::PureEdDsa448, "Ed448"}})
  {
    const auto keys = crypto->create_asymmetric_key_pair_sync(algorithm, std::nullopt);
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = p.issuerKeys = keys;
    p.subject.commonName = std::string{"Crl "} + name + " Root";
    p.serialNumber = "8120";
    p.basicConstraint.cA = true;
    p.keyUsage.keyCertSign = true;
    p.keyUsage.crlSign = true;
    p.certificateSignatureAlgorithm = signature;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    const auto root = pki.create_cert(p);

    const auto crl = pki.create_crl(root, keys, {"1"});
    ASSERT_NE(crl, nullptr) << name;
    const auto valid = validate_crl(crypto, crl, {root});
    EXPECT_TRUE(valid.is_good()) << name << ": " << std::hex << valid.status_code().as_uint32();
  }
}

// The CA rule runs after the chain, signature and validity checks, not instead of them: an intermediate CA
// requested for the CA use that has expired reports Bad_CertificateTimeInvalid, and one whose root is
// absent reports Bad_CertificateChainIncomplete. Either would read Good if the CA check short-circuited.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-03-CERTIFICATE-USE, scope=function)
TEST(CryptoOpenSslCertificateUse, TheCaUseStillRunsTheChainAndValidityChecks)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto root = pki.create_root_ca(rootKeys, "Order Root CA", "8110");
  const auto intermediateKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto now = DateTime::now().value();
  const auto expired = make_intermediate_ca(pki,
    intermediateKeys,
    rootKeys,
    root,
    DateTime{now - std::chrono::days{30}},
    DateTime{now - std::chrono::days{1}});
  const auto current = make_intermediate_ca(pki, intermediateKeys, rootKeys, root);

  const auto expiredResult = validate_for_use(crypto, expired, {root}, CertificateUse::CertificateAuthority);
  EXPECT_EQ(expiredResult.status_code().as_status(), Status::BadCertificateTimeInvalid);

  const auto rootlessResult = validate_for_use(crypto, current, {}, CertificateUse::CertificateAuthority);
  EXPECT_EQ(rootlessResult.status_code().as_status(), Status::BadCertificateChainIncomplete);
}

// The CRL's thisUpdate/nextUpdate window is checked only where revocation is checked, and a
// revocation-unknown suppression lifts it: an out-of-date CRL is refused under CheckRevocationStatusOffline
// (Bad_CertificateRevocationUnknown, CrlTimeInvalid) and accepted with revocation checking off, or with
// SuppressRevocationStatusUnknown added.
// @relation(AC-COMP-CORE-CRYPTO-OPENSSL-VALIDATION-04-CRL-VALIDATION, scope=function)
TEST(CryptoOpenSslCrlValidation, AnOutOfDateCrlIsRefusedOnlyWhereRevocationIsChecked)
{
  const auto crypto = OpenSslBackend::create_crypto();
  TestPki pki{crypto};
  const auto rootKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto root = pki.create_root_ca(rootKeys, "Window Root CA", "8111");
  const auto outOfDate = make_out_of_date_crl(crypto, pki, root, rootKeys);

  const auto checked = validate_crl(crypto,
    outOfDate,
    {root},
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline});
  EXPECT_EQ(checked.status_code().as_status(), Status::BadCertificateRevocationUnknown);
  ASSERT_NE(checked.shared_detail(), nullptr);
  EXPECT_EQ(checked.shared_detail()->code, "CrlTimeInvalid");

  const auto unchecked = validate_crl(crypto, outOfDate, {root});
  EXPECT_TRUE(unchecked.is_good()) << std::hex << unchecked.status_code().as_uint32();

  const auto suppressed = validate_crl(crypto,
    outOfDate,
    {root},
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline,
      TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown});
  EXPECT_TRUE(suppressed.is_good()) << std::hex << suppressed.status_code().as_uint32();
}

namespace
{

std::vector<byte> bytes_of_text(std::string_view text)
{
  std::vector<byte> bytes;
  bytes.reserve(text.size());
  for (char c : text)
    bytes.push_back(static_cast<byte>(c));
  return bytes;
}

std::shared_ptr<const Crypto> crypto_with_credential(std::string_view credential)
{
  return create_default_crypto(
    [secure = ua::SecureString{credential.data(), credential.size()}] { return secure; });
}

std::vector<byte> bytes_of(const ByteString& pem)
{
  std::vector<byte> bytes(pem.size());
  std::memcpy(bytes.data(), pem.data(), pem.size());
  return bytes;
}

}  // namespace

// A key a CertificateManager delivers for a StartNewKeyPairRequest is requested without a password, so it
// arrives unprotected (OPC 10000-12 7.9.5: "If a password was supplied the blob is protected with it"). The
// application's own Crypto reads it with the existing API, whatever its credential, and the loaded key pair
// is then kept under that credential (a test-only P-256 key).
// @relation(AC-CL-PULLCRT-005-A-GDS-GENERATED-KEY-IS-REQUESTED-UNPROTECTED-AND-HELD-UNDER-THE-APPLICATION-CREDENTIAL, scope=function)
TEST(CryptoPemUnprotected, AnUnprotectedKeyIsReadAndKeptUnderTheApplicationCredential)
{
  const std::string& unprotected = ua::test_keys::private_key_pem(ua::test_keys::KeyType::P256, 0);
  const auto application = crypto_with_credential("application");
  auto pem = bytes_of_text(unprotected);
  const auto loaded =
    application->get_private_key_from_pem(CertificateKeyAlgorithm::EccNistP256, span<byte>{pem});
  ASSERT_NE(loaded, nullptr);
  EXPECT_FALSE(loaded->public_key_der().empty());
  auto atRest = bytes_of(loaded->private_key_pem());
  EXPECT_NO_THROW(
    application->get_private_key_from_pem(CertificateKeyAlgorithm::EccNistP256, span<byte>{atRest}))
    << "the loaded key pair is kept under the application's own credential";
  const auto other = crypto_with_credential("someone-else");
  EXPECT_THROW(
    other->get_private_key_from_pem(CertificateKeyAlgorithm::EccNistP256, span<byte>{atRest}), UaException)
    << "control: at rest the key is protected, not left unprotected";
}

// Public API review D7 (API-D7.1, D7.2): the credential callback takes no arguments and returns a
// SecureString, which wipes the passphrase when it goes; the provider asks for it each time it encrypts or
// decrypts the key.
static_assert(std::is_same_v<Crypto::PrivateKeyCredentialCallback, std::function<SecureString()>>);

TEST(CryptoCredentialCallback, ThePassphraseIsAskedForAsASecureStringEachTimeTheKeyIsProtectedOrRead)
{
  auto calls = std::make_shared<std::atomic<int>>(0);
  const auto crypto = create_default_crypto(
    [calls]
    {
      calls->fetch_add(1);
      return SecureString{"d7-passphrase"};
    });
  const auto keys =
    crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  ASSERT_NE(keys, nullptr);
  const int afterGeneration = calls->load();
  EXPECT_GE(afterGeneration, 1) << "the generated key is protected at rest with the passphrase";

  auto atRest = bytes_of(keys->private_key_pem());
  const auto reloaded =
    crypto->get_private_key_from_pem(CertificateKeyAlgorithm::EccNistP256, span<byte>{atRest});
  ASSERT_NE(reloaded, nullptr);
  EXPECT_GT(calls->load(), afterGeneration) << "reading the key asks for the passphrase again";

  const auto other = create_default_crypto([] { return SecureString{"not-the-passphrase"}; });
  EXPECT_THROW(
    other->get_private_key_from_pem(CertificateKeyAlgorithm::EccNistP256, span<byte>{atRest}), UaException)
    << "control: another passphrase cannot read the key";
}

// Part 6 section 6.2.2 Table 43 requires keyCertSign for self-signed application certificates.
// This is independent of keeping cA FALSE and omitting pathLength. The operation under test generates
// its own application identity; separate certificate-construction fixtures use the shared key cache.
// @relation(AC-COMP-CRYPTO-APPLICATION-SELF-SIGNED-USAGE, scope=function)
TEST(CryptoSelfSigned, TheApplicationInstanceCertificateIsNotACa)
{
  const auto crypto = crypto_with_credential("application");
  Crypto::SubjectAlternateName names;
  names.uris.push_back("urn:test:self-signed");
  for (const auto type : {CertificateType::RsaMinApplication,
         CertificateType::RsaSha256Application,
         CertificateType::EccNistP256Application,
         CertificateType::EccNistP384Application,
         CertificateType::EccBrainpoolP256r1Application,
         CertificateType::EccBrainpoolP384r1Application,
         CertificateType::EccCurve25519Application,
         CertificateType::EccCurve448Application})
  {
    auto identity = crypto->try_create_self_signed_application_instance_certificate_sync(
      Crypto::Name{.commonName = "Self-signed"},
      DateTime{2050, 1, 1, 0, 0, 0},
      names,
      type,
      (type == CertificateType::RsaSha256Application || type == CertificateType::RsaMinApplication)
        ? std::optional<std::size_t>{2048}
        : std::nullopt);
    ASSERT_TRUE(identity.is_good());
    const auto& certificate = *identity.value().second;
    EXPECT_FALSE(certificate.basic_constraints_ca());
    EXPECT_TRUE(certificate.key_usage_key_cert_sign());
    EXPECT_EQ(certificate.basic_constraints_path_length(), UINT32_MAX) << "no pathLength";
    EXPECT_TRUE(certificate.self_signed());
    EXPECT_TRUE(
      ::ua::detail::check_certificate_usage(certificate, CertificateUse::ApplicationInstance).is_good());
    const auto asCa =
      ::ua::detail::check_certificate_usage(certificate, CertificateUse::CertificateAuthority);
    EXPECT_EQ(asCa.status_code().as_status(), Status::BadCertificateUseNotAllowed);
    ASSERT_NE(asCa.shared_detail(), nullptr);
    EXPECT_EQ(asCa.shared_detail()->code, "CertificateIsNotACa");
  }
}

// --- create_self_signed_application_instance_certificate_async: the codes of its two steps ---
//
// The composition runs on a parked provider so the test answers create_asymmetric_key_pair_async and
// create_certificate_async itself. The key pair is a step the SDK acts on (it signs a certificate with it),
// so only a Good one is used; the certificate is what the call answers, so its code is passed on.

namespace
{

struct ParkedSelfSigned
{
  std::shared_ptr<ua::test_helpers::FakeAsyncCrypto> crypto;
  std::shared_ptr<std::promise<SelfSignedCertResult>> answered;
  std::future<SelfSignedCertResult> answer;
};

ParkedSelfSigned start_parked_self_signed()
{
  ParkedSelfSigned started;
  started.crypto = ua::test_helpers::FakeAsyncCrypto::create();
  started.crypto->set_park_async(true);
  started.answered = std::make_shared<std::promise<SelfSignedCertResult>>();
  started.answer = started.answered->get_future();
  Crypto::Name subject;
  subject.commonName = "Parked Self-Signed";
  Crypto::SubjectAlternateName alternateName;
  alternateName.uris.push_back("urn:test:parked-self-signed");
  started.crypto->create_self_signed_application_instance_certificate_async(std::move(subject),
    UtcTime{2050, 1, 1, 0, 0, 0},
    std::move(alternateName),
    CertificateType::RsaSha256Application,
    2048,
    [answered = started.answered](SelfSignedCertResult result) { answered->set_value(std::move(result)); });
  return started;
}

std::shared_ptr<const Crypto> real_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

}  // namespace

// A key pair answered Uncertain without a key pair is refused: Bad_InternalError, CryptoAnswerUncertain,
// the Uncertain code as the inner status, and no certificate is requested.
TEST(CryptoSelfSignedComposition, AKeyPairAnsweredUncertainWithoutAKeyPairIsRefused)
{
  auto started = start_parked_self_signed();
  ASSERT_EQ(started.crypto->pending_create_asymmetric_key_pair_count(), 1U);
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  started.crypto->complete_pending_create_asymmetric_key_pair(0, KeyPairResult{uncertain});

  ASSERT_EQ(started.answer.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = started.answer.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  EXPECT_EQ(started.crypto->pending_create_certificate_count(), 0U);
}

// The same refusal when the Uncertain answer holds a key pair: the key pair is not used.
TEST(CryptoSelfSignedComposition, AKeyPairAnsweredUncertainHoldingAKeyPairIsRefused)
{
  const auto crypto = real_crypto();
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto started = start_parked_self_signed();
  ASSERT_EQ(started.crypto->pending_create_asymmetric_key_pair_count(), 1U);
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  started.crypto->complete_pending_create_asymmetric_key_pair(0, KeyPairResult{keys, uncertain});

  ASSERT_EQ(started.answer.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = started.answer.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  EXPECT_EQ(started.crypto->pending_create_certificate_count(), 0U);
}

// The certificate's code is the call's code: a Good subcode is kept with the key pair and certificate.
TEST(CryptoSelfSignedComposition, ACertificateCreatedWithAGoodSubcodeKeepsTheSubcode)
{
  const auto crypto = real_crypto();
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  TestPki pki{crypto};
  auto certificate = pki.create_root_ca(keys, "Parked", "11");
  auto started = start_parked_self_signed();
  ASSERT_EQ(started.crypto->pending_create_asymmetric_key_pair_count(), 1U);
  started.crypto->complete_pending_create_asymmetric_key_pair(0, KeyPairResult{keys});
  ASSERT_EQ(started.crypto->pending_create_certificate_count(), 1U);
  const StatusCode goodSubcode{Status::GoodClamped};

  started.crypto->complete_pending_create_certificate(0, CertificateResult{certificate, goodSubcode});

  ASSERT_EQ(started.answer.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = started.answer.get();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), goodSubcode.value());
  ASSERT_NO_THROW((void)result.value());
  EXPECT_EQ(result.value().first, keys);
  EXPECT_EQ(result.value().second, certificate);
}

// An Uncertain certificate is passed on as Uncertain, with the key pair and certificate.
TEST(CryptoSelfSignedComposition, ACertificateCreatedUncertainIsAnsweredUncertainWithIt)
{
  const auto crypto = real_crypto();
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  TestPki pki{crypto};
  auto certificate = pki.create_root_ca(keys, "Parked", "12");
  auto started = start_parked_self_signed();
  ASSERT_EQ(started.crypto->pending_create_asymmetric_key_pair_count(), 1U);
  started.crypto->complete_pending_create_asymmetric_key_pair(0, KeyPairResult{keys});
  ASSERT_EQ(started.crypto->pending_create_certificate_count(), 1U);
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  started.crypto->complete_pending_create_certificate(0, CertificateResult{certificate, uncertain});

  ASSERT_EQ(started.answer.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = started.answer.get();
  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), uncertain.value());
  ASSERT_NO_THROW((void)result.value());
  EXPECT_EQ(result.value().second, certificate);
}

// @relation(AC-COMP-CRYPTO-APPLICATION-SELF-SIGNED-USAGE, scope=function)
TEST(CryptoSelfSigned, NonCaCertificateSigningUsageRequiresAnActualSelfSignature)
{
  const auto crypto = crypto_with_credential("application");
  const auto keys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys = keys;
  parameters.subject.commonName = "Self-signed application";
  parameters.subject.organization = "Test";
  parameters.serialNumber = "8801";
  parameters.from = DateTime::now();
  parameters.to = DateTime{parameters.from.value() + std::chrono::days{1}};
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.basicConstraint.cA = false;
  parameters.keyUsage.digitalSignature = parameters.keyUsage.keyCertSign = true;
  const auto created = test_helpers::run_async_callback_sync<CertificateResult>(
    [&](auto complete) { crypto->create_certificate_async(parameters, std::move(complete)); });
  ASSERT_TRUE(created.is_good());
  EXPECT_TRUE(created.value()->self_signed());
  EXPECT_TRUE(created.value()->key_usage_key_cert_sign());
  EXPECT_FALSE(created.value()->basic_constraints_ca());

  // Distinct handles carrying the same key must work: pointer identity is not a cryptographic proof.
  const auto& privateKeyText = test_keys::private_key_pem(test_keys::KeyType::Rsa2048, 0);
  std::vector<byte> privateKeyBytes;
  for (const auto character : privateKeyText)
    privateKeyBytes.push_back(static_cast<byte>(character));
  parameters.issuerKeys =
    crypto->get_private_key_from_pem(CertificateKeyAlgorithm::Rsa, span<byte>{privateKeyBytes});
  EXPECT_TRUE(test_helpers::run_async_callback_sync<CertificateResult>(
    [&](auto complete) {
      crypto->create_certificate_async(parameters, std::move(complete));
    }).is_good());
  parameters.issuerKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 1);
  const auto differentlySigned = test_helpers::run_async_callback_sync<CertificateResult>(
    [&](auto complete) { crypto->create_certificate_async(parameters, std::move(complete)); });
  ASSERT_TRUE(differentlySigned.is_bad());
  EXPECT_EQ(differentlySigned.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(differentlySigned.shared_detail(), nullptr);
  EXPECT_EQ(differentlySigned.shared_detail()->code, "CertificateError");

  parameters.issuerKeys = keys;
  parameters.issuer = created.value();
  parameters.subject.commonName = "Different subject";
  const auto issued = test_helpers::run_async_callback_sync<CertificateResult>(
    [&](auto complete) { crypto->create_certificate_async(parameters, std::move(complete)); });
  ASSERT_TRUE(issued.is_bad());
  EXPECT_EQ(issued.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(issued.shared_detail(), nullptr);
  EXPECT_EQ(issued.shared_detail()->code, "CertificateError");
}

// @relation(AC-COMP-CRYPTO-APPLICATION-SELF-SIGNED-USAGE, scope=function)
TEST(CryptoSelfSigned, NonCaSigningUsageCannotOmitConstraintsOrRequestAPathLength)
{
  const auto crypto = crypto_with_credential("application");
  const auto keys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  Crypto::CreateCertificateConfig parameters;
  parameters.subjectKeys = parameters.issuerKeys = keys;
  parameters.subject.commonName = "Self-signed application";
  parameters.serialNumber = "8802";
  parameters.from = DateTime::now();
  parameters.to = DateTime{parameters.from.value() + std::chrono::days{1}};
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.keyUsage.digitalSignature = parameters.keyUsage.keyCertSign = true;
  for (const auto withPathLength : {false, true})
  {
    if (withPathLength)
    {
      parameters.basicConstraint.cA = false;
      parameters.basicConstraint.pathLength = 0;
    }
    const auto rejected = test_helpers::run_async_callback_sync<CertificateResult>(
      [&](auto complete) { crypto->create_certificate_async(parameters, std::move(complete)); });
    ASSERT_TRUE(rejected.is_bad());
    EXPECT_EQ(rejected.status_code().as_status(), Status::BadInvalidArgument);
    ASSERT_NE(rejected.shared_detail(), nullptr);
    EXPECT_EQ(rejected.shared_detail()->code, "CertificateError");
  }
}

// A CSR has not been issued as a self-signed certificate; the creation allowance does not apply.
// @relation(AC-COMP-CRYPTO-APPLICATION-SELF-SIGNED-USAGE, scope=function)
TEST(CryptoSelfSigned, NonCaCsrCannotRequestCertificateSigningAuthorityOrAPathLength)
{
  const auto crypto = crypto_with_credential("application");
  Crypto::CreateCsrConfig parameters;
  parameters.subjectKeys = test_keys::key_pair(*crypto, test_keys::KeyType::Rsa2048, 0);
  parameters.subject.commonName = "Application request";
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.keyUsage.digitalSignature = true;
  parameters.basicConstraint.cA = false;
  const auto create = [&]
  {
    return test_helpers::run_async_callback_sync<ByteStringResult>([&](auto complete)
      { crypto->create_certificate_signing_request_async(parameters, std::move(complete)); });
  };
  EXPECT_TRUE(create().is_good()) << "ordinary non-CA CSR";
  for (const auto signingAuthority : {true, false})
  {
    parameters.keyUsage.keyCertSign = signingAuthority;
    parameters.basicConstraint.pathLength = signingAuthority ? std::nullopt : std::optional<uint32_t>{0};
    const auto rejected = create();
    ASSERT_TRUE(rejected.is_bad());
    EXPECT_EQ(rejected.status_code().as_status(), Status::BadInvalidArgument);
    ASSERT_NE(rejected.shared_detail(), nullptr);
    EXPECT_EQ(rejected.shared_detail()->code, "CertificateError");
  }
  parameters.basicConstraint.cA = true;
  parameters.basicConstraint.pathLength = 0;
  parameters.keyUsage.keyCertSign = true;
  EXPECT_TRUE(create().is_good()) << "ordinary CA CSR remains permitted";
}
