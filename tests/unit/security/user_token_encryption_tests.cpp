// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <future>
#include <thread>

#include "ua_crypto.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_sec_pol_aes128_sha256_rsa_oaep.h"
#include "ua_sec_pol_aes256_sha256_rsa_pss.h"
#include "ua_sec_pol_basic128_rsa15.h"
#include "ua_sec_pol_basic256.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_sec_pol_none.h"
#include "ua_security_policy.h"
#include "ua_security_policy_compatibility.h"
#include "ua_to_string.h"
#include "ua_user_name_identity_token.h"
#include "ua_user_token_encryption.h"
#include "ua_x509_certificate.h"
#include "fake_async_crypto.h"
#include "run_async_sync.h"
#include "test_pki_helpers.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

namespace
{
// The strand a bound channel always carries. These entry points marshal every continuation onto it -
// they no longer accept not having one - so the pool has to be running for the blocking helpers
// below to ever see an answer.
boost::asio::strand<boost::asio::any_io_executor> crypto_test_strand()
{
  static boost::asio::thread_pool pool{2};
  return boost::asio::make_strand(boost::asio::any_io_executor{pool.get_executor()});
}
}  // namespace

using namespace ua;

namespace
{

std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

ByteString make_password(string_view text)
{
  ByteString bs;
  bs.assign(reinterpret_cast<const uint8_t*>(text.data()),
    reinterpret_cast<const uint8_t*>(text.data()) + text.size());
  return bs;
}

ByteString make_nonce(const Crypto& crypto, size_t size)
{
  ByteString nonce;
  nonce.resize(size);
  auto entropy = crypto.get_entropy_sync(size);
  std::memcpy(nonce.data(), entropy.data(), size);
  return nonce;
}

}  // namespace

// ===== SecurityPolicy::None tests =============================================

TEST(UserTokenEncryptionNone, NoPolicyIsNoOp)
{
  auto crypto = create_crypto();
  auto policyPtr = std::make_shared<SecPolNone>();

  auto token = std::make_shared<UserNameIdentityToken>();
  auto originalPassword = make_password("TestPassword123!");
  token->password() = originalPassword;

  ByteString nonce = make_nonce(*crypto, 32);

  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policyPtr,
        crypto,
        crypto_test_strand(),
        token,
        nonce,
        nullptr,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());

  // SecPolNone is neither RSA nor ECC, so the password should remain unchanged.
  EXPECT_EQ(token->password(), originalPassword);
  EXPECT_TRUE(token->encryption_algorithm().empty());
}

TEST(UserTokenEncryptionNone, EmptyPasswordIsNoOp)
{
  auto crypto = create_crypto();
  auto policyPtr = std::make_shared<SecPolNone>();

  auto token = std::make_shared<UserNameIdentityToken>();
  // password is empty by default

  ByteString nonce = make_nonce(*crypto, 32);

  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policyPtr,
        crypto,
        crypto_test_strand(),
        token,
        nonce,
        nullptr,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());
  EXPECT_TRUE(token->password().empty());
}

// ===== RSA parameterized tests ================================================

struct RsaPolicyTestParams
{
  std::function<std::shared_ptr<SecurityPolicy>()> createPolicy;
  size_t keyBits;
  CertificateSignatureAlgorithm certSigAlg;
  std::string name;
  /// Blocks of the longest legacy secret (Length || 64-byte password || 128-byte nonce = 196 bytes) under
  /// this policy and key size, counted by hand from the policy's padding: OAEP-SHA1 leaves 214 bytes of a
  /// 2048-bit block, OAEP-SHA256 190, PKCS#1 v1.5 117 of a 1024-bit block.
  size_t longestLegacySecretBlocks{1};
};

class UserTokenEncryptionRsaTests : public ::testing::TestWithParam<RsaPolicyTestParams>
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    const auto& params = GetParam();
    mPolicy = params.createPolicy();

    // Generate RSA key pair for the server
    mServerKeyPair = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, params.keyBits);

    // Create self-signed server certificate
    TestPki pki{create_crypto()};
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = mServerKeyPair;
    certParams.issuerKeys = mServerKeyPair;
    certParams.subject.commonName = "TestServer";
    certParams.serialNumber = "1";
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.keyUsage.keyEncipherment = true;
    certParams.certificateSignatureAlgorithm = params.certSigAlg;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    mServerCert = pki.create_cert(certParams);
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecurityPolicy> mPolicy;
  shared_ptr<const AsymmetricKeyPair> mServerKeyPair;
  shared_ptr<const X509Certificate> mServerCert;
};

// Part 4 v1.05.07 section 7.40.4 selects RSA username framing by UTF-8
// password length, independently of policy deprecation. Test both sides of
// the 64-byte boundary and verify the algorithm URI and recovered nonce/secret.
// @verifies CL-IDENT-005
// @relation(CL-IDENT-005, scope=function)
TEST_P(UserTokenEncryptionRsaTests, RoundTripEncryptDecrypt)
{
  for (const size_t passwordLength : {1u, 64u, 65u, 128u})
  {
    SCOPED_TRACE(passwordLength);
    const std::string passwordText(passwordLength, 'p');
    auto originalPassword = make_password(passwordText);
    auto serverNonce = make_nonce(*mCrypto, 32);

    auto token = std::make_shared<UserNameIdentityToken>();
    token->password() = originalPassword;

    // Encrypt
    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(mPolicy,
          mCrypto,
          crypto_test_strand(),
          token,
          serverNonce,
          mServerCert,
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });

    ASSERT_TRUE(encResult.is_good()) << "Encrypt status: " << to_string(encResult.status_code().as_status());

    // Verify password was changed
    EXPECT_NE(token->password(), originalPassword);
    EXPECT_FALSE(token->password().empty());
    EXPECT_EQ(std::string_view{token->encryption_algorithm()},
      asymmetric_encryption_algorithm_uri(mPolicy->asymmetric_encryption_algorithm()));

    if (passwordLength <= 64)
    {
      // Legacy section 7.41.2.2: the whole `Length(4 LE) || password || serverNonce` is RSA-encrypted.
      EXPECT_FALSE(is_rsa_encrypted_secret(span<const byte>{token->password()}))
        << "RSA passwords of at most 64 bytes require the legacy form";

      ByteString plainText;
      plainText.resize(token->password().size());

      auto decSpan = mCrypto->asymmetric_decrypt_sync(mPolicy->asymmetric_encryption_algorithm(),
        mServerKeyPair,
        span<const byte>{token->password()},
        span<byte>{plainText});

      auto expectedSize = 4u + originalPassword.size() + serverNonce.size();
      ASSERT_EQ(decSpan.size(), expectedSize);

      auto recovered = parse_legacy_encrypted_token_secret(decSpan, span<const byte>{serverNonce});
      ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
      EXPECT_EQ(recovered.value(), originalPassword);
    }
    else
    {
      // Modern section 7.41.2.4: the secret is an RsaEncryptedSecret ExtensionObject. Its TypeId prefix is
      // cleartext, so the server can detect it, and the decoder recovers the Nonce + Secret.
      ASSERT_TRUE(is_rsa_encrypted_secret(span<const byte>{token->password()}))
        << "RSA passwords over 64 bytes require RsaEncryptedSecret";

      auto decResult = ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
        [&](auto cb)
        {
          decrypt_rsa_encrypted_secret_async(token->password(),
            mPolicy,
            mCrypto,
            crypto_test_strand(),
            mServerKeyPair,
            mServerCert,
            false,
            ua::Logger{},
            std::move(cb));
        });

      ASSERT_TRUE(decResult.is_good()) << to_string(decResult.status_code().as_status());
      const auto& fields = decResult.value();
      EXPECT_EQ(fields.secret, originalPassword);
      EXPECT_EQ(fields.nonce, serverNonce);
      EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
    }
  }
}

TEST_P(UserTokenEncryptionRsaTests, EmptyPasswordIsNoOp)
{
  auto token = std::make_shared<UserNameIdentityToken>();
  // password is empty by default

  auto serverNonce = make_nonce(*mCrypto, 32);

  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        token,
        serverNonce,
        mServerCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());
  EXPECT_TRUE(token->password().empty());
}

// The token carries a ciphertext only after a Good crypto answer. The provider is parked so the test answers
// the first crypto step itself - the asymmetric encrypt of the legacy form, which a password of at most 64
// bytes takes, or the entropy of the RsaEncryptedSecret form, which a longer one takes (OPC 10000-4 7.40.4):
// an Uncertain answer is refused with Bad_InternalError, the CryptoAnswerUncertain ErrorDetail and the
// Uncertain code as its inner status, and the password is left as it was.
TEST_P(UserTokenEncryptionRsaTests, AnUncertainCryptoAnswerIsRefused)
{
  for (const bool legacy : {true, false})
  {
    SCOPED_TRACE(legacy ? "the legacy form" : "the RsaEncryptedSecret form");
    auto parked = ua::test_helpers::FakeAsyncCrypto::create();
    parked->set_park_async(true);
    const auto originalPassword =
      make_password(legacy ? std::string{"MySecurePassword!"} : std::string(72, 'p'));
    auto token = std::make_shared<UserNameIdentityToken>();
    token->password() = originalPassword;
    const StatusCode uncertain{Status::UncertainLastUsableValue};

    auto answered = std::make_shared<std::promise<VoidResult>>();
    auto future = answered->get_future();
    encrypt_user_token_async(mPolicy,
      parked,
      crypto_test_strand(),
      token,
      make_nonce(*mCrypto, 32),
      mServerCert,
      ByteString{},
      nullptr,
      nullptr,
      ua::Logger{},
      [answered](VoidResult result) { answered->set_value(std::move(result)); });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (parked->pending_asymmetric_encrypt_count() + parked->pending_get_entropy_count() == 0 &&
           std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    if (legacy)
    {
      ASSERT_EQ(parked->pending_asymmetric_encrypt_count(), 1U) << "the legacy encrypt was not issued";
      parked->complete_pending_asymmetric_encrypt(0, VoidResult{uncertain});
    }
    else
    {
      ASSERT_EQ(parked->pending_get_entropy_count(), 1U)
        << "the RsaEncryptedSecret entropy was not requested";
      parked->complete_pending_get_entropy(0, ByteStringResult{uncertain});
    }
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "the encrypt did not answer";
    const auto result = future.get();

    EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
    ASSERT_NE(result.error_detail(), nullptr);
    EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
    EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
    EXPECT_EQ(token->password(), originalPassword);
  }
}

// OPC 10000-4 7.40.4 allows a 64-byte password in the legacy format and 5.7.2 a 128-byte serverNonce, so
// the plaintext Length || password || serverNonce is 196 bytes: more than one RSA block under RSA-OAEP-SHA256
// with a 2048-bit key (190 bytes) and under PKCS#1 v1.5 with a 1024-bit key (117) - the Basic128Rsa15 and
// Aes256Sha256RsaPss2048 rows. OPC 10000-6 6.7.2 encrypts block by block. The secret is decrypted here block
// by block, independently of the SDK's decoder.
// @relation(AC-CL-IDENT-005-LEGACY-SECRET-SPANS-RSA-BLOCKS, scope=function)
TEST_P(UserTokenEncryptionRsaTests, TheLongestLegacySecretRoundTripsBlockByBlock)
{
  const auto originalPassword = make_password(std::string(64, 'p'));
  const auto serverNonce = make_nonce(*mCrypto, 128);
  auto token = std::make_shared<UserNameIdentityToken>();
  token->password() = originalPassword;

  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        token,
        serverNonce,
        mServerCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encResult.is_good()) << "Encrypt status: " << to_string(encResult.status_code().as_status());
  ASSERT_FALSE(is_rsa_encrypted_secret(span<const byte>{token->password()}))
    << "a 64-byte password keeps the legacy form";

  const size_t plainBlockSize = mPolicy->asymmetric_plaintext_block_size(mServerCert.get());
  const size_t cipherBlockSize = mPolicy->asymmetric_ciphertext_block_size(mServerCert.get());
  const size_t plainSize = 4 + originalPassword.size() + serverNonce.size();
  const size_t blocks = (plainSize + plainBlockSize - 1) / plainBlockSize;
  ASSERT_EQ(blocks, GetParam().longestLegacySecretBlocks) << "the row's hand-counted block count";
  ASSERT_EQ(token->password().size(), blocks * cipherBlockSize) << "one ciphertext block per plaintext block";

  std::vector<byte> plainText;
  const span<const byte> cipherText{token->password()};
  for (size_t block = 0; block < blocks; ++block)
  {
    ByteString decrypted;
    decrypted.resize(cipherBlockSize);
    const auto decSpan = mCrypto->asymmetric_decrypt_sync(mPolicy->asymmetric_encryption_algorithm(),
      mServerKeyPair,
      cipherText.subspan(block * cipherBlockSize, cipherBlockSize),
      span<byte>{decrypted});
    plainText.insert(plainText.end(), decSpan.begin(), decSpan.end());
  }
  ASSERT_EQ(plainText.size(), plainSize);
  const auto recovered =
    parse_legacy_encrypted_token_secret(span<const byte>{plainText}, span<const byte>{serverNonce});
  ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
  EXPECT_EQ(recovered.value(), originalPassword);
}

// The legacy secret decryption on its own, with a 2048-bit server key under Aes256Sha256RsaPss:
// RSA-OAEP-SHA256, 190 plaintext and 256 ciphertext bytes per block, so the longest legacy secret (196 bytes)
// is two blocks.
class LegacyTokenSecretDecryption : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPolicy = std::make_shared<SecPolAes256Sha256RsaPss>();
    mKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    TestPki pki{create_crypto()};
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = mKeys;
    certParams.issuerKeys = mKeys;
    certParams.subject.commonName = "TestServer";
    certParams.serialNumber = "1";
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.keyUsage.keyEncipherment = true;
    certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    mCert = pki.create_cert(certParams);
    mPlainBlock = mPolicy->asymmetric_plaintext_block_size(mCert.get());
    mCipherBlock = mPolicy->asymmetric_ciphertext_block_size(mCert.get());
  }

  /// @p plainText encrypted block by block with the certificate's public key.
  ByteString encrypt_blocks(const ByteString& plainText) const
  {
    const size_t blocks = (plainText.size() + mPlainBlock - 1) / mPlainBlock;
    ByteString cipherText;
    cipherText.resize(blocks * mCipherBlock);
    const ByteString publicKey = mCert->public_key();
    const span<const byte> plain{plainText};
    for (size_t block = 0; block < blocks; ++block)
    {
      const size_t offset = block * mPlainBlock;
      mCrypto->asymmetric_encrypt_sync(mPolicy->asymmetric_encryption_algorithm(),
        span<const byte>{publicKey},
        plain.subspan(offset, std::min(mPlainBlock, plain.size() - offset)),
        span<byte>{cipherText}.subspan(block * mCipherBlock, mCipherBlock));
    }
    return cipherText;
  }

  Result<span<const byte>> decrypt(const ByteString& cipherText, ByteString& plainText) const
  {
    return ua::test_helpers::run_async_function_sync<Result<span<const byte>>>(
      [&](auto cb)
      {
        decrypt_legacy_token_secret_async(mPolicy,
          mCrypto,
          crypto_test_strand(),
          mKeys,
          mPlainBlock,
          mCipherBlock,
          span<const byte>{cipherText},
          span<byte>{plainText},
          ua::Logger{},
          std::move(cb));
      });
  }

  static bool names_the_block_refusal(const Result<span<const byte>>& result)
  {
    return result.shared_detail() != nullptr &&
           to_string(*result.shared_detail()).find("LegacySecretBlocksInvalid") != std::string::npos;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecurityPolicy> mPolicy;
  shared_ptr<const AsymmetricKeyPair> mKeys;
  shared_ptr<const X509Certificate> mCert;
  size_t mPlainBlock{0};
  size_t mCipherBlock{0};
};

// Anyone can make valid blocks with the server's public key, so a secret of more blocks than the longest
// legacy secret needs is refused by its size, before any private-key operation: the refusal is the size
// check's (LegacySecretBlocksInvalid), not a decryption or parse failure.
// @relation(AC-SVR-IDENT-008-LEGACY-SECRET-BLOCKS-ARE-BOUNDED, scope=function)
TEST_F(LegacyTokenSecretDecryption, MoreBlocksThanTheLongestLegacySecretNeedsAreRefusedBeforeAnyDecryption)
{
  ASSERT_EQ(mPlainBlock, 190u);
  ASSERT_EQ(mCipherBlock, 256u);
  const ByteString threeBlocks = encrypt_blocks(ByteString(3 * mPlainBlock, uint8_t{0}));
  ByteString plainText(threeBlocks.size(), uint8_t{0});

  const auto result = decrypt(threeBlocks, plainText);

  ASSERT_TRUE(result.is_bad()) << "three valid blocks were decrypted";
  EXPECT_EQ(result.status_code().as_status(), Status::BadDecodingError);
  EXPECT_TRUE(names_the_block_refusal(result)) << to_string(result.status_code().as_status());
}

// @relation(AC-SVR-IDENT-008-LEGACY-SECRET-BLOCKS-ARE-BOUNDED, scope=function)
TEST_F(LegacyTokenSecretDecryption, ASecretThatIsNotAWholeNumberOfBlocksIsRefused)
{
  ByteString oneAndAHalfBlocks = encrypt_blocks(ByteString(mPlainBlock, uint8_t{0}));
  for (size_t i = 0; i < mCipherBlock / 2; ++i)
    oneAndAHalfBlocks.push_back(uint8_t{0x5A});
  ByteString plainText(oneAndAHalfBlocks.size(), uint8_t{0});

  const auto result = decrypt(oneAndAHalfBlocks, plainText);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadDecodingError);
  EXPECT_TRUE(names_the_block_refusal(result));
}

// A valid first block followed by one that does not decrypt: the secret is refused, and the first block's
// plaintext - the start of the password - does not stay in the caller's buffer (DEF-4).
// @relation(AC-SVR-IDENT-008-LEGACY-SECRET-BLOCKS-ARE-BOUNDED, scope=function)
TEST_F(LegacyTokenSecretDecryption, AFailingSecondBlockIsRefusedAndTheFirstBlockIsZeroed)
{
  ByteString cipherText = encrypt_blocks(ByteString(mPlainBlock, uint8_t{'A'}));
  for (size_t i = 0; i < mCipherBlock; ++i)
    cipherText.push_back(uint8_t{0x5A});
  ByteString plainText(cipherText.size(), uint8_t{0});

  const auto result = decrypt(cipherText, plainText);

  ASSERT_TRUE(result.is_bad()) << "a secret whose second block does not decrypt was accepted";
  EXPECT_FALSE(names_the_block_refusal(result)) << "the refusal must come from the second block's decryption";
  const span<const byte> firstBlock = span<const byte>{plainText}.first(mPlainBlock);
  EXPECT_TRUE(std::ranges::all_of(firstBlock, [](byte b) { return b == byte{0}; }))
    << "the recovered first block was left in the buffer";
}

// A block the Crypto provider answers Uncertain is not used, with or without a plaintext: the secret is
// refused with Bad_InternalError and the CryptoAnswerUncertain ErrorDetail whose inner status is the
// Uncertain code, and the block recovered before it - the start of the password - does not stay in the
// caller's buffer (DEF-4).
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(LegacyTokenSecretDecryption, AnUncertainBlockAnswerIsRefusedAndTheFirstBlockIsZeroed)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const ByteString cipherText = encrypt_blocks(ByteString(mPlainBlock + 6, uint8_t{'A'}));
  ASSERT_EQ(cipherText.size(), 2 * mCipherBlock);
  for (const bool withPlainText : {false, true})
  {
    SCOPED_TRACE(withPlainText ? "the answer holds a plaintext" : "the answer holds no plaintext");
    auto parked = ua::test_helpers::FakeAsyncCrypto::create();
    parked->set_park_async(true);
    ByteString plainText(cipherText.size(), uint8_t{0});
    const ByteString held(6, uint8_t{'B'});
    auto answered = std::make_shared<std::promise<Result<span<const byte>>>>();
    auto future = answered->get_future();
    decrypt_legacy_token_secret_async(mPolicy,
      parked,
      crypto_test_strand(),
      mKeys,
      mPlainBlock,
      mCipherBlock,
      span<const byte>{cipherText},
      span<byte>{plainText},
      ua::Logger{},
      [answered](Result<span<const byte>> result) { answered->set_value(std::move(result)); });

    const auto waitForBlock = [&parked]
    {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
      while (parked->pending_asymmetric_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
      return parked->pending_asymmetric_decrypt_count() == 1;
    };
    ASSERT_TRUE(waitForBlock()) << "the first block was not decrypted";
    parked->complete_pending_asymmetric_decrypt_with_fill(0, byte{'A'}, mPlainBlock);
    ASSERT_TRUE(waitForBlock()) << "the second block was not decrypted";
    parked->complete_pending_asymmetric_decrypt(0,
      withPlainText ? Crypto::ByteSpanResult{span<const byte>{held}, uncertain}
                    : Crypto::ByteSpanResult{uncertain});

    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "the decryption did not answer";
    const auto result = future.get();
    EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError)
      << to_string(result.status_code().as_status());
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "CryptoAnswerUncertain");
    EXPECT_EQ(result.shared_detail()->innerStatus, uncertain.value());
    const span<const byte> firstBlock = span<const byte>{plainText}.first(mPlainBlock);
    EXPECT_TRUE(std::ranges::all_of(firstBlock, [](byte b) { return b == byte{0}; }))
      << "the recovered first block was left in the buffer";
  }
}

INSTANTIATE_TEST_SUITE_P(UserTokenEncryptionRsaPolicies, UserTokenEncryptionRsaTests,
  ::testing::Values(RsaPolicyTestParams{[] { return std::make_shared<SecPolBasic128Rsa15>(); },
                      1024,
                      CertificateSignatureAlgorithm::RsaPkcs15Sha1,
                      "Basic128Rsa15",
                      2},
    RsaPolicyTestParams{[] { return std::make_shared<SecPolBasic256>(); },
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Basic256"},
    RsaPolicyTestParams{[] { return std::make_shared<SecPolBasic256Sha256>(); },
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Basic256Sha256"},
    RsaPolicyTestParams{[] { return std::make_shared<SecPolAes128Sha256RsaOaep>(); },
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Aes128Sha256RsaOaep"},
    RsaPolicyTestParams{[] { return std::make_shared<SecPolAes256Sha256RsaPss>(); },
      4096,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Aes256Sha256RsaPss"},
    // The common key size of RSA-OAEP-SHA256: 190 plaintext bytes per block, so the longest legacy secret
    // spans two blocks.
    RsaPolicyTestParams{[] { return std::make_shared<SecPolAes256Sha256RsaPss>(); },
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Aes256Sha256RsaPss2048",
      2}),
  [](const ::testing::TestParamInfo<RsaPolicyTestParams>& info) { return info.param.name; });

// ===== ECC parameterized tests ================================================

struct EccTokenTestParams
{
  std::function<std::shared_ptr<SecurityPolicy>()> createPolicy;
  CertificateKeyAlgorithm certKeyAlg;
  EphemeralKeyAlgorithm ephKeyAlg;
  CertificateSignatureAlgorithm certSigAlg;
  std::string name;
  std::optional<size_t> certKeyBits{};  // the RSA modulus size; unset for the ECC curves
};

class UserTokenEncryptionEccTests : public ::testing::TestWithParam<EccTokenTestParams>
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    const auto& params = GetParam();
    mPolicy = params.createPolicy();

    // Generate client ECC key pair and cert
    mClientKeyPair = mCrypto->create_asymmetric_key_pair_sync(params.certKeyAlg, params.certKeyBits);

    TestPki pki{create_crypto()};
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = mClientKeyPair;
    certParams.issuerKeys = mClientKeyPair;
    certParams.subject.commonName = "TestClient";
    certParams.serialNumber = "1";
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.certificateSignatureAlgorithm = params.certSigAlg;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    mClientCert = pki.create_cert(certParams);

    // Generate ephemeral key pairs for server
    mServerEphemeral = mCrypto->create_ephemeral_keys_sync(params.ephKeyAlg);
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecurityPolicy> mPolicy;
  shared_ptr<const AsymmetricKeyPair> mClientKeyPair;
  shared_ptr<const X509Certificate> mClientCert;
  Crypto::EphemeralKeyPair mServerEphemeral;
};

// Exercises the ECC EccEncryptedSecret format the client emits via encrypt_user_token_async for an ECC
// policy: the blob carries the common header + KeyData (sender/receiver ephemeral public keys) and an
// encrypted payload, and decodes back to the original nonce + secret. This is the ECC half of
// CL-IDENT-005 (UNP2 EccEncryptedSecret format per policy), asserting the format fields explicitly.
// @verifies CL-IDENT-005
// @relation(CL-IDENT-005, scope=function)
TEST_P(UserTokenEncryptionEccTests, RoundTripEncryptDecrypt)
{
  constexpr string_view passwordText = "EccTestPassword!";
  auto originalPassword = make_password(passwordText);
  auto serverNonce = make_nonce(*mCrypto, 32);

  auto token = std::make_shared<UserNameIdentityToken>();
  token->password() = originalPassword;

  // Encrypt
  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        token,
        serverNonce,
        nullptr,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        mClientKeyPair,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(encResult.is_good()) << "Encrypt status: " << to_string(encResult.status_code().as_status());

  // Verify password was changed (now an EccEncryptedSecret blob)
  EXPECT_NE(token->password(), originalPassword);
  EXPECT_FALSE(token->password().empty());
  EXPECT_EQ(token->encryption_algorithm(), mPolicy->uri());

  // Decrypt using the ECC decoder
  std::shared_ptr<const SecPolEphemeralKey> eccPolicyPtr{
    mPolicy, &dynamic_cast<const SecPolEphemeralKey&>(*mPolicy)};
  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{token->password()},
        eccPolicyPtr,
        mCrypto,
        crypto_test_strand(),
        mServerEphemeral.privateKey,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(decryptResult.is_good())
    << "Decrypt status: " << to_string(decryptResult.status_code().as_status()) << '\n'
    << (decryptResult.shared_detail() ? ua::to_string(*decryptResult.shared_detail()) : "no ErrorDetail");

  auto& fields = decryptResult.value();
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.certificate, mClientCert->der_encoding());
  EXPECT_EQ(fields.receiverPublicKey, mServerEphemeral.publicKey);
  EXPECT_EQ(fields.nonce, serverNonce);
  EXPECT_EQ(fields.secret, originalPassword);
}

INSTANTIATE_TEST_SUITE_P(UserTokenEncryptionEccPolicies, UserTokenEncryptionEccTests,
  ::testing::Values(EccTokenTestParams{[]
                      {
                        return std::make_shared<SecPolEphemeralKey>(
                          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
                      },
                      CertificateKeyAlgorithm::EccNistP256,
                      EphemeralKeyAlgorithm::EccNistP256,
                      CertificateSignatureAlgorithm::EcDsaSha2256,
                      "EccNistP256"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384AesGcm));
      },
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      "EccNistP384"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
      },
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      "EccNistP256WithP384SenderCertificate"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1AesGcm));
      },
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      "EccBrainpoolP256r1"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1AesGcm));
      },
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      "EccBrainpoolP384r1"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve25519ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccCurve25519,
      EphemeralKeyAlgorithm::EccCurve25519,
      CertificateSignatureAlgorithm::PureEdDsa25519,
      "EccCurve25519ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve448ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccCurve448,
      EphemeralKeyAlgorithm::EccCurve448,
      CertificateSignatureAlgorithm::PureEdDsa448,
      "EccCurve448ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccNistP256,
      EphemeralKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      "EccNistP256ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      "EccNistP384ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      "EccBrainpoolP256r1ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly));
      },
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      "EccBrainpoolP384r1ChaChaPoly"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve25519AesGcm));
      },
      CertificateKeyAlgorithm::EccCurve25519,
      EphemeralKeyAlgorithm::EccCurve25519,
      CertificateSignatureAlgorithm::PureEdDsa25519,
      "EccCurve25519AesGcm"},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve448AesGcm));
      },
      CertificateKeyAlgorithm::EccCurve448,
      EphemeralKeyAlgorithm::EccCurve448,
      CertificateSignatureAlgorithm::PureEdDsa448,
      "EccCurve448AesGcm"},
    EccTokenTestParams{[] {
                         return std::make_shared<SecPolEphemeralKey>(
                           *find_ephemeral_key_policy(SecurityPolicyId::RsaDhAesGcm));
                       },
      CertificateKeyAlgorithm::Rsa,
      EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "RsaDhAesGcm",
      2048},
    EccTokenTestParams{[]
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::RsaDhChaChaPoly));
      },
      CertificateKeyAlgorithm::Rsa,
      EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "RsaDhChaChaPoly",
      2048}),
  [](const ::testing::TestParamInfo<EccTokenTestParams>& info) { return info.param.name; });

TEST(UserTokenEncryptionEcc, EccMissingEphemeralKeyFails)
{
  auto crypto = create_crypto();
  auto policyPtr =
    std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));

  auto clientKeyPair =
    crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = clientKeyPair;
  certParams.issuerKeys = clientKeyPair;
  certParams.subject.commonName = "TestClient";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto clientCert = pki.create_cert(certParams);

  auto originalPassword = make_password("SomePassword");
  auto serverNonce = make_nonce(*crypto, 32);

  auto token = std::make_shared<UserNameIdentityToken>();
  token->password() = originalPassword;

  // Pass empty ephemeral key -- should fail
  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policyPtr,
        crypto,
        crypto_test_strand(),
        token,
        serverNonce,
        nullptr,
        ByteString{},
        clientCert,
        clientKeyPair,
        ua::Logger{},
        std::move(cb));
    });

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
}

TEST(UserTokenEncryptionEcc, EmptyPasswordIsNoOp)
{
  auto crypto = create_crypto();
  auto policyPtr =
    std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));

  auto serverEphemeral = crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);
  auto serverNonce = make_nonce(*crypto, 32);

  auto token = std::make_shared<UserNameIdentityToken>();
  // password is empty by default

  auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policyPtr,
        crypto,
        crypto_test_strand(),
        token,
        serverNonce,
        nullptr,
        ByteString{serverEphemeral.publicKey},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());
  EXPECT_TRUE(token->password().empty());
}

// ===== Legacy encrypted-secret format helpers (Part 4 section 7.41.2.2) ==============
//
// These exercise build_legacy_encrypted_token_plaintext / parse_legacy_encrypted_token_secret
// directly - the plaintext framing the RSA path encrypts/decrypts - without going through
// asymmetric crypto, so the spec format (Length||tokenData||serverNonce) and the historical
// prefix-less fallback are both covered deterministically.

namespace
{
span<const byte> as_bytes(const ByteString& bs)
{
  return span<const byte>{bs};
}

ByteString concat(span<const byte> a, span<const byte> b)
{
  std::vector<uint8_t> out;
  out.reserve(a.size() + b.size());
  for (byte v : a)
  {
    out.push_back(static_cast<uint8_t>(v));
  }
  for (byte v : b)
  {
    out.push_back(static_cast<uint8_t>(v));
  }
  return ByteString{std::move(out)};
}
}  // namespace

TEST(UserTokenLegacySecretFormat, BuildThenParseRoundTrips)
{
  auto password = make_password("TestPassword123!");
  ByteString nonce(32, 0xAB);

  ByteString plain = build_legacy_encrypted_token_plaintext(as_bytes(password), as_bytes(nonce));

  // Length(4 LE) prefix == password + nonce.
  ASSERT_EQ(plain.size(), 4u + password.size() + nonce.size());
  const uint32_t declared = static_cast<uint32_t>(plain[0]) | (static_cast<uint32_t>(plain[1]) << 8) |
                            (static_cast<uint32_t>(plain[2]) << 16) | (static_cast<uint32_t>(plain[3]) << 24);
  EXPECT_EQ(declared, password.size() + nonce.size());

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(plain), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
  EXPECT_EQ(recovered.value(), password);
}

TEST(UserTokenLegacySecretFormat, ParseAcceptsZeroPadding)
{
  auto password = make_password("pw");
  ByteString nonce(32, 0x01);

  ByteString plain = build_legacy_encrypted_token_plaintext(as_bytes(password), as_bytes(nonce));
  // Append zero padding (a Client may pad up to the plaintext block size).
  ByteString padded = concat(as_bytes(plain), as_bytes(ByteString(8, 0x00)));

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(padded), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
  EXPECT_EQ(recovered.value(), password);
}

TEST(UserTokenLegacySecretFormat, ParseRejectsNonZeroPadding)
{
  auto password = make_password("pw");
  ByteString nonce(32, 0x01);

  ByteString plain = build_legacy_encrypted_token_plaintext(as_bytes(password), as_bytes(nonce));
  ByteString padded = concat(as_bytes(plain), as_bytes(ByteString{0x00, 0x07, 0x00}));

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(padded), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_bad());
  EXPECT_EQ(recovered.status_code().as_status(), Status::BadIdentityTokenRejected);
}

TEST(UserTokenLegacySecretFormat, ParseAcceptsLegacyNoPrefixForm)
{
  // Historical SDK encoder: tokenData || serverNonce, no length prefix.
  auto password = make_password("legacy-pass");
  ByteString nonce(32, 0x5A);
  ByteString legacy = concat(as_bytes(password), as_bytes(nonce));

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(legacy), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
  EXPECT_EQ(recovered.value(), password);
}

TEST(UserTokenLegacySecretFormat, ParseRejectsNonceMismatch)
{
  auto password = make_password("pw");
  ByteString nonce(32, 0x01);
  ByteString wrongNonce(32, 0x02);

  ByteString plain = build_legacy_encrypted_token_plaintext(as_bytes(password), as_bytes(nonce));

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(plain), as_bytes(wrongNonce));
  ASSERT_TRUE(recovered.is_bad());
  EXPECT_EQ(recovered.status_code().as_status(), Status::BadIdentityTokenInvalid);
}

TEST(UserTokenLegacySecretFormat, ParseRejectsPayloadShorterThanNonce)
{
  ByteString nonce(32, 0x01);
  ByteString tooShort(8, 0x09);

  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(tooShort), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_bad());
  EXPECT_EQ(recovered.status_code().as_status(), Status::BadIdentityTokenInvalid);
}

TEST(UserTokenLegacySecretFormat, EmptyPasswordRoundTrips)
{
  ByteString password;  // empty
  ByteString nonce(32, 0x77);

  ByteString plain = build_legacy_encrypted_token_plaintext(as_bytes(password), as_bytes(nonce));
  auto recovered = parse_legacy_encrypted_token_secret(as_bytes(plain), as_bytes(nonce));
  ASSERT_TRUE(recovered.is_good()) << to_string(recovered.status_code().as_status());
  EXPECT_TRUE(recovered.value().empty());
}

// @relation(AC-SVR-IDENT-009-PASSWORD-LENGTH-LIMIT, scope=function)
TEST(UserTokenLegacySecretFormat, ParseAcceptsSixtyFourByteSecretAndRejectsSixtyFiveBytes)
{
  ByteString nonce(32, 0x77);
  ByteString atLimit(64, 0x31);
  ByteString overLimit(65, 0x32);

  auto acceptedPlaintext = build_legacy_encrypted_token_plaintext(as_bytes(atLimit), as_bytes(nonce));
  auto accepted = parse_legacy_encrypted_token_secret(as_bytes(acceptedPlaintext), as_bytes(nonce));
  ASSERT_TRUE(accepted.is_good()) << to_string(accepted.status_code().as_status());
  EXPECT_EQ(accepted.value(), atLimit);

  auto refusedPlaintext = build_legacy_encrypted_token_plaintext(as_bytes(overLimit), as_bytes(nonce));
  auto refused = parse_legacy_encrypted_token_secret(as_bytes(refusedPlaintext), as_bytes(nonce));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), Status::BadIdentityTokenInvalid);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "LegacyTokenSecretTooLong");
}
