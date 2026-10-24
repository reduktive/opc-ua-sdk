// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_rsa_encrypted_secret_decoder.h"
#include "ua_rsa_encrypted_secret_encoder.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_security_policy.h"
#include "ua_to_string.h"
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

// A crypto provider whose private-key credential callback yields the passphrase the test PKI helpers use,
// mirroring the encoder tests.
std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

// A 2048-bit RSA self-signed cert suitable for Basic256Sha256 (digital-signature + key-encipherment).
std::shared_ptr<const X509Certificate> make_rsa_cert(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const AsymmetricKeyPair>& keys, std::string_view commonName, std::string_view serial)
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = keys;
  certParams.issuerKeys = keys;
  certParams.subject.commonName = std::string{commonName};
  certParams.serialNumber = std::string{serial};
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  return pki.create_cert(certParams);
}

ByteString exact_bytes(std::string_view text)
{
  ByteString result;
  result.assign(reinterpret_cast<const uint8_t*>(text.data()),
    reinterpret_cast<const uint8_t*>(text.data()) + text.size());
  return result;
}

}  // namespace

// The decoder is the exact inverse of the encoder and is tier-0 security-critical. This fixture round-trips
// the encoder's output THROUGH the production decoder: encode a known secret + nonce, then decode the blob
// and verify every recovered field. The round-trip is the falsifiable oracle - only a byte-correct decoder
// that RSA-decrypts the KeyData, verifies the MAC, and AES-decrypts the payload can recover the secret.
class RsaEncryptedSecretDecoder : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPolicy = std::make_shared<SecPolBasic256Sha256>();
    mServerKeyPair = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mServerCert = make_rsa_cert(mCrypto, mServerKeyPair, "TestServer", "1");
  }

  // Encode with the production encoder (encrypting to the server certificate's public key).
  ByteString encode(const ByteString& serverNonce, const ByteString& secret)
  {
    auto result = ua::test_helpers::run_async_function_sync<ByteStringResult>(
      [&](auto cb)
      {
        encrypt_rsa_encrypted_secret_async(mPolicy,
          mCrypto,
          crypto_test_strand(),
          mServerCert,
          ByteString{serverNonce},
          ByteString{secret},
          ua::Logger{},
          std::move(cb));
      });
    EXPECT_TRUE(result.is_good()) << "encode status: " << to_string(result.status_code().as_status());
    return result.is_good() ? std::move(result).value() : ByteString{};
  }

  // Decode with the production decoder (RSA-decrypting with the server key pair).
  RsaEncryptedSecretFieldsResult decode(const ByteString& blob, bool acceptInvalidPadding = false)
  {
    return ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
      [&](auto cb)
      {
        decrypt_rsa_encrypted_secret_async(ByteString{blob},
          mPolicy,
          mCrypto,
          crypto_test_strand(),
          mServerKeyPair,
          mServerCert,
          acceptInvalidPadding,
          ua::Logger{},
          std::move(cb));
      });
  }

  ByteString random_bytes(size_t count)
  {
    ByteString bytes;
    bytes.resize(count);
    auto entropy = mCrypto->get_entropy_sync(count);
    std::memcpy(bytes.data(), entropy.data(), count);
    return bytes;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolBasic256Sha256> mPolicy;
  std::shared_ptr<const AsymmetricKeyPair> mServerKeyPair;
  std::shared_ptr<const X509Certificate> mServerCert;
};

// Full round-trip: encode a known secret + nonce, decode with the production decoder, and verify every
// recovered field. Falsifiable - a wrong region boundary, a mis-derived key, a wrong MAC region, or
// mis-placed padding stripping all fail a concrete assertion (the secret/nonce would not match).
// @verifies CL-IDENT-005
// @relation(CL-IDENT-005, scope=function)
TEST_F(RsaEncryptedSecretDecoder, RoundTripRecoversSecret)
{
  const ByteString serverNonce = random_bytes(32);
  const ByteString secret = exact_bytes("s3cr3t-password");

  const ByteString blob = encode(serverNonce, secret);
  ASSERT_FALSE(blob.empty());

  const RsaEncryptedSecretFieldsResult result = decode(blob);
  ASSERT_TRUE(result.is_good()) << "decode status: " << to_string(result.status_code().as_status());

  const RsaEncryptedSecretFields& fields = result.value();
  EXPECT_EQ(fields.secret, secret) << "decoded Secret must equal the encoded password";
  EXPECT_EQ(fields.nonce, serverNonce) << "decoded Nonce must equal the server nonce";
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.certificateThumbprint, mServerCert->thumbprint())
    << "Certificate field must be recovered as the server certificate SHA1 thumbprint";
  EXPECT_TRUE(fields.signingTime.value().time_since_epoch().count() != 0) << "SigningTime must be recovered";
}

// Verify-then-use: flip one byte inside the encrypted-payload region (which the MAC covers, but which sits
// before the trailing Signature). The decode must fail at the HMAC verify step with
// Bad_IdentityTokenInvalid - BEFORE the payload is AES-decrypted. Asserting the status came from the verify
// step (not a downstream BadDecodingError from AES/padding) proves the MAC is checked before the payload is
// trusted.
TEST_F(RsaEncryptedSecretDecoder, TamperedSignatureRejected)
{
  const ByteString serverNonce = random_bytes(16);
  const ByteString secret = exact_bytes("another-secret");

  ByteString blob = encode(serverNonce, secret);
  ASSERT_FALSE(blob.empty());

  // Sanity: the untampered blob decodes cleanly.
  ASSERT_TRUE(decode(blob).is_good());

  // The trailing symmetric-signature-size bytes are the Signature; the byte just before them is the last
  // byte of the encrypted payload (always >= one AES block, so this index is inside the payload region).
  const size_t signatureSize = mPolicy->symmetric_signature_size();
  ASSERT_GT(blob.size(), signatureSize + 1);
  const size_t flipIndex = blob.size() - signatureSize - 1;
  blob[flipIndex] = static_cast<uint8_t>(static_cast<uint8_t>(blob[flipIndex]) ^ 0xFF);

  const RsaEncryptedSecretFieldsResult result = decode(blob);
  ASSERT_TRUE(result.is_bad()) << "a flipped encrypted-payload byte must be rejected by the MAC check";
  EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenInvalid)
    << "a MAC mismatch must fail as Bad_IdentityTokenInvalid at the verify step, not a downstream decode "
       "error";
  ASSERT_NE(result.shared_detail(), nullptr) << "the failure must carry a source-tagged ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "server.tier0.rsa_encrypted_secret.verify")
    << "the failure must originate at the HMAC verify step (verify-then-use)";
}

// A too-short blob must be rejected as a decoding error without any crash / out-of-bounds read.
TEST_F(RsaEncryptedSecretDecoder, TruncatedBlobRejected)
{
  const ByteString serverNonce = random_bytes(16);
  const ByteString secret = exact_bytes("truncate-me");

  const ByteString blob = encode(serverNonce, secret);
  ASSERT_FALSE(blob.empty());

  // Keep only the first few bytes (well inside the framing prefix): the Length field will not match the
  // remaining bytes and the region bounds cannot be satisfied.
  ByteString truncated;
  truncated.resize(std::min<size_t>(blob.size(), 8));
  std::memcpy(truncated.data(), blob.data(), truncated.size());

  const RsaEncryptedSecretFieldsResult result = decode(truncated);
  ASSERT_TRUE(result.is_bad()) << "a truncated blob must be rejected, not decoded";
  EXPECT_EQ(result.status_code().as_status(), Status::BadDecodingError)
    << "a malformed / too-short blob must yield Bad_DecodingError";
}

// @verifies AC-SVR-IDENT-013-PAYLOAD-PADDING
// @relation(AC-SVR-IDENT-013-PAYLOAD-PADDING, scope=function)
TEST_F(RsaEncryptedSecretDecoder, PayloadPaddingMismatchHonoursCompatibilityOverride)
{
  // PayloadPaddingSize is UInt16 little-endian. A declared size of two therefore requires exactly
  // two preceding 0x02 bytes; this is the conforming control that prevents an implementation from
  // rejecting all non-empty padding regions.
  const ByteString validPadding{0xAA, 0x00, 0x02, 0x02, 0x02, 0x00};
  const auto valid = validate_rsa_secret_payload_padding(validPadding, false);
  ASSERT_TRUE(valid.is_good());
  EXPECT_EQ(valid.value(), 2u);

  // Change one of those two bytes without changing the declared size.
  const ByteString invalidPadding{0xAA, 0x00, 0x02, 0x03, 0x02, 0x00};

  const auto strict = validate_rsa_secret_payload_padding(invalidPadding, false);
  ASSERT_TRUE(strict.is_bad());
  EXPECT_EQ(strict.status_code().as_status(), Status::BadDecodingError);
  ASSERT_NE(strict.shared_detail(), nullptr);
  EXPECT_EQ(strict.shared_detail()->code, "PayloadPaddingInconsistent");

  const auto relaxed = validate_rsa_secret_payload_padding(invalidPadding, true);
  ASSERT_TRUE(relaxed.is_good());
  EXPECT_EQ(relaxed.value(), 2u);
}

namespace
{
// Basic256Sha256 in every algorithm and size, Aes128_Sha256_RsaOaep in the CommonHeader it writes: a
// secret it encrypts decrypts and verifies under Basic256Sha256, so only the header differs.
class HeaderMislabelledBasic256Sha256 final : public SecPolBasic256Sha256
{
public:
  String uri() const override
  {
    return SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep)->uri();
  }
};
}  // namespace

// OPC 10000-4 7.41.2.3: the SecurityPolicyUri "is used to determine what algorithms were used to encrypt
// and sign the data". A secret whose header names another policy decrypts and verifies cleanly here, so
// only the decoder's header check can refuse it. The control is the same secret labelled correctly.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
// @relation(AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED, scope=function)
TEST_F(RsaEncryptedSecretDecoder, HeaderNamingAnotherPolicyIsRefused)
{
  const ByteString serverNonce = random_bytes(32);
  const ByteString secret = exact_bytes("header-policy");

  // control: the correctly labelled secret decodes.
  ASSERT_TRUE(decode(encode(serverNonce, secret)).is_good());

  const std::shared_ptr<const SecurityPolicy> mislabelled =
    std::make_shared<HeaderMislabelledBasic256Sha256>();
  auto mislabelledBlob = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_rsa_encrypted_secret_async(mislabelled,
        mCrypto,
        crypto_test_strand(),
        mServerCert,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(mislabelledBlob.is_good());

  const RsaEncryptedSecretFieldsResult result = decode(mislabelledBlob.value());
  ASSERT_TRUE(result.is_bad()) << "a secret naming another policy must be refused";
  EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "EncryptedSecretPolicyMismatch");
}

// Table 189: the RsaEncryptedSecret Certificate is "The SHA1 hash of the DER form of the Certificate used
// to encrypt the KeyData". A second certificate over the same key pair decrypts the secret, but it is not
// the certificate the secret names, so the decoder refuses it; with no receiver certificate nothing can
// match. The control decodes with the certificate the secret was encrypted to.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
// @relation(AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED, scope=function)
TEST_F(RsaEncryptedSecretDecoder, HeaderNamingAnotherCertificateIsRefused)
{
  const ByteString blob = encode(random_bytes(32), exact_bytes("header-certificate"));
  ASSERT_FALSE(blob.empty());

  // control: the certificate the secret was encrypted to.
  ASSERT_TRUE(decode(blob).is_good());

  const auto siblingCert = make_rsa_cert(mCrypto, mServerKeyPair, "TestServer", "2");
  ASSERT_NE(siblingCert->thumbprint(), mServerCert->thumbprint());

  for (const auto& receiverCertificate : {siblingCert, std::shared_ptr<const X509Certificate>{}})
  {
    SCOPED_TRACE(receiverCertificate ? "sibling certificate" : "no certificate");
    const auto result = ua::test_helpers::run_async_function_sync<RsaEncryptedSecretFieldsResult>(
      [&](auto cb)
      {
        decrypt_rsa_encrypted_secret_async(ByteString{blob},
          mPolicy,
          mCrypto,
          crypto_test_strand(),
          mServerKeyPair,
          receiverCertificate,
          false,
          ua::Logger{},
          std::move(cb));
      });
    ASSERT_TRUE(result.is_bad()) << "a secret naming another certificate must be refused";
    EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenInvalid);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "EncryptedSecretCertificateMismatch");
  }
}

// The KeyData plaintext is taken only from a Good asymmetric_decrypt answer. The provider is parked so the
// test answers the decrypt itself: an Uncertain answer, with or without a plaintext, is refused with
// Bad_InternalError, the CryptoAnswerUncertain ErrorDetail and the Uncertain code as its inner status.
class RsaEncryptedSecretDecoderUncertainKeyData : public RsaEncryptedSecretDecoder
{
protected:
  RsaEncryptedSecretFieldsResult decode_with_key_data_answer(
    const ByteString& blob, Crypto::ByteSpanResult answer)
  {
    auto parked = ua::test_helpers::FakeAsyncCrypto::create();
    parked->set_park_async(true);
    auto answered = std::make_shared<std::promise<RsaEncryptedSecretFieldsResult>>();
    auto future = answered->get_future();
    decrypt_rsa_encrypted_secret_async(ByteString{blob},
      mPolicy,
      parked,
      crypto_test_strand(),
      mServerKeyPair,
      mServerCert,
      false,
      ua::Logger{},
      [answered](RsaEncryptedSecretFieldsResult result) { answered->set_value(std::move(result)); });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (parked->pending_asymmetric_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    EXPECT_EQ(parked->pending_asymmetric_decrypt_count(), 1U) << "the KeyData decrypt was not issued";
    if (parked->pending_asymmetric_decrypt_count() == 0)
    {
      return RsaEncryptedSecretFieldsResult{StatusCode{Status::BadTimeout}};
    }
    parked->complete_pending_asymmetric_decrypt(0, std::move(answer));
    if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the decoder did not answer";
      return RsaEncryptedSecretFieldsResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }
};

// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(RsaEncryptedSecretDecoderUncertainKeyData, AnUncertainAnswerWithoutAPlaintextIsRefused)
{
  const ByteString blob = encode(random_bytes(32), exact_bytes("s3cr3t-password"));
  ASSERT_FALSE(blob.empty());
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  const auto result = decode_with_key_data_answer(blob, Crypto::ByteSpanResult{uncertain});

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(RsaEncryptedSecretDecoderUncertainKeyData, AnUncertainAnswerHoldingAPlaintextIsRefused)
{
  const ByteString blob = encode(random_bytes(32), exact_bytes("s3cr3t-password"));
  ASSERT_FALSE(blob.empty());
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const std::vector<byte> plaintext(128, byte{0x5A});

  const auto result =
    decode_with_key_data_answer(blob, Crypto::ByteSpanResult{span<const byte>{plaintext}, uncertain});

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
}
