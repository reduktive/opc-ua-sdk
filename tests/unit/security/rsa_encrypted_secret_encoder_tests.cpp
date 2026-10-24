// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_rsa_encrypted_secret_encoder.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_x509_certificate.h"

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

// A crypto provider whose private-key credential callback yields the passphrase the test PKI helpers
// use, mirroring the ECC/UNP encryption tests.
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

// The recovered, decrypted structure the test-side oracle reconstructs from the encoder's bytes.
struct ParsedRsaEncryptedSecret
{
  NodeId typeId;
  uint8_t encodingMask{0};
  int32_t length{0};
  size_t bytesAfterLength{0};

  String securityPolicyUri;
  ByteString certificate;
  DateTime signingTime;

  ByteString signingKey;
  ByteString encryptingKey;
  ByteString iv;

  ByteString nonce;
  ByteString secret;
  uint16_t payloadPaddingSize{0};
  bool paddingBytesConsistent{false};

  // Regions (as spans into the blob copy) used for the HMAC recompute.
  ByteString signedRegion;  // CommonHeader | KeyDataLength | encKeyData | encPayload
  ByteString signature;  // trailing HMAC
};

}  // namespace

// The encoder is tier-0 security-critical. This fixture round-trips its output WITHOUT any production
// decoder: the test itself parses the ExtensionObject framing, RSA-decrypts the KeyData with the server
// private key, AES-CBC-decrypts the payload, and recomputes the HMAC. That end-to-end reconstruction is
// the falsifiable oracle: only a byte-correct encoder yields a blob the test can take apart and whose MAC
// matches.
class RsaEncryptedSecretEncoder : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPolicy = std::make_shared<SecPolBasic256Sha256>();
    mServerKeyPair = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mServerCert = make_rsa_cert(mCrypto, mServerKeyPair, "TestServer", "1");
  }

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

  // Full test-side parse + decrypt of the encoder's blob.
  ParsedRsaEncryptedSecret parse_and_decrypt(const ByteString& blob, const ByteString& serverNonce)
  {
    ParsedRsaEncryptedSecret parsed;
    const span<const byte> blobSpan{blob};

    const EncodingLimits limits;
    memory_stream_device::ExternalReadOnly device{blobSpan};
    MemoryStream stream{device};
    UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
    const StackDepth depth{1024};

    // 1. TypeId | EncodingMask | Length.
    decoder.decode(depth, parsed.typeId);
    decoder.decode(depth, parsed.encodingMask);
    decoder.decode(depth, parsed.length);
    const size_t afterLength = stream.get_position();
    parsed.bytesAfterLength = blob.size() - afterLength;

    // 2. CommonHeader: SecurityPolicyUri | Certificate(thumbprint) | SigningTime.
    const size_t headerStart = stream.get_position();
    decoder.decode(depth, parsed.securityPolicyUri);
    decoder.decode(depth, parsed.certificate);
    decoder.decode(depth, parsed.signingTime);

    // 3. KeyDataLength + encrypted KeyData (raw ciphertext, no inner length prefix).
    uint16_t keyDataLength = 0;
    decoder.decode(depth, keyDataLength);
    const size_t encKeyDataStart = stream.get_position();
    const span<const byte> encKeyData = blobSpan.subspan(encKeyDataStart, keyDataLength);

    // 4. Region boundaries. Signature is the trailing symmetric MAC.
    const size_t signatureSize = mPolicy->symmetric_signature_size();
    const size_t encPayloadStart = encKeyDataStart + keyDataLength;
    const size_t signedRegionEnd = blob.size() - signatureSize;
    const span<const byte> encPayload = blobSpan.subspan(encPayloadStart, signedRegionEnd - encPayloadStart);
    parsed.signedRegion = ByteString{blobSpan.subspan(headerStart, signedRegionEnd - headerStart)};
    parsed.signature = ByteString{blobSpan.subspan(signedRegionEnd, signatureSize)};

    // 5. RSA-decrypt the KeyData -> SigningKey | EncryptingKey | IV.
    ByteString keyDataPlainBuffer;
    keyDataPlainBuffer.resize(encKeyData.size());
    auto keyDataPlain = mCrypto->asymmetric_decrypt_sync(
      mPolicy->asymmetric_encryption_algorithm(), mServerKeyPair, encKeyData, keyDataPlainBuffer);
    {
      memory_stream_device::ExternalReadOnly kdDevice{keyDataPlain};
      MemoryStream kdStream{kdDevice};
      UaBinaryDecoder kdDecoder{StructureResolver{}, kdStream, limits};
      kdDecoder.decode(depth, parsed.signingKey);
      kdDecoder.decode(depth, parsed.encryptingKey);
      kdDecoder.decode(depth, parsed.iv);
    }

    // 6. AES-CBC-decrypt the payload -> Nonce | Secret | padding | PayloadPaddingSize.
    ByteString payloadPlain;
    payloadPlain.resize(encPayload.size());
    mCrypto->symmetric_decrypt_sync(mPolicy->symmetric_encryption_algorithm(),
      span<const byte>{parsed.iv},
      span<const byte>{parsed.encryptingKey},
      encPayload,
      payloadPlain);
    {
      const span<const byte> payloadSpan{payloadPlain};
      memory_stream_device::ExternalReadOnly plDevice{payloadSpan};
      MemoryStream plStream{plDevice};
      UaBinaryDecoder plDecoder{StructureResolver{}, plStream, limits};
      plDecoder.decode(depth, parsed.nonce);
      plDecoder.decode(depth, parsed.secret);
      const size_t afterSecret = plStream.get_position();

      // Trailing PayloadPaddingSize (UInt16 LE) plus the padding bytes preceding it.
      EXPECT_GE(payloadPlain.size(), afterSecret + 2);
      if (payloadPlain.size() >= afterSecret + 2)
      {
        parsed.payloadPaddingSize =
          static_cast<uint16_t>(static_cast<uint8_t>(payloadPlain[payloadPlain.size() - 2]) |
                                (static_cast<uint8_t>(payloadPlain[payloadPlain.size() - 1]) << 8));
        const auto expectedPaddingByte = static_cast<uint8_t>(parsed.payloadPaddingSize & 0xFF);
        parsed.paddingBytesConsistent =
          (static_cast<size_t>(parsed.payloadPaddingSize) + 2 <= payloadPlain.size() - afterSecret);
        for (size_t i = 0; i < parsed.payloadPaddingSize && parsed.paddingBytesConsistent; ++i)
        {
          const size_t idx = payloadPlain.size() - 2 - parsed.payloadPaddingSize + i;
          if (static_cast<uint8_t>(payloadPlain[idx]) != expectedPaddingByte)
          {
            parsed.paddingBytesConsistent = false;
          }
        }
      }
    }

    (void)serverNonce;
    return parsed;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolBasic256Sha256> mPolicy;
  std::shared_ptr<const AsymmetricKeyPair> mServerKeyPair;
  std::shared_ptr<const X509Certificate> mServerCert;
};

// Full round-trip: encode a known secret + nonce, then reconstruct + decrypt every field and verify the
// MAC. Falsifiable - a wrong TypeId, wrong Length, wrong thumbprint, mis-derived keys, mis-placed padding,
// or a MAC that does not cover the correct region all fail a concrete assertion.
TEST_F(RsaEncryptedSecretEncoder, RoundTripBasic256Sha256)
{
  ByteString serverNonce;
  serverNonce.resize(32);
  auto entropy = mCrypto->get_entropy_sync(32);
  std::memcpy(serverNonce.data(), entropy.data(), 32);

  const ByteString secret = exact_bytes("s3cr3t-password");

  const ByteString blob = encode(serverNonce, secret);
  ASSERT_FALSE(blob.empty());

  const ParsedRsaEncryptedSecret parsed = parse_and_decrypt(blob, serverNonce);

  // 1. ExtensionObject framing.
  EXPECT_EQ(parsed.typeId, NodeId{DataTypeId::RsaEncryptedSecret})
    << "TypeId must be the RsaEncryptedSecret DataType NodeId (ns0, id=17545)";
  EXPECT_EQ(parsed.encodingMask, 1) << "EncodingMask must be 0x01 (has body)";
  EXPECT_EQ(static_cast<size_t>(parsed.length), parsed.bytesAfterLength)
    << "Length must equal the byte count of everything following the Length field";

  // 2. CommonHeader.
  EXPECT_EQ(parsed.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(parsed.certificate, mServerCert->thumbprint())
    << "Certificate field must be the server certificate SHA1 thumbprint, not the full DER";
  EXPECT_TRUE(parsed.signingTime.value().time_since_epoch().count() != 0) << "SigningTime must be set";

  // 3. Recovered key material has the policy's sizes.
  EXPECT_EQ(parsed.signingKey.size(), mPolicy->symmetric_signature_key_size());
  EXPECT_EQ(parsed.encryptingKey.size(), mPolicy->symmetric_encryption_key_size());
  EXPECT_EQ(parsed.iv.size(), mPolicy->symmetric_ciphertext_block_size());

  // 4. Recovered payload.
  EXPECT_EQ(parsed.nonce, serverNonce) << "decrypted Nonce must equal the server nonce";
  EXPECT_EQ(parsed.secret, secret) << "decrypted Secret must equal the encoded password";
  EXPECT_TRUE(parsed.paddingBytesConsistent)
    << "each PayloadPadding byte must equal (PayloadPaddingSize & 0xFF)";

  // 5. HMAC over CommonHeader..encPayload with the recovered SigningKey must equal the Signature.
  auto recomputed = mCrypto->symmetric_sign_sync(mPolicy->symmetric_signature_algorithm(),
    span<const byte>{parsed.signingKey},
    span<const byte>{parsed.signedRegion});
  EXPECT_EQ(recomputed, parsed.signature)
    << "Signature must be HMAC-SHA256(SigningKey, CommonHeader..encryptedPayload)";
}

// Falsifiable negative: flipping one byte of the encrypted payload changes the MAC. This proves the
// Signature genuinely covers the payload region (a MAC over only the header/keydata would still match).
TEST_F(RsaEncryptedSecretEncoder, SignatureCoversEncryptedPayload)
{
  ByteString serverNonce;
  serverNonce.resize(16);
  auto entropy = mCrypto->get_entropy_sync(16);
  std::memcpy(serverNonce.data(), entropy.data(), 16);

  const ByteString secret = exact_bytes("another-secret");
  const ByteString blob = encode(serverNonce, secret);
  ASSERT_FALSE(blob.empty());

  const ParsedRsaEncryptedSecret parsed = parse_and_decrypt(blob, serverNonce);

  // Sanity: the untampered MAC matches.
  auto good = mCrypto->symmetric_sign_sync(mPolicy->symmetric_signature_algorithm(),
    span<const byte>{parsed.signingKey},
    span<const byte>{parsed.signedRegion});
  ASSERT_EQ(good, parsed.signature);

  // Flip the last byte of the signed region (which lies inside the encrypted payload) and re-MAC.
  ByteString tampered = parsed.signedRegion;
  ASSERT_GT(tampered.size(), 0u);
  tampered[tampered.size() - 1] =
    static_cast<uint8_t>(static_cast<uint8_t>(tampered[tampered.size() - 1]) ^ 0xFF);
  auto bad = mCrypto->symmetric_sign_sync(mPolicy->symmetric_signature_algorithm(),
    span<const byte>{parsed.signingKey},
    span<const byte>{tampered});
  EXPECT_NE(bad, parsed.signature)
    << "a flipped payload byte must change the HMAC - the Signature must cover the encrypted payload";
}
