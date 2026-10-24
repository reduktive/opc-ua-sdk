// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <algorithm>
#include <optional>
#include <cstring>
#include <stdexcept>

#include "ua_security_policy.h"
#include "ua_datatype_id.h"
#include "ua_node_id.h"
#include "ua_binary_codec.h"
#include "ua_to_string.h"
#include "ua_crypto.h"
#include "ua_ecc_encrypted_secret_decoder.h"
#include "ua_ecc_encrypted_secret_encoder.h"
#include "ua_memory_stream.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_x509_certificate.h"
#include "run_async_sync.h"
#include "test_pki_helpers.h"
#include "unit/security/sce_vector_helpers.h"
#include "unit/security/sce_vectors.h"
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

// Helper: build the HKDF salt for EccEncryptedSecret key derivation.
// Independent wire oracle: Part 6 section 6.8.4 uses HKDF output length in bytes.
// Salt = L(2 LE) | "opcua-secret" | SenderPublicKey | ReceiverPublicKey
ByteString build_secret_salt(
  size_t numberOfBytes, span<const byte> senderPublicKey, span<const byte> receiverPublicKey)
{
  static constexpr string_view secretLabel = "opcua-secret";
  auto saltSize = 2 + secretLabel.size() + senderPublicKey.size() + receiverPublicKey.size();
  ByteString salt;
  salt.resize(saltSize);

  auto lengthBytes = numeric_cast<uint16_t>(numberOfBytes);
  salt[0] = static_cast<uint8_t>(lengthBytes & 0xFF);
  salt[1] = static_cast<uint8_t>((lengthBytes >> 8) & 0xFF);

  size_t offset = 2;
  std::memcpy(&salt[offset], secretLabel.data(), secretLabel.size());
  offset += secretLabel.size();
  std::memcpy(&salt[offset], senderPublicKey.data(), senderPublicKey.size());
  offset += senderPublicKey.size();
  std::memcpy(&salt[offset], receiverPublicKey.data(), receiverPublicKey.size());

  return salt;
}

// UA Binary encode a ByteString: Int32 length prefix + raw bytes.
void ua_encode_byte_string(std::vector<byte>& out, span<const byte> data)
{
  auto length = static_cast<int32_t>(data.size());
  out.push_back(static_cast<byte>(length & 0xFF));
  out.push_back(static_cast<byte>((length >> 8) & 0xFF));
  out.push_back(static_cast<byte>((length >> 16) & 0xFF));
  out.push_back(static_cast<byte>((length >> 24) & 0xFF));
  out.insert(out.end(), data.begin(), data.end());
}

// UA Binary encode a String: same wire format as ByteString.
void ua_encode_string(std::vector<byte>& out, string_view str)
{
  auto asBytes = span<const byte>{utils::chars_to_bytes(str.data()), str.size()};
  ua_encode_byte_string(out, asBytes);
}

// UA Binary encode a DateTime (Int64 LE).
void ua_encode_date_time(std::vector<byte>& out, DateTime dt)
{
  auto val = dt.value().time_since_epoch().count();
  for (int i = 0; i < 8; ++i)
  {
    out.push_back(static_cast<byte>((val >> (i * 8)) & 0xFF));
  }
}

// UA Binary encode a UInt16 LE.
void ua_encode_uint16(std::vector<byte>& out, uint16_t val)
{
  out.push_back(static_cast<byte>(val & 0xFF));
  out.push_back(static_cast<byte>((val >> 8) & 0xFF));
}

std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

struct TestKeyMaterial
{
  shared_ptr<const AsymmetricKeyPair> clientAppKeyPair;
  shared_ptr<const X509Certificate> clientCert;
  Crypto::EphemeralKeyPair clientEphemeral;
  Crypto::EphemeralKeyPair serverEphemeral;
};

TestKeyMaterial generate_test_keys(const Crypto& crypto)
{
  TestKeyMaterial keys;

  // Generate ECC application key pair and self-signed cert for client
  keys.clientAppKeyPair =
    crypto.create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = keys.clientAppKeyPair;
  certParams.issuerKeys = keys.clientAppKeyPair;
  certParams.subject.commonName = "TestClient";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  keys.clientCert = pki.create_cert(certParams);

  // Generate ephemeral key pairs for client and server
  keys.clientEphemeral = crypto.create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);
  keys.serverEphemeral = crypto.create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);

  return keys;
}

// Build a valid EccEncryptedSecret blob for testing.
ByteString build_ecc_encrypted_secret(const Crypto& crypto, const SecPolEphemeralKey& eccPolicy,
  String securityPolicyUri, ByteString signingCertDer, DateTime signingTime, ByteString senderPublicKey,
  ByteString senderPrivateKey, ByteString receiverPublicKey,
  shared_ptr<const AsymmetricKeyPair> signingKeyPair, ByteString nonce, ByteString secret)
{
  // 1. Build common header: SecurityPolicyUri | Certificate(ByteString) | SigningTime(DateTime)
  std::vector<byte> commonHeader;
  ua_encode_string(commonHeader, securityPolicyUri);
  ua_encode_byte_string(commonHeader, span<const byte>{signingCertDer});
  ua_encode_date_time(commonHeader, signingTime);

  // 2. Build KeyData: SenderPublicKey(ByteString) | ReceiverPublicKey(ByteString)
  std::vector<byte> keyDataSerialized;
  ua_encode_byte_string(keyDataSerialized, span<const byte>{senderPublicKey});
  ua_encode_byte_string(keyDataSerialized, span<const byte>{receiverPublicKey});

  auto keyDataLength = static_cast<uint16_t>(keyDataSerialized.size());

  // 3. Build payload content: Nonce(ByteString) | Secret(ByteString)
  std::vector<byte> payloadContent;
  ua_encode_byte_string(payloadContent, span<const byte>{nonce});
  ua_encode_byte_string(payloadContent, span<const byte>{secret});

  // 4. Pad by the OPC 10000-6 section 6.8.3 formula with the AEAD BlockSize 16: the payload, padding and
  // PayloadPaddingSize fill whole blocks, and a block more is added while the padding and the secret together
  // are shorter than one block.
  const size_t blockSize = 16;
  const size_t dataLength = payloadContent.size() + 2;
  size_t paddingCount = dataLength % blockSize == 0 ? 0 : blockSize - dataLength % blockSize;
  if (paddingCount + secret.size() < blockSize)
    paddingCount += blockSize;
  auto paddingSize = static_cast<uint16_t>(paddingCount);

  auto paddingByte = static_cast<uint8_t>(paddingSize & 0xFF);
  std::vector<byte> paddedPayload = payloadContent;
  for (uint16_t i = 0; i < paddingSize; ++i)
  {
    paddedPayload.push_back(static_cast<byte>(paddingByte));
  }
  // Append UInt16 LE paddingSize
  paddedPayload.push_back(static_cast<byte>(paddingSize & 0xFF));
  paddedPayload.push_back(static_cast<byte>((paddingSize >> 8) & 0xFF));

  // 5. Derive encryption keys via ECDH + HKDF
  auto sharedSecret = crypto.calculate_shared_secret_sync(
    eccPolicy.ephemeral_key_algorithm(), senderPrivateKey, receiverPublicKey);

  auto encKeySize = eccPolicy.symmetric_encryption_key_size();
  auto ivSize = eccPolicy.symmetric_iv_size();
  auto numberOfBytes = encKeySize + ivSize;

  auto salt = build_secret_salt(numberOfBytes, senderPublicKey, receiverPublicKey);

  auto keyMaterial = crypto.derive_symmetric_keys_sync(
    eccPolicy.key_derivation_algorithm(), numberOfBytes, sharedSecret, salt, salt);

  span<const byte> encKey = span<const byte>{keyMaterial}.subspan(0, encKeySize);
  span<const byte> iv = span<const byte>{keyMaterial}.subspan(encKeySize, ivSize);

  // 6. The headers. Part 4 Table 183: namespace-zero numeric TypeId 17546, the Binary encoding mask, then the
  // Length of every byte after it - the encrypted payload, its 16-byte tag and the signature included.
  const size_t tagSize = 16;
  const auto signatureSize =
    2 * ((crypto.read_certificate_from_der(signingCertDer)->public_key_bit_length() + 7) / 8);
  const auto bodySize = numeric_cast<uint32_t>(
    commonHeader.size() + 2 + keyDataSerialized.size() + paddedPayload.size() + tagSize + signatureSize);
  std::vector<byte> dataToSign{byte{0x01}, byte{0x00}, byte{0x8A}, byte{0x44}, byte{0x01}};
  for (unsigned shift = 0; shift < 32; shift += 8)
    dataToSign.push_back(numeric_cast<byte>((bodySize >> shift) & 0xFF));
  dataToSign.insert(dataToSign.end(), commonHeader.begin(), commonHeader.end());
  ua_encode_uint16(dataToSign, keyDataLength);
  dataToSign.insert(dataToSign.end(), keyDataSerialized.begin(), keyDataSerialized.end());

  // 7. Seal the padded payload with the policy's AEAD cipher; every header above is the associated data
  // (OPC 10000-6 section 6.8.3). The ciphertext, then the tag, follow the headers.
  ByteString cipherText;
  cipherText.resize(paddedPayload.size());
  const auto tag = crypto.symmetric_encrypt_and_sign_sync(eccPolicy.symmetric_encryption_algorithm(),
    iv,
    encKey,
    span<const byte>{paddedPayload},
    span<const byte>{dataToSign},
    cipherText);
  {
    span<const byte> ctSpan = cipherText;
    dataToSign.insert(dataToSign.end(), ctSpan.begin(), ctSpan.end());
    span<const byte> tagSpan = tag;
    dataToSign.insert(dataToSign.end(), tagSpan.begin(), tagSpan.end());
  }

  // 8. Sign with client application cert private key
  auto signature = crypto.asymmetric_sign_sync(
    eccPolicy.asymmetric_signature_algorithm(), signingKeyPair, span<const byte>{dataToSign});

  // 9. Append the signature to the complete signed envelope.
  std::vector<byte> blob;
  blob.insert(blob.end(), dataToSign.begin(), dataToSign.end());
  {
    span<const byte> sigSpan = signature;
    blob.insert(blob.end(), sigSpan.begin(), sigSpan.end());
  }

  return ByteString{span<const byte>{blob}};
}

}  // namespace

class EccEncryptedSecretDecoderTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPolicy =
      std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
    mKeys = generate_test_keys(*mCrypto);
  }

  ByteString build_valid_blob(ByteString nonce, ByteString secret)
  {
    auto policyUri = mPolicy->uri();
    auto certDer = mKeys.clientCert->der_encoding();
    auto signingTime = DateTime::now();

    return build_ecc_encrypted_secret(*mCrypto,
      *mPolicy,
      std::move(policyUri),
      std::move(certDer),
      signingTime,
      mKeys.clientEphemeral.publicKey,
      mKeys.clientEphemeral.privateKey,
      mKeys.serverEphemeral.publicKey,
      mKeys.clientAppKeyPair,
      std::move(nonce),
      std::move(secret));
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolEphemeralKey> mPolicy;
  TestKeyMaterial mKeys;
};

// A coder refused before it starts (no Crypto provider) answers once: a callback that throws is not
// answered again with the failure its exception is turned into.
// @relation(AC-COMP-ECC-SECRET-CODERS-ANSWER-ONCE, scope=function)
TEST_F(EccEncryptedSecretDecoderTests, ACallbackThatThrowsOnARefusedStartIsNotAnsweredAgain)
{
  int decoded = 0;
  decrypt_ecc_encrypted_secret_async(ByteString{std::vector<byte>{byte{1}}},
    mPolicy,
    nullptr,
    crypto_test_strand(),
    mKeys.serverEphemeral.privateKey,
    ByteString{mKeys.serverEphemeral.publicKey},
    mKeys.clientCert,
    ua::Logger{},
    [&decoded](EccEncryptedSecretFieldsResult)
    {
      if (decoded++ == 0)
        throw std::runtime_error{"the caller's continuation failed"};
    });
  EXPECT_EQ(decoded, 1) << "the decoder";

  int encoded = 0;
  encrypt_ecc_encrypted_secret_async(mPolicy,
    nullptr,
    crypto_test_strand(),
    mKeys.serverEphemeral.publicKey,
    mKeys.clientCert,
    mKeys.clientAppKeyPair,
    ByteString{std::vector<byte>(32, byte{0x42})},
    ByteString{std::vector<byte>{byte{1}}},
    ua::Logger{},
    [&encoded](ByteStringResult)
    {
      if (encoded++ == 0)
        throw std::runtime_error{"the caller's continuation failed"};
    });
  EXPECT_EQ(encoded, 1) << "the encoder";
}

// @verifies AC-COMP-ECC-SECRET-WIRE
// @relation(AC-COMP-ECC-SECRET-WIRE, scope=function)
TEST_F(EccEncryptedSecretDecoderTests, RoundTripWithNistP256)
{
  ByteString nonce;
  nonce.resize(32);
  auto entropy = mCrypto->get_entropy_sync(32);
  std::memcpy(nonce.data(), entropy.data(), 32);

  ByteString secret;
  {
    constexpr string_view password = "MySecretPassword123!";
    secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
      reinterpret_cast<const uint8_t*>(password.data()) + password.size());
  }

  auto blob = build_valid_blob(nonce, secret);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());

  auto& fields = result.value();
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.certificate, mKeys.clientCert->der_encoding());
  EXPECT_EQ(fields.senderPublicKey, mKeys.clientEphemeral.publicKey);
  EXPECT_EQ(fields.receiverPublicKey, mKeys.serverEphemeral.publicKey);
  EXPECT_EQ(fields.nonce, nonce);
  EXPECT_EQ(fields.secret, secret);
}

// OPC 10000-4 7.41.2.3: the SecurityPolicyUri "is used to determine what algorithms were used to encrypt
// and sign the data". A secret built with the decoder's own algorithms but whose header names ECC_nistP384
// decrypts and verifies, so only the decoder's header check can refuse it. The control is the same secret
// labelled with the decrypting policy.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
// @relation(AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED, scope=function)
TEST_F(EccEncryptedSecretDecoderTests, HeaderNamingAnotherPolicyIsRefused)
{
  const auto decode = [this](const ByteString& blob)
  {
    return ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
      [&](auto cb)
      {
        decrypt_ecc_encrypted_secret_async(ByteString{blob},
          mPolicy,
          mCrypto,
          crypto_test_strand(),
          mKeys.serverEphemeral.privateKey,
          ByteString{mKeys.serverEphemeral.publicKey},
          mKeys.clientCert,
          ua::Logger{},
          std::move(cb));
      });
  };
  const auto build = [this](String policyUri)
  {
    ByteString nonce;
    nonce.resize(32);
    ByteString secret;
    secret.resize(8);
    return build_ecc_encrypted_secret(*mCrypto,
      *mPolicy,
      std::move(policyUri),
      mKeys.clientCert->der_encoding(),
      DateTime::now(),
      mKeys.clientEphemeral.publicKey,
      mKeys.clientEphemeral.privateKey,
      mKeys.serverEphemeral.publicKey,
      mKeys.clientAppKeyPair,
      std::move(nonce),
      std::move(secret));
  };

  // control: the secret labelled with the decrypting policy decodes.
  ASSERT_TRUE(decode(build(mPolicy->uri())).is_good());

  const auto result = decode(build(SecurityPolicy::create(SecurityPolicyId::EccNistP384AesGcm)->uri()));
  ASSERT_TRUE(result.is_bad()) << "a secret naming another policy must be refused";
  EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "EncryptedSecretPolicyMismatch");
}

TEST_F(EccEncryptedSecretDecoderTests, WrongReceiverPublicKeyIsRejected)
{
  ByteString nonce;
  nonce.resize(16);
  ByteString secret;
  secret.resize(8);

  // Build blob with a different receiver key than what the server has
  auto wrongServerEphemeral = mCrypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::EccNistP256);

  auto policyUri = mPolicy->uri();
  auto certDer = mKeys.clientCert->der_encoding();
  auto signingTime = DateTime::now();

  // Build blob using wrongServerEphemeral as the receiver key
  auto blob = build_ecc_encrypted_secret(*mCrypto,
    *mPolicy,
    std::move(policyUri),
    std::move(certDer),
    signingTime,
    mKeys.clientEphemeral.publicKey,
    mKeys.clientEphemeral.privateKey,
    wrongServerEphemeral.publicKey,
    mKeys.clientAppKeyPair,
    std::move(nonce),
    std::move(secret));

  // Decrypt with the real server ephemeral keys -- receiver key mismatch
  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIdentityTokenInvalid);
}

TEST_F(EccEncryptedSecretDecoderTests, CorruptSignatureIsRejected)
{
  ByteString nonce;
  nonce.resize(16);
  ByteString secret;
  secret.resize(8);

  auto blob = build_valid_blob(nonce, secret);

  // Corrupt the last byte of the signature (signature is at the end of the blob)
  ASSERT_GT(blob.size(), 1u);
  blob[blob.size() - 1] = static_cast<uint8_t>(static_cast<uint8_t>(blob[blob.size() - 1]) ^ 0xFF);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
}

// Part 4 section 7.41.2.3 lists the deserialisation steps, and the first two are ALTERNATIVES rather than a
// sequence:
//
//     - Verify the Signature if the KeyData is not encrypted;
//     - Decrypt the KeyData and verify the Signature if the KeyData is encrypted;
//     - Decrypt the payload;
//
// Which branch applies is fixed by the DataType. `RsaEncryptedSecret`'s KeyData is always encrypted -
// Table 189 defines the field as "encrypted with the PublicKey associated with the Certificate" and
// its KeyDataLength as "the length, in bytes, of the encrypted KeyData", with none of Table 187's
// conditional wording - so the RSA decoder's decrypt-KeyData -> verify -> decrypt-payload order is the
// second branch and is correct, however much it reads like decrypt-before-authenticate.
//
// The FIRST branch is this one. An EccEncryptedSecret's KeyData is an ephemeral public key and is not
// encrypted, so the Signature is verifiable immediately and Part 4 requires it to be verified before
// anything is decrypted. That is the classic ordering property: an attacker who can make a Server
// decrypt attacker-chosen data before authenticating it has a decryption oracle, and the sequence is
// written to deny one.
//
// `CorruptSignatureIsRejected` above establishes that the signature IS checked. It cannot establish
// that the check comes first, because a decoder that decrypted and then verified would reject the same
// blob with the same status. This one corrupts the payload as well, so the two orders give different
// answers: verify-first stops at the signature, decrypt-first reaches a payload that no longer parses
// and says so instead.
// @verifies AC-SVR-IDENT-013-ENCRYPTEDSECRET-ORDER
TEST_F(EccEncryptedSecretDecoderTests, TheSignatureIsVerifiedBeforeAnyDecryptionIsAttempted)
{
  ByteString nonce;
  nonce.resize(16);
  ByteString secret;
  secret.resize(8);

  auto blob = build_valid_blob(nonce, secret);
  ASSERT_GT(blob.size(), 64u) << "the blob is too small to corrupt two independent regions";

  // Corrupt the payload region - far enough past the header and KeyData to land in encrypted payload,
  // far enough before the end to leave the signature bytes alone.
  const auto payloadOffset = blob.size() / 2;
  blob[payloadOffset] = static_cast<uint8_t>(static_cast<uint8_t>(blob[payloadOffset]) ^ 0xFF);
  // ...and the signature, which is at the end.
  blob[blob.size() - 1] = static_cast<uint8_t>(static_cast<uint8_t>(blob[blob.size() - 1]) ^ 0xFF);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_bad()) << "a blob with a corrupt signature AND a corrupt payload was accepted";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed)
    << "the failure reported is 0x" << std::hex << result.status_code().as_uint32() << std::dec
    << ", not the signature check. A decoder that reached the payload before verifying the signature "
       "decrypted attacker-supplied bytes it had not authenticated, which is the construction Part 4 "
       "section 7.41.2.3's ordering exists to prevent";

  // The control, or the assertion above would pass against a decoder that answered
  // BadSecurityChecksFailed to everything: an untouched blob of the same shape decodes.
  auto intact = build_valid_blob(ByteString{nonce}, ByteString{secret});
  auto intactResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{intact},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });
  EXPECT_TRUE(intactResult.is_good())
    << "an untouched blob was refused with 0x" << std::hex << intactResult.status_code().as_uint32()
    << std::dec << ", so the refusal above says nothing about the corruption that provoked it";
}

TEST_F(EccEncryptedSecretDecoderTests, TruncatedBlobIsRejected)
{
  ByteString nonce;
  nonce.resize(16);
  ByteString secret;
  secret.resize(8);

  auto blob = build_valid_blob(nonce, secret);

  // Truncate to just a few bytes -- not enough for even the common header
  ByteString truncated{span<const uint8_t>{blob.data(), 4}};

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&, truncated = std::move(truncated)](auto cb) mutable
    {
      decrypt_ecc_encrypted_secret_async(std::move(truncated),
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadDecodingError);
}

TEST_F(EccEncryptedSecretDecoderTests, PaddingIsCorrectlyStripped)
{
  // Choose a nonce + secret size that produces a known padding amount.
  // Nonce: 5 bytes -> UA Binary: 4 (len) + 5 = 9 bytes
  // Secret: 3 bytes -> UA Binary: 4 (len) + 3 = 7 bytes
  // Total payload content: 16 bytes
  // Plus 2 bytes paddingSize field = 18 bytes -> round to 32 (next multiple of 16)
  // paddingSize = 32 - 16 - 2 = 14
  ByteString nonce;
  nonce.resize(5);
  for (size_t i = 0; i < 5; ++i)
    nonce[i] = static_cast<uint8_t>(0xA0 + i);

  ByteString secret;
  secret.resize(3);
  for (size_t i = 0; i < 3; ++i)
    secret[i] = static_cast<uint8_t>(0xB0 + i);

  auto blob = build_valid_blob(nonce, secret);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());
  EXPECT_EQ(result.value().nonce, nonce);
  EXPECT_EQ(result.value().secret, secret);
}

// ===== Multi-Policy Parameterized Tests ======================================
//
// Exercise the ECC encrypted secret decoder with both AEAD policies of each ECDSA curve to cover varying key
// sizes, HKDF algorithms, signature algorithms and ciphers. ECDSA only: build_ecc_encrypted_secret sizes the
// signature as an r|s pair; the encoder suite below covers the Edwards curves and RSA_DH.

struct EccPolicyTestParams
{
  SecurityPolicyId policyId;
  CertificateKeyAlgorithm certKeyAlg;
  EphemeralKeyAlgorithm ephKeyAlg;
  CertificateSignatureAlgorithm certSigAlg;
  std::function<std::shared_ptr<SecPolEphemeralKey>()> createPolicy;
  std::string name;
  std::optional<size_t> certKeyBits{};  // the RSA modulus size; unset for the ECC curves
};

class EccEncryptedSecretMultiPolicyTests : public ::testing::TestWithParam<EccPolicyTestParams>
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    const auto& params = GetParam();
    mPolicy = params.createPolicy();

    // Generate ECC application key pair and self-signed cert for client
    mClientAppKeyPair = mCrypto->create_asymmetric_key_pair_sync(params.certKeyAlg, std::nullopt);

    TestPki pki{create_crypto()};
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = mClientAppKeyPair;
    certParams.issuerKeys = mClientAppKeyPair;
    certParams.subject.commonName = "TestClient";
    certParams.serialNumber = "1";
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.certificateSignatureAlgorithm = params.certSigAlg;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    mClientCert = pki.create_cert(certParams);

    // Generate ephemeral key pairs for client and server
    mClientEphemeral = mCrypto->create_ephemeral_keys_sync(params.ephKeyAlg);
    mServerEphemeral = mCrypto->create_ephemeral_keys_sync(params.ephKeyAlg);
  }

  ByteString build_valid_blob(ByteString nonce, ByteString secret)
  {
    auto policyUri = mPolicy->uri();
    auto certDer = mClientCert->der_encoding();
    auto signingTime = DateTime::now();

    return build_ecc_encrypted_secret(*mCrypto,
      *mPolicy,
      std::move(policyUri),
      std::move(certDer),
      signingTime,
      mClientEphemeral.publicKey,
      mClientEphemeral.privateKey,
      mServerEphemeral.publicKey,
      mClientAppKeyPair,
      std::move(nonce),
      std::move(secret));
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolEphemeralKey> mPolicy;
  shared_ptr<const AsymmetricKeyPair> mClientAppKeyPair;
  shared_ptr<const X509Certificate> mClientCert;
  Crypto::EphemeralKeyPair mClientEphemeral;
  Crypto::EphemeralKeyPair mServerEphemeral;
};

TEST_P(EccEncryptedSecretMultiPolicyTests, RoundTripSucceeds)
{
  ByteString nonce;
  nonce.resize(32);
  auto entropy = mCrypto->get_entropy_sync(32);
  std::memcpy(nonce.data(), entropy.data(), 32);

  ByteString secret;
  {
    constexpr string_view password = "TestSecret456!";
    secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
      reinterpret_cast<const uint8_t*>(password.data()) + password.size());
  }

  auto blob = build_valid_blob(nonce, secret);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mServerEphemeral.privateKey,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());

  auto& fields = result.value();
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.certificate, mClientCert->der_encoding());
  EXPECT_EQ(fields.senderPublicKey, mClientEphemeral.publicKey);
  EXPECT_EQ(fields.receiverPublicKey, mServerEphemeral.publicKey);
  EXPECT_EQ(fields.nonce, nonce);
  EXPECT_EQ(fields.secret, secret);
}

TEST_P(EccEncryptedSecretMultiPolicyTests, PaddingHandledCorrectly)
{
  // Choose sizes that produce non-trivial padding for CBC (block size 16):
  // Nonce: 5 bytes -> UA Binary: 4 + 5 = 9 bytes
  // Secret: 3 bytes -> UA Binary: 4 + 3 = 7 bytes
  // Total payload content: 16 bytes + 2 paddingSize = 18 -> rounds to 32 -> paddingSize = 14
  ByteString nonce;
  nonce.resize(5);
  for (size_t i = 0; i < 5; ++i)
    nonce[i] = static_cast<uint8_t>(0xC0 + i);

  ByteString secret;
  secret.resize(3);
  for (size_t i = 0; i < 3; ++i)
    secret[i] = static_cast<uint8_t>(0xD0 + i);

  auto blob = build_valid_blob(nonce, secret);

  auto result = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mServerEphemeral.privateKey,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(result.is_good()) << "Status: " << to_string(result.status_code().as_status());
  EXPECT_EQ(result.value().nonce, nonce);
  EXPECT_EQ(result.value().secret, secret);
}

INSTANTIATE_TEST_SUITE_P(EccEncryptedSecretPolicies, EccEncryptedSecretMultiPolicyTests,
  ::testing::Values(EccPolicyTestParams{SecurityPolicyId::EccNistP256AesGcm,
                      CertificateKeyAlgorithm::EccNistP256,
                      EphemeralKeyAlgorithm::EccNistP256,
                      CertificateSignatureAlgorithm::EcDsaSha2256,
                      []
                      {
                        return std::make_shared<SecPolEphemeralKey>(
                          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
                      },
                      "NistP256"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP384AesGcm,
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384AesGcm));
      },
      "NistP384"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1AesGcm));
      },
      "BrainpoolP256r1"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1AesGcm));
      },
      "BrainpoolP384r1"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP256ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP256,
      EphemeralKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256ChaChaPoly));
      },
      "NistP256ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP384ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384ChaChaPoly));
      },
      "NistP384ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly));
      },
      "BrainpoolP256r1ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly));
      },
      "BrainpoolP384r1ChaChaPoly"}),
  [](const ::testing::TestParamInfo<EccPolicyTestParams>& info) { return info.param.name; });

// ===== Encoder Tests =========================================================
//
// Exercise the encrypt_ecc_encrypted_secret() encoder by verifying round-trip
// against the existing decoder.

class EccEncryptedSecretEncoderTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    mPolicy =
      std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
    mKeys = generate_test_keys(*mCrypto);
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolEphemeralKey> mPolicy;
  TestKeyMaterial mKeys;
};

// Independent decoding of the emitted bytes prevents a shared encoder/decoder defect
// from passing a round trip. Part 4 section 7.41.2.5 Table 190 and Figure 39.
// @verifies AC-COMP-ECC-SECRET-WIRE
// @relation(AC-COMP-ECC-SECRET-WIRE, scope=function)
TEST_F(EccEncryptedSecretEncoderTests, EncodesExtensionObjectAndSignsEntireEnvelope)
{
  auto encoded = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto callback)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.publicKey,
        mKeys.clientCert,
        mKeys.clientAppKeyPair,
        ByteString{std::vector<byte>(32, byte{0x42})},
        ByteString{std::vector<byte>{byte{1}, byte{2}, byte{3}}},
        ua::Logger{},
        std::move(callback));
    });
  ASSERT_TRUE(encoded.is_good());
  const auto& blob = encoded.value();
  ASSERT_GT(blob.size(), 73u);
  const std::vector<byte> expectedPrefix{byte{1}, byte{0}, byte{0x8A}, byte{0x44}, byte{1}};
  EXPECT_TRUE(std::ranges::equal(span<const byte>{blob}.first(5), expectedPrefix));
  const uint32_t bodyLength =
    blob[5] | (uint32_t{blob[6]} << 8) | (uint32_t{blob[7]} << 16) | (uint32_t{blob[8]} << 24);
  EXPECT_EQ(bodyLength, blob.size() - 9);
  const auto signedSize = blob.size() - 64;
  EXPECT_NO_THROW(mCrypto->asymmetric_verify_sync(mPolicy->asymmetric_signature_algorithm(),
    mKeys.clientCert->public_key(),
    span<const byte>{blob}.first(signedSize),
    span<const byte>{blob}.subspan(signedSize)));

  // Independently recover the payload using the specified HKDF length, L = 16-byte AES-128 key + 12-byte IV.
  // This does not call the SDK encrypted-secret decoder.
  memory_stream_device::ExternalReadOnly device{span<const byte>{blob}};
  MemoryStream stream{device};
  stream.seek_from_start(9);
  const EncodingLimits limits;
  UaBinaryDecoder decoder{StructureResolver{}, stream, limits};
  const StackDepth depth{1024};
  String policyUri;
  ByteString certificate;
  DateTime signingTime;
  uint16_t keyDataLength = 0;
  ByteString senderKey;
  ByteString receiverKey;
  decoder.decode(depth, policyUri);
  decoder.decode(depth, certificate);
  decoder.decode(depth, signingTime);
  decoder.decode(depth, keyDataLength);
  decoder.decode(depth, senderKey);
  decoder.decode(depth, receiverKey);
  EXPECT_EQ(policyUri, mPolicy->uri());
  EXPECT_EQ(certificate, mKeys.clientCert->der_encoding());
  EXPECT_EQ(receiverKey, mKeys.serverEphemeral.publicKey);
  auto salt = build_secret_salt(28, senderKey, receiverKey);
  ASSERT_EQ(salt[0], 0x1C);
  ASSERT_EQ(salt[1], 0x00);
  const auto sharedSecret = mCrypto->calculate_shared_secret_sync(
    mPolicy->ephemeral_key_algorithm(), mKeys.serverEphemeral.privateKey, senderKey);
  const auto keyMaterial =
    mCrypto->derive_symmetric_keys_sync(mPolicy->key_derivation_algorithm(), 28, sharedSecret, salt, salt);
  // The encrypted payload is the AES-128-GCM ciphertext followed by its 16-byte tag, sealed with every header
  // - TypeId through KeyData - as the associated data (Part 6 section 6.8.3).
  const auto headers = span<const byte>{blob}.first(stream.get_position());
  const auto encryptedPayload =
    span<const byte>{blob}.subspan(stream.get_position(), signedSize - stream.get_position());
  ASSERT_GT(encryptedPayload.size(), 16u);
  const auto ciphertext = encryptedPayload.first(encryptedPayload.size() - 16);
  ByteString plaintext;
  plaintext.resize(ciphertext.size());
  mCrypto->symmetric_verify_and_decrypt_sync(SymmetricEncryptionAlgorithm::Aes128Gcm,
    span<const byte>{keyMaterial}.subspan(16, 12),
    span<const byte>{keyMaterial}.first(16),
    ciphertext,
    headers,
    encryptedPayload.last(16),
    span<byte>{plaintext});
  // Part 6 section 6.8.3 padding with BlockSize 16: Data.Length = 4 + 32 + 4 + 3 + 2 = 45 needs 3 bytes, and
  // 3 + the 3-byte secret is under a block, so the padding is 19 and the payload fills 64 bytes.
  ASSERT_EQ(plaintext.size(), 64u);
  EXPECT_EQ(plaintext[62], 19u);
  EXPECT_EQ(plaintext[63], 0u);
  for (size_t i = 43; i < 62; ++i)
    EXPECT_EQ(plaintext[i], 19u) << "padding byte " << i;
  memory_stream_device::ExternalReadOnly payloadDevice{span<const byte>{plaintext}};
  MemoryStream payloadStream{payloadDevice};
  UaBinaryDecoder payloadDecoder{StructureResolver{}, payloadStream, limits};
  ByteString nonce;
  ByteString secret;
  payloadDecoder.decode(depth, nonce);
  payloadDecoder.decode(depth, secret);
  EXPECT_EQ(nonce, ByteString{std::vector<byte>(32, byte{0x42})});
  EXPECT_EQ(secret, (ByteString{std::vector<byte>{byte{1}, byte{2}, byte{3}}}));
}

// @verifies AC-COMP-ECC-SECRET-REJECTION
// @relation(AC-COMP-ECC-SECRET-REJECTION, scope=function)
TEST_F(EccEncryptedSecretDecoderTests, TamperedSigningTimeFailsSignatureVerification)
{
  auto blob = build_valid_blob(
    ByteString{std::vector<byte>(32, byte{0x42})}, ByteString{std::vector<byte>{byte{1}, byte{2}, byte{3}}});
  // Prefix, String length/URI, and certificate length/DER precede SigningTime.
  const auto signingTimeOffset = 9 + 4 + mPolicy->uri().size() + 4 + mKeys.clientCert->der_encoding().size();
  blob[signingTimeOffset] ^= 1;
  auto decoded = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto callback)
    {
      decrypt_ecc_encrypted_secret_async(blob,
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        mKeys.serverEphemeral.publicKey,
        mKeys.clientCert,
        ua::Logger{},
        std::move(callback));
    });
  ASSERT_TRUE(decoded.is_bad());
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_TRUE(decoded.shared_detail());
}

// @verifies AC-COMP-ECC-SECRET-REJECTION
// @relation(AC-COMP-ECC-SECRET-REJECTION, scope=function)
TEST_F(EccEncryptedSecretDecoderTests, RejectsInvalidExtensionObjectFraming)
{
  const auto valid = build_valid_blob(
    ByteString{std::vector<byte>(32, byte{0x42})}, ByteString{std::vector<byte>{byte{1}, byte{2}, byte{3}}});
  // Wrong TypeId, mask, inconsistent body length and negative body length.
  std::vector<ByteString> invalidBlobs;
  for (const auto offset : {2u, 4u, 5u, 8u})
  {
    auto blob = valid;
    blob[offset] ^= 0x80;
    invalidBlobs.push_back(std::move(blob));
  }
  for (const auto lengthAdjustment : {-1, 1})
  {
    auto blob = valid;
    const auto declaredLength = static_cast<uint32_t>(valid.size() - 9 + lengthAdjustment);
    for (size_t index = 0; index < 4; ++index)
      blob[5 + index] = static_cast<uint8_t>(declaredLength >> (8 * index));
    invalidBlobs.push_back(std::move(blob));
  }
  auto truncated = valid;
  truncated.resize(9);
  invalidBlobs.push_back(std::move(truncated));
  for (size_t index = 0; index < invalidBlobs.size(); ++index)
  {
    SCOPED_TRACE(index);
    const auto& blob = invalidBlobs[index];
    auto decoded = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
      [&](auto callback)
      {
        decrypt_ecc_encrypted_secret_async(blob,
          mPolicy,
          mCrypto,
          crypto_test_strand(),
          mKeys.serverEphemeral.privateKey,
          mKeys.serverEphemeral.publicKey,
          mKeys.clientCert,
          ua::Logger{},
          std::move(callback));
      });
    ASSERT_TRUE(decoded.is_bad());
    EXPECT_EQ(decoded.status_code().as_status(), Status::BadDecodingError);
    ASSERT_TRUE(decoded.shared_detail());
  }
}

TEST_F(EccEncryptedSecretEncoderTests, EncoderRoundTripWithDecoder)
{
  // Encode using encrypt_ecc_encrypted_secret, then decrypt and verify.
  ByteString serverNonce;
  serverNonce.resize(32);
  auto entropy = mCrypto->get_entropy_sync(32);
  std::memcpy(serverNonce.data(), entropy.data(), 32);

  constexpr string_view password = "EncoderTestPassword!";
  ByteString secret;
  secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
    reinterpret_cast<const uint8_t*>(password.data()) + password.size());

  auto encryptResult = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        mKeys.clientAppKeyPair,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(encryptResult.is_good())
    << "Encrypt status: " << to_string(encryptResult.status_code().as_status());
  auto blob = std::move(encryptResult).value();

  // Decrypt: the decoder needs the server's ephemeral private key
  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(decryptResult.is_good())
    << "Decrypt status: " << to_string(decryptResult.status_code().as_status());

  auto& fields = decryptResult.value();
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.certificate, mKeys.clientCert->der_encoding());
  EXPECT_EQ(fields.receiverPublicKey, mKeys.serverEphemeral.publicKey);
  EXPECT_EQ(fields.nonce, serverNonce);
  EXPECT_EQ(fields.secret, secret);
}

TEST_F(EccEncryptedSecretEncoderTests, EncoderWithSmallPayload)
{
  // Small nonce and secret to verify padding is correctly handled.
  ByteString serverNonce;
  serverNonce.resize(4);
  for (size_t i = 0; i < 4; ++i)
    serverNonce[i] = static_cast<uint8_t>(0x10 + i);

  ByteString secret;
  secret.resize(2);
  secret[0] = uint8_t{0xAA};
  secret[1] = uint8_t{0xBB};

  auto encryptResult = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        mKeys.clientAppKeyPair,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(encryptResult.is_good());
  auto blob = std::move(encryptResult).value();

  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(decryptResult.is_good());
  EXPECT_EQ(decryptResult.value().nonce, serverNonce);
  EXPECT_EQ(decryptResult.value().secret, secret);
}

TEST_F(EccEncryptedSecretEncoderTests, EncoderWithEmptySecret)
{
  ByteString serverNonce;
  serverNonce.resize(16);

  ByteString secret;  // Empty secret

  auto encryptResult = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        mKeys.clientAppKeyPair,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(encryptResult.is_good());
  auto blob = std::move(encryptResult).value();

  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mKeys.serverEphemeral.privateKey,
        ByteString{mKeys.serverEphemeral.publicKey},
        mKeys.clientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(decryptResult.is_good());
  EXPECT_EQ(decryptResult.value().nonce, serverNonce);
  EXPECT_EQ(decryptResult.value().secret, secret);
}

// Parameterized encoder tests across the ECC curves and both RSA_DH policies. An RSA_DH secret is signed with
// the client's RSA application key, so its signature is one modulus long rather than two field elements.
class EccEncryptedSecretEncoderMultiPolicyTests : public ::testing::TestWithParam<EccPolicyTestParams>
{
protected:
  void SetUp() override
  {
    mCrypto = create_crypto();
    const auto& params = GetParam();
    mPolicy = params.createPolicy();

    mClientAppKeyPair = mCrypto->create_asymmetric_key_pair_sync(params.certKeyAlg, params.certKeyBits);

    TestPki pki{create_crypto()};
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = mClientAppKeyPair;
    certParams.issuerKeys = mClientAppKeyPair;
    certParams.subject.commonName = "TestClient";
    certParams.serialNumber = "1";
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.certificateSignatureAlgorithm = params.certSigAlg;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    mClientCert = pki.create_cert(certParams);

    mServerEphemeral = mCrypto->create_ephemeral_keys_sync(params.ephKeyAlg);
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<SecPolEphemeralKey> mPolicy;
  shared_ptr<const AsymmetricKeyPair> mClientAppKeyPair;
  shared_ptr<const X509Certificate> mClientCert;
  Crypto::EphemeralKeyPair mServerEphemeral;
};

// @relation(AC-COMP-ECC-SECRET-WIRE, scope=function)
TEST_P(EccEncryptedSecretEncoderMultiPolicyTests, EncoderDecoderRoundTrip)
{
  ByteString serverNonce;
  serverNonce.resize(32);
  auto entropy = mCrypto->get_entropy_sync(32);
  std::memcpy(serverNonce.data(), entropy.data(), 32);

  constexpr string_view password = "MultiPolicyTest!";
  ByteString secret;
  secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
    reinterpret_cast<const uint8_t*>(password.data()) + password.size());

  auto encryptResult = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        mClientAppKeyPair,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(encryptResult.is_good())
    << "Encrypt status: " << to_string(encryptResult.status_code().as_status());
  auto blob = std::move(encryptResult).value();

  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(ByteString{blob},
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mServerEphemeral.privateKey,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        ua::Logger{},
        std::move(cb));
    });

  ASSERT_TRUE(decryptResult.is_good())
    << "Decrypt status: " << to_string(decryptResult.status_code().as_status());

  auto& fields = decryptResult.value();
  EXPECT_EQ(fields.securityPolicyUri, mPolicy->uri());
  EXPECT_EQ(fields.receiverPublicKey, mServerEphemeral.publicKey);
  EXPECT_EQ(fields.nonce, serverNonce);
  EXPECT_EQ(fields.secret, secret);
}

// The same envelope with its last signature byte altered is refused by the signature check, for every
// signature form (ECDSA, EdDSA and RSA); the round trip above is the control.
// @relation(AC-COMP-ECC-SECRET-REJECTION, scope=function)
TEST_P(EccEncryptedSecretEncoderMultiPolicyTests, AnAlteredSignatureIsRefused)
{
  ByteString serverNonce;
  serverNonce.resize(32, 0x4e);
  constexpr string_view password = "MultiPolicyTest!";
  ByteString secret;
  secret.assign(reinterpret_cast<const uint8_t*>(password.data()),
    reinterpret_cast<const uint8_t*>(password.data()) + password.size());

  auto encryptResult = ua::test_helpers::run_async_function_sync<ByteStringResult>(
    [&](auto cb)
    {
      encrypt_ecc_encrypted_secret_async(mPolicy,
        mCrypto,
        crypto_test_strand(),
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        mClientAppKeyPair,
        ByteString{serverNonce},
        ByteString{secret},
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encryptResult.is_good());
  auto blob = std::move(encryptResult).value();
  blob[blob.size() - 1] ^= 0x01;

  auto decryptResult = ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(std::move(blob),
        mPolicy,
        mCrypto,
        crypto_test_strand(),
        mServerEphemeral.privateKey,
        ByteString{mServerEphemeral.publicKey},
        mClientCert,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(decryptResult.is_bad());
  EXPECT_EQ(decryptResult.status_code().as_status(), Status::BadSecurityChecksFailed);
}

INSTANTIATE_TEST_SUITE_P(EccEncryptedSecretEncoderPolicies, EccEncryptedSecretEncoderMultiPolicyTests,
  ::testing::Values(EccPolicyTestParams{SecurityPolicyId::EccNistP256AesGcm,
                      CertificateKeyAlgorithm::EccNistP256,
                      EphemeralKeyAlgorithm::EccNistP256,
                      CertificateSignatureAlgorithm::EcDsaSha2256,
                      []
                      {
                        return std::make_shared<SecPolEphemeralKey>(
                          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm));
                      },
                      "NistP256"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP384AesGcm,
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384AesGcm));
      },
      "NistP384"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1AesGcm));
      },
      "BrainpoolP256r1"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1AesGcm));
      },
      "BrainpoolP384r1"},
    EccPolicyTestParams{SecurityPolicyId::EccCurve25519ChaChaPoly,
      CertificateKeyAlgorithm::EccCurve25519,
      EphemeralKeyAlgorithm::EccCurve25519,
      CertificateSignatureAlgorithm::PureEdDsa25519,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve25519ChaChaPoly));
      },
      "Curve25519"},
    EccPolicyTestParams{SecurityPolicyId::EccCurve448ChaChaPoly,
      CertificateKeyAlgorithm::EccCurve448,
      EphemeralKeyAlgorithm::EccCurve448,
      CertificateSignatureAlgorithm::PureEdDsa448,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve448ChaChaPoly));
      },
      "Curve448"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP256ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP256,
      EphemeralKeyAlgorithm::EccNistP256,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256ChaChaPoly));
      },
      "NistP256ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccNistP384ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP384,
      EphemeralKeyAlgorithm::EccNistP384,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccNistP384ChaChaPoly));
      },
      "NistP384ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      CertificateSignatureAlgorithm::EcDsaSha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly));
      },
      "BrainpoolP256r1ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      CertificateSignatureAlgorithm::EcDsaSha2384,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly));
      },
      "BrainpoolP384r1ChaChaPoly"},
    EccPolicyTestParams{SecurityPolicyId::EccCurve25519AesGcm,
      CertificateKeyAlgorithm::EccCurve25519,
      EphemeralKeyAlgorithm::EccCurve25519,
      CertificateSignatureAlgorithm::PureEdDsa25519,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve25519AesGcm));
      },
      "Curve25519AesGcm"},
    EccPolicyTestParams{SecurityPolicyId::EccCurve448AesGcm,
      CertificateKeyAlgorithm::EccCurve448,
      EphemeralKeyAlgorithm::EccCurve448,
      CertificateSignatureAlgorithm::PureEdDsa448,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::EccCurve448AesGcm));
      },
      "Curve448AesGcm"},
    EccPolicyTestParams{SecurityPolicyId::RsaDhAesGcm,
      CertificateKeyAlgorithm::Rsa,
      EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      [] {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::RsaDhAesGcm));
      },
      "RsaDhAesGcmRsa2048",
      2048},
    EccPolicyTestParams{SecurityPolicyId::RsaDhChaChaPoly,
      CertificateKeyAlgorithm::Rsa,
      EphemeralKeyAlgorithm::RsaDhFfdhe3072,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      []
      {
        return std::make_shared<SecPolEphemeralKey>(
          *find_ephemeral_key_policy(SecurityPolicyId::RsaDhChaChaPoly));
      },
      "RsaDhChaChaPolyRsa4096",
      4096}),
  [](const ::testing::TestParamInfo<EccPolicyTestParams>& info) { return info.param.name; });

namespace
{

namespace es = ua::test::sce_vectors::encrypted_secret;
using ua::test::sce_vectors::hex_bytes;

struct IndependentSecret
{
  SecurityPolicyId policyId;
  std::string_view blob;
  uint32_t payloadOffset;
  uint32_t tagOffset;
  uint32_t signingTimeOffset;
  uint32_t paddingSize;
  std::string_view secret;
  const char* name;
};

const std::vector<IndependentSecret>& independent_secrets()
{
  static const std::vector<IndependentSecret> secrets{
    {SecurityPolicyId::EccCurve25519AesGcm,
      es::aesGcmSecret,
      es::aesGcmPayloadOffset,
      es::aesGcmTagOffset,
      es::aesGcmSigningTimeOffset,
      es::aesGcmPaddingSize,
      es::shortSecret,
      "ECC_curve25519_AesGcm"},
    {SecurityPolicyId::EccCurve25519ChaChaPoly,
      es::chaChaPolySecret,
      es::chaChaPolyPayloadOffset,
      es::chaChaPolyTagOffset,
      es::chaChaPolySigningTimeOffset,
      es::chaChaPolyPaddingSize,
      es::longSecret,
      "ECC_curve25519_ChaChaPoly"},
  };
  return secrets;
}

EccEncryptedSecretFieldsResult decrypt_independent(const IndependentSecret& vector, ByteString blob,
  const shared_ptr<const Crypto>& crypto, shared_ptr<const X509Certificate> signingCertificate)
{
  auto policy = std::make_shared<SecPolEphemeralKey>(*find_ephemeral_key_policy(vector.policyId));
  return ua::test_helpers::run_async_function_sync<EccEncryptedSecretFieldsResult>(
    [&](auto cb)
    {
      decrypt_ecc_encrypted_secret_async(std::move(blob),
        policy,
        crypto,
        crypto_test_strand(),
        hex_bytes(es::receiverPrivateKey),
        hex_bytes(es::receiverPublicKey),
        std::move(signingCertificate),
        ua::Logger{},
        std::move(cb));
    });
}

}  // namespace

// An EccEncryptedSecret built outside the SDK (with Python `cryptography`, from Part 4
// Table 183 and Part 6 6.8.3) decrypts to its nonce and secret. The vectors pad by the 6.8.3 formula - the
// AesGcm one takes the extra block a short secret gets - seal with every header as the associated data and
// put the tag after PayloadPaddingSize, so a decoder that read any of these differently fails the tag or the
// padding.
// @relation(AC-SVR-SCE-009-SECRET-LAYOUT, scope=function)
TEST(EnhancedEncryptedSecret, TheIndependentSecretDecrypts)
{
  const auto crypto = create_crypto();
  const auto certificate = crypto->read_certificate_from_der(hex_bytes(es::signingCertificate));
  for (const auto& vector : independent_secrets())
  {
    SCOPED_TRACE(vector.name);
    const auto blob = hex_bytes(vector.blob);
    ASSERT_EQ(vector.tagOffset - vector.payloadOffset,
      4 + es::nonce.size() / 2 + 4 + vector.secret.size() / 2 + vector.paddingSize + 2)
      << "the vector's payload is not Nonce | Secret | PayloadPadding | PayloadPaddingSize";
    const auto result = decrypt_independent(vector, blob, crypto, certificate);
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
    EXPECT_EQ(result.value().nonce, hex_bytes(es::nonce));
    EXPECT_EQ(result.value().secret, hex_bytes(vector.secret));
  }
}

// The same secrets with one byte altered in a header (the SigningTime), in the encrypted payload and in the
// tag. With no certificate to verify the signature against, only the AEAD tag can catch them: the header
// alteration fails it, which shows the headers are the associated data. With the signing certificate, the
// signature catches every alteration before anything is decrypted.
// @relation(AC-SVR-SCE-009-SECRET-LAYOUT, scope=function)
TEST(EnhancedEncryptedSecret, AnAlteredSecretIsRefused)
{
  const auto crypto = create_crypto();
  const auto certificate = crypto->read_certificate_from_der(hex_bytes(es::signingCertificate));
  for (const auto& vector : independent_secrets())
  {
    SCOPED_TRACE(vector.name);
    const auto intact = hex_bytes(vector.blob);
    // Control: the tag alone accepts the intact secret.
    const auto control = decrypt_independent(vector, intact, crypto, nullptr);
    ASSERT_TRUE(control.is_good()) << to_string(control.status_code().as_status());
    EXPECT_EQ(control.value().secret, hex_bytes(vector.secret));

    const std::vector<std::pair<uint32_t, const char*>> alterations{
      {vector.signingTimeOffset, "a header byte (SigningTime)"},
      {vector.payloadOffset, "a payload byte"},
      {vector.tagOffset, "a tag byte"},
    };
    for (const auto& [offset, what] : alterations)
    {
      SCOPED_TRACE(what);
      auto altered = intact;
      altered[offset] ^= 0x01;
      const auto tagOnly = decrypt_independent(vector, altered, crypto, nullptr);
      EXPECT_EQ(tagOnly.status_code().as_status(), Status::BadIdentityTokenInvalid);
      const auto withSignature = decrypt_independent(vector, altered, crypto, certificate);
      EXPECT_EQ(withSignature.status_code().as_status(), Status::BadSecurityChecksFailed);
    }
  }
}
