// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The crypto backend's AEAD and ffdhe3072 primitives against independent vectors (sce_vectors.h, computed
// with Python `cryptography`).

#include "sce_vector_helpers.h"
#include "sce_vectors.h"
#include "ua_crypto.h"
#include "ua_exceptions.h"
#include "ua_secure_string.h"
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

using namespace ua;
namespace v = ua::test::sce_vectors;

namespace
{

std::shared_ptr<const Crypto> make_crypto()
{
  return create_default_crypto([]() { return SecureString{""}; });
}

// The status a call throws, or nothing when it returns.
template<typename F>
std::optional<Status> thrown_status(F&& call)
{
  try
  {
    call();
  }
  catch (const UaException& e)
  {
    return e.status();
  }
  return std::nullopt;
}

span<const byte> view(const ByteString& bytes)
{
  return span<const byte>{reinterpret_cast<const byte*>(bytes.data()), bytes.size()};
}

ByteString slice(const ByteString& bytes, size_t offset, size_t length)
{
  return ByteString(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
    bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
}

struct ChunkCase
{
  std::string name;
  SymmetricEncryptionAlgorithm algorithm;
  std::string_view key;
  std::string_view chunk;
  std::string_view iv;
  uint32_t sequenceNumber;
  bool signOnly;
};

std::vector<ChunkCase> chunk_cases()
{
  using A = SymmetricEncryptionAlgorithm;
  namespace c = v::chunk;
  return {
    {"Aes128GcmSign", A::Aes128Gcm, c::aes128GcmKey, c::aes128GcmSignChunk, c::iv, c::sequenceNumber, true},
    {"Aes128GcmSignAfterWrap",
      A::Aes128Gcm,
      c::aes128GcmKey,
      c::aes128GcmSignAfterWrapChunk,
      c::ivAfterWrap,
      c::sequenceNumberAfterWrap,
      true},
    {"Aes128GcmEncrypt",
      A::Aes128Gcm,
      c::aes128GcmKey,
      c::aes128GcmSignAndEncryptChunk,
      c::iv,
      c::sequenceNumber,
      false},
    {"Aes256GcmSign", A::Aes256Gcm, c::aes256GcmKey, c::aes256GcmSignChunk, c::iv, c::sequenceNumber, true},
    {"Aes256GcmEncrypt",
      A::Aes256Gcm,
      c::aes256GcmKey,
      c::aes256GcmSignAndEncryptChunk,
      c::iv,
      c::sequenceNumber,
      false},
    {"Aes256GcmEncryptAfterWrap",
      A::Aes256Gcm,
      c::aes256GcmKey,
      c::aes256GcmSignAndEncryptAfterWrapChunk,
      c::ivAfterWrap,
      c::sequenceNumberAfterWrap,
      false},
    {"ChaChaSign",
      A::ChaCha20Poly1305,
      c::chaCha20Poly1305Key,
      c::chaCha20Poly1305SignChunk,
      c::iv,
      c::sequenceNumber,
      true},
    {"ChaChaEncrypt",
      A::ChaCha20Poly1305,
      c::chaCha20Poly1305Key,
      c::chaCha20Poly1305SignAndEncryptChunk,
      c::iv,
      c::sequenceNumber,
      false},
    {"ChaChaEncryptAfterWrap",
      A::ChaCha20Poly1305,
      c::chaCha20Poly1305Key,
      c::chaCha20Poly1305SignAndEncryptAfterWrapChunk,
      c::ivAfterWrap,
      c::sequenceNumberAfterWrap,
      false},
  };
}

// Part 6 Figure 12: the message header (12 bytes) and the symmetric security header (4 bytes) are the
// associated data of an encrypted chunk; the sequence header and body are its payload.
constexpr size_t headersSize = 16;
constexpr size_t tagSize = 16;

// The plaintext an encrypted vector chunk carries: the sequence header and the body.
ByteString chunk_plaintext(uint32_t sequenceNumber)
{
  ByteString plain;
  for (uint32_t value : {sequenceNumber, v::chunk::requestId})
  {
    for (int shift = 0; shift < 32; shift += 8)
    {
      plain.push_back(static_cast<uint8_t>(value >> shift));
    }
  }
  for (uint8_t b : v::hex_bytes(v::chunk::body))
  {
    plain.push_back(b);
  }
  return plain;
}

}  // namespace

// Each AEAD algorithm, in Sign and SignAndEncrypt, produces exactly the tag and ciphertext of the independent
// chunk from the same key, IV, associated data and payload; in Sign the payload is empty.
// @relation(AC-COMP-CRYPTO-SCE-AEAD-ORACLE, scope=function)
TEST(CryptoAeadVectors, EncryptAndSignMatchesTheIndependentChunk)
{
  const auto crypto = make_crypto();
  for (const auto& tc : chunk_cases())
  {
    SCOPED_TRACE(tc.name);
    const auto key = v::hex_bytes(tc.key);
    const auto iv = v::hex_bytes(tc.iv);
    const auto chunk = v::hex_bytes(tc.chunk);
    const auto tag = slice(chunk, chunk.size() - tagSize, tagSize);
    if (tc.signOnly)
    {
      const auto aad = slice(chunk, 0, chunk.size() - tagSize);
      const auto produced =
        crypto->symmetric_encrypt_and_sign_sync(tc.algorithm, view(iv), view(key), {}, view(aad), {});
      EXPECT_EQ(produced, tag);
    }
    else
    {
      const auto aad = slice(chunk, 0, headersSize);
      const auto plain = chunk_plaintext(tc.sequenceNumber);
      ByteString cipher;
      cipher.resize(plain.size());
      const auto produced = crypto->symmetric_encrypt_and_sign_sync(tc.algorithm,
        view(iv),
        view(key),
        view(plain),
        view(aad),
        span<byte>{reinterpret_cast<byte*>(cipher.data()), cipher.size()});
      EXPECT_EQ(produced, tag);
      EXPECT_EQ(cipher, slice(chunk, headersSize, plain.size()));
    }
  }
}

// The independent chunks verify, and the encrypted ones decrypt to their sequence header and body.
// @relation(AC-COMP-CRYPTO-SCE-AEAD-ORACLE, scope=function)
TEST(CryptoAeadVectors, VerifyAndDecryptOpensTheIndependentChunk)
{
  const auto crypto = make_crypto();
  for (const auto& tc : chunk_cases())
  {
    SCOPED_TRACE(tc.name);
    const auto key = v::hex_bytes(tc.key);
    const auto iv = v::hex_bytes(tc.iv);
    const auto chunk = v::hex_bytes(tc.chunk);
    const auto tag = slice(chunk, chunk.size() - tagSize, tagSize);
    if (tc.signOnly)
    {
      const auto aad = slice(chunk, 0, chunk.size() - tagSize);
      EXPECT_EQ(thrown_status(
                  [&]
                  {
                    crypto->symmetric_verify_and_decrypt_sync(
                      tc.algorithm, view(iv), view(key), {}, view(aad), view(tag), {});
                  }),
        std::nullopt);
    }
    else
    {
      const auto aad = slice(chunk, 0, headersSize);
      const auto cipher = slice(chunk, headersSize, chunk.size() - headersSize - tagSize);
      ByteString plain;
      plain.resize(cipher.size());
      EXPECT_EQ(thrown_status(
                  [&]
                  {
                    crypto->symmetric_verify_and_decrypt_sync(tc.algorithm,
                      view(iv),
                      view(key),
                      view(cipher),
                      view(aad),
                      view(tag),
                      span<byte>{reinterpret_cast<byte*>(plain.data()), plain.size()});
                  }),
        std::nullopt);
      EXPECT_EQ(plain, chunk_plaintext(tc.sequenceNumber));
    }
  }
}

// One altered byte of the associated data, the sequence header, the body, or the first or last byte of the
// tag fails verification with Bad_SecurityChecksFailed, for every algorithm and both payload shapes, and
// leaves no decrypted byte in the caller's buffer.
// @relation(AC-COMP-CRYPTO-SCE-AEAD-TAMPER, scope=function)
TEST(CryptoAeadVectors, AnAlteredByteFailsTheTag)
{
  // The sequence header follows the 16 header bytes; the body follows the 8-byte sequence header.
  constexpr size_t bodyStart = headersSize + 8;
  const auto crypto = make_crypto();
  for (const auto& tc : chunk_cases())
  {
    const auto key = v::hex_bytes(tc.key);
    const auto iv = v::hex_bytes(tc.iv);
    const auto original = v::hex_bytes(tc.chunk);
    const size_t payloadEnd = original.size() - tagSize;
    for (size_t position : {size_t{5}, headersSize + 3, bodyStart + 2, payloadEnd, payloadEnd + tagSize - 1})
    {
      SCOPED_TRACE(tc.name + " byte " + std::to_string(position));
      auto chunk = original;
      chunk[position] ^= uint8_t{0x01};
      const auto tag = slice(chunk, payloadEnd, tagSize);
      std::optional<Status> status;
      if (tc.signOnly)
      {
        const auto aad = slice(chunk, 0, payloadEnd);
        status = thrown_status(
          [&]
          {
            crypto->symmetric_verify_and_decrypt_sync(
              tc.algorithm, view(iv), view(key), {}, view(aad), view(tag), {});
          });
      }
      else
      {
        const auto aad = slice(chunk, 0, headersSize);
        const auto cipher = slice(chunk, headersSize, payloadEnd - headersSize);
        // Pre-filled, so a buffer the refusal did not wipe still shows non-zero bytes.
        ByteString plain(cipher.size(), uint8_t{0xEE});
        status = thrown_status(
          [&]
          {
            crypto->symmetric_verify_and_decrypt_sync(tc.algorithm,
              view(iv),
              view(key),
              view(cipher),
              view(aad),
              view(tag),
              span<byte>{reinterpret_cast<byte*>(plain.data()), plain.size()});
          });
        EXPECT_EQ(plain, ByteString(cipher.size(), uint8_t{0})) << "no unauthenticated byte may remain";
      }
      EXPECT_EQ(status, Status::BadSecurityChecksFailed);
    }
  }
}

// The SDK's ffdhe3072 agreement computes the independent shared secret from either side's private key and
// the other side's public value, including a secret whose leading byte is zero and a peer public value whose
// leading byte is zero.
// @relation(AC-SVR-SCE-007-FFDHE-ORACLE, scope=function)
TEST(CryptoFfdhe3072, AgreementMatchesTheIndependentVectors)
{
  const auto crypto = make_crypto();
  const auto expected = v::hex_bytes(v::ffdhe::sharedSecret);
  ASSERT_EQ(expected.size(), 384u);
  ASSERT_EQ(expected[0], 0u) << "the vector must exercise the zero padding";
  const auto publicC = v::hex_bytes(v::ffdhe::publicC);
  ASSERT_EQ(publicC.size(), 384u);
  ASSERT_EQ(publicC[0], 0u) << "the vector must exercise a peer value with a leading zero byte";

  EXPECT_EQ(crypto->calculate_shared_secret_sync(EphemeralKeyAlgorithm::RsaDhFfdhe3072,
              view(v::hex_bytes(v::ffdhe::privateA)),
              view(v::hex_bytes(v::ffdhe::publicB))),
    expected);
  EXPECT_EQ(crypto->calculate_shared_secret_sync(EphemeralKeyAlgorithm::RsaDhFfdhe3072,
              view(v::hex_bytes(v::ffdhe::privateB)),
              view(v::hex_bytes(v::ffdhe::publicA))),
    expected);
  EXPECT_EQ(crypto->calculate_shared_secret_sync(
              EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(v::hex_bytes(v::ffdhe::privateA)), view(publicC)),
    v::hex_bytes(v::ffdhe::sharedSecretAC));

  // 2^c mod p through the same exponentiation: the generated public value of C, leading zero kept.
  ByteString two(384, uint8_t{0});
  two[383] = 2;
  EXPECT_EQ(crypto->calculate_shared_secret_sync(
              EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(v::hex_bytes(v::ffdhe::privateC)), view(two)),
    publicC);
}

// Generated keys have the shape of Part 6 Table 72: a 384-byte public value and a 275-bit private
// exponent; two generated pairs agree on one 384-byte secret.
// @relation(AC-SVR-SCE-007-FFDHE-ORACLE, scope=function)
TEST(CryptoFfdhe3072, GeneratedKeysHaveTheTable72Shape)
{
  const auto crypto = make_crypto();
  const auto client = crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::RsaDhFfdhe3072);
  const auto server = crypto->create_ephemeral_keys_sync(EphemeralKeyAlgorithm::RsaDhFfdhe3072);
  for (const auto* pair : {&client, &server})
  {
    EXPECT_EQ(pair->publicKey.size(), 384u);
    ASSERT_EQ(pair->privateKey.size(), 35u);
    // 275 bits in 35 bytes: the top five bits are clear and bit 274 is set.
    EXPECT_EQ(pair->privateKey[0] & 0xF8u, 0u);
    EXPECT_NE(pair->privateKey[0] & 0x04u, 0u);
  }
  EXPECT_NE(client.publicKey, server.publicKey);

  // The public value is 2^x mod p: the generator is 2, as Table 72 names it.
  ByteString two(384, uint8_t{0});
  two[383] = 2;
  for (const auto* pair : {&client, &server})
  {
    EXPECT_EQ(crypto->calculate_shared_secret_sync(
                EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(pair->privateKey), view(two)),
      pair->publicKey);
  }

  const auto clientSecret = crypto->calculate_shared_secret_sync(
    EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(client.privateKey), view(server.publicKey));
  const auto serverSecret = crypto->calculate_shared_secret_sync(
    EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(server.privateKey), view(client.publicKey));
  EXPECT_EQ(clientSecret.size(), 384u);
  EXPECT_EQ(clientSecret, serverSecret);
}

// A peer value that is not 384 bytes, or is outside 2 to p - 2, is refused with Bad_NonceInvalid; the
// bounds themselves are accepted.
// @relation(AC-SVR-SCE-007-BAD-NONCE-REFUSED, scope=function)
TEST(CryptoFfdhe3072, AnInvalidPeerValueIsRefused)
{
  const auto crypto = make_crypto();
  const auto privateKey = v::hex_bytes(v::ffdhe::privateA);
  const auto agree = [&](const ByteString& peer)
  {
    return thrown_status(
      [&]
      {
        (void)crypto->calculate_shared_secret_sync(
          EphemeralKeyAlgorithm::RsaDhFfdhe3072, view(privateKey), view(peer));
      });
  };
  const auto value = [](uint8_t last)
  {
    ByteString bytes(384, uint8_t{0});
    bytes[383] = last;
    return bytes;
  };
  const auto prime = v::hex_bytes(v::ffdhe::prime);
  const auto primeMinusOne = v::hex_bytes(v::ffdhe::primeMinusOne);
  auto primeMinusTwo = primeMinusOne;
  primeMinusTwo[383] = static_cast<uint8_t>(primeMinusTwo[383] - 1);

  // Each wrong length encodes the in-range value 2, so only the length check can refuse it.
  for (size_t length : {size_t{0}, size_t{256}, size_t{383}, size_t{385}, size_t{512}})
  {
    SCOPED_TRACE("length " + std::to_string(length));
    ByteString wrongLength(length, uint8_t{0});
    if (length > 0)
    {
      wrongLength[length - 1] = 2;
    }
    EXPECT_EQ(agree(wrongLength), Status::BadNonceInvalid);
  }
  EXPECT_EQ(agree(value(0)), Status::BadNonceInvalid);
  EXPECT_EQ(agree(value(1)), Status::BadNonceInvalid);
  EXPECT_EQ(agree(primeMinusOne), Status::BadNonceInvalid);
  EXPECT_EQ(agree(prime), Status::BadNonceInvalid);

  EXPECT_EQ(agree(value(2)), std::nullopt);
  EXPECT_EQ(agree(primeMinusTwo), std::nullopt);
}
