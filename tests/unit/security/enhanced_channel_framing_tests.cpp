// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The symmetric MessageChunk and the key set of the fourteen 1.05.07 policies through the policy layer,
// against the independent vectors of sce_vectors.h (generated with Python
// `cryptography`, from OPC 10000-6 Figure 12, Table 69 and 6.8.1).
// Which vector family belongs to which policy is written here from the profile table (plan section 1.2:
// cipher, key length and HKDF hash per policy), not read from the policy rows under test.

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <functional>
#include <future>
#include <string_view>
#include <thread>
#include <vector>

#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "run_async_sync.h"
#include "sce_vector_helpers.h"
#include "sce_vectors.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "test_utilities.h"
#include "ua_binary_codec.h"
#include "ua_crypto.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_secure_channel_context.h"
#include "ua_secure_string.h"
#include "ua_security_policy.h"
#include "ua_security_policy_test_access.h"
#include "ua_security_token.h"
#include "ua_security_token_request_type.h"
#include "ua_x509_certificate.h"

namespace
{
using namespace ua;
using namespace std::chrono_literals;
namespace vectors = ua::test::sce_vectors;
namespace chunk = ua::test::sce_vectors::chunk;
using vectors::hex_bytes;

struct Token final : public SecurityToken
{
  Token(boost::asio::strand<boost::asio::any_io_executor> strand, Keys keys, uint32_t id)
    : SecurityToken(std::move(strand), keys, keys, id, 10s, [] {})
  {}
};

// The chunk vectors of one AEAD cipher.
struct CipherVectors
{
  std::string_view name;
  SymmetricEncryptionAlgorithm algorithm;
  std::string_view key;
  std::string_view sign;
  std::string_view signAfterWrap;
  std::string_view signAndEncrypt;
  std::string_view signAndEncryptAfterWrap;
};

const CipherVectors aes128Gcm{"Aes128Gcm",
  SymmetricEncryptionAlgorithm::Aes128Gcm,
  chunk::aes128GcmKey,
  chunk::aes128GcmSignChunk,
  chunk::aes128GcmSignAfterWrapChunk,
  chunk::aes128GcmSignAndEncryptChunk,
  chunk::aes128GcmSignAndEncryptAfterWrapChunk};
const CipherVectors aes256Gcm{"Aes256Gcm",
  SymmetricEncryptionAlgorithm::Aes256Gcm,
  chunk::aes256GcmKey,
  chunk::aes256GcmSignChunk,
  chunk::aes256GcmSignAfterWrapChunk,
  chunk::aes256GcmSignAndEncryptChunk,
  chunk::aes256GcmSignAndEncryptAfterWrapChunk};
const CipherVectors chaCha20Poly1305{"ChaCha20Poly1305",
  SymmetricEncryptionAlgorithm::ChaCha20Poly1305,
  chunk::chaCha20Poly1305Key,
  chunk::chaCha20Poly1305SignChunk,
  chunk::chaCha20Poly1305SignAfterWrapChunk,
  chunk::chaCha20Poly1305SignAndEncryptChunk,
  chunk::chaCha20Poly1305SignAndEncryptAfterWrapChunk};

// The keys of one renewal in the chain, and the client key that a derivation from that renewal's secret alone
// would give instead.
struct RenewalVectors
{
  std::string_view clientKey;
  std::string_view clientIv;
  std::string_view serverKey;
  std::string_view serverIv;
  std::string_view unchainedClientKey;
};

// The derived key set of one (HKDF hash, encryption key length) pair, for the first token and two renewals.
struct KeySetVectors
{
  std::string_view name;
  std::string_view clientKey;
  std::string_view clientIv;
  std::string_view serverKey;
  std::string_view serverIv;
  std::array<RenewalVectors, 2> renewals;
};

const KeySetVectors sha256Key16{"Sha256Key16",
  vectors::keys::sha256Key16Token0ClientKey,
  vectors::keys::sha256Key16Token0ClientIv,
  vectors::keys::sha256Key16Token0ServerKey,
  vectors::keys::sha256Key16Token0ServerIv,
  {{{vectors::keys::sha256Key16Token1ClientKey,
      vectors::keys::sha256Key16Token1ClientIv,
      vectors::keys::sha256Key16Token1ServerKey,
      vectors::keys::sha256Key16Token1ServerIv,
      vectors::keys::sha256Key16Token1UnchainedClientKey},
    {vectors::keys::sha256Key16Token2ClientKey,
      vectors::keys::sha256Key16Token2ClientIv,
      vectors::keys::sha256Key16Token2ServerKey,
      vectors::keys::sha256Key16Token2ServerIv,
      vectors::keys::sha256Key16Token2UnchainedClientKey}}}};
const KeySetVectors sha256Key32{"Sha256Key32",
  vectors::keys::sha256Key32Token0ClientKey,
  vectors::keys::sha256Key32Token0ClientIv,
  vectors::keys::sha256Key32Token0ServerKey,
  vectors::keys::sha256Key32Token0ServerIv,
  {{{vectors::keys::sha256Key32Token1ClientKey,
      vectors::keys::sha256Key32Token1ClientIv,
      vectors::keys::sha256Key32Token1ServerKey,
      vectors::keys::sha256Key32Token1ServerIv,
      vectors::keys::sha256Key32Token1UnchainedClientKey},
    {vectors::keys::sha256Key32Token2ClientKey,
      vectors::keys::sha256Key32Token2ClientIv,
      vectors::keys::sha256Key32Token2ServerKey,
      vectors::keys::sha256Key32Token2ServerIv,
      vectors::keys::sha256Key32Token2UnchainedClientKey}}}};
const KeySetVectors sha384Key32{"Sha384Key32",
  vectors::keys::sha384Key32Token0ClientKey,
  vectors::keys::sha384Key32Token0ClientIv,
  vectors::keys::sha384Key32Token0ServerKey,
  vectors::keys::sha384Key32Token0ServerIv,
  {{{vectors::keys::sha384Key32Token1ClientKey,
      vectors::keys::sha384Key32Token1ClientIv,
      vectors::keys::sha384Key32Token1ServerKey,
      vectors::keys::sha384Key32Token1ServerIv,
      vectors::keys::sha384Key32Token1UnchainedClientKey},
    {vectors::keys::sha384Key32Token2ClientKey,
      vectors::keys::sha384Key32Token2ClientIv,
      vectors::keys::sha384Key32Token2ServerKey,
      vectors::keys::sha384Key32Token2ServerIv,
      vectors::keys::sha384Key32Token2UnchainedClientKey}}}};

struct PolicyCase
{
  SecurityPolicyId id;
  std::string_view name;
  const CipherVectors* cipher;
  const KeySetVectors* keySet;
};

// Plan section 1.2: AES128-GCM with HKDF-SHA2-256, ChaCha20Poly1305 (256-bit key) with HKDF-SHA2-256, and
// AES256-GCM or ChaCha20Poly1305 with HKDF-SHA2-384 (the 384-bit curves and curve448).
const std::array<PolicyCase, 14> policies{{
  {SecurityPolicyId::EccNistP256AesGcm, "EccNistP256AesGcm", &aes128Gcm, &sha256Key16},
  {SecurityPolicyId::EccNistP256ChaChaPoly, "EccNistP256ChaChaPoly", &chaCha20Poly1305, &sha256Key32},
  {SecurityPolicyId::EccNistP384AesGcm, "EccNistP384AesGcm", &aes256Gcm, &sha384Key32},
  {SecurityPolicyId::EccNistP384ChaChaPoly, "EccNistP384ChaChaPoly", &chaCha20Poly1305, &sha384Key32},
  {SecurityPolicyId::EccBrainpoolP256r1AesGcm, "EccBrainpoolP256r1AesGcm", &aes128Gcm, &sha256Key16},
  {SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    "EccBrainpoolP256r1ChaChaPoly",
    &chaCha20Poly1305,
    &sha256Key32},
  {SecurityPolicyId::EccBrainpoolP384r1AesGcm, "EccBrainpoolP384r1AesGcm", &aes256Gcm, &sha384Key32},
  {SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    "EccBrainpoolP384r1ChaChaPoly",
    &chaCha20Poly1305,
    &sha384Key32},
  {SecurityPolicyId::EccCurve25519AesGcm, "EccCurve25519AesGcm", &aes128Gcm, &sha256Key16},
  {SecurityPolicyId::EccCurve25519ChaChaPoly, "EccCurve25519ChaChaPoly", &chaCha20Poly1305, &sha256Key32},
  {SecurityPolicyId::EccCurve448AesGcm, "EccCurve448AesGcm", &aes256Gcm, &sha384Key32},
  {SecurityPolicyId::EccCurve448ChaChaPoly, "EccCurve448ChaChaPoly", &chaCha20Poly1305, &sha384Key32},
  {SecurityPolicyId::RsaDhAesGcm, "RsaDhAesGcm", &aes128Gcm, &sha256Key16},
  {SecurityPolicyId::RsaDhChaChaPoly, "RsaDhChaChaPoly", &chaCha20Poly1305, &sha256Key32},
}};

constexpr std::array modes{MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt};

const char* mode_name(MessageSecurityMode mode)
{
  return mode == MessageSecurityMode::Sign ? "Sign" : "SignAndEncrypt";
}

std::string_view vector_for(const CipherVectors& cipher, MessageSecurityMode mode, bool afterWrap)
{
  if (mode == MessageSecurityMode::Sign)
    return afterWrap ? cipher.signAfterWrap : cipher.sign;
  return afterWrap ? cipher.signAndEncryptAfterWrap : cipher.signAndEncrypt;
}

std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([] { return SecureString{"enhanced-channel-framing"}; });
}

class EnhancedChannelFraming : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  // A channel context in the Open state under @p id and @p mode whose active token is the vectors' token:
  // TokenId tokenId, the cipher's key, base IV baseIv and no signing key.
  std::shared_ptr<SecureChannelContext> make_context(
    SecurityPolicyId id, MessageSecurityMode mode, const CipherVectors& cipher)
  {
    auto context = std::make_shared<SecureChannelContext>();
    context->boundStrand = boost::asio::make_strand(mPool.get_executor());
    context->state = SecureChannelContext::State::Open;
    context->securityPolicy = SecurityPolicy::create(id);
    context->messageSecurityMode = mode;
    context->secureChannelId = chunk::channelId;
    context->encodingLimits =
      EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
    context->crypto = mCrypto;
    context->initialise_sequence_numbers(context->securityPolicy->uses_legacy_sequence_no());
    context->negotiatedLimits.sendBufferSize = 8192;
    context->negotiatedLimits.receiveBufferSize = 65536;
    SecurityToken::Keys keys;
    keys.encryptingKey = hex_bytes(cipher.key);
    keys.initializationVector = hex_bytes(chunk::baseIv);
    context->activeSecurityToken = std::make_unique<Token>(*context->boundStrand, keys, chunk::tokenId);
    return context;
  }

  // Encodes @p body as one MSG message through the policy's own symmetric encode.
  static std::pair<std::vector<ByteString>, VoidResult> encode(
    SecureChannelContext& context, uint32_t requestId, span<const byte> body)
  {
    std::vector<ByteString> chunks;
    SecurityPolicy::SendMessageChunk sink = [&chunks](ByteString c)
    {
      chunks.push_back(std::move(c));
    };
    auto result = test_helpers::run_async_callback_sync<VoidResult>(
      [&](auto callback)
      {
        test_access::SymmetricEncodeDriver::encode(
          *context.securityPolicy, context, requestId, body, sink, std::move(callback));
      });
    return {std::move(chunks), std::move(result)};
  }

  static DecodedMessageChunkResult decode(
    const std::shared_ptr<SecureChannelContext>& context, ByteString bytes)
  {
    return test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto callback) {
        context->securityPolicy->decode_message_chunk_async(context, std::move(bytes), std::move(callback));
      });
  }

  // The IV of Table 69 for the vectors' token and @p lastSequenceNumber, built here byte by byte.
  static ByteString chunk_iv(uint32_t lastSequenceNumber)
  {
    auto iv = hex_bytes(chunk::baseIv);
    for (size_t i = 0; i < 4; ++i)
    {
      iv[i] ^= static_cast<uint8_t>((chunk::tokenId >> (8 * i)) & 0xFF);
      iv[4 + i] ^= static_cast<uint8_t>((lastSequenceNumber >> (8 * i)) & 0xFF);
    }
    return iv;
  }

  // Encodes the OpenSecureChannel message of @p role on a fresh enhanced channel, then one MSG chunk, and
  // checks their sequence numbers and the MSG chunk's IV (see SequenceNumbersStartAtZero).
  void expect_sequence_numbers_start_at_zero(ChannelRole role)
  {
    const auto body = hex_bytes(chunk::body);
    auto context = make_context(SecurityPolicyId::EccNistP256AesGcm, MessageSecurityMode::Sign, aes128Gcm);
    context->state = SecureChannelContext::State::Uninitialised;
    context->secureChannelId = 0;
    context->role = role;
    context->namespaceIndexCallback = [](string_view)
    {
      return uint16_t{0};
    };
    context->negotiatedLimits.sendBufferSize = 65536;
    const auto localKeys = test_keys::key_pair(*mCrypto, test_keys::KeyType::P256, 0);
    const auto remoteKeys = test_keys::key_pair(*mCrypto, test_keys::KeyType::P256, 1);
    const auto certificate = [this](std::shared_ptr<const AsymmetricKeyPair> keys, const char* name)
    {
      Crypto::CreateCertificateConfig config;
      config.subjectKeys = config.issuerKeys = std::move(keys);
      config.subject.commonName = name;
      config.serialNumber = "7301";
      config.keyUsage.digitalSignature = true;
      config.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
      config.from = DateTime::now();
      config.to = DateTime{config.from.value() + std::chrono::days{30}};
      return TestPki{mCrypto}.create_cert(config);
    };
    context->localKeyPair = localKeys;
    context->localCertificate = certificate(localKeys, "Local");
    context->remoteCertificate = certificate(remoteKeys, "Remote");
    // A server answers a request it has verified, whose Signature its first response also covers (Part
    // 6 6.7.5).
    if (role == ChannelRole::Server)
      context->openSecureChannelRequestSignature = ByteString(64, uint8_t{0x5a});

    std::vector<ByteString> opnChunks;
    const auto opn = test_helpers::run_async_callback_sync<VoidResult>(
      [&](auto callback)
      {
        context->securityPolicy->encode_message_async(
          context,
          chunk::requestId,
          role == ChannelRole::Client
            ? std::shared_ptr<Structure>{std::make_shared<OpenSecureChannelRequest>()}
            : std::make_shared<OpenSecureChannelResponse>(),
          [&opnChunks](ByteString c) { opnChunks.push_back(std::move(c)); },
          std::move(callback));
      });
    ASSERT_TRUE(opn.is_good()) << to_string(opn.status_code().as_status());
    ASSERT_EQ(opnChunks.size(), 1u);
    {
      memory_stream_device::ExternalReadOnly device{span<const byte>{opnChunks.front()}};
      MemoryStream stream{device};
      UaBinaryDecoder decoder{StructureResolver{}, stream, context->encodingLimits};
      stack_utils::UaScMessageHeader header;
      header.decode(context->encodingLimits, decoder);
      stack_utils::AsymmetricSecurityHeader security;
      security.decode(context->encodingLimits, decoder, *mCrypto);
      stack_utils::SequenceHeader sequence;
      sequence.decode(context->encodingLimits, decoder);
      EXPECT_EQ(sequence.sequenceNumber, 0u) << "the OpenSecureChannel is the first chunk";
    }

    context->state = SecureChannelContext::State::Open;
    context->secureChannelId = chunk::channelId;
    auto [chunks, result] = encode(*context, chunk::requestId, span<const byte>{body});
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks.front(), sealed_sign_chunk(aes128Gcm, 1, 0, chunk::requestId, span<const byte>{body}));
  }

  // A Sign-mode MSG chunk sealed with the AEAD primitive (whose tags the vectors pin in
  // CryptoAeadVectors): header | token | sequence header | body | tag over everything before it.
  ByteString sealed_sign_chunk(const CipherVectors& cipher, uint32_t sequenceNumber,
    uint32_t ivLastSequenceNumber, uint32_t requestId, span<const byte> body) const
  {
    ByteString aad;
    const auto appendU32 = [&aad](uint32_t value)
    {
      for (size_t i = 0; i < 4; ++i)
        aad.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    };
    for (char c : std::string_view{"MSGF"})
      aad.push_back(static_cast<uint8_t>(c));
    appendU32(static_cast<uint32_t>(12 + 4 + 8 + body.size() + 16));
    appendU32(chunk::channelId);
    appendU32(chunk::tokenId);
    appendU32(sequenceNumber);
    appendU32(requestId);
    for (auto b : body)
      aad.push_back(static_cast<uint8_t>(b));
    const auto iv = chunk_iv(ivLastSequenceNumber);
    const auto key = hex_bytes(cipher.key);
    const auto tag = mCrypto->symmetric_encrypt_and_sign_sync(cipher.algorithm,
      span<const byte>{iv},
      span<const byte>{key},
      span<const byte>{},
      span<const byte>{aad},
      {});
    ByteString chunkBytes = aad;
    for (auto b : tag)
      chunkBytes.push_back(b);
    return chunkBytes;
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<const Crypto> mCrypto = create_crypto();
};

// Each policy encodes the vectors' body, under the vectors' token and after sequence number 7 (and after
// 0xFFFFFFFF), into exactly the independent chunk: no padding, the 16-byte tag as the footer, the body in
// the clear in Sign, and the IV of Table 69 from the PREVIOUS sequence number.
// @relation(AC-SVR-SCE-002-AEAD-ORACLE, scope=function)
// @relation(AC-SVR-SCE-003-IV-ORACLE, scope=function)
TEST_F(EnhancedChannelFraming, EveryPolicyEncodesTheIndependentChunk)
{
  const auto body = hex_bytes(chunk::body);
  for (const auto& policy : policies)
    for (const auto mode : modes)
      for (const bool afterWrap : {false, true})
      {
        SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode) + (afterWrap ? " after wrap" : ""));
        auto sender = make_context(policy.id, mode, *policy.cipher);
        sender->lastTxSequenceNumber =
          afterWrap ? chunk::lastSequenceNumberAfterWrap : chunk::lastSequenceNumber;
        sender->txChunkSent = true;
        auto [chunks, result] = encode(*sender, chunk::requestId, span<const byte>{body});
        ASSERT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
        ASSERT_EQ(chunks.size(), 1u);
        EXPECT_EQ(chunks.front(), hex_bytes(vector_for(*policy.cipher, mode, afterWrap)));
        EXPECT_EQ(
          sender->lastTxSequenceNumber, afterWrap ? chunk::sequenceNumberAfterWrap : chunk::sequenceNumber);
      }
}

// Each policy decodes the independent chunk to the vectors' request id and body.
// @relation(AC-SVR-SCE-002-AEAD-ORACLE, scope=function)
// @relation(AC-SVR-SCE-003-IV-ORACLE, scope=function)
TEST_F(EnhancedChannelFraming, EveryPolicyDecodesTheIndependentChunk)
{
  const auto body = hex_bytes(chunk::body);
  for (const auto& policy : policies)
    for (const auto mode : modes)
      for (const bool afterWrap : {false, true})
      {
        SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode) + (afterWrap ? " after wrap" : ""));
        auto receiver = make_context(policy.id, mode, *policy.cipher);
        receiver->lastRxSequenceNumber =
          afterWrap ? chunk::lastSequenceNumberAfterWrap : chunk::lastSequenceNumber;
        const auto decoded = decode(receiver, hex_bytes(vector_for(*policy.cipher, mode, afterWrap)));
        ASSERT_TRUE(decoded.is_good()) << to_string(decoded.status_code().as_status());
        ASSERT_TRUE(decoded.value().has_value());
        EXPECT_EQ(decoded.value()->first, chunk::requestId);
        EXPECT_EQ(decoded.value()->second, body);
        ASSERT_TRUE(receiver->lastRxSequenceNumber.has_value());
        EXPECT_EQ(*receiver->lastRxSequenceNumber,
          afterWrap ? chunk::sequenceNumberAfterWrap : chunk::sequenceNumber);
      }
}

// One altered byte of the message header (the chunk type), of the sequence header, of the body, or of the
// tag fails the tag check in both modes, and no body is delivered. The unaltered vector is the control.
// @relation(AC-SVR-SCE-002-TAMPER-REFUSED, scope=function)
TEST_F(EnhancedChannelFraming, AnAlteredChunkFailsTheTagCheck)
{
  for (const auto& policy : policies)
    for (const auto mode : modes)
    {
      const auto original = hex_bytes(vector_for(*policy.cipher, mode, false));
      {
        SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode) + " control");
        auto receiver = make_context(policy.id, mode, *policy.cipher);
        receiver->lastRxSequenceNumber = chunk::lastSequenceNumber;
        ASSERT_TRUE(decode(receiver, original).is_good());
      }
      // 3: the chunk type ('F'); 16: the first sequence-header byte; 30: a body byte; the tag's ends.
      for (const size_t offset :
        {size_t{3}, size_t{16}, size_t{30}, original.size() - 16, original.size() - 1})
      {
        SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode) + " offset " + std::to_string(offset));
        auto altered = original;
        altered[offset] =
          offset == 3 ? static_cast<uint8_t>('C') : static_cast<uint8_t>(altered[offset] ^ 0x01);
        auto receiver = make_context(policy.id, mode, *policy.cipher);
        receiver->lastRxSequenceNumber = chunk::lastSequenceNumber;
        const auto decoded = decode(receiver, altered);
        ASSERT_TRUE(decoded.is_bad());
        EXPECT_EQ(decoded.status_code().as_status(), Status::BadSecurityChecksFailed);
        EXPECT_TRUE(receiver->receivedMessageBody.empty());
      }
    }
}

// A chunk whose IV was built from its OWN sequence number (8) instead of the previous one (7) - the SDK's
// behaviour before owner ruling D-12 - fails the tag check under every ChaCha20Poly1305 policy. The
// correctly built vector decodes (control).
// @relation(AC-SVR-SCE-003-IV-ORACLE, scope=function)
TEST_F(EnhancedChannelFraming, AChunkEncryptedWithItsOwnSequenceNumberIsRefused)
{
  for (const auto& policy : policies)
  {
    if (policy.cipher != &chaCha20Poly1305)
      continue;
    SCOPED_TRACE(policy.name);
    auto control = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    control->lastRxSequenceNumber = chunk::lastSequenceNumber;
    ASSERT_TRUE(decode(control, hex_bytes(chunk::chaCha20Poly1305SignAndEncryptChunk)).is_good());

    auto receiver = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    receiver->lastRxSequenceNumber = chunk::lastSequenceNumber;
    const auto decoded =
      decode(receiver, hex_bytes(chunk::ownSequenceNumberChaCha20Poly1305SignAndEncryptChunk));
    ASSERT_TRUE(decoded.is_bad());
    EXPECT_EQ(decoded.status_code().as_status(), Status::BadSecurityChecksFailed);
  }
}

// A correctly sealed chunk whose sequence number skips one (9 after 7, sealed with the IV of the previous
// chunk, 7) is refused with Bad_SequenceNumberInvalid; the same chunk numbered 8 is accepted (control). A
// chunk numbered 9 whose sender believed it had sent 8 is refused by the tag, since the receiver's IV
// follows the last number it verified.
// @relation(AC-SVR-SCE-005-SEQUENCE-FROM-ZERO, scope=function)
TEST_F(EnhancedChannelFraming, ASkippedSequenceNumberIsRefused)
{
  const auto body = hex_bytes(chunk::body);
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    {
      auto receiver = make_context(policy.id, MessageSecurityMode::Sign, *policy.cipher);
      receiver->lastRxSequenceNumber = 7;
      const auto decoded =
        decode(receiver, sealed_sign_chunk(*policy.cipher, 8, 7, chunk::requestId, span<const byte>{body}));
      ASSERT_TRUE(decoded.is_good()) << "control: the next number with the previous number's IV";
      ASSERT_TRUE(decoded.value().has_value());
      EXPECT_EQ(decoded.value()->second, body);
    }
    {
      auto receiver = make_context(policy.id, MessageSecurityMode::Sign, *policy.cipher);
      receiver->lastRxSequenceNumber = 7;
      const auto decoded =
        decode(receiver, sealed_sign_chunk(*policy.cipher, 9, 7, chunk::requestId, span<const byte>{body}));
      ASSERT_TRUE(decoded.is_bad());
      EXPECT_EQ(decoded.status_code().as_status(), Status::BadSequenceNumberInvalid);
    }
    {
      auto receiver = make_context(policy.id, MessageSecurityMode::Sign, *policy.cipher);
      receiver->lastRxSequenceNumber = 7;
      const auto decoded =
        decode(receiver, sealed_sign_chunk(*policy.cipher, 9, 8, chunk::requestId, span<const byte>{body}));
      ASSERT_TRUE(decoded.is_bad());
      EXPECT_EQ(decoded.status_code().as_status(), Status::BadSecurityChecksFailed);
    }
  }
}

// On a fresh channel the OpenSecureChannel chunk carries SequenceNumber 0 in each direction (the client's
// request and the server's response), and the first symmetric chunk carries 1 and is sealed with
// LastSequenceNumber 0 (Table 69: the OpenSecureChannel is the previous chunk); the expected chunk is sealed
// independently with that IV.
// @relation(AC-SVR-SCE-005-SEQUENCE-FROM-ZERO, scope=function)
// @relation(AC-SVR-SCE-003-IV-ORACLE, scope=function)
TEST_F(EnhancedChannelFraming, SequenceNumbersStartAtZero)
{
  for (const auto role : {ChannelRole::Client, ChannelRole::Server})
  {
    SCOPED_TRACE(role == ChannelRole::Client ? "client request" : "server response");
    expect_sequence_numbers_start_at_zero(role);
  }
}

// Both modes of every policy derive, from the vectors' nonces and first shared secret, exactly the vectors'
// encryption keys and IVs with L = EncryptionKeyLength + InitializationVectorLength, and no signing key. The
// shared secret is injected through a parked crypto; HKDF runs on the real one.
// @relation(AC-SVR-SCE-004-KEY-SET, scope=function)
TEST_F(EnhancedChannelFraming, BothModesDeriveTheVectorKeySet)
{
  for (const auto& policy : policies)
    for (const auto mode : modes)
    {
      SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode));
      const auto fake = test_helpers::FakeAsyncCrypto::create();
      fake->set_park_async(true);
      auto context = make_context(policy.id, mode, *policy.cipher);
      context->crypto = fake;
      context->localEphemeralPrivateKey = ByteString{std::vector<uint8_t>{0x01}};
      auto completion = std::make_shared<std::promise<SecurityPolicy::DeriveSymmetricKeysResult>>();
      auto future = completion->get_future();
      context->securityPolicy->derive_symmetric_keys_async(context,
        hex_bytes(vectors::keys::serverNonce),
        hex_bytes(vectors::keys::clientNonce),
        ChannelRole::Server,
        [completion](auto result) { completion->set_value(std::move(result)); });
      const auto deadline = std::chrono::steady_clock::now() + 5s;
      while (
        fake->pending_calculate_shared_secret_count() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
      ASSERT_EQ(fake->pending_calculate_shared_secret_count(), 1u);
      fake->set_park_async(false);
      fake->complete_pending_calculate_shared_secret(0, ByteStringResult{hex_bytes(vectors::keys::secret0)});
      ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
      const auto derived = future.get();
      ASSERT_TRUE(derived.is_good()) << to_string(derived.status_code().as_status());
      const auto& [serverKeys, clientKeys] = derived.value();
      EXPECT_TRUE(serverKeys.signingKey.empty());
      EXPECT_TRUE(clientKeys.signingKey.empty());
      EXPECT_EQ(serverKeys.encryptingKey, hex_bytes(policy.keySet->serverKey));
      EXPECT_EQ(serverKeys.initializationVector, hex_bytes(policy.keySet->serverIv));
      EXPECT_EQ(clientKeys.encryptingKey, hex_bytes(policy.keySet->clientKey));
      EXPECT_EQ(clientKeys.initializationVector, hex_bytes(policy.keySet->clientIv));
    }
}

// Waits up to five seconds for @p condition, which another thread makes true.
template<typename Condition>
bool eventually(Condition condition)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!condition() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  return condition();
}

// Creates one token through SecurityToken::create_async, the server's side of the vectors, with @p secret
// injected as the shared secret: a parked crypto holds the shared-secret call (@p whileParked runs then) and
// HKDF then runs on the real one.
SecurityToken::CreateResult create_token_with(const std::shared_ptr<SecureChannelContext>& context,
  SecurityTokenRequestType requestType, uint32_t tokenId, ByteStringResult secret,
  const std::function<void()>& whileParked = {})
{
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_park_async(true);
  context->crypto = fake;
  context->localEphemeralPrivateKey = ByteString{std::vector<uint8_t>{0x01}};
  auto completion = std::make_shared<std::promise<SecurityToken::CreateResult>>();
  auto future = completion->get_future();
  SecurityToken::create_async(
    requestType,
    context,
    tokenId,
    std::chrono::minutes{60},
    hex_bytes(vectors::keys::serverNonce),
    hex_bytes(vectors::keys::clientNonce),
    ChannelRole::Server,
    [] {},
    [completion](SecurityToken::CreateResult result) { completion->set_value(std::move(result)); });
  if (!eventually([&] { return fake->pending_calculate_shared_secret_count() == 1; }))
    return SecurityToken::CreateResult{StatusCode{Status::BadTimeout}};
  if (whileParked)
    whileParked();
  fake->set_park_async(false);
  fake->complete_pending_calculate_shared_secret(0, std::move(secret));
  if (future.wait_for(5s) != std::future_status::ready)
    return SecurityToken::CreateResult{StatusCode{Status::BadTimeout}};
  return future.get();
}

SecurityToken::CreateResult create_token(const std::shared_ptr<SecureChannelContext>& context,
  SecurityTokenRequestType requestType, uint32_t tokenId, std::string_view secret)
{
  return create_token_with(context, requestType, tokenId, ByteStringResult{hex_bytes(secret)});
}

ByteString xor_of(std::initializer_list<std::string_view> secrets)
{
  ByteString result = hex_bytes(*secrets.begin());
  for (auto secret = secrets.begin() + 1; secret != secrets.end(); ++secret)
  {
    const auto bytes = hex_bytes(*secret);
    for (size_t i = 0; i < result.size(); ++i)
      result[i] ^= bytes[i];
  }
  return result;
}

// Part 6 6.8.1 Step 2: a renewal's input keying material is its shared secret XOR the IKM of the token before
// it. The keys of an initial token and two renewals, created through the token factory from the vectors'
// three secrets, equal the chained vectors, and the channel then holds secret0 ^ secret1 ^ secret2. The
// contrast: the Unchained rows are what a derivation from a renewal's secret alone gives, and no renewal
// derives them.
// @relation(AC-SVR-SCE-004-CHAINED-RENEW, scope=function)
TEST_F(EnhancedChannelFraming, RenewalsChainTheKeyMaterial)
{
  const std::array secrets{vectors::keys::secret0, vectors::keys::secret1, vectors::keys::secret2};
  for (const auto& policy : policies)
    for (const auto mode : modes)
    {
      SCOPED_TRACE(std::string{policy.name} + " " + mode_name(mode));
      const auto& keySet = *policy.keySet;
      auto context = make_context(policy.id, mode, *policy.cipher);
      for (size_t n = 0; n < secrets.size(); ++n)
      {
        SCOPED_TRACE("token " + std::to_string(n));
        const auto created = create_token(context,
          n == 0 ? SecurityTokenRequestType::Issue : SecurityTokenRequestType::Renew,
          static_cast<uint32_t>(100 + n),
          secrets[n]);
        ASSERT_TRUE(created.is_good()) << to_string(created.status_code().as_status());
        const auto& serverKeys = created.value()->local_keys();
        const auto& clientKeys = created.value()->remote_keys();
        if (n == 0)
        {
          EXPECT_EQ(serverKeys.encryptingKey, hex_bytes(keySet.serverKey));
          EXPECT_EQ(serverKeys.initializationVector, hex_bytes(keySet.serverIv));
          EXPECT_EQ(clientKeys.encryptingKey, hex_bytes(keySet.clientKey));
          EXPECT_EQ(clientKeys.initializationVector, hex_bytes(keySet.clientIv));
          continue;
        }
        const auto& renewal = keySet.renewals[n - 1];
        EXPECT_EQ(serverKeys.encryptingKey, hex_bytes(renewal.serverKey));
        EXPECT_EQ(serverKeys.initializationVector, hex_bytes(renewal.serverIv));
        EXPECT_EQ(clientKeys.encryptingKey, hex_bytes(renewal.clientKey));
        EXPECT_EQ(clientKeys.initializationVector, hex_bytes(renewal.clientIv));
        EXPECT_NE(clientKeys.encryptingKey, hex_bytes(renewal.unchainedClientKey));
      }
      EXPECT_EQ(context->keyAgreementIkm,
        xor_of({vectors::keys::secret0, vectors::keys::secret1, vectors::keys::secret2}));

      for (size_t n = 1; n < secrets.size(); ++n)
      {
        SCOPED_TRACE("unchained " + std::to_string(n));
        const auto fresh = make_context(policy.id, mode, *policy.cipher);
        const auto unchained = create_token(fresh, SecurityTokenRequestType::Issue, 1, secrets[n]);
        ASSERT_TRUE(unchained.is_good()) << to_string(unchained.status_code().as_status());
        EXPECT_EQ(unchained.value()->remote_keys().encryptingKey,
          hex_bytes(keySet.renewals[n - 1].unchainedClientKey));
      }
    }
}

// An Issue opens a channel, so it starts a new chain: a context that still holds key material derives the
// initial token's vector keys from secret0 alone and then holds secret0; a renewal on it chains from there.
// @relation(AC-COMP-ECC-KEY-CHAIN-STATE, scope=function)
TEST_F(EnhancedChannelFraming, AnIssueStartsANewKeyChain)
{
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    auto context = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    context->keyAgreementIkm = hex_bytes(vectors::keys::secret2);
    const auto issued = create_token(context, SecurityTokenRequestType::Issue, 100, vectors::keys::secret0);
    ASSERT_TRUE(issued.is_good()) << to_string(issued.status_code().as_status());
    EXPECT_EQ(issued.value()->remote_keys().encryptingKey, hex_bytes(policy.keySet->clientKey));
    EXPECT_EQ(issued.value()->local_keys().encryptingKey, hex_bytes(policy.keySet->serverKey));
    EXPECT_EQ(context->keyAgreementIkm, hex_bytes(vectors::keys::secret0));

    const auto renewed = create_token(context, SecurityTokenRequestType::Renew, 101, vectors::keys::secret1);
    ASSERT_TRUE(renewed.is_good()) << to_string(renewed.status_code().as_status());
    EXPECT_EQ(renewed.value()->remote_keys().encryptingKey, hex_bytes(policy.keySet->renewals[0].clientKey));
  }
}

// A renewal replaces the held key material only after both of its derivations succeed. When the second HKDF
// fails, the renewal fails with that status, and the next renewal still chains from the previous token: it
// derives the vectors' first renewal keys.
// @relation(AC-COMP-ECC-KEY-CHAIN-STATE, scope=function)
TEST_F(EnhancedChannelFraming, AFailedRenewalKeepsTheChain)
{
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    auto context = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    context->keyAgreementIkm = hex_bytes(vectors::keys::secret0);
    const auto fake = test_helpers::FakeAsyncCrypto::create();
    fake->set_park_async(true);
    context->crypto = fake;
    context->localEphemeralPrivateKey = ByteString{std::vector<uint8_t>{0x01}};
    auto completion = std::make_shared<std::promise<SecurityPolicy::DeriveSymmetricKeysResult>>();
    auto future = completion->get_future();
    context->securityPolicy->derive_symmetric_keys_async(context,
      hex_bytes(vectors::keys::serverNonce),
      hex_bytes(vectors::keys::clientNonce),
      ChannelRole::Server,
      [completion](auto result) { completion->set_value(std::move(result)); });

    ASSERT_TRUE(eventually([&] { return fake->pending_calculate_shared_secret_count() == 1; }));
    fake->complete_pending_calculate_shared_secret(0, ByteStringResult{hex_bytes(vectors::keys::secret1)});
    const auto length =
      context->securityPolicy->symmetric_encryption_key_size() + context->securityPolicy->symmetric_iv_size();
    ASSERT_TRUE(eventually([&] { return fake->pending_derive_symmetric_keys_count() == 1; }));
    fake->complete_pending_derive_symmetric_keys(0, ByteStringResult{ByteString(length, uint8_t{0x11})});
    ASSERT_TRUE(eventually([&] { return fake->pending_derive_symmetric_keys_count() == 1; }));
    fake->complete_pending_derive_symmetric_keys(0, ByteStringResult{StatusCode{Status::BadOutOfMemory}});

    ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
    const auto derived = future.get();
    EXPECT_EQ(derived.status_code(), Status::BadOutOfMemory);

    const auto next = create_token(context, SecurityTokenRequestType::Renew, 2, vectors::keys::secret1);
    ASSERT_TRUE(next.is_good()) << to_string(next.status_code().as_status());
    EXPECT_EQ(next.value()->remote_keys().encryptingKey, hex_bytes(policy.keySet->renewals[0].clientKey));
    EXPECT_EQ(next.value()->local_keys().encryptingKey, hex_bytes(policy.keySet->renewals[0].serverKey));
  }
}

// A channel that closes releases its key-agreement secrets. A renewal whose shared secret is still being
// calculated then answers Bad_SecureChannelClosed and puts nothing into the context - neither key material
// that would outlive the scrub nor keys chained from the scrubbed (empty) material.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-IN-FLIGHT-AT-CLOSE, scope=function)
TEST_F(EnhancedChannelFraming, ARenewalInFlightWhenTheChannelClosesTakesNothing)
{
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    auto context = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    const auto issued = create_token(context, SecurityTokenRequestType::Issue, 1, vectors::keys::secret0);
    ASSERT_TRUE(issued.is_good()) << to_string(issued.status_code().as_status());

    const auto renewed = create_token_with(context,
      SecurityTokenRequestType::Renew,
      2,
      ByteStringResult{hex_bytes(vectors::keys::secret1)},
      [&] { context->release_key_agreement_secrets(); });
    EXPECT_EQ(renewed.status_code(), Status::BadSecureChannelClosed);
    EXPECT_TRUE(context->keyAgreementIkm.empty());
    EXPECT_TRUE(context->localEphemeralPrivateKey.empty());
    EXPECT_EQ(context->pendingSecurityToken, nullptr);
  }
}

// The ephemeral private key is single-use: a derivation takes it out of the context when it starts and scrubs
// it on every exit. A derivation whose shared secret fails leaves no key in the context for a later
// assignment to free unscrubbed.
// @relation(AC-COMP-ECC-KEY-AGREEMENT-SECRETS-RELEASED, scope=function)
TEST_F(EnhancedChannelFraming, AFailedDerivationLeavesNoEphemeralPrivateKey)
{
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    auto context = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    const auto failed = create_token_with(context,
      SecurityTokenRequestType::Issue,
      1,
      ByteStringResult{StatusCode{Status::BadNonceInvalid}},
      [&] { EXPECT_TRUE(context->localEphemeralPrivateKey.empty()) << "taken when the derivation starts"; });
    EXPECT_EQ(failed.status_code(), Status::BadNonceInvalid);
    EXPECT_TRUE(context->localEphemeralPrivateKey.empty());
    EXPECT_TRUE(context->keyAgreementIkm.empty());
  }
}

// The held material and a new secret of one channel are the same length. When they are not, the renewal is
// refused with Bad_InternalError instead of combining a part of the secret, and the held material stays as it
// was.
// @relation(AC-COMP-ECC-KEY-CHAIN-STATE, scope=function)
TEST_F(EnhancedChannelFraming, AChainOfAnotherLengthIsRefused)
{
  const ByteString shortChain{std::vector<uint8_t>{1, 2, 3, 4, 5}};
  for (const auto& policy : policies)
  {
    SCOPED_TRACE(policy.name);
    auto context = make_context(policy.id, MessageSecurityMode::SignAndEncrypt, *policy.cipher);
    context->keyAgreementIkm = shortChain;
    const auto refused = create_token(context, SecurityTokenRequestType::Renew, 101, vectors::keys::secret1);
    EXPECT_EQ(refused.status_code(), Status::BadInternalError);
    ASSERT_NE(refused.shared_detail(), nullptr);
    EXPECT_EQ(refused.shared_detail()->code, "IkmLengthMismatch");
    EXPECT_EQ(context->keyAgreementIkm, shortChain);
  }
}

// Plan section 1.1: the four deprecated ECC policies, the two ECC policies of the Edwards curves without a
// cipher suffix, and the two pre-release names of the ChaCha20-Poly1305 Edwards policies.
constexpr std::array<std::string_view, 8> removedUris{
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaCha20Poly1305",
  "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_ChaCha20Poly1305",
};

// Each removed URI is unrecognised by the factory, the single place a URI becomes a policy: it is refused
// with the factory's Bad_InvalidArgument, as any unknown URI is.
// @relation(AC-CL-SCE-001-REMOVED-URI-UNKNOWN, scope=function)
TEST(SecurityPolicyRegistry, ARemovedEccUriIsUnknown)
{
  for (const auto uri : removedUris)
  {
    SCOPED_TRACE(uri);
    try
    {
      (void)SecurityPolicy::create(uri);
      ADD_FAILURE() << "a removed policy URI resolved to a policy";
    }
    catch (const UaException& e)
    {
      EXPECT_EQ(e.status_code().as_status(), Status::BadInvalidArgument);
    }
  }
}

// Each of the fourteen URIs resolves to a policy whose URI is the one requested and whose id resolves back to
// the same URI (control for the negative above).
// @relation(AC-CL-SCE-001-REMOVED-URI-UNKNOWN, scope=function)
TEST(SecurityPolicyRegistry, EveryEnhancedUriResolvesToItself)
{
  constexpr std::array<std::string_view, 14> suffixes{"ECC_nistP256_AesGcm",
    "ECC_nistP256_ChaChaPoly",
    "ECC_nistP384_AesGcm",
    "ECC_nistP384_ChaChaPoly",
    "ECC_brainpoolP256r1_AesGcm",
    "ECC_brainpoolP256r1_ChaChaPoly",
    "ECC_brainpoolP384r1_AesGcm",
    "ECC_brainpoolP384r1_ChaChaPoly",
    "ECC_curve25519_AesGcm",
    "ECC_curve25519_ChaChaPoly",
    "ECC_curve448_AesGcm",
    "ECC_curve448_ChaChaPoly",
    "RSA_DH_AesGcm",
    "RSA_DH_ChaChaPoly"};
  for (size_t i = 0; i < suffixes.size(); ++i)
  {
    const auto uri = std::string{"http://opcfoundation.org/UA/SecurityPolicy#"} + std::string{suffixes[i]};
    SCOPED_TRACE(uri);
    const auto byUri = SecurityPolicy::create(uri);
    ASSERT_NE(byUri, nullptr);
    EXPECT_EQ(std::string{byUri->uri()}, uri);
    EXPECT_EQ(byUri->id(), policies[i].id) << "the URI resolves to the policy of the same row of section 1.2";
    EXPECT_EQ(std::string{SecurityPolicy::create(byUri->id())->uri()}, uri);
  }
}

}  // namespace
