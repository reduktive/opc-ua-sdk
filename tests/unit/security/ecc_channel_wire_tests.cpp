// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The independent oracles use the OpenSSL 1.1 API, which OpenSSL 3 still provides at this compatibility
// level, so one source serves both supported OpenSSL versions. It must precede every OpenSSL header.
#define OPENSSL_API_COMPAT 10100

#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
#include <array>
#include <future>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "run_async_sync.h"
#include "sce_vectors.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_memory_stream.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_secure_channel_context.h"
#include "ua_secure_string.h"
#include "ua_x509_certificate.h"
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <thread>

namespace
{
using namespace ua;
using KeyOwner = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContextOwner = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using CipherContextOwner = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using BigNumOwner = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

struct CurveCase
{
  EphemeralKeyAlgorithm algorithm;
  SecurityPolicyId policy;
  std::string group;
  int curveId;
  size_t fieldBytes;
  std::string name;
  test_keys::KeyType certificateType;
};

const std::array<CurveCase, 6> curves{{{EphemeralKeyAlgorithm::EccNistP256,
                                         SecurityPolicyId::EccNistP256AesGcm,
                                         "prime256v1",
                                         NID_X9_62_prime256v1,
                                         32,
                                         "NistP256",
                                         test_keys::KeyType::P256},
  {EphemeralKeyAlgorithm::EccNistP384,
    SecurityPolicyId::EccNistP384AesGcm,
    "secp384r1",
    NID_secp384r1,
    48,
    "NistP384",
    test_keys::KeyType::P384},
  {EphemeralKeyAlgorithm::EccBrainpoolP256r1,
    SecurityPolicyId::EccBrainpoolP256r1AesGcm,
    "brainpoolP256r1",
    NID_brainpoolP256r1,
    32,
    "BrainpoolP256",
    test_keys::KeyType::Bp256},
  {EphemeralKeyAlgorithm::EccBrainpoolP384r1,
    SecurityPolicyId::EccBrainpoolP384r1AesGcm,
    "brainpoolP384r1",
    NID_brainpoolP384r1,
    48,
    "BrainpoolP384",
    test_keys::KeyType::Bp384},
  {EphemeralKeyAlgorithm::EccCurve25519,
    SecurityPolicyId::EccCurve25519ChaChaPoly,
    "X25519",
    0,
    32,
    "Curve25519",
    test_keys::KeyType::Ed25519},
  {EphemeralKeyAlgorithm::EccCurve448,
    SecurityPolicyId::EccCurve448ChaChaPoly,
    "X448",
    0,
    56,
    "Curve448",
    test_keys::KeyType::Ed448}}};

enum class Cipher
{
  Aes128Gcm,
  Aes256Gcm,
  ChaCha20Poly1305
};

// One row per policy of plan section 1.2, written from the profile table rather than read from the policy
// rows under test: the key exchange (no curve: RSA_DH in the ffdhe3072 group), the AEAD cipher and the HKDF
// hash.
struct PolicyCase
{
  SecurityPolicyId id;
  const CurveCase* curve;
  Cipher cipher;
  bool hkdfSha384;
  std::string name;
};

const std::array<PolicyCase, 14> policies{{
  {SecurityPolicyId::EccNistP256AesGcm, &curves[0], Cipher::Aes128Gcm, false, "NistP256AesGcm"},
  {SecurityPolicyId::EccNistP256ChaChaPoly,
    &curves[0],
    Cipher::ChaCha20Poly1305,
    false,
    "NistP256ChaChaPoly"},
  {SecurityPolicyId::EccNistP384AesGcm, &curves[1], Cipher::Aes256Gcm, true, "NistP384AesGcm"},
  {SecurityPolicyId::EccNistP384ChaChaPoly, &curves[1], Cipher::ChaCha20Poly1305, true, "NistP384ChaChaPoly"},
  {SecurityPolicyId::EccBrainpoolP256r1AesGcm, &curves[2], Cipher::Aes128Gcm, false, "BrainpoolP256AesGcm"},
  {SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
    &curves[2],
    Cipher::ChaCha20Poly1305,
    false,
    "BrainpoolP256ChaChaPoly"},
  {SecurityPolicyId::EccBrainpoolP384r1AesGcm, &curves[3], Cipher::Aes256Gcm, true, "BrainpoolP384AesGcm"},
  {SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
    &curves[3],
    Cipher::ChaCha20Poly1305,
    true,
    "BrainpoolP384ChaChaPoly"},
  {SecurityPolicyId::EccCurve25519AesGcm, &curves[4], Cipher::Aes128Gcm, false, "Curve25519AesGcm"},
  {SecurityPolicyId::EccCurve25519ChaChaPoly,
    &curves[4],
    Cipher::ChaCha20Poly1305,
    false,
    "Curve25519ChaChaPoly"},
  {SecurityPolicyId::EccCurve448AesGcm, &curves[5], Cipher::Aes256Gcm, true, "Curve448AesGcm"},
  {SecurityPolicyId::EccCurve448ChaChaPoly, &curves[5], Cipher::ChaCha20Poly1305, true, "Curve448ChaChaPoly"},
  {SecurityPolicyId::RsaDhAesGcm, nullptr, Cipher::Aes128Gcm, false, "RsaDhAesGcm"},
  {SecurityPolicyId::RsaDhChaChaPoly, nullptr, Cipher::ChaCha20Poly1305, false, "RsaDhChaChaPoly"},
}};

EphemeralKeyAlgorithm ephemeral_algorithm(const PolicyCase& policy)
{
  return policy.curve != nullptr ? policy.curve->algorithm : EphemeralKeyAlgorithm::RsaDhFfdhe3072;
}

size_t key_length(Cipher cipher)
{
  return cipher == Cipher::Aes128Gcm ? 16 : 32;
}

void require_openssl(bool success)
{
  if (!success)
    throw std::runtime_error{"Independent OpenSSL oracle failed"};
}

// The OpenSSL key type of an Edwards curve's key agreement.
int edwards_key_type(const CurveCase& curve)
{
  return curve.fieldBytes == 32 ? EVP_PKEY_X25519 : EVP_PKEY_X448;
}

KeyOwner private_key(const CurveCase& curve, const ByteString& encoded)
{
  if (curve.curveId != 0)
  {
    auto input = encoded.data();
    return KeyOwner{d2i_AutoPrivateKey(nullptr, &input, static_cast<long>(encoded.size())), EVP_PKEY_free};
  }
  return KeyOwner{
    EVP_PKEY_new_raw_private_key(edwards_key_type(curve), nullptr, encoded.data(), encoded.size()),
    EVP_PKEY_free};
}

ByteString public_wire(const CurveCase& curve, EVP_PKEY& key)
{
  if (curve.curveId != 0)
  {
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(&key);
    require_openssl(ec != nullptr);
    std::vector<unsigned char> sec1(1 + 2 * curve.fieldBytes);
    require_openssl(EC_POINT_point2oct(EC_KEY_get0_group(ec),
                      EC_KEY_get0_public_key(ec),
                      POINT_CONVERSION_UNCOMPRESSED,
                      sec1.data(),
                      sec1.size(),
                      nullptr) == sec1.size() &&
                    sec1.front() == 4);
    ByteString raw;
    raw.assign(sec1.data() + 1, sec1.data() + sec1.size());
    return raw;
  }
  size_t size = 0;
  require_openssl(EVP_PKEY_get_raw_public_key(&key, nullptr, &size) == 1);
  ByteString raw;
  raw.resize(size);
  require_openssl(EVP_PKEY_get_raw_public_key(&key, raw.data(), &size) == 1);
  return raw;
}

KeyOwner peer_key(CurveCase curve, const ByteString& raw)
{
  if (curve.curveId == 0)
    return KeyOwner{
      EVP_PKEY_new_raw_public_key(edwards_key_type(curve), nullptr, raw.data(), raw.size()), EVP_PKEY_free};
  std::vector<unsigned char> sec1{4};
  sec1.insert(sec1.end(), raw.begin(), raw.end());
  std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec{EC_KEY_new_by_curve_name(curve.curveId), EC_KEY_free};
  require_openssl(ec && EC_KEY_oct2key(ec.get(), sec1.data(), sec1.size(), nullptr) == 1);
  KeyOwner owner{EVP_PKEY_new(), EVP_PKEY_free};
  require_openssl(owner && EVP_PKEY_set1_EC_KEY(owner.get(), ec.get()) == 1);
  return owner;
}

ByteString agreement(EVP_PKEY& local, EVP_PKEY& peer)
{
  KeyContextOwner context{EVP_PKEY_CTX_new(&local, nullptr), EVP_PKEY_CTX_free};
  require_openssl(context && EVP_PKEY_derive_init(context.get()) == 1 &&
                  EVP_PKEY_derive_set_peer(context.get(), &peer) == 1);
  size_t size = 0;
  require_openssl(EVP_PKEY_derive(context.get(), nullptr, &size) == 1);
  ByteString secret;
  secret.resize(size);
  require_openssl(EVP_PKEY_derive(context.get(), secret.data(), &size) == 1);
  secret.resize(size);
  return secret;
}

// base^exponent modulo the RFC 7919 ffdhe3072 prime, as 384 big-endian bytes (Part 6 6.9, Table 72).
ByteString ffdhe3072_power(const ByteString& base, const ByteString& exponent)
{
  BIGNUM* prime = nullptr;
  require_openssl(BN_hex2bn(&prime, std::string{test::sce_vectors::ffdhe::prime}.c_str()) != 0);
  const BigNumOwner primeOwner{prime, BN_free};
  const BigNumOwner baseValue{BN_bin2bn(base.data(), static_cast<int>(base.size()), nullptr), BN_free};
  const BigNumOwner exponentValue{
    BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr), BN_free};
  const BigNumOwner result{BN_new(), BN_free};
  std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> context{BN_CTX_new(), BN_CTX_free};
  require_openssl(baseValue && exponentValue && result && context &&
                  BN_mod_exp(result.get(), baseValue.get(), exponentValue.get(), prime, context.get()) == 1);
  ByteString out;
  out.resize(384);
  require_openssl(BN_bn2binpad(result.get(), out.data(), static_cast<int>(out.size())) == 384);
  return out;
}

// The nonces and the shared secret of one key exchange, computed outside the SDK from the two private keys.
struct IndependentExchange
{
  ByteString localNonce;
  ByteString remoteNonce;
  ByteString secret;
};

IndependentExchange independent_exchange(
  const PolicyCase& policy, const Crypto::EphemeralKeyPair& local, const Crypto::EphemeralKeyPair& remote)
{
  if (policy.curve == nullptr)
  {
    const ByteString generator{std::vector<uint8_t>{2}};
    auto remoteNonce = ffdhe3072_power(generator, remote.privateKey);
    auto secret = ffdhe3072_power(remoteNonce, local.privateKey);
    return {ffdhe3072_power(generator, local.privateKey), std::move(remoteNonce), std::move(secret)};
  }
  const auto localKey = private_key(*policy.curve, local.privateKey);
  const auto remoteKey = private_key(*policy.curve, remote.privateKey);
  require_openssl(localKey && remoteKey);
  return {public_wire(*policy.curve, *localKey),
    public_wire(*policy.curve, *remoteKey),
    agreement(*localKey, *remoteKey)};
}

ByteString leading_four_point(const CurveCase& curve)
{
  std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group{
    EC_GROUP_new_by_curve_name(curve.curveId), EC_GROUP_free};
  require_openssl(bool(group));
  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point{EC_POINT_new(group.get()), EC_POINT_free};
  std::unique_ptr<BIGNUM, decltype(&BN_free)> scalar{BN_new(), BN_free};
  require_openssl(point && scalar);
  std::vector<unsigned char> sec1(1 + 2 * curve.fieldBytes);
  // A deterministic finite search over public test scalars; no random retries.
  for (unsigned long value = 1; value <= 4096; ++value)
  {
    require_openssl(BN_set_word(scalar.get(), value) == 1 &&
                    EC_POINT_mul(group.get(), point.get(), scalar.get(), nullptr, nullptr, nullptr) == 1);
    require_openssl(
      EC_POINT_point2oct(
        group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, sec1.data(), sec1.size(), nullptr) ==
      sec1.size());
    if (sec1[1] == 4)
    {
      ByteString raw;
      raw.assign(sec1.data() + 1, sec1.data() + sec1.size());
      return raw;
    }
  }
  throw std::runtime_error{"No leading-four test coordinate found within deterministic bound"};
}

class EccEphemeralWireTests : public testing::TestWithParam<CurveCase>
{};

class EccWeierstrassWireTests : public testing::TestWithParam<CurveCase>
{};

// @relation(AC-COMP-ECC-SIGNATURE-DATA, scope=function)
TEST_P(EccEphemeralWireTests, SignatureDataOmitsAlgorithmWithoutDisablingSignatures)
{
  const auto policy = SecurityPolicy::create(GetParam().policy);
  EXPECT_TRUE(policy->asymmetric_signature_algorithm_uri().empty());
  EXPECT_NE(policy->asymmetric_signature_algorithm(), AsymmetricSignatureAlgorithm::Invalid);
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccEphemeralWireTests, PublicExportMatchesIndependentOpenSsl)
{
  const auto crypto = create_default_crypto();
  const auto generated = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  const auto key = private_key(GetParam(), generated.privateKey);
  ASSERT_TRUE(key);
  EXPECT_EQ(generated.publicKey, public_wire(GetParam(), *key));
  EXPECT_EQ(generated.publicKey.size(), GetParam().fieldBytes * (GetParam().curveId ? 2 : 1));
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccEphemeralWireTests, AgreementMatchesIndependentOpenSsl)
{
  const auto crypto = create_default_crypto();
  const auto local = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  const auto remote = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  const auto localKey = private_key(GetParam(), local.privateKey);
  const auto remoteKey = private_key(GetParam(), remote.privateKey);
  ASSERT_TRUE(localKey && remoteKey);
  const auto raw = public_wire(GetParam(), *remoteKey);
  EXPECT_EQ(crypto->calculate_shared_secret_sync(GetParam().algorithm, local.privateKey, raw),
    agreement(*localKey, *remoteKey));
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccWeierstrassWireTests, PolicyAdvertisesRawCoordinateLength)
{
  EXPECT_EQ(SecurityPolicy::create(GetParam().policy)->nonce_length(), 2 * GetParam().fieldBytes);
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccWeierstrassWireTests, RawLeadingFourCoordinateIsNotStripped)
{
  const auto crypto = create_default_crypto();
  const auto local = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  const auto key = private_key(GetParam(), local.privateKey);
  ASSERT_TRUE(key);
  const auto raw = leading_four_point(GetParam());
  ASSERT_EQ(raw[0], 4);
  const auto remote = peer_key(GetParam(), raw);
  EXPECT_EQ(crypto->calculate_shared_secret_sync(GetParam().algorithm, local.privateKey, raw),
    agreement(*key, *remote));
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccWeierstrassWireTests, MalformedLengthsAreRejectedWithDetail)
{
  const auto crypto = create_default_crypto();
  const auto local = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  const auto key = private_key(GetParam(), local.privateKey);
  ASSERT_TRUE(key);
  const auto raw = public_wire(GetParam(), *key);
  ByteString sec1;
  sec1.push_back(4);
  for (const auto value : raw)
  {
    sec1.push_back(value);
  }
  ByteString shortKey = raw;
  shortKey.resize(raw.size() - 1);
  ByteString longKey = raw;
  longKey.push_back(1);
  for (const auto& malformed : {ByteString{}, shortKey, longKey, sec1})
  {
    try
    {
      crypto->calculate_shared_secret_sync(GetParam().algorithm, local.privateKey, malformed);
      ADD_FAILURE() << "Malformed public key accepted: " << malformed.size();
    }
    catch (const UaException& error)
    {
      EXPECT_EQ(error.status(), Status::BadInvalidArgument);
      ASSERT_NE(error.detail(), nullptr);
      EXPECT_EQ(error.detail()->code, malformed.empty() ? "InvalidInput" : "InvalidKeySize");
    }
  }
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-EPHEMERAL, scope=function)
TEST_P(EccWeierstrassWireTests, InvalidPointIsRejectedWithDetail)
{
  const auto crypto = create_default_crypto();
  const auto local = crypto->create_ephemeral_keys_sync(GetParam().algorithm);
  ByteString zero;
  zero.resize(GetParam().fieldBytes * 2);
  try
  {
    crypto->calculate_shared_secret_sync(GetParam().algorithm, local.privateKey, zero);
    FAIL() << "Invalid all-zero curve point accepted";
  }
  catch (const UaException& error)
  {
    EXPECT_NE(error.status(), Status::Good);
    EXPECT_NE(error.detail(), nullptr);
  }
}

struct RecipientCase
{
  PolicyCase policy;
  MessageSecurityMode mode;
  ChannelRole role;
  std::string name;
};

void PrintTo(const RecipientCase& recipient, std::ostream* os)
{
  *os << recipient.name;
}

std::vector<RecipientCase> recipient_cases()
{
  std::vector<RecipientCase> result;
  for (const auto& policy : policies)
    for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
      for (const auto role : {ChannelRole::Client, ChannelRole::Server})
        result.push_back({policy,
          mode,
          role,
          policy.name + (mode == MessageSecurityMode::Sign ? "Sign" : "Encrypt") +
            (role == ChannelRole::Client ? "Client" : "Server")});
  return result;
}

// Every policy in both modes, from the client's side: the handshake tests build both ends themselves.
std::vector<RecipientCase> client_cases()
{
  std::vector<RecipientCase> result;
  for (const auto& recipient : recipient_cases())
    if (recipient.role == ChannelRole::Client)
      result.push_back(recipient);
  return result;
}

// The RSA_DH cases in which this side is the client, so encode() produces an OpenSecureChannel request.
std::vector<RecipientCase> rsa_dh_client_cases()
{
  std::vector<RecipientCase> result;
  for (const auto& recipient : recipient_cases())
    if (recipient.policy.curve == nullptr && recipient.role == ChannelRole::Client)
      result.push_back(recipient);
  return result;
}

ByteString independent_thumbprint(const X509Certificate& certificate)
{
  const auto der = certificate.der_encoding();
  ByteString hash;
  hash.resize(20);
  unsigned int size = 0;
  require_openssl(
    EVP_Digest(der.data(), der.size(), hash.data(), &size, EVP_sha1(), nullptr) == 1 && size == 20);
  return hash;
}

class EccRecipientWireTests : public testing::TestWithParam<RecipientCase>
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([] { return SecureString{"native-ecc-unit"}; });
    mContext = make_context(GetParam().role);
    const auto keyType = GetParam().policy.curve != nullptr ? GetParam().policy.curve->certificateType
                                                            : test_keys::KeyType::Rsa2048;
    mLocalKeys = test_keys::key_pair(*mCrypto, keyType, 0);
    mRemoteKeys = test_keys::key_pair(*mCrypto, keyType, 1);
    mLocalCertificate = make_certificate(mLocalKeys, "Local", "7101");
    mRemoteCertificate = make_certificate(mRemoteKeys, "Remote", "7102");
    mContext->localKeyPair = mLocalKeys;
    mContext->localCertificate = mLocalCertificate;
    mContext->remoteCertificate = mRemoteCertificate;
    mStore = test_helpers::FakeCertificateStore::create();
    mContext->certStore = mStore;
  }

  void TearDown() override
  {
    mContext.reset();
    mPool.stop();
    mPool.join();
  }

  shared_ptr<SecureChannelContext> make_context(ChannelRole role)
  {
    auto context = std::make_shared<SecureChannelContext>();
    context->boundStrand = boost::asio::make_strand(mPool.get_executor());
    context->role = role;
    context->state = SecureChannelContext::State::Uninitialised;
    context->crypto = mCrypto;
    context->securityPolicy = SecurityPolicy::create(GetParam().policy.id);
    context->messageSecurityMode = GetParam().mode;
    context->encodingLimits =
      EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
    context->negotiatedLimits = {.sendBufferSize = 65536,
      .receiveBufferSize = 65536,
      .sendMaxMessageSize = 1u << 20,
      .sendMaxChunkCount = 100,
      .recvMaxMessageSize = 1u << 20,
      .recvMaxChunkCount = 100};
    context->namespaceIndexCallback = [](string_view)
    {
      return uint16_t{0};
    };
    context->initialise_sequence_numbers(false);
    // Every context starts as if its first OpenSecureChannel request had been exchanged, so that a server
    // end can sign, and a client end can check, a first response (Part 6 6.7.5). The handshake tests
    // replace it with the Signature of a real request.
    context->openSecureChannelRequestSignature = ByteString{std::vector<uint8_t>(64, 0x5a)};
    return context;
  }

  shared_ptr<const X509Certificate> make_certificate(
    shared_ptr<const AsymmetricKeyPair> keys, const std::string& name, const std::string& serial)
  {
    Crypto::CreateCertificateConfig config;
    config.subjectKeys = config.issuerKeys = std::move(keys);
    config.subject.commonName = name;
    config.serialNumber = serial;
    config.keyUsage.digitalSignature = true;
    config.keyUsage.nonRepudiation = true;
    config.keyUsage.serverAuth = true;
    config.keyUsage.clientAuth = true;
    const auto* curve = GetParam().policy.curve;
    if (curve == nullptr)
      config.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    else
      config.certificateSignatureAlgorithm =
        curve->curveId != 0 ? (curve->fieldBytes == 32 ? CertificateSignatureAlgorithm::EcDsaSha2256
                                                       : CertificateSignatureAlgorithm::EcDsaSha2384)
                            : (curve->fieldBytes == 32 ? CertificateSignatureAlgorithm::PureEdDsa25519
                                                       : CertificateSignatureAlgorithm::PureEdDsa448);
    config.from = DateTime::now();
    config.to = DateTime{config.from.value() + std::chrono::days{365}};
    return TestPki{mCrypto}.create_cert(config);
  }

  std::pair<VoidResult, std::vector<ByteString>> encode(shared_ptr<Structure> message, uint32_t requestId)
  {
    return encode_on(mContext, std::move(message), requestId);
  }

  static std::pair<VoidResult, std::vector<ByteString>> encode_on(
    shared_ptr<SecureChannelContext> context, shared_ptr<Structure> message, uint32_t requestId)
  {
    auto chunks = std::make_shared<std::vector<ByteString>>();
    auto result = test_helpers::run_async_callback_sync<VoidResult>(
      [context, message, requestId, chunks](auto callback)
      {
        context->securityPolicy->encode_message_async(
          context,
          requestId,
          message,
          [chunks](auto chunk) { chunks->push_back(std::move(chunk)); },
          std::move(callback));
      });
    return {std::move(result), std::move(*chunks)};
  }

  // Encodes this side's OpenSecureChannel message.
  std::pair<VoidResult, std::vector<ByteString>> encode()
  {
    if (GetParam().role == ChannelRole::Client)
      return encode(std::make_shared<OpenSecureChannelRequest>(), 71);
    return encode(std::make_shared<OpenSecureChannelResponse>(), 71);
  }

  stack_utils::AsymmetricSecurityHeader read_header(const ByteString& chunk)
  {
    memory_stream_device::ExternalReadOnly device{span<const byte>{chunk}};
    MemoryStream stream{device};
    UaBinaryDecoder decoder{StructureResolver{}, stream, mContext->encodingLimits};
    stack_utils::UaScMessageHeader header;
    header.decode(mContext->encodingLimits, decoder);
    stack_utils::AsymmetricSecurityHeader security;
    security.decode(mContext->encodingLimits, decoder, *mCrypto);
    return security;
  }

  // An unsigned OpenSecureChannel chunk from @p sender (by default the remote certificate) naming
  // @p recipient.
  ByteString unsigned_chunk(const ByteString& recipient, shared_ptr<const X509Certificate> sender = nullptr)
  {
    memory_stream_device::Dynamic device{65536, true};
    MemoryStream stream{device};
    UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
    stack_utils::AsymmetricSecurityHeader security;
    security.securityPolicyUri = mContext->securityPolicy->uri();
    security.senderCertificate = sender != nullptr ? std::move(sender) : mRemoteCertificate;
    security.receiverCertificateThumbprint = recipient;
    stack_utils::UaScMessageHeader header;
    header.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
    header.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
    header.encode(mContext->encodingLimits, encoder);
    security.encode(mContext->encodingLimits, encoder);
    stack_utils::SequenceHeader sequence;
    sequence.sequenceNumber = 0;
    sequence.requestId = 71;
    sequence.encode(mContext->encodingLimits, encoder);
    const auto size = stream.get_position();
    header.messageChunkSize = static_cast<uint32_t>(size);
    stream.seek_from_start(0);
    header.encode(mContext->encodingLimits, encoder);
    auto storage = device.move_storage_out();
    storage.resize(size);
    return ByteString{span<const byte>{storage}};
  }

  DecodedMessageChunkResult decode(ByteString chunk)
  {
    return decode_on(mContext, std::move(chunk));
  }

  static DecodedMessageChunkResult decode_on(shared_ptr<SecureChannelContext> context, ByteString chunk)
  {
    return test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [context, chunk = std::move(chunk)](auto callback) mutable {
        context->securityPolicy->decode_message_chunk_async(context, std::move(chunk), std::move(callback));
      });
  }

  boost::asio::thread_pool mPool{2};
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<SecureChannelContext> mContext;
  shared_ptr<test_helpers::FakeCertificateStore> mStore;
  shared_ptr<const AsymmetricKeyPair> mLocalKeys;
  shared_ptr<const AsymmetricKeyPair> mRemoteKeys;
  shared_ptr<const X509Certificate> mLocalCertificate;
  shared_ptr<const X509Certificate> mRemoteCertificate;
};

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
// @relation(AC-SVR-SCE-008-RSA-DH-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, EncoderIncludesExactRemoteIdentity)
{
  const auto [result, chunks] = encode();
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(chunks.size(), 1);
  EXPECT_EQ(
    read_header(chunks[0]).receiverCertificateThumbprint, independent_thumbprint(*mRemoteCertificate));
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, EncoderWithoutRemoteCertificateFails)
{
  mContext->remoteCertificate.reset();
  const auto [result, chunks] = encode();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadCertificateInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MissingReceiverCertificate");
  EXPECT_TRUE(chunks.empty());
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
// @relation(AC-SVR-SCE-008-RSA-DH-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, DecoderRejectsInvalidIdentitiesBeforeAdoption)
{
  auto shortHash = independent_thumbprint(*mLocalCertificate);
  shortHash.resize(19);
  auto longHash = independent_thumbprint(*mLocalCertificate);
  longHash.push_back(1);
  for (const auto& hash : {ByteString{},
         ByteString{std::vector<uint8_t>{}},
         shortHash,
         longHash,
         independent_thumbprint(*mRemoteCertificate)})
  {
    mContext->remoteCertificate.reset();
    const auto result = decode(unsigned_chunk(hash));
    EXPECT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), Status::BadCertificateInvalid);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "ReceiverCertificateThumbprintUnknown");
    EXPECT_EQ(mContext->remoteCertificate, nullptr);
    EXPECT_EQ(mStore->validateCallCount, 0);
  }
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, DecoderWithoutLocalCertificateFails)
{
  const auto chunk = unsigned_chunk(independent_thumbprint(*mLocalCertificate));
  mContext->localCertificate.reset();
  mContext->remoteCertificate.reset();
  const auto result = decode(chunk);
  EXPECT_EQ(result.status_code(), Status::BadCertificateInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "MissingReceiverCertificate");
  EXPECT_EQ(mContext->remoteCertificate, nullptr);
  EXPECT_EQ(mStore->validateCallCount, 0);
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, MatchingRecipientRetainsCertificateValidation)
{
  mStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted,
    make_error_detail("NativeTrustFailure", "Controlled certificate validation failure", "EccWireTest")};
  const auto result = decode(unsigned_chunk(independent_thumbprint(*mLocalCertificate)));
  EXPECT_EQ(result.status_code(), Status::BadCertificateUntrusted);
  EXPECT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(mStore->validateCallCount, 1);
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
// @relation(AC-SVR-SCE-008-RSA-DH-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, MatchingRecipientAcceptsRealSignature)
{
  const auto [result, chunks] = encode();
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(chunks.size(), 1);
  mContext = make_context(GetParam().role == ChannelRole::Client ? ChannelRole::Server : ChannelRole::Client);
  mContext->localCertificate = mRemoteCertificate;
  mContext->remoteCertificate = mLocalCertificate;
  mContext->certStore = mStore;
  const auto decoded = decode(chunks[0]);
  EXPECT_TRUE(decoded.is_good()) << std::hex << decoded.status_code().as_uint32();
  EXPECT_EQ(mStore->validateCallCount, 1);
}

// @relation(AC-COMP-ECC-CHANNEL-WIRE-RECIPIENT, scope=function)
TEST_P(EccRecipientWireTests, MatchingRecipientDoesNotBypassSignatureValidation)
{
  auto [result, chunks] = encode();
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(chunks.size(), 1);
  auto& chunk = chunks[0];
  chunk[chunk.size() - 1] ^= 1;
  mContext = make_context(GetParam().role == ChannelRole::Client ? ChannelRole::Server : ChannelRole::Client);
  mContext->localCertificate = mRemoteCertificate;
  mContext->remoteCertificate = mLocalCertificate;
  mContext->certStore = mStore;
  const auto decoded = decode(std::move(chunk));
  EXPECT_TRUE(decoded.is_bad());
  // Part 6 6.7.6: a Signature that does not verify is reported as Bad_SecurityChecksFailed. RATIFICATION
  // PENDING (plan G-26): this arm expected Bad_ApplicationSignatureInvalid.
  EXPECT_EQ(decoded.status_code(), Status::BadSecurityChecksFailed);
  EXPECT_NE(decoded.shared_detail(), nullptr);
  EXPECT_EQ(mStore->validateCallCount, 1);
}

// A certificate validation is acted on only when Good: an Uncertain verdict refuses the OpenSecureChannel
// chunk with Bad_SecurityChecksFailed and the CryptoAnswerUncertain ErrorDetail whose inner status is the
// Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_P(EccRecipientWireTests, AnUncertainCertificateValidationIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  mStore->validateCertificateStatus = uncertain;
  const auto result = decode(unsigned_chunk(independent_thumbprint(*mLocalCertificate)));
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.shared_detail()->innerStatus, uncertain.value());
  EXPECT_EQ(mStore->validateCallCount, 1);
}

// A signature is accepted only on a Good verification: an Uncertain answer refuses the OpenSecureChannel
// chunk with Bad_SecurityChecksFailed and the CryptoAnswerUncertain ErrorDetail whose inner status is the
// Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_P(EccRecipientWireTests, AnUncertainSignatureVerificationIsRefused)
{
  const auto [encoded, chunks] = encode();
  ASSERT_TRUE(encoded.is_good());
  ASSERT_EQ(chunks.size(), 1);
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_asymmetric_verify_answer(uncertain);
  mContext = make_context(GetParam().role == ChannelRole::Client ? ChannelRole::Server : ChannelRole::Client);
  mContext->localCertificate = mRemoteCertificate;
  mContext->remoteCertificate = mLocalCertificate;
  mContext->certStore = mStore;
  mContext->crypto = fake;
  const auto result = decode(chunks[0]);
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.shared_detail()->innerStatus, uncertain.value());
}

// An OpenSecureChannel chunk is sent only with a Good signature: an Uncertain sign answer refuses the message
// with Bad_ApplicationSignatureInvalid and the CryptoAnswerUncertain ErrorDetail whose inner status is the
// Uncertain code, and no chunk is sent.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_P(EccRecipientWireTests, AnUncertainSignAnswerIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_asymmetric_sign_failure(uncertain);
  mContext->crypto = fake;
  const auto [result, chunks] = encode();
  EXPECT_EQ(result.status_code().as_status(), Status::BadApplicationSignatureInvalid);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  EXPECT_TRUE(chunks.empty());
}

class RsaDhRecipient : public EccRecipientWireTests
{};

// The client's RSA_DH OpenSecureChannel request names the server by the SHA1 thumbprint of its certificate
// (Part 6 Table 58). The server refuses a request that names no recipient, a 19-byte thumbprint or the
// thumbprint of another certificate before it adopts the sender or validates anything, and accepts the real
// request (control).
// @relation(AC-SVR-SCE-008-RSA-DH-RECIPIENT, scope=function)
TEST_P(RsaDhRecipient, AnRsaDhRequestForAnotherRecipientIsRefused)
{
  const auto [result, chunks] = encode();
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(chunks.size(), 1);
  const auto serverThumbprint = independent_thumbprint(*mRemoteCertificate);
  EXPECT_EQ(read_header(chunks[0]).receiverCertificateThumbprint, serverThumbprint);

  // The server's side: its own certificate is the one the client holds as remote.
  const auto becomeServer = [this]
  {
    mContext = make_context(ChannelRole::Server);
    mContext->localCertificate = mRemoteCertificate;
    mContext->certStore = mStore;
  };
  auto shortHash = serverThumbprint;
  shortHash.resize(19);
  for (const auto& hash : {ByteString{}, shortHash, independent_thumbprint(*mLocalCertificate)})
  {
    becomeServer();
    const auto refused = decode(unsigned_chunk(hash, mLocalCertificate));
    EXPECT_EQ(refused.status_code(), Status::BadCertificateInvalid);
    ASSERT_NE(refused.shared_detail(), nullptr);
    EXPECT_EQ(refused.shared_detail()->code, "ReceiverCertificateThumbprintUnknown");
    EXPECT_EQ(mContext->remoteCertificate, nullptr);
  }
  EXPECT_EQ(mStore->validateCallCount, 0);

  becomeServer();
  const auto accepted = decode(chunks[0]);
  EXPECT_TRUE(accepted.is_good()) << std::hex << accepted.status_code().as_uint32();
  EXPECT_EQ(mStore->validateCallCount, 1);
}

// Verifies @p signature over @p data with the public key of @p certificate, outside the SDK:
// RSA-PKCS15-SHA2-256 for RSA_DH, ECDSA over SHA2-256 or SHA2-384 with the r|s encoding of Part 6 for the
// Weierstrass curves, and PureEdDSA for the Edwards curves.
bool independent_verify(const PolicyCase& policy, const X509Certificate& certificate, span<const byte> data,
  span<const byte> signature)
{
  const auto der = certificate.der_encoding();
  const auto* cursor = reinterpret_cast<const unsigned char*>(der.data());
  std::unique_ptr<X509, decltype(&X509_free)> x509{
    d2i_X509(nullptr, &cursor, static_cast<long>(der.size())), X509_free};
  require_openssl(bool(x509));
  EVP_PKEY* key = X509_get0_pubkey(x509.get());
  require_openssl(key != nullptr);

  const EVP_MD* digest = nullptr;
  const auto* signatureBytes = reinterpret_cast<const unsigned char*>(signature.data());
  std::vector<unsigned char> encoded(signatureBytes, signatureBytes + signature.size());
  if (policy.curve == nullptr)
  {
    digest = EVP_sha256();
  }
  else if (policy.curve->curveId != 0)
  {
    const auto fieldBytes = policy.curve->fieldBytes;
    digest = fieldBytes == 32 ? EVP_sha256() : EVP_sha384();
    if (signature.size() != 2 * fieldBytes)
      return false;
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> pair{ECDSA_SIG_new(), ECDSA_SIG_free};
    require_openssl(bool(pair));
    BIGNUM* r = BN_bin2bn(signatureBytes, static_cast<int>(fieldBytes), nullptr);
    BIGNUM* s = BN_bin2bn(signatureBytes + fieldBytes, static_cast<int>(fieldBytes), nullptr);
    require_openssl(r != nullptr && s != nullptr && ECDSA_SIG_set0(pair.get(), r, s) == 1);
    const int size = i2d_ECDSA_SIG(pair.get(), nullptr);
    require_openssl(size > 0);
    encoded.resize(static_cast<size_t>(size));
    auto* out = encoded.data();
    require_openssl(i2d_ECDSA_SIG(pair.get(), &out) == size);
  }
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  require_openssl(bool(context) && EVP_DigestVerifyInit(context.get(), nullptr, digest, nullptr, key) == 1);
  return EVP_DigestVerify(context.get(),
           encoded.data(),
           encoded.size(),
           reinterpret_cast<const unsigned char*>(data.data()),
           data.size()) == 1;
}

// The length of the Signature the fixture's keys make: one 2048-bit modulus for RSA_DH, 64 or 114 bytes for
// Ed25519 or Ed448, and r|s for the Weierstrass curves.
size_t independent_signature_size(const PolicyCase& policy)
{
  if (policy.curve == nullptr)
    return 256;
  if (policy.curve->curveId == 0)
    return policy.curve->fieldBytes == 32 ? 64 : 114;
  return 2 * policy.curve->fieldBytes;
}

// The two ends of one SecureChannel, each with its own context: the client holds the local certificate and
// the server the remote one. The OpenSecureChannel exchange runs through the policy's real encoders and
// decoders.
class EnhancedChannelHandshake : public EccRecipientWireTests
{
protected:
  shared_ptr<SecureChannelContext> client_end()
  {
    auto context = make_context(ChannelRole::Client);
    context->localKeyPair = mLocalKeys;
    context->localCertificate = mLocalCertificate;
    context->remoteCertificate = mRemoteCertificate;
    context->certStore = mStore;
    context->openSecureChannelRequestSignature = {};
    return context;
  }

  shared_ptr<SecureChannelContext> server_end()
  {
    auto context = make_context(ChannelRole::Server);
    context->localKeyPair = mRemoteKeys;
    context->localCertificate = mRemoteCertificate;
    context->certStore = mStore;
    context->openSecureChannelRequestSignature = {};
    return context;
  }

  // Encodes one OpenSecureChannel message on @p context, which must fit one chunk.
  static ByteString open_chunk(
    const shared_ptr<SecureChannelContext>& context, bool request, uint32_t requestId)
  {
    auto [result, chunks] = request
                              ? encode_on(context, std::make_shared<OpenSecureChannelRequest>(), requestId)
                              : encode_on(context, std::make_shared<OpenSecureChannelResponse>(), requestId);
    EXPECT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
    EXPECT_EQ(chunks.size(), 1u);
    return chunks.empty() ? ByteString{} : std::move(chunks.front());
  }

  // The Signature that ends @p chunk; empty (and a test failure) when the chunk is shorter than one.
  span<const byte> signature_of(const ByteString& chunk) const
  {
    const auto size = independent_signature_size(GetParam().policy);
    if (chunk.size() < size)
    {
      ADD_FAILURE() << "a chunk of " << chunk.size() << " bytes holds no " << size << "-byte Signature";
      return {};
    }
    return span<const byte>{chunk}.subspan(chunk.size() - size);
  }

  span<const byte> signed_bytes_of(const ByteString& chunk) const
  {
    const auto size = independent_signature_size(GetParam().policy);
    if (chunk.size() < size)
    {
      ADD_FAILURE() << "a chunk of " << chunk.size() << " bytes holds no " << size << "-byte Signature";
      return {};
    }
    return span<const byte>{chunk}.first(chunk.size() - size);
  }

  // Encodes one OpenSecureChannel message on @p context with a send buffer @p shrinkBy bytes smaller than the
  // single chunk it needs, so that it takes two.
  static std::vector<ByteString> open_chunks_split(
    const shared_ptr<SecureChannelContext>& context, bool request, uint32_t requestId, size_t singleChunkSize)
  {
    constexpr size_t shrinkBy = 40;
    context->negotiatedLimits.sendBufferSize = static_cast<uint32_t>(singleChunkSize - shrinkBy);
    auto [result, chunks] = request
                              ? encode_on(context, std::make_shared<OpenSecureChannelRequest>(), requestId)
                              : encode_on(context, std::make_shared<OpenSecureChannelResponse>(), requestId);
    EXPECT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
    return chunks;
  }
};

// Part 6 6.7.5: the server signs its first response over the response bytes followed by the Signature of the
// first request, which are not sent. Checked outside the SDK, the Signature verifies over that concatenation
// and not over the response bytes alone, and it is the server's ChannelThumbprint. The response to a renewal
// is signed over its own bytes and leaves the ChannelThumbprint as it was.
// @relation(AC-SVR-SCE-006-RESPONSE-SIGNS-REQUEST, scope=function)
TEST_P(EnhancedChannelHandshake, TheFirstResponseSignsTheRequestSignature)
{
  const auto client = client_end();
  const auto server = server_end();
  const auto request = open_chunk(client, true, 71);
  ASSERT_FALSE(request.empty());
  const auto accepted = decode_on(server, request);
  ASSERT_TRUE(accepted.is_good()) << std::hex << accepted.status_code().as_uint32();
  const ByteString requestSignature{signature_of(request)};
  EXPECT_EQ(server->openSecureChannelRequestSignature, requestSignature);

  const auto response = open_chunk(server, false, 71);
  ASSERT_FALSE(response.empty());
  ByteString bound{signed_bytes_of(response)};
  for (const auto value : requestSignature)
    bound.push_back(value);
  EXPECT_TRUE(independent_verify(GetParam().policy, *mRemoteCertificate, bound, signature_of(response)));
  EXPECT_FALSE(independent_verify(
    GetParam().policy, *mRemoteCertificate, signed_bytes_of(response), signature_of(response)));
  EXPECT_EQ(server->channelThumbprint, ByteString{signature_of(response)});

  const auto thumbprint = server->channelThumbprint;
  const auto renewal = open_chunk(server, false, 72);
  ASSERT_FALSE(renewal.empty());
  EXPECT_TRUE(independent_verify(
    GetParam().policy, *mRemoteCertificate, signed_bytes_of(renewal), signature_of(renewal)));
  EXPECT_EQ(server->channelThumbprint, thumbprint);
}

// The client checks its first response over the request Signature (Part 6 6.7.5). A response signed over its
// own bytes only - what a server end that took the exchange for a renewal produces - is refused with
// Bad_SecurityChecksFailed and sets no ChannelThumbprint; the response signed over the request Signature is
// accepted and its Signature becomes the client's ChannelThumbprint.
// @relation(AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED, scope=function)
TEST_P(EnhancedChannelHandshake, AFirstResponseNotBoundToTheRequestIsRefused)
{
  const auto client = client_end();
  const auto request = open_chunk(client, true, 71);
  ASSERT_FALSE(request.empty());

  const auto unboundServer = server_end();
  ASSERT_TRUE(decode_on(unboundServer, request).is_good());
  unboundServer->channelThumbprint = ByteString{std::vector<uint8_t>{0x01}};
  const auto unbound = open_chunk(unboundServer, false, 71);
  ASSERT_FALSE(unbound.empty());
  // The stimulus is unbound and otherwise valid: its Signature verifies over the response bytes alone.
  ASSERT_TRUE(independent_verify(
    GetParam().policy, *mRemoteCertificate, signed_bytes_of(unbound), signature_of(unbound)));
  const auto refused = decode_on(client, unbound);
  EXPECT_EQ(refused.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "FirstResponseSignatureInvalid");
  EXPECT_TRUE(client->channelThumbprint.empty());

  const auto boundServer = server_end();
  ASSERT_TRUE(decode_on(boundServer, request).is_good());
  const auto bound = open_chunk(boundServer, false, 71);
  ASSERT_FALSE(bound.empty());
  const auto accepted = decode_on(client, bound);
  EXPECT_TRUE(accepted.is_good()) << std::hex << accepted.status_code().as_uint32();
  EXPECT_EQ(client->channelThumbprint, ByteString{signature_of(bound)});
  EXPECT_EQ(client->channelThumbprint, boundServer->channelThumbprint);
}

// Both ends of one exchange hold the same ChannelThumbprint, the Signature of the first response, and the
// same request Signature. A renewal exchange is signed and checked over its own bytes in both directions and
// changes neither end's ChannelThumbprint or recorded request Signature.
// @relation(AC-SVR-SCE-006-RESPONSE-SIGNS-REQUEST, scope=function)
// @relation(AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED, scope=function)
TEST_P(EnhancedChannelHandshake, BothEndsKeepTheChannelThumbprintAcrossARenewal)
{
  const auto client = client_end();
  const auto server = server_end();
  const auto request = open_chunk(client, true, 71);
  ASSERT_FALSE(request.empty());
  ASSERT_TRUE(decode_on(server, request).is_good());
  const auto response = open_chunk(server, false, 71);
  ASSERT_FALSE(response.empty());
  const auto opened = decode_on(client, response);
  ASSERT_TRUE(opened.is_good()) << std::hex << opened.status_code().as_uint32();
  ASSERT_FALSE(client->channelThumbprint.empty());
  EXPECT_EQ(client->channelThumbprint, server->channelThumbprint);
  EXPECT_EQ(client->openSecureChannelRequestSignature, server->openSecureChannelRequestSignature);
  const auto thumbprint = client->channelThumbprint;
  const auto requestSignature = client->openSecureChannelRequestSignature;

  const auto renewRequest = open_chunk(client, true, 72);
  ASSERT_FALSE(renewRequest.empty());
  EXPECT_TRUE(independent_verify(
    GetParam().policy, *mLocalCertificate, signed_bytes_of(renewRequest), signature_of(renewRequest)));
  const auto renewAccepted = decode_on(server, renewRequest);
  EXPECT_TRUE(renewAccepted.is_good()) << std::hex << renewAccepted.status_code().as_uint32();
  const auto renewResponse = open_chunk(server, false, 72);
  ASSERT_FALSE(renewResponse.empty());
  const auto renewed = decode_on(client, renewResponse);
  EXPECT_TRUE(renewed.is_good()) << std::hex << renewed.status_code().as_uint32();

  EXPECT_EQ(client->channelThumbprint, thumbprint);
  EXPECT_EQ(server->channelThumbprint, thumbprint);
  EXPECT_EQ(client->openSecureChannelRequestSignature, requestSignature);
  EXPECT_EQ(server->openSecureChannelRequestSignature, requestSignature);
}

// A first exchange that does not fit one chunk (plan G-27). The request Signature both ends record is the
// Signature of the request's last chunk. Every chunk of the first response is signed over its own bytes
// followed by that Signature, which an independent verifier confirms, and the client accepts each. On both
// ends the ChannelThumbprint is the Signature of the response's last chunk.
// @relation(AC-SVR-SCE-006-RESPONSE-SIGNS-REQUEST, scope=function)
// @relation(AC-CL-SCE-006-UNBOUND-RESPONSE-REFUSED, scope=function)
TEST_P(EnhancedChannelHandshake, EveryChunkOfAMultiChunkFirstResponseIsBound)
{
  // The single-chunk sizes of this policy's request and response, from a throwaway exchange.
  const auto probeRequest = open_chunk(client_end(), true, 70);
  ASSERT_FALSE(probeRequest.empty());
  const auto probeServer = server_end();
  ASSERT_TRUE(decode_on(probeServer, probeRequest).is_good());
  const auto probeResponse = open_chunk(probeServer, false, 70);
  ASSERT_FALSE(probeResponse.empty());

  const auto client = client_end();
  const auto server = server_end();
  const auto requestChunks = open_chunks_split(client, true, 71, probeRequest.size());
  ASSERT_GE(requestChunks.size(), 2u);
  for (size_t i = 0; i < requestChunks.size(); ++i)
  {
    SCOPED_TRACE("request chunk " + std::to_string(i));
    const auto decoded = decode_on(server, requestChunks[i]);
    ASSERT_TRUE(decoded.is_good()) << std::hex << decoded.status_code().as_uint32();
  }
  const ByteString requestSignature{signature_of(requestChunks.back())};
  EXPECT_EQ(client->openSecureChannelRequestSignature, requestSignature);
  EXPECT_EQ(server->openSecureChannelRequestSignature, requestSignature);

  const auto responseChunks = open_chunks_split(server, false, 71, probeResponse.size());
  ASSERT_GE(responseChunks.size(), 2u);
  for (size_t i = 0; i < responseChunks.size(); ++i)
  {
    SCOPED_TRACE("response chunk " + std::to_string(i));
    ByteString bound{signed_bytes_of(responseChunks[i])};
    for (const auto value : requestSignature)
      bound.push_back(value);
    EXPECT_TRUE(
      independent_verify(GetParam().policy, *mRemoteCertificate, bound, signature_of(responseChunks[i])));
    const auto accepted = decode_on(client, responseChunks[i]);
    EXPECT_TRUE(accepted.is_good()) << std::hex << accepted.status_code().as_uint32();
  }
  const ByteString lastSignature{signature_of(responseChunks.back())};
  EXPECT_EQ(server->channelThumbprint, lastSignature);
  EXPECT_EQ(client->channelThumbprint, lastSignature);
}

// Without a request Signature to bind to - a state the channels never reach - the first response is neither
// signed nor accepted: Bad_InternalError, no chunk and no ChannelThumbprint, rather than a response that
// binds nothing.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-THUMBPRINT-FAILS-CLOSED, scope=function)
TEST_P(EnhancedChannelHandshake, WithoutTheRequestSignatureTheFirstResponseIsNeitherSignedNorAccepted)
{
  const auto lonelyServer = server_end();
  lonelyServer->remoteCertificate = mLocalCertificate;
  const auto [refusedEncode, chunks] =
    encode_on(lonelyServer, std::make_shared<OpenSecureChannelResponse>(), 71);
  EXPECT_EQ(refusedEncode.status_code(), Status::BadInternalError);
  ASSERT_NE(refusedEncode.shared_detail(), nullptr);
  EXPECT_EQ(refusedEncode.shared_detail()->code, "NoRequestSignature");
  EXPECT_TRUE(chunks.empty());
  EXPECT_TRUE(lonelyServer->channelThumbprint.empty());

  // A conforming exchange produces a bound response; a client end that never sent the request cannot check
  // it.
  const auto requestingClient = client_end();
  const auto server = server_end();
  ASSERT_TRUE(decode_on(server, open_chunk(requestingClient, true, 71)).is_good());
  const auto response = open_chunk(server, false, 71);
  const auto silentClient = client_end();
  const auto refusedDecode = decode_on(silentClient, response);
  EXPECT_EQ(refusedDecode.status_code(), Status::BadInternalError);
  ASSERT_NE(refusedDecode.shared_detail(), nullptr);
  EXPECT_EQ(refusedDecode.shared_detail()->code, "NoRequestSignature");
  EXPECT_TRUE(silentClient->channelThumbprint.empty());
  EXPECT_TRUE(decode_on(requestingClient, response).is_good());
}

ByteString independent_key_material(bool sha384, const ByteString& secret, string_view label,
  const ByteString& firstNonce, const ByteString& secondNonce, size_t length)
{
  ByteString salt;
  salt.push_back(static_cast<uint8_t>(length & 0xff));
  salt.push_back(static_cast<uint8_t>((length >> 8) & 0xff));
  for (auto character : label)
    salt.push_back(static_cast<uint8_t>(character));
  for (auto value : firstNonce)
    salt.push_back(value);
  for (auto value : secondNonce)
    salt.push_back(value);
  KeyContextOwner context{EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free};
  require_openssl(bool(context));
  require_openssl(
    EVP_PKEY_derive_init(context.get()) == 1 &&
    EVP_PKEY_CTX_set_hkdf_md(context.get(), sha384 ? EVP_sha384() : EVP_sha256()) == 1 &&
    EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt.data(), static_cast<int>(salt.size())) == 1 &&
    EVP_PKEY_CTX_set1_hkdf_key(context.get(), secret.data(), static_cast<int>(secret.size())) == 1 &&
    EVP_PKEY_CTX_add1_hkdf_info(context.get(), salt.data(), static_cast<int>(salt.size())) == 1);
  ByteString material;
  material.resize(length);
  auto actualLength = length;
  require_openssl(
    EVP_PKEY_derive(context.get(), material.data(), &actualLength) == 1 && actualLength == length);
  return material;
}

class EccKeyDerivationWireTests : public testing::TestWithParam<RecipientCase>
{};

// Both modes derive, for each direction, exactly the independent HKDF output with
// L = EncryptionKeyLength + InitializationVectorLength in bytes: the encryption key and the 12-byte IV, and
// no signing key (Part 6 6.8.1 under AuthenticatedEncryption). The nonces and the shared secret are computed
// outside the SDK from the two private keys.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-DERIVATION, scope=function)
TEST_P(EccKeyDerivationWireTests, DirectionalMaterialMatchesIndependentHkdf)
{
  const auto& parameters = GetParam();
  boost::asio::thread_pool pool{2};
  const auto crypto = create_default_crypto();
  const auto local = crypto->create_ephemeral_keys_sync(ephemeral_algorithm(parameters.policy));
  const auto remote = crypto->create_ephemeral_keys_sync(ephemeral_algorithm(parameters.policy));
  const auto exchange = independent_exchange(parameters.policy, local, remote);
  EXPECT_EQ(local.publicKey, exchange.localNonce);
  EXPECT_EQ(remote.publicKey, exchange.remoteNonce);
  const auto policy = SecurityPolicy::create(parameters.policy.id);
  const auto context = std::make_shared<SecureChannelContext>();
  context->boundStrand = boost::asio::make_strand(pool.get_executor());
  context->crypto = crypto;
  context->securityPolicy = policy;
  context->messageSecurityMode = parameters.mode;
  context->localEphemeralPrivateKey = local.privateKey;
  const auto result = test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
    [policy, context, &exchange, role = parameters.role](auto callback)
    {
      policy->derive_symmetric_keys_async(
        context, exchange.localNonce, exchange.remoteNonce, role, std::move(callback));
    });
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  const size_t encryptionLength = key_length(parameters.policy.cipher);
  const size_t ivLength = 12;
  const auto length = encryptionLength + ivLength;
  const auto localLabel = parameters.role == ChannelRole::Client ? "opcua-client" : "opcua-server";
  const auto remoteLabel = parameters.role == ChannelRole::Client ? "opcua-server" : "opcua-client";
  const auto sha384 = parameters.policy.hkdfSha384;
  const auto expectedLocal = independent_key_material(
    sha384, exchange.secret, localLabel, exchange.localNonce, exchange.remoteNonce, length);
  const auto expectedRemote = independent_key_material(
    sha384, exchange.secret, remoteLabel, exchange.remoteNonce, exchange.localNonce, length);
  const auto& [localKeys, remoteKeys] = result.value();
  for (const auto& [keys, material] :
    {std::pair{localKeys, expectedLocal}, std::pair{remoteKeys, expectedRemote}})
  {
    EXPECT_TRUE(keys.signingKey.empty());
    EXPECT_EQ(keys.encryptingKey, ByteString{span<const byte>{material}.subspan(0, encryptionLength)});
    EXPECT_EQ(
      keys.initializationVector, ByteString{span<const byte>{material}.subspan(encryptionLength, ivLength)});
  }
  EXPECT_TRUE(context->localEphemeralPrivateKey.empty());
  pool.join();
}

const EVP_CIPHER* evp_cipher(Cipher cipher)
{
  switch (cipher)
  {
  case Cipher::Aes128Gcm:
    return EVP_aes_128_gcm();
  case Cipher::Aes256Gcm:
    return EVP_aes_256_gcm();
  case Cipher::ChaCha20Poly1305:
    return EVP_chacha20_poly1305();
  }
  throw std::invalid_argument{"unknown cipher"};
}

const unsigned char* bytes_of(span<const byte> bytes)
{
  return reinterpret_cast<const unsigned char*>(bytes.data());
}

constexpr size_t tagLength = 16;
constexpr size_t symmetricHeaderSize = 16;  // UaScMessageHeader (12) and TokenId (4)

// Part 6 6.8.1 Table 69: the token's base IV with TokenId XORed into bytes 0-3 and the previous chunk's
// SequenceNumber into bytes 4-7, both little-endian.
ByteString independent_iv(const ByteString& baseIv, uint32_t tokenId, uint32_t lastSequenceNumber)
{
  ByteString iv = baseIv;
  for (size_t index = 0; index < 4; ++index)
  {
    iv[index] ^= static_cast<uint8_t>((tokenId >> (8 * index)) & 0xff);
    iv[4 + index] ^= static_cast<uint8_t>((lastSequenceNumber >> (8 * index)) & 0xff);
  }
  return iv;
}

// The ciphertext of @p plaintext followed by its 16-byte tag over @p aad and the ciphertext.
ByteString independent_seal(Cipher cipher, const ByteString& key, const ByteString& iv, span<const byte> aad,
  span<const byte> plaintext)
{
  CipherContextOwner context{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
  int length = 0;
  require_openssl(
    context && EVP_EncryptInit_ex(context.get(), evp_cipher(cipher), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
    EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
    EVP_EncryptUpdate(context.get(), nullptr, &length, bytes_of(aad), static_cast<int>(aad.size())) == 1);
  ByteString sealed;
  sealed.resize(plaintext.size() + tagLength);
  int written = 0;
  if (!plaintext.empty())
    require_openssl(
      EVP_EncryptUpdate(
        context.get(), sealed.data(), &written, bytes_of(plaintext), static_cast<int>(plaintext.size())) ==
      1);
  int finalLength = 0;
  require_openssl(EVP_EncryptFinal_ex(context.get(), sealed.data() + written, &finalLength) == 1 &&
                  static_cast<size_t>(written + finalLength) == plaintext.size());
  require_openssl(
    EVP_CIPHER_CTX_ctrl(
      context.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tagLength), sealed.data() + plaintext.size()) ==
    1);
  return sealed;
}

// The plaintext of a ciphertext-and-tag, or nothing when the tag does not verify.
std::optional<ByteString> independent_open(
  Cipher cipher, const ByteString& key, const ByteString& iv, span<const byte> aad, span<const byte> sealed)
{
  require_openssl(sealed.size() >= tagLength);
  const auto cipherText = sealed.first(sealed.size() - tagLength);
  ByteString tag{sealed.last(tagLength)};
  CipherContextOwner context{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
  int length = 0;
  require_openssl(
    context && EVP_DecryptInit_ex(context.get(), evp_cipher(cipher), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
    EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
    EVP_DecryptUpdate(context.get(), nullptr, &length, bytes_of(aad), static_cast<int>(aad.size())) == 1);
  ByteString plaintext;
  plaintext.resize(cipherText.size());
  int written = 0;
  if (!cipherText.empty())
    require_openssl(EVP_DecryptUpdate(context.get(),
                      plaintext.data(),
                      &written,
                      bytes_of(cipherText),
                      static_cast<int>(cipherText.size())) == 1);
  require_openssl(
    EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1);
  int finalLength = 0;
  if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + written, &finalLength) != 1)
    return std::nullopt;
  return plaintext;
}

uint32_t read_u32(const ByteString& bytes, size_t offset)
{
  uint32_t value = 0;
  for (size_t index = 0; index < 4; ++index)
    value |= static_cast<uint32_t>(bytes[offset + index]) << (8 * index);
  return value;
}

// An enhanced channel in the Open state with a token issued from a real key exchange, whose MessageChunks
// are checked against an AEAD computed outside the SDK.
class EphemeralKeyAeadWireTests : public EccRecipientWireTests
{
protected:
  SecurityToken::CreateResult create_token(SecurityTokenRequestType type, uint32_t tokenId)
  {
    const auto local = mCrypto->create_ephemeral_keys_sync(ephemeral_algorithm(GetParam().policy));
    const auto remote = mCrypto->create_ephemeral_keys_sync(ephemeral_algorithm(GetParam().policy));
    mContext->localEphemeralPrivateKey = local.privateKey;
    return test_helpers::run_async_callback_sync<SecurityToken::CreateResult>(
      [context = mContext, type, tokenId, local, remote, role = GetParam().role](auto callback)
      {
        SecurityToken::create_async(
          type,
          context,
          tokenId,
          std::chrono::hours{1},
          local.publicKey,
          remote.publicKey,
          role,
          [] {},
          std::move(callback));
      });
  }

  SecurityToken::CreateResult prepare_renewal()
  {
    return create_token(SecurityTokenRequestType::Renew, 0x10203041);
  }

  void SetUp() override
  {
    EccRecipientWireTests::SetUp();
    ASSERT_TRUE(create_token(SecurityTokenRequestType::Issue, 0x10203040).is_good());
    ASSERT_NE(mContext->activeSecurityToken, nullptr);
    mContext->state = SecureChannelContext::State::Open;
    mContext->secureChannelId = 71;
  }

  bool encrypted() const
  {
    return GetParam().mode == MessageSecurityMode::SignAndEncrypt;
  }

  shared_ptr<Structure> symmetric_message() const
  {
    if (GetParam().role == ChannelRole::Client)
      return std::make_shared<ReadRequest>();
    return std::make_shared<ReadResponse>();
  }

  // The sequence header and body of @p chunk, opened outside the SDK with @p keys and @p iv (Part 6
  // Figure 12): in SignAndEncrypt the headers are the associated data and the rest is sealed; in Sign the
  // whole chunk before the tag is the associated data and nothing is sealed.
  std::optional<ByteString> open_chunk(
    const ByteString& chunk, const SecurityToken::Keys& keys, const ByteString& iv)
  {
    const span<const byte> bytes{chunk};
    const auto cipher = GetParam().policy.cipher;
    if (encrypted())
      return independent_open(
        cipher, keys.encryptingKey, iv, bytes.first(symmetricHeaderSize), bytes.subspan(symmetricHeaderSize));
    if (!independent_open(
          cipher, keys.encryptingKey, iv, bytes.first(bytes.size() - tagLength), bytes.last(tagLength)))
      return std::nullopt;
    return ByteString{bytes.subspan(symmetricHeaderSize, bytes.size() - symmetricHeaderSize - tagLength)};
  }

  stack_utils::SequenceHeader read_sequence(const ByteString& payload)
  {
    memory_stream_device::ExternalReadOnly device{span<const byte>{payload}};
    MemoryStream stream{device};
    UaBinaryDecoder decoder{StructureResolver{}, stream, mContext->encodingLimits};
    stack_utils::SequenceHeader sequence;
    sequence.decode(mContext->encodingLimits, decoder);
    return sequence;
  }

  struct OracleChunk
  {
    ByteString chunk;
    ByteString payload;  // the sequence header and body, in the clear
  };

  // A Final MSG chunk of eight 0x5a body bytes for request 76 under the active token, sealed outside the SDK
  // with the remote keys and the IV of @p ivSequenceNumber.
  OracleChunk oracle_chunk(uint32_t sequenceNumber, uint32_t ivSequenceNumber, bool corruptTag = false)
  {
    const auto& keys = mContext->activeSecurityToken->remote_keys();
    const auto tokenId = mContext->activeSecurityToken->id();
    ByteString body;
    body.resize(8, 0x5a);
    memory_stream_device::Dynamic device{65536, true};
    MemoryStream stream{device};
    UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
    stack_utils::UaScMessageHeader header;
    header.messageType = stack_utils::UaScMessageHeader::MessageType::Message;
    header.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
    header.secureChannelId = mContext->secureChannelId;
    header.messageChunkSize = static_cast<uint32_t>(symmetricHeaderSize + 8 + body.size() + tagLength);
    header.encode(mContext->encodingLimits, encoder);
    stack_utils::SymmetricSecurityHeader security;
    security.tokenId = tokenId;
    security.encode(mContext->encodingLimits, encoder);
    stack_utils::SequenceHeader sequence;
    sequence.sequenceNumber = sequenceNumber;
    sequence.requestId = 76;
    sequence.encode(mContext->encodingLimits, encoder);
    stream.write_all(body);
    const auto size = stream.get_position();
    auto storage = device.move_storage_out();
    storage.resize(size);
    const ByteString plain{span<const byte>{storage}};
    const span<const byte> all{plain};
    const auto iv = independent_iv(keys.initializationVector, tokenId, ivSequenceNumber);
    OracleChunk oracle;
    oracle.payload = ByteString{all.subspan(symmetricHeaderSize)};
    if (encrypted())
    {
      oracle.chunk = ByteString{all.first(symmetricHeaderSize)};
      const auto sealed = independent_seal(GetParam().policy.cipher,
        keys.encryptingKey,
        iv,
        all.first(symmetricHeaderSize),
        all.subspan(symmetricHeaderSize));
      for (auto value : sealed)
        oracle.chunk.push_back(value);
    }
    else
    {
      oracle.chunk = plain;
      for (auto value : independent_seal(GetParam().policy.cipher, keys.encryptingKey, iv, all, {}))
        oracle.chunk.push_back(value);
    }
    if (corruptTag)
      oracle.chunk[oracle.chunk.size() - 1] ^= 1;
    return oracle;
  }
};

// The encoded chunk opens outside the SDK with the token's encrypting key and the IV of the PREVIOUS
// sequence number, and does not open with the IV of its own: no padding, the 16-byte tag as the footer, and
// the token's keys hold no signing key.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
TEST_P(EphemeralKeyAeadWireTests, EncoderMatchesIndependentAead)
{
  mContext->lastTxSequenceNumber = 41;
  mContext->txChunkSent = true;
  const auto message = symmetric_message();
  const auto [result, chunks] = encode(message, 76);
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_EQ(chunks.size(), 1);
  const auto& chunk = chunks.front();
  const auto& keys = mContext->activeSecurityToken->local_keys();
  const auto tokenId = mContext->activeSecurityToken->id();
  EXPECT_TRUE(keys.signingKey.empty());
  EXPECT_EQ(keys.encryptingKey.size(), key_length(GetParam().policy.cipher));
  EXPECT_EQ(keys.initializationVector.size(), 12u);
  EXPECT_EQ(read_u32(chunk, 4), chunk.size());
  EXPECT_EQ(read_u32(chunk, 12), tokenId);
  const auto opened = open_chunk(chunk, keys, independent_iv(keys.initializationVector, tokenId, 41));
  ASSERT_TRUE(opened.has_value()) << "the chunk does not open with the IV of the previous sequence number";
  // No padding: the plaintext is the sequence header and the encoded message, and nothing after them.
  ByteString encodedMessage;
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream{device};
    const CodecNamespaceContext namespaces{mContext->namespaceIndexCallback};
    UaBinaryEncoder binaryEncoder{namespaces, stream};
    const auto depth = mContext->encodingLimits.stack_depth();
    Encoder encoder{binaryEncoder};
    message->encode_id(depth, namespaces, encoder);
    binaryEncoder.encode(depth, *message);
    const auto storage = device.move_storage_out();
    encodedMessage = ByteString{span<const byte>{storage}};
  }
  ASSERT_EQ(opened->size(), stack_utils::SequenceHeader::sizeInBytes + encodedMessage.size());
  EXPECT_EQ(
    ByteString{span<const byte>{*opened}.subspan(stack_utils::SequenceHeader::sizeInBytes)}, encodedMessage);
  const auto sequence = read_sequence(*opened);
  EXPECT_EQ(sequence.sequenceNumber, 42u);
  EXPECT_EQ(sequence.requestId, 76u);
  EXPECT_FALSE(open_chunk(chunk, keys, independent_iv(keys.initializationVector, tokenId, 42)).has_value())
    << "the chunk opens with the IV of its own sequence number";
}

// A chunk whose encryption is in flight when the token is replaced keeps the TokenId it was encoded under;
// the next chunk is encoded under the replacement token and opens with its keys.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
// @relation(AC-SVR-SCE-003-IV-ORACLE, scope=function)
TEST_P(EphemeralKeyAeadWireTests, EncoderRetainsChunkTokenAcrossEncryptCompletion)
{
  ASSERT_TRUE(prepare_renewal().is_good());
  ASSERT_NE(mContext->pendingSecurityToken, nullptr);
  const auto originalId = mContext->activeSecurityToken->id();
  const auto originalKeys = mContext->activeSecurityToken->local_keys();
  const auto renewedId = mContext->pendingSecurityToken->id();
  EXPECT_NE(originalId, renewedId);
  EXPECT_NE(originalKeys.encryptingKey, mContext->pendingSecurityToken->local_keys().encryptingKey);
  EXPECT_NE(
    originalKeys.initializationVector, mContext->pendingSecurityToken->local_keys().initializationVector);
  mContext->lastTxSequenceNumber = 41;
  mContext->txChunkSent = true;

  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_park_async(true);
  mContext->crypto = fake;
  auto chunks = std::make_shared<std::vector<ByteString>>();
  auto completion = std::make_shared<std::promise<VoidResult>>();
  auto future = completion->get_future();
  const auto message = symmetric_message();
  mContext->securityPolicy->encode_message_async(
    mContext,
    76,
    message,
    [chunks](auto chunk) { chunks->push_back(std::move(chunk)); },
    [completion](auto result) { completion->set_value(std::move(result)); });

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (fake->pending_symmetric_encrypt_and_sign_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(fake->pending_symmetric_encrypt_and_sign_count(), 1);
  ASSERT_TRUE(chunks->empty());
  // The in-flight chunk was sealed with the original token's key and the IV of the previous number, 41.
  const auto parked = fake->parked_symmetric_encrypt_and_sign_inputs(0);
  EXPECT_EQ(parked.key, originalKeys.encryptingKey);
  EXPECT_EQ(parked.iv, independent_iv(originalKeys.initializationVector, originalId, 41));
  ByteString injectedTag;
  injectedTag.resize(tagLength, 0x6d);
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, fake, injectedTag]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      // The old token is destroyed on the bound strand while the encryption completion is held.
      context->activeSecurityToken = std::move(context->pendingSecurityToken);
      fake->set_park_async(false);
      fake->complete_pending_symmetric_encrypt_and_sign(0,
        Crypto::SymmetricEncryptAndSignOutputResult{
          Crypto::SymmetricEncryptAndSignOutput{ByteString{}, std::nullopt, injectedTag}});
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  ASSERT_TRUE(future.get().is_good());
  ASSERT_EQ(chunks->size(), 1);
  EXPECT_EQ(read_u32(chunks->front(), 12), originalId);
  EXPECT_EQ(ByteString{span<const byte>{chunks->front()}.last(tagLength)}, injectedTag);

  chunks->clear();
  const auto second = test_helpers::run_async_callback_sync<VoidResult>(
    [context = mContext, message, chunks](auto callback)
    {
      context->securityPolicy->encode_message_async(
        context,
        77,
        message,
        [chunks](auto chunk) { chunks->push_back(std::move(chunk)); },
        std::move(callback));
    });
  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(chunks->size(), 1);
  const auto& renewedKeys = mContext->activeSecurityToken->local_keys();
  EXPECT_EQ(read_u32(chunks->front(), 12), renewedId);
  const auto opened =
    open_chunk(chunks->front(), renewedKeys, independent_iv(renewedKeys.initializationVector, renewedId, 42));
  ASSERT_TRUE(opened.has_value()) << "the next chunk does not open with the replacement token's keys";
  EXPECT_EQ(read_sequence(*opened).sequenceNumber, 43u);
}

// A chunk sealed outside the SDK with the remote keys and the IV of the previous sequence number decodes to
// its request id and body.
// @relation(AC-SVR-SCE-002-AEAD-ORACLE, scope=function)
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
TEST_P(EphemeralKeyAeadWireTests, DecoderAcceptsIndependentAead)
{
  mContext->lastRxSequenceNumber = 41;
  const auto result = decode(oracle_chunk(42, 41).chunk);
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_TRUE(result.value().has_value());
  EXPECT_EQ(result.value()->first, 76);
  ByteString expected;
  expected.resize(8, 0x5a);
  EXPECT_EQ(result.value()->second, expected);
  ASSERT_TRUE(mContext->lastRxSequenceNumber.has_value());
  EXPECT_EQ(*mContext->lastRxSequenceNumber, 42u);
}

// The token a chunk selects is the one whose keys open it and under which its sequence number is recorded,
// even when the token is replaced between the selection and the posted launch of the decryption.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
TEST_P(EphemeralKeyAeadWireTests, DecoderRetainsSelectedTokenBeforePostedLaunch)
{
  ASSERT_TRUE(prepare_renewal().is_good());
  ASSERT_NE(mContext->pendingSecurityToken, nullptr);
  const auto originalId = mContext->activeSecurityToken->id();
  const auto renewedId = mContext->pendingSecurityToken->id();
  mContext->lastRxSequenceNumber = 41;
  const auto chunk = oracle_chunk(42, 41).chunk;
  auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
  auto future = completion->get_future();
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, chunk, completion]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      boost::asio::post(context->strand(),
        [weak]
        {
          const auto current = weak.lock();
          if (current)
            current->activeSecurityToken = std::move(current->pendingSecurityToken);
        });
      // Token selection is synchronous, but operation launch is queued after promotion.
      context->securityPolicy->decode_message_chunk_async(
        context, chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_TRUE(result.value().has_value());
  EXPECT_EQ(result.value()->first, 76);
  ByteString expected;
  expected.resize(8, 0x5a);
  EXPECT_EQ(result.value()->second, expected);
  EXPECT_EQ(mContext->activeSecurityToken->id(), renewedId);
  EXPECT_EQ(mContext->rxUseUnderToken.tokenId, originalId);
  EXPECT_NE(originalId, renewedId);
}

// A sequence number already used under the chunk's token is refused under that token, even when the token is
// replaced while the verification is in flight.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
TEST_P(EphemeralKeyAeadWireTests, DecoderRejectsWireTokenReuseAfterVerificationCompletion)
{
  ASSERT_TRUE(prepare_renewal().is_good());
  const auto originalId = mContext->activeSecurityToken->id();
  mContext->lastRxSequenceNumber = std::numeric_limits<uint32_t>::max();
  mContext->rxUseUnderToken = {originalId, 0, std::numeric_limits<uint32_t>::max()};
  const auto oracle = oracle_chunk(0, std::numeric_limits<uint32_t>::max());
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_park_async(true);
  mContext->crypto = fake;
  auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
  auto future = completion->get_future();
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, chunk = oracle.chunk, completion]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      context->securityPolicy->decode_message_chunk_async(
        context, chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (
    fake->pending_symmetric_verify_and_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(fake->pending_symmetric_verify_and_decrypt_count(), 1);
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, fake, payload = oracle.payload]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      context->activeSecurityToken = std::move(context->pendingSecurityToken);
      fake->set_park_async(false);
      // The verification succeeds with the chunk's own plaintext.
      fake->complete_pending_symmetric_verify_and_decrypt(0,
        Crypto::SymmetricVerifyAndDecryptOutputResult{
          Crypto::SymmetricVerifyAndDecryptOutput{ByteString{}, payload}});
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  EXPECT_EQ(result.status_code(), Status::BadSequenceNumberInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "SequenceNumberReusedUnderToken");
  EXPECT_EQ(mContext->rxUseUnderToken.tokenId, originalId);
}

// A chunk is sent only after a Good AEAD encryption: an Uncertain answer, with or without a tag, refuses the
// message with Bad_InternalError and the CryptoAnswerUncertain ErrorDetail whose inner status is the
// Uncertain code, and no chunk is sent.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_P(EphemeralKeyAeadWireTests, AnUncertainAeadEncryptionIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  for (const bool withTag : {false, true})
  {
    SCOPED_TRACE(withTag ? "the answer holds a tag" : "the answer holds no tag");
    const auto fake = test_helpers::FakeAsyncCrypto::create();
    fake->set_park_async(true);
    mContext->crypto = fake;
    auto chunks = std::make_shared<std::vector<ByteString>>();
    auto completion = std::make_shared<std::promise<VoidResult>>();
    auto future = completion->get_future();
    mContext->securityPolicy->encode_message_async(
      mContext,
      76,
      symmetric_message(),
      [chunks](auto chunk) { chunks->push_back(std::move(chunk)); },
      [completion](auto result) { completion->set_value(std::move(result)); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (
      fake->pending_symmetric_encrypt_and_sign_count() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    ASSERT_EQ(fake->pending_symmetric_encrypt_and_sign_count(), 1);
    ByteString tag;
    tag.resize(tagLength, 0x6d);
    fake->complete_pending_symmetric_encrypt_and_sign(0,
      withTag ? Crypto::SymmetricEncryptAndSignOutputResult{Crypto::SymmetricEncryptAndSignOutput{
                                                              ByteString{}, std::nullopt, tag},
                  uncertain}
              : Crypto::SymmetricEncryptAndSignOutputResult{uncertain});
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    const auto result = future.get();
    EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
    ASSERT_NE(result.error_detail(), nullptr);
    EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
    EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
    EXPECT_TRUE(chunks->empty());
  }
}

// A chunk is accepted only after a Good AEAD verification: an Uncertain answer, with or without the
// plaintext, refuses the chunk with Bad_SecurityChecksFailed and the CryptoAnswerUncertain ErrorDetail whose
// inner status is the Uncertain code, and the received sequence number is not advanced.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_P(EphemeralKeyAeadWireTests, AnUncertainAeadDecryptionIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  for (const bool withPlaintext : {false, true})
  {
    SCOPED_TRACE(withPlaintext ? "the answer holds the plaintext" : "the answer holds no plaintext");
    mContext->lastRxSequenceNumber = 41;
    const auto oracle = oracle_chunk(42, 41);
    const auto fake = test_helpers::FakeAsyncCrypto::create();
    fake->set_park_async(true);
    mContext->crypto = fake;
    auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
    auto future = completion->get_future();
    mContext->securityPolicy->decode_message_chunk_async(
      mContext, oracle.chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (
      fake->pending_symmetric_verify_and_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    ASSERT_EQ(fake->pending_symmetric_verify_and_decrypt_count(), 1);
    fake->complete_pending_symmetric_verify_and_decrypt(0,
      withPlaintext ? Crypto::SymmetricVerifyAndDecryptOutputResult{Crypto::SymmetricVerifyAndDecryptOutput{
                                                                      ByteString{}, oracle.payload},
                        uncertain}
                    : Crypto::SymmetricVerifyAndDecryptOutputResult{uncertain});
    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    const auto result = future.get();
    EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "CryptoAnswerUncertain");
    EXPECT_EQ(result.shared_detail()->innerStatus, uncertain.value());
    ASSERT_TRUE(mContext->lastRxSequenceNumber.has_value());
    EXPECT_EQ(*mContext->lastRxSequenceNumber, 41u);
  }
}

// A chunk whose tag does not verify, and a chunk too short to hold a tag, are refused with
// Bad_SecurityChecksFailed and an ErrorDetail.
// @relation(AC-COMP-ECC-CHANNEL-WIRE-AEAD, scope=function)
TEST_P(EphemeralKeyAeadWireTests, DecoderRetainsTagRejection)
{
  mContext->lastRxSequenceNumber = 41;
  const auto result = decode(oracle_chunk(42, 41, true).chunk);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  EXPECT_NE(result.shared_detail(), nullptr);

  auto truncated = oracle_chunk(42, 41).chunk;
  truncated.resize(symmetricHeaderSize + 8);
  for (size_t index = 0; index < 4; ++index)
    truncated[4 + index] = static_cast<uint8_t>((truncated.size() >> (8 * index)) & 0xff);
  const auto tooShort = decode(truncated);
  EXPECT_TRUE(tooShort.is_bad());
  EXPECT_EQ(tooShort.status_code(), Status::BadSecurityChecksFailed);
  ASSERT_NE(tooShort.shared_detail(), nullptr);
  EXPECT_EQ(tooShort.shared_detail()->code, "CryptoOperationFailed");
}

// OPC 10000-6 6.7.4 (1.05.06; CL-SC-010): after the renew response the client keeps the token it replaced
// for receiving, and the AEAD decoder opens a chunk under it with that token's keys and IV, until a chunk
// under the active token is accepted. The context is set as the client's renew response leaves it: the old
// token retired, the renewed one active. Falsifiable: a decoder that knows only the active and pending tokens
// refuses the first chunk; one that never drops the retired token accepts the third.
// @relation(AC-CL-SC-010-02, scope=function)
TEST_P(EphemeralKeyAeadWireTests, DecoderAcceptsTheRetiredTokenUntilAChunkUnderTheActiveOne)
{
  mContext->lastRxSequenceNumber = 41;
  const auto underOld = oracle_chunk(42, 41).chunk;
  const auto laterUnderOld = oracle_chunk(44, 43).chunk;
  ASSERT_TRUE(prepare_renewal().is_good());
  ASSERT_NE(mContext->pendingSecurityToken, nullptr);
  mContext->retiredSecurityToken = std::move(mContext->activeSecurityToken);
  mContext->activeSecurityToken = std::move(mContext->pendingSecurityToken);

  const auto first = decode(underOld);
  ASSERT_TRUE(first.is_good()) << "a chunk under the retired token was refused: " << std::hex
                               << first.status_code().as_uint32();
  ASSERT_TRUE(first.value().has_value());
  EXPECT_EQ(first.value()->first, 76);

  const auto underNew = decode(oracle_chunk(43, 42).chunk);
  ASSERT_TRUE(underNew.is_good()) << std::hex << underNew.status_code().as_uint32();
  EXPECT_EQ(mContext->retiredSecurityToken, nullptr)
    << "a chunk under the active token did not retire the old one";

  const auto third = decode(laterUnderOld);
  EXPECT_EQ(third.status_code().as_status(), Status::BadSecureChannelTokenUnknown)
    << "the retired token was still accepted after a chunk under the active token: " << std::hex
    << third.status_code().as_uint32();
}

// A chunk accepted under the active token ends the acceptance of the token the renewal replaced - that token
// only. Here a second renewal completes while the chunk is decrypted and retires the token the chunk was
// under, which the Server may still be answering under; the chunk's completion must leave it. Falsifiable: a
// decoder that resets whatever is retired when the chunk completes drops it.
// @relation(AC-CL-SC-010-02, scope=function)
TEST_P(EphemeralKeyAeadWireTests, ACompletedChunkDropsOnlyTheTokenRetiredWhenItWasSelected)
{
  // Retired A, active B (one renewal done), pending C (a second renewal).
  ASSERT_TRUE(prepare_renewal().is_good());
  mContext->retiredSecurityToken = std::move(mContext->activeSecurityToken);
  mContext->activeSecurityToken = std::move(mContext->pendingSecurityToken);
  ASSERT_TRUE(create_token(SecurityTokenRequestType::Renew, 0x10203042).is_good());
  ASSERT_NE(mContext->pendingSecurityToken, nullptr);
  const auto selectedId = mContext->activeSecurityToken->id();
  mContext->lastRxSequenceNumber = 41;
  const auto oracle = oracle_chunk(42, 41);
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_park_async(true);
  mContext->crypto = fake;
  auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
  auto future = completion->get_future();
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, chunk = oracle.chunk, completion]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      context->securityPolicy->decode_message_chunk_async(
        context, chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (
    fake->pending_symmetric_verify_and_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(fake->pending_symmetric_verify_and_decrypt_count(), 1);
  boost::asio::post(mContext->strand(),
    [weak = weak_ptr<SecureChannelContext>{mContext}, fake, payload = oracle.payload]
    {
      const auto context = weak.lock();
      if (!context)
        return;
      // The second renewal completes as the client's renew response does: B retired, C active.
      context->retiredSecurityToken = std::move(context->activeSecurityToken);
      context->activeSecurityToken = std::move(context->pendingSecurityToken);
      fake->set_park_async(false);
      fake->complete_pending_symmetric_verify_and_decrypt(0,
        Crypto::SymmetricVerifyAndDecryptOutputResult{
          Crypto::SymmetricVerifyAndDecryptOutput{ByteString{}, payload}});
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
  ASSERT_NE(mContext->retiredSecurityToken, nullptr)
    << "the chunk's completion dropped the token the second renewal had just retired";
  EXPECT_EQ(mContext->retiredSecurityToken->id(), selectedId);
}

// Only a Server activates a renewed token on the peer's first chunk under it (it keeps the old one until
// then). A client activates its own on the renew response (CL-SC-009), so a chunk under a renewed token it
// has not activated yet is refused and the token it sends under stays the same. The Server arm is the
// control: the same chunk activates the renewed token. Falsifiable: a client that took the server's path
// would let a later renew response retire the new token and go on sending under the old one.
// @relation(AC-CL-SC-009-02, scope=function)
TEST_P(EphemeralKeyAeadWireTests, OnlyAServerActivatesARenewedTokenOnAChunkUnderIt)
{
  ASSERT_TRUE(prepare_renewal().is_good());
  const auto originalId = mContext->activeSecurityToken->id();
  const auto renewedId = mContext->pendingSecurityToken->id();
  mContext->lastRxSequenceNumber = 41;
  // oracle_chunk seals under the active token, so the renewed one is active while the chunk is sealed.
  std::swap(mContext->activeSecurityToken, mContext->pendingSecurityToken);
  const auto underRenewed = oracle_chunk(42, 41).chunk;
  std::swap(mContext->activeSecurityToken, mContext->pendingSecurityToken);

  const auto result = decode(underRenewed);
  if (GetParam().role == ChannelRole::Client)
  {
    EXPECT_EQ(result.status_code(), Status::BadSecureChannelTokenUnknown)
      << "the client activated a renewed token on a chunk under it: " << std::hex
      << result.status_code().as_uint32();
    EXPECT_EQ(mContext->activeSecurityToken->id(), originalId);
  }
  else
  {
    ASSERT_TRUE(result.is_good()) << std::hex << result.status_code().as_uint32();
    EXPECT_EQ(mContext->activeSecurityToken->id(), renewedId);
  }
}

INSTANTIATE_TEST_SUITE_P(AllPoliciesRolesAndModes, EphemeralKeyAeadWireTests,
  testing::ValuesIn(recipient_cases()), [](const auto& info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(AllPoliciesRolesAndModes, EccKeyDerivationWireTests,
  testing::ValuesIn(recipient_cases()), [](const auto& info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(AllRolesAndModes, EccRecipientWireTests, testing::ValuesIn(recipient_cases()),
  [](const auto& info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(RsaDhModes, RsaDhRecipient, testing::ValuesIn(rsa_dh_client_cases()),
  [](const auto& info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(AllPoliciesAndModes, EnhancedChannelHandshake, testing::ValuesIn(client_cases()),
  [](const auto& info) { return info.param.name; });

INSTANTIATE_TEST_SUITE_P(
  AllSix, EccEphemeralWireTests, testing::ValuesIn(curves), [](const auto& info) { return info.param.name; });
INSTANTIATE_TEST_SUITE_P(NistAndBrainpool, EccWeierstrassWireTests,
  testing::ValuesIn(curves.begin(), curves.begin() + 4), [](const auto& info) { return info.param.name; });
}  // namespace
