// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.1 (Crypto / OpenSslCrypto).
//
// These pins lock in the externally-observable behaviour of `Crypto::*_async`. They
// are committed before any Crypto consumer is flipped to callback-canonical
// (sub-phases 4.3, 4.5, 4.7, 4.8, 4.9, 4.10, 4.13) so that those flips cannot
// silently change observable Crypto behaviour.
//
// What is pinned:
//   A: get_entropy_async - success status + correct byte count.
//   B: calculate_digest_async - SHA-256 of "a" matches the known KAT.
//   C: calculate_digest_async - SHA-256 of "abc" matches RFC 6234 section 8.5 KAT.
//   D: symmetric_sign + symmetric_verify - roundtrip succeeds.
//   E: symmetric_verify - tampered signature returns Bad with non-null detail.
//   F: asymmetric_sign + asymmetric_verify - roundtrip succeeds.
//   G: asymmetric_verify - tampered input returns Bad with non-null detail.
//   H: validate_certificate - expired cert returns BadCertificateTimeInvalid + detail.
//   I: ErrorDetail attribution - failure detail's mSource or code references crypto layer.
//
// What is NOT pinned and why - see runbook section 4 ("Pins explicitly NOT covered").

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "certificate_validation_request_helpers.h"
#include "test_pki_helpers.h"

#include "ua_byte_string.h"
#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_trust_list_validation_options.h"
#include "ua_utc_time.h"

namespace ua::test::behaviour_pins
{
namespace
{

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// Crypto holds no strand or pool; *_async fires on the calling thread (inline for
// the default OpenSslCrypto, asynchronously for future HSM-backed impls). The
// fixture therefore needs no executor - std::promise / std::future on the main
// test thread is the canonical wait mechanism.

class CryptoPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    ASSERT_NE(mCrypto, nullptr);
  }

  std::shared_ptr<const Crypto> mCrypto;
};

// Convert hex string ("ba7816bf...") to a ByteString for KAT comparisons. Hex must
// be lower-case and even-length.
ByteString hex_to_byte_string(std::string_view hex)
{
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  auto nibble = [](char c) -> uint8_t
  {
    if (c >= '0' && c <= '9')
      return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
      return static_cast<uint8_t>(c - 'a' + 10);
    return 0xff;
  };
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
  {
    out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return ByteString{std::move(out)};
}

// Permissive substring check - used by Pin I to confirm Crypto failures are
// attributable to the crypto layer without locking in a specific error message.
bool contains_ci(std::string_view haystack, std::string_view needle)
{
  if (needle.empty() || haystack.size() < needle.size())
    return false;
  auto lower = [](char c)
  {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
  };
  for (size_t i = 0; i + needle.size() <= haystack.size(); ++i)
  {
    bool match = true;
    for (size_t j = 0; j < needle.size(); ++j)
    {
      if (lower(haystack[i + j]) != lower(needle[j]))
      {
        match = false;
        break;
      }
    }
    if (match)
      return true;
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Pin A - Entropy success path.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, EntropyAsyncReturnsRequestedBytesWithStatusGood)
{
  constexpr size_t size = 32;

  std::promise<ByteStringResult> promise;
  mCrypto->get_entropy_async(size, [&promise](ByteStringResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code(), Status::Good);
  EXPECT_EQ(result.value().size(), size);
}

// ---------------------------------------------------------------------------
// Pin B - SHA-256 KAT for single-byte input "a".
// ---------------------------------------------------------------------------
//
// Note: empty-input would be the RFC 6234 section 8.4 vector, but the SDK's Crypto
// rejects empty input with BadInvalidArgument as a defensive precondition. We
// pin a non-empty single-character KAT instead. The empty-input rejection is
// intentionally NOT pinned - it is a defensive impl choice, not a contract.

TEST_F(CryptoPin, Sha256OfSingleByteAMatchesKnownVector)
{
  constexpr std::string_view inputText{"a"};
  constexpr std::string_view expectedHex = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
  const ByteString expected = hex_to_byte_string(expectedHex);

  const span<const byte> input{reinterpret_cast<const byte*>(inputText.data()), inputText.size()};
  std::promise<Crypto::CalculateDigestOutputResult> promise;
  mCrypto->calculate_digest_async(HashAlgorithm::Sha2256,
    {},
    input,
    [&promise](Crypto::CalculateDigestOutputResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  ASSERT_TRUE(result.is_good()) << "digest of 'a' failed: " << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(result.value().digest, expected) << "SHA-256 of 'a' does not match the known KAT";
}

// ---------------------------------------------------------------------------
// Pin C - SHA-256 KAT for "abc" (RFC 6234 section 8.5).
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, Sha256OfRfc6234VectorOneMatchesKnownDigest)
{
  constexpr std::string_view inputText{"abc"};
  constexpr std::string_view expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const ByteString expected = hex_to_byte_string(expectedHex);

  const span<const byte> input{reinterpret_cast<const byte*>(inputText.data()), inputText.size()};

  std::promise<Crypto::CalculateDigestOutputResult> promise;
  mCrypto->calculate_digest_async(HashAlgorithm::Sha2256,
    {},
    input,
    [&promise](Crypto::CalculateDigestOutputResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  ASSERT_TRUE(result.is_good()) << "digest of 'abc' failed: " << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(result.value().digest, expected) << "SHA-256 of 'abc' does not match RFC 6234 section 8.5 KAT";
}

// ---------------------------------------------------------------------------
// Pin D - Symmetric sign/verify roundtrip.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, SymmetricSignAndVerifyRoundtripSucceeds)
{
  const ByteString key = mCrypto->get_entropy_sync(32);
  const std::string message = "Pin D - sign/verify roundtrip";
  const span<const byte> payload{reinterpret_cast<const byte*>(message.data()), message.size()};

  std::promise<ByteStringResult> signPromise;
  mCrypto->symmetric_sign_async(nullptr,
    SymmetricSignatureAlgorithm::HmacSha2256,
    key,
    payload,
    [&signPromise](ByteStringResult r) { signPromise.set_value(std::move(r)); });

  auto signResult = signPromise.get_future().get();
  ASSERT_TRUE(signResult.is_good()) << "sign failed: " << std::hex << signResult.status_code().as_uint32();
  ASSERT_TRUE(signResult.is_good());
  const ByteString signature = std::move(signResult).value();

  std::promise<VoidResult> verifyPromise;
  mCrypto->symmetric_verify_async(nullptr,
    SymmetricSignatureAlgorithm::HmacSha2256,
    key,
    payload,
    signature,
    [&verifyPromise](VoidResult r) { verifyPromise.set_value(std::move(r)); });

  auto verifyResult = verifyPromise.get_future().get();
  EXPECT_TRUE(verifyResult.is_good())
    << "verify on a freshly-signed payload failed: " << std::hex << verifyResult.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// Pin E - Symmetric verify rejects tampered signature with detail.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, SymmetricVerifyOnTamperedSignatureReturnsBadWithDetail)
{
  const ByteString key = mCrypto->get_entropy_sync(32);
  const std::string message = "Pin E - tamper detection";
  const span<const byte> payload{reinterpret_cast<const byte*>(message.data()), message.size()};

  ByteString signature = mCrypto->symmetric_sign_sync(SymmetricSignatureAlgorithm::HmacSha2256, key, payload);
  ASSERT_FALSE(signature.empty());

  // Tamper the last byte.
  ASSERT_FALSE(signature.empty());
  const size_t lastIdx = signature.size() - 1;
  signature[lastIdx] = static_cast<uint8_t>(signature[lastIdx] ^ uint8_t{0x01});

  std::promise<VoidResult> promise;
  mCrypto->symmetric_verify_async(nullptr,
    SymmetricSignatureAlgorithm::HmacSha2256,
    key,
    payload,
    signature,
    [&promise](VoidResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  EXPECT_TRUE(result.is_bad()) << "verify should reject tampered signature";
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  EXPECT_NE(result.shared_detail(), nullptr)
    << "tamper failure must carry an ErrorDetail (the highest-priority repository rule)";
}

// ---------------------------------------------------------------------------
// Pin F - Asymmetric sign/verify roundtrip.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, AsymmetricSignAndVerifyRoundtripSucceeds)
{
  std::promise<KeyPairResult> keyPromise;
  mCrypto->create_asymmetric_key_pair_async(CertificateKeyAlgorithm::Rsa,
    /*keyLengthInBits=*/2048,
    [&keyPromise](KeyPairResult r) { keyPromise.set_value(std::move(r)); });
  auto keyResult = keyPromise.get_future().get();
  ASSERT_TRUE(keyResult.is_good()) << "key generation failed: " << std::hex
                                   << keyResult.status_code().as_uint32();
  ASSERT_TRUE(keyResult.is_good());
  auto keyPair = std::move(keyResult).value();
  ASSERT_NE(keyPair, nullptr);

  const std::string message = "Pin F - asymmetric roundtrip";
  const span<const byte> payload{reinterpret_cast<const byte*>(message.data()), message.size()};

  std::promise<ByteStringResult> signPromise;
  mCrypto->asymmetric_sign_async(nullptr,
    AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
    keyPair,
    payload,
    [&signPromise](ByteStringResult r) { signPromise.set_value(std::move(r)); });
  auto signResult = signPromise.get_future().get();
  ASSERT_TRUE(signResult.is_good()) << "asymmetric sign failed: " << std::hex
                                    << signResult.status_code().as_uint32();
  const ByteString signature = std::move(signResult).value();

  const ByteString publicKey = keyPair->public_key_der();

  std::promise<VoidResult> verifyPromise;
  mCrypto->asymmetric_verify_async(nullptr,
    AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
    publicKey,
    payload,
    signature,
    [&verifyPromise](VoidResult r) { verifyPromise.set_value(std::move(r)); });
  auto verifyResult = verifyPromise.get_future().get();
  EXPECT_TRUE(verifyResult.is_good()) << "asymmetric verify on a freshly-signed payload failed: " << std::hex
                                      << verifyResult.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// Pin G - Asymmetric verify rejects tampered input with detail.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, AsymmetricVerifyOnTamperedInputReturnsBadWithDetail)
{
  auto keyPair =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, /*keyLengthInBits=*/2048);
  ASSERT_NE(keyPair, nullptr);

  std::string message = "Pin G - input tamper";
  span<const byte> originalPayload{reinterpret_cast<const byte*>(message.data()), message.size()};

  const ByteString signature =
    mCrypto->asymmetric_sign_sync(AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256, keyPair, originalPayload);
  ASSERT_FALSE(signature.empty());

  // Tamper the input AFTER signing - the signature now belongs to the original.
  message.back() = (message.back() == 'r' ? 'R' : 'r');
  span<const byte> tamperedPayload{reinterpret_cast<const byte*>(message.data()), message.size()};

  const ByteString publicKey = keyPair->public_key_der();

  std::promise<VoidResult> promise;
  mCrypto->asymmetric_verify_async(nullptr,
    AsymmetricSignatureAlgorithm::RsaPkcs15Sha2256,
    publicKey,
    tamperedPayload,
    signature,
    [&promise](VoidResult r) { promise.set_value(std::move(r)); });
  auto result = promise.get_future().get();

  EXPECT_TRUE(result.is_bad()) << "verify should reject tampered input";
  EXPECT_EQ(result.status_code(), Status::BadSecurityChecksFailed);
  EXPECT_NE(result.shared_detail(), nullptr) << "asymmetric tamper failure must carry an ErrorDetail";
}

// ---------------------------------------------------------------------------
// Pin H - Cert validation rejects expired cert with BadCertificateTimeInvalid + detail.
// ---------------------------------------------------------------------------

TEST_F(CryptoPin, ValidateCertificateOnExpiredCertReturnsTimeInvalidWithDetail)
{
  TestPki pki{mCrypto};

  auto rootKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, /*keyLengthInBits=*/2048);
  ASSERT_NE(rootKeys, nullptr);
  auto rootCert = pki.create_root_ca(rootKeys, "PinH Root", "1");

  auto leafKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, /*keyLengthInBits=*/2048);
  ASSERT_NE(leafKeys, nullptr);

  // Validity window in the past: from -2 days to -1 day.
  const auto nowTp = DateTime::now().value();
  const auto from = DateTime{nowTp - std::chrono::days{2}};
  const auto to = DateTime{nowTp - std::chrono::days{1}};

  auto leafCert = pki.create_leaf_cert(leafKeys,
    rootKeys,
    rootCert,
    from,
    to,
    /*uris=*/{"urn:test:pinh:leaf"},
    /*hostnames=*/{},
    /*name=*/"PinH Leaf");

  std::promise<VoidResult> promise;
  mCrypto->validate_certificate_async(ua::test::make_crypto_request(leafCert,
                                        /*applicationUri=*/std::string{"urn:test:pinh:leaf"},
                                        /*endpointUrl=*/std::nullopt,
                                        CertificateUse::ApplicationInstance),
    ua::test::make_validation_material(TrustListValidationOptions{},
      /*trusted=*/{rootCert},
      /*trustedCrls=*/{},
      /*issuer=*/{},
      /*issuerCrls=*/{}),
    [&promise](VoidResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  EXPECT_TRUE(result.is_bad()) << "expired cert should be rejected";
  EXPECT_EQ(result.status_code(), Status::BadCertificateTimeInvalid);
  EXPECT_NE(result.shared_detail(), nullptr) << "cert-validation failure must carry an ErrorDetail";
}

// ---------------------------------------------------------------------------
// Pin I - ErrorDetail attribution to the crypto layer.
// ---------------------------------------------------------------------------
//
// Pulls the ErrorDetail emitted by an arbitrary Crypto failure (here, the same
// expired-cert stimulus as Pin H) and asserts the detail is attributable to the
// crypto layer via mSource or code. Permissive substring match - does not lock
// in a specific message.

TEST_F(CryptoPin, ErrorDetailFromCryptoFailureCarriesAttribution)
{
  TestPki pki{mCrypto};
  auto rootKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, /*keyLengthInBits=*/2048);
  ASSERT_NE(rootKeys, nullptr);
  auto rootCert = pki.create_root_ca(rootKeys, "PinI Root", "1");
  auto leafKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, /*keyLengthInBits=*/2048);
  ASSERT_NE(leafKeys, nullptr);

  const auto nowTp = DateTime::now().value();
  const auto from = DateTime{nowTp - std::chrono::days{2}};
  const auto to = DateTime{nowTp - std::chrono::days{1}};
  auto leafCert = pki.create_leaf_cert(leafKeys,
    rootKeys,
    rootCert,
    from,
    to,
    /*uris=*/{"urn:test:pini:leaf"},
    /*hostnames=*/{},
    /*name=*/"PinI Leaf");

  std::promise<VoidResult> promise;
  mCrypto->validate_certificate_async(ua::test::make_crypto_request(leafCert,
                                        /*applicationUri=*/std::string{"urn:test:pini:leaf"},
                                        /*endpointUrl=*/std::nullopt,
                                        CertificateUse::ApplicationInstance),
    ua::test::make_validation_material(TrustListValidationOptions{},
      /*trusted=*/{rootCert},
      /*trustedCrls=*/{},
      /*issuer=*/{},
      /*issuerCrls=*/{}),
    [&promise](VoidResult r) { promise.set_value(std::move(r)); });

  auto result = promise.get_future().get();
  ASSERT_TRUE(result.is_bad());
  auto detail = result.shared_detail();
  ASSERT_NE(detail, nullptr) << "see Pin H - every crypto failure must have detail";

  const bool sourceAttributed = contains_ci(detail->source, "crypto") ||
                                contains_ci(detail->source, "openssl") ||
                                contains_ci(detail->source, "certificate");
  const bool codeAttributed = contains_ci(detail->code, "cert") || contains_ci(detail->code, "crypto");

  EXPECT_TRUE(sourceAttributed || codeAttributed)
    << "ErrorDetail does not attribute the failure to the crypto layer.\n"
    << "  mSource = '" << detail->source << "'\n"
    << "  code   = '" << detail->code << "'\n"
    << "  summary = '" << detail->summary << "'\n"
    << "(Pin I requires a substring match on 'crypto'/'openssl'/'certificate' in "
       "mSource, or 'cert'/'crypto' in code. If the new code is genuinely better "
       "attributed, update Pin I in a separate PR - do NOT weaken to make this pass.)";
}

}  // namespace ua::test::behaviour_pins
