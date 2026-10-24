// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.3a (SecurityPolicy::decode_asymmetric_message_chunk).
//
// What is pinned (synchronous-precondition-only subset; no Crypto async hop reached):
//   DA-F: Mismatched SecurityPolicy URI in the security header rejected with
//         BadSecurityPolicyRejected + non-null ErrorDetail.
//   DA-G: Mismatched receiver-certificate thumbprint rejected with
//         BadCertificateInvalid + non-null ErrorDetail.
//   DA-H: Remote certificate change on an already-open channel rejected with
//         BadCertificateInvalid + non-null ErrorDetail.
//   DA-I: Missing sender certificate on an authenticated policy rejected with
//         BadCertificateInvalid + non-null ErrorDetail.
//   DA-J: Sender certificate exceeding the chunk-overhead bound (Part 6 section 6.7.2)
//         rejected with BadDecodingError + non-null ErrorDetail.
//
// Pins not authored in this file (with reason - see runbook section 4.1 for full table):
//   DA-A, DA-B, DA-C, DA-D, DA-E, DA-K - boundary-property pins around
//                                         validate_certificate / asymmetric_decrypt /
//                                         asymmetric_verify; require FakeAsyncCrypto
//                                         (sub-phase-local fake described in
//                                         runbook section 4.0.1, not yet authored).
//   DA-L - threading-affinity pin requires `running_in_this_thread()` on
//          boost::asio::strand<boost::asio::any_io_executor> which does not exist on the current
//          boost::asio::strand<boost::asio::any_io_executor> surface.

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "run_async_sync.h"
#include "test_pki_helpers.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_null_stream.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_stack_utilities.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_status_code.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

EncodingLimits pin_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

std::shared_ptr<const Crypto> create_pin_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

// Build an OPN chunk with the given AsymmetricSecurityHeader fields. Used by
// pins that exercise the synchronous header-validation paths.
ByteString build_opn_chunk(uint32_t secureChannelId, std::string securityPolicyUri,
  std::shared_ptr<const X509Certificate> senderCert,
  std::vector<std::shared_ptr<const X509Certificate>> issuerCerts, ByteString receiverThumbprint,
  uint32_t sequenceNumber, uint32_t requestId, span<const byte> body)
{
  stack_utils::AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = std::move(securityPolicyUri);
  sh.senderCertificate = std::move(senderCert);
  sh.issuerCertificates = std::move(issuerCerts);
  sh.receiverCertificateThumbprint = std::move(receiverThumbprint);

  size_t securityHeaderSize = 0;
  {
    NullStream ns;
    UaBinaryEncoder enc(CodecNamespaceContext{}, ns);
    sh.encode(pin_limits(), enc);
    securityHeaderSize = enc.stream().get_position();
  }

  const uint32_t chunkSize =
    static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes + securityHeaderSize +
                          stack_utils::SequenceHeader::sizeInBytes + body.size());

  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  auto limits = pin_limits();

  stack_utils::UaScMessageHeader header;
  header.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
  header.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
  header.messageChunkSize = chunkSize;
  header.secureChannelId = secureChannelId;
  header.encode(limits, enc);

  sh.encode(limits, enc);

  stack_utils::SequenceHeader seq;
  seq.sequenceNumber = sequenceNumber;
  seq.requestId = requestId;
  seq.encode(limits, enc);

  enc.stream().write_all(body);

  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  return ByteString{span<const byte>{out}};
}

// Build an OPN chunk with raw security-header field bytes - bypasses the encoder
// so we can inject an oversized sender certificate (DA-J).
ByteString build_opn_chunk_raw(uint32_t secureChannelId, ua::String securityPolicyUri,
  ByteString senderCertificates, ByteString receiverThumbprint, uint32_t sequenceNumber, uint32_t requestId,
  span<const byte> body)
{
  memory_stream_device::Dynamic streamDevice{64 * 1024, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  auto limits = pin_limits();
  auto depth = limits.stack_depth();

  stack_utils::UaScMessageHeader header;
  header.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
  header.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
  header.messageChunkSize = 0;  // patched below
  header.secureChannelId = secureChannelId;
  header.encode(limits, enc);

  enc.encode(depth, securityPolicyUri);
  enc.encode(depth, senderCertificates);
  enc.encode(depth, receiverThumbprint);

  stack_utils::SequenceHeader seq;
  seq.sequenceNumber = sequenceNumber;
  seq.requestId = requestId;
  seq.encode(limits, enc);

  enc.stream().write_all(body);

  const uint32_t chunkSize = static_cast<uint32_t>(stream.get_position());
  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  // Patch MessageChunkSize at offset 4 (after type[3] + isFinal[1]).
  out[4] = static_cast<byte>(chunkSize & 0xFF);
  out[5] = static_cast<byte>((chunkSize >> 8) & 0xFF);
  out[6] = static_cast<byte>((chunkSize >> 16) & 0xFF);
  out[7] = static_cast<byte>((chunkSize >> 24) & 0xFF);
  return ByteString{span<const byte>{out}};
}

std::shared_ptr<SecureChannelContext> make_uninitialised_context(boost::asio::any_io_executor /*ex*/,
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> crypto,
  std::shared_ptr<const X509Certificate> localCertificate)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = pin_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = std::move(crypto);
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = std::move(localCertificate);
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;
  return ctx;
}

std::shared_ptr<SecureChannelContext> make_open_context_with_remote(boost::asio::any_io_executor /*ex*/,
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> crypto,
  uint32_t secureChannelId, std::shared_ptr<const X509Certificate> localCertificate,
  std::shared_ptr<const X509Certificate> remoteCertificate)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->encodingLimits = pin_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = std::move(crypto);
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = std::move(localCertificate);
  ctx->remoteCertificate = std::move(remoteCertificate);
  ctx->secureChannelId = secureChannelId;
  ctx->lastRxSequenceNumber = std::nullopt;
  return ctx;
}

}  // namespace

class DecodeAsymmetricPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(mExecutor));
    mCrypto = create_pin_crypto();
    ASSERT_NE(mCrypto, nullptr);
  }

  void TearDown() override
  {
    mPool.join();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  std::shared_ptr<const Crypto> mCrypto;
};

// ---------------------------------------------------------------------------
// Pin DA-F - security policy URI mismatch.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:404-412 throws synchronously when the
// AsymmetricSecurityHeader's URI does not match the policy. Asserts status
// BadSecurityPolicyRejected + non-null detail.

TEST_F(DecodeAsymmetricPin, MismatchedSecurityPolicyUriIsRejectedSynchronously)
{
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-F Server", "10");

  auto ctx = make_uninitialised_context(mExecutor, *mStrand, mCrypto, localCert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#None",
    /*senderCert*/ nullptr,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ {},
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  bool rightStatus = false;
  bool detailNonNull = false;
  try
  {
    (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    rightStatus = (ex.status() == Status::BadSecurityPolicyRejected);
    detailNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(rightStatus) << "URI mismatch must be rejected with BadSecurityPolicyRejected";
  EXPECT_TRUE(detailNonNull) << "URI-mismatch failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DA-G - mismatched receiver-certificate thumbprint.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:428-434 throws synchronously when the
// ReceiverCertificateThumbprint in the header does not match the local
// certificate's thumbprint.

TEST_F(DecodeAsymmetricPin, MismatchedReceiverThumbprintIsRejectedSynchronously)
{
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-G Server", "20");

  auto clientKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert = pki.create_self_signed_application_cert(clientKeys, "PinDA-G Client", "201");

  auto ctx = make_uninitialised_context(mExecutor, *mStrand, mCrypto, localCert);

  ByteString wrongThumbprint = localCert->thumbprint();
  ASSERT_FALSE(wrongThumbprint.empty());
  wrongThumbprint[0] = static_cast<uint8_t>(~static_cast<unsigned char>(wrongThumbprint[0]));

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ clientCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ wrongThumbprint,
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  bool rightStatus = false;
  bool detailNonNull = false;
  try
  {
    (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    rightStatus = (ex.status() == Status::BadCertificateInvalid);
    detailNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(rightStatus) << "thumbprint mismatch must be rejected with BadCertificateInvalid";
  EXPECT_TRUE(detailNonNull) << "thumbprint-mismatch failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DA-H - remote certificate change on an already-open channel.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:441-447 throws synchronously when the
// channel is already open with a remote certificate and the new sender certificate
// in the OPN chunk differs from it.

TEST_F(DecodeAsymmetricPin, RemoteCertChangeOnOpenChannelIsRejectedSynchronously)
{
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-H Server", "30");

  auto client1Keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto client1Cert = pki.create_self_signed_application_cert(client1Keys, "PinDA-H Client1", "301");
  auto client2Keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto client2Cert = pki.create_self_signed_application_cert(client2Keys, "PinDA-H Client2", "302");

  auto ctx =
    make_open_context_with_remote(mExecutor, *mStrand, mCrypto, /*channelId*/ 1, localCert, client1Cert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 1,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ client2Cert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  bool rightStatus = false;
  bool detailNonNull = false;
  try
  {
    (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    rightStatus = (ex.status() == Status::BadCertificateInvalid);
    detailNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(rightStatus) << "remote cert change must be rejected with BadCertificateInvalid";
  EXPECT_TRUE(detailNonNull) << "remote-cert-change failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DA-I - missing sender certificate on an authenticated policy.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:418-424 throws synchronously when the
// policy is authenticated and the security header's senderCertificate is null.

TEST_F(DecodeAsymmetricPin, MissingSenderCertOnAuthenticatedPolicyIsRejectedSynchronously)
{
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-I Server", "40");

  auto ctx = make_uninitialised_context(mExecutor, *mStrand, mCrypto, localCert);

  const std::array<byte, 1> body{std::byte{0x00}};
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ nullptr,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  bool rightStatus = false;
  bool detailNonNull = false;
  try
  {
    (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    rightStatus = (ex.status() == Status::BadCertificateInvalid);
    detailNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(rightStatus)
    << "missing sender cert on authenticated policy must be rejected with BadCertificateInvalid";
  EXPECT_TRUE(detailNonNull) << "missing-sender-cert failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DA-J - sender certificate exceeding chunk-overhead bound.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:391-401 throws synchronously when the
// declared sender-certificate size (after subtracting fixed header overhead)
// exceeds what fits in the negotiated receive buffer. Locks Part 6 section 6.7.2 - locks
// that 4.3b doesn't move this check past the validate_certificate hop where a fast
// path could skip it.
//
// Stimulus: bloat the sender-certificate bytes with garbage so the
// SenderCertificateLength field reads larger than allowed, while the
// ReceiveBufferSize is tight (4096 bytes). Pre-flip: BadDecodingError.

TEST_F(DecodeAsymmetricPin, OversizedSenderCertIsRejectedSynchronouslyWithBadDecodingError)
{
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-J Server", "50");

  // For DA-J, use SecurityPolicy::None - the oversize-cert check fires before
  // is_authenticated() per ua_security_policy.cpp:391-401, ahead of policy URI
  // checks too. Tight ReceiveBufferSize forces enforcement.
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = *mStrand;
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = pin_limits();
  ctx->crypto = mCrypto;
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 4096;

  // Bloat the sender-certificate DER buffer by appending trailing garbage.
  auto der = localCert->der_encoding();
  ByteString bloated;
  bloated.payload().insert(bloated.end(), der.begin(), der.end());
  bloated.resize(bloated.size() + 60000, uint8_t{0xEE});

  const std::array<byte, 1> body{std::byte{0x01}};
  auto chunk = build_opn_chunk_raw(/*secureChannelId*/ 0,
    "http://opcfoundation.org/UA/SecurityPolicy#None",
    std::move(bloated),
    {},
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  bool rightStatus = false;
  bool detailNonNull = false;
  try
  {
    (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    rightStatus = (ex.status() == Status::BadDecodingError);
    detailNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(rightStatus) << "oversized sender cert must be rejected with BadDecodingError";
  EXPECT_TRUE(detailNonNull) << "oversized-cert failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DA-PAD - oversized declared PaddingSize in the decrypted plaintext.
// ---------------------------------------------------------------------------
//
// Covers: the asymmetric padding-strip underflow guard in
// on_decode_asymmetric_verify_complete (ua_security_policy.cpp). A forged/edge-case
// OPN whose decrypted plaintext declares a PaddingSize larger than the plaintext
// length must be rejected with Bad_SecurityChecksFailed, NOT crash the server. Before
// the guard, plainText.size() - totalPaddingOverhead underflowed a size_t and
// safe_sub_span threw [BadOutOfRange] out of a strand handler -> std::terminate (DoS).
//
// Reproduction: real decode flow over decode_message_chunk_async with crypto parked
// (FakeAsyncCrypto). A 4096-bit sender certificate selects the two-byte ExtraPadding
// path (public_key_bit_length() > 2048), so the injected post-decrypt plaintext can
// declare PaddingSize 0xFFFF - far larger than the recovered plaintext. The cert store
// is faked so certificate validation succeeds without crypto; the parked asymmetric
// decrypt writes attacker-controlled 0xFF plaintext into the output buffer (mirroring
// the real provider contract), and asymmetric verify is completed as success so the
// flow reaches the padding-strip guard exactly as a forged-signature-bypass would. The
// context carries no strand, so dispatch_to_strand runs inline and the flow is driven
// deterministically on the test thread.

TEST_F(DecodeAsymmetricPin, OversizedPaddingSizeIsRejectedWithoutCrash)
{
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  ASSERT_NE(fakeCrypto, nullptr);

  // 4096-bit keys force the two-byte ExtraPadding decode path so PaddingSize can be
  // made to exceed the plaintext length (single-byte padding maxes at 255). Certificates must be
  // created with the REAL crypto (mCrypto) - FakeAsyncCrypto's key pair has no real private
  // credential, so PEM export during cert creation throws. The fake is only for the parked
  // decrypt/verify in the context below.
  TestPki pki{mCrypto};
  auto localKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 4096);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "PinDA-PAD Server", "60");
  auto clientKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 4096);
  auto clientCert = pki.create_self_signed_application_cert(clientKeys, "PinDA-PAD Client", "601");
  ASSERT_GT(clientCert->public_key_bit_length(), 2048u)
    << "sender key must exceed 2048 bits to select the ExtraPadding decode path";

  auto certStore = ua::test_helpers::FakeCertificateStore::create();

  auto ctx = std::make_shared<SecureChannelContext>();
  // The decode flow marshals every step onto the context strand. A strand over an io_context THIS
  // TEST polls keeps the sequence exactly as deterministic as inline dispatch was: nothing runs
  // until drain() is called, and drain() returns only once the strand has emptied. restart() first,
  // because an io_context left STOPPED by running out of work ignores a later poll().
  boost::asio::io_context decodeIo;
  ctx->boundStrand = boost::asio::make_strand(boost::asio::any_io_executor{decodeIo.get_executor()});
  const auto drain = [&decodeIo]
  {
    decodeIo.restart();
    decodeIo.poll();
  };
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = pin_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = fakeCrypto;
  ctx->certStore = certStore;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ctx->localCertificate = localCert;
  ctx->localKeyPair = localKeys;
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;

  // Ciphertext region = SequenceHeader(8) + body. For two 512-byte RSA-4096 blocks
  // (1024 bytes) the body is 1024 - 8 = 1016 bytes. Block content is arbitrary - the
  // parked decrypt ignores it and writes the injected plaintext into the output buffer.
  std::vector<byte> body(1016, byte{0x5A});
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    /*securityPolicyUri*/ "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    /*senderCert*/ clientCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*seq*/ 1,
    /*reqId*/ 1,
    body);

  fakeCrypto->set_park_async(true);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  std::optional<DecodedMessageChunkResult> outcome;
  ASSERT_NO_THROW({
    policy->decode_message_chunk_async(
      ctx, std::move(chunk), [&outcome](DecodedMessageChunkResult result) { outcome = std::move(result); });
    drain();

    // Drive the parked crypto operations. Two ciphertext blocks -> two decrypt
    // completions; each writes 512 bytes of 0xFF into the caller's output buffer.
    // After the 512-byte signature is stripped, the surviving plaintext ends in
    // 0xFF 0xFF -> declared PaddingSize 0xFFFF.
    ASSERT_EQ(fakeCrypto->pending_asymmetric_decrypt_count(), 1u);
    fakeCrypto->complete_pending_asymmetric_decrypt_with_fill(0, byte{0xFF}, /*length*/ 512);
    drain();
    ASSERT_EQ(fakeCrypto->pending_asymmetric_decrypt_count(), 1u);
    fakeCrypto->complete_pending_asymmetric_decrypt_with_fill(0, byte{0xFF}, /*length*/ 512);
    drain();

    // Signature verify passes so the flow reaches the padding-strip guard.
    ASSERT_EQ(fakeCrypto->pending_asymmetric_verify_count(), 1u);
    fakeCrypto->complete_pending_asymmetric_verify(0, VoidResult{});
    drain();
  });

  ASSERT_TRUE(outcome.has_value()) << "decode must complete (graceful failure) rather than crash/hang";
  EXPECT_TRUE(outcome->is_bad()) << "oversized padding must be rejected, not accepted";
  EXPECT_EQ(outcome->status_code(), Status::BadSecurityChecksFailed)
    << "oversized padding must surface as Bad_SecurityChecksFailed";
  EXPECT_NE(outcome->shared_detail(), nullptr) << "padding rejection must carry an ErrorDetail";

  ctx.reset();
}

// ---------------------------------------------------------------------------
// An ECC OPN chunk must carry its security header, the sequence header and the trailing signature
// in full. A chunk shorter than that is refused with Bad_SecurityChecksFailed before any length
// arithmetic on it; the reassembly path never sees it.
// @relation(AC-SVR-SC-007-ECC-OPN-CHUNK-SHORTER-THAN-ITS-SIGNATURE-IS-REFUSED, scope=function)
TEST_F(DecodeAsymmetricPin, EccOpnChunkShorterThanItsSignatureIsRefused)
{
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  ASSERT_NE(fakeCrypto, nullptr);

  TestPki pki{mCrypto};
  auto senderKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto senderCert = pki.create_root_ca(senderKeys, "EC-SHORT Client", "702");
  ASSERT_NE(senderCert, nullptr);
  // The chunk names this side's certificate as its recipient (Part 6 Table 58), so the recipient check
  // passes and the refusal under test is the length one.
  auto localKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "EC-SHORT Server", "703");
  ASSERT_NE(localCert, nullptr);

  auto eccPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  ASSERT_NE(eccPolicy, nullptr);
  auto certStore = ua::test_helpers::FakeCertificateStore::create();

  auto ctx = std::make_shared<SecureChannelContext>();
  boost::asio::io_context decodeIo;
  ctx->boundStrand = boost::asio::make_strand(boost::asio::any_io_executor{decodeIo.get_executor()});
  const auto drain = [&decodeIo]
  {
    decodeIo.restart();
    decodeIo.poll();
  };
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = pin_limits();
  ctx->negotiatedLimits = {
    .receiveBufferSize = 65536, .recvMaxMessageSize = 1u << 20, .recvMaxChunkCount = 10};
  ctx->crypto = fakeCrypto;
  ctx->certStore = certStore;
  ctx->securityPolicy = eccPolicy;
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = localCert;
  ctx->localKeyPair = localKeys;
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;

  // A body shorter than the policy's signature: the chunk cannot contain a signature at all.
  const size_t signatureSize = eccPolicy->asymmetric_signature_size(senderCert.get());
  ASSERT_EQ(signatureSize, 64u);
  const std::vector<byte> body(8, byte{0x5A});
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    std::string{eccPolicy->uri()},
    senderCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  fakeCrypto->set_park_async(true);

  std::optional<DecodedMessageChunkResult> outcome;
  size_t verifiesAttempted = 0;
  ASSERT_NO_THROW({
    eccPolicy->decode_message_chunk_async(
      ctx, std::move(chunk), [&outcome](DecodedMessageChunkResult result) { outcome = std::move(result); });
    drain();
    // The refusal precedes signature verification: the pending count is asserted to be zero below.
    // Should a verify be pending, the decode reached the arithmetic it must not reach; it is completed
    // only so the outcome can be inspected instead of hanging.
    verifiesAttempted = fakeCrypto->pending_asymmetric_verify_count();
    if (verifiesAttempted == 1)
    {
      fakeCrypto->complete_pending_asymmetric_verify(0, VoidResult{});
      drain();
    }
  });
  EXPECT_EQ(verifiesAttempted, 0u)
    << "the short chunk must be refused before signature verification is attempted";

  ASSERT_TRUE(outcome.has_value()) << "decode must complete (graceful refusal) rather than crash or hang";
  EXPECT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code(), Status::BadSecurityChecksFailed)
    << "a chunk without room for its signature must be refused as a security-check failure";
  EXPECT_NE(outcome->shared_detail(), nullptr);
  EXPECT_TRUE(ctx->receivedMessageBody.empty()) << "nothing of the refused chunk may be accumulated";

  ctx.reset();
  drain();
}

// Pin EC-FLOOD - ECC OPN reassembly must honour the negotiated MaxChunkCount.
// ---------------------------------------------------------------------------
//
// Covers the anti chunk-flood reassembly bound on the ephemeral-key OPN path (ua_sec_pol_ephemeral_key.cpp).
// The ECC sign-only OPN path accumulates the assembled message body itself and previously NEVER consulted the
// negotiated MaxChunkCount / MaxMessageSize that the base (RSA) SecurityPolicy::copy_message_body enforces.
// An unauthenticated peer could therefore stream Intermediate ('C') ECC OPN chunks - each validly self-signed
// with its own sender certificate - to grow receivedMessageBody without bound, a pre-auth resource-exhaustion
// DoS. The bound must reject with Bad_TcpMessageTooLarge (which tears the channel down).
//
// Reproduction mirrors DA-PAD: crypto is PARKED (FakeAsyncCrypto) so the ECDSA verify is completed as
// success and the flow reaches finalize_decode_ecc exactly as a forged-signature bypass would
// (certificate validation auto-accepts via FakeCertificateStore). The context is primed with
// receivedChunkCount already at the negotiated cap (== one prior Intermediate chunk accepted), so
// this chunk pushes the per-message count over the limit and must be rejected. No context strand, so
// dispatch_to_strand runs inline and the flow is driven deterministically here.
// @relation(AC-SVR-SC-007-ECC-OPN-CHUNK-SHORTER-THAN-ITS-SIGNATURE-IS-REFUSED, scope=function)  // control arm
TEST_F(DecodeAsymmetricPin, EccOpnReassemblyHonoursMaxChunkCount)
{
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  ASSERT_NE(fakeCrypto, nullptr);

  // Real ECC sender certificate (the fake only parks the validate/verify hops below).
  TestPki pki{mCrypto};
  auto senderKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto senderCert = pki.create_self_signed_application_cert(senderKeys, "EC-FLOOD Client", "701");
  ASSERT_NE(senderCert, nullptr);
  // The chunk names this side's certificate as its recipient (Part 6 Table 58), so the recipient check
  // passes and the flow reaches the reassembly bound.
  auto localKeys =
    mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "EC-FLOOD Server", "704");
  ASSERT_NE(localCert, nullptr);

  auto eccPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  ASSERT_NE(eccPolicy, nullptr);

  auto certStore = ua::test_helpers::FakeCertificateStore::create();

  auto ctx = std::make_shared<SecureChannelContext>();
  // The decode flow marshals every step onto the context strand. A strand over an io_context THIS
  // TEST polls keeps the sequence exactly as deterministic as inline dispatch was: nothing runs
  // until drain() is called, and drain() returns only once the strand has emptied. restart() first,
  // because an io_context left STOPPED by running out of work ignores a later poll().
  boost::asio::io_context decodeIo;
  ctx->boundStrand = boost::asio::make_strand(boost::asio::any_io_executor{decodeIo.get_executor()});
  const auto drain = [&decodeIo]
  {
    decodeIo.restart();
    decodeIo.poll();
  };
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = pin_limits();
  ctx->negotiatedLimits = {
    .receiveBufferSize = 65536, .recvMaxMessageSize = 1u << 20, .recvMaxChunkCount = 1};
  ctx->crypto = fakeCrypto;
  ctx->certStore = certStore;
  ctx->securityPolicy = eccPolicy;
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->localCertificate = localCert;
  ctx->localKeyPair = localKeys;
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;
  // Prime mid-reassembly state: one Intermediate chunk already accumulated, count at the cap.
  ctx->receivedChunkCount = 1;

  // Body = small payload + a 64-byte (NistP256) placeholder ECDSA signature. The parked verify makes
  // the signature content irrelevant; only its SIZE matters for the body/signature split in finalize.
  const size_t signatureSize = eccPolicy->asymmetric_signature_size(senderCert.get());
  ASSERT_EQ(signatureSize, 64u);
  const std::vector<byte> body(8 + signatureSize, byte{0x5A});
  auto chunk = build_opn_chunk(/*secureChannelId*/ 0,
    std::string{eccPolicy->uri()},
    senderCert,
    /*issuerCerts*/ {},
    /*receiverThumbprint*/ localCert->thumbprint(),
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  fakeCrypto->set_park_async(true);

  std::optional<DecodedMessageChunkResult> outcome;
  ASSERT_NO_THROW({
    eccPolicy->decode_message_chunk_async(
      ctx, std::move(chunk), [&outcome](DecodedMessageChunkResult result) { outcome = std::move(result); });
    drain();

    // Certificate validation auto-accepts via the fake store; the ECDSA verify is parked - complete it
    // as success so the flow reaches the reassembly bound in finalize_decode_ecc.
    ASSERT_EQ(fakeCrypto->pending_asymmetric_verify_count(), 1u);
    fakeCrypto->complete_pending_asymmetric_verify(0, VoidResult{});
    drain();
  });

  ASSERT_TRUE(outcome.has_value()) << "decode must complete (graceful failure) rather than crash/hang";
  EXPECT_TRUE(outcome->is_bad()) << "over-cap ECC reassembly must be rejected, not accepted";
  EXPECT_EQ(outcome->status_code(), Status::BadTcpMessageTooLarge)
    << "exceeding the negotiated MaxChunkCount must surface as Bad_TcpMessageTooLarge";
  EXPECT_NE(outcome->shared_detail(), nullptr) << "rejection must carry an ErrorDetail";

  ctx.reset();
}

}  // namespace ua::test::behaviour_pins
