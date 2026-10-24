// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Regression pins for sub-phase 4.3 - SecureChannelContext keep-alive across an
// in-flight async decode / encode crypto hop (UAF fix, commit 9cbb3ef).
//
// THE BUG:
//   SecurityPolicy::decode_message_chunk_async / encode_message_async pass the
//   SecureChannelContext to inner flow structs that BORROW it as
//   `SecureChannelContext& context` ("caller-owned; outlives the flow"). The
//   flows hop off the strand onto crypto workers and back. If the owning channel
//   is destroyed mid-hop (~SecureChannelImpl dropping its
//   shared_ptr<SecureChannelContext> on a connection drop during the handshake),
//   the borrowed reference dangles. When the parked crypto completion landed it
//   dereferenced the freed context (e.g. flow->context.mStrand in
//   on_decode_asymmetric_decrypt_complete, flow->context.mRemoteCertificate in
//   start_decode_asymmetric_verify) - TSan reported a heap-use-after-free.
//
// THE FIX:
//   The public entry points already receive shared_ptr<SecureChannelContext>.
//   The fix captures that shared_ptr in the entry-point callback wrapper, which
//   is threaded through every flow step (each continuation holds the flow, which
//   holds the callback). The context therefore outlives any in-flight flow and
//   cannot be freed mid-flight.
//
// WHAT THESE PINS DO:
//   Use FakeAsyncCrypto in PARKED mode to hold a decode (and an encode) mid-flight
//   at a crypto hop. Drop the test's only external shared_ptr<SecureChannelContext>
//   so the entry callback's captured copy is the LAST owner. Then fire the parked
//   completion and assert the callback runs cleanly and returns a sane Result.
//
// FALSIFIABILITY:
//   The value is realized under ASAN/TSan: in a plain debug build the UAF is
//   invisible (the freed memory usually still reads back). On the UNFIXED code,
//   dropping the external context ref before firing the parked completion frees
//   the SecureChannelContext while the flow holds only a dangling reference; the
//   parked completion then dereferences freed memory. CI gcc-asan / gcc-tsan
//   flag this as a heap-use-after-free at on_decode_asymmetric_decrypt_complete /
//   start_decode_asymmetric_verify. On the FIXED code the captured shared_ptr
//   keeps the context alive, so the completion runs cleanly. These pins assert
//   the post-teardown completion runs and produces a Result (no crash, no UAF).
//
//   The teardown-during-parked-crypto path is exercised regardless of build
//   sanitiser, so this also serves as a behavioural smoke test that the entry
//   callback survives external-owner drop on both the decode and encode surfaces.

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "test_pki_helpers.h"

#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_crypto.h"
#include "ua_memory_stream.h"
#include "ua_null_stream.h"
#include "ua_open_secure_channel_request.h"
#include "ua_read_request.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_stack_utilities.h"

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

EncodingLimits keepalive_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

std::shared_ptr<const Crypto> create_real_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

// Build an OPN chunk whose cipherText region (SequenceHeader + body) is a whole
// number of asymmetric blocks, so SecurityPolicy::asymmetric_decrypt_async passes
// its block-size check and reaches the per-block crypto hop (which the parked
// FakeAsyncCrypto holds). Mirrors the build_opn_chunk helper used by the 4.3
// pins; kept file-local because it must control the body size precisely.
ByteString build_opn_chunk_block_aligned(std::string securityPolicyUri,
  std::shared_ptr<const X509Certificate> senderCert, ByteString receiverThumbprint, size_t bodySize)
{
  stack_utils::AsymmetricSecurityHeader securityHeader;
  securityHeader.securityPolicyUri = std::move(securityPolicyUri);
  securityHeader.senderCertificate = std::move(senderCert);
  securityHeader.receiverCertificateThumbprint = std::move(receiverThumbprint);

  size_t securityHeaderSize = 0;
  {
    NullStream ns;
    UaBinaryEncoder enc(CodecNamespaceContext{}, ns);
    securityHeader.encode(keepalive_limits(), enc);
    securityHeaderSize = enc.stream().get_position();
  }

  const uint32_t chunkSize =
    static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes + securityHeaderSize +
                          stack_utils::SequenceHeader::sizeInBytes + bodySize);

  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  auto limits = keepalive_limits();

  stack_utils::UaScMessageHeader header;
  header.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
  header.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
  header.messageChunkSize = chunkSize;
  header.secureChannelId = 0;
  header.encode(limits, enc);

  securityHeader.encode(limits, enc);

  stack_utils::SequenceHeader seq;
  seq.sequenceNumber = 1;
  seq.requestId = 1;
  seq.encode(limits, enc);

  std::vector<byte> body(bodySize, byte{0x00});
  enc.stream().write_all(span<const byte>{body});

  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  return ByteString{span<const byte>{out}};
}

// Build a SecureChannelContext whose crypto is the PARKED FakeAsyncCrypto and
// whose cert store inline-validates. Uninitialised so the decode adopts the
// sender certificate as mRemoteCertificate.
std::shared_ptr<SecureChannelContext> make_parked_context(
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> parkedCrypto,
  std::shared_ptr<CertificateStore> certStore, std::shared_ptr<const X509Certificate> localCertificate)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->encodingLimits = keepalive_limits();
  ctx->negotiatedLimits = {.sendBufferSize = 65536, .receiveBufferSize = 65536};
  ctx->crypto = std::move(parkedCrypto);
  ctx->certStore = certStore;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ctx->localCertificate = std::move(localCertificate);
  ctx->secureChannelId = 0;
  ctx->lastRxSequenceNumber = std::nullopt;
  return ctx;
}

// Busy-wait (bounded) until the predicate is true. Used to detect that the flow
// has reached and parked the crypto hop before we drop the external context ref.
template<typename Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout = 2000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
      return true;
    std::this_thread::sleep_for(1ms);
  }
  return pred();
}

}  // namespace

class ContextKeepalivePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(mExecutor));
    mRealCrypto = create_real_crypto();
    ASSERT_NE(mRealCrypto, nullptr);
    mParkedCrypto = ::ua::test_helpers::FakeAsyncCrypto::create();
    mParkedCrypto->set_park_async(true);
    mCertStore = ::ua::test_helpers::FakeCertificateStore::create();
  }

  void TearDown() override
  {
    mPool.join();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  std::shared_ptr<const Crypto> mRealCrypto;
  std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto> mParkedCrypto;
  std::shared_ptr<::ua::test_helpers::FakeCertificateStore> mCertStore;
};

// ---------------------------------------------------------------------------
// DECODE: context survives external-owner drop while a decode is parked at the
// asymmetric crypto hop.
// ---------------------------------------------------------------------------
TEST_F(ContextKeepalivePin, DecodeCompletionRunsAfterExternalContextOwnerDropped)
{
  TestPki pki{mRealCrypto};
  auto localKeys = mRealCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "Keepalive Server", "70");
  auto clientKeys = mRealCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert = pki.create_self_signed_application_cert(clientKeys, "Keepalive Client", "700");

  auto ctx = make_parked_context(*mStrand, mParkedCrypto, mCertStore, localCert);

  // cipherText = SequenceHeader (8) + body must be a multiple of the 2048-bit RSA
  // block size (256), so body = 256 - 8 = 248.
  auto chunk = build_opn_chunk_block_aligned(
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", clientCert, localCert->thumbprint(), 248);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  std::promise<DecodedMessageChunkResult> resultPromise;
  auto resultFuture = resultPromise.get_future();

  policy->decode_message_chunk_async(ctx,
    std::move(chunk),
    [&resultPromise](DecodedMessageChunkResult result) mutable
    { resultPromise.set_value(std::move(result)); });

  // The decode runs: header checks -> inline cert validate -> asymmetric decrypt
  // (PARKED on the per-block hop). Wait for it to reach and park that hop.
  ASSERT_TRUE(wait_until([&]() { return mParkedCrypto->pending_asymmetric_decrypt_count() >= 1; }))
    << "decode should reach and park the asymmetric decrypt hop";

  // Drop the test's ONLY external strong reference to the context. If the entry
  // callback did not capture the context (unfixed code), this frees it while the
  // flow holds only a dangling reference.
  ctx.reset();

  // Fire the parked decrypt completion. On the fixed code the captured shared_ptr
  // keeps the context alive, so on_decode_asymmetric_decrypt_complete can safely
  // touch flow->context.mStrand / mRemoteCertificate. On the unfixed code under
  // ASAN/TSan this dereferences freed memory.
  mParkedCrypto->complete_pending_asymmetric_decrypt(0, ua::Crypto::ByteSpanResult{span<const byte>{}});

  // The flow advances to the asymmetric verify hop (also parked). Fire it so the
  // flow runs to its terminal callback.
  ASSERT_TRUE(wait_until([&]() { return mParkedCrypto->pending_asymmetric_verify_count() >= 1; }))
    << "decode should advance to and park the asymmetric verify hop after decrypt completes";
  mParkedCrypto->complete_pending_asymmetric_verify(0, VoidResult{});

  // The terminal callback must run (no UAF / no crash) and yield a Result. The
  // status is not required here - the parked completions supply no real
  // plaintext, so a Bad status is expected; the point is the callback RAN
  // cleanly after the external context owner was dropped.
  ASSERT_EQ(resultFuture.wait_for(2s), std::future_status::ready)
    << "decode terminal callback must run after teardown-during-parked-crypto";
  auto result = resultFuture.get();
  EXPECT_TRUE(result.is_good() || result.is_bad())
    << "decode must produce a sane Result after the context owner was dropped mid-flight";
}

// ---------------------------------------------------------------------------
// ENCODE: context survives external-owner drop while an encode is parked at the
// asymmetric crypto hop.
// ---------------------------------------------------------------------------
TEST_F(ContextKeepalivePin, EncodeCompletionRunsAfterExternalContextOwnerDropped)
{
  TestPki pki{mRealCrypto};
  auto localKeys = mRealCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_self_signed_application_cert(localKeys, "Keepalive Enc Server", "71");
  auto localKeyPair = localKeys;
  auto remoteKeys = mRealCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto remoteCert = pki.create_self_signed_application_cert(remoteKeys, "Keepalive Enc Client", "710");

  auto ctx = make_parked_context(*mStrand, mParkedCrypto, mCertStore, localCert);
  ctx->localKeyPair = localKeyPair;
  ctx->remoteCertificate = remoteCert;
  ctx->namespaceIndexCallback = [](std::string_view) -> uint16_t
  {
    return 0;
  };

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // Encoding an OpenSecureChannelRequest drives the asymmetric encode path (sign
  // / encrypt) which hops to the parked crypto. Any OPN-typed message routes to
  // encode_asymmetric_message_async.
  auto message = std::make_shared<OpenSecureChannelRequest>();

  std::promise<VoidResult> resultPromise;
  auto resultFuture = resultPromise.get_future();

  policy->encode_message_async(
    ctx,
    /*requestId=*/1,
    message,
    [](ua::ByteString) {},
    [&resultPromise](VoidResult result) mutable { resultPromise.set_value(std::move(result)); });

  // Wait for the encode to reach and park its first asymmetric crypto hop
  // (sign for SignAndEncrypt). encode signs before it encrypts.
  ASSERT_TRUE(wait_until(
    [&]()
    {
      return mParkedCrypto->pending_asymmetric_sign_count() >= 1 ||
             mParkedCrypto->pending_asymmetric_encrypt_count() >= 1;
    }))
    << "encode should reach and park an asymmetric crypto hop";

  // Drop the test's ONLY external strong reference to the context.
  ctx.reset();

  // Fire the parked hop(s). Complete sign first (if present), then encrypt, until
  // the terminal callback fires. We complete whatever is parked; the encode flow
  // chains sign -> encrypt -> chunk emission. We do not require encode SUCCESS -
  // only that the terminal callback RUNS after the external owner was dropped.
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  while (
    resultFuture.wait_for(0ms) != std::future_status::ready && std::chrono::steady_clock::now() < deadline)
  {
    if (mParkedCrypto->pending_asymmetric_sign_count() >= 1)
    {
      // A short sign result is enough to advance the flow; the encode either
      // proceeds or fails on the bogus signature length - both run the callback.
      std::vector<byte> sig(256, byte{0x00});
      mParkedCrypto->complete_pending_asymmetric_sign(0, ByteString{span<const byte>{sig}});
    }
    else if (mParkedCrypto->pending_asymmetric_encrypt_count() >= 1)
    {
      mParkedCrypto->complete_pending_asymmetric_encrypt(0, VoidResult{});
    }
    else
    {
      std::this_thread::sleep_for(1ms);
    }
  }

  ASSERT_EQ(resultFuture.wait_for(2s), std::future_status::ready)
    << "encode terminal callback must run after teardown-during-parked-crypto";
  auto result = resultFuture.get();
  EXPECT_TRUE(result.is_good() || result.is_bad())
    << "encode must produce a sane Result after the context owner was dropped mid-flight";
}

}  // namespace ua::test::behaviour_pins
