// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.3a (SecurityPolicy::decode_symmetric_message_chunk).
//
// What is pinned (synchronous-precondition-only subset):
//   DS-D: Unknown token ID with no pending token rejected with
//         BadSecureChannelTokenUnknown + non-null ErrorDetail.
//   DS-E: Unknown token ID with mismatched pending token rejected with
//         BadSecureChannelTokenUnknown + non-null ErrorDetail.
//   DS-F: Pending token promoted to active on first chunk that uses its ID; the
//         previous active token is dropped. Locks the section 3.2 token-swap invariant.
//   DS-H: Missing active security token rejected with BadInvalidState +
//         non-null ErrorDetail.
//
// Pins not authored in this file (with reason - see runbook section 4.2 for full table):
//   DS-A, DS-B, DS-C - boundary-property pins around symmetric_decrypt/verify;
//                      require FakeAsyncCrypto (sub-phase-local fake described in
//                      runbook section 4.0.1, not yet authored).
//   DS-G - invalid-padding pin requires the symmetric_decrypt path to complete
//          successfully; needs encrypted-and-signed token state. Authoring this
//          end-to-end (real OpenSslCrypto + valid signing keys) duplicates the
//          existing parameterised test fixtures and adds no pin-specific value
//          over them.
//   DS-I - threading-affinity pin requires `running_in_this_thread()` on
//          boost::asio::strand<boost::asio::any_io_executor> which does not exist on the current
//          boost::asio::strand<boost::asio::any_io_executor> surface.

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
#include <utility>

#include <gtest/gtest.h>

#include "fake_async_crypto.h"
#include "run_async_sync.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
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

struct PinSecurityToken final : public SecurityToken
{
  PinSecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
    uint32_t id, std::chrono::milliseconds revisedLifetime)
    : SecurityToken(
        std::move(strand), std::move(localKeys), std::move(remoteKeys), id, revisedLifetime, []() {})
  {}
};

ByteString build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal isFinal, uint32_t secureChannelId,
  uint32_t tokenId, uint32_t sequenceNumber, uint32_t requestId, span<const byte> body)
{
  const uint32_t chunkSize = static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes +
                                                   stack_utils::SymmetricSecurityHeader::sizeInBytes +
                                                   stack_utils::SequenceHeader::sizeInBytes + body.size());

  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  const auto limits = pin_limits();

  stack_utils::UaScMessageHeader h;
  h.messageType = stack_utils::UaScMessageHeader::MessageType::Message;
  h.isFinal = isFinal;
  h.messageChunkSize = chunkSize;
  h.secureChannelId = secureChannelId;
  h.encode(limits, enc);

  stack_utils::SymmetricSecurityHeader sh;
  sh.tokenId = tokenId;
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

std::shared_ptr<SecureChannelContext> make_open_none_context(boost::asio::any_io_executor ex,
  boost::asio::strand<boost::asio::any_io_executor> strand, uint32_t channelId, uint32_t activeTokenId)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = channelId;
  ctx->encodingLimits = pin_limits();
  ctx->lastRxSequenceNumber = std::nullopt;

  SecurityToken::Keys emptyKeys;
  ctx->activeSecurityToken =
    std::make_unique<PinSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, activeTokenId, 10s);
  return ctx;
}

std::shared_ptr<SecureChannelContext> make_open_none_context_without_active_token(
  boost::asio::any_io_executor /*ex*/, boost::asio::strand<boost::asio::any_io_executor> strand,
  uint32_t channelId)
{
  // Open channel but no active token - simulates the BadInvalidState precondition.
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = channelId;
  ctx->encodingLimits = pin_limits();
  ctx->lastRxSequenceNumber = std::nullopt;
  // Intentionally leave activeSecurityToken null.
  return ctx;
}

}  // namespace

class DecodeSymmetricPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(mExecutor));
  }

  void TearDown() override
  {
    mPool.join();
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
};

// ---------------------------------------------------------------------------
// Pin DS-D - unknown token ID with no pending token.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:564-571 throws synchronously when the
// chunk's token ID matches neither the active token nor any pending token. Asserts
// status BadSecureChannelTokenUnknown and non-null ErrorDetail.

TEST_F(DecodeSymmetricPin, UnknownTokenIdWithoutPendingIsRejected)
{
  auto ctx = make_open_none_context(mExecutor, *mStrand, /*channelId*/ 1, /*activeTokenId*/ 10);
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x01}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 9999,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

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
    rightStatus = (ex.status() == Status::BadSecureChannelTokenUnknown);
    detailNonNull = (ex.detail() != nullptr);
  }
  EXPECT_TRUE(rightStatus) << "unknown token ID must be rejected with BadSecureChannelTokenUnknown";
  EXPECT_TRUE(detailNonNull) << "token-unknown failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DS-E - unknown token ID with a mismatched pending token.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:572-580 covers the case where a pending
// token exists but its ID also doesn't match. The body distinguishes "no pending"
// from "wrong pending"; both branches must throw BadSecureChannelTokenUnknown with
// detail. This pin covers the wrong-pending branch (DS-D covers the no-pending
// branch).

TEST_F(DecodeSymmetricPin, UnknownTokenIdWithMismatchedPendingIsRejected)
{
  auto ctx = make_open_none_context(mExecutor, *mStrand, /*channelId*/ 1, /*activeTokenId*/ 10);

  // Install a pending token with id=11 - the chunk will arrive with token id=9999.
  SecurityToken::Keys emptyKeys;
  ctx->pendingSecurityToken =
    std::make_unique<PinSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x01}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 9999,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

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
    rightStatus = (ex.status() == Status::BadSecureChannelTokenUnknown);
    detailNonNull = (ex.detail() != nullptr);
  }
  EXPECT_TRUE(rightStatus) << "mismatched pending token must be rejected with BadSecureChannelTokenUnknown";
  EXPECT_TRUE(detailNonNull) << "token-unknown failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DS-F - pending token promoted on first chunk that uses its ID.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:582-586 swaps activeSecurityToken with
// pendingSecurityToken (and clears pendingSecurityToken) when a chunk arrives
// with the pending token's ID. This is observable through the channel context
// after the call returns.

TEST_F(DecodeSymmetricPin, PendingTokenIsPromotedOnFirstChunkUnderNewTokenId)
{
  auto ctx = make_open_none_context(mExecutor, *mStrand, /*channelId*/ 1, /*activeTokenId*/ 10);

  // Install a pending token with id=11.
  SecurityToken::Keys emptyKeys;
  ctx->pendingSecurityToken =
    std::make_unique<PinSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x99}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 11,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  auto decoded = ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
    [&](auto cb) {
      policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb));
    }).value();
  ASSERT_TRUE(decoded.has_value());

  ASSERT_NE(ctx->activeSecurityToken, nullptr) << "active token must remain non-null after promotion";
  EXPECT_EQ(ctx->activeSecurityToken->id(), 11u) << "pending token (id=11) must have been promoted to active";
  EXPECT_EQ(ctx->pendingSecurityToken, nullptr) << "pending slot must be cleared after promotion";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DS-H - missing active security token.
// ---------------------------------------------------------------------------
//
// Pre-flip body at ua_security_policy.cpp:554-560 throws BadInvalidState when the
// channel is open but activeSecurityToken is null. Pins the precondition that a
// symmetric decode requires an active token - locks that 4.3b doesn't move this
// check into a continuation that could be skipped on a fast path.

TEST_F(DecodeSymmetricPin, MissingActiveTokenIsRejectedWithBadInvalidState)
{
  auto ctx = make_open_none_context_without_active_token(mExecutor, *mStrand, /*channelId*/ 1);
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x01}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

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
    rightStatus = (ex.status() == Status::BadInvalidState);
    detailNonNull = (ex.detail() != nullptr);
  }
  EXPECT_TRUE(rightStatus) << "missing active token must be rejected with BadInvalidState";
  EXPECT_TRUE(detailNonNull) << "missing-active-token failure must carry an ErrorDetail";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin DS-PAD - too-short SignAndEncrypt plaintext must not underflow the padding strip.
// ---------------------------------------------------------------------------
//
// Covers the symmetric padding-strip guard in on_decode_symmetric_verify_complete
// (ua_security_policy.cpp). A SignAndEncrypt MSG chunk whose decrypted+verified plaintext is shorter
// than the security + sequence headers must be rejected gracefully, NOT crash the server. Before the
// guard, `plainText.size() - headerSize - SequenceHeader::sizeInBytes` was an unchecked size_t
// subtraction that underflowed to a huge value, defeated the bounds check, and the safe_sub_span
// below then threw [BadOutOfRange] out of a strand handler -> std::terminate (a DoS; the sibling of
// the asymmetric DA-PAD pin, hardened 2026-06-08 for the CTT Security CUs).
//
// Reproduction mirrors DA-PAD: the real decode flow runs over decode_message_chunk_async with crypto
// PARKED (FakeAsyncCrypto), so symmetric decrypt+verify are completed as success and the flow reaches
// the padding guard exactly as a forged-signature bypass would. A 48-byte chunk (16-byte header + 32
// bytes of "ciphertext") yields a 16-byte plaintext after the 32-byte HMAC-SHA256 signature is
// stripped - shorter than headerSize(16) + SequenceHeader(8) + 1, so the guard must fire. The context
// carries no strand, so dispatch_to_strand runs inline and the flow is driven deterministically here.
TEST_F(DecodeSymmetricPin, TooShortSignAndEncryptPlaintextRejectedWithoutCrash)
{
  auto fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
  ASSERT_NE(fakeCrypto, nullptr);
  fakeCrypto->set_park_async(true);

  constexpr uint32_t channelId = 7;
  constexpr uint32_t tokenId = 9;

  auto ctx = std::make_shared<SecureChannelContext>();
  // The decode flow marshals every step onto the context strand. A strand over an io_context THIS
  // TEST polls keeps the sequence exactly as deterministic as inline dispatch was: nothing runs
  // until poll() is called, and poll() returns only once the strand has drained - so each parked
  // crypto completion below is still observed in a fixed order, with no threads and no waiting.
  boost::asio::io_context decodeIo;
  ctx->boundStrand = boost::asio::make_strand(boost::asio::any_io_executor{decodeIo.get_executor()});
  // restart() before every poll(): an io_context that has run out of work is left STOPPED, and a
  // stopped context's poll() returns immediately without running anything.
  const auto drain = [&decodeIo] { decodeIo.restart(); decodeIo.poll(); };
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ctx->secureChannelId = channelId;
  ctx->encodingLimits = pin_limits();
  ctx->crypto = fakeCrypto;
  ctx->lastRxSequenceNumber = std::nullopt;

  // Empty key material: the parked fake ignores key content (it only queues the callback). The token
  // needs a strand for its lifetime timer; the context's inline dispatch is independent of it.
  SecurityToken::Keys emptyKeys;
  ctx->activeSecurityToken =
    std::make_unique<PinSecurityToken>(*mStrand, emptyKeys, emptyKeys, tokenId, 10s);

  // 48-byte chunk: 16-byte header (UaScMessageHeader + SymmetricSecurityHeader) + 32 bytes that the
  // encrypted path treats as ciphertext (SequenceHeader + body). Content is irrelevant - the parked
  // decrypt leaves the body region zeroed; only the SIZE drives the guard.
  const std::vector<byte> body(24, byte{0x00});
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    channelId,
    tokenId,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);
  ASSERT_EQ(chunk.size(), 48u) << "header sizing assumption changed; adjust the body length";

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  std::optional<DecodedMessageChunkResult> outcome;
  ASSERT_NO_THROW({
    policy->decode_message_chunk_async(
      ctx, std::move(chunk), [&outcome](DecodedMessageChunkResult result) { outcome = std::move(result); });
    drain();

    // Drive the parked crypto: decrypt completes (plaintext = header + zeroed body), then verify is
    // completed as success so the flow reaches the padding-strip guard. Each poll() runs the step
    // the completion queued, so the next count below is read only once the flow has advanced.
    ASSERT_EQ(fakeCrypto->pending_symmetric_decrypt_count(), 1u);
    fakeCrypto->complete_pending_symmetric_decrypt(0, VoidResult{});
    drain();
    ASSERT_EQ(fakeCrypto->pending_symmetric_verify_count(), 1u);
    fakeCrypto->complete_pending_symmetric_verify(0, VoidResult{});
    drain();
  });

  ASSERT_TRUE(outcome.has_value()) << "decode must complete (graceful failure) rather than crash/hang";
  EXPECT_TRUE(outcome->is_bad()) << "too-short plaintext must be rejected, not accepted";
  EXPECT_EQ(outcome->status_code(), Status::BadSecurityChecksFailed)
    << "too-short plaintext must surface as Bad_SecurityChecksFailed";
  EXPECT_NE(outcome->shared_detail(), nullptr) << "padding rejection must carry an ErrorDetail";

  ctx.reset();
}

}  // namespace ua::test::behaviour_pins
