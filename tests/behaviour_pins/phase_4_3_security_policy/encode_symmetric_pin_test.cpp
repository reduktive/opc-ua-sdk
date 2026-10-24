// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.3a (SecurityPolicy::encode_symmetric_message).
//
// What is pinned (synchronous-precondition-only subset):
//   ES-E: encode_symmetric rejects body exceeding max message size with
//         BadResponseTooLarge + non-null ErrorDetail.
//   ES-F: encode_symmetric rejects required chunks exceeding max chunk count with
//         BadResponseTooLarge + non-null ErrorDetail.
//
// Pins not authored in this file (with reason - see runbook section 4.4 for full table):
//   ES-A, ES-B, ES-C, ES-D - require FakeAsyncCrypto (sub-phase-local fake described in
//                            runbook section 4.0.1 but not yet authored; runbook flags as new
//                            file gated on TODO resolution).
//   ES-G - runbook section 4.4 explicitly flags ES-G as a "stop and ask" TODO
//          (asymmetric_encrypt-style missing co_await; defect-or-spec question
//          unresolved).
//   ES-H - threading-affinity pin requires `running_in_this_thread()` on
//          boost::asio::strand<boost::asio::any_io_executor> which does not exist on the current
//          boost::asio::strand<boost::asio::any_io_executor> surface.

#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "run_async_sync.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_close_secure_channel_request.h"
#include "ua_codec_namespace_context.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_status_code.h"
#include "ua_structure.h"
#include <boost/asio/thread_pool.hpp>

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

// ---------------------------------------------------------------------------
// Helpers - minimal SecureChannelContext for None-policy symmetric encoding.
// ---------------------------------------------------------------------------

struct PinSecurityToken final : public SecurityToken
{
  PinSecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
    uint32_t id, std::chrono::milliseconds revisedLifetime)
    : SecurityToken(
        std::move(strand), std::move(localKeys), std::move(remoteKeys), id, revisedLifetime, []() {})
  {}
};

class PinPayloadStructure final : public Structure
{
public:
  explicit PinPayloadStructure(size_t payloadSize) : mPayloadSize(payloadSize)
  {}

  NodeId type_id(const CodecNamespaceContext& ns) const override
  {
    UA_UNUSED(ns);
    return NodeId{0u, 0u};
  }

  ExpandedNodeId type_id() const override
  {
    return ExpandedNodeId{};
  }

  String type_name() const override
  {
    return String{"PinPayloadStructure"};
  }

  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override
  {
    UA_UNUSED(ns);
    auto* bin = encoder.get_ua_binary();
    check(bin);
    NodeId id{0u, 0u};
    bin->encode(limit, id);
  }

  void encode(StackDepth limit, Encoder& encoder) const override
  {
    auto* bin = encoder.get_ua_binary();
    check(bin);
    ByteString payload;
    payload.resize(mPayloadSize, uint8_t{0xAB});
    bin->encode(limit, payload);
  }

  unique_ptr<Structure> clone() const override
  {
    return std::make_unique<PinPayloadStructure>(mPayloadSize);
  }

  std::string to_string(int /*indent*/ = 0) const override
  {
    return "PinPayloadStructure{}";
  }

private:
  size_t mPayloadSize{0};
};

std::shared_ptr<SecureChannelContext> make_open_none_send_context(boost::asio::any_io_executor ex,
  boost::asio::strand<boost::asio::any_io_executor> strand, uint32_t channelId, uint32_t tokenId)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = channelId;
  ctx->encodingLimits =
    ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  ctx->namespaceIndexCallback = [](string_view)
  {
    return uint16_t{0};
  };

  SecurityToken::Keys emptyKeys;
  ctx->activeSecurityToken =
    std::make_unique<PinSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, tokenId, 10s);
  return ctx;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class EncodeSymmetricPin : public ::testing::Test
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
// Pin ES-E - encode rejects body exceeding max message size synchronously.
// ---------------------------------------------------------------------------
//
// Stimulus: encode_message with a body whose encoded size exceeds the negotiated
// SendMaxMessageSize. Pre-flip throws synchronously at ua_security_policy.cpp:973-981
// before any Crypto hop. Asserts:
//   1. UaException carries Status::BadResponseTooLarge.
//   2. UaException carries a non-null ErrorDetail.
//   3. sendMessageChunk was never invoked (no chunks emitted).
//
// Bug this catches: a 4.3b restructure that moves the size check into a continuation
// after a Crypto hop would emit the first chunk before discovering the violation,
// leaking partial cipher-text on the wire.

TEST_F(EncodeSymmetricPin, BodyExceedingMaxMessageSizeIsRejectedSynchronously)
{
  auto ctx = make_open_none_send_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);
  ctx->negotiatedLimits.sendBufferSize = 4096;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<PinPayloadStructure>(/*payloadSize*/ 512);

  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&chunkCount](ByteString)
  {
    ++chunkCount;
  };

  bool threwBadResponseTooLarge = false;
  bool detailWasNonNull = false;
  try
  {
    ua::test_helpers::run_async_callback_sync<VoidResult>(
      [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    threwBadResponseTooLarge = (ex.status() == Status::BadResponseTooLarge);
    detailWasNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(threwBadResponseTooLarge)
    << "encode_message must reject oversized body with BadResponseTooLarge";
  EXPECT_TRUE(detailWasNonNull) << "BadResponseTooLarge failure must carry an ErrorDetail "
                                   "(the highest-priority repository rule)";
  EXPECT_EQ(chunkCount, 0u) << "no chunk should be emitted when max message size is exceeded synchronously";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin ES-F - encode rejects required-chunk-count exceeding max synchronously.
// ---------------------------------------------------------------------------
//
// Stimulus: encode_message with negotiated SendMaxChunkCount=1 but a body that
// requires multiple chunks under the negotiated SendBufferSize. Pre-flip throws
// synchronously at ua_security_policy.cpp:964-970 before any Crypto hop.

TEST_F(EncodeSymmetricPin, RequiredChunksExceedingMaxChunkCountIsRejectedSynchronously)
{
  auto ctx = make_open_none_send_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);
  // Force multi-chunk encoding via a small SendBufferSize; cap chunk count at 1.
  ctx->negotiatedLimits.sendBufferSize = 1000;
  ctx->negotiatedLimits.sendMaxChunkCount = 1;
  ctx->negotiatedLimits.sendMaxMessageSize = 16 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<PinPayloadStructure>(/*payloadSize*/ 4096);

  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&chunkCount](ByteString)
  {
    ++chunkCount;
  };

  bool threwBadResponseTooLarge = false;
  bool detailWasNonNull = false;
  try
  {
    ua::test_helpers::run_async_callback_sync<VoidResult>(
      [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
      .value();
  }
  catch (const UaException& ex)
  {
    threwBadResponseTooLarge = (ex.status() == Status::BadResponseTooLarge);
    detailWasNonNull = (ex.detail() != nullptr);
  }

  EXPECT_TRUE(threwBadResponseTooLarge)
    << "encode_message must reject excess chunk count with BadResponseTooLarge";
  EXPECT_TRUE(detailWasNonNull)
    << "BadResponseTooLarge failure must carry an ErrorDetail (the highest-priority repository rule)";
  EXPECT_EQ(chunkCount, 0u) << "no chunk should be emitted when max chunk count is exceeded synchronously";
  ctx.reset();
}

// ---------------------------------------------------------------------------
// Pin ES-CLO - a CloseSecureChannelRequest is framed with the CLO message-type
// token, not MSG.
// ---------------------------------------------------------------------------
//
// Stimulus: encode_message with a CloseSecureChannelRequest payload drives the
// real encode_unknown_message_async -> encode_symmetric_message_async path. The
// first three bytes of each emitted chunk are the SC message-type token written
// by UaScMessageHeader::encode ({'C','L','O'} for Close, {'M','S','G'} for an
// ordinary message). Per OPC 10000-6 section 6.7.2.2 Table 50 the client's
// CloseSecureChannel request must be framed as CLO. It is request-only: section 7.1.4
// says the Server sends no CloseSecureChannel response, so there is no CLO
// response on the wire. The close request body is empty, so it always ships as a
// single final chunk (IsFinal == 'F').
//
// Bug this catches: the symmetric chunk builder previously hardcoded
// MessageType::Message, so the close request shipped as MSG. A companion
// assertion confirms an ordinary service request still leads with MSG, guarding
// the default path.

TEST_F(EncodeSymmetricPin, CloseSecureChannelRequestEmitsCloMessageType)
{
  auto ctx = make_open_none_send_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);
  ctx->negotiatedLimits.sendBufferSize = 4096;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 16 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto closeRequest = std::make_shared<ua::CloseSecureChannelRequest>();

  ByteString captured;
  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&captured, &chunkCount](ByteString chunk)
  {
    ++chunkCount;
    captured = std::move(chunk);
  };

  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, closeRequest, send, std::move(cb)); })
    .value();

  ASSERT_EQ(chunkCount, 1u) << "Close request should emit exactly one chunk for this body size";
  ASSERT_GE(captured.size(), 3u);
  EXPECT_EQ(captured[0], uint8_t{'C'}) << "CloseSecureChannel must be framed as CLO, not MSG";
  EXPECT_EQ(captured[1], uint8_t{'L'});
  EXPECT_EQ(captured[2], uint8_t{'O'});
  ctx.reset();
}

// Companion negative pin - an ordinary service request still frames as MSG,
// proving the defaulted message-type parameter leaves normal traffic unchanged.
TEST_F(EncodeSymmetricPin, OrdinaryRequestEmitsMsgMessageType)
{
  auto ctx = make_open_none_send_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);
  ctx->negotiatedLimits.sendBufferSize = 4096;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 16 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<PinPayloadStructure>(/*payloadSize*/ 64);

  ByteString captured;
  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&captured, &chunkCount](ByteString chunk)
  {
    ++chunkCount;
    captured = std::move(chunk);
  };

  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
    .value();

  ASSERT_EQ(chunkCount, 1u);
  ASSERT_GE(captured.size(), 3u);
  EXPECT_EQ(captured[0], uint8_t{'M'}) << "ordinary service request must remain framed as MSG";
  EXPECT_EQ(captured[1], uint8_t{'S'});
  EXPECT_EQ(captured[2], uint8_t{'G'});
  ctx.reset();
}

}  // namespace ua::test::behaviour_pins
