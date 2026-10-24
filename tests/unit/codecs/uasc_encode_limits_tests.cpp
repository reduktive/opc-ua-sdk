// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "run_async_sync.h"
#include <boost/asio/strand.hpp>

#include "ua_binary_codec.h"
#include "ua_error_detail.h"

#include "ua_expanded_node_id.h"
#include "ua_node_id.h"

#include "ua_security_policy.h"
#include "ua_secure_channel_context.h"
#include "ua_security_token.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

#include <stdexcept>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

static stack_utils::UaScMessageHeader decode_uasc_header(span<const byte> chunk)
{
  memory_stream_device::ExternalReadOnly dev{chunk};
  MemoryStream stream{dev};
  StructureFactory f;
  auto limits =
    ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(f.resolver(), stream, limits);

  stack_utils::UaScMessageHeader h;
  h.decode(limits, dec);
  return h;
}

static std::pair<Status, std::string> decode_abort_body(span<const byte> chunk)
{
  memory_stream_device::ExternalReadOnly dev{chunk};
  MemoryStream stream{dev};
  StructureFactory f;
  auto limits =
    ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  UaBinaryDecoder dec(f.resolver(), stream, limits);
  auto depth = limits.stack_depth();

  stack_utils::UaScMessageHeader h;
  h.decode(limits, dec);
  stack_utils::SymmetricSecurityHeader sh;
  sh.decode(limits, dec);
  stack_utils::SequenceHeader seq;
  seq.decode(limits, dec);

  uint32_t stRaw{0};
  String reason;
  dec.decode(depth, stRaw);
  dec.decode(depth, reason);
  return {static_cast<Status>(stRaw), std::string{reason}};
}

struct TestSecurityToken final : public SecurityToken
{
  TestSecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
    uint32_t id, std::chrono::milliseconds revisedLifetime)
    : SecurityToken(
        std::move(strand), std::move(localKeys), std::move(remoteKeys), id, revisedLifetime, []() {})
  {}
};

static void expect_runtime_exception_status(const std::function<void()>& fn, Status expected)
{
  try
  {
    fn();
    FAIL() << "Expected UaException";
  }
  catch (const UaException& e)
  {
    EXPECT_EQ(e.status(), expected);
  }
}

class LargeStructure final : public Structure
{
public:
  explicit LargeStructure(size_t payloadSize) : mPayloadSize(payloadSize)
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
    return String{"LargeStructure"};
  }

  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override
  {
    UA_UNUSED(ns);
    // Encode a dummy NodeId as the type id.
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
    payload.resize(mPayloadSize, uint8_t{0xAA});
    bin->encode(limit, payload);
  }

  unique_ptr<Structure> clone() const override
  {
    return std::make_unique<LargeStructure>(mPayloadSize);
  }

  std::string to_string(int /*indent*/ = 0) const override
  {
    return "LargeStructure{}";
  }

private:
  size_t mPayloadSize{0};
};

static std::shared_ptr<SecureChannelContext> make_minimal_context_for_send(
  boost::asio::any_io_executor ex, boost::asio::strand<boost::asio::any_io_executor> strand)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 1;
  ctx->encodingLimits =
    ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
  ctx->namespaceIndexCallback = [](string_view)
  {
    return uint16_t{0};
  };

  SecurityToken::Keys emptyKeys;
  ctx->activeSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 10, 10s);

  return ctx;
}

}  // namespace

// @relation(AC-SVR-TCP-007-TOOLARGE, SVR-TCP-032, scope=function)
TEST(UascEncodeLimitsTests, ResponseExceedingMaxMessageSizeIsRejected)
{
  // Requirement: P6-71-0006 (MaxMessageSize response limit)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  ctx->negotiatedLimits.sendBufferSize = 4096;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Large enough that UA binary encoding will exceed MaxMessageSize.
  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 512);

  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&](ByteString)
  {
    ++chunkCount;
  };

  expect_runtime_exception_status(
    [&]()
    {
      ua::test_helpers::run_async_callback_sync<VoidResult>(
        [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
        .value();
    },
    Status::BadResponseTooLarge);
  EXPECT_EQ(chunkCount, 0u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-012 - encode_message_async must fire the completion callback EXACTLY ONCE and must not
// let a throwing callback escape an async boundary, even on the synchronous size-ceiling rejection path.
// The size-ceiling rejection fires the completion synchronously from inside encode_message_async's try; a
// callback that throws there would otherwise be caught by the catch and either fired a second time (the
// original in-try placement) or invoked as a moved-from std::function -> std::bad_function_call escaping the
// call. The fireOnce single-fire guard makes the completion fire once and swallows the throwing callback.
// @relation(CL-TCP-012, scope=function)
TEST(UascEncodeLimitsTests, EncodeMessageFiresCompletionExactlyOnceWhenCallbackThrows)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  ctx->negotiatedLimits.sendBufferSize = 4096;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64;  // small cap -> the message is rejected as too large

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 512);  // > 64 -> synchronous rejection

  SecurityPolicy::SendMessageChunk send = [&](ByteString) {
  };

  int callCount = 0;
  bool escaped = false;
  // A completion callback that throws on its FIRST invocation. A correct implementation fires it exactly
  // once and does not propagate the throw out of encode_message_async.
  try
  {
    policy->encode_message_async(ctx,
      /*requestId*/ 1,
      msg,
      send,
      [&](VoidResult)
      {
        ++callCount;
        if (callCount == 1)
        {
          throw std::runtime_error("callback boom");
        }
      });
  }
  catch (...)
  {
    escaped = true;
  }

  EXPECT_EQ(callCount, 1)
    << "the completion must fire exactly once; callCount==2 means a catch re-fired the already-fired "
       "completion";
  EXPECT_FALSE(escaped)
    << "a throwing completion callback must not escape encode_message_async (double-fire via a moved-from "
       "callback would throw std::bad_function_call)";

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-047-AN-OUTBOUND-RESPONSE-NEEDING-MORE-CHUNKS, scope=function)

// @relation(AC-SVR-TCP-009-CHUNKCOUNT, SVR-TCP-032, scope=function)
TEST(UascEncodeLimitsTests, ResponseExceedingMaxChunkCountIsRejected)
{
  // Requirement: P6-71-0008 (MaxChunkCount response limit)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  // Force multi-chunk encoding by using a small negotiated SendBufferSize.
  // Must still be large enough to hold UASC headers.
  ctx->negotiatedLimits.sendBufferSize = 1000;
  ctx->negotiatedLimits.sendMaxChunkCount = 1;
  // Keep MaxMessageSize large enough that we can encode the message body before chunking.
  ctx->negotiatedLimits.sendMaxMessageSize = 16 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 4096);

  size_t chunkCount = 0;
  SecurityPolicy::SendMessageChunk send = [&](ByteString)
  {
    ++chunkCount;
  };

  expect_runtime_exception_status(
    [&]()
    {
      ua::test_helpers::run_async_callback_sync<VoidResult>(
        [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
        .value();
    },
    Status::BadResponseTooLarge);

  EXPECT_EQ(chunkCount, 0u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-047-AN-OUTBOUND-RESPONSE-NEEDING-MORE-CHUNKS, scope=function)

// @relation(AC-SVR-TCP-008-ABORT, SVR-TCP-032, SVR-UASC-017, SVR-UASC-018, SVR-UASC-061, scope=function)
TEST(UascEncodeLimitsTests, ResponseExceedingLimitsAfterChunksSentIsAborted)
{
  // Requirements: P6-71-0007, P6-67-0017 (abort after chunks already sent)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  ctx->negotiatedLimits.sendBufferSize = 256;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 4096);

  std::vector<ByteString> chunks;
  size_t sendCalls = 0;
  bool threwOnce = false;
  SecurityPolicy::SendMessageChunk send = [&](ByteString c)
  {
    // Simulate an error occurring after at least one chunk was already sent.
    // Throw exactly once (on the second send attempt), then allow the abort chunk through.
    if (!threwOnce && (sendCalls == 1))
    {
      threwOnce = true;
      throw UaException{
        Status::BadResponseTooLarge, make_error_detail("SimulatedError", std::string(6000, 'x'), "Test")};
    }
    ++sendCalls;
    chunks.push_back(std::move(c));
  };

  expect_runtime_exception_status(
    [&]()
    {
      ua::test_helpers::run_async_callback_sync<VoidResult>(
        [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
        .value();
    },
    Status::BadResponseTooLarge);

  // We expect: at least one normal chunk + one abort chunk.
  ASSERT_GE(chunks.size(), 2u);

  auto lastHeader = decode_uasc_header(chunks.back());
  EXPECT_EQ(lastHeader.isFinal, stack_utils::UaScMessageHeader::IsFinal::Aborted);

  auto [st, reason] = decode_abort_body(chunks.back());
  EXPECT_EQ(st, Status::BadResponseTooLarge);
  EXPECT_LE(reason.size(), 4096u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-016-SPLIT, scope=function)
// @relation(AC-SVR-UASC-047-AN-OUTBOUND-RESPONSE-NEEDING-MORE-CHUNKS, scope=function)

TEST(UascEncodeLimitsTests, ServerSendChunkingRespectsNegotiatedSendBufferSize)
{
  // Requirements: P6-67-0015, P6-67-0016, P6-71-0013, P6-71-0014

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  ctx->negotiatedLimits.sendBufferSize = 300;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 1024);

  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk send = [&](ByteString c)
  {
    chunks.push_back(std::move(c));
  };

  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
    .value();

  ASSERT_GE(chunks.size(), 2u);

  const size_t maxChunkSize = ctx->negotiatedLimits.sendBufferSize;
  const size_t headerOverhead = stack_utils::UaScMessageHeader::sizeInBytes +
                                stack_utils::SymmetricSecurityHeader::sizeInBytes +
                                stack_utils::SequenceHeader::sizeInBytes;
  ASSERT_LT(headerOverhead, maxChunkSize);
  const size_t maxBodyPerChunk = maxChunkSize - headerOverhead;

  for (size_t i = 0; i < chunks.size(); ++i)
  {
    const auto& c = chunks[i];
    EXPECT_LE(c.size(), maxChunkSize);

    // For SecurityPolicy None, payload bytes follow immediately after headers.
    EXPECT_LE(c.size() - headerOverhead, maxBodyPerChunk);
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-010, SVR-UASC-061, scope=function)
TEST(UascEncodeLimitsTests, ServerDoesNotEnforce8192MinChunkSizeInEncode)
{
  // Requirement: P6-67-0010 (sender min chunk size 8192) - documents current behavior.

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = make_minimal_context_for_send(ex, strand);
  ctx->negotiatedLimits.sendBufferSize = 512;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto msg = std::make_shared<LargeStructure>(/*payloadSize*/ 1024);

  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk send = [&](ByteString c)
  {
    chunks.push_back(std::move(c));
  };

  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->encode_message_async(ctx, /*requestId*/ 1, msg, send, std::move(cb)); })
    .value();

  ASSERT_FALSE(chunks.empty());
  EXPECT_LE(chunks.front().size(), ctx->negotiatedLimits.sendBufferSize);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Inbound reassembly limits (defensive anti chunk-flood DoS).
//
// The Connection Protocol layer caps each individual chunk at the negotiated ReceiveBufferSize, but the
// *assembled* message body and the *chunk count* are otherwise unbounded during reassembly in
// SecurityPolicy::copy_message_body. A hostile peer could stream unbounded Intermediate ('C') chunks to
// exhaust memory. These tests encode a real multi-chunk message, then decode it through a receive
// context whose negotiated MaxChunkCount / MaxMessageSize is too small, and assert the decode fails
// with Bad_TcpMessageTooLarge (which tears the channel down). RED before the copy_message_body bound:
// decode accumulated without limit and the final chunk decoded successfully.
// ---------------------------------------------------------------------------

namespace
{
std::shared_ptr<SecureChannelContext> make_minimal_recv_context(
  boost::asio::strand<boost::asio::any_io_executor> strand)
{
  auto ctx = make_minimal_context_for_send({}, std::move(strand));
  ctx->lastRxSequenceNumber = std::nullopt;  // accept the first received sequence number
  ctx->negotiatedLimits.receiveBufferSize = 65536;  // large per-chunk buffer (not the limit under test)
  return ctx;
}

std::vector<ByteString> encode_multichunk_message(
  const std::shared_ptr<SecureChannelContext>& sendCtx, const SecurityPolicy& policy, size_t payloadSize)
{
  auto msg = std::make_shared<LargeStructure>(payloadSize);
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk send = [&chunks](ByteString c)
  {
    chunks.push_back(std::move(c));
  };
  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy.encode_message_async(sendCtx, /*requestId*/ 1, msg, send, std::move(cb)); })
    .value();
  return chunks;
}
}  // namespace

TEST(UascEncodeLimitsTests, InboundExceedingMaxChunkCountIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Force >= 2 chunks by tightening the send buffer.
  auto sendCtx = make_minimal_context_for_send(ex, strand);
  sendCtx->negotiatedLimits.sendBufferSize = 512;
  sendCtx->negotiatedLimits.sendMaxChunkCount = 0;
  sendCtx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;
  auto chunks = encode_multichunk_message(sendCtx, *policy, /*payloadSize*/ 1024);
  ASSERT_GE(chunks.size(), 2u) << "test needs a multi-chunk message";

  // Receiver allows only a single chunk per message.
  auto recvCtx = make_minimal_recv_context(strand);
  recvCtx->negotiatedLimits.recvMaxChunkCount = 1;
  recvCtx->negotiatedLimits.recvMaxMessageSize = 0;  // size unlimited - isolate the chunk-count check

  // First chunk accepted (count == 1).
  auto first = ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
    [&](auto cb) { policy->decode_message_chunk_async(recvCtx, ByteString{chunks[0]}, std::move(cb)); });
  EXPECT_TRUE(first.is_good()) << "first chunk should be within the 1-chunk limit";

  // Second chunk pushes the count over the limit -> rejected.
  expect_runtime_exception_status(
    [&]()
    {
      // value() is called for its throw-on-bad side effect (the expected rejection); the decoded value is
      // deliberately discarded, so (void) the nodiscard result.
      (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
        [&](auto cb) { policy->decode_message_chunk_async(recvCtx, ByteString{chunks[1]}, std::move(cb)); })
        .value();
    },
    Status::BadTcpMessageTooLarge);

  sendCtx.reset();
  recvCtx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(UascEncodeLimitsTests, InboundExceedingMaxMessageSizeIsRejected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Single large chunk (send buffer big enough to hold the whole body in one chunk).
  auto sendCtx = make_minimal_context_for_send(ex, strand);
  sendCtx->negotiatedLimits.sendBufferSize = 65536;
  sendCtx->negotiatedLimits.sendMaxChunkCount = 0;
  sendCtx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;
  auto chunks = encode_multichunk_message(sendCtx, *policy, /*payloadSize*/ 1024);
  ASSERT_GE(chunks.size(), 1u);

  // Receiver caps assembled body well below the ~1 KB message.
  auto recvCtx = make_minimal_recv_context(strand);
  recvCtx->negotiatedLimits.recvMaxChunkCount = 0;  // count unlimited - isolate the size check
  recvCtx->negotiatedLimits.recvMaxMessageSize = 64;

  // Decoding the chunks must reject once the accumulated body exceeds 64 bytes.
  expect_runtime_exception_status(
    [&]()
    {
      for (auto& chunk : chunks)
      {
        // value() is called for its throw-on-bad side effect (the expected rejection); the decoded value is
        // deliberately discarded, so (void) the nodiscard result.
        (void)ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
          [&](auto cb) { policy->decode_message_chunk_async(recvCtx, ByteString{chunk}, std::move(cb)); })
          .value();
      }
    },
    Status::BadTcpMessageTooLarge);

  sendCtx.reset();
  recvCtx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}
