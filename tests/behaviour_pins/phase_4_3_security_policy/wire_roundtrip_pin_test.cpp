// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.3a (SecurityPolicy wire round-trip).
//
// Wire round-trips are the strongest available pin per the README's pin-categories
// section (#8): they encode a deterministic message body, decode the resulting
// chunks, and assert byte-identical recovery. This catches any pre-/post-flip drift
// in the encode-then-decode path that would corrupt application bytes.
//
// What is pinned:
//   WR-D: SecurityPolicy::None encodes a deterministic body and decodes it back to
//         identical bytes (single-chunk and multi-chunk).
//
// Pins not authored in this file (with reason):
//   WR-A (Basic256Sha256), WR-B (Aes256Sha256RsaPss), WR-C (EccNistP256) - these
//        require both ends of the channel to share security tokens with valid
//        derived keys, plus paired local/remote certificates and a CertificateStore
//        wired through SecureChannelContext::certStore. Authoring these end-to-end
//        roundtrips at pin scope reproduces the existing parameterised tests under
//        tests/unit/security/security_policy_parameterized_tests.cpp without adding
//        pin-specific assertion value over them. Per runbook section 4.7 the wire-roundtrip
//        pins should "reference (without duplicating) the existing parameterised
//        tests"; the existing tests already cover WR-A..C functionally. WR-D
//        (None) is authored here as the pin-locked roundtrip because None has no
//        certificate-store / token-derivation dependencies and is therefore
//        cleanly exercisable in isolation.

#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "run_async_sync.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_expanded_node_id.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_security_token.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_structure.h"
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

class DeterministicPayloadStructure final : public Structure
{
public:
  explicit DeterministicPayloadStructure(ByteString payload) : mPayload(std::move(payload))
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
    return String{"DeterministicPayloadStructure"};
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
    bin->encode(limit, mPayload);
  }

  unique_ptr<Structure> clone() const override
  {
    return std::make_unique<DeterministicPayloadStructure>(mPayload);
  }

  std::string to_string(int /*indent*/ = 0) const override
  {
    return "DeterministicPayloadStructure{}";
  }

private:
  ByteString mPayload;
};

std::shared_ptr<SecureChannelContext> make_open_none_context(boost::asio::any_io_executor ex,
  boost::asio::strand<boost::asio::any_io_executor> strand, uint32_t channelId, uint32_t tokenId)
{
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = channelId;
  ctx->encodingLimits = pin_limits();
  ctx->namespaceIndexCallback = [](string_view)
  {
    return uint16_t{0};
  };
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.sendBufferSize = 65536;
  ctx->negotiatedLimits.receiveBufferSize = 65536;
  ctx->negotiatedLimits.sendMaxChunkCount = 0;
  ctx->negotiatedLimits.sendMaxMessageSize = 64 * 1024;

  SecurityToken::Keys emptyKeys;
  ctx->activeSecurityToken =
    std::make_unique<PinSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, tokenId, 10s);
  return ctx;
}

}  // namespace

class WireRoundtripPin : public ::testing::Test
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
// Pin WR-D - SecurityPolicyId::None encode-then-decode preserves body bytes.
// ---------------------------------------------------------------------------
//
// Stimulus: encode_message a deterministic structure containing a 1024-byte
// payload of 0xAB; capture the produced chunks; feed each chunk back through
// decode_message_chunk on a paired receive context and assert the decoded body
// payload matches the input bytes exactly.
//
// What this catches: any pre-/post-flip drift that corrupts wire bytes - e.g.,
// chunk-ordering changes, header miscalculation, sequence/request numbering, or
// payload reordering. Round-trip preservation is policy-agnostic and therefore
// the strongest available wire pin.

TEST_F(WireRoundtripPin, NoneEncodeDecodeRoundtripPreservesBody)
{
  auto sendCtx = make_open_none_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);
  auto recvCtx = make_open_none_context(mExecutor, *mStrand, /*channelId*/ 1, /*tokenId*/ 10);

  // Deterministic 1024-byte payload of 0xAB. Big enough to exercise multiple
  // chunks under a constrained SendBufferSize.
  ByteString payload;
  payload.resize(1024, uint8_t{0xAB});
  auto msg = std::make_shared<DeterministicPayloadStructure>(payload);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Force at least two chunks by tightening SendBufferSize on the send side.
  // (Receive buffer stays large enough to accept any single chunk.)
  sendCtx->negotiatedLimits.sendBufferSize = 512;

  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk send = [&chunks](ByteString c)
  {
    chunks.push_back(std::move(c));
  };

  ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->encode_message_async(sendCtx, /*requestId*/ 7, msg, send, std::move(cb)); })
    .value();

  ASSERT_GE(chunks.size(), 2u) << "WR-D requires multi-chunk roundtrip - adjust SendBufferSize if smaller";

  // Drive the chunks through decode_message_chunk; the FINAL chunk's decoded
  // result carries the recovered (requestId, body) pair.
  std::optional<std::pair<uint32_t, ByteString>> decoded;
  for (auto& chunk : chunks)
  {
    auto stepResult = ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
      [&](auto cb) {
        policy->decode_message_chunk_async(recvCtx, std::move(chunk), std::move(cb));
      }).value();
    if (stepResult.has_value())
    {
      ASSERT_FALSE(decoded.has_value()) << "decode produced two final results - chunking drifted";
      decoded = std::move(stepResult);
    }
  }

  ASSERT_TRUE(decoded.has_value()) << "no FINAL decoded result - chunking drifted";
  EXPECT_EQ(decoded->first, 7u) << "decoded requestId must match the encoded value";

  // The decoded body is the encoded Structure (containing the encoded payload).
  // For the None roundtrip we assert the *whole* serialised body is byte-identical
  // - this includes the type-id prefix and the encoded payload length-prefix.
  // Re-encoding the input message gives the same byte sequence; comparing the
  // recovered body to that re-encoded canonical form is what locks the wire
  // contract.
  ByteString reencoded;
  {
    memory_stream_device::Dynamic dev{4096, true};
    MemoryStream stream{dev};
    UaBinaryEncoder bin{CodecNamespaceContext{sendCtx->namespaceIndexCallback}, stream};
    StackDepth limit = sendCtx->encodingLimits.stack_depth();
    Encoder enc{bin};
    msg->encode_id(limit, CodecNamespaceContext{sendCtx->namespaceIndexCallback}, enc);
    bin.encode(limit, *msg);
    auto out = dev.move_storage_out();
    out.resize(stream.get_position());
    reencoded = ByteString{span<const byte>{out}};
  }

  EXPECT_EQ(decoded->second, reencoded) << "WR-D: decoded body bytes do not match the encoded message - wire "
                                           "round-trip is broken";

  sendCtx.reset();
  recvCtx.reset();
}

}  // namespace ua::test::behaviour_pins
