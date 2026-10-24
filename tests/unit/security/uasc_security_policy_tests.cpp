// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "run_async_sync.h"
#include <boost/asio/strand.hpp>

#include "ua_security_policy.h"
#include "ua_secure_channel_context.h"
#include "ua_security_token.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_open_secure_channel_request.h"

#include "ua_crypto.h"
#include "test_pki_helpers.h"
#include "ua_certificate_store_files.h"
#include "ua_guid.h"

#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

#include "ua_error_detail.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_security_policy_test_access.h"

#include "fake_async_crypto.h"

#include <filesystem>
#include <future>
#include <mutex>
#include <thread>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

// Local convenience: synchronously drive decode_message_chunk_async and return the
// unwrapped DecodedMessageChunkResult. Mirrors the pre-flip Task<>::value() shape;
// .value() on the Result throws UaException on bad, preserving the throw contract
// these tests rely on.
template<typename Policy>
auto decode_chunk_sync(const Policy& policy, std::shared_ptr<SecureChannelContext> ctx, ByteString chunk)
{
  return ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
    [&](auto cb) { policy->decode_message_chunk_async(std::move(ctx), std::move(chunk), std::move(cb)); });
}

struct TestSecurityToken final : public SecurityToken
{
  TestSecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
    uint32_t id, std::chrono::milliseconds revisedLifetime)
    : SecurityToken(
        std::move(strand), std::move(localKeys), std::move(remoteKeys), id, revisedLifetime, []() {})
  {}
};

static EncodingLimits test_limits()
{
  return EncodingLimits{.execution = ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

static std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() -> ua::SecureString { return ua::SecureString{"password"}; });
}

static ByteString build_uasc_header(stack_utils::UaScMessageHeader::MessageType type,
  stack_utils::UaScMessageHeader::IsFinal isFinal, uint32_t chunkSize, uint32_t secureChannelId)
{
  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  const auto limits = test_limits();

  stack_utils::UaScMessageHeader h;
  h.messageType = type;
  h.isFinal = isFinal;
  h.messageChunkSize = chunkSize;
  h.secureChannelId = secureChannelId;
  h.encode(limits, enc);

  auto out = streamDevice.move_storage_out();
  out.resize(stream.get_position());
  return ByteString{span<const byte>{out}};
}

static ByteString build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal isFinal,
  uint32_t secureChannelId, uint32_t tokenId, uint32_t sequenceNumber, uint32_t requestId,
  span<const byte> body)
{
  const uint32_t chunkSize = static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes +
                                                   stack_utils::SymmetricSecurityHeader::sizeInBytes +
                                                   stack_utils::SequenceHeader::sizeInBytes + body.size());

  memory_stream_device::Dynamic streamDevice{chunkSize, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  const auto limits = test_limits();
  auto depth = limits.stack_depth();

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

static ByteString build_asymmetric_opn_chunk(uint32_t secureChannelId,
  const stack_utils::AsymmetricSecurityHeader& sh, uint32_t sequenceNumber, uint32_t requestId,
  span<const byte> body,
  stack_utils::UaScMessageHeader::IsFinal isFinal = stack_utils::UaScMessageHeader::IsFinal::Final)
{
  // Encode to a dynamic buffer first; then patch the chunk size field once we know it.
  memory_stream_device::Dynamic streamDevice{64 * 1024, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  const auto limits = test_limits();
  auto depth = limits.stack_depth();

  // UaScMessageHeader (OPN?)
  stack_utils::UaScMessageHeader h;
  h.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
  h.isFinal = isFinal;
  h.messageChunkSize = 0;  // patched later
  h.secureChannelId = secureChannelId;
  h.encode(limits, enc);

  sh.encode(limits, enc);

  stack_utils::SequenceHeader seq;
  seq.sequenceNumber = sequenceNumber;
  seq.requestId = requestId;
  seq.encode(limits, enc);

  enc.stream().write_all(body);

  const uint32_t chunkSize = static_cast<uint32_t>(stream.get_position());

  // Patch MessageChunkSize at offset 4 (after type[3] + isFinal[1]).
  auto out = streamDevice.move_storage_out();
  out.resize(chunkSize);
  out[4] = static_cast<byte>(chunkSize & 0xFF);
  out[5] = static_cast<byte>((chunkSize >> 8) & 0xFF);
  out[6] = static_cast<byte>((chunkSize >> 16) & 0xFF);
  out[7] = static_cast<byte>((chunkSize >> 24) & 0xFF);
  return ByteString{span<const byte>{out}};
}

static ByteString build_asymmetric_opn_chunk_raw(uint32_t secureChannelId, ua::String securityPolicyUri,
  ByteString senderCertificates, ByteString receiverThumbprint, uint32_t sequenceNumber, uint32_t requestId,
  span<const byte> body)
{
  memory_stream_device::Dynamic streamDevice{64 * 1024, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  const auto limits = test_limits();
  auto depth = limits.stack_depth();

  stack_utils::UaScMessageHeader h;
  h.messageType = stack_utils::UaScMessageHeader::MessageType::Open;
  h.isFinal = stack_utils::UaScMessageHeader::IsFinal::Final;
  h.messageChunkSize = 0;  // patched later
  h.secureChannelId = secureChannelId;
  h.encode(limits, enc);

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
  out[4] = static_cast<byte>(chunkSize & 0xFF);
  out[5] = static_cast<byte>((chunkSize >> 8) & 0xFF);
  out[6] = static_cast<byte>((chunkSize >> 16) & 0xFF);
  out[7] = static_cast<byte>((chunkSize >> 24) & 0xFF);
  return ByteString{span<const byte>{out}};
}

static SecureChannelContext make_minimal_context_open_none(boost::asio::any_io_executor ex,
  boost::asio::strand<boost::asio::any_io_executor> strand, uint32_t secureChannelId, uint32_t activeTokenId)
{
  SecureChannelContext ctx;
  ctx.boundStrand = std::move(strand);
  ctx.state = SecureChannelContext::State::Open;
  ctx.securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx.messageSecurityMode = MessageSecurityMode::None;
  ctx.secureChannelId = secureChannelId;
  ctx.encodingLimits = test_limits();

  // Make first chunk deterministic by opting into the "first seen sets previous" path.
  ctx.lastRxSequenceNumber = std::nullopt;

  SecurityToken::Keys emptyKeys;
  ctx.activeSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx.boundStrand, emptyKeys, emptyKeys, activeTokenId, 10s);

  return ctx;
}

/// Whether `code` is the detail's own code or that of any cause beneath it.
static bool detail_chain_names(const ErrorDetail* detail, std::string_view code)
{
  for (; detail != nullptr; detail = detail->cause.get())
    if (detail->code == code)
      return true;
  return false;
}

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

}  // namespace

// @relation(AC-SVR-TCP-021-ASSOCIATE, SVR-TCP-032, SVR-UASC-001, SVR-UASC-031, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, SecureChannelIdMismatchWhenContextOpenIsRejected)
{
  // Requirements: P6-67-0001, P6-67-0031

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto headerOnly = build_uasc_header(stack_utils::UaScMessageHeader::MessageType::Message,
    stack_utils::UaScMessageHeader::IsFinal::Final,
    static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes),
    /*secureChannelId*/ 2);

  expect_runtime_exception_status([&]()
    { (void)decode_chunk_sync(policy, ctx, std::move(headerOnly)).value(); },
    Status::BadSecureChannelIdInvalid);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SC-010, SVR-UASC-001, SVR-UASC-031, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, NonOpnWithSecureChannelIdNonZeroBeforeOpenIsRejected)
{
  // Requirements: P6-67-0001, P6-67-0031

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->lastRxSequenceNumber = std::nullopt;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  auto headerOnly = build_uasc_header(stack_utils::UaScMessageHeader::MessageType::Message,
    stack_utils::UaScMessageHeader::IsFinal::Final,
    static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes),
    /*secureChannelId*/ 123);

  expect_runtime_exception_status([&]()
    { (void)decode_chunk_sync(policy, ctx, std::move(headerOnly)).value(); },
    Status::BadSecureChannelIdInvalid);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-013-LEGACY-SEQUENCE-WRAP, scope=function)

// @relation(AC-SVR-UASC-012-SEQREUSE, SVR-UASC-037, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, SequenceNumberMustIncrementByOne)
{
  // Requirements: P6-67-0012, P6-67-0037

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // First chunk establishes previous sequence number.
  {
    const std::array<byte, 1> body{std::byte{0xAB}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 1,
      body);

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->first, 1u);
  }

  // Skip a sequence number => transport error.
  {
    const std::array<byte, 1> body{std::byte{0xCD}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 3,
      /*requestId*/ 2,
      body);

    expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
      Status::BadSequenceNumberInvalid);
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// CL-UASC-019 - a server ABORT message chunk (IsFinal='A', Part 6 6.7.3) must
// surface its Error StatusCode to the aborted request WITHOUT tearing the
// channel down.
// ---------------------------------------------------------------------------
//
// @verifies CL-UASC-019
//
// Forges a None-mode symmetric MSG chunk with IsFinal=Aborted whose body is the
// Table 56 abort payload {Error UInt32 StatusCode, Reason String}, then drives the
// real symmetric decode path. The finalizer must (a) produce a benign EMPTY result
// - a bad Result would close the channel - and (b) record the {RequestId, Error}
// pair on SecureChannelContext::receivedAbort so the owning channel can fail
// exactly that one request. Falsifiable: before the fix the Aborted chunk falls
// through to nullopt and receivedAbort is never set, so the has_value() assertion
// fails; and if the finalizer instead returned a bad Result the is_good() assertion
// fails.
// @relation(CL-UASC-019, scope=function)
TEST(UascSecurityPolicyTests, AbortChunkSurfacesErrorStatusToRequest)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  constexpr uint32_t requestId = 4242;
  const StatusCode abortError{Status::BadEncodingError};

  // Table 56 abort body: Error (UInt32 StatusCode) followed by Reason (String).
  const auto limits = test_limits();
  const auto depth = limits.stack_depth();
  memory_stream_device::Dynamic bodyDevice{64, true};
  MemoryStream bodyStream{bodyDevice};
  UaBinaryEncoder bodyEnc(CodecNamespaceContext{}, bodyStream);
  bodyEnc.encode(depth, abortError.value());
  bodyEnc.encode(depth, String{"request aborted by server"});
  auto abortBody = bodyDevice.move_storage_out();
  abortBody.resize(bodyStream.get_position());

  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Aborted,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 1,
    /*requestId*/ requestId,
    span<const byte>{abortBody});

  auto outcome = decode_chunk_sync(policy, ctx, std::move(chunk));
  ASSERT_TRUE(outcome.is_good())
    << "an abort chunk must not fail the decode (a bad Result would tear the channel down)";
  auto decoded = std::move(outcome).value();
  EXPECT_FALSE(decoded.has_value()) << "an abort chunk assembles no message body";

  ASSERT_TRUE(ctx->receivedAbort.has_value())
    << "abort must be recorded on the context side-channel, not silently dropped";
  EXPECT_EQ(ctx->receivedAbort->first, requestId);
  EXPECT_EQ(ctx->receivedAbort->second, abortError);

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies CL-TCP-011
// Part 6 section 6.7.3 / section 10.14: once a request has begun multi-chunk encoding (chunksSent > 0) and a
// later chunk fails mid-stream, the client MUST emit an Abort ('A') message chunk for that RequestId - so the
// server stops awaiting a Final chunk - and fail the request with the deferred error. The SIZE-limit crossing
// the matrix row literally names is unreachable in this SDK (oversized requests are rejected UP FRONT before
// chunk 1 - CL-TCP-010/012), so the abort-emission path is exercised via the OTHER reachable trigger: a send
// that throws after chunk 1 is already on the wire. A throwing SendMessageChunk on the 2nd chunk sets the
// "send failed" deferred error and drives handle_encode_symmetric_deferred_error with chunksSent == 1.
// This unit-verifies the emission the integration matrix row reports as blocked (it needs a mid-stream
// fault-injection transport interface). Falsifiable: with no abort emission the server sees only chunk 1 and
// no 'A' - capture would hold a single chunk and none would carry IsFinal 'A'.
// @relation(CL-TCP-011, scope=function)
TEST(UascSecurityPolicyTests, MidStreamFailureAfterFirstChunkEmitsAbortChunk)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  // Small send buffer forces multi-chunk; generous message/chunk-count limits so the UP-FRONT size guard
  // passes and we actually reach chunk emission (the point of this test, not the up-front rejection).
  ctx->negotiatedLimits.sendBufferSize = 8192;
  ctx->negotiatedLimits.sendMaxMessageSize = 10u * 1024u * 1024u;
  ctx->negotiatedLimits.sendMaxChunkCount = 1000u;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // A body that spans several 8192-byte chunks, so chunk 1 is sent before chunk 2 fails. Driven through the
  // test_access friend interface onto the (protected) symmetric encode path - production reaches it only via
  // the channel's real transport send, which a unit test cannot make fail mid-stream.
  ByteString body(size_t{40000}, uint8_t{0x44});

  struct Capture
  {
    std::vector<ByteString> chunks;
    int calls = 0;
  };

  auto capture = std::make_shared<Capture>();
  SecurityPolicy::SendMessageChunk sender = [capture](ByteString chunk)
  {
    const int n = capture->calls++;
    if (n == 1)
    {
      // The SECOND send (chunk 2) fails AFTER chunk 1 is already on the wire (chunksSent == 1).
      throw UaException(StatusCode{Status::BadCommunicationError});
    }
    capture->chunks.push_back(std::move(chunk));
  };

  auto result = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb)
    {
      ua::test_access::SymmetricEncodeDriver::encode(
        *policy, *ctx, /*requestId*/ 7, body, sender, std::move(cb));
    });

  EXPECT_TRUE(result.is_bad()) << "a mid-stream chunk failure must fail the request";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCommunicationError})
    << "the deferred 'send failed' status must surface to the request";

  // capture->chunks == [chunk 1 (captured), abort chunk (captured)]; the throwing 2nd send was not captured.
  ASSERT_EQ(capture->chunks.size(), 2u)
    << "chunk 1 plus the emitted Abort chunk must be observed (the failing chunk 2 send was not captured)";
  ASSERT_GE(capture->chunks[0].size(), 4u);
  ASSERT_GE(capture->chunks[1].size(), 4u);
  // UaScMessageHeader wire layout: a 3-byte MessageType then a 1-byte IsFinal ('C'/'F'/'A') at index 3.
  EXPECT_NE(capture->chunks[0][3], static_cast<uint8_t>('A'))
    << "chunk 1 must be a normal message chunk, not an Abort";
  EXPECT_EQ(capture->chunks[1][3], static_cast<uint8_t>('A'))
    << "after chunksSent>0 a mid-stream failure must emit an Abort ('A') chunk (Part 6 6.7.3)";

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-037, scope=function)
TEST(UascSecurityPolicyTests, RequestIdMustBeStableAcrossChunksOfSameMessage)
{
  // Requirements: P6-67-0037

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Chunk 1: intermediate, requestId=10.
  {
    const std::array<byte, 1> body{std::byte{0x01}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Intermediate,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 10,
      body);

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    EXPECT_FALSE(decoded.has_value());
  }

  // Chunk 2: final, but requestId differs => decoding error.
  {
    const std::array<byte, 1> body{std::byte{0x02}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 2,
      /*requestId*/ 11,
      body);

    expect_runtime_exception_status(
      [&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); }, Status::BadDecodingError);
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-029-NOINTERPRET, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, BodyIsNotAccumulatedWhenSequenceVerificationFails)
{
  // Requirement: P6-67-0029

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Establish expected next sequence number to be 2.
  {
    const std::array<byte, 1> body{std::byte{0x11}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 1,
      body);
    (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value();
  }

  ASSERT_TRUE(ctx->receivedMessageBody.empty());

  // Now send a chunk with a bad sequence number and a recognizable body marker.
  const std::array<byte, 4> marker{std::byte{'M'}, std::byte{'A'}, std::byte{'R'}, std::byte{'K'}};
  auto bad = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Intermediate,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 4,
    /*requestId*/ 2,
    marker);

  expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(bad)).value(); },
    Status::BadSequenceNumberInvalid);

  // The body copy happens after `check_sequence_header`; if sequence verification fails,
  // nothing from this chunk should be accumulated.
  EXPECT_TRUE(ctx->receivedMessageBody.empty());
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-008-HEADERLEN, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, MissingSymmetricSecurityHeaderBytesIsRejected)
{
  // Requirement: P6-67-0008 (invalid security header lengths)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Build a UASC MSG header which claims a full header size but provide only UaScMessageHeader bytes.
  // This forces the SymmetricSecurityHeader decode to hit end-of-buffer.
  const uint32_t claimedSize = static_cast<uint32_t>(stack_utils::UaScMessageHeader::sizeInBytes +
                                                     stack_utils::SymmetricSecurityHeader::sizeInBytes +
                                                     stack_utils::SequenceHeader::sizeInBytes + 1);

  auto truncated = build_uasc_header(stack_utils::UaScMessageHeader::MessageType::Message,
    stack_utils::UaScMessageHeader::IsFinal::Final,
    claimedSize,
    /*secureChannelId*/ 1);

  // Expectation change (2026-09-28): the truncated header is refused as a decoding error at the point
  // the stream runs out. The status this arm asserted before, Bad_SecureChannelTokenUnknown, was the
  // trace of a defect: the in-memory stream zero-filled the missing bytes, so the chunk WAS processed
  // against a partially-read header (TokenId 0) and refused only because that token was unknown.
  // AC-SVR-UASC-008-HEADERLEN requires that the chunk is not processed against a partial header.
  expect_runtime_exception_status(
    [&]() { (void)decode_chunk_sync(policy, ctx, std::move(truncated)).value(); }, Status::BadDecodingError);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-003, SVR-UASC-004, SVR-UASC-009, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, AsymmetricSenderCertificateMustLeaveRoomForBody)
{
  // Requirements: P6-67-0003, P6-67-0009

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  // Create a valid certificate so DER parsing succeeds.
  auto caKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto caCert = pki.create_root_ca(caKeys, "Test Root", "10");
  auto leafKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto from = DateTime::now();
  auto to = DateTime{from.value() + std::chrono::days{30}};
  auto leafCert = pki.create_leaf_cert(leafKeys, caKeys, caCert, from, to);

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->lastRxSequenceNumber = std::nullopt;
  // Receiver transport limit: keep small to force sender-certificate size enforcement.
  ctx->negotiatedLimits.receiveBufferSize = 4096;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  stack_utils::AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  sh.senderCertificate = leafCert;
  sh.issuerCertificates.push_back(caCert);
  sh.receiverCertificateThumbprint.clear();

  const std::array<byte, 1> body{std::byte{0x01}};

  // First ensure the baseline chunk decodes.
  {
    auto ok = build_asymmetric_opn_chunk(/*secureChannelId*/ 0, sh, /*seq*/ 1, /*req*/ 1, body);
    auto decoded = decode_chunk_sync(policy, ctx, std::move(ok)).value();
    ASSERT_TRUE(decoded.has_value());
  }

  // Now bloat the sender certificate bytes by appending trailing garbage to the DER buffer.
  // This keeps the first cert parseable but increases the encoded SenderCertificateLength.
  auto der = leafCert->der_encoding();
  ByteString bloated;
  bloated.payload().insert(bloated.end(), der.begin(), der.end());
  bloated.resize(bloated.size() + 60000, uint8_t{0xEE});

  auto bad = build_asymmetric_opn_chunk_raw(/*secureChannelId*/ 0,
    "http://opcfoundation.org/UA/SecurityPolicy#None",
    std::move(bloated),
    {},
    /*seq*/ 2,
    /*req*/ 2,
    body);

  expect_runtime_exception_status(
    [&]() { (void)decode_chunk_sync(policy, ctx, std::move(bad)).value(); }, Status::BadDecodingError);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SC-008, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, PolicyNoneIgnoresApplicationInstanceCertificateInOpn)
{
  // Requirement: P4-0008 (securityPolicyUri None: server ignores ApplicationInstanceCertificate)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();
  TestPki pki{crypto};

  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto from = DateTime::now();
  auto to = DateTime{from.value() + std::chrono::days{30}};
  auto cert = pki.create_root_ca(keys, "Cert", "1");

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 65536;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // Encode sender certificate bytes (ApplicationInstanceCertificate) even though policy is None.
  ByteString senderCertBytes;
  {
    auto der = cert->der_encoding();
    senderCertBytes.payload().insert(senderCertBytes.end(), der.begin(), der.end());
  }

  // Receiver thumbprint may be present; policy None does not use it.
  ByteString receiverThumbprint;
  receiverThumbprint.resize(32, uint8_t{0x11});

  const std::array<byte, 1> body{std::byte{0x42}};
  auto chunk = build_asymmetric_opn_chunk_raw(/*secureChannelId*/ 0,
    String{"http://opcfoundation.org/UA/SecurityPolicy#None"},
    std::move(senderCertBytes),
    std::move(receiverThumbprint),
    /*seq*/ 1,
    /*req*/ 1,
    body);

  auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
  ASSERT_TRUE(decoded.has_value());
  ASSERT_EQ(decoded->first, 1u);
  ASSERT_EQ(decoded->second.size(), 1u);
  EXPECT_EQ(decoded->second[0], uint8_t{0x42});
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-UASC-020-OPNSPLIT, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, OpnBodyDecodesAsOpenSecureChannelRequest)
{
  // Requirement: P6-67-0020 (OPN parameters split header/body)

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto crypto = create_crypto();

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 65536;

  // Encode a representative OpenSecureChannelRequest payload into the OPN body.
  // This test only verifies that parameters are correctly split between header/body
  // (i.e., the body bytes are preserved and returned), not that the service decode pipeline runs.
  OpenSecureChannelRequest req;
  req.client_protocol_version() = 0;
  req.request_type() = SecurityTokenRequestType::Issue;
  req.security_mode() = MessageSecurityMode::None;
  req.client_nonce().clear();
  req.requested_lifetime() = 1000;

  ByteString body;
  {
    memory_stream_device::Dynamic dev{1024, true};
    MemoryStream stream{dev};
    UaBinaryEncoder binEnc(CodecNamespaceContext{}, stream);
    Encoder enc{binEnc};
    auto depth = test_limits().stack_depth();
    req.encode(depth, enc);
    auto encodedSize = stream.get_position();
    auto raw = dev.move_storage_out();
    raw.resize(encodedSize);
    body = ByteString{span<const byte>{raw}};
  }

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // For policy None, the asymmetric security header can include empty cert/thumbprint fields.
  auto chunk = build_asymmetric_opn_chunk_raw(/*secureChannelId*/ 0,
    String{"http://opcfoundation.org/UA/SecurityPolicy#None"},
    {},
    {},
    /*seq*/ 1,
    /*req*/ 10,
    body);

  auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->first, 10u);

  EXPECT_EQ(decoded->second, body);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Covers SVR-UASC-061 (coverage-audit retag).
// @relation(AC-SVR-UASC-011-TOKENID, SVR-UASC-035, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, UnknownTokenIdIsRejected)
{
  // Requirements: P6-67-0011, P6-67-0035

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x42}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 999,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
    Status::BadSecureChannelTokenUnknown);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-023, scope=function)
// @verifies AC-SVR-SC-013-PENDING-TOKEN-PROMOTED-ONLY-BY-AN-ACCEPTED-CHUNK
TEST(UascSecurityPolicyTests, PendingTokenIsPromotedWhenMessageArrivesWithNewTokenId)
{
  // Requirements: P6-67-0023, P6-67-0025

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));

  // Add a pending token (simulating a successful renew).
  SecurityToken::Keys emptyKeys;
  ctx->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x99}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 11,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
  ASSERT_TRUE(decoded.has_value());

  ASSERT_NE(ctx->activeSecurityToken, nullptr);
  EXPECT_EQ(ctx->activeSecurityToken->id(), 11u);
  EXPECT_EQ(ctx->pendingSecurityToken, nullptr);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// H-D5 (B2-6): the pending token is installed only by a chunk that is ACCEPTED. A chunk naming the
// pending token that fails (here: a sequence number that cannot follow) leaves the active token
// active and the pending token pending, so no state changes on input that was not accepted.
// @verifies AC-SVR-SC-013-PENDING-TOKEN-PROMOTED-ONLY-BY-AN-ACCEPTED-CHUNK
TEST(UascSecurityPolicyTests, AChunkRefusedUnderThePendingTokenLeavesBothTokensAsTheyWere)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  ctx->lastRxSequenceNumber = 1;  // the next acceptable number is 2
  SecurityToken::Keys emptyKeys;
  ctx->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  const std::array<byte, 1> body{std::byte{0x99}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 11,
    /*sequenceNumber*/ 7,  // not 2: refused
    /*requestId*/ 1,
    body);

  expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
    Status::BadSequenceNumberInvalid);

  ASSERT_NE(ctx->activeSecurityToken, nullptr);
  EXPECT_EQ(ctx->activeSecurityToken->id(), 10u)
    << "the refused chunk must not have promoted the pending token";
  ASSERT_NE(ctx->pendingSecurityToken, nullptr);
  EXPECT_EQ(ctx->pendingSecurityToken->id(), 11u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// H-D6 (B2-7): an OpenSecureChannel chunk marked Abort is refused; it used to append its body and
// leave the reassembly state behind.
// @verifies AC-SVR-SC-007-OPN-CHUNK-MARKED-ABORT-IS-REFUSED
TEST(UascSecurityPolicyTests, AnOpnChunkMarkedAbortIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::None);
  ctx->messageSecurityMode = MessageSecurityMode::None;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = create_crypto();
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 65536;

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  stack_utils::AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
  const std::array<byte, 1> body{std::byte{0x01}};

  auto aborted = build_asymmetric_opn_chunk(
    /*secureChannelId*/ 0, sh, /*seq*/ 1, /*req*/ 1, body, stack_utils::UaScMessageHeader::IsFinal::Aborted);
  auto refused = decode_chunk_sync(policy, ctx, std::move(aborted));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "AbortChunkInOpenSecureChannel");
  EXPECT_TRUE(ctx->receivedMessageBody.empty()) << "nothing of the refused chunk is kept";

  // Control: the same chunk marked Final decodes.
  auto ok = build_asymmetric_opn_chunk(/*secureChannelId*/ 0, sh, /*seq*/ 1, /*req*/ 1, body);
  auto decoded = decode_chunk_sync(policy, ctx, std::move(ok)).value();
  EXPECT_TRUE(decoded.has_value());
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// H-D8 (CRY-4): a sequence number that returns to the first one used under the current token is a
// reuse (Part 6 6.7.2.4) and is refused; under a different token the same number is a fresh start.
// The context is seeded as 2^32 chunks would have left it.
// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, AReceivedSequenceNumberReturningToItsFirstValueUnderOneTokenIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  ctx->lastRxSequenceNumber = 4;  // 5 is the next number in sequence...
  ctx->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u};  // ...and where token 10 began

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  const std::array<byte, 1> body{std::byte{0x01}};
  auto reuse = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 5,
    /*requestId*/ 1,
    body);
  auto refused = decode_chunk_sync(policy, ctx, std::move(reuse));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSequenceNumberInvalid);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "SequenceNumberReusedUnderToken")
    << "the reuse rule, not the ordinary sequence check, refused it";

  // Control: the same number under a newly promoted token is that token's first use.
  auto fresh = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  fresh->lastRxSequenceNumber = 4;
  fresh->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u};
  SecurityToken::Keys emptyKeys;
  fresh->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*fresh->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);
  auto underNewToken = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 11,
    /*sequenceNumber*/ 5,
    /*requestId*/ 1,
    body);
  auto decoded = decode_chunk_sync(policy, fresh, std::move(underNewToken)).value();
  EXPECT_TRUE(decoded.has_value());
  EXPECT_EQ(fresh->rxUseUnderToken.tokenId, 11u);
  ctx.reset();
  fresh.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

/// The validator SecurityPolicy::validate_certificate_async delegates to (owner review 2026-10-02, item 2:
/// the Security Policy Check is Table 106 step 4 of the certificate store's validation, run against the
/// request's policy): a certificate store in a fresh temporary directory whose trust list holds @p trusted.
struct TrustingStore
{
  std::filesystem::path directory;
  std::shared_ptr<CertificateStore> store;

  TrustingStore(boost::asio::any_io_executor executor, const std::shared_ptr<const Crypto>& crypto,
    const std::vector<std::shared_ptr<const X509Certificate>>& trusted)
    : directory(std::filesystem::temp_directory_path() /
                ("ua_policy_check_" + Guid::create_and_generate().as_string()))
  {
    std::filesystem::create_directories(directory);
    store = CertificateStoreFiles::create(std::move(executor), crypto, {.trustListPath = directory});
    for (const auto& certificate : trusted)
    {
      store->add_to_trusted_certificates_sync(certificate);
    }
  }

  TrustingStore(const TrustingStore&) = delete;
  TrustingStore& operator=(const TrustingStore&) = delete;

  ~TrustingStore()
  {
    store.reset();
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);
  }
};

/// A self-signed certificate that meets OPC 10000-6 Table 43 (RSA keyUsage, serverAuth and clientAuth), so
/// the only rule it can break is the one the arm varies.
Crypto::CreateCertificateConfig application_certificate_parameters(
  const std::shared_ptr<const AsymmetricKeyPair>& keys, CertificateSignatureAlgorithm algorithm)
{
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = p.issuerKeys = keys;
  p.subject.commonName = "Sha1 Leaf";
  p.serialNumber = "7";
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyEncipherment = true;
  p.keyUsage.dataEncipherment = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = algorithm;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{30}};
  return p;
}

}  // namespace

// H-D7 (CRY-3): the certificate's own signature algorithm must be one the policy permits; a SHA-1
// signed certificate on a SHA-256 policy is a policy-check failure. Owner review 2026-10-02, item 2: the
// policy rules moved into the validator (Table 106 step 4, SecurityPolicy::check_certificate_compliance),
// so the arm validates through the store the policy delegates to, with the certificate trusted, and the
// refusal is the validator's Security Policy Check rather than a check run before the store is asked.
// @verifies AC-SVR-SECADMIN-004-CERTIFICATE-SIGNATURE-ALGORITHM-AND-KEY-LENGTH-ARE-POLICY-CHECKS
TEST(UascSecurityPolicyTests, ACertificateSignedWithSha1IsRefusedByASha256Policy)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto p = application_certificate_parameters(keys, CertificateSignatureAlgorithm::RsaPkcs15Sha1);
  auto sha1Cert = pki.create_cert(p);
  ASSERT_EQ(sha1Cert->signature_algorithm(), CertificateSignatureAlgorithm::RsaPkcs15Sha1);
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.serialNumber = "70";
  auto sha256Cert = pki.create_cert(p);
  auto store = std::make_unique<TrustingStore>(tp.get_executor(), crypto, std::vector{sha1Cert, sha256Cert});

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->certStore = store->store;
  ctx->remoteCertificate = sha1Cert;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto result = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->validate_certificate_async(*ctx, std::move(cb)); });
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificatePolicyCheckFailed);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CertificateSignatureAlgorithmNotPermitted");

  // Control: the same certificate signed with SHA-256, equally trusted, passes the policy check and
  // validates.
  ctx->remoteCertificate = sha256Cert;
  auto control = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->validate_certificate_async(*ctx, std::move(cb)); });
  EXPECT_TRUE(control.is_good()) << std::hex << control.status_code().as_uint32();
  ctx.reset();
  store.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Owner review 2026-10-02, item 2: the key-length rule is the validator's Security Policy Check (Table 106
// step 4); the arm validates a trusted certificate through the store the policy delegates to. The detail
// code is the validator's (CertificateKeyLengthOutOfRange,
// SecPolAsymmetricEncryption::check_certificate_compliance).
// @verifies AC-SVR-SECADMIN-004-CERTIFICATE-SIGNATURE-ALGORITHM-AND-KEY-LENGTH-ARE-POLICY-CHECKS
TEST(UascSecurityPolicyTests, AKeyLengthOutsideThePolicyRangeIsAPolicyCheckFailure)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto shortKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 1024);
  auto cert = pki.create_self_signed_application_root(shortKeys, "Short Key", "8");
  auto store = std::make_unique<TrustingStore>(tp.get_executor(), crypto, std::vector{cert});

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->certStore = store->store;
  ctx->remoteCertificate = cert;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto result = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->validate_certificate_async(*ctx, std::move(cb)); });
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificatePolicyCheckFailed);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CertificateKeyLengthOutOfRange");
  ctx.reset();
  store.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// H-D1 (B2-4): whatever the primitive reports, an asymmetric decrypt failure answers
// Bad_SecurityChecksFailed, the code a signature failure is masked to, so the ERR does not say
// which step refused the OPN.
// @verifies AC-SVR-UASC-030-ASYMMETRIC-DECRYPT-FAILURE-IS-ONE-SECURITY-CHECKS-FAILURE
TEST(UascSecurityPolicyTests, AnAsymmetricDecryptFailureAnswersSecurityChecksFailed)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(keys, "Local", "9");

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->localCertificate = localCert;
  ctx->localKeyPair = keys;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // Eight header bytes, then one 256-byte block that is not a ciphertext.
  ByteString chunk = crypto->get_entropy_sync(8 + 256);
  auto result = ua::test_helpers::run_async_callback_sync<ByteStringResult>(
    [&](auto cb) { policy->asymmetric_decrypt_async(*ctx, span<const byte>{chunk}, 8, std::move(cb)); });
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoOperationFailed");
  ASSERT_TRUE(result.error_detail()->cause) << "the primitive's own status travels as the cause, for the log";
  EXPECT_FALSE(result.error_detail()->cause->code.empty());
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
// Runs policy->asymmetric_decrypt_async over one 256-byte block with a parked crypto provider, answers the
// block's decrypt with @p answer, and returns what the policy answers.
ByteStringResult asymmetric_decrypt_with_answer(Crypto::ByteSpanResult answer)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto localCert = pki.create_root_ca(keys, "Local", "9");

  auto parked = test_helpers::FakeAsyncCrypto::create();
  parked->set_park_async(true);
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = parked;
  ctx->localCertificate = localCert;
  ctx->localKeyPair = keys;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  ByteString chunk = crypto->get_entropy_sync(8 + 256);
  auto answered = std::make_shared<std::promise<ByteStringResult>>();
  auto future = answered->get_future();
  policy->asymmetric_decrypt_async(*ctx,
    span<const byte>{chunk},
    8,
    [answered](ByteStringResult result) { answered->set_value(std::move(result)); });

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (parked->pending_asymmetric_decrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(5ms);
  }
  ByteStringResult result{StatusCode{Status::BadTimeout}};
  if (parked->pending_asymmetric_decrypt_count() == 1)
  {
    parked->complete_pending_asymmetric_decrypt(0, std::move(answer));
    if (future.wait_for(5s) == std::future_status::ready)
    {
      result = future.get();
    }
    else
    {
      ADD_FAILURE() << "the policy did not answer";
    }
  }
  else
  {
    ADD_FAILURE() << "the block's decrypt was not issued";
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return result;
}
}  // namespace

// H-D1 for an Uncertain answer: a block is taken only from a Good decrypt, so an Uncertain answer holding
// a plaintext is refused with Bad_SecurityChecksFailed, like a Bad one, and the CryptoAnswerUncertain
// ErrorDetail whose cause is the Uncertain code.
// @verifies AC-SVR-UASC-030-ASYMMETRIC-DECRYPT-FAILURE-IS-ONE-SECURITY-CHECKS-FAILURE
// @relation(AC-SVR-UASC-030-ASYMMETRIC-DECRYPT-FAILURE-IS-ONE-SECURITY-CHECKS-FAILURE, scope=function)
TEST(UascSecurityPolicyTests, AnUncertainAsymmetricDecryptHoldingAPlaintextAnswersSecurityChecksFailed)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  const std::vector<byte> plaintext(64, byte{0x5A});

  const auto result =
    asymmetric_decrypt_with_answer(Crypto::ByteSpanResult{span<const byte>{plaintext}, uncertain});

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
}

// The same refusal for an Uncertain answer that holds no plaintext.
// @verifies AC-SVR-UASC-030-ASYMMETRIC-DECRYPT-FAILURE-IS-ONE-SECURITY-CHECKS-FAILURE
// @relation(AC-SVR-UASC-030-ASYMMETRIC-DECRYPT-FAILURE-IS-ONE-SECURITY-CHECKS-FAILURE, scope=function)
TEST(UascSecurityPolicyTests, AnUncertainAsymmetricDecryptWithoutAPlaintextAnswersSecurityChecksFailed)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  const auto result = asymmetric_decrypt_with_answer(Crypto::ByteSpanResult{uncertain});

  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
}

namespace
{
// Runs policy->asymmetric_encrypt_async over one block with a parked crypto provider, answers the block's
// encrypt with @p answer, and returns what the policy answers.
VoidResult asymmetric_encrypt_with_answer(VoidResult answer)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto remoteCert = pki.create_root_ca(keys, "Remote", "9");

  auto parked = test_helpers::FakeAsyncCrypto::create();
  parked->set_park_async(true);
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = parked;
  ctx->remoteCertificate = remoteCert;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  ByteString plaintext = crypto->get_entropy_sync(policy->asymmetric_plaintext_block_size(remoteCert.get()));
  ByteString ciphertext;
  ciphertext.resize(policy->asymmetric_ciphertext_block_size(remoteCert.get()));
  auto answered = std::make_shared<std::promise<VoidResult>>();
  auto future = answered->get_future();
  policy->asymmetric_encrypt_async(*ctx,
    span<const byte>{plaintext},
    span<byte>{ciphertext},
    [answered](VoidResult result) { answered->set_value(std::move(result)); });

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (parked->pending_asymmetric_encrypt_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(5ms);
  }
  VoidResult result{StatusCode{Status::BadTimeout}};
  if (parked->pending_asymmetric_encrypt_count() == 1)
  {
    parked->complete_pending_asymmetric_encrypt(0, std::move(answer));
    if (future.wait_for(5s) == std::future_status::ready)
    {
      result = future.get();
    }
    else
    {
      ADD_FAILURE() << "the policy did not answer";
    }
  }
  else
  {
    ADD_FAILURE() << "the block's encrypt was not issued";
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return result;
}
}  // namespace

// A ciphertext block is used only after a Good encrypt: an Uncertain answer is refused with
// Bad_InternalError, the CryptoAnswerUncertain ErrorDetail and the Uncertain code as its inner status.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(UascSecurityPolicyTests, AnUncertainAsymmetricEncryptIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};

  const auto result = asymmetric_encrypt_with_answer(VoidResult{uncertain});

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
}

// The control: a Bad answer is passed on with its own code, and a Good one completes the encrypt.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(UascSecurityPolicyTests, AnAsymmetricEncryptAnswerIsPassedOnWhenBadAndCompletesWhenGood)
{
  const auto bad = asymmetric_encrypt_with_answer(VoidResult{StatusCode{Status::BadEncodingError}});
  EXPECT_EQ(bad.status_code().as_status(), Status::BadEncodingError);

  const auto good = asymmetric_encrypt_with_answer(VoidResult{});
  EXPECT_TRUE(good.is_good());
}

// The ECDH shared secret is used only after a Good answer: an Uncertain one is refused with the step's
// Bad_InternalError and the CryptoAnswerUncertain ErrorDetail whose cause is the Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(UascSecurityPolicyTests, AnUncertainEccSharedSecretIsRefused)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto parked = test_helpers::FakeAsyncCrypto::create();
  parked->set_park_async(true);
  auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = parked;
  ctx->securityPolicy = policy;
  ByteString localNonce;
  localNonce.resize(64);
  ByteString remoteNonce;
  remoteNonce.resize(64);

  auto answered = std::make_shared<std::promise<SecurityPolicy::DeriveSymmetricKeysResult>>();
  auto future = answered->get_future();
  policy->derive_symmetric_keys_async(ctx,
    std::move(localNonce),
    std::move(remoteNonce),
    ChannelRole::Client,
    [answered](SecurityPolicy::DeriveSymmetricKeysResult result) { answered->set_value(std::move(result)); });

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (parked->pending_calculate_shared_secret_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(parked->pending_calculate_shared_secret_count(), 1U) << "the shared secret was not requested";
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  parked->complete_pending_calculate_shared_secret(0, ByteStringResult{uncertain});
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the policy did not answer";
  const auto result = future.get();

  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
  EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Each HKDF answer is used only when Good: an Uncertain answer for the server's keys, or for the client's
// after the server's were derived, holding key material or not, is refused with the step's Bad_InternalError
// and the CryptoAnswerUncertain ErrorDetail whose inner status is the Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(UascSecurityPolicyTests, AnUncertainEccKeyDerivationIsRefused)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  for (const bool clientStep : {false, true})
  {
    for (const bool withMaterial : {false, true})
    {
      SCOPED_TRACE(std::string{clientStep ? "the client's keys" : "the server's keys"} +
                   (withMaterial ? ", the answer holds key material" : ", the answer holds none"));
      boost::asio::thread_pool tp;
      auto strand = boost::asio::make_strand(tp.get_executor());
      auto parked = test_helpers::FakeAsyncCrypto::create();
      parked->set_park_async(true);
      auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
      auto ctx = std::make_shared<SecureChannelContext>();
      ctx->boundStrand = strand;
      ctx->encodingLimits = test_limits();
      ctx->crypto = parked;
      ctx->securityPolicy = policy;
      ByteString localNonce;
      localNonce.resize(64);
      ByteString remoteNonce;
      remoteNonce.resize(64);
      ByteString material;
      material.resize(policy->symmetric_signature_key_size() + policy->symmetric_encryption_key_size() +
                        policy->symmetric_iv_size(),
        0x3c);

      auto answered = std::make_shared<std::promise<SecurityPolicy::DeriveSymmetricKeysResult>>();
      auto future = answered->get_future();
      policy->derive_symmetric_keys_async(ctx,
        std::move(localNonce),
        std::move(remoteNonce),
        ChannelRole::Client,
        [answered](SecurityPolicy::DeriveSymmetricKeysResult result)
        { answered->set_value(std::move(result)); });

      const auto waitFor = [&](auto count)
      {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (count() == 0 && std::chrono::steady_clock::now() < deadline)
          std::this_thread::sleep_for(5ms);
        return count();
      };
      ASSERT_EQ(waitFor([&] { return parked->pending_calculate_shared_secret_count(); }), 1U);
      ByteString secret;
      secret.resize(32, 0x5a);
      parked->complete_pending_calculate_shared_secret(0, ByteStringResult{secret});
      ASSERT_EQ(waitFor([&] { return parked->pending_derive_symmetric_keys_count(); }), 1U)
        << "the server's keys were not requested";
      if (clientStep)
      {
        parked->complete_pending_derive_symmetric_keys(0, ByteStringResult{material});
        ASSERT_EQ(waitFor([&] { return parked->pending_derive_symmetric_keys_count(); }), 1U)
          << "the client's keys were not requested";
      }
      parked->complete_pending_derive_symmetric_keys(
        0, withMaterial ? ByteStringResult{material, uncertain} : ByteStringResult{uncertain});
      ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the policy did not answer";
      const auto result = future.get();

      EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
      ASSERT_NE(result.error_detail(), nullptr);
      EXPECT_EQ(result.error_detail()->code, "CryptoAnswerUncertain");
      EXPECT_EQ(result.error_detail()->innerStatus, uncertain.value());
      ctx.reset();
      ::ua::test_utils::drain_with_timeout(tp);
    }
  }
}

// H-D6 on the ECC OPN path, which has its own decode operation: the same refusal, before any
// certificate or signature work.
// @verifies AC-SVR-SC-007-OPN-CHUNK-MARKED-ABORT-IS-REFUSED
TEST(UascSecurityPolicyTests, AnEccOpnChunkMarkedAbortIsRefused)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = create_crypto();
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 65536;

  stack_utils::AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = std::string{ctx->securityPolicy->uri()};
  const std::array<byte, 1> body{std::byte{0x01}};
  auto aborted = build_asymmetric_opn_chunk(
    /*secureChannelId*/ 0, sh, /*seq*/ 1, /*req*/ 1, body, stack_utils::UaScMessageHeader::IsFinal::Aborted);
  auto refused = decode_chunk_sync(ctx->securityPolicy, ctx, std::move(aborted));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "AbortChunkInOpenSecureChannel");
  EXPECT_TRUE(ctx->receivedMessageBody.empty());
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// C-5: under the legacy numbering the peer may wrap to any value below 1024; a wrap onto a number at
// or above the token's first number reuses one already sent under it.
// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, ALegacyWrapOntoANumberAlreadyUsedUnderTheTokenIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);
  constexpr uint32_t nearTheTop = std::numeric_limits<uint32_t>::max() - 5;

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  ctx->lastRxSequenceNumber = nearTheTop;  // the legacy rule accepts any number below 1024 from here
  ctx->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 100u, .lastSequenceNumber = nearTheTop};

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);
  const std::array<byte, 1> body{std::byte{0x01}};
  auto reuse = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 500,  // below 1024, above the first number: used before under token 10
    /*requestId*/ 1,
    body);
  auto refused = decode_chunk_sync(policy, ctx, std::move(reuse));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSequenceNumberInvalid);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "SequenceNumberReusedUnderToken");

  // Control: a wrap below the first number lands on numbers never used under this token.
  auto fresh = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  fresh->lastRxSequenceNumber = nearTheTop;
  fresh->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 100u, .lastSequenceNumber = nearTheTop};
  auto unused = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 50,
    /*requestId*/ 1,
    body);
  auto accepted = decode_chunk_sync(policy, fresh, std::move(unused)).value();
  EXPECT_TRUE(accepted.has_value());
  ctx.reset();
  fresh.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// T-10: the deprecated policies still admit a SHA-1 signature (the opt-in legacy interop the
// deprecation gate exists for). Owner review 2026-10-02, item 2: the policy check runs in the validator,
// so with no store the arm could not tell an admitted certificate from a refused one; it validates the
// trusted certificate through the store the policy delegates to, and the certificate validates.
// @verifies AC-SVR-SECADMIN-004-CERTIFICATE-SIGNATURE-ALGORITHM-AND-KEY-LENGTH-ARE-POLICY-CHECKS
TEST(UascSecurityPolicyTests, ASha1SignedCertificateIsStillAdmittedByADeprecatedPolicy)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  TestPki pki{crypto};
  auto keys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto sha1Cert =
    pki.create_cert(application_certificate_parameters(keys, CertificateSignatureAlgorithm::RsaPkcs15Sha1));
  auto store = std::make_unique<TrustingStore>(tp.get_executor(), crypto, std::vector{sha1Cert});

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->encodingLimits = test_limits();
  ctx->crypto = crypto;
  ctx->certStore = store->store;
  ctx->remoteCertificate = sha1Cert;
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256);
  ASSERT_TRUE(policy->is_deprecated());
  auto result = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) { policy->validate_certificate_async(*ctx, std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "the deprecated policy admits the SHA-1 certificate; " << std::hex
                                << result.status_code().as_uint32();
  ctx.reset();
  store.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// R2-3: on an authenticated RSA policy the refusal comes before the security header is decoded, so
// an Abort chunk carrying no certificate is refused as an Abort, not as a missing certificate.
// @verifies AC-SVR-SC-007-OPN-CHUNK-MARKED-ABORT-IS-REFUSED
TEST(UascSecurityPolicyTests, AnRsaOpnChunkMarkedAbortIsRefusedBeforeItsCertificateIsLookedAt)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = strand;
  ctx->state = SecureChannelContext::State::Uninitialised;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::Sign;
  ctx->secureChannelId = 0;
  ctx->encodingLimits = test_limits();
  ctx->crypto = create_crypto();
  ctx->lastRxSequenceNumber = std::nullopt;
  ctx->negotiatedLimits.receiveBufferSize = 65536;

  stack_utils::AsymmetricSecurityHeader sh;
  sh.securityPolicyUri = std::string{ctx->securityPolicy->uri()};
  const std::array<byte, 1> body{std::byte{0x01}};
  auto aborted = build_asymmetric_opn_chunk(
    /*secureChannelId*/ 0, sh, /*seq*/ 1, /*req*/ 1, body, stack_utils::UaScMessageHeader::IsFinal::Aborted);
  auto refused = decode_chunk_sync(ctx->securityPolicy, ctx, std::move(aborted));
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSecurityChecksFailed);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "AbortChunkInOpenSecureChannel");
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-UASC-025, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, InvalidTokenIdIsNotIgnoredByCurrentImplementation)
{
  // Requirement: P6-67-0025
  // Note: Spec says receivers shall ignore invalid/expired TokenIds; current implementation treats
  // unknown TokenId as a transport error (`BadSecureChannelTokenUnknown`).

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const std::array<byte, 1> body{std::byte{0x01}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 1234,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
    Status::BadSecureChannelTokenUnknown);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-SC-001, SVR-SC-013, SVR-SC-016, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, TokenRolloverPromotesPendingTokenAndRejectsOldTokenAfterPromotion)
{
  // Requirements: P4-0001, P4-0013, P4-0016

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));

  // Add a pending token to simulate a renew.
  SecurityToken::Keys emptyKeys;
  ctx->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx->boundStrand, emptyKeys, emptyKeys, /*id*/ 11, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  // 1) Message with active token id is accepted.
  {
    const std::array<byte, 1> body{std::byte{0x01}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 1,
      body);

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(ctx->activeSecurityToken->id(), 10u);
    ASSERT_NE(ctx->pendingSecurityToken, nullptr);
    EXPECT_EQ(ctx->pendingSecurityToken->id(), 11u);
  }

  // 2) First message with pending token id promotes it to active.
  {
    const std::array<byte, 1> body{std::byte{0x02}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 11,
      /*sequenceNumber*/ 2,
      /*requestId*/ 2,
      body);

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    ASSERT_TRUE(decoded.has_value());
    ASSERT_NE(ctx->activeSecurityToken, nullptr);
    EXPECT_EQ(ctx->activeSecurityToken->id(), 11u);
    EXPECT_EQ(ctx->pendingSecurityToken, nullptr);
  }

  // 3) After promotion, old token id is rejected.
  {
    const std::array<byte, 1> body{std::byte{0x03}};
    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 3,
      /*requestId*/ 3,
      body);

    expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
      Status::BadSecureChannelTokenUnknown);
  }
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-SC-023-MODE-ENFORCED-PER-ENDPOINT, SVR-UASC-036, SVR-UASC-061, scope=function)
TEST(UascSecurityPolicyTests, SignAndEncryptModeRequiresProperlyEncryptedChunk)
{
  // Requirement: P6-67-0036 (security mode enforcement).
  // For authenticated policies with MessageSecurityMode::SignAndEncrypt, the chunk must be encrypted.
  // Current implementation rejects ill-formed (non-block-aligned) ciphertext before attempting crypto.

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>();
  ctx->boundStrand = std::move(strand);
  ctx->state = SecureChannelContext::State::Open;
  ctx->securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ctx->secureChannelId = 1;
  ctx->encodingLimits = test_limits();
  ctx->lastRxSequenceNumber = std::nullopt;

  SecurityToken::Keys keys;
  keys.signingKey.resize(32);
  keys.encryptingKey.resize(32);
  keys.initializationVector.resize(16);
  ctx->activeSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx->boundStrand, keys, keys, /*id*/ 10, 10s);

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // Build a non-encrypted chunk (sequence header + 1 byte body) which is not a multiple of AES block size.
  const std::array<byte, 1> body{std::byte{0xAB}};
  auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
    /*secureChannelId*/ 1,
    /*tokenId*/ 10,
    /*sequenceNumber*/ 1,
    /*requestId*/ 1,
    body);

  expect_runtime_exception_status([&]() { (void)decode_chunk_sync(policy, ctx, std::move(chunk)).value(); },
    Status::BadSecurityChecksFailed);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// ECC Security Policy Tests
// ---------------------------------------------------------------------------

#include "ua_sec_pol_ephemeral_key.h"

// ===== Per-Message IV Construction ==========================================

// Part 6 6.8.1 Table 69: the first 8 bytes of the base IV are XORed with TokenId and LastSequenceNumber,
// each a little-endian UInt32; the rest of the IV is unchanged. Owner ruling D-12 (2026-10-13) replaced
// the earlier expectation that the two values overwrite those bytes.
TEST(EccSecurityPolicyTests, ConstructPerMessageIvXorsTheFirstEightBytes)
{
  // Base IV: 16 bytes with a recognizable pattern.
  ByteString baseIv(16, uint8_t{0xAA});

  const uint32_t tokenId = 0x04030201;
  const uint32_t lastSequenceNumber = 0x08070605;

  auto iv = SecPolEphemeralKey::construct_per_message_iv(baseIv, tokenId, lastSequenceNumber);

  ASSERT_EQ(iv.size(), 16u);

  // First 4 bytes: 0xAA XOR tokenId in little-endian.
  EXPECT_EQ(iv[0], uint8_t{0xAA ^ 0x01});
  EXPECT_EQ(iv[1], uint8_t{0xAA ^ 0x02});
  EXPECT_EQ(iv[2], uint8_t{0xAA ^ 0x03});
  EXPECT_EQ(iv[3], uint8_t{0xAA ^ 0x04});

  // Next 4 bytes: 0xAA XOR lastSequenceNumber in little-endian.
  EXPECT_EQ(iv[4], uint8_t{0xAA ^ 0x05});
  EXPECT_EQ(iv[5], uint8_t{0xAA ^ 0x06});
  EXPECT_EQ(iv[6], uint8_t{0xAA ^ 0x07});
  EXPECT_EQ(iv[7], uint8_t{0xAA ^ 0x08});

  // Remaining bytes are unchanged.
  for (size_t i = 8; i < 16; ++i)
  {
    EXPECT_EQ(iv[i], uint8_t{0xAA}) << "Byte at index " << i << " should be unchanged";
  }
}

// As above for the 12-byte IV of the AEAD ciphers. Owner ruling D-12 (2026-10-13).
TEST(EccSecurityPolicyTests, ConstructPerMessageIvWithChaCha20NonceSize)
{
  // ChaCha20 uses 12-byte nonces.
  ByteString baseIv(12, uint8_t{0xBB});

  auto iv = SecPolEphemeralKey::construct_per_message_iv(baseIv, 1, 2);

  ASSERT_EQ(iv.size(), 12u);

  // Token ID = 1 LE, XORed.
  EXPECT_EQ(iv[0], uint8_t{0xBB ^ 0x01});
  EXPECT_EQ(iv[1], uint8_t{0xBB});
  EXPECT_EQ(iv[2], uint8_t{0xBB});
  EXPECT_EQ(iv[3], uint8_t{0xBB});

  // Last sequence number = 2 LE, XORed.
  EXPECT_EQ(iv[4], uint8_t{0xBB ^ 0x02});
  EXPECT_EQ(iv[5], uint8_t{0xBB});
  EXPECT_EQ(iv[6], uint8_t{0xBB});
  EXPECT_EQ(iv[7], uint8_t{0xBB});

  // Remaining 4 bytes unchanged.
  for (size_t i = 8; i < 12; ++i)
  {
    EXPECT_EQ(iv[i], uint8_t{0xBB});
  }
}

TEST(UascSecurityPolicyTests, AbortChunkAfterIntermediateDecodesErrorFromAbortChunkOwnBody)
{
  // Requirement: P6-67-0017 (abort chunk IsFinal='A'); CL-UASC-019.
  // Part 6 6.7.3: an abort chunk aborts the in-flight request, DISCARDS the previously accumulated chunks,
  // and its OWN body carries {Error, Reason}. This interrupts a multi-chunk message with an abort and proves
  // the reported Error comes from the ABORT CHUNK'S OWN body, not from the accumulated intermediate bytes.
  // The intermediate chunk carries a 4-byte DECOY status; if the finalizer decoded the Error from the
  // accumulated buffer it would report that decoy, so asserting the real abort status is falsifiable against
  // both the original silent-drop bug AND the accumulated-buffer bug.

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  const StatusCode decoyStatus{Status::BadInternalError};  // must NOT be reported
  const StatusCode abortError{Status::BadTimeout};  // the real abort Error, from the abort chunk's own body

  // Intermediate chunk whose body is the 4-byte encoding of the decoy status (a red herring for the abort
  // decode: reading the accumulated buffer would surface this instead of the real abort Error).
  {
    memory_stream_device::Dynamic decoyDev{16, true};
    MemoryStream decoyStream{decoyDev};
    UaBinaryEncoder decoyEnc(CodecNamespaceContext{}, decoyStream);
    decoyEnc.encode(test_limits().stack_depth(), decoyStatus.value());
    auto decoyBody = decoyDev.move_storage_out();
    decoyBody.resize(decoyStream.get_position());

    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Intermediate,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 42,
      span<const byte>{decoyBody});

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    EXPECT_FALSE(decoded.has_value());
  }

  ASSERT_EQ(ctx->receivedMessageBody.size(), sizeof(uint32_t));

  // Abort chunk with a well-formed Table 56 body {Error, Reason}.
  {
    memory_stream_device::Dynamic abortDev{64, true};
    MemoryStream abortStream{abortDev};
    UaBinaryEncoder abortEnc(CodecNamespaceContext{}, abortStream);
    abortEnc.encode(test_limits().stack_depth(), abortError.value());
    abortEnc.encode(test_limits().stack_depth(), String{"server aborted after partial send"});
    auto abortBody = abortDev.move_storage_out();
    abortBody.resize(abortStream.get_position());

    auto chunk = build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Aborted,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 2,
      /*requestId*/ 42,
      span<const byte>{abortBody});

    auto decoded = decode_chunk_sync(policy, ctx, std::move(chunk)).value();
    EXPECT_FALSE(decoded.has_value());
  }

  // The accumulated intermediate body is discarded, and the abort Error is decoded from the abort chunk's
  // OWN body (BadTimeout) - NOT the decoy (BadInternalError) that the accumulated buffer would have yielded.
  EXPECT_TRUE(ctx->receivedMessageBody.empty());
  ASSERT_TRUE(ctx->receivedAbort.has_value());
  EXPECT_EQ(ctx->receivedAbort->first, 42u);
  EXPECT_EQ(ctx->receivedAbort->second, abortError)
    << "abort Error must come from the abort chunk's own body";
  EXPECT_NE(ctx->receivedAbort->second, decoyStatus) << "must not decode the Error from the accumulated body";
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Symmetric-encode abort emission (CL-UASC-017 / CL-UASC-018 / CL-TCP-011).
// ---------------------------------------------------------------------------

namespace
{

// Surfaces the protected encode_symmetric_message_async so a unit test can drive the symmetric-encode
// path directly through a subclass. Constructed via
// make_shared so enable_shared_from_this is satisfied inside the encode flow.
struct EncodeSymmetricAccess final : public SecPolBasic256Sha256
{
  using SecPolBasic256Sha256::encode_symmetric_message_async;
};

// Builds an Open Basic256Sha256 SecureChannelContext in Sign mode (authenticated, not encrypted) with an
// active token carrying HMAC signing keys and a small negotiated send buffer. Mirrors
// make_minimal_context_open_none but for a signing policy so the symmetric-encode abort path - a
// mid-stream sign failure that has already emitted >=1 chunk - is reachable. Kept local so the shared
// None harness stays untouched.
static SecureChannelContext make_minimal_context_open_sign(
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> crypto,
  uint32_t secureChannelId, uint32_t activeTokenId, uint32_t sendBufferSize)
{
  SecureChannelContext ctx;
  ctx.boundStrand = std::move(strand);
  ctx.state = SecureChannelContext::State::Open;
  ctx.securityPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ctx.messageSecurityMode = MessageSecurityMode::Sign;
  ctx.secureChannelId = secureChannelId;
  ctx.encodingLimits = test_limits();
  ctx.crypto = std::move(crypto);
  ctx.lastRxSequenceNumber = std::nullopt;
  ctx.negotiatedLimits.sendBufferSize = sendBufferSize;

  SecurityToken::Keys keys;
  keys.signingKey.resize(32, uint8_t{0x2B});
  keys.encryptingKey.resize(32, uint8_t{0x2B});
  keys.initializationVector.resize(16, uint8_t{0x2B});
  ctx.activeSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx.boundStrand, keys, keys, activeTokenId, 10s);

  return ctx;
}

// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, TheSenderRefusesToReuseASequenceNumberUnderOneToken)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto ctx = std::make_shared<SecureChannelContext>(make_minimal_context_open_sign(strand,
    create_crypto(),
    /*secureChannelId*/ 1,
    /*activeTokenId*/ 10,
    /*sendBufferSize*/ 8192));
  ctx->lastTxSequenceNumber = 4;  // the next number sent is 5...
  ctx->txUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u};  // ...where token 10 began

  auto policy = std::make_shared<EncodeSymmetricAccess>();
  std::vector<byte> body(16, byte{0x5A});
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    chunks.push_back(std::move(chunk));
  };
  auto result = test_helpers::run_async_callback_sync<VoidResult>([&](auto cb)
    { policy->encode_symmetric_message_async(*ctx, 1, span<const byte>{body}, sink, std::move(cb)); });
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSequenceNumberInvalid);
  EXPECT_TRUE(detail_chain_names(result.error_detail(), "SequenceNumberReusedUnderToken"));
  EXPECT_TRUE(chunks.empty()) << "the reusing chunk is never produced";

  // Control: one number earlier is an ordinary send.
  ctx->lastTxSequenceNumber = 3;
  auto ok = test_helpers::run_async_callback_sync<VoidResult>([&](auto cb)
    { policy->encode_symmetric_message_async(*ctx, 2, span<const byte>{body}, sink, std::move(cb)); });
  EXPECT_TRUE(ok.is_good());
  EXPECT_EQ(chunks.size(), 1u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// An Open ECC symmetric context (SignAndEncrypt) whose token keys are filled with `keyFill`, so two
// contexts built with the same fill share keys and one can decode what the other encodes.
static SecureChannelContext make_ecc_symmetric_context(
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> crypto,
  SecurityPolicyId policyId, uint32_t activeTokenId, uint8_t keyFill)
{
  SecureChannelContext ctx;
  ctx.boundStrand = std::move(strand);
  ctx.state = SecureChannelContext::State::Open;
  ctx.securityPolicy = SecurityPolicy::create(policyId);
  ctx.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ctx.secureChannelId = 1;
  ctx.encodingLimits = test_limits();
  ctx.crypto = std::move(crypto);
  ctx.initialise_sequence_numbers(ctx.securityPolicy->uses_legacy_sequence_no());
  ctx.negotiatedLimits.sendBufferSize = 8192;
  ctx.negotiatedLimits.receiveBufferSize = 65536;
  SecurityToken::Keys keys;
  keys.signingKey.resize(ctx.securityPolicy->symmetric_signature_key_size(), keyFill);
  keys.encryptingKey.resize(ctx.securityPolicy->symmetric_encryption_key_size(), keyFill);
  keys.initializationVector.resize(ctx.securityPolicy->symmetric_iv_size(), keyFill);
  ctx.activeSecurityToken =
    std::make_unique<TestSecurityToken>(*ctx.boundStrand, keys, keys, activeTokenId, 10s);
  return ctx;
}

/// Encodes one body through the policy's own symmetric encode; returns the chunks and the completion.
static std::pair<std::vector<ByteString>, VoidResult> encode_symmetric_body(
  SecureChannelContext& ctx, uint32_t requestId, span<const byte> body)
{
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    chunks.push_back(std::move(chunk));
  };
  auto result = test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb)
    {
      test_access::SymmetricEncodeDriver::encode(
        *ctx.securityPolicy, ctx, requestId, body, sink, std::move(cb));
    });
  return {std::move(chunks), std::move(result)};
}

// The CRY-4 rule on the ephemeral-key receive path (both AEAD ciphers), which carries its own decode
// operation: a chunk the peer encoded under the shared keys with the number the token began on is refused as
// a reuse, and accepted when the record belongs to another token.
static void ecc_receive_refuses_reuse(SecurityPolicyId policyId)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  const std::vector<byte> body(24, byte{0x5A});

  auto encoder =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 10, 0x2B));
  encoder->lastTxSequenceNumber = 4;  // the chunk carries 5
  auto [chunks, encoded] = encode_symmetric_body(*encoder, 1, span<const byte>{body});
  ASSERT_TRUE(encoded.is_good());
  ASSERT_EQ(chunks.size(), 1u);

  auto receiver =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 10, 0x2B));
  receiver->lastRxSequenceNumber = 4;
  receiver->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u, .lastSequenceNumber = 5u};
  auto refused = decode_chunk_sync(receiver->securityPolicy, receiver, chunks.front());
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSequenceNumberInvalid);
  ASSERT_NE(refused.error_detail(), nullptr);
  EXPECT_EQ(refused.error_detail()->code, "SequenceNumberReusedUnderToken");

  // Control: the record belongs to another token, so 5 is this token's first number.
  auto fresh =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 10, 0x2B));
  fresh->lastRxSequenceNumber = 4;
  fresh->rxUseUnderToken = {.tokenId = 9u, .firstSequenceNumber = 5u, .lastSequenceNumber = 5u};
  auto accepted = decode_chunk_sync(fresh->securityPolicy, fresh, chunks.front());
  ASSERT_TRUE(accepted.is_good()) << to_string(accepted.status_code().as_status());
  EXPECT_TRUE(accepted.value().has_value());
  encoder.reset();
  receiver.reset();
  fresh.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The CRY-4 rule on the ECC send paths: the encode fails and produces no chunk.
static void ecc_sender_refuses_reuse(SecurityPolicyId policyId)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto ctx = std::make_shared<SecureChannelContext>(
    make_ecc_symmetric_context(strand, create_crypto(), policyId, 10, 0x2B));
  ctx->lastTxSequenceNumber = 4;
  ctx->txUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u, .lastSequenceNumber = 5u};
  const std::vector<byte> body(24, byte{0x5A});
  auto [chunks, result] = encode_symmetric_body(*ctx, 1, span<const byte>{body});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSequenceNumberInvalid);
  EXPECT_TRUE(detail_chain_names(result.error_detail(), "SequenceNumberReusedUnderToken"));
  EXPECT_TRUE(chunks.empty());
  ctx->lastTxSequenceNumber = 3;  // control: an ordinary send
  auto [okChunks, ok] = encode_symmetric_body(*ctx, 2, span<const byte>{body});
  EXPECT_TRUE(ok.is_good());
  EXPECT_EQ(okChunks.size(), 1u);
  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// H-D5 on the ECC paths: a chunk under the pending token whose keys do not verify it leaves the
// active token active and the pending token pending.
static void ecc_refused_pending_chunk_leaves_tokens(SecurityPolicyId policyId, Status refusal)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  auto crypto = create_crypto();
  const std::vector<byte> body(24, byte{0x5A});

  // Encoded under token 11 with keys the receiver's pending token 11 does not hold.
  auto forger =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 11, 0x5C));
  auto [chunks, encoded] = encode_symmetric_body(*forger, 1, span<const byte>{body});
  ASSERT_TRUE(encoded.is_good());
  ASSERT_EQ(chunks.size(), 1u);

  auto receiver =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 10, 0x2B));
  SecurityToken::Keys pendingKeys = receiver->activeSecurityToken->local_keys();
  receiver->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*receiver->boundStrand, pendingKeys, pendingKeys, /*id*/ 11, 10s);
  auto refused = decode_chunk_sync(receiver->securityPolicy, receiver, chunks.front());
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), refusal) << "the path's own tag or MAC failure";
  ASSERT_NE(receiver->activeSecurityToken, nullptr);
  EXPECT_EQ(receiver->activeSecurityToken->id(), 10u)
    << "the refused chunk must not have promoted the pending token";
  ASSERT_NE(receiver->pendingSecurityToken, nullptr);
  EXPECT_EQ(receiver->pendingSecurityToken->id(), 11u);

  // Control: a chunk under token 11 encoded with the pending token's keys is accepted and promotes it.
  auto peer =
    std::make_shared<SecureChannelContext>(make_ecc_symmetric_context(strand, crypto, policyId, 11, 0x2B));
  auto [goodChunks, goodEncode] = encode_symmetric_body(*peer, 2, span<const byte>{body});
  ASSERT_TRUE(goodEncode.is_good());
  ASSERT_EQ(goodChunks.size(), 1u);
  auto accepted = decode_chunk_sync(receiver->securityPolicy, receiver, goodChunks.front());
  ASSERT_TRUE(accepted.is_good()) << to_string(accepted.status_code().as_status());
  ASSERT_NE(receiver->activeSecurityToken, nullptr);
  EXPECT_EQ(receiver->activeSecurityToken->id(), 11u) << "an accepted chunk promotes the pending token";
  EXPECT_EQ(receiver->pendingSecurityToken, nullptr);
  forger.reset();
  peer.reset();
  receiver.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, AReuseIsRefusedOnTheEccAeadReceivePath)
{
  ecc_receive_refuses_reuse(SecurityPolicyId::EccCurve25519ChaChaPoly);
}

// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, AReuseIsRefusedOnTheAesGcmReceivePath)
{
  ecc_receive_refuses_reuse(SecurityPolicyId::EccNistP256AesGcm);
}

// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, TheSenderRefusesAReuseOnTheEccAeadPath)
{
  ecc_sender_refuses_reuse(SecurityPolicyId::EccCurve25519ChaChaPoly);
}

// @verifies AC-SVR-UASC-012-SEQUENCE-NUMBER-IS-NOT-REUSED-UNDER-ONE-TOKEN
TEST(UascSecurityPolicyTests, TheSenderRefusesAReuseOnTheAesGcmPath)
{
  ecc_sender_refuses_reuse(SecurityPolicyId::EccNistP256AesGcm);
}

// @verifies AC-SVR-SC-013-PENDING-TOKEN-PROMOTED-ONLY-BY-AN-ACCEPTED-CHUNK
TEST(UascSecurityPolicyTests, AChunkRefusedUnderThePendingTokenLeavesBothTokensAsTheyWereOnTheEccAeadPath)
{
  // The AEAD path reports a failed tag as Bad_SecurityChecksFailed.
  ecc_refused_pending_chunk_leaves_tokens(
    SecurityPolicyId::EccCurve25519ChaChaPoly, Status::BadSecurityChecksFailed);
}

// @verifies AC-SVR-SC-013-PENDING-TOKEN-PROMOTED-ONLY-BY-AN-ACCEPTED-CHUNK
TEST(UascSecurityPolicyTests, AChunkRefusedUnderThePendingTokenLeavesBothTokensAsTheyWereOnTheAesGcmPath)
{
  // The AES-GCM twin of the ChaCha20-Poly1305 case: a failed tag is Bad_SecurityChecksFailed. (The
  // pre-1.05.07 twin drove the AES-CBC path, which reported a failed MAC as Bad_ApplicationSignatureInvalid;
  // that path is removed with the deprecated ECC policies.)
  ecc_refused_pending_chunk_leaves_tokens(
    SecurityPolicyId::EccNistP256AesGcm, Status::BadSecurityChecksFailed);
}

// A Basic256Sha256 Sign-mode receiver with active token 10 (keys 0x2B, as the sender's) and pending token 11
// (keys 0x5C) on @p crypto: the shape both tests below change while a chunk is in flight.
static std::shared_ptr<SecureChannelContext> make_renewing_sign_receiver(
  boost::asio::strand<boost::asio::any_io_executor> strand, std::shared_ptr<const Crypto> crypto)
{
  auto receiver = std::make_shared<SecureChannelContext>(make_minimal_context_open_sign(std::move(strand),
    std::move(crypto),
    /*secureChannelId*/ 1,
    /*activeTokenId*/ 10,
    /*sendBufferSize*/ 8192));
  receiver->lastRxSequenceNumber = 4;
  SecurityToken::Keys renewed;
  renewed.signingKey.resize(32, uint8_t{0x5C});
  renewed.encryptingKey.resize(32, uint8_t{0x5C});
  renewed.initializationVector.resize(16, uint8_t{0x5C});
  receiver->pendingSecurityToken =
    std::make_unique<TestSecurityToken>(*receiver->boundStrand, renewed, renewed, /*id*/ 11, 10s);
  return receiver;
}

// One Sign-mode chunk numbered 5 under token 10, encoded by the policy with the keys token 10 holds.
static ByteString sign_chunk_under_token_10(boost::asio::strand<boost::asio::any_io_executor> strand)
{
  auto sender = std::make_shared<SecureChannelContext>(make_minimal_context_open_sign(std::move(strand),
    create_crypto(),
    /*secureChannelId*/ 1,
    /*activeTokenId*/ 10,
    /*sendBufferSize*/ 8192));
  sender->lastTxSequenceNumber = 4;  // the chunk carries 5
  const std::vector<byte> body(16, byte{0x5A});
  auto [chunks, encoded] = encode_symmetric_body(*sender, 1, span<const byte>{body});
  EXPECT_TRUE(encoded.is_good());
  EXPECT_EQ(chunks.size(), 1u);
  return chunks.empty() ? ByteString{} : chunks.front();
}

// The generic receive path verifies a chunk with the keys of the token its TokenId selected: here the active
// and pending tokens trade places after the selection and before the decode operation runs, so the token the
// chunk selected (10) is pending by then. The chunk is accepted and its number recorded under token 10.
// @verifies AC-SVR-UASC-012-SELECTED-TOKEN-ACROSS-A-RENEWAL
TEST(UascSecurityPolicyTests, TheGenericReceivePathVerifiesWithTheTokenTheChunkSelected)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  const auto chunk = sign_chunk_under_token_10(strand);
  ASSERT_FALSE(chunk.empty());
  auto receiver = make_renewing_sign_receiver(strand, create_crypto());

  auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
  auto future = completion->get_future();
  boost::asio::post(receiver->strand(),
    [receiver, chunk, completion]
    {
      // Queued ahead of the decode operation, which the selection below launches onto the same strand.
      boost::asio::post(receiver->strand(),
        [receiver] { std::swap(receiver->activeSecurityToken, receiver->pendingSecurityToken); });
      receiver->securityPolicy->decode_message_chunk_async(
        receiver, chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code().as_status());
  EXPECT_TRUE(result.value().has_value());
  EXPECT_EQ(receiver->rxUseUnderToken.tokenId, 10u);
  receiver.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// A number token 10 already began on is refused under token 10 even when token 11 is promoted while the
// signature verification is in flight: the record follows the TokenId on the wire, not whichever token is
// active when the verification completes.
// @verifies AC-SVR-UASC-012-SELECTED-TOKEN-ACROSS-A-RENEWAL
TEST(UascSecurityPolicyTests, AReuseIsRefusedUnderTheSelectedTokenWhenARenewalLandsMidVerification)
{
  boost::asio::thread_pool tp;
  auto strand = boost::asio::make_strand(tp.get_executor());
  const auto chunk = sign_chunk_under_token_10(strand);
  ASSERT_FALSE(chunk.empty());
  const auto fake = test_helpers::FakeAsyncCrypto::create();
  fake->set_park_async(true);
  auto receiver = make_renewing_sign_receiver(strand, fake);
  receiver->rxUseUnderToken = {.tokenId = 10u, .firstSequenceNumber = 5u, .lastSequenceNumber = 5u};

  auto completion = std::make_shared<std::promise<DecodedMessageChunkResult>>();
  auto future = completion->get_future();
  boost::asio::post(receiver->strand(),
    [receiver, chunk, completion]
    {
      receiver->securityPolicy->decode_message_chunk_async(
        receiver, chunk, [completion](auto result) { completion->set_value(std::move(result)); });
    });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (fake->pending_symmetric_verify_count() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::yield();
  ASSERT_EQ(fake->pending_symmetric_verify_count(), 1u);
  boost::asio::post(receiver->strand(),
    [receiver, fake]
    {
      receiver->activeSecurityToken = std::move(receiver->pendingSecurityToken);
      fake->set_park_async(false);
      fake->complete_pending_symmetric_verify(0, VoidResult{});  // the signature is valid
    });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
  const auto result = future.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSequenceNumberInvalid);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "SequenceNumberReusedUnderToken");
  EXPECT_EQ(receiver->rxUseUnderToken.tokenId, 10u);
  receiver.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Decodes only the IsFinal flag from a symmetric chunk's UaScMessageHeader.
static stack_utils::UaScMessageHeader::IsFinal decode_chunk_is_final(const ByteString& chunk)
{
  memory_stream_device::ExternalReadOnly streamDevice{span<const byte>{chunk}};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);

  stack_utils::UaScMessageHeader header;
  header.decode(limits, dec);
  return header.isFinal;
}

struct DecodedAbortChunk
{
  stack_utils::UaScMessageHeader::IsFinal isFinal{};
  uint32_t requestId{0};
  StatusCode error;
  std::string reason;
};

// Decodes a symmetric abort chunk's headers plus its Table 56 body {Error UInt32, Reason String}. The
// trailing signature (signing policies) is ignored: the String decode consumes exactly its length prefix.
static DecodedAbortChunk decode_abort_chunk(const ByteString& chunk)
{
  memory_stream_device::ExternalReadOnly streamDevice{span<const byte>{chunk}};
  MemoryStream stream{streamDevice};
  StructureFactory factory;
  auto limits = test_limits();
  UaBinaryDecoder dec(factory.resolver(), stream, limits);
  const auto depth = limits.stack_depth();

  stack_utils::UaScMessageHeader header;
  header.decode(limits, dec);

  stack_utils::SymmetricSecurityHeader securityHeader;
  securityHeader.decode(limits, dec);

  stack_utils::SequenceHeader sequenceHeader;
  sequenceHeader.decode(limits, dec);

  uint32_t error{0};
  dec.decode(depth, error);
  std::string reason;
  dec.decode(depth, reason);

  DecodedAbortChunk out;
  out.isFinal = header.isFinal;
  out.requestId = sequenceHeader.requestId;
  out.error = StatusCode{error};
  out.reason = std::move(reason);
  return out;
}

}  // namespace

// A mid-stream symmetric SIGN failure - after at least one chunk has already been signed and handed to
// the transport - must emit a terminal ABORT chunk (IsFinal='A', Part 6 6.7.3) carrying {Error, Reason}
// for the same RequestId, then complete the encode bad with that Error. A 500-byte body over a 256-byte
// send buffer needs three Sign-mode chunks; the FakeAsyncCrypto signs chunk #0 successfully (so
// chunksSent>=1) then fails chunk #1's sign. Falsifiable: without the mid-stream abort emission the last
// captured chunk would not be Aborted, and without carrying the deferred error the completion would be
// Good.
//
// @verifies CL-UASC-017
// @verifies CL-TCP-011
// @relation(CL-TCP-011, CL-UASC-017, scope=function)
TEST(UascSecurityPolicyTests, EncodeSymmetricEmitsAbortChunkOnMidStreamSignFailure)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto fake = test_helpers::FakeAsyncCrypto::create();
  // Chunk #0 signs (call 0), chunk #1's sign (call 1) fails.
  fake->fail_nth_symmetric_sign(1, ua::StatusCode{Status::BadApplicationSignatureInvalid});

  auto ctx = std::make_shared<SecureChannelContext>(make_minimal_context_open_sign(strand,
    fake,
    /*secureChannelId*/ 1,
    /*activeTokenId*/ 10,
    /*sendBufferSize*/ 256));

  auto policy = std::make_shared<EncodeSymmetricAccess>();

  constexpr uint32_t requestId = 8899;
  std::vector<byte> body(500, byte{0x5A});

  std::mutex chunkMutex;
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    std::lock_guard<std::mutex> lock(chunkMutex);
    chunks.push_back(std::move(chunk));
  };

  auto result = test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) {
      policy->encode_symmetric_message_async(*ctx, requestId, span<const byte>{body}, sink, std::move(cb));
    });

  // The completion carries the deferred sign error (not Good).
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadApplicationSignatureInvalid});

  std::lock_guard<std::mutex> lock(chunkMutex);
  ASSERT_GE(chunks.size(), 2u)
    << "chunk #0 must have been signed and sent before the failure, then a terminal abort chunk emitted";

  // The first emitted chunk proves chunksSent>=1 (an intermediate, non-abort chunk).
  EXPECT_EQ(decode_chunk_is_final(chunks.front()), stack_utils::UaScMessageHeader::IsFinal::Intermediate);

  // The last emitted chunk is the abort chunk that fails exactly this request.
  auto abortChunk = decode_abort_chunk(chunks.back());
  EXPECT_EQ(abortChunk.isFinal, stack_utils::UaScMessageHeader::IsFinal::Aborted);
  EXPECT_EQ(abortChunk.error, StatusCode{Status::BadApplicationSignatureInvalid});
  EXPECT_FALSE(abortChunk.reason.empty());
  EXPECT_EQ(abortChunk.requestId, requestId);

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// When the FIRST chunk's sign fails (chunksSent==0), no abort chunk may be emitted - nothing has yet gone
// to the transport, so there is no in-flight request on the wire to abort. The encode still completes bad.
// Pins the `chunksSent == 0` guard in handle_encode_symmetric_deferred_error: deleting it would emit an
// Aborted chunk here, turning this test RED.
//
// @verifies CL-UASC-017
// @relation(CL-UASC-017, scope=function)
TEST(UascSecurityPolicyTests, EncodeSymmetricNoAbortChunkWhenFirstChunkFails)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto fake = test_helpers::FakeAsyncCrypto::create();
  // Fail the FIRST sign (call 0) so no chunk is ever sent.
  fake->fail_nth_symmetric_sign(0, ua::StatusCode{Status::BadApplicationSignatureInvalid});

  auto ctx = std::make_shared<SecureChannelContext>(make_minimal_context_open_sign(strand,
    fake,
    /*secureChannelId*/ 1,
    /*activeTokenId*/ 10,
    /*sendBufferSize*/ 256));

  auto policy = std::make_shared<EncodeSymmetricAccess>();

  constexpr uint32_t requestId = 8900;
  std::vector<byte> body(500, byte{0x5A});

  std::mutex chunkMutex;
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    std::lock_guard<std::mutex> lock(chunkMutex);
    chunks.push_back(std::move(chunk));
  };

  auto result = test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb) {
      policy->encode_symmetric_message_async(*ctx, requestId, span<const byte>{body}, sink, std::move(cb));
    });

  EXPECT_TRUE(result.is_bad());

  std::lock_guard<std::mutex> lock(chunkMutex);
  for (const auto& chunk : chunks)
  {
    EXPECT_NE(decode_chunk_is_final(chunk), stack_utils::UaScMessageHeader::IsFinal::Aborted)
      << "no abort chunk may be emitted when the first chunk's sign fails (chunksSent==0)";
  }

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// P6-67-0018: an abort chunk's Reason string must be clamped to 4096 bytes. The natural encode-abort path
// only ever produces short internal literals, so this drives the real abort flow through the test interface
// with a caller-seeded 5000-byte reason. Falsifiable: deleting the clamp encodes the full 5000 bytes.
//
// @verifies CL-UASC-018
// @relation(CL-UASC-018, scope=function)
TEST(UascSecurityPolicyTests, AbortReasonClampedTo4096Bytes)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto strand = boost::asio::make_strand(ex);

  auto ctx = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, strand, /*secureChannelId*/ 1, /*activeTokenId*/ 10));
  auto policy = SecurityPolicy::create(SecurityPolicyId::None);

  constexpr uint32_t requestId = 7;

  std::mutex chunkMutex;
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    std::lock_guard<std::mutex> lock(chunkMutex);
    chunks.push_back(std::move(chunk));
  };

  auto result = test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb)
    {
      ua::test_access::start_symmetric_abort_with_reason(policy,
        *ctx,
        requestId,
        Status::BadTcpMessageTooLarge,
        std::string(5000, 'X'),
        sink,
        /*maxChunkSize*/ 8192,
        std::move(cb));
    });
  (void)result;

  std::lock_guard<std::mutex> lock(chunkMutex);
  ASSERT_EQ(chunks.size(), 1u) << "the abort flow emits exactly one abort chunk";

  auto abortChunk = decode_abort_chunk(chunks.front());
  EXPECT_EQ(abortChunk.isFinal, stack_utils::UaScMessageHeader::IsFinal::Aborted);
  EXPECT_EQ(abortChunk.error, StatusCode{Status::BadTcpMessageTooLarge});
  EXPECT_FALSE(abortChunk.reason.empty());
  EXPECT_EQ(abortChunk.reason.size(), 4096u)
    << "abort reason must be clamped to 4096 bytes (was seeded with 5000)";

  ctx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// SVR-UASC-038 - the discard of an out-of-order SequenceNumber must reach the log.
// ---------------------------------------------------------------------------
//
// The framer (SecurityPolicy) only THROWS Bad_SequenceNumberInvalid; the record of the discard is
// written by the owning SecureChannel, so this section drives the wire path end to end - fake
// transport -> real ConnectionProtocol -> real server SecureChannel -> real SecurityPolicy decode -
// with a sink installed on the channel's own logger.

#include "fake_connection_protocol_deps.h"
#include "fake_secure_channel_dependencies.h"
#include "fake_transport_connection.h"

#include "ua_connection_protocol.h"
#include "ua_log_entry.h"
#include "ua_log_format.h"
#include "ua_log_sink.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"

#include <condition_variable>
#include <string>
#include <vector>

namespace
{

using ChannelAccess = ::ua::server::SecureChannelTestAccess;
using ServerChannelDeps = ::ua::test::behaviour_pins::phase_4_7::FakeSecureChannelDependencies;

/// A LogSink that retains every rendered line so a test can assert on what the channel LOGGED,
/// rather than only on what it returned. Rendering goes through the same `format_log_line` the
/// production console/file sinks use, so a structured field is observed exactly as an operator
/// would see it.
class RecordingLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    auto line = ::ua::detail::format_log_line(entry);
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      mLines.push_back(std::move(line));
    }
    mCv.notify_all();
  }

  /// Blocks until some retained line contains @p needle, or @p timeout elapses.
  bool wait_for_line_containing(const std::string& needle, std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock{mMutex};
    return mCv.wait_for(lock, timeout, [&]() { return contains_locked(needle); });
  }

  std::vector<std::string> lines() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mLines;
  }

  std::string text() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    std::string out;
    for (const auto& line : mLines)
    {
      out += line;
    }
    return out;
  }

private:
  bool contains_locked(const std::string& needle) const
  {
    for (const auto& line : mLines)
    {
      if (line.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }

  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::string> mLines;
};

/// Encodes a HELF message so the fake transport can drive a real HEL/ACK handshake.
static std::vector<byte> build_hello_message(
  uint32_t receiveBufferSize, uint32_t sendBufferSize, std::string endpointUrl)
{
  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::maxUrlSize + 128, true};
  MemoryStream stream{streamDevice};
  UaBinaryEncoder enc(CodecNamespaceContext{}, stream);
  auto limit = test_limits().stack_depth();

  enc.encode(limit, uint8_t{'H'});
  enc.encode(limit, uint8_t{'E'});
  enc.encode(limit, uint8_t{'L'});
  enc.encode(limit, uint8_t{'F'});

  const size_t sizePos = stream.get_position();
  enc.encode(limit, uint32_t{0});  // MessageSize, patched below

  enc.encode(limit, uint32_t{0});  // ProtocolVersion
  enc.encode(limit, receiveBufferSize);
  enc.encode(limit, sendBufferSize);
  enc.encode(limit, uint32_t{0});  // MaxMessageSize
  enc.encode(limit, uint32_t{0});  // MaxChunkCount
  enc.encode(limit, endpointUrl);

  const auto msgSize = static_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePos);
  enc.encode(limit, msgSize);

  auto out = streamDevice.move_storage_out();
  out.resize(msgSize);
  return out;
}

/// Hands a fully framed UASC chunk to the fake transport the way the wire delivers it: the
/// 8-byte transport header first, then the remainder read at that offset.
static void deliver_chunk_over_transport(
  test_helpers::FakeTransportConnection& transport, const ByteString& chunk)
{
  constexpr auto headerSize = static_cast<std::ptrdiff_t>(ua::connection_protocol::headerSize);
  const span<const byte> bytes{chunk};
  std::vector<byte> header(bytes.begin(), bytes.begin() + headerSize);
  std::vector<byte> remainder(bytes.begin() + headerSize, bytes.end());
  transport.enqueue_read_exact(std::move(header));
  transport.enqueue_read_exact(std::move(remainder));
}

}  // namespace

// Part 6 6.7.5 (SVR-UASC-038): a chunk whose SequenceNumber breaks the "previous + 1" rule must be
// discarded, and because the discard is deliberately silent to the peer - what does go on the wire
// is a masked transport error carrying no reason - the structured log is the only place the event
// exists at all. A plausible implementation rejects the chunk purely inside the framer, returning a
// bad Result that the channel turns into a connection close without ever reaching a logging site,
// leaving an administrator no record that a reordered or replayed chunk was seen. Driven over a real
// ConnectionProtocol so the log entry comes from the production channel, not from the fixture: the
// first (intermediate) chunk legitimately advances the channel's sequence state, and only the second
// chunk violates it.
// @verifies AC-SVR-UASC-038-SEQUENCE-LOGGED
TEST(UascSecurityPolicyTests, InvalidSequenceNumberIsDiscardedAndLogged)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // Real ConnectionProtocol over a scriptable transport, so chunks enter the channel the way the
  // wire delivers them rather than through a test-only injection interface.
  auto cpDeps = std::make_shared<test_helpers::FakeConnectionProtocolDeps>(ex);
  cpDeps->set_server_limits(ua::connection_protocol::Limits{});
  auto transport = std::make_shared<test_helpers::FakeTransportConnection>();
  transport->enqueue_hello_message(build_hello_message(8192, 8192, "opc.tcp://127.0.0.1:4840"));

  std::mutex handshakeMutex;
  std::condition_variable handshakeCv;
  bool handshakeComplete{false};
  std::shared_ptr<ConnectionProtocol> cp;

  auto pending = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    cpDeps,
    transport,
    false,
    60s,
    [&](StatusCode status,
      std::shared_ptr<ConnectionProtocol>
        connection,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      EXPECT_TRUE(status.is_good());
      {
        std::lock_guard<std::mutex> lock{handshakeMutex};
        cp = std::move(connection);
        handshakeComplete = true;
      }
      handshakeCv.notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) { ADD_FAILURE() << "unexpected handshake error"; },
    {},
    [](string_view) { return true; });

  {
    std::unique_lock<std::mutex> lock{handshakeMutex};
    ASSERT_TRUE(handshakeCv.wait_for(lock, 2s, [&]() { return handshakeComplete; }));
  }
  ASSERT_NE(cp, nullptr);

  // The sink must be installed before the channel is created: the channel takes its logger from the
  // dependencies, and a null sink there would make the obligation unobservable for the wrong reason.
  auto sink = std::make_shared<RecordingLogSink>();
  auto deps = std::make_shared<ServerChannelDeps>(ex);
  deps->set_log_sink(sink);

  auto sc = ua::server::SecureChannel::create(
    deps, cp, ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");
  ASSERT_NE(sc, nullptr);

  // Open, policy None, one active token. lastRxSequenceNumber is left at its production default
  // (0), so the channel itself decides that the first acceptable SequenceNumber is 1 - the test does
  // not pre-set the condition it is about to observe.
  ChannelAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "L/None");
      auto& channelContext = *g.context();
      channelContext.state = SecureChannelContext::State::Open;
      channelContext.secureChannelId = 1;
      SecurityToken::Keys emptyKeys;
      channelContext.activeSecurityToken = std::make_unique<TestSecurityToken>(
        *channelContext.boundStrand, emptyKeys, emptyKeys, /*id*/ 10, 10s);
      g.channel_state() = ChannelAccess::ChannelState::Open;
    });

  // Chunk 1: a legitimate intermediate chunk (SequenceNumber 1) that the channel accepts and whose
  // single body byte it accumulates. This establishes the "previous" the next chunk must follow.
  const std::array<byte, 1> firstBody{std::byte{0x01}};
  deliver_chunk_over_transport(*transport,
    build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Intermediate,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 1,
      /*requestId*/ 77,
      firstBody));

  // Chunk 2: same message, same RequestId, but SequenceNumber 3 instead of 2. Its body carries a
  // marker so that "discarded" is falsifiable: an implementation that accumulated the chunk before
  // verifying the sequence header would leave the marker in the assembled body.
  const std::array<byte, 4> marker{std::byte{'M'}, std::byte{'A'}, std::byte{'R'}, std::byte{'K'}};
  deliver_chunk_over_transport(*transport,
    build_symmetric_chunk(stack_utils::UaScMessageHeader::IsFinal::Final,
      /*secureChannelId*/ 1,
      /*tokenId*/ 10,
      /*sequenceNumber*/ 3,
      /*requestId*/ 77,
      marker));

  const std::string expectedReason{"BadSequenceNumberInvalid"};
  EXPECT_TRUE(sink->wait_for_line_containing(expectedReason, 5s))
    << "the discard is silent to the peer, so nothing but the log records it; the channel logged:\n"
    << sink->text();

  // Non-vacuous: assert the sink actually holds entries before scanning them.
  const auto loggedLines = sink->lines();
  ASSERT_FALSE(loggedLines.empty()) << "the channel logged nothing at all for the discarded chunk";
  size_t linesNamingTheReason = 0;
  for (const auto& line : loggedLines)
  {
    if (line.find(expectedReason) != std::string::npos)
    {
      ++linesNamingTheReason;
    }
  }
  EXPECT_GE(linesNamingTheReason, 1u)
    << "the discard must be logged with Bad_SequenceNumberInvalid as the reason; the channel logged:\n"
    << sink->text();

  // ... and the chunk really was discarded, not merely reported: its body was never accumulated, and
  // the channel recorded the sequence violation as the reason it stopped serving this connection.
  ByteString accumulatedBody;
  StatusCode closeReason;
  ChannelAccess::on_strand(*sc,
    [&](auto& g)
    {
      accumulatedBody = g.context()->receivedMessageBody;
      closeReason = g.close_reason();
    });

  EXPECT_EQ(closeReason, StatusCode{Status::BadSequenceNumberInvalid})
    << "the sequence violation must be the recorded reason the channel stopped";
  ASSERT_EQ(accumulatedBody.size(), 1u)
    << "only the accepted intermediate chunk may contribute to the assembled body";
  EXPECT_EQ(accumulatedBody[0], uint8_t{0x01}) << "the out-of-order chunk's body must not be accumulated";

  sc.reset();
  cp.reset();
  pending.reset();
  transport.reset();
  cpDeps.reset();
  deps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// SVR-SC-025 - which session-less SecureChannel a server reclaims at its channel ceiling.
// ---------------------------------------------------------------------------
//
// The decision lives in the server (ServerImpl), not in the framer, so this section drives the real
// admission path: a real ServerImpl configured with a MaxSecureChannels ceiling, two real server
// SecureChannels each sitting on a real ConnectionProtocol over a scriptable transport, and a third
// connection arriving to force the reclaim.

#include "async_test_runtime.h"
#include "server_impl_test_access.h"

#include "ua_application_configuration.h"
#include "ua_get_endpoints_request.h"
#include "ua_server_impl.h"

#include <thread>

#include "test_components.h"

namespace
{

using ServerAccess = ::ua::test_helpers::ServerImplTestAccess;

/// A scriptable transport plus the real ConnectionProtocol that has completed a HEL/ACK handshake
/// over it, so a server SecureChannel built on top receives chunks the way the wire delivers them.
struct WiredConnection
{
  std::shared_ptr<test_helpers::FakeConnectionProtocolDeps> deps;
  std::shared_ptr<test_helpers::FakeTransportConnection> transport;
  std::shared_ptr<ConnectionProtocol> pending;
  std::shared_ptr<ConnectionProtocol> protocol;

  void reset()
  {
    protocol.reset();
    pending.reset();
    transport.reset();
    deps.reset();
  }
};

/// Drives a real HEL/ACK handshake to completion and returns the established ConnectionProtocol.
static WiredConnection make_wired_connection(boost::asio::any_io_executor ex)
{
  WiredConnection connection;
  connection.deps = std::make_shared<test_helpers::FakeConnectionProtocolDeps>(ex);
  connection.deps->set_server_limits(ua::connection_protocol::Limits{});
  connection.transport = std::make_shared<test_helpers::FakeTransportConnection>();
  connection.transport->enqueue_hello_message(build_hello_message(8192, 8192, "opc.tcp://127.0.0.1:4840"));

  auto mutex = std::make_shared<std::mutex>();
  auto cv = std::make_shared<std::condition_variable>();
  auto done = std::make_shared<bool>(false);
  auto established = std::make_shared<std::shared_ptr<ConnectionProtocol>>();

  connection.pending = ConnectionProtocol::create(
    ConnectionProtocolRole::Server,
    connection.deps,
    connection.transport,
    false,
    60s,
    [mutex, cv, done, established](StatusCode status,
      std::shared_ptr<ConnectionProtocol>
        establishedConnection,
      ua::connection_protocol::NegotiatedLimits,
      std::optional<ua::detail::ReverseHelloMessage>)
    {
      EXPECT_TRUE(status.is_good());
      {
        std::lock_guard<std::mutex> lock{*mutex};
        *established = std::move(establishedConnection);
        *done = true;
      }
      cv->notify_one();
    },
    [](StatusCode, string_view, ua::FatalCloseDisposition) {},
    {},
    [](string_view) { return true; });

  {
    std::unique_lock<std::mutex> lock{*mutex};
    cv->wait_for(lock, 2s, [&]() { return *done; });
  }
  connection.protocol = *established;
  return connection;
}

/// A real ServerImpl whose only binding admission limit is MaxSecureChannels, so the Part 4 5.5.2
/// reclaim path - and not the MaxConnections backstop - is what decides which channel survives.
static shared_ptr<ua::server::ServerImpl> make_server_with_channel_cap(
  boost::asio::any_io_executor ex, uint32_t maxSecureChannels)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig serverCfg;
  serverCfg.maxConnections = 16;
  serverCfg.maxSecureChannels = maxSecureChannels;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
    endpoint.securityPolicyId = ua::SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(endpoint));

    serverCfg.listeners().push_back(std::move(listener));
  }
  serverCfg.validate();
  frozen.server = std::move(serverCfg);

  auto server = ua::server::ServerImpl::create(
    ex, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  ServerAccess{*server}.initialise_listeners_from_config();
  return server;
}

/// Builds an Open, session-less, policy-None server channel on @p connection and registers it with
/// the server. Registration order is the caller's call order, which is the creation order the
/// reclaim must NOT use as its criterion.
static shared_ptr<ua::server::SecureChannel> add_open_sessionless_channel(ua::server::ServerImpl& server,
  boost::asio::any_io_executor ex, const WiredConnection& connection, uint32_t secureChannelId,
  uint32_t tokenId)
{
  auto deps = ServerAccess{server}.secure_channel_dependencies();
  auto sc = ua::server::SecureChannel::create(deps,
    connection.protocol,
    ua::connection_protocol::NegotiatedLimits{},
    ::ua::server::ListenerHandle{1},
    "TestListener");

  ChannelAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex, "TestListener/None");
      auto& channelContext = *g.context();
      // set_minimal_context_none installs a FRESH context, discarding the namespace resolver the
      // channel's constructor bound to the address space. Restore one: SecurityPolicy's outgoing
      // encode requires a resolver up front, so without it the channel could not frame the response
      // to the request this test sends and would tear its own connection down.
      channelContext.namespaceIndexCallback = [](string_view)
      {
        return uint16_t{0};
      };
      channelContext.state = SecureChannelContext::State::Open;
      channelContext.secureChannelId = secureChannelId;
      SecurityToken::Keys emptyKeys;
      channelContext.activeSecurityToken =
        std::make_unique<TestSecurityToken>(*channelContext.boundStrand, emptyKeys, emptyKeys, tokenId, 10s);
      g.channel_state() = ChannelAccess::ChannelState::Open;
    });

  ServerAccess{server}.add_secure_channel(sc);
  return sc;
}

}  // namespace

// Part 4 5.5.2 (SPEC-SVR-SC-025): "the Server shall maintain a last used time for the SecureChannel
// to detect the oldest unused SecureChannel". The plausible implementation keeps no timestamp at all
// and reclaims the first session-less channel it walks past - which is creation order - so a
// long-lived working channel is thrown away in favour of a freshly-opened idle one, precisely the
// inversion the clause exists to prevent. This separates the two orderings: channel A is created
// FIRST and is the one that carries a session-less GetEndpoints over the real wire, while channel B
// is created second and never carries anything. Creation order therefore names A and last-use order
// names B, so the observation is falsifiable either way. Both conjuncts of "the idle one is evicted"
// are asserted - the idle channel's transport must be closed AND the used channel's must not be.
// @verifies AC-SVR-SC-025-SESSIONLESS-LAST-USED
// @verifies AC-SVR-SC-002-NEVER-OPENED-CHANNELS-ARE-RECLAIMED-BEFORE-OPENED-ONES
TEST(UascSecurityPolicyTests, SessionlessChannelEvictionFollowsLastUseNotCreationOrder)
{
  // Declared first so it is destroyed LAST: the server and the channels post teardown work that the
  // runtime must still be alive to drain (async_test_runtime.h teardown contract).
  ua::test_helpers::AsyncTestRuntime runtime;
  auto ex = runtime.executor();

  shared_ptr<ua::server::ServerImpl> server;
  ASSERT_NO_THROW(server = make_server_with_channel_cap(ex, /*maxSecureChannels*/ 2));

  constexpr uint32_t channelIdA = 1;
  constexpr uint32_t tokenIdA = 10;
  constexpr uint32_t channelIdB = 2;
  constexpr uint32_t tokenIdB = 20;

  auto connectionA = make_wired_connection(ex);
  ASSERT_NE(connectionA.protocol, nullptr) << "channel A's HEL/ACK handshake did not complete";
  auto channelA = add_open_sessionless_channel(*server, ex, connectionA, channelIdA, tokenIdA);
  ASSERT_NE(channelA, nullptr);

  auto connectionB = make_wired_connection(ex);
  ASSERT_NE(connectionB.protocol, nullptr) << "channel B's HEL/ACK handshake did not complete";
  auto channelB = add_open_sessionless_channel(*server, ex, connectionB, channelIdB, tokenIdB);
  ASSERT_NE(channelB, nullptr);

  // Non-vacuous precondition: BOTH channels are session-less, so both are genuine reclaim
  // candidates and the only thing that can separate them is when each was last used.
  ASSERT_EQ(channelA->session_count(), 0u);
  ASSERT_EQ(channelB->session_count(), 0u);

  // Use channel A: a session-less GetEndpoints invocation (Part 4 6.3 - the traffic this clause is
  // written for), framed by the production SecurityPolicy encoder against a client-side context that
  // mirrors channel A's id and token, then handed to A's transport the way the wire delivers it.
  auto forgeStrand = boost::asio::make_strand(ex);
  auto forgeContext = std::make_shared<SecureChannelContext>(
    make_minimal_context_open_none(ex, forgeStrand, channelIdA, tokenIdA));
  forgeContext->negotiatedLimits.sendBufferSize = 8192;
  forgeContext->negotiatedLimits.sendMaxMessageSize = 1024u * 1024u;
  forgeContext->negotiatedLimits.sendMaxChunkCount = 100u;
  // The encoder demands a namespace resolver before it serializes anything; a GetEndpointsRequest is
  // a namespace-0 type, so the resolver is never consulted and any index answers.
  forgeContext->namespaceIndexCallback = [](string_view)
  {
    return uint16_t{0};
  };

  auto forgePolicy = SecurityPolicy::create(SecurityPolicyId::None);

  std::mutex forgeMutex;
  std::vector<ByteString> forgedChunks;
  SecurityPolicy::SendMessageChunk forgeSink = [&](ByteString chunk)
  {
    std::lock_guard<std::mutex> lock(forgeMutex);
    forgedChunks.push_back(std::move(chunk));
  };

  auto encodeResult = ua::test_helpers::run_async_callback_sync<VoidResult>(
    [&](auto cb)
    {
      forgePolicy->encode_message_async(forgeContext,
        /*requestId*/ 501,
        std::make_shared<GetEndpointsRequest>(),
        forgeSink,
        std::move(cb));
    });
  ASSERT_TRUE(encodeResult.is_good()) << "could not frame the session-less request for channel A";
  ASSERT_EQ(forgedChunks.size(), 1u) << "a GetEndpoints request must fit one chunk of the send buffer";

  deliver_chunk_over_transport(*connectionA.transport, forgedChunks.front());

  // The request really reached channel A - the channel's own receive state advanced to this chunk's
  // SequenceNumber. Without this, "A is the more recently used channel" would be an assumption.
  optional<uint32_t> lastRxOnA;
  for (int attempt = 0; attempt < 300; ++attempt)
  {
    ChannelAccess::on_strand(*channelA, [&](auto& g) { lastRxOnA = g.context()->lastRxSequenceNumber; });
    if (lastRxOnA.has_value() && (*lastRxOnA == 1u))
    {
      break;
    }
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_TRUE(lastRxOnA.has_value());
  ASSERT_EQ(*lastRxOnA, 1u)
    << "the session-less request never reached channel A, so it is not the more recently used channel";

  // A session-less invocation creates no Session, so A stays an eviction candidate: the reclaim has
  // to choose between two session-less channels on last-use alone.
  ASSERT_EQ(channelA->session_count(), 0u)
    << "a session-less request must not give channel A a Session (which would make it non-evictable "
       "for an unrelated reason)";
  ASSERT_EQ(channelB->session_count(), 0u);

  // A third connection arrives with the channel ceiling already reached, forcing the reclaim.
  auto connectionC = make_wired_connection(ex);
  ASSERT_NE(connectionC.protocol, nullptr) << "the arriving connection's handshake did not complete";
  ASSERT_NO_THROW(ServerAccess{*server}.new_connection_complete(::ua::server::ListenerHandle{1},
    "TestListener",
    Status::Good,
    connectionC.protocol,
    ua::connection_protocol::NegotiatedLimits{},
    {}));

  EXPECT_TRUE(connectionB.transport->wait_for_close(3s))
    << "the channel that has been idle since it was created must be the one reclaimed - last use, "
       "not creation time, decides which session-less channel is the oldest unused one";
  EXPECT_FALSE(connectionA.transport->closed())
    << "the channel that carried a session-less request must survive the reclaim; evicting it means "
       "the server ordered by creation time and keeps no last-used time at all";

  channelA.reset();
  channelB.reset();
  connectionA.reset();
  connectionB.reset();
  connectionC.reset();
}

// ---------------------------------------------------------------------------------------------------
// ECC symmetric paths: the received-chunk counter is per MESSAGE (MaxChunkCount bounds one message's
// chunks, Part 6 section 7.1.2.3) and must reset at every message boundary, as the RSA path does.
// ---------------------------------------------------------------------------------------------------

namespace
{

struct EccRoundTripParams
{
  SecurityPolicyId policy;
  EphemeralKeyAlgorithm ephemeralAlgorithm;
  std::string_view name;
};

}  // namespace

class EccSymmetricRoundTrip : public ::testing::TestWithParam<EccRoundTripParams>
{};

// @relation(AC-SVR-UASC-047-ECC-CHUNK-COUNT-RESETS-PER-MESSAGE, scope=function)
TEST_P(EccSymmetricRoundTrip, ChunkCountResetsAtEachMessageBoundary)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto crypto = create_crypto();
  // One policy instance per side, as in production: a policy instance may carry the key-exchange
  // state of its own channel, so the two ends must not share one.
  auto serverPolicy = SecurityPolicy::create(GetParam().policy);
  auto clientPolicy = SecurityPolicy::create(GetParam().policy);
  ASSERT_NE(serverPolicy, nullptr);
  ASSERT_NE(clientPolicy, nullptr);

  auto serverEphemeral = crypto->create_ephemeral_keys_sync(GetParam().ephemeralAlgorithm);
  auto clientEphemeral = crypto->create_ephemeral_keys_sync(GetParam().ephemeralAlgorithm);

  const auto makeContext = [&](shared_ptr<SecurityPolicy> policy)
  {
    auto ctx = std::make_shared<SecureChannelContext>();
    ctx->boundStrand = boost::asio::make_strand(ex);
    ctx->state = SecureChannelContext::State::Open;
    ctx->crypto = crypto;
    ctx->securityPolicy = std::move(policy);
    ctx->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    ctx->secureChannelId = 7;
    ctx->encodingLimits = test_limits();
    // The receiving side is negotiated to ONE chunk per message: a counter that carries over from the
    // previous message refuses the second single-chunk message.
    ctx->negotiatedLimits = {.sendBufferSize = 8192,
      .receiveBufferSize = 8192,
      .sendMaxMessageSize = 1u << 20,
      .sendMaxChunkCount = 100,
      .recvMaxMessageSize = 1u << 20,
      .recvMaxChunkCount = 1};
    ctx->namespaceIndexCallback = [](string_view)
    {
      return uint16_t{0};
    };
    // The CBC receiver predicts the next SequenceNumber (last received + 1) for the per-message IV
    // and the sender numbers its first chunk 1: leave the receiver's last-received at its default 0.
    return ctx;
  };

  const auto deriveKeys = [&](std::shared_ptr<SecureChannelContext> ctx,
                            const ByteString& localPublic,
                            const ByteString& remotePublic,
                            ChannelRole role)
  {
    auto policy = ctx->securityPolicy;
    return ua::test_helpers::run_async_callback_sync<SecurityPolicy::DeriveSymmetricKeysResult>(
      [&](auto cb) {
        policy->derive_symmetric_keys_async(std::move(ctx), localPublic, remotePublic, role, std::move(cb));
      });
  };

  auto serverCtx = makeContext(serverPolicy);
  serverCtx->localEphemeralPrivateKey = serverEphemeral.privateKey;
  auto serverKeys =
    deriveKeys(serverCtx, serverEphemeral.publicKey, clientEphemeral.publicKey, ChannelRole::Server);
  ASSERT_TRUE(serverKeys.is_good()) << serverKeys.status_code().as_uint32();
  serverCtx->activeSecurityToken = std::make_unique<TestSecurityToken>(
    *serverCtx->boundStrand, serverKeys.value().first, serverKeys.value().second, /*id*/ 42, 10s);

  auto clientCtx = makeContext(clientPolicy);
  clientCtx->localEphemeralPrivateKey = clientEphemeral.privateKey;
  auto clientKeys =
    deriveKeys(clientCtx, clientEphemeral.publicKey, serverEphemeral.publicKey, ChannelRole::Client);
  ASSERT_TRUE(clientKeys.is_good()) << clientKeys.status_code().as_uint32();
  clientCtx->activeSecurityToken = std::make_unique<TestSecurityToken>(
    *clientCtx->boundStrand, clientKeys.value().first, clientKeys.value().second, /*id*/ 42, 10s);

  std::mutex chunkMutex;
  std::vector<ByteString> chunks;
  SecurityPolicy::SendMessageChunk sink = [&](ByteString chunk)
  {
    const std::lock_guard<std::mutex> lock(chunkMutex);
    chunks.push_back(std::move(chunk));
  };

  for (uint32_t requestId = 1; requestId <= 2; ++requestId)
  {
    {
      const std::lock_guard<std::mutex> lock(chunkMutex);
      chunks.clear();
    }
    auto encodeResult = ua::test_helpers::run_async_callback_sync<VoidResult>(
      [&](auto cb)
      {
        clientPolicy->encode_message_async(
          clientCtx, requestId, std::make_shared<GetEndpointsRequest>(), sink, std::move(cb));
      });
    ASSERT_TRUE(encodeResult.is_good())
      << "0x" << std::hex << encodeResult.status_code().as_uint32() << " "
      << (encodeResult.shared_detail() ? encodeResult.shared_detail()->code : "") << ": "
      << (encodeResult.shared_detail() ? encodeResult.shared_detail()->summary : "") << " ["
      << (encodeResult.shared_detail() ? encodeResult.shared_detail()->source : "") << "]";
    ASSERT_EQ(chunks.size(), 1u) << "a GetEndpoints request must fit one chunk";

    auto decoded = decode_chunk_sync(serverPolicy, serverCtx, chunks.front());
    ASSERT_TRUE(decoded.is_good()) << "message " << requestId << " with MaxChunkCount = 1 must decode: 0x"
                                   << std::hex << decoded.status_code().as_uint32() << " "
                                   << (decoded.shared_detail() ? decoded.shared_detail()->code : "") << ": "
                                   << (decoded.shared_detail() ? decoded.shared_detail()->summary : "")
                                   << " [" << (decoded.shared_detail() ? decoded.shared_detail()->source : "")
                                   << "]";
    ASSERT_TRUE(decoded.value().has_value()) << "a Final chunk completes the message";
  }

  serverCtx.reset();
  clientCtx.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

INSTANTIATE_TEST_SUITE_P(EphemeralKeyPolicies, EccSymmetricRoundTrip,
  ::testing::Values(
    EccRoundTripParams{SecurityPolicyId::EccNistP256AesGcm, EphemeralKeyAlgorithm::EccNistP256, "NistP256"},
    EccRoundTripParams{SecurityPolicyId::EccNistP384AesGcm, EphemeralKeyAlgorithm::EccNistP384, "NistP384"},
    EccRoundTripParams{SecurityPolicyId::EccCurve25519ChaChaPoly,
      EphemeralKeyAlgorithm::EccCurve25519,
      "Curve25519ChaChaPoly"},
    EccRoundTripParams{
      SecurityPolicyId::EccNistP256ChaChaPoly, EphemeralKeyAlgorithm::EccNistP256, "NistP256ChaChaPoly"},
    EccRoundTripParams{
      SecurityPolicyId::EccNistP384ChaChaPoly, EphemeralKeyAlgorithm::EccNistP384, "NistP384ChaChaPoly"},
    EccRoundTripParams{SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      "BrainpoolP256r1AesGcm"},
    EccRoundTripParams{SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      EphemeralKeyAlgorithm::EccBrainpoolP256r1,
      "BrainpoolP256r1ChaChaPoly"},
    EccRoundTripParams{SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      "BrainpoolP384r1AesGcm"},
    EccRoundTripParams{SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      EphemeralKeyAlgorithm::EccBrainpoolP384r1,
      "BrainpoolP384r1ChaChaPoly"},
    EccRoundTripParams{
      SecurityPolicyId::EccCurve25519AesGcm, EphemeralKeyAlgorithm::EccCurve25519, "Curve25519AesGcm"},
    EccRoundTripParams{
      SecurityPolicyId::EccCurve448AesGcm, EphemeralKeyAlgorithm::EccCurve448, "Curve448AesGcm"},
    EccRoundTripParams{
      SecurityPolicyId::EccCurve448ChaChaPoly, EphemeralKeyAlgorithm::EccCurve448, "Curve448ChaChaPoly"},
    EccRoundTripParams{SecurityPolicyId::RsaDhAesGcm, EphemeralKeyAlgorithm::RsaDhFfdhe3072, "RsaDhAesGcm"},
    EccRoundTripParams{
      SecurityPolicyId::RsaDhChaChaPoly, EphemeralKeyAlgorithm::RsaDhFfdhe3072, "RsaDhChaChaPoly"}),
  [](const ::testing::TestParamInfo<EccRoundTripParams>& info) { return std::string{info.param.name}; });
