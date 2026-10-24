// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SECURITY_POLICY_TEST_ACCESS_H
#define UA_SECURITY_POLICY_TEST_ACCESS_H

/// @file
/// @brief Test-only interfaces into the SecurityPolicy symmetric-encode internals.
///
/// These entry points exist solely so unit tests can drive code paths that production stimulus
/// cannot reach (see @ref ua::test_access::start_symmetric_abort_with_reason). They are not part
/// of the shipped public surface and must not be used by production code.

#include <functional>
#include <memory>
#include <string>

#include "ua_result.h"
#include "ua_security_policy.h"
#include "ua_status.h"

namespace ua
{

struct SecureChannelContext;

namespace test_access
{

/// Drives the symmetric abort flow directly with a caller-supplied @p reason, bypassing the
/// natural encode path.
///
/// The reasons produced by the natural encode-abort path are always short internal literals
/// ("encode failed", "Could not sign symmetric message chunk", ...), so they can never exercise
/// the P6-67-0018 abort-reason clamp (`reason.size() > 4096 -> resize(4096)`). Seeding a reason
/// longer than the clamp here and decoding the emitted abort chunk's Reason field is the only way
/// to make that clamp falsifiable. Not used in production.
///
/// @param policy          Security policy that owns the abort emission logic; must be non-null and
///                        managed by a `shared_ptr` (the flow captures it).
/// @param context         Per-channel state; must have an active security token and outlive the call.
/// @param requestId       Request id stamped into the abort chunk's sequence header.
/// @param abortStatus     Error status carried in the abort chunk body.
/// @param reason          Reason string carried in the abort chunk body (subject to the clamp).
/// @param sendMessageChunk Sink invoked with the finished abort chunk.
/// @param maxChunkSize    Negotiated send-buffer size the abort chunk must fit into.
/// @param callback        Receives the terminal @ref VoidResult of the abort flow.
void start_symmetric_abort_with_reason(std::shared_ptr<const SecurityPolicy> policy,
  SecureChannelContext& context, uint32_t requestId, Status abortStatus, std::string reason,
  SecurityPolicy::SendMessageChunk sendMessageChunk, uint32_t maxChunkSize,
  std::function<void(VoidResult)> callback);

/// Friend interface that forwards to the protected @ref SecurityPolicy::encode_symmetric_message_async so a unit
/// test can drive the FULL symmetric encode path (chunk sizing + multi-chunk emission) with a caller-supplied
/// @p sendMessageChunk. Production stimulus reaches this path only through the channel's real transport send,
/// which a unit test cannot make fail mid-stream; injecting a throwing send here is the only way to reach the
/// `handle_encode_symmetric_deferred_error` chunksSent>0 branch that emits an Abort chunk (CL-TCP-011).
struct SymmetricEncodeDriver
{
  static void encode(const SecurityPolicy& policy, SecureChannelContext& context, uint32_t requestId,
    span<const byte> messageBody, SecurityPolicy::SendMessageChunk sendMessageChunk,
    std::function<void(VoidResult)> callback)
  {
    policy.encode_symmetric_message_async(
      context, requestId, messageBody, std::move(sendMessageChunk), std::move(callback));
  }
};

}  // namespace test_access
}  // namespace ua

#endif  // UA_SECURITY_POLICY_TEST_ACCESS_H
