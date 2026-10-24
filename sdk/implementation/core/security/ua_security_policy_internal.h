// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SECURITY_POLICY_INTERNAL_H
#define UA_SECURITY_POLICY_INTERNAL_H

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_includes.h"
#include "ua_memory_stream.h"
#include "ua_security_policy.h"
#include "ua_secure_memory.h"
#include "ua_security_token.h"
#include "ua_status_code.h"
#include "ua_structure_factory.h"

#include <string>
#include <string_view>

namespace ua::security_internal
{

/// The ErrorDetail of an Uncertain crypto answer a security step does not use: "CryptoAnswerUncertain", with
/// the Uncertain code (and its detail) as the cause.
///
/// @param answer The provider's Uncertain status.
/// @param source The ErrorDetail source, the step that refuses the answer.
/// @return The detail.
inline shared_ptr<const ErrorDetail> uncertain_answer_detail(
  const StatusCode& answer, std::string_view source)
{
  return ErrorDetail::build("CryptoAnswerUncertain",
    "The SDK does not act on an answer the crypto provider is uncertain of",
    std::string{source})
    .cause(answer);
}

/// The status a security step answers in place of a crypto answer that is not Good. A step uses a value, or
/// treats an operation as done, only on a Good answer: a Bad answer is passed on unchanged, and an Uncertain
/// one, with or without a value, is refused with @p refusal and the detail of @ref uncertain_answer_detail.
///
/// @param answer  The provider's status; not Good.
/// @param refusal The Bad code the step answers for an Uncertain answer.
/// @param source  The ErrorDetail source of the refusal.
/// @return The status to answer.
inline StatusCode not_good_answer(const StatusCode& answer, Status refusal, std::string_view source)
{
  if (answer.is_bad())
  {
    return answer;
  }
  return StatusCode{refusal, uncertain_answer_detail(answer, source)};
}

/// The ErrorDetail a security step attaches to a Bad code of its own when a crypto answer is not Good: a Bad
/// answer's own detail, unchanged, or the detail of @ref uncertain_answer_detail for an Uncertain answer.
///
/// @param answer The provider's status; not Good.
/// @param source The ErrorDetail source of the refusal.
/// @return The detail; null when a Bad answer carries none.
inline shared_ptr<const ErrorDetail> not_good_answer_detail(const StatusCode& answer, std::string_view source)
{
  if (answer.is_bad())
  {
    return answer.shared_detail();
  }
  return uncertain_answer_detail(answer, source);
}

/// The ErrorDetail of an Uncertain certificate store answer a step does not use:
/// "CertificateStoreAnswerUncertain", with the Uncertain code (and its detail) as the cause.
///
/// @param answer The store's Uncertain status.
/// @param source The ErrorDetail source, the step that refuses the answer.
/// @return The detail.
inline shared_ptr<const ErrorDetail> uncertain_store_answer_detail(
  const StatusCode& answer, std::string_view source)
{
  return ErrorDetail::build("CertificateStoreAnswerUncertain",
    "The SDK does not act on an answer the certificate store is uncertain of",
    std::string{source})
    .cause(answer);
}

/// The status a step answers in place of a certificate store answer that is not Good. A step uses the
/// store's certificates, lists or keys, or treats a store operation as done, only on a Good answer: a Bad
/// answer is passed on unchanged, and an Uncertain one, with or without a value, is refused with @p refusal
/// and the detail of @ref uncertain_store_answer_detail.
///
/// @param answer  The store's status; not Good.
/// @param refusal The Bad code the step answers for an Uncertain answer.
/// @param source  The ErrorDetail source of the refusal.
/// @return The status to answer.
inline StatusCode not_good_store_answer(const StatusCode& answer, Status refusal, std::string_view source)
{
  if (answer.is_bad())
  {
    return answer;
  }
  return StatusCode{refusal, uncertain_store_answer_detail(answer, source)};
}

/// The ErrorDetail a step attaches to a Bad code of its own when a certificate store answer is not Good: a
/// Bad answer's own detail, unchanged, or the detail of @ref uncertain_store_answer_detail for an Uncertain
/// answer.
///
/// @param answer The store's status; not Good.
/// @param source The ErrorDetail source of the refusal.
/// @return The detail; null when a Bad answer carries none.
inline shared_ptr<const ErrorDetail> not_good_store_answer_detail(
  const StatusCode& answer, std::string_view source)
{
  if (answer.is_bad())
  {
    return answer.shared_detail();
  }
  return uncertain_store_answer_detail(answer, source);
}

/// Slice raw key material into signing key / encrypting key / IV per the policy's symmetric
/// key sizes. Lives in this private header (not on `SecurityPolicy`) so that per-flow
/// free-function continuations in anonymous namespaces of the policy `.cpp` files can call
/// it without forcing an internal helper onto the class's public/protected surface. Takes the derived block
/// by value and zeroes it once sliced, so no copy of the key material outlives the keys.
inline SecurityToken::Keys slice_key_material(const SecurityPolicy& policy, ByteString keyMaterial)
{
  const security::ScrubOnExit scrub{keyMaterial};
  const span<const byte> material{keyMaterial};
  auto signKeySize = policy.symmetric_signature_key_size();
  auto encKeySize = policy.symmetric_encryption_key_size();
  auto ivSize = policy.symmetric_iv_size();
  SecurityToken::Keys keys;
  keys.signingKey = ByteString{material.subspan(0, signKeySize)};
  keys.encryptingKey = ByteString{material.subspan(signKeySize, encKeySize)};
  keys.initializationVector = ByteString{material.subspan(signKeySize + encKeySize, ivSize)};
  return keys;
}

/// Decode the body of an ABORT message chunk (Part 6 6.7.3, Table 56).
///
/// The body carries `Error` (a UInt32 StatusCode) followed by `Reason` (a String), inside the
/// signed/encrypted region. This helper decodes the `Error` field and returns it as the StatusCode to
/// report back to the single request the abort targets; the `Reason` is decoded (so the whole body is
/// validated and the encoding limits bound its length) but discarded, since the abort mechanism only
/// needs the status. Shared by every symmetric decode finalizer.
///
/// Robustness: this never throws. A too-short body, an over-length Reason, or any other decode failure
/// yields @ref Status::BadSecurityChecksFailed, so a malformed abort cannot escape the decode finalizer
/// and tear the channel down. The finalizer surfaces the abort on the channel context side-channel and
/// keeps the channel open, exactly as the spec requires (the abort aborts one request, not the channel).
///
/// @param abortBody Reassembled abort body bytes (the region after the SequenceHeader).
/// @param limits    Encoding limits governing the decode (string length, work limits, ...).
/// @return The decoded `Error` StatusCode, or @ref Status::BadSecurityChecksFailed on any decode failure.
inline ua::StatusCode decode_abort_error(ua::span<const ua::byte> abortBody, const ua::EncodingLimits& limits)
{
  try
  {
    // The Error field is a UInt32 (Table 56). MemoryStream::read_all silently no-ops on underrun rather
    // than throwing, so a body shorter than the Error field would otherwise decode as a bogus Good(0)
    // and report the aborted request as SUCCEEDING. Guard the size explicitly so a truncated/malformed
    // abort body is reported as Bad_SecurityChecksFailed, never as success.
    if (abortBody.size() < sizeof(uint32_t))
    {
      return ua::StatusCode{ua::Status::BadSecurityChecksFailed};
    }

    ua::memory_stream_device::ExternalReadOnly streamDevice{abortBody};
    ua::MemoryStream stream{streamDevice};
    ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits};
    const ua::StackDepth depth = limits.stack_depth();

    uint32_t errorValue = 0;
    decoder.decode(depth, errorValue);

    // Decode (and discard) the Reason so the body is fully validated; the client only needs the Error.
    // Any over-length Reason is rejected by the encoding limits here rather than being materialised.
    ua::String reason;
    decoder.decode(depth, reason);

    return ua::StatusCode{static_cast<ua::StatusCodeValue>(errorValue)};
  }
  catch (...)
  {
    return ua::StatusCode{ua::Status::BadSecurityChecksFailed};
  }
}

}  // namespace ua::security_internal

#endif  // UA_SECURITY_POLICY_INTERNAL_H
