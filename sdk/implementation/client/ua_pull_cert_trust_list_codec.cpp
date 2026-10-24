// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_pull_cert_trust_list_codec.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_client_answer_status.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_memory_stream.h"
#include "ua_status.h"
#include "ua_structure_factory.h"
#include "ua_variant.h"

#include <string>
#include <utility>

namespace ua::client::detail
{

namespace
{
constexpr std::string_view decodeFailedSource = "client.tier1.pull_cert.trust_list.decode_failed";
constexpr std::string_view getTrustListSource = "client.tier1.pull_cert.trust_list.get_trust_list";
constexpr std::string_view getCertificateStatusSource = "client.tier1.pull_cert.get_certificate_status";
constexpr std::string_view lastUpdateTimeSource = "client.tier1.pull_cert.trust_list.last_update_time";

/// The Method's answer the pull cycle acts on, when the service and the Method both answered Good (a Good
/// subcode is consumed). Otherwise the status to fail with: a Bad answer as it is, an Uncertain one refused
/// with Bad_InternalError (`ServiceAnswerUncertain`).
ua::Result<ua::CallMethodResult> good_method_answer(ua::Result<ua::CallResult> call, std::string_view source)
{
  if (!call.is_good())
  {
    return ua::Result<ua::CallMethodResult>{
      answer_refused(call.status_code(), "ServiceAnswerUncertain", source)};
  }
  ua::CallResult method = std::move(call).value();
  if (!method.is_good())
  {
    return ua::Result<ua::CallMethodResult>{
      answer_refused(method.status_code(), "ServiceAnswerUncertain", source)};
  }
  return ua::Result<ua::CallMethodResult>{std::move(method).value()};
}
}  // namespace

std::vector<ua::Variant> build_get_trust_list_arguments(
  ua::NodeId applicationId, ua::NodeId certificateGroupId)
{
  return {ua::Variant{std::move(applicationId)}, ua::Variant{std::move(certificateGroupId)}};
}

std::vector<ua::Variant> build_get_certificate_status_arguments(
  ua::NodeId applicationId, ua::NodeId certificateGroupId, ua::NodeId certificateTypeId)
{
  return {ua::Variant{std::move(applicationId)},
    ua::Variant{std::move(certificateGroupId)},
    ua::Variant{std::move(certificateTypeId)}};
}

ua::Result<bool> decode_get_certificate_status_result(ua::Result<ua::CallResult> call)
{
  auto answer = good_method_answer(std::move(call), getCertificateStatusSource);
  if (!answer.is_good())
  {
    return {answer.status_code()};
  }
  const auto methodResult = std::move(answer).value();
  const auto& outputs = methodResult.output_arguments();
  if (outputs.size() != 1)
  {
    return {ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("PullCertGetCertificateStatusOutputCountMismatch",
        "GetCertificateStatus returned an unexpected number of output arguments",
        std::string{getCertificateStatusSource})
        .context(ua::ContextKeys::sizeActual, outputs.size())
        .context(ua::ContextKeys::sizeExpected, std::size_t{1})};
  }
  const auto* updateRequired = outputs[0].try_as<bool>();
  if (!updateRequired)
  {
    return {ua::Status::BadTypeMismatch,
      ua::make_error_detail("PullCertGetCertificateStatusTypeMismatch",
        "GetCertificateStatus returned a non-Boolean updateRequired",
        std::string{getCertificateStatusSource})};
  }
  return {*updateRequired};
}

ua::Result<ua::NodeId> decode_get_trust_list_result(ua::Result<ua::CallResult> call)
{
  auto answer = good_method_answer(std::move(call), getTrustListSource);
  if (!answer.is_good())
  {
    return {answer.status_code()};
  }
  auto methodResult = std::move(answer).value();
  const auto& outputs = methodResult.output_arguments();
  if (outputs.size() != 1)
  {
    return {ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("PullCertGetTrustListOutputCountMismatch",
        "GetTrustList returned an unexpected number of output arguments",
        std::string{getTrustListSource})
        .context(ua::ContextKeys::sizeActual, outputs.size())
        .context(ua::ContextKeys::sizeExpected, std::size_t{1})};
  }
  const auto* trustListId = outputs[0].try_as<ua::NodeId>();
  if (!trustListId)
  {
    return {ua::Status::BadTypeMismatch,
      ua::make_error_detail("PullCertGetTrustListTypeMismatch",
        "GetTrustList returned a non-NodeId TrustList Object",
        std::string{getTrustListSource})};
  }
  return {*trustListId};
}

ua::Result<std::optional<ua::DateTime>> interpret_trust_list_last_update_time(
  ua::Result<ua::DataValue> readResult)
{
  // The update decision is taken only on a Good answer: a Bad one is passed on with its ErrorDetail and an
  // Uncertain one, with or without a value, is refused (ReadAnswerUncertain).
  if (!readResult.is_good())
  {
    return ua::Result<std::optional<ua::DateTime>>{
      answer_refused(readResult.status_code(), "ReadAnswerUncertain", lastUpdateTimeSource)};
  }
  const ua::DataValue& dataValue = readResult.value();
  const auto& valueStatus = dataValue.status();
  if (valueStatus.has_value() && !valueStatus.value().is_good())
  {
    // A value status that is not Good (e.g. Bad_UserAccessDenied) fails the read rather than being taken
    // for an absent value  -  a denied read must NOT degrade to nullopt (which would silently skip the
    // update, CL-PULLCRT-005).
    return ua::Result<std::optional<ua::DateTime>>{
      answer_refused(valueStatus.value(), "ReadAnswerUncertain", lastUpdateTimeSource)};
  }
  const ua::Variant& value = dataValue.value();
  if (value.empty())
  {
    // Null / absent LastUpdateTime: no update marker (CL-PULLCRT-005 skip semantics).
    return ua::Result<std::optional<ua::DateTime>>{std::optional<ua::DateTime>{}};
  }
  const ua::Result<ua::DateTime> lastUpdate = value.to<ua::DateTime>();
  if (!lastUpdate.has_value())
  {
    // A non-empty value that is not a DateTime is a malformed LastUpdateTime: propagate the coercion
    // ErrorDetail rather than pretending the value was absent.
    return ua::Result<std::optional<ua::DateTime>>{lastUpdate.status_code(), lastUpdate.shared_detail()};
  }
  return ua::Result<std::optional<ua::DateTime>>{std::optional<ua::DateTime>{lastUpdate.value()}};
}

ua::Result<ua::TrustListDataType> decode_trust_list_body(const ua::ByteString& body)
{
  auto decodeFailed = [](std::string summary)
  {
    return ua::Result<ua::TrustListDataType>{ua::StatusCode{ua::Status::BadDecodingError,
      ua::ErrorDetail::build("PullCertTrustListDecodeFailed",
        "The downloaded TrustList body is invalid",
        std::string{decodeFailedSource})
        .context(ua::ContextKeys::errorMessage, summary)}};
  };
  if (body.empty())
  {
    // An empty body is never a valid TrustListDataType (it carries at least a 4-byte `specifiedLists` mask).
    // Reject it rather than silently decoding an EMPTY trust list  -  which would replace the client's trust
    // anchors with nothing. The in-repo UA-Binary decoder is LENIENT (reads past EOF as zeros without
    // throwing), so this explicit guard is required.
    return decodeFailed("the downloaded TrustList File body is empty (not a valid TrustListDataType)");
  }
  ua::TrustListDataType trustList;
  try
  {
    // Decode the raw UA-Binary TrustListDataType structure body (no ExtensionObject wrapper): this mirrors
    // the server's TrustList File encode/decode round-trip (ua_trust_list_manager.cpp), the authoritative
    // in-repo wire shape for a TrustListType File body.
    ua::memory_stream_device::ExternalReadOnly readDevice{ua::span<const ua::byte>{body}};
    ua::MemoryStream<ua::memory_stream_device::ExternalReadOnly> readStream{readDevice};
    ua::UaBinaryDecoder decoder{ua::StructureResolver{}, readStream, ua::EncodingLimits{}};
    decoder.decode(ua::EncodingLimits{}.stack_depth(), trustList);

    // ROUND-TRIP SIZE validation. The in-repo UA-Binary decoder is LENIENT: an EOF-short read returns 0
    // WITHOUT throwing AND WITHOUT advancing the position, so a truncated/malformed body silently decodes to
    // a partial/empty TrustList  -  and a boundary-aligned truncation (e.g. a 4-byte `{0F 00 00 00}` File
    // that decodes to specifiedLists=all-lists yet every list empty) even leaves the position exactly at
    // body.size(), defeating a plain position==size check (section 3.1). Re-encode the decoded value and
    // require the re-encoded LENGTH to equal body.size(): a truncated/over-read/trailing-garbage body
    // re-encodes to a different length, so this rejects it  -  stopping a silent empty/partial trust list
    // from replacing the client's trust anchors with nothing.
    //
    // SIZE, not byte-identity (section 3.1): UA-Binary has TWO legal encodings for an empty array/ByteString
    // - length 0 and length -1 (OPC 10000-6 section 5.1.11)  -  and the SDK decoder accepts both while the
    // SDK encoder canonicalises empties to -1. A byte-for-byte compare would therefore FALSE-REJECT a
    // conformant server (OPC Foundation .NET / open62541 GDS emit length-0 empties)  -  a
    // certification-breaking interop bug. Both empty forms occupy the same 4-byte length field, so the SIZE
    // is invariant to the 0-vs-(-1) choice while a genuine truncation still changes it.
    ua::memory_stream_device::Dynamic encodeDevice{body.size() + 1024, /*reserve=*/true};
    ua::MemoryStream<ua::memory_stream_device::Dynamic> encodeStream{encodeDevice};
    ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, encodeStream};
    encoder.encode(ua::EncodingLimits{}.stack_depth(), trustList);
    if (encodeDevice.get_data().size() != body.size())
    {
      return decodeFailed(
        "the downloaded TrustList File body is malformed (its re-encoded length differs "
        "from the received length - truncated / trailing bytes)");
    }
  }
  catch (...)
  {
    return decodeFailed("the downloaded TrustList File body could not be decoded as a TrustListDataType");
  }
  return ua::Result<ua::TrustListDataType>{std::move(trustList)};
}

}  // namespace ua::client::detail
