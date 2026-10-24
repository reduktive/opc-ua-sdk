// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_pull_certificate_request_codec.h"

#include "ua_client_answer_status.h"
#include "ua_error_detail.h"
#include "ua_status.h"

#include <utility>

namespace ua::client::detail
{

namespace
{

constexpr std::string_view codecSource{"client.tier1.pull_cert.certificate_request.codec"};

template<typename Value>
ua::Result<Value> output_count_error(std::string code, std::size_t actual, std::size_t expected)
{
  return {ua::Status::BadUnexpectedError,
    ua::ErrorDetail::build(std::move(code),
      "the CertificateDirectory Method returned an unexpected number of output arguments",
      std::string{codecSource})
      .context(ua::ContextKeys::sizeActual, actual)
      .context(ua::ContextKeys::sizeExpected, expected)};
}

template<typename Value>
ua::Result<Value> output_type_error(std::string code, std::size_t index)
{
  return {ua::Status::BadTypeMismatch,
    ua::ErrorDetail::build(std::move(code),
      "the CertificateDirectory Method returned an output argument with the wrong type",
      std::string{codecSource})
      .context(ua::ContextKeys::operationIndex, index)};
}

/// The Method's answer the pull cycle acts on, when the service and the Method both answered Good (a Good
/// subcode is consumed). Otherwise the status to fail with: a Bad answer as it is (FinishRequest's
/// Bad_NothingToDo included), an Uncertain one refused with Bad_InternalError (`ServiceAnswerUncertain`).
ua::Result<ua::CallMethodResult> good_method_answer(ua::Result<ua::CallResult> call)
{
  if (!call.is_good())
  {
    return ua::Result<ua::CallMethodResult>{
      answer_refused(call.status_code(), "ServiceAnswerUncertain", codecSource)};
  }
  ua::CallResult method = std::move(call).value();
  if (!method.is_good())
  {
    return ua::Result<ua::CallMethodResult>{
      answer_refused(method.status_code(), "ServiceAnswerUncertain", codecSource)};
  }
  return ua::Result<ua::CallMethodResult>{std::move(method).value()};
}

}  // namespace

ua::Result<std::vector<ua::Variant>> build_start_certificate_request_arguments(
  StartCertificateRequestWireParams params)
{
  std::vector<ua::Variant> arguments;
  if (!params.newKeyPair)
  {
    if (params.certificateRequest.empty())
    {
      return {ua::Status::BadInvalidArgument,
        ua::make_error_detail("PullCertSigningRequestEmpty",
          "StartSigningRequest requires a DER PKCS#10 certificateRequest",
          std::string{codecSource})};
    }
    arguments.reserve(4);
    arguments.emplace_back(std::move(params.applicationId));
    arguments.emplace_back(std::move(params.certificateGroupId));
    arguments.emplace_back(std::move(params.certificateTypeId));
    arguments.emplace_back(std::move(params.certificateRequest));
    return {std::move(arguments)};
  }

  ua::Array<ua::String> domainNames;
  domainNames.reserve(params.domainNames.size());
  for (auto& domainName : params.domainNames)
  {
    domainNames.emplace_back(std::move(domainName));
  }
  arguments.reserve(7);
  arguments.emplace_back(std::move(params.applicationId));
  arguments.emplace_back(std::move(params.certificateGroupId));
  arguments.emplace_back(std::move(params.certificateTypeId));
  arguments.emplace_back(ua::String{std::move(params.subjectName)});
  arguments.emplace_back(std::move(domainNames));
  arguments.emplace_back(ua::String{std::move(params.privateKeyFormat)});
  // privateKeyPassword is always empty: the key is requested unprotected (OPC 10000-12 7.9.4/7.9.5), so it is
  // read with the application's own Crypto credential and never needs a second secret.
  arguments.emplace_back(ua::String{});
  return {std::move(arguments)};
}

ua::Result<ua::NodeId> decode_start_certificate_request_result(ua::Result<ua::CallResult> call)
{
  auto answer = good_method_answer(std::move(call));
  if (!answer.is_good())
  {
    return {answer.status_code()};
  }
  auto methodResult = std::move(answer).value();
  const auto& outputs = methodResult.output_arguments();
  if (outputs.size() != 1)
  {
    return output_count_error<ua::NodeId>("PullCertStartOutputCountMismatch", outputs.size(), 1);
  }
  const auto* requestId = outputs[0].try_as<ua::NodeId>();
  if (!requestId)
  {
    return output_type_error<ua::NodeId>("PullCertStartRequestIdTypeMismatch", 0);
  }
  return {*requestId};
}

std::vector<ua::Variant> build_finish_certificate_request_arguments(
  ua::NodeId applicationId, ua::NodeId requestId)
{
  std::vector<ua::Variant> arguments;
  arguments.reserve(2);
  arguments.emplace_back(std::move(applicationId));
  arguments.emplace_back(std::move(requestId));
  return arguments;
}

ua::Result<FinishCertificateRequestWireResult> decode_finish_certificate_request_result(
  ua::Result<ua::CallResult> call)
{
  auto answer = good_method_answer(std::move(call));
  if (!answer.is_good())
  {
    return {answer.status_code()};
  }
  auto methodResult = std::move(answer).value();
  const auto& outputs = methodResult.output_arguments();
  if (outputs.size() != 3)
  {
    return output_count_error<FinishCertificateRequestWireResult>(
      "PullCertFinishOutputCountMismatch", outputs.size(), 3);
  }
  const auto* certificate = outputs[0].try_as<ua::ByteString>();
  const auto* privateKey = outputs[1].try_as<ua::ByteString>();
  auto issuers = outputs[2].to_vector<ua::ByteString>();
  if (!certificate)
  {
    return output_type_error<FinishCertificateRequestWireResult>("PullCertFinishCertificateTypeMismatch", 0);
  }
  if (!privateKey)
  {
    return output_type_error<FinishCertificateRequestWireResult>("PullCertFinishPrivateKeyTypeMismatch", 1);
  }
  if (!issuers.has_value())
  {
    return output_type_error<FinishCertificateRequestWireResult>("PullCertFinishIssuersTypeMismatch", 2);
  }
  return {FinishCertificateRequestWireResult{*certificate, *privateKey, std::move(issuers).value()}};
}

}  // namespace ua::client::detail
