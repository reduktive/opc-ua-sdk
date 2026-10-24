// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PULL_CERTIFICATE_REQUEST_CODEC_H
#define UA_PULL_CERTIFICATE_REQUEST_CODEC_H

/// @file
/// @brief Pure Part 12 CertificateDirectory Start/FinishRequest wire helpers.
/// @ingroup client

#include "ua_byte_string.h"
#include "ua_call_method_result.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <string>
#include <vector>

namespace ua::client::detail
{

struct StartCertificateRequestWireParams
{
  ua::NodeId applicationId;
  ua::NodeId certificateGroupId;
  ua::NodeId certificateTypeId;
  bool newKeyPair = false;
  ua::ByteString certificateRequest;
  std::string subjectName;
  std::vector<std::string> domainNames;
  std::string privateKeyFormat{"PEM"};
};

struct FinishCertificateRequestWireResult
{
  ua::ByteString certificate;
  ua::ByteString privateKey;
  std::vector<ua::ByteString> issuerCertificates;
};

/// Builds the exact Part 12 section 7.9.3 or section 7.9.4 input argument sequence.
[[nodiscard]] ua::Result<std::vector<ua::Variant>> build_start_certificate_request_arguments(
  StartCertificateRequestWireParams params);

/// Decodes the single NodeId requestId output. It is used only when the service and the Method answered Good
/// (a Good subcode is consumed): a Bad answer at either layer is passed on with its ErrorDetail, an Uncertain
/// one is refused with Bad_InternalError (`ServiceAnswerUncertain`).
[[nodiscard]] ua::Result<ua::NodeId> decode_start_certificate_request_result(ua::Result<ua::CallResult> call);

/// Builds the exact Part 12 section 7.9.5 `{applicationId, requestId}` input argument sequence.
[[nodiscard]] std::vector<ua::Variant> build_finish_certificate_request_arguments(
  ua::NodeId applicationId, ua::NodeId requestId);

/// Decodes the three Part 12 section 7.9.5 ByteString outputs. They are used only when the service and the
/// Method answered Good (a Good subcode is consumed): a Bad answer at either layer is passed on with its
/// ErrorDetail (Bad_NothingToDo included), an Uncertain one is refused with Bad_InternalError
/// (`ServiceAnswerUncertain`).
[[nodiscard]] ua::Result<FinishCertificateRequestWireResult> decode_finish_certificate_request_result(
  ua::Result<ua::CallResult> call);

}  // namespace ua::client::detail

#endif  // UA_PULL_CERTIFICATE_REQUEST_CODEC_H
