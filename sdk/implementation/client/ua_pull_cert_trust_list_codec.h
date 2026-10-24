// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PULL_CERT_TRUST_LIST_CODEC_H
#define UA_PULL_CERT_TRUST_LIST_CODEC_H

/// @file
/// @brief Pure decode/interpret helpers for the client PullCert TrustList RPCs (CL-PULLCRT-005), extracted
///        from PullCertificateManagerClientHost so their branch ladders are unit-testable without a live GDS
///        Connection.
/// @ingroup client

#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_call_method_result.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_trust_list_data_type.h"

#include <optional>
#include <vector>

namespace ua::client::detail
{

/// `GetTrustList(applicationId, certificateGroupId)` input arguments (OPC 10000-12 7.9.9).
[[nodiscard]] std::vector<ua::Variant> build_get_trust_list_arguments(
  ua::NodeId applicationId, ua::NodeId certificateGroupId);

/// The TrustList Object the `GetTrustList` Method returns. It is used only when the service and the Method
/// answered Good (a Good subcode is consumed): a Bad answer is passed on, an Uncertain one is refused with
/// Bad_InternalError (`ServiceAnswerUncertain`); any output shape other than one NodeId is malformed.
[[nodiscard]] ua::Result<ua::NodeId> decode_get_trust_list_result(ua::Result<ua::CallResult> call);

/// `GetCertificateStatus(applicationId, certificateGroupId, certificateTypeId)` input arguments
/// (OPC 10000-12 7.9.10).
[[nodiscard]] std::vector<ua::Variant> build_get_certificate_status_arguments(
  ua::NodeId applicationId, ua::NodeId certificateGroupId, ua::NodeId certificateTypeId);

/// The `updateRequired` output of `GetCertificateStatus`. It is used only when the service and the Method
/// answered Good (a Good subcode is consumed): a Bad answer is passed on, an Uncertain one is refused with
/// Bad_InternalError (`ServiceAnswerUncertain`); any output shape other than one Boolean is malformed.
[[nodiscard]] ua::Result<bool> decode_get_certificate_status_result(ua::Result<ua::CallResult> call);

/// Interprets the `Result<DataValue>` of a `TrustListType.LastUpdateTime` Read into the manager's
/// `optional<DateTime>` skip marker (CL-PULLCRT-005). The ladder, in order:
///  - a service-level Bad Result propagates verbatim (code + ErrorDetail);
///  - a Bad value status (e.g. `Bad_UserAccessDenied`) propagates  -  it must NOT degrade to `nullopt`, which
///    would silently skip a needed trust-list update;
///  - an Uncertain Result or value status, with or without a value, is refused with Bad_InternalError
///    (`ReadAnswerUncertain`): the update decision is taken only on a Good answer;
///  - an empty Variant  to  `nullopt` (the server published no LastUpdateTime  -  the "force download"
///  marker);
///  - a non-`DateTime` value  to  the `Variant::to<DateTime>()` coercion error (a malformed value is not
///  absent);
///  - otherwise the `DateTime`.
[[nodiscard]] ua::Result<std::optional<ua::DateTime>> interpret_trust_list_last_update_time(
  ua::Result<ua::DataValue> readResult);

/// Decodes a downloaded TrustListType File body (a raw UA-Binary `TrustListDataType`, no ExtensionObject
/// wrapper  -  the authoritative in-repo wire shape, cf. the server's `TrustListManager` round-trip) into a
/// `TrustListDataType`. STRICT: an empty body, a body not fully consumed on decode (the in-repo decoder is
/// lenient and pads past EOF with zeros without throwing, so truncation would otherwise decode to a partial/
/// empty list), or a body that throws in the decoder all become a source-tagged `Bad_DecodingError`  -  never
/// a silent empty trust list that would replace the client's trust anchors with nothing.
[[nodiscard]] ua::Result<ua::TrustListDataType> decode_trust_list_body(const ua::ByteString& body);

}  // namespace ua::client::detail

#endif  // UA_PULL_CERT_TRUST_LIST_CODEC_H
