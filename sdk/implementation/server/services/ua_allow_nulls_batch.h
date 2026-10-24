// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALLOW_NULLS_BATCH_H
#define UA_ALLOW_NULLS_BATCH_H

#include "ua_address_space.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_status_code.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace ua::server
{

/// A Variable's AllowNulls verdict: Good with no value when it has no AllowNulls Property, Good with the
/// Property's Boolean Value, or the reason the Property could not be resolved or read.
struct AllowNullsOutcome
{
  StatusCode status;
  std::optional<bool> allowed;
};

/// The AllowNulls Properties of a request's Variables (NR-24 5b), with one namespace call per namespace per
/// round: one `read_references_async` of the Variables' forward HasProperty References, one lookup of their
/// targets, one `read_values_async` (no caller, maxAge 0) of the AllowNulls Properties found.
///
/// Per Variable, as `instance_utils::find_child_variable_accessor_by_browse_name_async` decides it: the first
/// target in Reference order that is found and whose BrowseName is (0, "AllowNulls") is the Property; when
/// none is, the first target whose lookup failed other than with `Bad_NodeIdUnknown` gives the answer;
/// otherwise the Variable has no Property. A Property that is not a Variable is `Bad_TypeMismatch`; a Value
/// that cannot be read, whose status is Bad, or that is not a Boolean is refused as the Write service refuses
/// it. A deleted Variable, and any `Bad_NodeIdUnknown`, is a Variable without the Property.
///
/// The SDK decides on these answers itself, so it acts only on a Good one. An Uncertain answer, whether or
/// not it holds References, a Node or a Value, is refused with `Bad_InternalError` and the ErrorDetail code
/// `ReferencesAnswerUncertain`, `LookupAnswerUncertain` or `ReadAnswerUncertain` (summary "The SDK does not
/// act on an answer the namespace is uncertain of"), whose cause is the Uncertain code with its detail.
class AllowNullsBatch
{
public:
  /// The verdict of each Variable of @p variables, in order.
  ///
  /// @param browseLimit The operation limit of a `read_references_async` call (maxNodesPerBrowse).
  /// @param readLimit   The operation limit of a `read_values_async` call (maxNodesPerRead).
  static void resolve_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit,
    std::optional<uint32_t> readLimit, std::function<void(std::vector<AllowNullsOutcome>)> done) noexcept;
};

}  // namespace ua::server

#endif  // !UA_ALLOW_NULLS_BATCH_H
