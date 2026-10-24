// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EU_RANGE_RESOLVER_H
#define UA_EU_RANGE_RESOLVER_H

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_request_info.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace ua::server
{

/// One Variable's EURange Property, as @ref EuRangeResolver found and read it.
struct EuRangeProperty
{
  /// The Property's NodeId; null when no Property was found.
  NodeId property;
  /// The Property's Value as its namespace answered it Good (with any Good subcode), a Bad quality included;
  /// or why there is none: `Bad_NodeIdUnknown` when the Variable has no EURange Property, the failure of the
  /// Variable's References read or of a candidate's lookup (below), `Bad_TypeMismatch` when the Property is
  /// not a Variable, or the read's failure. A read answered Uncertain, whether or not it holds a Value, is
  /// refused with `Bad_InternalError` (`ReadAnswerUncertain`, its cause the Uncertain code).
  DataValueResult value{StatusCode{Status::BadNodeIdUnknown}};
};

/// The EURange Properties of PercentDeadband items' Variables (OPC 10000-8 6.2), for CreateMonitoredItems,
/// ModifyMonitoredItems and the re-read after a SemanticsChanged mark, with one namespace call of each kind
/// per namespace: one `read_references_async` of the Variables' forward HasProperty References, one lookup of
/// their distinct local targets, one `read_values_async` (no caller, maxAge 0, no IndexRange) of the
/// Properties found (NR-26 step 4a, NR-62 rule 2).
///
/// Per Variable, as `instance_utils::find_child_variable_accessor_by_browse_name_async` decides it (DL-50
/// (3), DL-53): the first target in Reference order that is found and whose BrowseName is (0, "EURange") is
/// the Property, whatever its NodeClass; when none is, the first target whose lookup failed other than with
/// `Bad_NodeIdUnknown` gives the answer; otherwise the Variable has none. A deleted Variable has none.
///
/// The SDK computes a deadband from these answers, so it acts only on a Good one. An Uncertain answer to the
/// References read, a lookup or the Value read, whether or not it holds References, a Node or a Value, is
/// refused with `Bad_InternalError` and the ErrorDetail code `ReferencesAnswerUncertain`,
/// `LookupAnswerUncertain` or `ReadAnswerUncertain` (summary "The SDK does not act on an answer the namespace
/// is uncertain of"), whose cause is the Uncertain code with its detail.
class EuRangeResolver
{
public:
  /// The EURange Property of each Variable of @p variables, in order.
  ///
  /// @param addressSpace The address space the Properties are looked up in.
  /// @param request      The request served; the server's own for a re-read.
  /// @param variables    The Variables, each found by a lookup for @p request.
  /// @param browseLimit  The operation limit of a `read_references_async` call (maxNodesPerBrowse).
  /// @param done         One answer per Variable, in order; called once, and must not throw.
  static void resolve_async(AddressSpace addressSpace, RequestInfo request,
    std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit,
    std::function<void(std::vector<EuRangeProperty>)> done) noexcept;
};

}  // namespace ua::server

#endif  // !UA_EU_RANGE_RESOLVER_H
