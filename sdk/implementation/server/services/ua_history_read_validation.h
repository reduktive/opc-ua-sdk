// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_READ_VALIDATION_H
#define UA_HISTORY_READ_VALIDATION_H

#include "ua_continuation_points.h"
#include "ua_history_read_value_id.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_status_code.h"

#include <vector>

namespace ua::server::history_read_validation
{

// =============================================================================================
// Shared HistoryRead per-operation validation (OPC 10000-4 5.10.3, OPC 10000-11 6.3).
//
// These are the per-item checks the HistoryRead service applies before - or instead of -
// dispatching an operation to a NamespaceHistoryDelegate. Centralising them guarantees every
// code path classifies an item identically: fresh reads, continuation reads, and the
// releaseContinuationPoints fast-path must all use the same rules, so no path can silently skip
// a check (the omission that let a fresh read return Good under releaseContinuationPoints).
// =============================================================================================

/// The kind of history selected by the request's concrete HistoryReadDetails.
enum class HistoryAccessKind
{
  Values,
  Events,
};

/// Whether a node supports the requested kind of historical Read, from its description, and the per-operation
/// StatusCode to report when it does not.
///   - Values: requires a Variable with the HistoryRead AccessLevel bit (OPC 10000-11 5.2). Missing ->
///     Bad_HistoryOperationUnsupported; an Object is Bad_HistoryOperationUnsupported.
///   - Events: requires an Object with the HistoryRead EventNotifier bit. Missing ->
///     Bad_HistoryOperationUnsupported; a Variable is Bad_HistoryOperationUnsupported.
///   - any other node class: Bad_HistoryOperationInvalid (history is undefined for it).
/// A description without an AccessLevel or EventNotifier counts as one without the HistoryRead bit.
/// Returns Status::Good when the node supports the requested historical read.
StatusCode classify_history_access(const NodeDescription& node, HistoryAccessKind requestedAccess);

/// Classification of a HistoryReadValueId's continuation-point field against the continuation
/// points pulled from the session for this request.
enum class ContinuationKind
{
  Fresh,  ///< no continuation point supplied - this is a fresh read
  Found,  ///< a continuation point was supplied and matches a known entry (entry set)
  Invalid,  ///< a continuation point was supplied but is unparseable or unknown
};

struct ContinuationLookup
{
  ContinuationKind kind{ContinuationKind::Invalid};
  HistoryContinuationPoint* entry{nullptr};  ///< non-null only when kind == Found
};

/// Classify `nodeToRead.continuation_point()` against `available`. When a non-empty continuation
/// point parses to a Guid present in `available`, returns Found with `entry` pointing at it; when
/// the field is empty returns Fresh; otherwise Invalid. The returned pointer is borrowed from
/// `available` (valid for that vector's lifetime).
ContinuationLookup lookup_continuation_point(
  const HistoryReadValueId& nodeToRead, std::vector<HistoryContinuationPoint>& available);

/// The per-node return cap actually applied to one HistoryRead operation: the client's own
/// `numValuesPerNode` bounded by the server's advertised limit.
///
/// OPC 10000-11 5.2 defines `MaxReturnDataValues` / `MaxReturnEventValues` as "the maximum number
/// of values that can be returned by the Server FOR EACH HistoricalNode accessed during a request",
/// with 0 meaning no limit - so this is PER NODE, not per request: 50 nodes at a limit of 100 may
/// legitimately return 5000 values, each node with its own continuation point. Returning a
/// continuation point where the client asked for everything is explicitly valid (6.4.3).
///
/// @param requested   The client's `numValuesPerNode` from the request details (0 = "all of them").
/// @param serverLimit The server's configured cap for this data kind (0 = no server limit).
/// @return The cap to hand the delegate: the stricter of the two, treating 0 on either side as
///         "unbounded from that side". Zero only when BOTH are unbounded.
uint32_t effective_max_values_per_node(uint32_t requested, uint32_t serverLimit);

}  // namespace ua::server::history_read_validation

#endif  // UA_HISTORY_READ_VALIDATION_H
