// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_EVENT_VALIDATION_H
#define UA_HISTORY_EVENT_VALIDATION_H

#include "ua_address_space.h"
#include "ua_event_type_model.h"
#include "ua_node_id.h"
#include "ua_status_code.h"
#include "ua_update_event_details.h"

#include <functional>
#include <string>
#include <vector>

namespace ua::server::history_event_validation
{

// =============================================================================================
// UpdateEventDetails parameter validation (OPC 10000-11 6.9.4.2).
//
// The Event-history insert path shares its EventFilter type with the Event-history *read* path,
// where every field of that filter is meaningful. On the insert path most of them are not: a
// whereClause selects nothing, an IndexRange slices nothing, and the selectClause is a schema
// declaration rather than a projection. Left unchecked the Client is told its insert succeeded
// while the parameters it believed were doing something did nothing, and the archived Event is
// one no later query can find or trust.
//
// The rules are stated against the Event's own type, so they are answered from the address space
// rather than from a table in this file: the EventType named by the eventData row is resolved,
// its declared fields are collected across the whole supertype chain up to BaseEventType, and the
// selectClause and the row are read against those declarations. That is what makes the check
// hold for a companion-spec EventType nobody compiled in.
// =============================================================================================

/// The verdict on one `UpdateEventDetails`, split the way OPC 10000-11 6.9.4.2 splits it.
///
/// The clause distinguishes faults in the *filter* - which describe the whole operation and are
/// reported once - from faults in an *eventData row*, which are reported per row through
/// `operationResults`. A malformed filter therefore stops the operation before any row is
/// considered, while one unusable row leaves its siblings free to be archived.
struct Outcome
{
  /// Filter-wide verdict: the detail's own `HistoryUpdateResult::statusCode`. Good when the
  /// filter itself conforms; when bad, no row was examined and none may be dispatched.
  StatusCode detailStatus{Status::Good};

  /// Per-row verdict, parallel to `UpdateEventDetails::event_data()`. `Good` means dispatch the
  /// row; `Good_DataIgnored` means dispatch it and report the fields dropped; anything bad means
  /// the row is refused and never reaches the historian.
  std::vector<StatusCode> rowStatus;

  /// Per-row names of the selectClause fields the historian will not store, parallel to
  /// `rowStatus`. Non-empty exactly where `rowStatus` is `Good_DataIgnored`, and carried
  /// separately because OPC 10000-11 6.9.4.2 requires the ignored fields to be named in the
  /// DiagnosticInformation rather than merely counted.
  std::vector<std::vector<std::string>> ignoredFields;

  /// Per-row names of fields whose values cannot be processed as their declared Event field
  /// types, parallel to `rowStatus`. Non-empty exactly where the row is refused with
  /// `Bad_InvalidArgument`; the names are carried to the related DiagnosticInformation.
  std::vector<std::vector<std::string>> invalidFields;

  /// True when at least one row may be handed to the historian.
  [[nodiscard]] bool has_dispatchable_row() const noexcept;
};

/// Completion handler for @ref validate_async. Runs on an address-space worker thread when the
/// validation had to resolve nodes, and inline on the caller's thread when the filter was
/// rejected before any lookup - callers must therefore be re-entrancy safe, as everywhere else
/// in the service core.
using Callback = std::function<void(Outcome)>;
using CollectDeclarationsHook = std::function<void(AddressSpace, NodeId, event_type_model::CollectCallback)>;
using FindNodeHook = std::function<void(AddressSpace, NodeId, AddressSpace::FindNodeCompleteCallback)>;

/// Validate one Event-history update against OPC 10000-11 6.9.4.2.
///
/// Everything the check needs is copied out of @p details before the first asynchronous hop, so
/// the caller is free to destroy the request afterwards. @p addressSpace is used to resolve the
/// EventType named by each row, the fields that type declares, and the SourceNode the row
/// attributes the Event to.
///
/// @param addressSpace The address space the EventType and SourceNode are resolved against.
/// @param details      The update being validated; read synchronously, never retained.
/// @param onComplete          Receives the verdict exactly once. Never throws.
/// @param collectDeclarations Internal EventType-model dependency; empty selects production.
/// @param findNode            Internal SourceNode dependency; empty selects production.
void validate_async(AddressSpace addressSpace, const UpdateEventDetails& details, Callback onComplete,
  CollectDeclarationsHook collectDeclarations = {}, FindNodeHook findNode = {}) noexcept;

}  // namespace ua::server::history_event_validation

#endif  // !UA_HISTORY_EVENT_VALIDATION_H
