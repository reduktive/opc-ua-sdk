// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_BACKBONE_OPS_H
#define UA_EVENT_BACKBONE_OPS_H

/// @file
/// @brief The narrow, mockable tier-1 interface the tier-2 @ref ua::client::detail::EventSubscriberImpl
/// (section 8.13)
///        consumes to create / modify / delete its backbone event MonitoredItem(s).
///
/// The design's section 8.2A.13 `SubscriptionOps` role was intended to carry the wire-shaped subscription
/// surface (CreateSubscription / CreateMonitoredItems / ModifyMonitoredItems / DeleteMonitoredItems), but the
/// BUILT `SubscriptionOps` (@ref ua_connection_ops.h) is the pipeline SEND interface (send_publish / republish)  -
/// the wire-shaped surface was never added to it. Rather than widen that role for one consumer, this slice
/// introduces a purpose-built, ISP-narrow interface (per the design specification) that captures
/// EXACTLY the three backbone operations the subscriber needs. A tier-2 unit test drives the subscriber's
/// own coalescing / demux / owner logic against a `FakeEventBackboneOps` with NO `ConnectionImpl`, Session,
/// or executor; the real implementation forwards to @ref ua::client::detail::ConnectionImpl.
/// @ingroup client

#include "ua_event_filter.h"
#include "ua_event_filter_result.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace ua::client::detail
{

/// The location of a bad status carried by an EventFilterResult.
enum class EventFilterDiagnosticKind
{
  SelectClause,
  WhereClauseElement,
  WhereClauseOperand
};

/// One status-bearing EventFilterResult diagnostic. For a select clause or where-clause element,
/// @ref index is its array index and @ref operandIndex is unused. For an operand, @ref index is the
/// where-clause element index and @ref operandIndex is the operand index.
struct EventFilterDiagnostic
{
  EventFilterDiagnosticKind kind = EventFilterDiagnosticKind::SelectClause;
  std::size_t index = 0;
  std::size_t operandIndex = 0;
  ua::StatusCode status;
};

using EventFilterDiagnostics = std::vector<EventFilterDiagnostic>;

/// Extracts every bad select-clause, where-clause element, and where-clause operand status. Good statuses
/// need no advisory and are intentionally omitted.
[[nodiscard]] EventFilterDiagnostics bad_event_filter_diagnostics(const ua::EventFilterResult& result);

/// The server ids + structured `EventFilterResult` diagnostics returned by a backbone create (CL-MI-018).
struct EventBackboneCreated
{
  std::uint32_t subscriptionId = 0;
  std::uint32_t monitoredItemId = 0;
  EventFilterDiagnostics filterDiagnostics;
};

/// The three backbone wire operations the @ref EventSubscriberImpl posts (each internally posts to the
/// connection strand and delivers on the executor  -  the tier-1 contract). A backbone is a Subscription plus
/// one event MonitoredItem on a notifier; the subscriber coalesces N logical consumers onto it.
class EventBackboneOps
{
public:
  EventBackboneOps() = default;
  EventBackboneOps(const EventBackboneOps&) = delete;
  EventBackboneOps& operator=(const EventBackboneOps&) = delete;
  EventBackboneOps(EventBackboneOps&&) = delete;
  EventBackboneOps& operator=(EventBackboneOps&&) = delete;
  virtual ~EventBackboneOps() = default;

  /// Creates a Subscription and an event MonitoredItem on @p notifier carrying @p filter, with
  /// `samplingInterval = 0` and `attributeId = EventNotifier` forced at the wire boundary (CL-MI-013/014).
  /// @p clientHandle is the Connection-unique handle assigned to the backbone MI (for inbound demux).
  virtual void create_backbone_async(ua::NodeId notifier, ua::EventFilter filter, std::uint32_t clientHandle,
    std::uint32_t queueSize, std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept = 0;

  /// Modifies the backbone MI's filter (`ModifyMonitoredItems`). Delivers structured bad statuses from the
  /// returned `EventFilterResult` (or a bad Result).
  virtual void modify_backbone_filter_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::uint32_t clientHandle, ua::EventFilter filter,
    std::function<void(ua::Result<EventFilterDiagnostics>)> callback) noexcept = 0;

  /// Deletes the backbone MI and its Subscription (last-consumer teardown for a non-default backbone).
  virtual void delete_backbone_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::function<void(ua::VoidResult)> callback) noexcept = 0;

  /// Resolves the SUBTYPE CLOSURE of @p roots: every event type that is @p roots or a transitive
  /// `HasSubtype` descendant of one, as the server's own type hierarchy declares it.
  ///
  /// `OfType` is a subtype-inclusive test (OPC 10000-4 7.4.4.5): a server that accepts
  /// `OfType(ConditionType)` delivers every alarm subtype through it. When several consumers coalesce onto
  /// one backbone the wire filter carries their UNION, so the client-side demux decides which consumer
  /// sees which event, and it can only do that against the full subtype closure.
  ///
  /// The result MUST include the roots themselves. A bad Result means the hierarchy could not be
  /// established; the caller's contract is then to isolate the consumer on its own backbone so the SERVER's
  /// filter stays authoritative, never to fall back to exact matching.
  ///
  /// @param roots    The requested event types (the `OfType` operands).
  /// @param callback Receives roots-plus-descendants on success, or a bad Result (on the executor).
  virtual void resolve_event_subtypes_async(std::vector<ua::NodeId> roots,
    std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept = 0;
};

}  // namespace ua::client::detail

#endif  // UA_EVENT_BACKBONE_OPS_H
