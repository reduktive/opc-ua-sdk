// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Sink interfaces for pushing events and monitored-item samples into the server pipeline.
/// @ingroup address_space

#ifndef UA_SINKS_H
#define UA_SINKS_H

#include "ua_base_event.h"
#include "ua_data_value.h"
#include "ua_integer_id.h"
#include "ua_request_info.h"
#include "ua_status_code.h"

#include <memory>
#include <utility>
#include <vector>

namespace ua
{

/// Sink that accepts OPC UA events for routing into the server's event pipeline.
///
/// Implementations are thread-safe: an event may be submitted from any thread,
/// and the implementation posts it to an internal strand for routing and
/// dispatch to subscribers. A reference to a sink is handed to each namespace
/// (via its namespace context) so that proxy namespaces can inject events
/// originating in external systems.
///
/// @ingroup address_space
class EventSink
{
public:
  EventSink() = default;

  EventSink(const EventSink&) = delete;
  EventSink& operator=(const EventSink&) = delete;
  EventSink(EventSink&&) = delete;
  EventSink& operator=(EventSink&&) = delete;

  /// Submits an event for delivery through the server's event pipeline.
  ///
  /// Thread-safe; may be called from any thread. Any of the mandatory
  /// timestamping/identity fields left unset on @p event are auto-filled before
  /// dispatch: @ref BaseEvent::eventId if empty, @ref BaseEvent::receiveTime
  /// always, and @ref BaseEvent::time if null.
  ///
  /// @param[in,out] event Event to emit. Borrowed for the duration of the call
  ///                      only and not retained; the implementation may mutate
  ///                      the auto-filled fields described above. The caller
  ///                      retains ownership.
  virtual void emit(BaseEvent& event) = 0;

  /// Destroys the sink. Virtual to allow destruction through this interface.
  virtual ~EventSink() = default;
};

/// Batch delivery interface through which a namespace pushes sampled values into a subscription.
///
/// One SampleSink exists per Subscription and is shared (via `shared_ptr`) across all monitored
/// items of that subscription, regardless of which namespace owns the source nodes. The namespace
/// accumulates samples internally and posts them in batches at whatever granularity it chooses
/// (per sampling tick, per event cycle, etc.), rather than one call per sample.
///
/// All methods are thread-safe and callable from any thread; implementations must not block the
/// caller. The sink is held by `shared_ptr`, so it remains alive for the duration of any in-flight
/// call even if the subscription is concurrently torn down.
/// @ingroup address_space
class SampleSink
{
public:
  SampleSink() = default;
  virtual ~SampleSink() = default;

  SampleSink(const SampleSink&) = delete;
  SampleSink& operator=(const SampleSink&) = delete;
  SampleSink(SampleSink&&) = delete;
  SampleSink& operator=(SampleSink&&) = delete;

  /// Posts a batch of sampled values into the subscription.
  ///
  /// Each entry pairs the originating monitored-item id with its newly sampled value. Ownership of
  /// @p samples is transferred to the sink. Thread-safe and lock-free; callable from any thread.
  ///
  /// @param samples Sampled values to deliver, each as `(monitoredItemId, DataValue)`.
  virtual void push(std::vector<std::pair<IntegerId, DataValue>> samples) = 0;

  /// Reports that a monitored item's source node was deleted or became unavailable.
  ///
  /// The subscription transitions the affected item to the given status. Thread-safe; callable from
  /// any thread.
  ///
  /// @param monitoredItemId Item whose source is no longer sampleable.
  /// @param reason          Status code describing why the source became unavailable.
  virtual void invalidate(IntegerId monitoredItemId, StatusCode reason) = 0;

  /// Reports that a semantic property of a monitored item's value changed.
  ///
  /// The item must deliver one data-change carrying the SemanticsChanged StatusCode bit, even through
  /// a deadband (e.g. an AnalogItem's EURange change - CTT Data Access Analog 008). The default
  /// implementation is a no-op: a sink that does not track semantics (test doubles, or sinks whose
  /// upstream already sets the bit) ignores it. Thread-safe; callable from any thread.
  ///
  /// @param monitoredItemId Item whose value semantics changed.
  virtual void mark_semantics_changed(IntegerId monitoredItemId)
  {
    (void)monitoredItemId;
  }

  /// Reports that the structure of a monitored item's value changed: the DataTypeEncoding its Variable's
  /// Value is serialized with, as when the Variable's DataType changes.
  ///
  /// The item must deliver one data-change carrying the StructureChanged StatusCode bit: the value queued
  /// and not yet published, else one made from the value last published, else the next value it takes.
  /// When a queue overflow discards the notification that carries the bit, the next notification in the
  /// queue carries it (OPC 10000-4 7.39.1 Table 180). The default implementation is a no-op: a sink that
  /// does not track structure (test doubles, or sinks whose upstream already sets the bit) ignores it.
  /// Thread-safe; callable from any thread.
  ///
  /// @param monitoredItemId Item whose value structure changed.
  virtual void mark_structure_changed(IntegerId monitoredItemId)
  {
    (void)monitoredItemId;
  }

  /// The caller this subscription's items are sampled for now: its Session's current @ref CallerInfo, which
  /// changes when the Session's user changes, the subscription is transferred, or the Session's Roles are
  /// refreshed. Null for a sink with no Session, whose items are read as the server's own reads.
  ///
  /// The SDK's sampling asks once per tick and reads the sink's due items for the answer, so a change takes
  /// effect at the next tick with no call into the namespace. A namespace that samples by itself asks at its
  /// own tick; it does not keep the answer beyond the reads it makes with it. The default answers null.
  /// Thread-safe; callable from any thread.
  ///
  /// @return The current caller, or null.
  virtual std::shared_ptr<const CallerInfo> caller() const
  {
    return nullptr;
  }

  /// Disconnects the namespace from this sink.
  ///
  /// Called when the namespace is shutting down or no longer monitoring any items for this
  /// subscription. After this returns, the namespace makes no further calls on the sink. Thread-safe;
  /// callable from any thread.
  virtual void detach() = 0;
};

}  // namespace ua

#endif  // !UA_SINKS_H
