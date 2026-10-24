// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BASE_EVENT_H
#define UA_BASE_EVENT_H

/// @file
/// @brief Base class for OPC UA event payloads in the address space.
/// @ingroup address_space

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_string.h"
#include "ua_utc_time.h"
#include "ua_variant.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace ua
{

/// Base class for all OPC UA events.
///
/// Holds the nine mandatory `BaseEventType` properties as concrete members for O(1)
/// access. Subclasses (generated or hand-written) add type-specific fields and override
/// resolve_field() to expose them.
///
/// This is a pure value type: no async, no strands, no I/O. Instances are constructed,
/// populated, and handed to the EventBus, which fills in any unset auto-assigned fields
/// (see the per-member notes) before dispatch.
/// @ingroup address_space
class BaseEvent
{
public:
  // --- Mandatory BaseEventType fields ---

  /// Unique identifier for this event occurrence.
  ///
  /// Auto-assigned by the EventBus if empty at emission time.
  ByteString eventId;

  /// NodeId of the EventType (e.g. `ObjectTypeId::SystemStatusChangeEventType`).
  ///
  /// Set by generated subtype constructors.
  NodeId eventType;

  /// NodeId of the node that is the source of the event.
  NodeId sourceNode;

  /// Human-readable description of the event source.
  String sourceName;

  /// Time the event occurred.
  ///
  /// Auto-assigned by the EventBus if null at emission time.
  UtcTime time;

  /// Time the server received the event.
  ///
  /// Always auto-assigned by the EventBus, overwriting any value set by the caller.
  UtcTime receiveTime;

  /// Human-readable event description.
  LocalizedText message;

  /// Severity from 1 (lowest) to 1000 (highest).
  uint16_t severity{0};

  // --- Optional BaseEventType fields ---

  /// NodeId of the condition class this event belongs to, if any.
  std::optional<NodeId> conditionClassId;

  /// Human-readable name of the condition class named by condition_class_id, if any.
  std::optional<LocalizedText> conditionClassName;

  /// NodeId of the ConditionType instance this event is about (the ConditionId), if any.
  ///
  /// Set for condition-derived events. A `SimpleAttributeOperand` with an empty browse path and the
  /// NodeId attribute (the standard ConditionId selector, Part 9 / Part 4 7.4.4.5) resolves to this.
  std::optional<NodeId> conditionNodeId;

  // --- Field resolution ---

  /// Resolves a field by browse path for EventFilter evaluation.
  ///
  /// The browse path is relative to the EventType (e.g. `{"Severity"}` selects
  /// `BaseEventType.Severity`). Subtypes override this to expose their own fields,
  /// typically delegating to resolve_base_field() for the mandatory properties first.
  ///
  /// @param browsePath Relative browse path of the field to resolve.
  /// @return The field value, or a null Variant if the field is not part of this
  ///         event type.
  /// @see resolve_base_field
  virtual Variant resolve_field(std::span<const QualifiedName> browsePath) const;

  /// Creates a heap-allocated copy preserving the concrete event type.
  ///
  /// Used by the EventBus to share events across subscriptions without slicing.
  /// Subtypes override this to clone their own fields.
  ///
  /// @return An owning pointer to a copy with the same dynamic type as `*this`.
  virtual std::unique_ptr<BaseEvent> clone() const;

  /// Returns the EventType id in URI-bearing form.
  ///
  /// NS0 events live in namespace 0, so the default simply wraps event_type. A
  /// companion-spec event type lives in the spec's namespace, whose runtime index is
  /// only known to the emitting server; generated companion payloads override this to
  /// carry their spec URI so the server can resolve event_type to a concrete NodeId at
  /// emit time.
  ///
  /// @return The EventType identifier as an ExpandedNodeId.
  virtual ExpandedNodeId event_type_expanded() const;

  /// Returns true for condition-derived events (Condition and all subtypes).
  ///
  /// Used by the subscription layer to detect condition event loss on queue overflow
  /// and trigger RefreshRequiredEvent emission (Part 9 5.7.2).
  ///
  /// @return `true` if this event derives from ConditionType, otherwise `false`.
  virtual bool is_condition_event() const;

  /// The resolved EventType supertype chain for this event occurrence:
  /// `[event_type, parent, ..., BaseEventType]`.
  ///
  /// Populated by the EventBus at dispatch from the address-space `HasSubtype`
  /// hierarchy (the spec's source of truth for EventFilter `OfType` subtype matching,
  /// Part 4 7.7.3). The subscription layer's filter evaluation tests membership in
  /// this chain. Empty for events not dispatched through the EventBus (e.g. direct
  /// unit-test evaluation), in which case only an exact event_type match is possible.
  ///
  /// Shared and immutable so all occurrences of the same EventType reuse one cached
  /// chain. NOT part of the address space or the wire encoding - it is resolved type
  /// metadata carried alongside the event, like event_type.
  std::shared_ptr<const std::vector<NodeId>> eventTypeHierarchy;

  BaseEvent() = default;
  virtual ~BaseEvent() = default;

  /// Copy-constructs a BaseEvent; the field snapshots are value members, so the copy is independent.
  BaseEvent(const BaseEvent&) = default;
  /// Copy-assigns a BaseEvent; the field snapshots are value members, so the copy is independent.
  /// @return Reference to this event.
  BaseEvent& operator=(const BaseEvent&) = default;
  /// Move-constructs a BaseEvent, transferring the field snapshots from the source.
  BaseEvent(BaseEvent&&) = default;
  /// Move-assigns a BaseEvent, transferring the field snapshots from the source.
  /// @return Reference to this event.
  BaseEvent& operator=(BaseEvent&&) = default;

protected:
  /// Resolves a mandatory `BaseEventType` field by browse path.
  ///
  /// Provided for subtype implementations of resolve_field(): generated subtypes call
  /// this first for the nine mandatory properties, then check their own fields.
  ///
  /// @param browsePath Relative browse path of the field to resolve.
  /// @return The mandatory field value, or a null Variant if `browse_path` does not
  ///         name a mandatory `BaseEventType` field.
  /// @see resolve_field
  Variant resolve_base_field(std::span<const QualifiedName> browsePath) const;
};

}  // namespace ua

#endif  // !UA_BASE_EVENT_H
