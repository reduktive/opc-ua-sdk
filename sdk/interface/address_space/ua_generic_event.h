// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Property-bag event payload for event types without generated C++ structs.
/// @ingroup address_space

#ifndef UA_GENERIC_EVENT_H
#define UA_GENERIC_EVENT_H

#include "ua_base_event.h"

#include <utility>
#include <vector>

namespace ua
{

/// Property-bag event for event types that have no generated C++ struct.
///
/// Extends @ref BaseEvent with a set of extension fields keyed by browse path,
/// letting an application emit custom or user-defined event types without
/// code-generating a payload class. The mandatory BaseEventType properties are
/// set through the inherited @ref BaseEvent members; type-specific properties
/// are added with @ref set_field. Like @ref BaseEvent this is a plain data type
/// - no async, no strands, no I/O - so instances are not thread-safe and must
/// be externally synchronised if shared.
///
/// @see BaseEvent
/// @ingroup address_space
class GenericEvent : public BaseEvent
{
public:
  /// Constructs an event of the given EventType.
  ///
  /// @param typeId NodeId of the EventType this occurrence represents; moved
  ///                into the inherited @ref BaseEvent::eventType member.
  explicit GenericEvent(NodeId typeId)
  {
    eventType = std::move(typeId);
  }

  /// Sets an extension field, addressed by its browse path relative to the
  /// EventType.
  ///
  /// Adds or replaces the field at @p browsePath. The path is relative to the
  /// EventType (e.g. ``{"PressureValue"}``); a multi-segment path addresses a
  /// nested property. The stored value is later returned by @ref resolve_field
  /// during EventFilter evaluation.
  ///
  /// @param browsePath Browse path identifying the field; moved into storage.
  /// @param value       Field value; moved into storage. A null Variant clears
  ///                    the field's value but keeps the path addressable.
  void set_field(std::vector<QualifiedName> browsePath, Variant value);

  /// Resolves a field by browse path, checking mandatory base fields first, then
  /// the extension fields added via @ref set_field.
  ///
  /// @param browsePath Browse path relative to the EventType.
  /// @return The field value, or a null Variant if no base or extension field
  ///         matches @p browsePath.
  /// @see set_field, BaseEvent::resolve_field
  Variant resolve_field(std::span<const QualifiedName> browsePath) const override;

  /// Creates a heap-allocated copy preserving the concrete type and extension
  /// fields.
  ///
  /// Called by the EventBus to share an event across subscriptions without
  /// slicing. Overriding @ref BaseEvent::clone is required here: the base
  /// implementation would copy only the @ref BaseEvent slice and drop the
  /// extension fields.
  ///
  /// @return An owning copy of this event as a @ref BaseEvent pointer; never
  ///         null.
  /// @see BaseEvent::clone
  std::unique_ptr<BaseEvent> clone() const override;

private:
  std::vector<std::pair<std::vector<QualifiedName>, Variant>> mExtraFields;
};

}  // namespace ua

#endif  // !UA_GENERIC_EVENT_H
