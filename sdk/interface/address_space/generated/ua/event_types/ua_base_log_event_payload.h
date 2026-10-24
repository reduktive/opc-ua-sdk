// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BASE_LOG_EVENT_PAYLOAD_H
#define UA_BASE_LOG_EVENT_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_base_event.h"
#include <optional>

namespace ua
{

/// Event payload for the OPC UA BaseLogEventType.
/// @ingroup ua_information_model
struct BaseLogEventPayload : public BaseEvent
{
  /// The `ConditionClassId` event field.
  NodeId conditionClassId{};
  /// The `ConditionClassName` event field.
  LocalizedText conditionClassName{};
  /// The `ErrorCode` event field.
  std::optional<StatusCode> errorCode;
  /// The `ErrorCodeNode` event field.
  std::optional<NodeId> errorCodeNode;

  /// Constructs the payload with the event type's default field values.
  BaseLogEventPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_BASE_LOG_EVENT_PAYLOAD_H
