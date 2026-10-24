// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONDITION_PAYLOAD_H
#define UA_CONDITION_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_base_event.h"
#include "ua_variable_states.h"
#include "ua_array.h"
#include <optional>

namespace ua
{

/// Event payload for the OPC UA ConditionType.
/// @ingroup ua_information_model
struct ConditionPayload : public BaseEvent
{
  /// The `ConditionClassId` event field.
  NodeId conditionClassId{};
  /// The `ConditionClassName` event field.
  LocalizedText conditionClassName{};
  /// The `ConditionSubClassId` event field.
  std::optional<Array<NodeId>> conditionSubClassId;
  /// The `ConditionSubClassName` event field.
  std::optional<Array<LocalizedText>> conditionSubClassName;
  /// The `ConditionName` event field.
  String conditionName{};
  /// The `BranchId` event field.
  NodeId branchId{};
  /// The `Retain` event field.
  bool retain{};
  /// The `SupportsFilteredRetain` event field.
  bool supportsFilteredRetain{};
  /// The `EnabledState` event field.
  TwoStateVariableState enabledState{};
  /// The `Quality` event field.
  ConditionVariableState quality{};
  /// The `LastSeverity` event field.
  ConditionVariableState lastSeverity{};
  /// The `Comment` event field.
  ConditionVariableState comment{};
  /// The `ClientUserId` event field.
  String clientUserId{};

  /// Constructs the payload with the event type's default field values.
  ConditionPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_CONDITION_PAYLOAD_H
