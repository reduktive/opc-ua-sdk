// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_CONDITION_PAYLOAD_H
#define UA_ALARM_CONDITION_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_variable_states.h"
#include <optional>

namespace ua
{

/// Event payload for the OPC UA AlarmConditionType.
/// @ingroup ua_information_model
struct AlarmConditionPayload : public AcknowledgeableConditionPayload
{
  /// The `ActiveState` event field.
  TwoStateVariableState activeState{};
  /// The `InputNode` event field.
  NodeId inputNode{};
  /// The `SuppressedState` event field.
  std::optional<TwoStateVariableState> suppressedState;
  /// The `OutOfServiceState` event field.
  std::optional<TwoStateVariableState> outOfServiceState;
  /// The `ShelvingState` event field.
  std::optional<ShelvedStateVariableState> shelvingState;
  /// The `SuppressedOrShelved` event field.
  bool suppressedOrShelved{};
  /// The `MaxTimeShelved` event field.
  std::optional<Variant> maxTimeShelved;
  /// The `AudibleEnabled` event field.
  std::optional<bool> audibleEnabled;
  /// The `SilenceState` event field.
  std::optional<TwoStateVariableState> silenceState;
  /// The `OnDelay` event field.
  std::optional<Variant> onDelay;
  /// The `OffDelay` event field.
  std::optional<Variant> offDelay;
  /// The `LatchedState` event field.
  std::optional<TwoStateVariableState> latchedState;
  /// The `ReAlarmTime` event field.
  std::optional<Variant> reAlarmTime;

  /// Constructs the payload with the event type's default field values.
  AlarmConditionPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_ALARM_CONDITION_PAYLOAD_H
