// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LIMIT_ALARM_PAYLOAD_H
#define UA_LIMIT_ALARM_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_alarm_condition_payload.h"
#include <optional>

namespace ua
{

/// Event payload for the OPC UA LimitAlarmType.
/// @ingroup ua_information_model
struct LimitAlarmPayload : public AlarmConditionPayload
{
  /// The `HighHighLimit` event field.
  std::optional<double> highHighLimit;
  /// The `HighLimit` event field.
  std::optional<double> highLimit;
  /// The `LowLimit` event field.
  std::optional<double> lowLimit;
  /// The `LowLowLimit` event field.
  std::optional<double> lowLowLimit;
  /// The `BaseHighHighLimit` event field.
  std::optional<double> baseHighHighLimit;
  /// The `BaseHighLimit` event field.
  std::optional<double> baseHighLimit;
  /// The `BaseLowLimit` event field.
  std::optional<double> baseLowLimit;
  /// The `BaseLowLowLimit` event field.
  std::optional<double> baseLowLowLimit;
  /// The `SeverityHighHigh` event field.
  std::optional<uint16_t> severityHighHigh;
  /// The `SeverityHigh` event field.
  std::optional<uint16_t> severityHigh;
  /// The `SeverityLow` event field.
  std::optional<uint16_t> severityLow;
  /// The `SeverityLowLow` event field.
  std::optional<uint16_t> severityLowLow;
  /// The `HighHighDeadband` event field.
  std::optional<double> highHighDeadband;
  /// The `HighDeadband` event field.
  std::optional<double> highDeadband;
  /// The `LowDeadband` event field.
  std::optional<double> lowDeadband;
  /// The `LowLowDeadband` event field.
  std::optional<double> lowLowDeadband;

  /// Constructs the payload with the event type's default field values.
  LimitAlarmPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_LIMIT_ALARM_PAYLOAD_H
