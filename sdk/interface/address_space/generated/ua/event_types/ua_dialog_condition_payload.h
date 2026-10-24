// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIALOG_CONDITION_PAYLOAD_H
#define UA_DIALOG_CONDITION_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_condition_payload.h"
#include "ua_variable_states.h"
#include "ua_array.h"

namespace ua
{

/// Event payload for the OPC UA DialogConditionType.
/// @ingroup ua_information_model
struct DialogConditionPayload : public ConditionPayload
{
  /// The `DialogState` event field.
  TwoStateVariableState dialogState{};
  /// The `Prompt` event field.
  LocalizedText prompt{};
  /// The `ResponseOptionSet` event field.
  Array<LocalizedText> responseOptionSet{};
  /// The `DefaultResponse` event field.
  int32_t defaultResponse{};
  /// The `OkResponse` event field.
  int32_t okResponse{};
  /// The `CancelResponse` event field.
  int32_t cancelResponse{};
  /// The `LastResponse` event field.
  int32_t lastResponse{};

  /// Constructs the payload with the event type's default field values.
  DialogConditionPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_DIALOG_CONDITION_PAYLOAD_H
