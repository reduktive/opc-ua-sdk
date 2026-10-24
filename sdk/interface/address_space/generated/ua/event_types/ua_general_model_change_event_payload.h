// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_GENERAL_MODEL_CHANGE_EVENT_PAYLOAD_H
#define UA_GENERAL_MODEL_CHANGE_EVENT_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_base_model_change_event_payload.h"

namespace ua
{

/// Event payload for the OPC UA GeneralModelChangeEventType.
/// @ingroup ua_information_model
struct GeneralModelChangeEventPayload : public BaseModelChangeEventPayload
{
  /// The `Changes` event field.
  Variant changes{};

  /// Constructs the payload with the event type's default field values.
  GeneralModelChangeEventPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_GENERAL_MODEL_CHANGE_EVENT_PAYLOAD_H
