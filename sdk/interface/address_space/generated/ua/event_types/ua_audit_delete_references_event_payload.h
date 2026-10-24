// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AUDIT_DELETE_REFERENCES_EVENT_PAYLOAD_H
#define UA_AUDIT_DELETE_REFERENCES_EVENT_PAYLOAD_H

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_audit_node_management_event_payload.h"

namespace ua
{

/// Event payload for the OPC UA AuditDeleteReferencesEventType.
/// @ingroup ua_information_model
struct AuditDeleteReferencesEventPayload : public AuditNodeManagementEventPayload
{
  /// The `ReferencesToDelete` event field.
  Variant referencesToDelete{};

  /// Constructs the payload with the event type's default field values.
  AuditDeleteReferencesEventPayload();
  /// Polymorphically deep-copies this event payload.
  /// @return A heap-allocated copy held by its `BaseEvent` base.
  std::unique_ptr<BaseEvent> clone() const override;
  /// Resolves a field value by its browse path; used to evaluate event filters.
  /// @param browse_path The field's browse path relative to the event.
  /// @return The field value, or an empty `Variant` if the path does not match a field.
  Variant resolve_field(std::span<const QualifiedName> browse_path) const override;
};

}  // namespace ua
#endif  // !UA_AUDIT_DELETE_REFERENCES_EVENT_PAYLOAD_H
