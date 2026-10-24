// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RETAINED_NOTIFICATION_AUTHORIZATION_H
#define UA_RETAINED_NOTIFICATION_AUTHORIZATION_H

#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_event_type_model.h"
#include "ua_integer_id.h"
#include "ua_node_id.h"
#include "ua_numeric_range.h"

#include <memory>
#include <optional>

namespace ua
{

class BaseEvent;

namespace server
{

class CompiledEventFilter;

/// User-independent input and stable subject retained alongside one data-change notification.
///
/// The value has received no identity-derived projection. For an attribute whose value the server
/// produces (UserAccessLevel, UserWriteMask, UserExecutable, RolePermissions, UserRolePermissions) it is the
/// whole value of the attribute the namespace holds, and @ref indexRange is the MonitoredItem's IndexRange,
/// which a Republish applies after projecting it again, so the notification keeps the range it was
/// published with. For any other attribute the value is as its producer narrowed it, and @ref indexRange is
/// empty. Absence of the value is an explicit conservative-redaction state, never permission to reuse the
/// wire value.
struct RetainedDataProjection
{
  IntegerId monitoredItemId{0};
  NodeId subject;
  AttributeId attribute{AttributeId::Value};
  std::optional<DataValue> userIndependentValue;
  NumericRange indexRange{};
};

/// User-independent input and accessor-free authorization metadata retained alongside one Event.
///
/// These fields are deliberately outside the wire NotificationMessage. The raw Event and immutable
/// filter/model copies reproduce the original selected and where values; only stable NodeIds survive
/// in their authorization metadata, so Republish must resolve fresh NodeAccessor handles.
struct RetainedEventProjection
{
  IntegerId clientHandle{0};
  NodeId sourceNode;
  NodeId eventType;
  std::shared_ptr<const BaseEvent> userIndependentEvent;
  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel;
  std::shared_ptr<const CompiledEventFilter> filter;

  bool complete() const noexcept
  {
    return userIndependentEvent && filter;
  }
};

}  // namespace server
}  // namespace ua

#endif  // UA_RETAINED_NOTIFICATION_AUTHORIZATION_H
