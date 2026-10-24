// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>

#include "ua_base_event.h"

#include "ua_data_value.h"
#include "ua_objecttype_id.h"

namespace ua
{

Variant BaseEvent::resolve_field(std::span<const QualifiedName> browsePath) const
{
  return resolve_base_field(browsePath);
}

std::unique_ptr<BaseEvent> BaseEvent::clone() const
{
  return std::make_unique<BaseEvent>(*this);
}

ExpandedNodeId BaseEvent::event_type_expanded() const
{
  // NS0 (and any already-resolved) event type: no spec URI, just the NodeId.
  return ExpandedNodeId{eventType};
}

bool BaseEvent::is_condition_event() const
{
  const NodeId conditionType{ObjectTypeId::ConditionType};
  if (eventType == conditionType)
    return true;

  return eventTypeHierarchy &&
         std::ranges::find(*eventTypeHierarchy, conditionType) != eventTypeHierarchy->end();
}

Variant BaseEvent::resolve_base_field(std::span<const QualifiedName> browsePath) const
{
  if (browsePath.empty())
    return Variant{};

  // BaseEventType fields are all in namespace 0 with a single-element browse path.
  const auto& first = browsePath[0];
  if (first.namespace_index() != 0 || browsePath.size() != 1)
    return Variant{};

  const auto name = static_cast<std::string_view>(first.name());

  if (name == "EventId")
    return Variant{eventId};
  if (name == "EventType")
    return Variant{eventType};
  if (name == "SourceNode")
    return Variant{sourceNode};
  if (name == "SourceName")
    return Variant{sourceName};
  if (name == "Time")
    return Variant{time};
  if (name == "ReceiveTime")
    return Variant{receiveTime};
  if (name == "Message")
    return Variant{message};
  if (name == "Severity")
    return Variant{severity};

  // Optional fields
  if (name == "ConditionClassId" && conditionClassId)
    return Variant{*conditionClassId};
  if (name == "ConditionClassName" && conditionClassName)
    return Variant{*conditionClassName};

  return Variant{};
}

}  // namespace ua
