// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_off_normal_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_off_normal_alarm_payload.h"

namespace ua
{

// --- Configuration ---

void OffNormalAlarmLogic::set_normal_state(Variant normalValue)
{
  mNormalState = std::move(normalValue);
}

void OffNormalAlarmLogic::set_normal_state_node(NodeId nodeId)
{
  mNormalStateNode = std::move(nodeId);
}

// --- Input evaluation ---

ConditionStateTransition OffNormalAlarmLogic::evaluate_input(const Variant& value, DateTime /*timestamp*/)
{
  if (value != mNormalState)
  {
    // Off-normal: activate with current severity (or default 500)
    if (!active())
    {
      return activate(severity() > 0 ? severity() : 500);
    }
    return {};
  }
  else
  {
    // Normal: deactivate if currently active
    if (active())
    {
      return deactivate();
    }
    return {};
  }
}

// --- Event building ---

std::unique_ptr<BaseEvent> OffNormalAlarmLogic::build_event() const
{
  auto event = std::make_unique<OffNormalAlarmPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields: every one - ShelvingState, MaxTimeShelved, InputNode and the optional
  // states included - from the filler the plain alarm uses, so a subtype cannot drift from it.
  populate_alarm_payload_fields(*event);

  // OffNormalAlarmPayload fields
  event->normalState = mNormalStateNode;

  return event;
}

// --- Protected accessors ---

const Variant& OffNormalAlarmLogic::normal_state() const
{
  return mNormalState;
}

const NodeId& OffNormalAlarmLogic::normal_state_node() const
{
  return mNormalStateNode;
}

}  // namespace ua
