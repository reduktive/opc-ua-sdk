// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_discrete_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_discrete_alarm_payload.h"

namespace ua
{

std::unique_ptr<BaseEvent> DiscreteAlarmLogic::build_event() const
{
  auto event = std::make_unique<DiscreteAlarmPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields: every one - ShelvingState, MaxTimeShelved, InputNode and the optional
  // states included - from the filler the plain alarm uses, so a subtype cannot drift from it.
  populate_alarm_payload_fields(*event);

  return event;
}

}  // namespace ua
