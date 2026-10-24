// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_discrepancy_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_discrepancy_alarm_payload.h"

#include <cmath>

namespace ua
{

// --- Configuration ---

void DiscrepancyAlarmLogic::set_target_value_node(NodeId nodeId)
{
  mTargetValueNode = std::move(nodeId);
}

void DiscrepancyAlarmLogic::set_expected_time(double ms)
{
  mExpectedTimeMs = ms;
}

void DiscrepancyAlarmLogic::set_tolerance(double tolerance)
{
  mTolerance = tolerance;
}

void DiscrepancyAlarmLogic::set_target_value(Variant value)
{
  mTargetValue = std::move(value);
}

// --- Helpers ---

bool DiscrepancyAlarmLogic::try_extract_double(const Variant& value, double& out)
{
  if (auto* d = value.try_as<double>())
  {
    out = *d;
    return true;
  }
  if (auto* f = value.try_as<float>())
  {
    out = static_cast<double>(*f);
    return true;
  }
  if (auto* i = value.try_as<int32_t>())
  {
    out = static_cast<double>(*i);
    return true;
  }
  if (auto* u = value.try_as<uint32_t>())
  {
    out = static_cast<double>(*u);
    return true;
  }
  if (auto* i = value.try_as<int16_t>())
  {
    out = static_cast<double>(*i);
    return true;
  }
  if (auto* u = value.try_as<uint16_t>())
  {
    out = static_cast<double>(*u);
    return true;
  }
  if (auto* i = value.try_as<int8_t>())
  {
    out = static_cast<double>(*i);
    return true;
  }
  if (auto* u = value.try_as<uint8_t>())
  {
    out = static_cast<double>(*u);
    return true;
  }
  if (auto* i = value.try_as<int64_t>())
  {
    out = static_cast<double>(*i);
    return true;
  }
  if (auto* u = value.try_as<uint64_t>())
  {
    out = static_cast<double>(*u);
    return true;
  }
  return false;
}

bool DiscrepancyAlarmLogic::is_at_target(const Variant& value) const
{
  if (mTolerance.has_value())
  {
    double inputVal = 0.0;
    double targetVal = 0.0;

    if (!try_extract_double(value, inputVal) || !try_extract_double(mTargetValue, targetVal))
    {
      // Non-numeric: fall through to exact comparison
      return value == mTargetValue;
    }

    return std::abs(inputVal - targetVal) <= *mTolerance;
  }

  return value == mTargetValue;
}

// --- Input evaluation ---

ConditionStateTransition DiscrepancyAlarmLogic::evaluate_input(const Variant& value, DateTime timestamp)
{
  if (is_at_target(value))
  {
    // Value reached target - clear tracking and deactivate if active
    mDiscrepancyStart.reset();
    if (active())
    {
      return deactivate();
    }
    return {};
  }

  // Value is off-target
  if (!mDiscrepancyStart.has_value())
  {
    // Start tracking discrepancy
    mDiscrepancyStart = timestamp;
  }

  if (mExpectedTimeMs > 0.0 && mDiscrepancyStart.has_value())
  {
    auto elapsed = timestamp.value() - mDiscrepancyStart->value();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (static_cast<double>(elapsedMs) >= mExpectedTimeMs)
    {
      // Expected time exceeded - activate
      if (!active())
      {
        return activate(severity() > 0 ? severity() : 500);
      }
    }
  }

  return {};
}

// --- Event building ---

std::unique_ptr<BaseEvent> DiscrepancyAlarmLogic::build_event() const
{
  auto event = std::make_unique<DiscrepancyAlarmPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields: every one - ShelvingState, MaxTimeShelved, InputNode and the optional
  // states included - from the filler the plain alarm uses, so a subtype cannot drift from it.
  populate_alarm_payload_fields(*event);

  // DiscrepancyAlarmPayload fields
  event->targetValueNode = mTargetValueNode;
  event->expectedTime = Variant{mExpectedTimeMs};
  event->tolerance = mTolerance;  // event is freshly constructed; copy the optional through as-is

  return event;
}

// --- Protected accessors ---

const NodeId& DiscrepancyAlarmLogic::target_value_node() const
{
  return mTargetValueNode;
}

double DiscrepancyAlarmLogic::expected_time_ms() const
{
  return mExpectedTimeMs;
}

const std::optional<double>& DiscrepancyAlarmLogic::tolerance() const
{
  return mTolerance;
}

}  // namespace ua
