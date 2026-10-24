// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_limit_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_exclusive_limit_alarm_payload.h"
#include "ua_limit_alarm_payload.h"
#include "ua_non_exclusive_limit_alarm_payload.h"
#include "ua_object_id.h"
#include "ua_variant.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace ua
{

namespace
{
/// Build a TwoStateVariableState for one non-exclusive limit sub-state from its active flag and the time
/// it last changed. The boolean Id is what event-filter evaluation reads; the localized CurrentState text
/// mirrors it.
TwoStateVariableState limit_substate(bool active, DateTime transitionTime)
{
  TwoStateVariableState state;
  state.id = active;
  state.currentState = LocalizedText{"", active ? "active" : "inactive"};
  state.transitionTime = transitionTime;
  return state;
}

/// Map the active exclusive limit to the ExclusiveLimitStateMachine's CurrentState (Value + .Id) for
/// the ExclusiveLimitAlarm event payload's LimitState field. ActiveLimit::None (alarm inactive) leaves
/// a null state - there is no current limit. State NodeIds: Part 9 ExclusiveLimitStateMachineType.
FiniteStateVariableState exclusive_limit_state(ActiveLimit limit)
{
  switch (limit)
  {
  case ActiveLimit::HighHigh:
    return {LocalizedText{"", "HighHigh"},
      NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_HighHigh)}};
  case ActiveLimit::High:
    return {LocalizedText{"", "High"},
      NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_High)}};
  case ActiveLimit::Low:
    return {LocalizedText{"", "Low"},
      NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_Low)}};
  case ActiveLimit::LowLow:
    return {LocalizedText{"", "LowLow"},
      NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_LowLow)}};
  case ActiveLimit::None:
    break;
  }
  return FiniteStateVariableState{};
}

const double* available_value(const std::optional<ConfiguredLimit>& limit) noexcept
{
  if (!limit || !limit->is_available())
  {
    return nullptr;
  }
  return &*limit->value();
}
}  // namespace

// --- Configuration ---

void LimitAlarmLogic::set_limits(LimitConfig config)
{
  if (!config.highHighLimit.has_value() && !config.highLimit.has_value() && !config.lowLimit.has_value() &&
      !config.lowLowLimit.has_value())
  {
    throw std::invalid_argument("LimitAlarm requires at least one configured limit");
  }

  const double* highHigh = available_value(config.highHighLimit);
  const double* high = available_value(config.highLimit);
  const double* low = available_value(config.lowLimit);
  const double* lowLow = available_value(config.lowLowLimit);

  // Validate ordering among the values the underlying system can actually supply. Unavailable
  // limits remain exposed, but there is no numeric value to compare or evaluate.
  if (highHigh && high)
  {
    if (*highHigh <= *high)
    {
      throw std::invalid_argument("HighHighLimit must be greater than HighLimit");
    }
  }
  if (high && low)
  {
    if (*high <= *low)
    {
      throw std::invalid_argument("HighLimit must be greater than LowLimit");
    }
  }
  if (low && lowLow)
  {
    if (*low <= *lowLow)
    {
      throw std::invalid_argument("LowLimit must be greater than LowLowLimit");
    }
  }
  if (highHigh && low && !high)
  {
    if (*highHigh <= *low)
    {
      throw std::invalid_argument("HighHighLimit must be greater than LowLimit");
    }
  }
  if (high && lowLow && !low)
  {
    if (*high <= *lowLow)
    {
      throw std::invalid_argument("HighLimit must be greater than LowLowLimit");
    }
  }
  if (highHigh && lowLow && !high && !low)
  {
    if (*highHigh <= *lowLow)
    {
      throw std::invalid_argument("HighHighLimit must be greater than LowLowLimit");
    }
  }

  mLimits = config;
}

void LimitAlarmLogic::set_exclusive(bool exclusive)
{
  mExclusive = exclusive;
}

void LimitAlarmLogic::enable_rate_of_change_per_second()
{
  mRateOfChangePerSecond = true;
  mPreviousInputValue.reset();
  mPreviousInputTimestamp.reset();
}

// --- Limit state queries ---

ActiveLimit LimitAlarmLogic::active_limit() const
{
  return mActiveLimit;
}

bool LimitAlarmLogic::high_high_active() const
{
  return mHighHighActive;
}

bool LimitAlarmLogic::high_active() const
{
  return mHighActive;
}

bool LimitAlarmLogic::low_active() const
{
  return mLowActive;
}

bool LimitAlarmLogic::low_low_active() const
{
  return mLowLowActive;
}

const LimitConfig& LimitAlarmLogic::limits() const
{
  return mLimits;
}

bool LimitAlarmLogic::exclusive() const
{
  return mExclusive;
}

// --- Input evaluation ---

ConditionStateTransition LimitAlarmLogic::evaluate_input(const Variant& value, DateTime timestamp)
{
  double inputValue = 0.0;
  if (!try_extract_double(value, inputValue))
  {
    return {};
  }

  if (mRateOfChangePerSecond)
  {
    if (!mPreviousInputValue.has_value() || !mPreviousInputTimestamp.has_value())
    {
      mPreviousInputValue = inputValue;
      mPreviousInputTimestamp = timestamp;
      return {};
    }

    const auto elapsed = timestamp.value() - mPreviousInputTimestamp->value();
    const double elapsedSeconds = std::chrono::duration<double>{elapsed}.count();
    if (elapsedSeconds <= 0.0)
    {
      return {};
    }

    const double previousInputValue = *mPreviousInputValue;
    mPreviousInputValue = inputValue;
    mPreviousInputTimestamp = timestamp;
    inputValue = (inputValue - previousInputValue) / elapsedSeconds;
  }

  mLastInputValue = inputValue;

  if (mExclusive)
  {
    return evaluate_exclusive(inputValue);
  }
  return evaluate_non_exclusive(inputValue);
}

// --- Exclusive evaluation ---

ConditionStateTransition LimitAlarmLogic::evaluate_exclusive(double inputValue)
{
  auto newLimit = compute_exclusive_limit(inputValue);

  if (newLimit == mActiveLimit)
  {
    // No change
    return {};
  }

  auto previousLimit = mActiveLimit;
  mActiveLimit = newLimit;

  if (newLimit == ActiveLimit::None)
  {
    // Was active, now inactive
    return transition_raw_active(false, severity());
  }

  if (previousLimit == ActiveLimit::None)
  {
    // Was inactive, now active
    return transition_raw_active(true, severity_for_limit(newLimit));
  }

  // Transition between limits: update severity and emit event
  set_severity(severity_for_limit(newLimit));
  return make_transition(true);
}

// --- Non-exclusive evaluation ---

ConditionStateTransition LimitAlarmLogic::evaluate_non_exclusive(double inputValue)
{
  const bool prevHighHigh = mHighHighActive;
  const bool prevHigh = mHighActive;
  const bool prevLow = mLowActive;
  const bool prevLowLow = mLowLowActive;

  // Evaluate each limit independently
  if (const double* limit = available_value(mLimits.highHighLimit))
  {
    mHighHighActive = is_high_violated(inputValue, *limit, mLimits.highHighDeadband, mHighHighActive);
  }
  else
  {
    mHighHighActive = false;
  }

  if (const double* limit = available_value(mLimits.highLimit))
  {
    mHighActive = is_high_violated(inputValue, *limit, mLimits.highDeadband, mHighActive);
  }
  else
  {
    mHighActive = false;
  }

  if (const double* limit = available_value(mLimits.lowLimit))
  {
    mLowActive = is_low_violated(inputValue, *limit, mLimits.lowDeadband, mLowActive);
  }
  else
  {
    mLowActive = false;
  }

  if (const double* limit = available_value(mLimits.lowLowLimit))
  {
    mLowLowActive = is_low_violated(inputValue, *limit, mLimits.lowLowDeadband, mLowLowActive);
  }
  else
  {
    mLowLowActive = false;
  }

  const bool anyChanged = (prevHighHigh != mHighHighActive) || (prevHigh != mHighActive) ||
                          (prevLow != mLowActive) || (prevLowLow != mLowLowActive);

  if (!anyChanged)
  {
    return {};
  }

  // Each state that changed was entered now; a state that did not change keeps its TransitionTime.
  const auto now = DateTime::now();
  const auto stamp = [&now](bool previous, bool current, DateTime& transitionTime)
  {
    if (previous != current)
      transitionTime = now;
  };
  stamp(prevHighHigh, mHighHighActive, mHighHighTransitionTime);
  stamp(prevHigh, mHighActive, mHighTransitionTime);
  stamp(prevLow, mLowActive, mLowTransitionTime);
  stamp(prevLowLow, mLowLowActive, mLowLowTransitionTime);

  const bool wasAnyActive = prevHighHigh || prevHigh || prevLow || prevLowLow;
  const bool isAnyActive = mHighHighActive || mHighActive || mLowActive || mLowLowActive;

  if (!wasAnyActive && isAnyActive)
  {
    // Transition to active
    return transition_raw_active(true, max_non_exclusive_severity());
  }

  if (wasAnyActive && !isAnyActive)
  {
    // Transition to inactive
    return transition_raw_active(false, severity());
  }

  // Still active but limits changed: update severity
  set_severity(max_non_exclusive_severity());
  return make_transition(true);
}

// --- Helpers ---

bool LimitAlarmLogic::try_extract_double(const Variant& value, double& out)
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

ActiveLimit LimitAlarmLogic::compute_exclusive_limit(double inputValue) const
{
  // Check from most severe to least severe.
  // For high-side limits, use the existing active limit to apply deadband.
  if (const double* limit = available_value(mLimits.highHighLimit))
  {
    const bool currentlyActive = (mActiveLimit == ActiveLimit::HighHigh);
    if (is_high_violated(inputValue, *limit, mLimits.highHighDeadband, currentlyActive))
    {
      return ActiveLimit::HighHigh;
    }
  }

  if (const double* limit = available_value(mLimits.lowLowLimit))
  {
    const bool currentlyActive = (mActiveLimit == ActiveLimit::LowLow);
    if (is_low_violated(inputValue, *limit, mLimits.lowLowDeadband, currentlyActive))
    {
      return ActiveLimit::LowLow;
    }
  }

  if (const double* limit = available_value(mLimits.highLimit))
  {
    const bool currentlyActive = (mActiveLimit == ActiveLimit::High);
    if (is_high_violated(inputValue, *limit, mLimits.highDeadband, currentlyActive))
    {
      return ActiveLimit::High;
    }
  }

  if (const double* limit = available_value(mLimits.lowLimit))
  {
    const bool currentlyActive = (mActiveLimit == ActiveLimit::Low);
    if (is_low_violated(inputValue, *limit, mLimits.lowDeadband, currentlyActive))
    {
      return ActiveLimit::Low;
    }
  }

  return ActiveLimit::None;
}

bool LimitAlarmLogic::is_high_violated(double inputValue, double limit, double deadband, bool currentlyActive)
{
  if (currentlyActive)
  {
    // Once active, require return below (limit - deadband) to deactivate
    return inputValue >= (limit - deadband);
  }
  // To activate, must exceed the limit
  return inputValue >= limit;
}

bool LimitAlarmLogic::is_low_violated(double inputValue, double limit, double deadband, bool currentlyActive)
{
  if (currentlyActive)
  {
    // Once active, require return above (limit + deadband) to deactivate
    return inputValue <= (limit + deadband);
  }
  // To activate, must go below the limit
  return inputValue <= limit;
}

uint16_t LimitAlarmLogic::severity_for_limit(ActiveLimit limit) const
{
  switch (limit)
  {
  case ActiveLimit::HighHigh:
    return mLimits.severityHighHigh;
  case ActiveLimit::High:
    return mLimits.severityHigh;
  case ActiveLimit::Low:
    return mLimits.severityLow;
  case ActiveLimit::LowLow:
    return mLimits.severityLowLow;
  case ActiveLimit::None:
    return 0;
  }
  return 0;
}

uint16_t LimitAlarmLogic::max_non_exclusive_severity() const
{
  uint16_t maxSev = 0;
  if (mHighHighActive)
  {
    maxSev = std::max(maxSev, mLimits.severityHighHigh);
  }
  if (mHighActive)
  {
    maxSev = std::max(maxSev, mLimits.severityHigh);
  }
  if (mLowActive)
  {
    maxSev = std::max(maxSev, mLimits.severityLow);
  }
  if (mLowLowActive)
  {
    maxSev = std::max(maxSev, mLimits.severityLowLow);
  }
  return maxSev;
}

// --- Event building ---

std::unique_ptr<BaseEvent> LimitAlarmLogic::build_event() const
{
  // Emit the CONCRETE payload for the configured limit mode so the event reports the right EventType:
  // ExclusiveLimitAlarmType or NonExclusiveLimitAlarmType, never the abstract LimitAlarmType. Per
  // Part 9 LimitAlarmType is abstract; clients (and the UACTT) discover limit alarms by their concrete
  // type, so an abstract EventType makes the alarm undiscoverable.
  std::unique_ptr<LimitAlarmPayload> event;
  if (mExclusive)
  {
    auto exclusivePayload = std::make_unique<ExclusiveLimitAlarmPayload>();
    // LimitState (ExclusiveLimitStateMachine): report the active limit as CurrentState (+ .Id) so an
    // EventFilter on LimitState.CurrentState / LimitState.CurrentState.Id resolves (CTT A&C limit CUs).
    exclusivePayload->limitState = exclusive_limit_state(active_limit());
    event = std::move(exclusivePayload);
  }
  else
  {
    auto nonExclusive = std::make_unique<NonExclusiveLimitAlarmPayload>();
    nonExclusive->highHighState = limit_substate(mHighHighActive, mHighHighTransitionTime);
    nonExclusive->highState = limit_substate(mHighActive, mHighTransitionTime);
    nonExclusive->lowState = limit_substate(mLowActive, mLowTransitionTime);
    nonExclusive->lowLowState = limit_substate(mLowLowActive, mLowLowTransitionTime);
    event = std::move(nonExclusive);
  }

  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields (ActiveState, InputNode, SuppressedOrShelved, optional sub-states,
  // delays) - shared with AlarmConditionLogic so a limit alarm carries the full alarm field set.
  populate_alarm_payload_fields(*event);

  // LimitAlarmPayload fields
  if (const double* limit = available_value(mLimits.highHighLimit))
    event->highHighLimit = *limit;
  if (const double* limit = available_value(mLimits.highLimit))
    event->highLimit = *limit;
  if (const double* limit = available_value(mLimits.lowLimit))
    event->lowLimit = *limit;
  if (const double* limit = available_value(mLimits.lowLowLimit))
    event->lowLowLimit = *limit;

  event->severityHighHigh = mLimits.severityHighHigh;
  event->severityHigh = mLimits.severityHigh;
  event->severityLow = mLimits.severityLow;
  event->severityLowLow = mLimits.severityLowLow;

  event->highHighDeadband = mLimits.highHighDeadband;
  event->highDeadband = mLimits.highDeadband;
  event->lowDeadband = mLimits.lowDeadband;
  event->lowLowDeadband = mLimits.lowLowDeadband;

  return event;
}

}  // namespace ua
