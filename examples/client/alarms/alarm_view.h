// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_ALARMS_ALARM_VIEW_H
#define UASDK_EXAMPLE_ALARMS_ALARM_VIEW_H

/// @file
/// @brief Reading and waiting on what the alarm tracker currently believes.

#include "ua_alarm_condition_tracker.h"
#include "ua_connection.h"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace examples::alarms
{

/// A ceiling on waiting for a state the server should reach immediately, not a delay anyone expects
/// to spend. Reaching it means something is wrong, and the caller says which state never arrived.
inline constexpr auto stateBudget = std::chrono::milliseconds{10000};

/// The same kind of ceiling, for the tracker's asynchronous attach.
inline constexpr auto attachBudget = std::chrono::milliseconds{10000};

/// The two things an operator asks about a condition, and the pair this example waits on.
using AlarmState = std::pair<bool, bool>;  // active, acknowledged

/// Whether a two-state field is present and set.
///
/// Each state a condition can carry is optional, because not every ConditionType has it, and the
/// flag inside it is optional again for a server that has not reported it yet. Absent is not the
/// same as false, and treating it as false is how a client claims an alarm is inactive when the
/// truth is that nobody said.
bool is_set(const std::optional<ua::client::TwoStateValue>& state);

/// Describes what the tracker currently believes, in the terms an operator cares about.
std::string describe(const std::vector<ua::client::TrackedCondition>& conditions);

/// Waits until the tracker is attached to the event backbone that carries its condition events.
void await_tracker_attached(ua::client::Connection& connection);

/// Waits for the tracker to report @p wanted, or fails saying which state never arrived.
void await_state(ua::client::AlarmConditionTracker& alarms, AlarmState wanted, std::string_view what);

/// Waits until nothing is retained: the condition is neither active nor unacknowledged.
void await_cleared(ua::client::AlarmConditionTracker& alarms);

/// Acknowledges the first retained condition, or fails saying there was nothing to acknowledge.
void acknowledge_first(ua::client::AlarmConditionTracker& alarms);

}  // namespace examples::alarms

#endif  // UASDK_EXAMPLE_ALARMS_ALARM_VIEW_H
