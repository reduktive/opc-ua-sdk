// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "alarm_view.h"

#include "example_support.h"

#include "ua_error_detail.h"
#include "ua_event_subscriber.h"
#include "ua_exceptions.h"
#include "ua_localized_text.h"
#include "ua_status.h"

#include <fmt/format.h>

#include <optional>
#include <thread>

namespace examples::alarms
{

bool is_set(const std::optional<ua::client::TwoStateValue>& state)
{
  return state.has_value() && state->id.value_or(false);
}

namespace
{
constexpr std::string_view acknowledgeComment = "Seen by the example operator";
}  // namespace

/// Waits until the tracker is attached to the event backbone that carries its condition events.
///
/// `Connection::alarms()` builds the tracker lazily and attaches it asynchronously, so a refresh
/// issued before the attach completes has no SubscriptionId to name and is refused. The subscriber
/// republishes both counts in the same completion that hands the tracker its backbone, so this is a
/// real signal rather than a guess: it waits exactly as long as the attach takes, where a fixed
/// sleep would either race it and report a real failure as a timing problem, or waste the
/// difference on every run.
/// Describes what the tracker currently believes, in the terms an operator cares about.
///
/// Active and acknowledged are independent. An alarm that has gone away but was never acknowledged
/// is still the operator's business, which is exactly why a condition is retained rather than
/// forgotten when it stops being true.
std::string describe(const std::vector<ua::client::TrackedCondition>& conditions)
{
  if (conditions.empty())
  {
    return "nothing retained";
  }
  std::string described;
  for (const ua::client::TrackedCondition& condition : conditions)
  {
    described += described.empty() ? "" : ", ";
    const std::string_view name{condition.conditionName.text()};
    described += fmt::format("{} [{}, {}]",
      name.empty() ? std::string_view{condition.sourceName} : name,
      is_set(condition.activeState) ? "active" : "inactive",
      is_set(condition.ackedState) ? "acknowledged" : "unacknowledged");
  }
  return described;
}

void await_tracker_attached(ua::client::Connection& connection)
{
  ua::client::EventSubscriber events = connection.events();
  const auto deadline = std::chrono::steady_clock::now() + attachBudget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    const std::shared_ptr<const ua::client::EventSubscriberInfo> info = events.info();
    if (info && info->trackerCount > 0 && info->backboneCount > 0)
    {
      return;
    }
    std::this_thread::yield();
  }
  throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
    ua::ErrorDetail::build("ExampleTrackerNeverAttached",
      "The alarm tracker never attached to an event backbone",
      "client.alarms")}};
}

void await_state(ua::client::AlarmConditionTracker& alarms, AlarmState wanted, std::string_view what)
{
  // The tracker's snapshot is the authority on what it currently believes, so this asks it rather
  // than waiting for a particular callback to fire: a state can settle through a path that raises
  // no change notification, and a client that waits on the notification instead of the state hangs
  // for a transition that has already happened.
  const auto deadline = std::chrono::steady_clock::now() + stateBudget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    for (const ua::client::TrackedCondition& condition : alarms.list_conditions_sync())
    {
      if (AlarmState{is_set(condition.activeState), is_set(condition.ackedState)} == wanted)
      {
        return;
      }
    }
    std::this_thread::yield();
  }
  throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
    ua::ErrorDetail::build("ExampleAlarmStateNotReached",
      fmt::format("The tracker never reported the condition {}", what),
      "client.alarms")}};
}

void await_cleared(ua::client::AlarmConditionTracker& alarms)
{
  // A condition is retained while it still needs an operator's attention. Once it is neither active
  // nor unacknowledged there is nothing left to do about it, Retain goes false, and it leaves the
  // list. Disappearing is the success case here, not a lost notification.
  const auto deadline = std::chrono::steady_clock::now() + stateBudget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (alarms.list_conditions_sync().empty())
    {
      return;
    }
    std::this_thread::yield();
  }
  throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
    ua::ErrorDetail::build("ExampleConditionStillRetained",
      "The condition stayed retained after it went inactive and acknowledged",
      "client.alarms")}};
}

void acknowledge_first(ua::client::AlarmConditionTracker& alarms)
{
  const std::vector<ua::client::TrackedCondition> retained = alarms.list_conditions_sync();
  if (retained.empty())
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadNothingToDo,
      ua::ErrorDetail::build(
        "ExampleNoRetainedCondition", "The server retained no condition to acknowledge", "client.alarms")}};
  }
  alarms.acknowledge_sync(retained.front().key, ua::LocalizedText{"", std::string{acknowledgeComment}});
  await_state(alarms, AlarmState{true, true}, "acknowledged while still active");
}

}  // namespace examples::alarms
