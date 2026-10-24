// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_condition_logic.h"

#include "ua_alarm_condition_payload.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_object_id.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <algorithm>
#include <chrono>
#include <limits>

namespace ua
{

// --- Activation ---

ConditionStateTransition AlarmConditionLogic::activate(uint16_t severity)
{
  // Create branch of current (unacked) state before resetting.
  // Only branch if a previous event was emitted (last_event_id non-empty)
  // and the trunk is currently unacknowledged.
  std::vector<BranchEventData> pendingBranchEvents;
  if (supports_branches() && !acknowledged() && !last_event_id().empty())
  {
    pendingBranchEvents = create_branch();
  }

  mActiveState.id = true;
  mActiveState.currentState = LocalizedText{"", "Active"};
  mActiveState.transitionTime = DateTime::now();

  // Reset acked/confirmed on new activation
  reset_acked_state();
  reset_confirmed_state();

  // Latched: activation sets LatchedState.Id=true
  if (mLatchedState.has_value())
  {
    mLatchedState->id = true;
    mLatchedState->currentState = LocalizedText{"", "Latched"};
    mLatchedState->transitionTime = DateTime::now();
  }

  // Update severity (tracked by base)
  set_severity(severity);

  // Silence auto-reset: new activation clears silence
  if (mSilenceState.has_value())
  {
    mSilenceState->id = false;
    mSilenceState->currentState = LocalizedText{"", "NotSilenced"};
    mSilenceState->transitionTime = DateTime::now();
  }

  auto transition = make_transition(true);
  transition.branchEvents = std::move(pendingBranchEvents);
  if (mReAlarmTimeMs > 0.0 && enabled())
  {
    transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::StartReAlarmTimer, mReAlarmTimeMs});
  }
  return transition;
}

ConditionStateTransition AlarmConditionLogic::deactivate()
{
  // Create branch of current (unacked) state before deactivating.
  // Only branch if a previous event was emitted.
  std::vector<BranchEventData> pendingBranchEvents;
  if (supports_branches() && !acknowledged() && !last_event_id().empty())
  {
    pendingBranchEvents = create_branch();
  }

  mActiveState.id = false;
  mActiveState.currentState = LocalizedText{"", "Inactive"};
  mActiveState.transitionTime = DateTime::now();

  // OPC 10000-9 5.8.17.1: the system-generated "Any Transition Occurs" transition, "generated when the
  // Condition goes to an inactive state", ends a OneShotShelve. A TimedShelve is not affected; it lasts
  // until its time expires or it is unshelved.
  if (mShelveState == ShelveState::OneShotShelved)
  {
    mShelveState = ShelveState::Unshelved;
    update_suppressed_or_shelved();
  }

  auto transition = make_transition(true);
  transition.branchEvents = std::move(pendingBranchEvents);
  if (mReAlarmTimeMs > 0.0)
  {
    transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::CancelReAlarmTimer, 0.0});
  }
  return transition;
}

// --- Suppression ---

ConditionStateTransition AlarmConditionLogic::suppress()
{
  if (!mSuppressedState.has_value())
  {
    mSuppressedState = TwoStateVariableState{};
  }

  mSuppressedState->id = true;
  mSuppressedState->currentState = LocalizedText{"", "Suppressed"};
  mSuppressedState->transitionTime = DateTime::now();

  update_suppressed_or_shelved();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::suppress(const LocalizedText& comment)
{
  return apply_method_comment(suppress(), comment);
}

ConditionStateTransition AlarmConditionLogic::unsuppress()
{
  if (mSuppressedState.has_value())
  {
    mSuppressedState->id = false;
    mSuppressedState->currentState = LocalizedText{"", "Unsuppressed"};
    mSuppressedState->transitionTime = DateTime::now();
  }

  update_suppressed_or_shelved();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::unsuppress(const LocalizedText& comment)
{
  return apply_method_comment(unsuppress(), comment);
}

// --- Out of service ---

ConditionStateTransition AlarmConditionLogic::remove_from_service()
{
  // OPC 10000-9 5.8.12: "Instances that do not expose the OutOfService State shall reject
  // RemoveFromService calls." Default-constructing the sub-state here would accept the call AND
  // promote the instance's declared composition - supports_out_of_service() is that optional's
  // has_value() - so an alarm the application never gave an out-of-service facet would start
  // publishing OutOfServiceState and SuppressedOrShelved because a Client asked it to.
  if (!mOutOfServiceState.has_value())
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadMethodInvalid};
    return result;
  }

  mOutOfServiceState->id = true;
  mOutOfServiceState->currentState = LocalizedText{"", "OutOfService"};
  mOutOfServiceState->transitionTime = DateTime::now();

  update_suppressed_or_shelved();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::remove_from_service(const LocalizedText& comment)
{
  return apply_method_comment(remove_from_service(), comment);
}

ConditionStateTransition AlarmConditionLogic::place_in_service()
{
  if (mOutOfServiceState.has_value())
  {
    mOutOfServiceState->id = false;
    mOutOfServiceState->currentState = LocalizedText{"", "InService"};
    mOutOfServiceState->transitionTime = DateTime::now();
  }

  update_suppressed_or_shelved();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::place_in_service(const LocalizedText& comment)
{
  return apply_method_comment(place_in_service(), comment);
}

// --- Silence ---

ConditionStateTransition AlarmConditionLogic::silence()
{
  if (!mSilenceState.has_value())
  {
    mSilenceState = TwoStateVariableState{};
  }

  mSilenceState->id = true;
  mSilenceState->currentState = LocalizedText{"", "Silenced"};
  mSilenceState->transitionTime = DateTime::now();

  return make_transition(true);
}

// --- Shelving ---

ConditionStateTransition AlarmConditionLogic::timed_shelve(double durationMs)
{
  if (mShelveState == ShelveState::TimedShelved || mShelveState == ShelveState::OneShotShelved)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionAlreadyShelved};
    return result;
  }

  // OPC 10000-9 5.8.17.4: the Server may refuse a ShelvingTime, and must refuse one past MaxTimeShelved.
  // A negative or NaN duration names no time at all. A very large one - Clients use the largest Double
  // for "as long as allowed" - is accepted; the timer saturates it.
  if (!(durationMs >= 0.0) || (mMaxTimeShelved > 0.0 && durationMs > mMaxTimeShelved))
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadShelvingTimeOutOfRange};
    return result;
  }

  mShelveState = ShelveState::TimedShelved;
  mShelvingTimeMs = durationMs;
  mShelvedAt = DateTime::now();
  update_suppressed_or_shelved();

  auto transition = make_transition(true);
  transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::StartShelveTimer, durationMs});
  return transition;
}

ConditionStateTransition AlarmConditionLogic::timed_shelve(double durationMs, const LocalizedText& comment)
{
  return apply_method_comment(timed_shelve(durationMs), comment);
}

ConditionStateTransition AlarmConditionLogic::one_shot_shelve()
{
  if (mShelveState == ShelveState::TimedShelved || mShelveState == ShelveState::OneShotShelved)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionAlreadyShelved};
    return result;
  }

  mShelveState = ShelveState::OneShotShelved;
  update_suppressed_or_shelved();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::one_shot_shelve(const LocalizedText& comment)
{
  return apply_method_comment(one_shot_shelve(), comment);
}

ConditionStateTransition AlarmConditionLogic::unshelve()
{
  if (mShelveState == ShelveState::Unshelved)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionNotShelved};
    return result;
  }

  const bool wasTimedShelved = (mShelveState == ShelveState::TimedShelved);
  mShelveState = ShelveState::Unshelved;
  update_suppressed_or_shelved();

  auto transition = make_transition(true);
  if (wasTimedShelved)
  {
    transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::CancelShelveTimer, 0.0});
  }
  return transition;
}

ConditionStateTransition AlarmConditionLogic::unshelve(const LocalizedText& comment)
{
  return apply_method_comment(unshelve(), comment);
}

ConditionStateTransition AlarmConditionLogic::on_shelve_timer_expired()
{
  if (mShelveState != ShelveState::TimedShelved)
  {
    return {};
  }

  mShelveState = ShelveState::Unshelved;
  update_suppressed_or_shelved();

  return make_transition(true);
}

// --- On/off delay ---

ConditionStateTransition AlarmConditionLogic::on_delay_expired()
{
  if (!mOnDelayPending || !mRawActive)
  {
    mOnDelayPending = false;
    return {};
  }

  mOnDelayPending = false;
  return activate(mRawSeverity);
}

ConditionStateTransition AlarmConditionLogic::off_delay_expired()
{
  if (!mOffDelayPending || mRawActive)
  {
    mOffDelayPending = false;
    return {};
  }

  mOffDelayPending = false;
  return deactivate();
}

ConditionStateTransition AlarmConditionLogic::on_re_alarm_timer_expired()
{
  if (!enabled() || !mActiveState.id || mReAlarmTimeMs <= 0.0)
  {
    return {};
  }

  // Part 9 section 5.8.2: a re-alarm is presented as newly active without an inactive transition.
  const DateTime reAlarmTime = DateTime::now();
  mActiveState.transitionTime = reAlarmTime;
  reset_acked_state();
  reset_confirmed_state();

  if (mSilenceState.has_value())
  {
    mSilenceState->id = false;
    mSilenceState->currentState = LocalizedText{"", "NotSilenced"};
    mSilenceState->transitionTime = reAlarmTime;
  }

  auto transition = make_transition(true);
  transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::StartReAlarmTimer, mReAlarmTimeMs});
  return transition;
}

// --- Input evaluation ---

ConditionStateTransition AlarmConditionLogic::evaluate_input(const Variant& /*value*/, DateTime /*timestamp*/)
{
  // Base implementation does nothing. Subclasses (LimitAlarmLogic) override this.
  return {};
}

// --- Latching ---

ConditionStateTransition AlarmConditionLogic::reset()
{
  if (!mLatchedState.has_value())
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadInvalidState};
    return result;
  }

  // Reset requires: inactive and acknowledged
  if (mActiveState.id)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadInvalidState};
    return result;
  }

  if (!acknowledged())
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadInvalidState};
    return result;
  }

  mLatchedState->id = false;
  mLatchedState->currentState = LocalizedText{"", "Unlatched"};
  mLatchedState->transitionTime = DateTime::now();

  return make_transition(true);
}

ConditionStateTransition AlarmConditionLogic::reset(const LocalizedText& comment)
{
  return apply_method_comment(reset(), comment);
}

// --- Initial state ---

void AlarmConditionLogic::set_initial_active(bool active, uint16_t severity)
{
  mActiveState.id = active;
  mActiveState.currentState = LocalizedText{"", active ? "Active" : "Inactive"};
  mActiveState.transitionTime = DateTime::now();
  mRawActive = active;
  // set_severity returns a transition but we ignore it - no events during initial state setup.
  (void)set_severity(severity);
  recompute_retain_no_emit();
}

void AlarmConditionLogic::set_initial_acked(bool acked)
{
  AcknowledgeableConditionLogic::set_initial_acked(acked);
  if (mSilenceState.has_value() && !mInitialSilenceSet)
  {
    mSilenceState->id = acked;
    mSilenceState->currentState = LocalizedText{"", acked ? "Silenced" : "NotSilenced"};
    mSilenceState->transitionTime = DateTime::now();
  }
}

void AlarmConditionLogic::set_initial_suppressed(bool suppressed)
{
  if (mSuppressedState.has_value())
  {
    mSuppressedState->id = suppressed;
    mSuppressedState->currentState = LocalizedText{"", suppressed ? "Suppressed" : "Unsuppressed"};
    mSuppressedState->transitionTime = DateTime::now();
    update_suppressed_or_shelved();
    recompute_retain_no_emit();
  }
}

void AlarmConditionLogic::set_initial_out_of_service(bool outOfService)
{
  if (mOutOfServiceState.has_value())
  {
    mOutOfServiceState->id = outOfService;
    mOutOfServiceState->currentState = LocalizedText{"", outOfService ? "OutOfService" : "InService"};
    mOutOfServiceState->transitionTime = DateTime::now();
    update_suppressed_or_shelved();
    recompute_retain_no_emit();
  }
}

void AlarmConditionLogic::set_initial_silenced(bool silenced)
{
  mInitialSilenceSet = true;
  if (mSilenceState.has_value())
  {
    mSilenceState->id = silenced;
    mSilenceState->currentState = LocalizedText{"", silenced ? "Silenced" : "NotSilenced"};
    mSilenceState->transitionTime = DateTime::now();
  }
}

void AlarmConditionLogic::set_initial_latched(bool latched)
{
  if (mLatchedState.has_value())
  {
    mLatchedState->id = latched;
    mLatchedState->currentState = LocalizedText{"", latched ? "Latched" : "Unlatched"};
    mLatchedState->transitionTime = DateTime::now();
  }
}

void AlarmConditionLogic::set_initial_shelved(ShelveState state)
{
  mShelveState = state;
  update_suppressed_or_shelved();
  recompute_retain_no_emit();
}

// --- Configuration setters ---

void AlarmConditionLogic::set_input_node(NodeId nodeId)
{
  mInputNode = std::move(nodeId);
}

void AlarmConditionLogic::set_max_time_shelved(double ms)
{
  mMaxTimeShelved = ms;
}

void AlarmConditionLogic::set_on_delay(double ms)
{
  mOnDelayMs = ms;
}

void AlarmConditionLogic::set_off_delay(double ms)
{
  mOffDelayMs = ms;
}

void AlarmConditionLogic::set_re_alarm_time(double ms)
{
  mReAlarmTimeMs = ms;
}

void AlarmConditionLogic::set_supports_suppressed(bool value)
{
  if (value && !mSuppressedState.has_value())
  {
    mSuppressedState = TwoStateVariableState{};
  }
  else if (!value)
  {
    mSuppressedState.reset();
  }
  update_suppressed_or_shelved();
}

void AlarmConditionLogic::set_supports_out_of_service(bool value)
{
  if (value && !mOutOfServiceState.has_value())
  {
    mOutOfServiceState = TwoStateVariableState{};
  }
  else if (!value)
  {
    mOutOfServiceState.reset();
  }
  update_suppressed_or_shelved();
}

void AlarmConditionLogic::set_supports_silence(bool value)
{
  if (value && !mSilenceState.has_value())
  {
    mSilenceState = TwoStateVariableState{};
  }
  else if (!value)
  {
    mSilenceState.reset();
  }
}

void AlarmConditionLogic::set_supports_latched(bool value)
{
  if (value && !mLatchedState.has_value())
  {
    mLatchedState = TwoStateVariableState{};
  }
  else if (!value)
  {
    mLatchedState.reset();
  }
}

bool AlarmConditionLogic::supports_suppressed() const
{
  return mSuppressedState.has_value();
}

bool AlarmConditionLogic::supports_out_of_service() const
{
  return mOutOfServiceState.has_value();
}

bool AlarmConditionLogic::supports_silence() const
{
  return mSilenceState.has_value();
}

bool AlarmConditionLogic::supports_latched() const
{
  return mLatchedState.has_value();
}

// --- Event building ---

double UnshelveClock::remaining_ms(DateTime now) const noexcept
{
  switch (state)
  {
  case ShelveState::TimedShelved:
  {
    const double elapsedMs =
      std::chrono::duration<double, std::milli>(now.value() - shelvedAt.value()).count();
    return std::max(0.0, shelvingTimeMs - elapsedMs);
  }
  case ShelveState::OneShotShelved:
    return oneShotMs;
  case ShelveState::Unshelved:
    break;
  }
  return 0.0;
}

UnshelveClock AlarmConditionLogic::unshelve_clock() const
{
  return UnshelveClock{shelve_state(),
    mShelvedAt,
    mShelvingTimeMs,
    mMaxTimeShelved > 0.0 ? mMaxTimeShelved : std::numeric_limits<double>::max()};
}

void AlarmConditionLogic::populate_alarm_payload_fields(AlarmConditionPayload& event) const
{
  event.activeState = mActiveState;
  event.inputNode = mInputNode;
  // ShelvingState/CurrentState, its Id and UnshelveTime travel with every alarm event: a Client decides
  // from them whether an alarm supports shelving, whether it is shelved and for how much longer.
  // UnshelveTime (OPC 10000-9 5.8.17.1) is the remaining time for a TimedShelve, and MaxTimeShelved - or
  // the maximum Duration when there is none - for a OneShotShelve.
  const auto clock = unshelve_clock();
  const double unshelveTimeMs = clock.remaining_ms(DateTime::now());
  switch (clock.state)
  {
  case ShelveState::Unshelved:
    event.shelvingState = ShelvedStateVariableState{
      LocalizedText{"", "Unshelved"}, NodeId{ObjectId::ShelvedStateMachineType_Unshelved}, unshelveTimeMs};
    break;
  case ShelveState::TimedShelved:
    event.shelvingState = ShelvedStateVariableState{LocalizedText{"", "TimedShelved"},
      NodeId{ObjectId::ShelvedStateMachineType_TimedShelved},
      unshelveTimeMs};
    break;
  case ShelveState::OneShotShelved:
    event.shelvingState = ShelvedStateVariableState{LocalizedText{"", "OneShotShelved"},
      NodeId{ObjectId::ShelvedStateMachineType_OneShotShelved},
      unshelveTimeMs};
    break;
  }
  event.suppressedOrShelved = mSuppressedOrShelved;
  event.suppressedState = mSuppressedState;
  event.outOfServiceState = mOutOfServiceState;
  event.silenceState = mSilenceState;
  event.latchedState = mLatchedState;

  if (mMaxTimeShelved > 0.0)
  {
    event.maxTimeShelved = Variant{mMaxTimeShelved};
  }
  if (mOnDelayMs > 0.0)
  {
    event.onDelay = Variant{mOnDelayMs};
  }
  if (mOffDelayMs > 0.0)
  {
    event.offDelay = Variant{mOffDelayMs};
  }
  if (mReAlarmTimeMs > 0.0)
  {
    event.reAlarmTime = Variant{mReAlarmTimeMs};
  }
}

std::unique_ptr<BaseEvent> AlarmConditionLogic::build_event() const
{
  auto event = std::make_unique<AlarmConditionPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload fields
  event->ackedState = acked_state();
  event->confirmedState = confirmed_state();

  // AlarmConditionPayload fields
  populate_alarm_payload_fields(*event);

  return event;
}

// --- Protected accessors ---

bool AlarmConditionLogic::active() const
{
  return mActiveState.id;
}

const TwoStateVariableState& AlarmConditionLogic::active_state() const
{
  return mActiveState;
}

ShelveState AlarmConditionLogic::shelve_state() const
{
  return mShelveState;
}

bool AlarmConditionLogic::suppressed_or_shelved() const
{
  return mSuppressedOrShelved;
}

bool AlarmConditionLogic::raw_active() const
{
  return mRawActive;
}

double AlarmConditionLogic::on_delay_ms() const
{
  return mOnDelayMs;
}

double AlarmConditionLogic::off_delay_ms() const
{
  return mOffDelayMs;
}

ConditionStateTransition AlarmConditionLogic::transition_raw_active(bool rawActive, uint16_t severity)
{
  mRawActive = rawActive;
  mRawSeverity = severity;

  ConditionStateTransition transition;
  if (rawActive)
  {
    if (mOffDelayPending)
    {
      mOffDelayPending = false;
      transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::CancelOffDelay, 0.0});
    }
    if (mActiveState.id)
      return transition;
    if (mOnDelayMs > 0.0)
    {
      mOnDelayPending = true;
      transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::StartOnDelay, mOnDelayMs});
      return transition;
    }
    return activate(severity);
  }

  if (mOnDelayPending)
  {
    mOnDelayPending = false;
    transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::CancelOnDelay, 0.0});
  }
  if (!mActiveState.id)
    return transition;
  if (mOffDelayMs > 0.0)
  {
    mOffDelayPending = true;
    transition.timerCommands.push_back(TimerCommand{TimerCommand::Kind::StartOffDelay, mOffDelayMs});
    return transition;
  }
  return deactivate();
}

// --- Overrides ---

bool AlarmConditionLogic::compute_retain() const
{
  if (!enabled())
  {
    return false;
  }

  // Active keeps retain true
  if (mActiveState.id)
  {
    return true;
  }

  // Unacknowledged keeps retain true
  if (!acknowledged())
  {
    return true;
  }

  // Unconfirmed (if confirm supported) keeps retain true
  const auto& confirmedState = confirmed_state();
  if (confirmedState.has_value() && !confirmedState->id)
  {
    return true;
  }

  // Retain while any branch needs attention
  if (has_unresolved_branches())
  {
    return true;
  }

  return false;
}

void AlarmConditionLogic::on_enabled()
{
  // Call base to reset acked/confirmed
  AcknowledgeableConditionLogic::on_enabled();
}

// --- Private helpers ---

void AlarmConditionLogic::update_suppressed_or_shelved()
{
  mSuppressedOrShelved = false;

  if (mSuppressedState.has_value() && mSuppressedState->id)
  {
    mSuppressedOrShelved = true;
  }

  if (mOutOfServiceState.has_value() && mOutOfServiceState->id)
  {
    mSuppressedOrShelved = true;
  }

  if (mShelveState != ShelveState::Unshelved)
  {
    mSuppressedOrShelved = true;
  }
}

}  // namespace ua
