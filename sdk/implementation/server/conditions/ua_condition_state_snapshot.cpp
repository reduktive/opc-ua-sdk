// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_state_snapshot.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_alarm_condition_payload.h"
#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_object_id.h"

namespace ua
{

// --- Getters (read under mutex) ---

ByteString ConditionStateSnapshot::event_id() const
{
  const std::lock_guard lock(mMutex);
  return mEventId;
}

NodeId ConditionStateSnapshot::event_type() const
{
  const std::lock_guard lock(mMutex);
  return mEventType;
}

NodeId ConditionStateSnapshot::source_node() const
{
  const std::lock_guard lock(mMutex);
  return mSourceNode;
}

String ConditionStateSnapshot::source_name() const
{
  const std::lock_guard lock(mMutex);
  return mSourceName;
}

DateTime ConditionStateSnapshot::time() const
{
  const std::lock_guard lock(mMutex);
  return mTime;
}

DateTime ConditionStateSnapshot::receive_time() const
{
  const std::lock_guard lock(mMutex);
  return mReceiveTime;
}

LocalizedText ConditionStateSnapshot::message() const
{
  const std::lock_guard lock(mMutex);
  return mMessage;
}

NodeId ConditionStateSnapshot::condition_class_id() const
{
  const std::lock_guard lock(mMutex);
  return mConditionClassId;
}

LocalizedText ConditionStateSnapshot::condition_class_name() const
{
  const std::lock_guard lock(mMutex);
  return mConditionClassName;
}

String ConditionStateSnapshot::condition_name() const
{
  const std::lock_guard lock(mMutex);
  return mConditionName;
}

NodeId ConditionStateSnapshot::branch_id() const
{
  const std::lock_guard lock(mMutex);
  return mBranchId;
}

String ConditionStateSnapshot::client_user_id() const
{
  const std::lock_guard lock(mMutex);
  return mClientUserId;
}

std::optional<TwoStateVariableState> ConditionStateSnapshot::high_high_state() const
{
  const std::lock_guard lock(mMutex);
  return mHighHighState;
}

std::optional<TwoStateVariableState> ConditionStateSnapshot::high_state() const
{
  const std::lock_guard lock(mMutex);
  return mHighState;
}

std::optional<TwoStateVariableState> ConditionStateSnapshot::low_state() const
{
  const std::lock_guard lock(mMutex);
  return mLowState;
}

std::optional<TwoStateVariableState> ConditionStateSnapshot::low_low_state() const
{
  const std::lock_guard lock(mMutex);
  return mLowLowState;
}

LocalizedText ConditionStateSnapshot::limit_state_name() const
{
  const std::lock_guard lock(mMutex);
  return mLimitStateName;
}

NodeId ConditionStateSnapshot::limit_state_id() const
{
  const std::lock_guard lock(mMutex);
  return mLimitStateId;
}

LocalizedText ConditionStateSnapshot::shelve_state_name() const
{
  const std::lock_guard lock(mMutex);
  return mShelveStateName;
}

NodeId ConditionStateSnapshot::shelve_state_id() const
{
  const std::lock_guard lock(mMutex);
  return mShelveStateId;
}

bool ConditionStateSnapshot::enabled() const
{
  const std::lock_guard lock(mMutex);
  return mEnabled;
}

bool ConditionStateSnapshot::retained() const
{
  const std::lock_guard lock(mMutex);
  return mRetain;
}

uint16_t ConditionStateSnapshot::severity() const
{
  const std::lock_guard lock(mMutex);
  return mSeverity;
}

StatusCode ConditionStateSnapshot::quality() const
{
  const std::lock_guard lock(mMutex);
  return mQuality;
}

DateTime ConditionStateSnapshot::quality_source_timestamp() const
{
  const std::lock_guard lock(mMutex);
  return mQualitySourceTimestamp;
}

LocalizedText ConditionStateSnapshot::comment() const
{
  const std::lock_guard lock(mMutex);
  return mComment;
}

DateTime ConditionStateSnapshot::comment_source_timestamp() const
{
  const std::lock_guard lock(mMutex);
  return mCommentSourceTimestamp;
}

uint16_t ConditionStateSnapshot::last_severity() const
{
  const std::lock_guard lock(mMutex);
  return mLastSeverity;
}

DateTime ConditionStateSnapshot::last_severity_source_timestamp() const
{
  const std::lock_guard lock(mMutex);
  return mLastSeveritySourceTimestamp;
}

bool ConditionStateSnapshot::acked() const
{
  const std::lock_guard lock(mMutex);
  return mAcked;
}

DateTime ConditionStateSnapshot::acked_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mAckedState.transitionTime;
}

LocalizedText ConditionStateSnapshot::acked_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mAckedState.currentState;
}

bool ConditionStateSnapshot::confirmed() const
{
  const std::lock_guard lock(mMutex);
  return mConfirmed;
}

DateTime ConditionStateSnapshot::confirmed_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mConfirmedState.transitionTime;
}

LocalizedText ConditionStateSnapshot::confirmed_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mConfirmedState.currentState;
}

bool ConditionStateSnapshot::active() const
{
  const std::lock_guard lock(mMutex);
  return mActive;
}

DateTime ConditionStateSnapshot::active_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mActiveState.transitionTime;
}

LocalizedText ConditionStateSnapshot::active_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mActiveState.currentState;
}

LocalizedText ConditionStateSnapshot::enabled_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mEnabledState.currentState;
}

DateTime ConditionStateSnapshot::enabled_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mEnabledState.transitionTime;
}

bool ConditionStateSnapshot::suppressed_or_shelved() const
{
  const std::lock_guard lock(mMutex);
  return mSuppressedOrShelved;
}

NodeId ConditionStateSnapshot::input_node() const
{
  const std::lock_guard lock(mMutex);
  return mInputNode;
}

std::optional<bool> ConditionStateSnapshot::suppressed() const
{
  const std::lock_guard lock(mMutex);
  if (!mSuppressedState.has_value())
  {
    return std::nullopt;
  }
  return mSuppressedState->id;
}

LocalizedText ConditionStateSnapshot::suppressed_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mSuppressedState.has_value() ? mSuppressedState->currentState : LocalizedText{};
}

DateTime ConditionStateSnapshot::suppressed_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mSuppressedState.has_value() ? mSuppressedState->transitionTime : DateTime{};
}

std::optional<bool> ConditionStateSnapshot::out_of_service() const
{
  const std::lock_guard lock(mMutex);
  if (!mOutOfServiceState.has_value())
  {
    return std::nullopt;
  }
  return mOutOfServiceState->id;
}

LocalizedText ConditionStateSnapshot::out_of_service_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mOutOfServiceState.has_value() ? mOutOfServiceState->currentState : LocalizedText{};
}

DateTime ConditionStateSnapshot::out_of_service_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mOutOfServiceState.has_value() ? mOutOfServiceState->transitionTime : DateTime{};
}

std::optional<bool> ConditionStateSnapshot::silenced() const
{
  const std::lock_guard lock(mMutex);
  if (!mSilenceState.has_value())
  {
    return std::nullopt;
  }
  return mSilenceState->id;
}

LocalizedText ConditionStateSnapshot::silenced_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mSilenceState.has_value() ? mSilenceState->currentState : LocalizedText{};
}

DateTime ConditionStateSnapshot::silenced_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mSilenceState.has_value() ? mSilenceState->transitionTime : DateTime{};
}

std::optional<bool> ConditionStateSnapshot::latched() const
{
  const std::lock_guard lock(mMutex);
  if (!mLatchedState.has_value())
  {
    return std::nullopt;
  }
  return mLatchedState->id;
}

LocalizedText ConditionStateSnapshot::latched_current_state() const
{
  const std::lock_guard lock(mMutex);
  return mLatchedState.has_value() ? mLatchedState->currentState : LocalizedText{};
}

DateTime ConditionStateSnapshot::latched_transition_time() const
{
  const std::lock_guard lock(mMutex);
  return mLatchedState.has_value() ? mLatchedState->transitionTime : DateTime{};
}

// --- Updates from event structs (write under mutex) ---

void ConditionStateSnapshot::update_from(const ConditionPayload& event)
{
  const std::lock_guard lock(mMutex);
  update_condition_fields(event);
}

void ConditionStateSnapshot::update_from(const AcknowledgeableConditionPayload& event)
{
  const std::lock_guard lock(mMutex);
  update_condition_fields(event);
  update_acknowledgeable_fields(event);
}

void ConditionStateSnapshot::update_from(const AlarmConditionPayload& event)
{
  const std::lock_guard lock(mMutex);
  update_condition_fields(event);
  update_acknowledgeable_fields(event);
  update_alarm_fields(event);
}

void ConditionStateSnapshot::set_non_exclusive_limit_states(std::optional<TwoStateVariableState> highHigh,
  std::optional<TwoStateVariableState> high, std::optional<TwoStateVariableState> low,
  std::optional<TwoStateVariableState> lowLow)
{
  const std::lock_guard lock(mMutex);
  mHighHighState = std::move(highHigh);
  mHighState = std::move(high);
  mLowState = std::move(low);
  mLowLowState = std::move(lowLow);
}

void ConditionStateSnapshot::set_exclusive_limit_state(LocalizedText currentStateName, NodeId currentStateId)
{
  const std::lock_guard lock(mMutex);
  mLimitStateName = std::move(currentStateName);
  mLimitStateId = std::move(currentStateId);
}

namespace
{

/// The ShelvedStateMachineType transition (OPC 10000-9 5.8.17.1) from one shelving state to another,
/// or nullopt when @p from and @p to are not joined by one.
std::optional<ConditionStateSnapshot::ShelveTransition> shelve_transition(
  const NodeId& from, const NodeId& to)
{
  struct Row
  {
    ObjectId from;
    ObjectId to;
    ObjectId transition;
    const char* name;
  };

  static constexpr Row transitions[] = {
    {ObjectId::ShelvedStateMachineType_Unshelved,
      ObjectId::ShelvedStateMachineType_TimedShelved,
      ObjectId::ShelvedStateMachineType_UnshelvedToTimedShelved,
      "UnshelvedToTimedShelved"},
    {ObjectId::ShelvedStateMachineType_Unshelved,
      ObjectId::ShelvedStateMachineType_OneShotShelved,
      ObjectId::ShelvedStateMachineType_UnshelvedToOneShotShelved,
      "UnshelvedToOneShotShelved"},
    {ObjectId::ShelvedStateMachineType_TimedShelved,
      ObjectId::ShelvedStateMachineType_Unshelved,
      ObjectId::ShelvedStateMachineType_TimedShelvedToUnshelved,
      "TimedShelvedToUnshelved"},
    {ObjectId::ShelvedStateMachineType_TimedShelved,
      ObjectId::ShelvedStateMachineType_OneShotShelved,
      ObjectId::ShelvedStateMachineType_TimedShelvedToOneShotShelved,
      "TimedShelvedToOneShotShelved"},
    {ObjectId::ShelvedStateMachineType_OneShotShelved,
      ObjectId::ShelvedStateMachineType_Unshelved,
      ObjectId::ShelvedStateMachineType_OneShotShelvedToUnshelved,
      "OneShotShelvedToUnshelved"},
    {ObjectId::ShelvedStateMachineType_OneShotShelved,
      ObjectId::ShelvedStateMachineType_TimedShelved,
      ObjectId::ShelvedStateMachineType_OneShotShelvedToTimedShelved,
      "OneShotShelvedToTimedShelved"},
  };
  for (const auto& row : transitions)
  {
    if (from == NodeId{row.from} && to == NodeId{row.to})
    {
      return ConditionStateSnapshot::ShelveTransition{
        LocalizedText{"", row.name}, NodeId{row.transition}, DateTime::now()};
    }
  }
  return std::nullopt;
}

}  // namespace

void ConditionStateSnapshot::set_shelve_state(LocalizedText currentStateName, NodeId currentStateId)
{
  const std::lock_guard lock(mMutex);
  // The state is re-published on every Condition change; only a change of state is a transition.
  if (auto transition = shelve_transition(mShelveStateId, currentStateId))
  {
    mLastShelveTransition = std::move(*transition);
  }
  mShelveStateName = std::move(currentStateName);
  mShelveStateId = std::move(currentStateId);
}

ConditionStateSnapshot::ShelveTransition ConditionStateSnapshot::last_shelve_transition() const
{
  const std::lock_guard lock(mMutex);
  return mLastShelveTransition;
}

UnshelveClock ConditionStateSnapshot::unshelve_clock() const
{
  const std::lock_guard lock(mMutex);
  return mUnshelveClock;
}

void ConditionStateSnapshot::set_unshelve_clock(UnshelveClock clock)
{
  const std::lock_guard lock(mMutex);
  mUnshelveClock = clock;
}

// --- Private helpers (called with mutex held) ---

void ConditionStateSnapshot::update_condition_fields(const ConditionPayload& event)
{
  // Base BaseEventType / ConditionType fields, mirrored so the condition NODE's mandatory property
  // variables (EventId, EventType, Time, ReceiveTime, Message, ConditionClassId/Name, ConditionName,
  // SourceNode/Name) are readable from the address space, not just carried in the event notification.
  mEventId = event.eventId;
  mEventType = event.eventType;
  mSourceNode = event.sourceNode;
  mSourceName = event.sourceName;
  mTime = event.time;
  mReceiveTime = event.receiveTime;
  mMessage = event.message;
  mConditionClassId = event.conditionClassId;
  mConditionClassName = event.conditionClassName;
  mConditionName = event.conditionName;
  mBranchId = event.branchId;
  mClientUserId = event.clientUserId;

  mEnabled = event.enabledState.id;
  mRetain = event.retain;
  mEnabledState = event.enabledState;
  mSeverity = event.severity;

  if (auto* statusCode = event.quality.value.try_as<StatusCode>())
  {
    mQuality = *statusCode;
  }
  mQualitySourceTimestamp = event.quality.sourceTimestamp;

  if (auto* severityValue = event.lastSeverity.value.try_as<uint16_t>())
  {
    mLastSeverity = *severityValue;
  }
  mLastSeveritySourceTimestamp = event.lastSeverity.sourceTimestamp;

  if (auto* commentText = event.comment.value.try_as<LocalizedText>())
  {
    mComment = *commentText;
  }
  mCommentSourceTimestamp = event.comment.sourceTimestamp;
}

void ConditionStateSnapshot::update_acknowledgeable_fields(const AcknowledgeableConditionPayload& event)
{
  mAcked = event.ackedState.id;
  mAckedState = event.ackedState;

  if (event.confirmedState.has_value())
  {
    mConfirmed = event.confirmedState->id;
    mConfirmedState = *event.confirmedState;
  }
}

void ConditionStateSnapshot::update_alarm_fields(const AlarmConditionPayload& event)
{
  mActive = event.activeState.id;
  mActiveState = event.activeState;
  mInputNode = event.inputNode;
  mSuppressedOrShelved = event.suppressedOrShelved;
  mSuppressedState = event.suppressedState;
  mOutOfServiceState = event.outOfServiceState;
  mSilenceState = event.silenceState;
  mLatchedState = event.latchedState;
}

}  // namespace ua
