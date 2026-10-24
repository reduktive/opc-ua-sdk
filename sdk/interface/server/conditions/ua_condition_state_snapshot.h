// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Thread-safe snapshot of condition state for cross-strand reads.
/// @ingroup server

#ifndef UA_CONDITION_STATE_SNAPSHOT_H
#define UA_CONDITION_STATE_SNAPSHOT_H

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_variable_states.h"
#include "ua_alarm_condition_logic.h"

#include <cstdint>
#include <mutex>
#include <optional>

namespace ua
{

// Forward declarations for event types (full definitions in .cpp)
struct ConditionPayload;
struct AcknowledgeableConditionPayload;
struct AlarmConditionPayload;

/// Thread-safe snapshot of a condition's current state, readable from any thread.
///
/// A condition's authoritative state lives on its `ConditionInstance` strand. This snapshot
/// mirrors the subset of that state that must be read outside the strand - for example by an
/// `ExternalValueSource` handler servicing an attribute read on an unrelated thread. The
/// `ConditionInstance` writes the snapshot from its strand via the `update_from` overloads; readers
/// call the getters from any thread. Every read and write is serialized by an internal mutex, so no
/// external synchronization is required.
///
/// Getters return values by copy. For the optional alarm sub-states (suppression, out-of-service,
/// silencing, latching) the `std::optional<bool>` accessor is empty when the condition does not
/// model that capability, while the paired current-state/transition-time accessors return
/// default-constructed values in that case.
/// @ingroup server
class ConditionStateSnapshot
{
public:
  // --- Thread-safe getters (read under mutex) ---

  /// Returns the EventId of the most recently emitted event for this condition.
  /// @return EventId of the most recently emitted event for this condition.
  ByteString event_id() const;

  /// Returns the concrete EventType of the condition (its type-definition NodeId).
  /// @return The condition's concrete EventType (its type-definition NodeId).
  NodeId event_type() const;

  /// Returns the NodeId of the condition's source node.
  /// @return NodeId of the condition's source node.
  NodeId source_node() const;

  /// Returns the human-readable name of the condition's source.
  /// @return Human-readable name of the condition's source.
  String source_name() const;

  /// Returns the time the condition's most recent event was generated.
  /// @return Time the condition's most recent event was generated.
  DateTime time() const;

  /// Returns the time the condition's most recent event was received for processing.
  /// @return Time the condition's most recent event was received for processing.
  DateTime receive_time() const;

  /// Returns the condition's current message.
  /// @return The condition's current message.
  LocalizedText message() const;

  /// Returns the ConditionClassId (the well-known condition-class type, Part 9).
  /// @return ConditionClassId (the well-known condition-class type, Part 9).
  NodeId condition_class_id() const;

  /// Returns the ConditionClassName (display name of the condition class).
  /// @return ConditionClassName (display name of the condition class).
  LocalizedText condition_class_name() const;

  /// Returns the ConditionName (the application-assigned name of this condition).
  /// @return ConditionName (the application-assigned name of this condition).
  String condition_name() const;

  /// Returns the BranchId of the condition (null NodeId for the main/current branch).
  /// @return BranchId of the condition (null NodeId for the main/current branch).
  NodeId branch_id() const;

  /// Returns the ClientUserId - the identity of the client that last drove a state change.
  /// @return ClientUserId - the identity of the client that last drove a state change.
  String client_user_id() const;

  /// Returns the NonExclusiveLimitAlarm HighHighState, or empty if not a non-exclusive limit alarm.
  /// @return NonExclusiveLimitAlarm HighHighState, or an empty optional if not a non-exclusive limit
  /// alarm.
  std::optional<TwoStateVariableState> high_high_state() const;

  /// Returns the NonExclusiveLimitAlarm HighState, or empty if not a non-exclusive limit alarm.
  /// @return NonExclusiveLimitAlarm HighState, or an empty optional if not a non-exclusive limit
  /// alarm.
  std::optional<TwoStateVariableState> high_state() const;

  /// Returns the NonExclusiveLimitAlarm LowState, or empty if not a non-exclusive limit alarm.
  /// @return NonExclusiveLimitAlarm LowState, or an empty optional if not a non-exclusive limit
  /// alarm.
  std::optional<TwoStateVariableState> low_state() const;

  /// Returns the NonExclusiveLimitAlarm LowLowState, or empty if not a non-exclusive limit alarm.
  /// @return NonExclusiveLimitAlarm LowLowState, or an empty optional if not a non-exclusive limit
  /// alarm.
  std::optional<TwoStateVariableState> low_low_state() const;

  /// Returns the ExclusiveLimitAlarm LimitState.CurrentState display name (empty when no limit active).
  /// @return ExclusiveLimitAlarm LimitState.CurrentState display name (empty when no limit is
  /// active).
  LocalizedText limit_state_name() const;

  /// Returns the ExclusiveLimitAlarm LimitState.CurrentState.Id (the state NodeId; null when inactive).
  /// @return ExclusiveLimitAlarm LimitState.CurrentState.Id (the state NodeId; null when inactive).
  NodeId limit_state_id() const;

  /// Returns the AlarmCondition ShelvingState.CurrentState display name (e.g. "Unshelved").
  /// @return AlarmCondition ShelvingState.CurrentState display name (e.g. "Unshelved").
  LocalizedText shelve_state_name() const;

  /// Returns the AlarmCondition ShelvingState.CurrentState.Id (the ShelvedStateMachineType state NodeId).
  /// @return AlarmCondition ShelvingState.CurrentState.Id (the ShelvedStateMachineType state NodeId).
  NodeId shelve_state_id() const;

  /// The last transition of the ShelvingState machine, read by ShelvingState.LastTransition.
  struct ShelveTransition
  {
    LocalizedText name;  ///< The transition's name, e.g. "UnshelvedToTimedShelved"; empty before the first.
    NodeId id;  ///< The ShelvedStateMachineType transition NodeId; null before the first.
    DateTime time;  ///< When the transition happened; the minimum DateTime before the first.
  };

  /// Returns the last shelving transition (all fields empty until the first transition).
  /// @return The last shelving transition.
  ShelveTransition last_shelve_transition() const;

  /// The clock ShelvingState.UnshelveTime is evaluated from at read time.
  /// @return The alarm's UnshelveClock as of its last change.
  UnshelveClock unshelve_clock() const;

  /// Records the alarm's UnshelveClock. Called by the owning `ConditionInstance` from its strand.
  /// @param clock The alarm logic's current clock.
  void set_unshelve_clock(UnshelveClock clock);

  /// Returns whether the condition is enabled.
  /// @return True if the condition is enabled.
  bool enabled() const;

  /// Returns whether the condition is retained (currently of interest to a client).
  /// @return True if the condition is retained (currently of interest to a client).
  bool retained() const;

  /// Returns the current severity, on the OPC UA 1..1000 scale.
  /// @return Current severity, on the OPC UA 1..1000 scale.
  uint16_t severity() const;

  /// Returns the quality of the condition's underlying value.
  /// @return Quality of the condition's underlying value.
  StatusCode quality() const;

  /// Returns the source timestamp of the current quality.
  /// @return Source timestamp of the current quality.
  DateTime quality_source_timestamp() const;

  /// Returns the most recent comment associated with the condition.
  /// @return Most recent comment associated with the condition.
  LocalizedText comment() const;

  /// Returns the source timestamp of the current comment.
  /// @return Source timestamp of the current comment.
  DateTime comment_source_timestamp() const;

  /// Returns the previous severity, recorded when severity last changed.
  /// @return Previous severity, recorded when severity last changed.
  uint16_t last_severity() const;

  /// Returns the source timestamp at which @ref last_severity was recorded.
  /// @return Source timestamp at which @ref last_severity was recorded.
  DateTime last_severity_source_timestamp() const;

  /// Returns whether the condition has been acknowledged.
  /// @return True if the condition has been acknowledged.
  bool acked() const;

  /// Returns the time of the last transition of the AckedState two-state variable.
  /// @return Time of the last transition of the AckedState two-state variable.
  DateTime acked_transition_time() const;

  /// Returns the localized name of the current AckedState.
  /// @return Localized name of the current AckedState.
  LocalizedText acked_current_state() const;

  /// Returns whether the condition has been confirmed.
  /// @return True if the condition has been confirmed.
  bool confirmed() const;

  /// Returns the time of the last transition of the ConfirmedState two-state variable.
  /// @return Time of the last transition of the ConfirmedState two-state variable.
  DateTime confirmed_transition_time() const;

  /// Returns the localized name of the current ConfirmedState.
  /// @return Localized name of the current ConfirmedState.
  LocalizedText confirmed_current_state() const;

  /// Returns whether the alarm is active.
  /// @return True if the alarm is active.
  bool active() const;

  /// Returns the time of the last transition of the ActiveState two-state variable.
  /// @return Time of the last transition of the ActiveState two-state variable.
  DateTime active_transition_time() const;

  /// Returns the localized name of the current ActiveState.
  /// @return Localized name of the current ActiveState.
  LocalizedText active_current_state() const;

  /// Returns the localized name of the current EnabledState.
  /// @return Localized name of the current EnabledState.
  LocalizedText enabled_current_state() const;

  /// Returns the time of the last transition of the EnabledState two-state variable.
  /// @return Time of the last transition of the EnabledState two-state variable.
  DateTime enabled_transition_time() const;

  /// Returns whether the alarm is currently suppressed or shelved.
  /// @return True if the alarm is currently suppressed or shelved.
  bool suppressed_or_shelved() const;

  /// Returns the node whose value drives this alarm's input.
  /// @return NodeId of the node whose value drives this alarm's input.
  NodeId input_node() const;

  /// Returns the suppression state, or an empty optional if the condition does not model
  /// suppression.
  /// @return Suppression state, or an empty optional if the condition does not model suppression.
  std::optional<bool> suppressed() const;

  /// Returns the localized name of the current SuppressedState, or an empty value if not modelled.
  /// @return Localized name of the current SuppressedState, or an empty value if not modelled.
  LocalizedText suppressed_current_state() const;

  /// Returns the time of the last SuppressedState transition, or a default value if not modelled.
  /// @return Time of the last SuppressedState transition, or a default value if not modelled.
  DateTime suppressed_transition_time() const;

  /// Returns the out-of-service state, or an empty optional if the condition does not model it.
  /// @return Out-of-service state, or an empty optional if the condition does not model it.
  std::optional<bool> out_of_service() const;

  /// Returns the localized name of the current OutOfServiceState, or an empty value if not
  /// modelled.
  /// @return Localized name of the current OutOfServiceState, or an empty value if not modelled.
  LocalizedText out_of_service_current_state() const;

  /// Returns the time of the last OutOfServiceState transition, or a default value if not modelled.
  /// @return Time of the last OutOfServiceState transition, or a default value if not modelled.
  DateTime out_of_service_transition_time() const;

  /// Returns the silencing state, or an empty optional if the condition does not model silencing.
  /// @return Silencing state, or an empty optional if the condition does not model silencing.
  std::optional<bool> silenced() const;

  /// Returns the localized name of the current SilenceState, or an empty value if not modelled.
  /// @return Localized name of the current SilenceState, or an empty value if not modelled.
  LocalizedText silenced_current_state() const;

  /// Returns the time of the last SilenceState transition, or a default value if not modelled.
  /// @return Time of the last SilenceState transition, or a default value if not modelled.
  DateTime silenced_transition_time() const;

  /// Returns the latching state, or an empty optional if the condition does not model latching.
  /// @return Latching state, or an empty optional if the condition does not model latching.
  std::optional<bool> latched() const;

  /// Returns the localized name of the current LatchedState, or an empty value if not modelled.
  /// @return Localized name of the current LatchedState, or an empty value if not modelled.
  LocalizedText latched_current_state() const;

  /// Returns the time of the last LatchedState transition, or a default value if not modelled.
  /// @return Time of the last LatchedState transition, or a default value if not modelled.
  DateTime latched_transition_time() const;

  // --- Thread-safe updates (write under mutex) --- called from ConditionInstance strand

  /// Updates the snapshot's base condition fields from a condition event payload.
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param event Source payload supplying the base condition fields.
  void update_from(const ConditionPayload& event);

  /// Updates the snapshot's acknowledgement-related fields from an acknowledgeable condition
  /// payload.
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param event Source payload supplying the acknowledge/confirm fields.
  void update_from(const AcknowledgeableConditionPayload& event);

  /// Updates the snapshot's alarm-related fields from an alarm condition payload.
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param event Source payload supplying the alarm fields.
  void update_from(const AlarmConditionPayload& event);

  /// Sets the NonExclusiveLimitAlarm per-limit sub-states (empty for non-limit / exclusive alarms).
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param highHigh HighHighState sub-state, or an empty optional when the limit is not modelled.
  /// @param high HighState sub-state, or an empty optional when the limit is not modelled.
  /// @param low LowState sub-state, or an empty optional when the limit is not modelled.
  /// @param lowLow LowLowState sub-state, or an empty optional when the limit is not modelled.
  void set_non_exclusive_limit_states(std::optional<TwoStateVariableState> highHigh,
    std::optional<TwoStateVariableState> high, std::optional<TwoStateVariableState> low,
    std::optional<TwoStateVariableState> lowLow);

  /// Sets the ExclusiveLimitAlarm LimitState.CurrentState name + state NodeId.
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param currentStateName Display name of the LimitState.CurrentState.
  /// @param currentStateId NodeId of the LimitState.CurrentState.
  void set_exclusive_limit_state(LocalizedText currentStateName, NodeId currentStateId);

  /// Sets the AlarmCondition ShelvingState.CurrentState name + ShelvedStateMachineType state NodeId.
  ///
  /// Called by the owning `ConditionInstance` from its strand. Acquires the internal mutex.
  ///
  /// @param currentStateName Display name of the ShelvingState.CurrentState.
  /// @param currentStateId NodeId of the ShelvingState.CurrentState (a ShelvedStateMachineType
  /// state).
  void set_shelve_state(LocalizedText currentStateName, NodeId currentStateId);

private:
  // Helpers called with mutex already held
  void update_condition_fields(const ConditionPayload& event);
  void update_acknowledgeable_fields(const AcknowledgeableConditionPayload& event);
  void update_alarm_fields(const AlarmConditionPayload& event);

  mutable std::mutex mMutex;

  // Base condition fields
  ByteString mEventId{};
  NodeId mEventType{};
  NodeId mSourceNode{};
  String mSourceName{};
  DateTime mTime{};
  DateTime mReceiveTime{};
  LocalizedText mMessage{};
  NodeId mConditionClassId{};
  LocalizedText mConditionClassName{};
  String mConditionName{};
  NodeId mBranchId{};
  String mClientUserId{};
  bool mEnabled{false};
  bool mRetain{false};
  uint16_t mSeverity{0};
  StatusCode mQuality{};
  DateTime mQualitySourceTimestamp{};
  LocalizedText mComment{};
  DateTime mCommentSourceTimestamp{};
  uint16_t mLastSeverity{0};
  DateTime mLastSeveritySourceTimestamp{};
  TwoStateVariableState mEnabledState{};

  // AcknowledgeableConditionPayload fields
  bool mAcked{false};
  TwoStateVariableState mAckedState{};
  bool mConfirmed{false};
  TwoStateVariableState mConfirmedState{};

  // AlarmConditionPayload fields
  bool mActive{false};
  TwoStateVariableState mActiveState{};
  NodeId mInputNode{};
  bool mSuppressedOrShelved{false};
  std::optional<TwoStateVariableState> mSuppressedState;
  std::optional<TwoStateVariableState> mOutOfServiceState;
  std::optional<TwoStateVariableState> mSilenceState;
  std::optional<TwoStateVariableState> mLatchedState;

  // Limit-alarm sub-states. Non-exclusive: per-limit TwoStateVariables. Exclusive: the
  // ExclusiveLimitStateMachine LimitState.CurrentState (name + state NodeId).
  std::optional<TwoStateVariableState> mHighHighState;
  std::optional<TwoStateVariableState> mHighState;
  std::optional<TwoStateVariableState> mLowState;
  std::optional<TwoStateVariableState> mLowLowState;
  LocalizedText mLimitStateName{};
  NodeId mLimitStateId{};

  // AlarmCondition ShelvingState.CurrentState (a ShelvedStateMachineType). Derived from the alarm
  // logic's ShelveState (not carried in any payload), mirrored here for the wired CurrentState node.
  LocalizedText mShelveStateName{};
  NodeId mShelveStateId{};
  ShelveTransition mLastShelveTransition{};
  UnshelveClock mUnshelveClock{};
};

}  // namespace ua

#endif  // !UA_CONDITION_STATE_SNAPSHOT_H
