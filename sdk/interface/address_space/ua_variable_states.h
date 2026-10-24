// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Snapshots of state-machine / condition-variable instances for event field resolution.
/// @ingroup address_space

#ifndef UA_VARIABLE_STATES_H
#define UA_VARIABLE_STATES_H

#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_variant.h"

namespace ua
{

/// Snapshot of a FiniteStateMachine's CurrentState for an event payload.
///
/// Carries the two fields a client selects via an EventFilter on a state-machine
/// component (e.g. ExclusiveLimitAlarmType's LimitState): the CurrentState Value
/// (the human-readable state name, a LocalizedText) and its Id property (the
/// NodeId of the active state). Mirrors @ref TwoStateVariableState but for a
/// FiniteStateVariableType, whose Id is a NodeId rather than a boolean.
/// @ingroup address_space
struct FiniteStateVariableState
{
  LocalizedText currentState{};  ///< CurrentState Value: the active state's display name.
  NodeId id{};  ///< CurrentState.Id: the NodeId of the active state.
};

/// Snapshot of an AlarmCondition's ShelvingState (a ShelvedStateMachineType) for event field resolution.
///
/// The FiniteStateVariableState pair plus the machine's Mandatory UnshelveTime Property, which OPC 10000-9
/// 5.8.17.1 defines as "the remaining time in milliseconds until the Alarm automatically transitions into
/// the Un-shelved state": the ShelvingTime for a TimedShelve, MaxTimeShelved (or the maximum Duration) for
/// a OneShotShelve.
/// @ingroup address_space
struct ShelvedStateVariableState
{
  LocalizedText currentState{};  ///< ShelvingState/CurrentState Value.
  NodeId id{};  ///< ShelvingState/CurrentState/Id.
  double unshelveTime{};  ///< ShelvingState/UnshelveTime, a Duration in milliseconds.
};

/// Snapshot of a ConditionVariableType instance's state for event field resolution.
///
/// Used as a compound field in generated condition event structs. Holds the current value
/// and the source timestamp of that value, mirroring the Value attribute and its
/// SourceTimestamp on a ConditionVariableType instance.
/// @ingroup address_space
struct ConditionVariableState
{
  Variant value{};  ///< Current value of the condition variable.
  DateTime sourceTimestamp{};  ///< Source timestamp of @ref value.
};

/// Snapshot of a TwoStateVariableType instance's state for event field resolution.
///
/// Used as a compound field in generated condition event structs. Mirrors the Id and
/// EffectiveDisplayName (CurrentState) of a TwoStateVariableType instance together with the
/// timestamp of the last state transition.
/// @ingroup address_space
struct TwoStateVariableState
{
  bool id{false};  ///< Current boolean state: the Id property of the TwoStateVariableType.
  LocalizedText currentState{};  ///< Display text for the active state, e.g. "Enabled"/"Disabled".
  DateTime transitionTime{};  ///< Timestamp of the most recent transition of @ref id.
};

}  // namespace ua

#endif  // !UA_VARIABLE_STATES_H
