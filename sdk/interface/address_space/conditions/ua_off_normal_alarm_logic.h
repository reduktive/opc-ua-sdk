// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OFF_NORMAL_ALARM_LOGIC_H
#define UA_OFF_NORMAL_ALARM_LOGIC_H

/// @file
/// @brief State machine for the OPC UA OffNormalAlarmType alarm.
/// @ingroup address_space

#include "ua_discrete_alarm_logic.h"
#include "ua_node_id.h"
#include "ua_variant.h"

namespace ua
{

namespace test
{
class OffNormalAlarmLogicTestAccess;
}  // namespace test

/// State machine for the OPC UA OffNormalAlarmType (Part 9).
///
/// Extends @ref DiscreteAlarmLogic with a comparison against a configured
/// "normal" state. On each input evaluation the alarm activates when the input
/// value differs from the normal state and deactivates when it equals the
/// normal state. The comparison is by value equality of the @ref Variant.
/// @ingroup address_space
class OffNormalAlarmLogic : public DiscreteAlarmLogic
{
public:
  ~OffNormalAlarmLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  OffNormalAlarmLogic(const OffNormalAlarmLogic&) = delete;
  OffNormalAlarmLogic& operator=(const OffNormalAlarmLogic&) = delete;
  OffNormalAlarmLogic(OffNormalAlarmLogic&&) = delete;
  OffNormalAlarmLogic& operator=(OffNormalAlarmLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  OffNormalAlarmLogic() = default;
  // --- Configuration ---

  /// Sets the value that represents the "normal" (non-alarming) state.
  ///
  /// The input passed to @ref evaluate_input is compared against this value;
  /// equality means normal (deactivated), inequality means off-normal
  /// (activated).
  ///
  /// @param normalValue Value taken to represent the normal state.
  void set_normal_state(Variant normalValue);

  /// Sets the NodeId of the NormalState property exposed by the alarm node.
  ///
  /// @param nodeId NodeId of the NormalState property in the address space.
  void set_normal_state_node(NodeId nodeId);

  // --- Input evaluation ---

  /// Evaluates a new input value against the normal state and returns the
  /// resulting condition state transition.
  ///
  /// Activates the alarm when @p value differs from the configured normal
  /// state and deactivates it when @p value equals the normal state.
  ///
  /// @param value     New input value to evaluate.
  /// @param timestamp Source timestamp associated with the input change.
  /// @return The transition describing any resulting condition state change.
  ConditionStateTransition evaluate_input(const Variant& value, DateTime timestamp) override;

  // --- Event building ---

  /// Builds an OffNormalAlarm event reflecting the current alarm state.
  ///
  /// @return A newly allocated event whose ownership is transferred to the
  ///         caller; never null.
  std::unique_ptr<BaseEvent> build_event() const override;

protected:
  /// Returns the configured normal-state value.
  ///
  /// Intended for subclasses that refine off-normal evaluation. The reference
  /// remains valid until the next call to @ref set_normal_state.
  ///
  /// @return The value representing the normal (non-alarming) state.
  const Variant& normal_state() const;

  /// Returns the NodeId of the NormalState property.
  ///
  /// Intended for subclasses. The reference remains valid until the next call
  /// to @ref set_normal_state_node.
  ///
  /// @return The NodeId of the NormalState property node.
  const NodeId& normal_state_node() const;

private:
  friend class test::OffNormalAlarmLogicTestAccess;

  Variant mNormalState{};
  NodeId mNormalStateNode{};
};

}  // namespace ua

#endif  // !UA_OFF_NORMAL_ALARM_LOGIC_H
