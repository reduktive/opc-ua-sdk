// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DISCREPANCY_ALARM_LOGIC_H
#define UA_DISCREPANCY_ALARM_LOGIC_H

/// @file
/// @brief State machine for the OPC UA DiscrepancyAlarmType alarm.
/// @ingroup address_space

#include "ua_alarm_condition_logic.h"
#include "ua_node_id.h"
#include "ua_variant.h"

#include <optional>

namespace ua
{

namespace test
{
class DiscrepancyAlarmLogicTestAccess;
}  // namespace test

/// State machine for the OPC UA DiscrepancyAlarmType (Part 9, 5.8.25).
///
/// Monitors whether an input value reaches a configured target value within an
/// expected time. When the input differs from the target (outside tolerance) for
/// longer than the expected time, the alarm activates; when the input reaches the
/// target, the alarm deactivates. Like every ConditionLogic this is a pure state
/// machine: it performs no I/O, owns no strand, and is driven by a shell component
/// that feeds it inputs and acts on the returned transitions.
/// @ingroup address_space
class DiscrepancyAlarmLogic : public AlarmConditionLogic
{
public:
  ~DiscrepancyAlarmLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  DiscrepancyAlarmLogic(const DiscrepancyAlarmLogic&) = delete;
  DiscrepancyAlarmLogic& operator=(const DiscrepancyAlarmLogic&) = delete;
  DiscrepancyAlarmLogic(DiscrepancyAlarmLogic&&) = delete;
  DiscrepancyAlarmLogic& operator=(DiscrepancyAlarmLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  DiscrepancyAlarmLogic() = default;
  // --- Configuration ---

  /// Sets the NodeId of the variable that holds the target value.
  ///
  /// Identifies the address-space node the shell reads to populate the target; this
  /// logic object itself performs no read.
  ///
  /// @param nodeId NodeId of the target-value variable.
  void set_target_value_node(NodeId nodeId);

  /// Sets the time the input may discrepate from the target before the alarm activates.
  ///
  /// @param ms Expected time to reach the target, in milliseconds.
  void set_expected_time(double ms);

  /// Sets the tolerance band used for target comparison.
  ///
  /// When set, the input counts as at-target while `|value - target| <= tolerance`;
  /// when unset, an exact match is required.
  ///
  /// @param tolerance Maximum absolute difference, in input units, still treated as
  ///                  at-target.
  void set_tolerance(double tolerance);

  /// Sets the current target value the input is compared against.
  ///
  /// @param value Target value; its type should match the input supplied to
  ///              evaluate_input.
  void set_target_value(Variant value);

  // --- Input evaluation ---

  /// Evaluates a new input sample against the target and updates alarm state.
  ///
  /// Activates the alarm once the input has stayed outside tolerance of the target for
  /// longer than the expected time, and deactivates it once the input is at-target.
  /// Pure and synchronous: it mutates only this object's state and returns the
  /// resulting transition for the shell to act on (emit events, run timers).
  ///
  /// @param value     The input sample to evaluate.
  /// @param timestamp Source timestamp of the sample, used to measure how long the
  ///                  input has been discrepant.
  /// @return The state transition produced by the evaluation.
  ConditionStateTransition evaluate_input(const Variant& value, DateTime timestamp) override;

  // --- Event building ---

  /// Builds a DiscrepancyAlarmType event populated from the current state.
  ///
  /// @return An owning event struct carrying this alarm's fields; never null.
  std::unique_ptr<BaseEvent> build_event() const override;

protected:
  /// Returns the NodeId of the target-value variable set by set_target_value_node.
  ///
  /// @return Reference valid for the lifetime of this object.
  const NodeId& target_value_node() const;

  /// Returns the expected time to reach the target, in milliseconds.
  ///
  /// @return The expected time to reach the target, in milliseconds.
  double expected_time_ms() const;

  /// Returns the configured tolerance band, or an empty optional if none is set.
  ///
  /// @return Reference valid for the lifetime of this object.
  const std::optional<double>& tolerance() const;

private:
  friend class test::DiscrepancyAlarmLogicTestAccess;

  /// Try to extract a double from the given Variant. Returns false if the value is not numeric.
  ///
  /// @param value Variant to extract a numeric value from.
  /// @param[out] out Receives the extracted double when @p value is numeric.
  /// @return true if @p value was numeric and @p out was populated; false otherwise.
  static bool try_extract_double(const Variant& value, double& out);

  bool is_at_target(const Variant& value) const;

  NodeId mTargetValueNode{};
  double mExpectedTimeMs{0.0};
  std::optional<double> mTolerance;
  Variant mTargetValue{};
  std::optional<DateTime> mDiscrepancyStart;
};

}  // namespace ua

#endif  // !UA_DISCREPANCY_ALARM_LOGIC_H
