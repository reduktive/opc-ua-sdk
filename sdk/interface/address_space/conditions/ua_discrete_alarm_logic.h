// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief State machine logic for the OPC UA DiscreteAlarmType (Part 9).
/// @ingroup address_space

#ifndef UA_DISCRETE_ALARM_LOGIC_H
#define UA_DISCRETE_ALARM_LOGIC_H

#include "ua_alarm_condition_logic.h"

namespace ua
{

namespace test
{
class DiscreteAlarmLogicTestAccess;
}  // namespace test

/// Pure state machine for the OPC UA DiscreteAlarmType (Part 9).
///
/// A discrete alarm is driven by changes to a discrete input rather than by
/// limit comparison against an analog process value. It inherits the full
/// AlarmConditionLogic behavior (activation, shelving, suppression,
/// out-of-service, silence, latching, on/off delays) unchanged and only
/// specializes the emitted event type. Like its bases it performs no I/O and
/// touches no address space or strand; a strand-serialized shell drives it.
///
/// @ingroup address_space
class DiscreteAlarmLogic : public AlarmConditionLogic
{
public:
  ~DiscreteAlarmLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  DiscreteAlarmLogic(const DiscreteAlarmLogic&) = delete;
  DiscreteAlarmLogic& operator=(const DiscreteAlarmLogic&) = delete;
  DiscreteAlarmLogic(DiscreteAlarmLogic&&) = delete;
  DiscreteAlarmLogic& operator=(DiscreteAlarmLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  DiscreteAlarmLogic() = default;
  // --- Event building ---

  /// Builds a DiscreteAlarm event struct from the current alarm state.
  ///
  /// Overrides AlarmConditionLogic::build_event so the snapshot carries the
  /// DiscreteAlarmType event fields; the rest of the payload is populated from
  /// the inherited alarm state.
  ///
  /// @return An owning handle to the freshly built event; never null.
  std::unique_ptr<BaseEvent> build_event() const override;

private:
  friend class test::DiscreteAlarmLogicTestAccess;
};

}  // namespace ua

#endif  // !UA_DISCRETE_ALARM_LOGIC_H
