// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Limit-alarm state machine for the OPC UA LimitAlarmType (Part 9).
/// @ingroup address_space

#ifndef UA_LIMIT_ALARM_LOGIC_H
#define UA_LIMIT_ALARM_LOGIC_H

#include "ua_alarm_condition_logic.h"
#include "ua_date_time.h"

#include <cstdint>
#include <optional>

namespace ua
{

class Variant;

namespace test
{
class LimitAlarmLogicTestAccess;
}  // namespace test

/// Which limit threshold is currently active, in exclusive limit mode.
///
/// Reported by `LimitAlarmLogic::active_limit`. In non-exclusive mode each
/// limit is tracked independently and this enum is not used.
enum class ActiveLimit
{
  None,  ///< No limit is currently violated.
  HighHigh,  ///< The HighHigh limit is active (most severe high side).
  High,  ///< The High limit is active.
  Low,  ///< The Low limit is active.
  LowLow  ///< The LowLow limit is active (most severe low side).
};

/// One limit exposed by a LimitAlarmType.
///
/// A configured limit may carry its numeric threshold or may be unavailable because the underlying
/// system cannot supply the actual value. The latter remains an exposed Property but is excluded
/// from alarm evaluation and has no Event-field value.
/// @ingroup address_space
class ConfiguredLimit final
{
public:
  /// Constructs an available configured limit.
  /// @param value Numeric threshold in the input's engineering units.
  ConfiguredLimit(double value) noexcept : mValue(value)
  {}

  /// Replaces this limit with an available numeric threshold.
  /// @param value Numeric threshold in the input's engineering units.
  /// @return This configured limit.
  ConfiguredLimit& operator=(double value) noexcept
  {
    mValue = value;
    return *this;
  }

  /// Constructs a configured limit whose actual value is unavailable.
  /// @return A present but unavailable limit.
  static ConfiguredLimit unavailable() noexcept
  {
    return ConfiguredLimit{};
  }

  /// Returns whether the underlying system supplied the numeric threshold.
  /// @return `true` when a threshold was supplied; `false` when the limit is configured - the
  ///         model declares it - but its actual value is not known to this server.
  bool is_available() const noexcept
  {
    return mValue.has_value();
  }

  /// Returns the supplied threshold, or empty when its actual value is unavailable.
  /// @return The threshold in the input's engineering units, or an empty optional when the limit
  ///         is configured but unavailable - the same distinction @ref is_available reports.
  const std::optional<double>& value() const noexcept
  {
    return mValue;
  }

private:
  ConfiguredLimit() = default;

  std::optional<double> mValue;
};

/// Configuration for limit thresholds, per-limit deadbands, and per-limit severities.
///
/// Each limit has three states: an absent outer optional is not exposed, an available
/// ConfiguredLimit is exposed and evaluated, and an unavailable ConfiguredLimit is exposed with
/// CurrentRead cleared but is not evaluated. Available values use the same engineering units as the
/// alarm's input. Severities are OPC UA severity values in the range 1..1000.
/// @ingroup address_space
struct LimitConfig
{
  std::optional<ConfiguredLimit> highHighLimit;  ///< HighHigh limit; unset omits the Property.
  std::optional<ConfiguredLimit> highLimit;  ///< High limit; unset omits the Property.
  std::optional<ConfiguredLimit> lowLimit;  ///< Low limit; unset omits the Property.
  std::optional<ConfiguredLimit> lowLowLimit;  ///< LowLow limit; unset omits the Property.

  /// Per-limit deadbands. Deadband prevents chattering at the limit boundary.
  /// Activation requires crossing the limit; deactivation requires returning past (limit - deadband)
  /// for high limits or (limit + deadband) for low limits.
  double highHighDeadband{0.0};  ///< Deadband for the HighHigh limit, in input units.
  double highDeadband{0.0};  ///< Deadband for the High limit, in input units.
  double lowDeadband{0.0};  ///< Deadband for the Low limit, in input units.
  double lowLowDeadband{0.0};  ///< Deadband for the LowLow limit, in input units.

  /// Per-limit severity values.
  uint16_t severityHighHigh{900};  ///< Severity reported while the HighHigh limit is active.
  uint16_t severityHigh{500};  ///< Severity reported while the High limit is active.
  uint16_t severityLow{500};  ///< Severity reported while the Low limit is active.
  uint16_t severityLowLow{900};  ///< Severity reported while the LowLow limit is active.
};

/// State machine for the OPC UA LimitAlarmType (Part 9).
///
/// Extends @ref AlarmConditionLogic with limit evaluation, deadband support, and
/// exclusive/non-exclusive limit modes.
///
/// In exclusive mode, only the most severe violated limit is active at a time.
/// In non-exclusive mode, each limit is evaluated independently and multiple
/// can be active simultaneously.
///
/// @ingroup address_space
class LimitAlarmLogic : public AlarmConditionLogic
{
public:
  ~LimitAlarmLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  LimitAlarmLogic(const LimitAlarmLogic&) = delete;
  LimitAlarmLogic& operator=(const LimitAlarmLogic&) = delete;
  LimitAlarmLogic(LimitAlarmLogic&&) = delete;
  LimitAlarmLogic& operator=(LimitAlarmLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  LimitAlarmLogic() = default;
  // --- Configuration ---

  /// Sets the limit thresholds, deadbands, and severities.
  ///
  /// Replaces the entire configuration. Validates threshold ordering
  /// HighHigh > High > Low > LowLow for whichever limits are present.
  ///
  /// @param config New limit configuration; ownership is taken by value.
  /// @see limits, set_exclusive
  void set_limits(LimitConfig config);

  /// Selects exclusive (`true`) or non-exclusive (`false`) limit mode.
  ///
  /// Exclusive mode activates only the most severe violated limit at a time;
  /// non-exclusive mode evaluates each limit independently.
  ///
  /// @param exclusive `true` for exclusive mode, `false` for non-exclusive mode.
  /// @see exclusive
  void set_exclusive(bool exclusive);

  /// Enables evaluation of limits against the input's rate of change per second.
  ///
  /// Enabling this mode clears any previous sample. The first subsequent numeric sample establishes
  /// the derivative baseline and does not change alarm state.
  void enable_rate_of_change_per_second();

  // --- Limit state queries ---

  /// Returns the currently active limit.
  ///
  /// Meaningful only in exclusive mode; in non-exclusive mode use the per-limit
  /// `*_active` queries instead.
  ///
  /// @return The active limit, or @ref ActiveLimit::None when no limit is violated.
  /// @see high_high_active, high_active, low_active, low_low_active
  ActiveLimit active_limit() const;

  /// Returns whether the HighHigh limit is currently active (non-exclusive mode).
  /// @return `true` when the HighHigh limit is currently violated.
  bool high_high_active() const;

  /// Returns whether the High limit is currently active (non-exclusive mode).
  /// @return `true` when the High limit is currently violated.
  bool high_active() const;

  /// Returns whether the Low limit is currently active (non-exclusive mode).
  /// @return `true` when the Low limit is currently violated.
  bool low_active() const;

  /// Returns whether the LowLow limit is currently active (non-exclusive mode).
  /// @return `true` when the LowLow limit is currently violated.
  bool low_low_active() const;

  /// Returns the current limit configuration.
  ///
  /// @return A reference valid until the next @ref set_limits call.
  const LimitConfig& limits() const;

  /// Returns whether exclusive mode is enabled.
  /// @return `true` when exclusive limit mode is enabled, `false` for non-exclusive mode.
  bool exclusive() const;

  // --- Overrides ---

  /// Evaluates a new input value against the configured limits and updates state.
  ///
  /// Extracts a numeric value from @p value and applies the active limit mode and
  /// per-limit deadbands. A non-numeric value leaves the alarm state unchanged.
  ///
  /// @param value     New process value to evaluate; must be numeric to take effect.
  /// @param timestamp Source timestamp associated with the value.
  /// @return The resulting state transition (which states changed, and whether an
  ///         event should be emitted).
  ConditionStateTransition evaluate_input(const Variant& value, DateTime timestamp) override;

  /// Builds the event instance reflecting the current limit-alarm state.
  ///
  /// @return A newly allocated event populated with the current condition state;
  ///         ownership transfers to the caller.
  std::unique_ptr<BaseEvent> build_event() const override;

private:
  friend class test::LimitAlarmLogicTestAccess;

  /// Try to extract a double from the given Variant. Returns false if the value is not numeric.
  static bool try_extract_double(const Variant& value, double& out);

  /// Evaluate limits in exclusive mode. Returns the transition result.
  ConditionStateTransition evaluate_exclusive(double inputValue);

  /// Evaluate limits in non-exclusive mode. Returns the transition result.
  ConditionStateTransition evaluate_non_exclusive(double inputValue);

  /// Determine the most severe violated limit for the given input value,
  /// taking deadband into account for the current active limit.
  ActiveLimit compute_exclusive_limit(double inputValue) const;

  /// Check whether a high-side limit is violated, applying deadband for deactivation.
  static bool is_high_violated(double inputValue, double limit, double deadband, bool currentlyActive);

  /// Check whether a low-side limit is violated, applying deadband for deactivation.
  static bool is_low_violated(double inputValue, double limit, double deadband, bool currentlyActive);

  /// Return the severity for the given active limit.
  uint16_t severity_for_limit(ActiveLimit limit) const;

  /// Return the maximum severity across all currently active non-exclusive limits.
  uint16_t max_non_exclusive_severity() const;

  LimitConfig mLimits{};
  bool mExclusive{true};
  bool mRateOfChangePerSecond{false};
  std::optional<double> mPreviousInputValue;
  std::optional<DateTime> mPreviousInputTimestamp;

  // Exclusive mode state
  ActiveLimit mActiveLimit{ActiveLimit::None};

  // Non-exclusive mode state
  bool mHighHighActive{false};
  bool mHighActive{false};
  bool mLowActive{false};
  bool mLowLowActive{false};
  // When each non-exclusive limit state last changed - its TwoStateVariable TransitionTime (OPC 10000-9
  // 5.8.21). They start when the logic is created, which is when each state was entered.
  DateTime mHighHighTransitionTime{DateTime::now()};
  DateTime mHighTransitionTime{mHighHighTransitionTime};
  DateTime mLowTransitionTime{mHighHighTransitionTime};
  DateTime mLowLowTransitionTime{mHighHighTransitionTime};

  double mLastInputValue{0.0};
};

}  // namespace ua

#endif  // !UA_LIMIT_ALARM_LOGIC_H
