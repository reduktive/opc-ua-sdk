// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Pure state machine for the OPC UA AlarmConditionType (Part 9).
/// @ingroup address_space

#ifndef UA_ALARM_CONDITION_LOGIC_H
#define UA_ALARM_CONDITION_LOGIC_H

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_date_time.h"
#include "ua_node_id.h"
#include "ua_variable_states.h"

#include <cstdint>
#include <optional>

namespace ua
{

class Variant;
struct AlarmConditionPayload;

namespace test
{
class AlarmConditionLogicTestAccess;
}  // namespace test

/// Shelving state of an alarm, per the Part 9 ShelvedStateMachineType.
enum class ShelveState
{
  Unshelved,  ///< Not shelved; the alarm is reported normally.
  TimedShelved,  ///< Shelved for a fixed duration; auto-unshelves when the shelve timer expires.
  OneShotShelved,  ///< Shelved until the alarm next deactivates and reactivates.
};

/// What ShelvingState/UnshelveTime reports at a given moment (OPC 10000-9 5.8.17.1): the time left of a
/// TimedShelve, MaxTimeShelved - or the maximum Duration when there is none - for a OneShotShelve, and 0
/// when unshelved. A value, so a Read of UnshelveTime can evaluate it at read time without the logic,
/// with the same formula the alarm's events use.
struct UnshelveClock
{
  ShelveState state{ShelveState::Unshelved};  ///< The shelving state the clock describes.
  DateTime shelvedAt{};  ///< When the current TimedShelve began.
  double shelvingTimeMs{0.0};  ///< The TimedShelve's requested duration.
  double oneShotMs{0.0};  ///< What a OneShotShelve reports.

  /// UnshelveTime in milliseconds at @p now.
  /// @param now Time at which the remaining duration is evaluated.
  /// @return The remaining time in milliseconds for this shelving state.
  double remaining_ms(DateTime now) const noexcept;
};

/// Pure state machine for the OPC UA AlarmConditionType (Part 9).
///
/// Extends @ref AcknowledgeableConditionLogic with ActiveState plus the optional alarm
/// sub-states: shelving, suppression, out-of-service, silence, latching, and on/off delay
/// behaviour. Like its base classes this is a pure logic object: it performs no I/O, owns no
/// address space, and is not strand-serialized. Each mutator returns a
/// @ref ConditionStateTransition that a strand-serialized shell inspects to drive event
/// emission and timer commands; none of these methods throw.
/// @ingroup address_space
class AlarmConditionLogic : public AcknowledgeableConditionLogic
{
public:
  ~AlarmConditionLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  AlarmConditionLogic(const AlarmConditionLogic&) = delete;
  AlarmConditionLogic& operator=(const AlarmConditionLogic&) = delete;
  AlarmConditionLogic(AlarmConditionLogic&&) = delete;
  AlarmConditionLogic& operator=(AlarmConditionLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  AlarmConditionLogic() = default;
  // --- Activation ---

  /// Activates the alarm.
  ///
  /// Sets ActiveState.Id to true, resets AckedState and ConfirmedState, updates the severity,
  /// and requests an event when the condition is retained. Virtual so input-driven subclasses
  /// (e.g. LimitAlarmLogic) can extend activation.
  ///
  /// @param severity New alarm severity, 1..1000 per Part 8.
  /// @return The resulting state transition for the shell to apply.
  virtual ConditionStateTransition activate(uint16_t severity);

  /// Deactivates the alarm.
  ///
  /// Sets ActiveState.Id to false and requests an event when the condition is retained.
  /// Virtual so input-driven subclasses can extend deactivation.
  ///
  /// @return The resulting state transition for the shell to apply.
  virtual ConditionStateTransition deactivate();

  // --- Suppression ---

  /// Sets SuppressedState to suppressed.
  ///
  /// @return The resulting state transition. No-op unless suppression is supported.
  /// @see set_supports_suppressed
  ConditionStateTransition suppress();

  /// Suppresses the alarm and records a comment against it (Suppress2, OPC 10000-9 5.8.9).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref suppress().
  ConditionStateTransition suppress(const LocalizedText& comment);

  /// Clears SuppressedState back to unsuppressed.
  ///
  /// @return The resulting state transition. No-op unless suppression is supported.
  /// @see set_supports_suppressed
  ConditionStateTransition unsuppress();

  /// Unsuppresses the alarm and records a comment against it (Unsuppress2, OPC 10000-9 5.8.11).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref unsuppress().
  ConditionStateTransition unsuppress(const LocalizedText& comment);

  // --- Out of service ---

  /// Sets OutOfServiceState to out-of-service.
  ///
  /// @return The resulting state transition. No-op unless out-of-service is supported.
  /// @see set_supports_out_of_service
  ConditionStateTransition remove_from_service();

  /// Takes the alarm out of service and records a comment against it
  /// (RemoveFromService2, OPC 10000-9 5.8.13).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref remove_from_service().
  ConditionStateTransition remove_from_service(const LocalizedText& comment);

  /// Clears OutOfServiceState back to in-service.
  ///
  /// @return The resulting state transition. No-op unless out-of-service is supported.
  /// @see set_supports_out_of_service
  ConditionStateTransition place_in_service();

  /// Returns the alarm to service and records a comment against it
  /// (PlaceInService2, OPC 10000-9 5.8.15).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref place_in_service().
  ConditionStateTransition place_in_service(const LocalizedText& comment);

  // --- Silence ---

  /// Sets SilenceState to silenced.
  ///
  /// @return The resulting state transition. No-op unless silence is supported.
  /// @see set_supports_silence
  ConditionStateTransition silence();

  // --- Shelving ---

  /// The longest a condition timer runs, in milliseconds: ten years. A TimedShelve past it expires after
  /// this long, because a longer steady-clock deadline is not representable. UnshelveTime still reports the
  /// ShelvingTime the Client asked for (OPC 10000-9 5.8.17.1: "initialised with the ShelvingTime argument").
  static constexpr double longestShelvingTimeMs = 10.0 * 365.0 * 24.0 * 60.0 * 60.0 * 1000.0;

  /// Shelves the alarm for a fixed duration (TimedShelved).
  ///
  /// @param durationMs Shelve duration in milliseconds. Refused with Bad_ShelvingTimeOutOfRange
  ///                   when negative, NaN or past a configured MaxTimeShelved.
  /// @return The resulting state transition, including a start-shelve-timer command for the
  ///         shell.
  /// @see set_max_time_shelved, on_shelve_timer_expired, longestShelvingTimeMs
  ConditionStateTransition timed_shelve(double durationMs);

  /// Shelves the alarm for a fixed duration and records a comment against it
  /// (TimedShelve2, OPC 10000-9 5.8.17.5).
  ///
  /// The MaxTimeShelved bound applies exactly as it does to @ref timed_shelve(double): a refused
  /// duration records no comment.
  ///
  /// @param durationMs Shelve duration in milliseconds.
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref timed_shelve(double).
  ConditionStateTransition timed_shelve(double durationMs, const LocalizedText& comment);

  /// Shelves the alarm until it next deactivates and reactivates (OneShotShelved).
  ///
  /// @return The resulting state transition.
  ConditionStateTransition one_shot_shelve();

  /// One-shot shelves the alarm and records a comment against it
  /// (OneShotShelve2, OPC 10000-9 5.8.17.7).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref one_shot_shelve().
  ConditionStateTransition one_shot_shelve(const LocalizedText& comment);

  /// Returns the alarm to the Unshelved state.
  ///
  /// @return The resulting state transition, including a cancel-shelve-timer command for the
  ///         shell.
  ConditionStateTransition unshelve();

  /// Unshelves the alarm and records a comment against it (Unshelve2, OPC 10000-9 5.8.17.3).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref unshelve().
  ConditionStateTransition unshelve(const LocalizedText& comment);

  /// Handles expiry of the shelve timer started by @ref timed_shelve.
  ///
  /// Transitions a TimedShelved alarm back to Unshelved.
  ///
  /// @return The resulting state transition.
  ConditionStateTransition on_shelve_timer_expired();

  // --- On/off delay ---

  /// Handles expiry of the on-delay timer, committing a delayed activation.
  ///
  /// @return The resulting state transition.
  /// @see set_on_delay
  ConditionStateTransition on_delay_expired();

  /// Handles expiry of the off-delay timer, committing a delayed deactivation.
  ///
  /// @return The resulting state transition.
  /// @see set_off_delay
  ConditionStateTransition off_delay_expired();

  // --- Re-alarm ---

  /// Handles expiry of the configured ReAlarmTime while the Alarm remains active.
  ///
  /// Re-presents the Alarm as newly active by resetting AckedState and SilenceState, updating the
  /// ActiveState transition time, emitting an event, and rearming the timer.
  /// @return The resulting state transition, or a no-op when disabled, inactive, or unconfigured.
  ConditionStateTransition on_re_alarm_timer_expired();

  // --- Input evaluation (for subclasses like LimitAlarmLogic) ---

  /// Evaluates a new input sample and updates alarm state accordingly.
  ///
  /// The base implementation is a no-op; subclasses such as LimitAlarmLogic override it to map
  /// the sampled value onto activation, severity, and sub-state changes.
  ///
  /// @param value     The newly sampled input value.
  /// @param timestamp Source timestamp of the sample.
  /// @return The resulting state transition for the shell to apply.
  virtual ConditionStateTransition evaluate_input(const Variant& value, DateTime timestamp);

  // --- Latching ---

  /// Resets a latched alarm whose input has already cleared.
  ///
  /// @return The resulting state transition. No-op unless latching is supported.
  /// @see set_supports_latched
  ConditionStateTransition reset();

  /// Resets a latched alarm and records a comment against it (Reset2, OPC 10000-9 5.8.6).
  ///
  /// @param comment Comment to apply; a NULL comment leaves any existing one unchanged.
  /// @return The resulting state transition, identical to @ref reset().
  ConditionStateTransition reset(const LocalizedText& comment);

  // --- Initial state (for attach path / restart recovery) ---

  /// Sets the initial active state without triggering transitions or events.
  ///
  /// For the attach path and restart recovery, when populating from persisted or imported state
  /// before the condition is live.
  ///
  /// @param active   Initial ActiveState value.
  /// @param severity Initial severity, 1..1000.
  void set_initial_active(bool active, uint16_t severity);

  /// Seeds AckedState and, when SilenceState was not independently recovered, uses it as the
  /// required recovery fallback for SilenceState.
  ///
  /// @param acked Initial AckedState value: `true` for a condition recovered as acknowledged. When
  ///        the alarm carries the optional SilenceState and no initial silence was set, this value
  ///        also seeds SilenceState (silenced when acknowledged), which is the recovery fallback
  ///        rather than an equivalence between the two states.
  void set_initial_acked(bool acked);

  /// Sets the initial suppressed state without triggering transitions or events.
  ///
  /// @param suppressed Initial SuppressedState value.
  /// @pre Suppression support is enabled via @ref set_supports_suppressed; otherwise a no-op.
  void set_initial_suppressed(bool suppressed);

  /// Sets the initial out-of-service state without triggering transitions or events.
  ///
  /// @param outOfService Initial OutOfServiceState value.
  /// @pre Out-of-service support is enabled via @ref set_supports_out_of_service; otherwise a
  ///      no-op.
  void set_initial_out_of_service(bool outOfService);

  /// Sets the initial silence state without triggering transitions or events.
  ///
  /// @param silenced Initial SilenceState value.
  /// @pre Silence support is enabled via @ref set_supports_silence; otherwise a no-op.
  void set_initial_silenced(bool silenced);

  /// Sets the initial latched state without triggering transitions or events.
  ///
  /// @param latched Initial LatchedState value.
  /// @pre Latching support is enabled via @ref set_supports_latched; otherwise a no-op.
  void set_initial_latched(bool latched);

  /// Sets the initial shelve state without triggering transitions or events.
  ///
  /// @param state Initial @ref ShelveState.
  void set_initial_shelved(ShelveState state);

  // --- Configuration setters ---

  /// Sets the NodeId of the input source whose samples drive this alarm.
  ///
  /// @param nodeId NodeId of the input source whose samples drive this alarm.
  void set_input_node(NodeId nodeId);

  /// Sets the maximum permitted shelve duration in milliseconds (MaxTimeShelved).
  ///
  /// @param ms Upper bound applied to @ref timed_shelve durations; 0 disables the cap.
  void set_max_time_shelved(double ms);

  /// The configured MaxTimeShelved in milliseconds, or 0 when the alarm imposes no maximum.
  ///
  /// The Property is Optional (OPC 10000-9 5.8.2), so a Condition exposes it only when this is set.
  /// @return The configured maximum duration in milliseconds, or zero when uncapped.
  double max_time_shelved() const noexcept
  {
    return mMaxTimeShelved;
  }

  /// Sets the on-delay in milliseconds applied before a pending activation takes effect.
  ///
  /// @param ms Delay duration in milliseconds; 0 disables the delay.
  void set_on_delay(double ms);

  /// Sets the off-delay in milliseconds applied before a pending deactivation takes effect.
  ///
  /// @param ms Delay duration in milliseconds; 0 disables the delay.
  void set_off_delay(double ms);

  /// Sets the re-alarm interval in milliseconds (ReAlarmTime).
  ///
  /// @param ms Repeat interval in milliseconds; a non-positive value disables re-alarming.
  void set_re_alarm_time(double ms);

  /// Enables or disables the optional SuppressedState sub-state.
  ///
  /// @param value true to enable the SuppressedState sub-state; false to disable it.
  void set_supports_suppressed(bool value);

  /// Enables or disables the optional OutOfServiceState sub-state.
  ///
  /// @param value true to enable the OutOfServiceState sub-state; false to disable it.
  void set_supports_out_of_service(bool value);

  /// Enables or disables the optional SilenceState sub-state.
  ///
  /// @param value true to enable the SilenceState sub-state; false to disable it.
  void set_supports_silence(bool value);

  /// Enables or disables the optional LatchedState sub-state.
  ///
  /// @param value true to enable the LatchedState sub-state; false to disable it.
  void set_supports_latched(bool value);

  /// Returns whether the SuppressedState sub-state is supported.
  ///
  /// @return true if the SuppressedState sub-state is supported.
  bool supports_suppressed() const;

  /// Returns whether the OutOfServiceState sub-state is supported.
  ///
  /// @return true if the OutOfServiceState sub-state is supported.
  bool supports_out_of_service() const;

  /// Returns whether the SilenceState sub-state is supported.
  ///
  /// @return true if the SilenceState sub-state is supported.
  bool supports_silence() const;

  /// Returns whether the LatchedState sub-state is supported.
  ///
  /// @return true if the LatchedState sub-state is supported.
  bool supports_latched() const;

  // --- Event building ---

  /// Builds an alarm event snapshot from the current state.
  ///
  /// Adds the alarm-specific fields (ActiveState and any supported sub-states) on top of the
  /// acknowledgeable-condition fields.
  ///
  /// @return A newly allocated event whose ownership transfers to the caller.
  std::unique_ptr<BaseEvent> build_event() const override;

  /// Returns the current @ref ShelveState.
  ///
  /// Public so the strand-shell (`ConditionInstance`) can mirror ShelvingState.CurrentState into the
  /// condition snapshot - the same strand-shell->logic read precedent as `LimitAlarmLogic::active_limit()`.
  /// The ShelveState is not carried in any event payload, so it must be read from the logic directly.
  ///
  /// @return The current @ref ShelveState.
  ShelveState shelve_state() const;

  /// The clock ShelvingState/UnshelveTime is read from; see @ref UnshelveClock.
  /// @return A value snapshot used to evaluate UnshelveTime.
  UnshelveClock unshelve_clock() const;

protected:
  // --- Accessors for subclasses ---

  /// Returns the effective ActiveState value, accounting for any pending on/off delay.
  ///
  /// @return true if the alarm is effectively active, accounting for any pending on/off delay.
  bool active() const;

  /// Returns the ActiveState two-state variable.
  ///
  /// @return The ActiveState two-state variable.
  const TwoStateVariableState& active_state() const;

  /// Returns whether the alarm is currently suppressed or shelved (and thus not reported).
  ///
  /// @return true if the alarm is currently suppressed or shelved.
  bool suppressed_or_shelved() const;

  /// Returns the raw active flag, ignoring on/off delay debouncing.
  ///
  /// @return true if the raw active flag is set, ignoring on/off delay debouncing.
  bool raw_active() const;

  /// Returns the configured on-delay in milliseconds.
  ///
  /// @return The configured on-delay, in milliseconds.
  double on_delay_ms() const;

  /// Returns the configured off-delay in milliseconds.
  ///
  /// @return The configured off-delay, in milliseconds.
  double off_delay_ms() const;

  /// Applies a raw active/inactive decision through the configured on/off delay state machine.
  ///
  /// The raw decision is recorded immediately; whether ActiveState follows it depends on the
  /// delays. With a delay configured the transition is deferred and a timer command is returned
  /// instead, and a raw decision that reverses before its delay elapses cancels the pending timer
  /// rather than transitioning.
  ///
  /// @param active   The raw active decision, before on/off delay is applied.
  /// @param severity Severity to carry into the resulting transition, 1..1000. Recorded even while
  ///                 a delay defers the state change, so the transition that eventually fires
  ///                 reports the severity current at that point.
  /// @return The state changes, timer commands and events the owning shell must apply. Empty of
  ///         work when the raw decision agrees with the state already reached.
  ConditionStateTransition transition_raw_active(bool active, uint16_t severity);

  /// Populates the AlarmConditionType-level fields (ActiveState, InputNode, SuppressedOrShelved, the
  /// optional Suppressed/OutOfService/Silence/Latched sub-states, MaxTimeShelved, On/OffDelay) onto an
  /// alarm payload. Shared by @ref build_event and by subclass overrides (e.g. LimitAlarmLogic) so the
  /// full mandatory/optional alarm field set is populated consistently in one place.
  ///
  /// @param[out] event Alarm payload whose AlarmConditionType-level fields are populated from the
  ///                   current state.
  void populate_alarm_payload_fields(AlarmConditionPayload& event) const;

  // --- Overrides ---

  /// Computes whether Retain should be true for an alarm.
  ///
  /// Extends the acknowledgeable-condition rule with ActiveState so that an active alarm stays
  /// retained even once acknowledged and confirmed.
  ///
  /// @return true if the alarm should be retained.
  bool compute_retain() const override;

  /// Re-evaluates the input on enable so the alarm reflects its current source value.
  void on_enabled() override;

private:
  friend class test::AlarmConditionLogicTestAccess;

  void update_suppressed_or_shelved();

  TwoStateVariableState mActiveState{};
  std::optional<TwoStateVariableState> mSuppressedState;
  std::optional<TwoStateVariableState> mOutOfServiceState;
  std::optional<TwoStateVariableState> mSilenceState;
  std::optional<TwoStateVariableState> mLatchedState;
  bool mSuppressedOrShelved{false};
  NodeId mInputNode{};
  ShelveState mShelveState{ShelveState::Unshelved};
  /// The ShelvingTime of the current TimedShelve and when it began; UnshelveTime is their difference from
  /// now. Held as a start and a length, not a deadline, because a Client may pass the largest Double.
  double mShelvingTimeMs{0.0};
  DateTime mShelvedAt{};
  double mMaxTimeShelved{0.0};
  double mOnDelayMs{0.0};
  double mOffDelayMs{0.0};
  double mReAlarmTimeMs{0.0};
  bool mOnDelayPending{false};
  bool mOffDelayPending{false};
  bool mRawActive{false};
  uint16_t mRawSeverity{0};
  bool mInitialSilenceSet{false};
};

}  // namespace ua

#endif  // !UA_ALARM_CONDITION_LOGIC_H
