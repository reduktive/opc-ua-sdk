// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Pure state machine for the OPC UA ConditionType (Part 9).
/// @ingroup address_space

#ifndef UA_CONDITION_LOGIC_H
#define UA_CONDITION_LOGIC_H

#include "ua_base_event.h"
#include "ua_byte_string.h"
#include "ua_variable_states.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace ua
{

struct ConditionPayload;

namespace test
{
class ConditionLogicTestAccess;
}  // namespace test

/// A timer operation that the Condition shell must execute after a state transition.
///
/// Produced by the pure @ref ConditionStateTransition logic and replayed by the owning
/// Condition instance, which schedules or cancels the corresponding alarm timer (on/off
/// delay, shelving, or re-alarm) on its strand.
/// @ingroup address_space
struct TimerCommand
{
  /// The timer and operation a command refers to.
  enum class Kind
  {
    None,  ///< No-op; the command carries no timer action.
    StartOnDelay,  ///< (Re)start the active-state on-delay timer.
    CancelOnDelay,  ///< Cancel any pending on-delay timer.
    StartOffDelay,  ///< (Re)start the inactive-state off-delay timer.
    CancelOffDelay,  ///< Cancel any pending off-delay timer.
    StartShelveTimer,  ///< (Re)start the one-shot/timed-shelving unshelve timer.
    CancelShelveTimer,  ///< Cancel any pending shelving timer.
    StartReAlarmTimer,  ///< (Re)start the re-alarm repeat timer.
    CancelReAlarmTimer  ///< Cancel any pending re-alarm timer.
  };

  Kind kind{Kind::None};  ///< Which timer to act on, and whether to start or cancel it.

  /// Delay before the timer fires, in milliseconds; ignored for cancel kinds.
  double durationMs{0.0};
};

/// A branch event that the Condition shell must emit after a state transition.
///
/// Each entry corresponds to one ConditionBranch whose state changed and must be
/// reported to subscribers via an event.
/// @ingroup address_space
struct BranchEventData
{
  NodeId branchId;  ///< Identifier of the ConditionBranch the event reports on.
  bool retain{true};  ///< true to emit a normal branch event; false to emit the final
                      ///< event (Retain=False) that deletes the branch.
};

/// The outcome of a ConditionLogic state mutation.
///
/// Returned by the pure Condition logic and inspected by the owning Condition instance
/// (the "shell"), which decides whether to emit the condition event, replay the timer
/// commands, emit any branch events, and what status to report back to the caller. This
/// is a plain value with no ownership or threading semantics of its own.
///
/// @ingroup address_space
struct ConditionStateTransition
{
  bool changed{false};  ///< true if the mutation altered any condition state.
  bool emitEvent{false};  ///< true if the shell must emit the main condition event.
  StatusCode status{};  ///< Status to report back to the caller of the mutation.
  std::vector<TimerCommand> timerCommands;  ///< Timer operations to execute, in order.
  std::vector<BranchEventData> branchEvents;  ///< Branch events to emit, in order.
};

/// Pure state machine for the OPC UA ConditionType (Part 9).
///
/// Holds all condition state and exposes deterministic, side-effect-free transitions. Performs no
/// I/O, holds no address-space references, and is not strand-serialized - every method runs
/// synchronously on the caller's thread and never blocks. Intended for the Logic/Shell split
/// pattern: a strand-serialized shell component owns this object, drives the async operations it
/// describes (event emission, timer commands), and feeds the results back in.
///
/// State mutations return a @ref ConditionStateTransition that tells the shell whether an event
/// must be emitted, which timer commands to run, and the status to report to the caller; the logic
/// object itself never emits events.
///
/// Subclasses (AcknowledgeableConditionLogic, AlarmConditionLogic, etc.) override the protected
/// extension points - compute_retain(), on_enabled(), on_disabled() - to add their type-specific
/// behavior.
///
/// @note Not thread-safe. The owning shell must serialize all access (its strand provides this).
/// @ingroup address_space
class ConditionLogic
{
public:
  virtual ~ConditionLogic() = default;

  // Polymorphic base held only via unique_ptr; copying/moving would slice (C.67).
  ConditionLogic(const ConditionLogic&) = delete;
  ConditionLogic& operator=(const ConditionLogic&) = delete;
  ConditionLogic(ConditionLogic&&) = delete;
  ConditionLogic& operator=(ConditionLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  ConditionLogic() = default;
  // --- Public state mutations ---

  /// Enables the condition.
  ///
  /// @return The resulting transition. Carries status BadConditionAlreadyEnabled (and no change)
  ///         when the condition was already enabled.
  ConditionStateTransition enable();

  /// Disables the condition.
  ///
  /// @return The resulting transition. Carries status BadConditionAlreadyDisabled (and no change)
  ///         when the condition was already disabled.
  ConditionStateTransition disable();

  /// Adds a comment to the condition or one of its branches.
  ///
  /// Validates @p eventId against the last emitted EventId; a stale or unknown id yields a failing
  /// status in the returned transition. Virtual so AcknowledgeableConditionLogic can dispatch the
  /// comment to the matching branch.
  ///
  /// @param eventId EventId of the event the comment refers to, used to select the target branch.
  /// @param comment Comment text to record.
  /// @return The resulting transition.
  virtual ConditionStateTransition add_comment(const ByteString& eventId, const LocalizedText& comment);

  /// Updates the condition quality.
  ///
  /// @param quality New quality status code.
  /// @return The resulting transition; requests an event emission when the condition is retained.
  ConditionStateTransition set_quality(StatusCode quality);

  /// Updates the condition severity.
  ///
  /// Records the prior value as the last severity before applying @p severity.
  ///
  /// @param severity New severity, in OPC UA severity units (1-1000).
  /// @return The resulting transition; requests an event emission when the condition is retained.
  ConditionStateTransition set_severity(uint16_t severity);

  // --- Initial state (for attach path / restart recovery) ---

  /// Sets the initial enabled state without triggering any transition or event.
  ///
  /// Intended to be called once, before the condition goes live, when seeding state from a
  /// persisted or imported source.
  ///
  /// @param enabled Initial enabled flag.
  /// @pre The condition is not yet live (no transitions have been driven).
  void set_initial_enabled(bool enabled);

  // --- Simple setters ---

  /// Sets the source node and source name reported in emitted events.
  ///
  /// @param sourceNode NodeId of the source the condition relates to.
  /// @param sourceName Human-readable source name.
  void set_source(NodeId sourceNode, String sourceName);

  /// Sets the condition name reported in emitted events.
  ///
  /// @param name Condition name reported in emitted events.
  void set_condition_name(String name);

  /// Sets the condition class identifier and its display name.
  ///
  /// @param classId   NodeId of the condition class (e.g. a well-known ConditionClassType).
  /// @param className Localized display name of the condition class.
  void set_condition_class(NodeId classId, LocalizedText className);

  /// Sets the ClientUserId recorded on the next comment/acknowledge interaction.
  ///
  /// @param userId ClientUserId to record on the next comment/acknowledge interaction.
  void set_client_user_id(String userId);

  /// Sets whether the condition supports the FilteredRetain behavior.
  ///
  /// @param value true to enable FilteredRetain behavior support; false to disable it.
  void set_supports_filtered_retain(bool value);

  /// Sets the last event ID.
  ///
  /// Called by the shell after event emission assigns an EventId, so subsequent comment and
  /// acknowledge requests can be validated against it. Virtual so AcknowledgeableConditionLogic can
  /// retire the outgoing trunk EventId (recording its acked/confirmed resolution) before it is replaced,
  /// so a later Acknowledge/Confirm with it reports already-acked/confirmed rather than EventIdUnknown.
  ///
  /// @param eventId EventId of the most recently emitted event.
  virtual void set_last_event_id(ByteString eventId);

  /// Returns the last emitted event ID, used to correlate ConditionRefresh.
  ///
  /// @return Reference to the stored EventId; valid until the next set_last_event_id() call.
  const ByteString& last_event_id() const;

  // --- Event building ---

  /// Builds an event struct populated from the current condition state.
  ///
  /// Virtual so subclasses can return their type-specific payload (e.g. an alarm payload).
  ///
  /// @return An owning pointer to a freshly built event; never null.
  virtual std::unique_ptr<BaseEvent> build_event() const;

protected:
  // --- Accessors for subclasses ---

  /// Returns whether the condition is currently enabled.
  ///
  /// @return true if the condition is currently enabled.
  bool enabled() const;

  /// Returns whether the condition is currently retained.
  ///
  /// @return true if the condition is currently retained.
  bool retained() const;

  /// Returns the current severity, in OPC UA severity units (1-1000).
  ///
  /// @return The current severity, in OPC UA severity units (1-1000).
  uint16_t severity() const;

  /// Returns the current quality status code.
  ///
  /// @return The current quality status code.
  const StatusCode& quality() const;

  /// Returns the EnabledState two-state variable.
  ///
  /// @return The EnabledState two-state variable.
  const TwoStateVariableState& enabled_state() const;

  /// Returns the source node reported in emitted events.
  ///
  /// @return The source node reported in emitted events.
  const NodeId& source_node() const;

  /// Returns the source name reported in emitted events.
  ///
  /// @return The source name reported in emitted events.
  const String& source_name() const;

  // --- Helpers for subclasses ---

  /// Fills the BaseEventType fields (source, time, severity, message, ...) on an event struct.
  ///
  /// @param[out] event Event whose base fields are populated from the current state.
  void populate_base_fields(BaseEvent& event) const;

  /// Fills the ConditionType-level fields on any ConditionPayload-derived event struct.
  ///
  /// @param[out] event Condition payload whose condition fields are populated from the current
  ///                   state. populate_base_fields() should be applied as well for a complete event.
  void populate_condition_fields(ConditionPayload& event) const;

  /// Recomputes the retain flag via compute_retain() and applies it.
  ///
  /// @return true if retain changed from true to false - the edge that requires an event emission.
  /// @warning For initial-state setup and the disable path only. Never call this before
  ///          make_transition(): make_transition() owns the retain computation for normal state
  ///          mutations, and calling this first loses the Retain true->false edge.
  /// @see make_transition
  bool recompute_retain_no_emit();

  /// Computes whether retain should be true.
  ///
  /// Base implementation returns the enabled flag. Subclasses override to additionally factor in
  /// active/unacknowledged/unconfirmed state.
  ///
  /// @return true if the condition should be retained.
  virtual bool compute_retain() const;

  /// Creates a transition result with emit_event set according to the recomputed retain flag.
  ///
  /// Owns the retain computation: it calls recompute_retain_no_emit() internally.
  ///
  /// @param stateChanged Whether the mutation changed observable state.
  /// @return The assembled transition.
  /// @warning Subclasses must NOT call recompute_retain_no_emit() before calling this, as doing so
  ///          defeats the Retain true->false edge detection required by Part 9 5.5.2.
  /// @see recompute_retain_no_emit
  ConditionStateTransition make_transition(bool stateChanged);

  /// Updates the comment and comment state without EventId validation.
  ///
  /// Used by subclass methods (Acknowledge, Confirm) that update the comment as a side effect of
  /// another transition.
  ///
  /// @param comment New comment text.
  void update_comment_state(const LocalizedText& comment);

  /// Applies the Comment argument of a Part 9 "...2" Method variant to a completed transition.
  ///
  /// Suppress2, Unshelve2 and their siblings each "extend" a base Method "by adding an optional
  /// Comment" (OPC 10000-9 5.8.9, 5.8.17.3/.5/.7) and are otherwise defined by the base. The comment
  /// is recorded only when the base transition succeeded: a Method that refused - an already-shelved
  /// alarm, a ShelvingTime past MaxTimeShelved - must leave the Condition exactly as it found it, and
  /// a recorded comment is a state change a Client can read. A NULL comment is ignored by
  /// @ref update_comment_state, which is the rule those clauses state for the argument itself.
  ///
  /// @param transition The transition the base mutation returned; passed through unchanged.
  /// @param comment The Comment argument as received from the Client.
  /// @return @p transition.
  ConditionStateTransition apply_method_comment(
    ConditionStateTransition transition, const LocalizedText& comment);

  /// Extension point invoked after enable() sets the enabled flag.
  ///
  /// Base implementation does nothing. Subclasses override to evaluate input and seed derived state.
  virtual void on_enabled();

  /// Extension point invoked during disable(), before the transition is returned.
  ///
  /// Base implementation does nothing. Subclasses override to clean up branches.
  ///
  /// @param[in,out] transition Transition being assembled; subclasses may append branch events or
  ///                           timer commands.
  virtual void on_disabled(ConditionStateTransition& transition);

private:
  friend class test::ConditionLogicTestAccess;

  NodeId mSourceNode{};
  String mSourceName{};
  bool mEnabled{false};
  /// True once disable() has moved this Condition out of the enabled state.
  ///
  /// OPC 10000-9 5.5.2 hangs its "no longer provided" rule on the Condition *entering* the Disabled
  /// state, and that is the distinction this records. A Condition that has never been enabled has
  /// withdrawn nothing: its Quality is the initial Good, not a live reading being withheld.
  bool mEnteredDisabled{false};
  bool mRetain{false};
  uint16_t mSeverity{0};
  StatusCode mQuality{};
  LocalizedText mComment{};
  String mClientUserId{};
  String mConditionName{};
  // Part 9: ConditionClassId is mandatory. Default to BaseConditionClassType - the generic class valid
  // for any Condition - so the field is always a usable NodeId; applications may override per condition.
  NodeId mConditionClassId{NodeId{ObjectTypeId::BaseConditionClassType}};
  // ConditionClassName must equal the DisplayName of the ConditionClassId node (Part 9). Default it to
  // BaseConditionClassType's DisplayName so the default class id/name pair is self-consistent.
  LocalizedText mConditionClassName{LocalizedText{"", "BaseConditionClassType"}};
  NodeId mBranchId{};
  TwoStateVariableState mEnabledState{};
  // Part 9: Quality is a mandatory StatusCode; default Good so the event field is always correctly typed.
  ConditionVariableState mQualityState{Variant{StatusCode{}}};
  ConditionVariableState mLastSeverityState{};
  // Part 9: Comment is a mandatory LocalizedText; default an empty-but-typed LocalizedText (not null).
  ConditionVariableState mCommentState{Variant{LocalizedText{}}};
  ByteString mLastEventId{};
  bool mSupportsFilteredRetain{false};
};

}  // namespace ua

#endif  // !UA_CONDITION_LOGIC_H
