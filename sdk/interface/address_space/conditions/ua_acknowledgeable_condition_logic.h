// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Pure state machine for the OPC UA AcknowledgeableConditionType (Part 9).
/// @ingroup address_space

#ifndef UA_ACKNOWLEDGEABLE_CONDITION_LOGIC_H
#define UA_ACKNOWLEDGEABLE_CONDITION_LOGIC_H

#include "ua_condition_logic.h"
#include "ua_variable_states.h"

#include <memory>
#include <optional>
#include <vector>

namespace ua
{

/// A prior condition state that was retained because it still needs operator attention.
///
/// A branch is created when the trunk transitions while an unacknowledged or unconfirmed
/// state is outstanding, so the earlier state is not lost. The snapshot is a polymorphic
/// @ref BaseEvent captured via build_event() at branch-creation time; acknowledgement and
/// confirmation are tracked by mutating the snapshot's fields in place.
/// @ingroup address_space
struct ConditionBranch
{
  NodeId branchId;  ///< Non-null Guid NodeId identifying this branch.
  ByteString eventId;  ///< EventId of the branch's last emitted event; assigned by the shell after emission.
  std::unique_ptr<BaseEvent> snapshot;  ///< Owned snapshot of the full event state at branch-creation time.
};

namespace test
{
class AcknowledgeableConditionLogicTestAccess;
}  // namespace test

/// Pure state machine for the OPC UA AcknowledgeableConditionType (Part 9).
///
/// Extends @ref ConditionLogic with AckedState and an optional ConfirmedState, and tracks any
/// outstanding branches. The retain computation accounts for acknowledgement and confirmation in
/// addition to enable state. Like its base, this holds state only: no I/O, no address space, no
/// strands. A strand-serialized shell drives async work and feeds results back via the setters.
/// @ingroup address_space
class AcknowledgeableConditionLogic : public ConditionLogic
{
public:
  ~AcknowledgeableConditionLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  AcknowledgeableConditionLogic(const AcknowledgeableConditionLogic&) = delete;
  AcknowledgeableConditionLogic& operator=(const AcknowledgeableConditionLogic&) = delete;
  AcknowledgeableConditionLogic(AcknowledgeableConditionLogic&&) = delete;
  AcknowledgeableConditionLogic& operator=(AcknowledgeableConditionLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  AcknowledgeableConditionLogic() = default;
  // --- Public state mutations ---

  /// Acknowledges the condition (or branch) identified by an EventId.
  ///
  /// Validates @p eventId against the trunk and outstanding branches, then sets the matching
  /// AckedState.Id to true and records @p comment.
  ///
  /// @param eventId EventId of the trunk or branch event being acknowledged.
  /// @param comment Operator comment to attach to the acknowledgement.
  /// @return The resulting transition. Its status is BadEventIdUnknown if @p eventId matches no
  ///         outstanding event, or BadConditionBranchAlreadyAcked if it is already acknowledged.
  /// @see confirm, add_comment
  ConditionStateTransition acknowledge(const ByteString& eventId, const LocalizedText& comment);

  /// Adds a comment to the condition or one of its branches.
  ///
  /// Resolves @p eventId against the trunk first, then the outstanding branches.
  ///
  /// @param eventId EventId of the trunk or branch event to comment on.
  /// @param comment Comment to attach.
  /// @return The resulting transition; its status is BadEventIdUnknown if @p eventId matches no
  ///         outstanding event.
  ConditionStateTransition add_comment(const ByteString& eventId, const LocalizedText& comment) override;

  /// Confirms the condition (or branch) identified by an EventId.
  ///
  /// Validates @p eventId, then sets the matching ConfirmedState.Id to true and records @p comment.
  ///
  /// @param eventId EventId of the trunk or branch event being confirmed.
  /// @param comment Operator comment to attach to the confirmation.
  /// @return The resulting transition. Its status is BadEventIdUnknown if @p eventId matches no
  ///         outstanding event, or BadConditionBranchAlreadyConfirmed if it is already confirmed or
  ///         if confirmation is not supported.
  /// @see acknowledge, supports_confirm
  ConditionStateTransition confirm(const ByteString& eventId, const LocalizedText& comment);

  /// Returns whether ConfirmedState is supported.
  ///
  /// @return true if ConfirmedState is supported.
  /// @see set_supports_confirm
  bool supports_confirm() const;

  /// Enables or disables ConfirmedState support.
  ///
  /// @param value true to enable ConfirmedState support; false to disable it.
  /// @see supports_confirm
  void set_supports_confirm(bool value);

  /// Enables or disables branch support (optional per Part 9 4.2).
  ///
  /// @param value true to enable branch support; false to disable it.
  void set_supports_branches(bool value);

  /// Sets the maximum number of live ConditionBranches retained at once (memory bound).
  ///
  /// When a new branch would exceed this, the oldest branch(es) are dropped (Retain=False) first.
  /// Must be >= 1; values below 1 are clamped to 1. Defaults to a generous bound.
  ///
  /// @param maxBranches Maximum number of live ConditionBranches to retain at once; clamped to a
  ///                    minimum of 1.
  void set_max_branches(size_t maxBranches);

  // --- Branch management ---

  /// Returns read-only access to the live branches.
  ///
  /// The reference is borrowed; it stays valid only until the next mutation of this logic object.
  /// Used by the shell to emit ConditionRefresh events for outstanding branches.
  ///
  /// @return The live branches; the reference stays valid only until the next mutation of this
  ///         logic object.
  const std::vector<ConditionBranch>& branches() const;

  /// Records the EventId assigned by the EventBus after emitting a branch event.
  ///
  /// Called by the shell to feed the assigned EventId back into the branch identified by
  /// @p branchId. No-op if no such branch exists.
  ///
  /// @param branchId Identifier of the branch to update.
  /// @param eventId  EventId assigned to the branch's most recent event.
  void set_branch_event_id(const NodeId& branchId, ByteString eventId);

  /// Removes a resolved branch.
  ///
  /// Called by the shell after it has emitted the branch's final Retain=False event. No-op if no
  /// branch matches @p branchId.
  ///
  /// @param branchId Identifier of the branch to remove.
  void remove_branch(const NodeId& branchId);

  /// Builds a clone of a branch's snapshot event with its branch_id and Retain flag set.
  ///
  /// @param branchId Identifier of the branch to clone.
  /// @param retain   Value to set on the cloned event's Retain field.
  /// @return An owned clone of the branch's snapshot, or nullptr if no branch matches @p branchId.
  std::unique_ptr<BaseEvent> build_branch_event(const NodeId& branchId, bool retain) const;

  /// Records the EventId assigned after emitting the trunk event.
  ///
  /// Overridden to RETIRE the previous trunk EventId - capturing its acked/confirmed resolution - before
  /// it is replaced, so a later Acknowledge/Confirm referencing that retired EventId reports
  /// already-acked/already-confirmed (OPC 10000-9 5.13) rather than the misleading EventIdUnknown.
  ///
  /// @param eventId EventId assigned to the most recently emitted trunk event.
  void set_last_event_id(ByteString eventId) override;

  // --- Initial state (for attach path / restart recovery) ---

  /// Sets the initial acknowledged state without triggering transitions or events.
  ///
  /// For the attach path and restart recovery only, when populating from persisted/imported state.
  ///
  /// @param acked Initial AckedState.Id value.
  void set_initial_acked(bool acked);

  /// Sets the initial confirmed state without triggering transitions or events.
  ///
  /// For the attach path and restart recovery only, when populating from persisted/imported state.
  ///
  /// @param confirmed Initial ConfirmedState.Id value.
  void set_initial_confirmed(bool confirmed);

  // --- Event building ---

  /// Builds an AcknowledgeableConditionType event struct from the current state.
  ///
  /// Extends the base condition payload with AckedState and, where supported, ConfirmedState.
  ///
  /// @return An owned event carrying the current condition state.
  std::unique_ptr<BaseEvent> build_event() const override;

protected:
  // --- Accessors for subclasses ---

  /// Returns whether the trunk is currently acknowledged.
  ///
  /// @return true if the trunk is currently acknowledged.
  bool acknowledged() const;

  /// Returns whether the trunk is currently confirmed.
  ///
  /// @return true if the trunk is currently confirmed.
  bool confirmed() const;

  /// Returns the AckedState two-state variable.
  ///
  /// @return The AckedState two-state variable.
  const TwoStateVariableState& acked_state() const;

  /// Returns the ConfirmedState two-state variable, or nullopt when confirmation is unsupported.
  ///
  /// @return The ConfirmedState two-state variable, or nullopt when confirmation is unsupported.
  const std::optional<TwoStateVariableState>& confirmed_state() const;

  /// Resets AckedState to unacknowledged.
  ///
  /// Called by subclasses when the alarm (re)activates.
  void reset_acked_state();

  /// Resets ConfirmedState to unconfirmed.
  ///
  /// Called by subclasses when the alarm (re)activates.
  void reset_confirmed_state();

  /// Returns whether branches are supported and enabled.
  ///
  /// @return true if branches are supported and enabled.
  bool supports_branches() const;

  /// Returns whether any branch still needs operator attention.
  ///
  /// @return true if any branch still needs operator attention.
  bool has_unresolved_branches() const;

  /// Creates a branch from the current trunk state, bounding the number of retained branches.
  ///
  /// Calls build_event() to snapshot the trunk into a new @ref ConditionBranch. A condition that
  /// toggles repeatedly without acknowledgement would otherwise accumulate ConditionBranches without
  /// limit, so when the live branch count is at the cap (see @ref set_max_branches) the oldest
  /// branch(es) are dropped first - each yielding a Retain=False event so the client removes it from
  /// its view.
  ///
  /// @return The branch events to emit, in order: any Retain=False drops first, then the new branch
  ///         (Retain=True). The new branch is always the last element.
  std::vector<BranchEventData> create_branch();

  /// Appends Retain=False branch events for all branches and clears the branch list.
  ///
  /// Used by the disable path to tear down every outstanding branch.
  ///
  /// @param[in,out] transition Transition to which the branch deletion events are appended.
  void clear_all_branches(ConditionStateTransition& transition);

  // --- Overrides ---

  /// Returns whether retain should be true.
  ///
  /// Extends the base computation to keep retaining while acknowledgement or confirmation is
  /// outstanding, or while any branch remains unresolved.
  ///
  /// @return true if the condition should be retained.
  bool compute_retain() const override;

  /// Hook invoked after the condition is enabled.
  void on_enabled() override;

  /// Hook invoked while the condition is being disabled.
  ///
  /// Tears down outstanding branches by appending their deletion events to @p transition.
  ///
  /// @param[in,out] transition Transition being assembled for the disable operation.
  void on_disabled(ConditionStateTransition& transition) override;

private:
  friend class test::AcknowledgeableConditionLogicTestAccess;

  TwoStateVariableState mAckedState{};
  std::optional<TwoStateVariableState> mConfirmedState;
  bool mSupportsConfirm{false};
  bool mSupportsBranches{false};
  std::vector<ConditionBranch> mBranches;

  // Branches removed from the live set but whose Retain=False event has not been emitted yet.
  //
  // A retraction event is BUILT from the branch's own snapshot (see build_branch_event), and the shell
  // emits it after the transition that produced it. A branch dropped by the retention cap, or by a
  // disable, therefore has to outlive its own removal or its retraction cannot be rendered and the
  // client is never told the branch is gone. The shell's remove_branch call after emission is what
  // clears these, so the list holds only the retractions of a single in-flight transition.
  std::vector<ConditionBranch> mRetiredBranches;

  // Memory bound on retained branches (drop-oldest on overflow). Default generous; constrained
  // deployments lower it. See create_branch / set_max_branches.
  size_t mMaxBranches{100};

  // Retired trunk EventIds -> their {acked, confirmed} resolution at retirement. A trunk EventId is retired
  // (replaced by a new one) without leaving a branch only when its state was already resolved; consulting
  // this list lets a later Acknowledge/Confirm with such an EventId report already-acked/already-confirmed
  // (OPC 10000-9 5.13 Table 137) instead of EventIdUnknown. Bounded to the most recent few.
  struct RetiredResolution
  {
    bool acked{false};
    bool confirmed{false};
  };

  std::vector<std::pair<ByteString, RetiredResolution>> mRetiredEventIds;
  static constexpr size_t sMaxRetiredEventIds = 16;

  /// Returns the resolution recorded for a retired EventId, or nullopt if it is not a retired EventId.
  ///
  /// @param eventId EventId to look up among the retired trunk EventIds.
  /// @return The recorded {acked, confirmed} resolution, or nullopt if @p eventId is not retired.
  std::optional<RetiredResolution> find_retired_event_id(const ByteString& eventId) const;
};

}  // namespace ua

#endif  // !UA_ACKNOWLEDGEABLE_CONDITION_LOGIC_H
