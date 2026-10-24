// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_acknowledgeable_condition_logic.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_guid.h"
#include "ua_status.h"

#include <algorithm>

namespace ua
{

// --- Branch helpers (private) ---

namespace
{

/// Check if a branch is fully resolved (acked and, if confirm supported, confirmed).
bool is_branch_resolved(const BaseEvent& snapshot, bool supportsConfirm)
{
  auto* ack = dynamic_cast<const AcknowledgeableConditionPayload*>(&snapshot);
  if (!ack)
  {
    return true;
  }

  if (!ack->ackedState.id)
  {
    return false;
  }

  if (supportsConfirm && ack->confirmedState.has_value() && !ack->confirmedState->id)
  {
    return false;
  }

  return true;
}

}  // namespace

// --- Public state mutations ---

ConditionStateTransition AcknowledgeableConditionLogic::acknowledge(
  const ByteString& eventId, const LocalizedText& comment)
{
  // Check trunk first
  if (eventId == last_event_id())
  {
    if (mAckedState.id)
    {
      ConditionStateTransition result;
      result.status = StatusCode{Status::BadConditionBranchAlreadyAcked};
      return result;
    }

    mAckedState.id = true;
    mAckedState.currentState = LocalizedText{"", "Acknowledged"};
    mAckedState.transitionTime = DateTime::now();

    update_comment_state(comment);

    return make_transition(true);
  }

  // Check branches
  for (auto& branch : mBranches)
  {
    if (eventId == branch.eventId)
    {
      auto* ack = dynamic_cast<AcknowledgeableConditionPayload*>(branch.snapshot.get());
      if (!ack)
      {
        break;
      }

      if (ack->ackedState.id)
      {
        ConditionStateTransition result;
        result.status = StatusCode{Status::BadConditionBranchAlreadyAcked};
        return result;
      }

      ack->ackedState.id = true;
      ack->ackedState.currentState = LocalizedText{"", "Acknowledged"};
      ack->ackedState.transitionTime = DateTime::now();

      // Update branch comment, unless the comment is NULL (leave it unchanged per
      // OPC 10000-9 5.7.3 / 5.7.4); an empty text with a locale still resets it.
      if (!comment.is_null())
      {
        ack->comment.value = Variant{comment};
        ack->comment.sourceTimestamp = DateTime::now();
      }

      const bool resolved = is_branch_resolved(*branch.snapshot, mSupportsConfirm);

      auto result = make_transition(true);
      result.branchEvents.push_back({branch.branchId, /*retain=*/!resolved});
      return result;
    }
  }

  // Not the current trunk or a live branch: if this is a retired EventId whose state was already
  // acknowledged, report Bad_ConditionBranchAlreadyAcked rather than Bad_EventIdUnknown (OPC 10000-9 5.13).
  if (auto retired = find_retired_event_id(eventId); retired && retired->acked)
  {
    ConditionStateTransition alreadyAcked;
    alreadyAcked.status = StatusCode{Status::BadConditionBranchAlreadyAcked};
    return alreadyAcked;
  }

  ConditionStateTransition result;
  result.status = StatusCode{Status::BadEventIdUnknown};
  return result;
}

ConditionStateTransition AcknowledgeableConditionLogic::confirm(
  const ByteString& eventId, const LocalizedText& comment)
{
  if (!mSupportsConfirm || !mConfirmedState.has_value())
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionBranchAlreadyConfirmed};
    return result;
  }

  // Check trunk first
  if (eventId == last_event_id())
  {
    if (mConfirmedState->id)
    {
      ConditionStateTransition result;
      result.status = StatusCode{Status::BadConditionBranchAlreadyConfirmed};
      return result;
    }

    mConfirmedState->id = true;
    mConfirmedState->currentState = LocalizedText{"", "Confirmed"};
    mConfirmedState->transitionTime = DateTime::now();

    update_comment_state(comment);

    return make_transition(true);
  }

  // Check branches
  for (auto& branch : mBranches)
  {
    if (eventId == branch.eventId)
    {
      auto* ack = dynamic_cast<AcknowledgeableConditionPayload*>(branch.snapshot.get());
      if (!ack || !ack->confirmedState.has_value())
      {
        break;
      }

      if (ack->confirmedState->id)
      {
        ConditionStateTransition result;
        result.status = StatusCode{Status::BadConditionBranchAlreadyConfirmed};
        return result;
      }

      ack->confirmedState->id = true;
      ack->confirmedState->currentState = LocalizedText{"", "Confirmed"};
      ack->confirmedState->transitionTime = DateTime::now();

      // Update branch comment, unless the comment is NULL (leave it unchanged per
      // OPC 10000-9 5.7.3 / 5.7.4); an empty text with a locale still resets it.
      if (!comment.is_null())
      {
        ack->comment.value = Variant{comment};
        ack->comment.sourceTimestamp = DateTime::now();
      }

      const bool resolved = is_branch_resolved(*branch.snapshot, mSupportsConfirm);

      auto result = make_transition(true);
      result.branchEvents.push_back({branch.branchId, /*retain=*/!resolved});
      return result;
    }
  }

  // Not the current trunk or a live branch: if this is a retired EventId whose state was already
  // confirmed, report Bad_ConditionBranchAlreadyConfirmed rather than Bad_EventIdUnknown (OPC 10000-9 5.13,
  // UACTT Confirm Err_004 "Secondary Confirm").
  if (auto retired = find_retired_event_id(eventId); retired && retired->confirmed)
  {
    ConditionStateTransition alreadyConfirmed;
    alreadyConfirmed.status = StatusCode{Status::BadConditionBranchAlreadyConfirmed};
    return alreadyConfirmed;
  }

  ConditionStateTransition result;
  result.status = StatusCode{Status::BadEventIdUnknown};
  return result;
}

ConditionStateTransition AcknowledgeableConditionLogic::add_comment(
  const ByteString& eventId, const LocalizedText& comment)
{
  // Try trunk first via base class logic
  if (eventId == last_event_id())
  {
    return ConditionLogic::add_comment(eventId, comment);
  }

  // Check branches
  for (auto& branch : mBranches)
  {
    if (eventId == branch.eventId)
    {
      auto* cond = dynamic_cast<ConditionPayload*>(branch.snapshot.get());
      if (!cond)
      {
        break;
      }

      cond->comment.value = Variant{comment};
      cond->comment.sourceTimestamp = DateTime::now();

      auto result = make_transition(true);
      result.branchEvents.push_back({branch.branchId, /*retain=*/true});
      return result;
    }
  }

  ConditionStateTransition result;
  result.status = StatusCode{Status::BadEventIdUnknown};
  return result;
}

// --- Initial state ---

void AcknowledgeableConditionLogic::set_initial_acked(bool acked)
{
  mAckedState.id = acked;
  mAckedState.currentState = LocalizedText{"", acked ? "Acknowledged" : "Unacknowledged"};
  mAckedState.transitionTime = DateTime::now();
  recompute_retain_no_emit();
}

void AcknowledgeableConditionLogic::set_initial_confirmed(bool confirmed)
{
  if (!mConfirmedState.has_value())
  {
    return;
  }
  mConfirmedState->id = confirmed;
  mConfirmedState->currentState = LocalizedText{"", confirmed ? "Confirmed" : "Unconfirmed"};
  mConfirmedState->transitionTime = DateTime::now();
  recompute_retain_no_emit();
}

bool AcknowledgeableConditionLogic::supports_confirm() const
{
  return mSupportsConfirm;
}

void AcknowledgeableConditionLogic::set_supports_confirm(bool value)
{
  mSupportsConfirm = value;
  if (value && !mConfirmedState.has_value())
  {
    mConfirmedState = TwoStateVariableState{};
  }
  else if (!value)
  {
    mConfirmedState.reset();
  }
}

void AcknowledgeableConditionLogic::set_supports_branches(bool value)
{
  mSupportsBranches = value;
}

void AcknowledgeableConditionLogic::set_max_branches(size_t maxBranches)
{
  mMaxBranches = maxBranches < 1 ? 1 : maxBranches;
}

void AcknowledgeableConditionLogic::set_last_event_id(ByteString eventId)
{
  // Retire the outgoing trunk EventId with its current acked/confirmed resolution before it is replaced, so
  // a later Acknowledge/Confirm referencing it reports already-acked/already-confirmed (OPC 10000-9 5.13)
  // instead of Bad_EventIdUnknown. An unresolved trunk state is preserved as a live branch and matched there
  // first, so a duplicate retired entry is harmless.
  const auto& previous = last_event_id();
  if (!previous.empty())
  {
    mRetiredEventIds.emplace_back(
      previous, RetiredResolution{mAckedState.id, mConfirmedState.has_value() && mConfirmedState->id});
    if (mRetiredEventIds.size() > sMaxRetiredEventIds)
    {
      mRetiredEventIds.erase(mRetiredEventIds.begin());
    }
  }
  ConditionLogic::set_last_event_id(std::move(eventId));
}

std::optional<AcknowledgeableConditionLogic::RetiredResolution>
  AcknowledgeableConditionLogic::find_retired_event_id(const ByteString& eventId) const
{
  // Search newest-first so the most recent resolution of a reused EventId wins.
  for (auto it = mRetiredEventIds.rbegin(); it != mRetiredEventIds.rend(); ++it)
  {
    if (it->first == eventId)
    {
      return it->second;
    }
  }
  return std::nullopt;
}

// --- Branch management ---

const std::vector<ConditionBranch>& AcknowledgeableConditionLogic::branches() const
{
  return mBranches;
}

void AcknowledgeableConditionLogic::set_branch_event_id(const NodeId& branchId, ByteString eventId)
{
  for (auto& branch : mBranches)
  {
    if (branch.branchId == branchId)
    {
      branch.eventId = std::move(eventId);
      return;
    }
  }
}

void AcknowledgeableConditionLogic::remove_branch(const NodeId& branchId)
{
  const auto matches = [&branchId](const ConditionBranch& b)
  {
    return b.branchId == branchId;
  };
  mBranches.erase(std::remove_if(mBranches.begin(), mBranches.end(), matches), mBranches.end());
  // Also drops the branch if it was awaiting its retraction: the shell calls this once the Retain=False
  // event has been emitted, which is what bounds mRetiredBranches.
  mRetiredBranches.erase(
    std::remove_if(mRetiredBranches.begin(), mRetiredBranches.end(), matches), mRetiredBranches.end());
}

std::unique_ptr<BaseEvent> AcknowledgeableConditionLogic::build_branch_event(
  const NodeId& branchId, bool retain) const
{
  // Live branches first, then those awaiting their own retraction: a branch dropped by the cap or by a
  // disable is no longer live, and its Retain=False event still has to be rendered from its snapshot.
  for (const auto* set : {&mBranches, &mRetiredBranches})
  {
    for (const auto& branch : *set)
    {
      if (branch.branchId != branchId)
      {
        continue;
      }
      auto event = branch.snapshot->clone();

      // Override branch-specific fields on the ConditionPayload base
      if (auto* cond = dynamic_cast<ConditionPayload*>(event.get()))
      {
        cond->branchId = branchId;
        cond->retain = retain;
      }

      return event;
    }
  }

  return nullptr;
}

// --- Event building ---

std::unique_ptr<BaseEvent> AcknowledgeableConditionLogic::build_event() const
{
  auto event = std::make_unique<AcknowledgeableConditionPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // AcknowledgeableConditionPayload-specific fields
  event->ackedState = mAckedState;
  event->confirmedState = mConfirmedState;

  return event;
}

// --- Protected accessors ---

bool AcknowledgeableConditionLogic::acknowledged() const
{
  return mAckedState.id;
}

bool AcknowledgeableConditionLogic::confirmed() const
{
  return mConfirmedState.has_value() && mConfirmedState->id;
}

const TwoStateVariableState& AcknowledgeableConditionLogic::acked_state() const
{
  return mAckedState;
}

const std::optional<TwoStateVariableState>& AcknowledgeableConditionLogic::confirmed_state() const
{
  return mConfirmedState;
}

void AcknowledgeableConditionLogic::reset_acked_state()
{
  mAckedState.id = false;
  mAckedState.currentState = LocalizedText{"", "Unacknowledged"};
  mAckedState.transitionTime = DateTime::now();
}

void AcknowledgeableConditionLogic::reset_confirmed_state()
{
  if (mConfirmedState.has_value())
  {
    mConfirmedState->id = false;
    mConfirmedState->currentState = LocalizedText{"", "Unconfirmed"};
    mConfirmedState->transitionTime = DateTime::now();
  }
}

bool AcknowledgeableConditionLogic::supports_branches() const
{
  return mSupportsBranches;
}

bool AcknowledgeableConditionLogic::has_unresolved_branches() const
{
  return std::any_of(mBranches.begin(),
    mBranches.end(),
    [this](const ConditionBranch& b) { return !is_branch_resolved(*b.snapshot, mSupportsConfirm); });
}

std::vector<BranchEventData> AcknowledgeableConditionLogic::create_branch()
{
  std::vector<BranchEventData> events;

  // Bound retained branches (memory fail-safe). A condition that toggles repeatedly while the operator
  // never acknowledges would otherwise grow mBranches without limit. Drop the oldest branch(es) first,
  // emitting Retain=False so the client removes them from its view, before adding the new branch.
  const size_t cap = mMaxBranches == 0 ? 1 : mMaxBranches;
  while (mBranches.size() >= cap)
  {
    events.push_back({mBranches.front().branchId, /*retain=*/false});
    mRetiredBranches.push_back(std::move(mBranches.front()));
    mBranches.erase(mBranches.begin());
  }

  ConditionBranch branch;
  branch.branchId = NodeId{Guid::create_and_generate()};
  branch.snapshot = build_event();

  // Set the branch_id on the snapshot so it's correct when cloned for emission
  if (auto* cond = dynamic_cast<ConditionPayload*>(branch.snapshot.get()))
  {
    cond->branchId = branch.branchId;
    cond->retain = true;
  }

  events.push_back({branch.branchId, /*retain=*/true});
  mBranches.push_back(std::move(branch));
  return events;
}

void AcknowledgeableConditionLogic::clear_all_branches(ConditionStateTransition& transition)
{
  for (auto& branch : mBranches)
  {
    transition.branchEvents.push_back({branch.branchId, /*retain=*/false});
    mRetiredBranches.push_back(std::move(branch));
  }
  mBranches.clear();
}

// --- Overrides ---

bool AcknowledgeableConditionLogic::compute_retain() const
{
  if (!enabled())
  {
    return false;
  }

  // Retain while unacknowledged
  if (!mAckedState.id)
  {
    return true;
  }

  // Retain while unconfirmed (if confirmation is supported)
  if (mSupportsConfirm && mConfirmedState.has_value() && !mConfirmedState->id)
  {
    return true;
  }

  // Retain while any branch needs attention
  if (has_unresolved_branches())
  {
    return true;
  }

  return false;
}

void AcknowledgeableConditionLogic::on_enabled()
{
  reset_acked_state();
  if (mSupportsConfirm)
  {
    reset_confirmed_state();
  }
}

void AcknowledgeableConditionLogic::on_disabled(ConditionStateTransition& transition)
{
  clear_all_branches(transition);
}

}  // namespace ua
