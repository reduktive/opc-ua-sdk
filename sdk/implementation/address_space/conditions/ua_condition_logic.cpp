// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_logic.h"

#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_status.h"
#include "ua_variant.h"

namespace ua
{

// --- Public state mutations ---

ConditionStateTransition ConditionLogic::enable()
{
  if (mEnabled)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionAlreadyEnabled};
    return result;
  }

  mEnabled = true;
  mEnteredDisabled = false;
  mEnabledState.id = true;
  mEnabledState.currentState = LocalizedText{"", "Enabled"};
  mEnabledState.transitionTime = DateTime::now();

  on_enabled();

  return make_transition(true);
}

ConditionStateTransition ConditionLogic::disable()
{
  if (!mEnabled)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadConditionAlreadyDisabled};
    return result;
  }

  mEnabled = false;
  mEnteredDisabled = true;
  mEnabledState.id = false;
  mEnabledState.currentState = LocalizedText{"", "Disabled"};
  mEnabledState.transitionTime = DateTime::now();

  mRetain = false;

  // OPC 10000-9 4.3 (Figure 1): a transition into the Disabled state always results in a
  // Condition Event, after which no further notifications are generated until the Condition is
  // re-enabled. This holds even when the Condition was not retained at disable time (e.g. an
  // inactive, acknowledged alarm whose Retain was already false).
  ConditionStateTransition result;
  result.changed = true;
  result.emitEvent = true;

  on_disabled(result);

  return result;
}

void ConditionLogic::on_disabled(ConditionStateTransition& /*transition*/)
{
  // Base does nothing. Subclasses override to clean up branches.
}

ConditionStateTransition ConditionLogic::add_comment(const ByteString& eventId, const LocalizedText& comment)
{
  // Validate EventId against last emitted
  if (eventId != mLastEventId)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadEventIdUnknown};
    return result;
  }

  update_comment_state(comment);

  return make_transition(true);
}

ConditionStateTransition ConditionLogic::set_quality(StatusCode quality)
{
  auto now = DateTime::now();
  mQuality = quality;
  mQualityState.value = Variant{quality};
  mQualityState.sourceTimestamp = now;

  return make_transition(true);
}

ConditionStateTransition ConditionLogic::set_severity(uint16_t severity)
{
  auto now = DateTime::now();

  // Track last severity before updating
  mLastSeverityState.value = Variant{mSeverity};
  mLastSeverityState.sourceTimestamp = now;

  mSeverity = severity;

  return make_transition(true);
}

// --- Initial state ---

void ConditionLogic::set_initial_enabled(bool enabled)
{
  mEnabled = enabled;
  // Recovery seeds the state a Condition was persisted in, so a Condition recovered as disabled is a
  // Condition in the Disabled state - not one that has yet to be switched on for the first time.
  mEnteredDisabled = !enabled;
  mEnabledState.id = enabled;
  mEnabledState.currentState = LocalizedText{"", enabled ? "Enabled" : "Disabled"};
  mEnabledState.transitionTime = DateTime::now();
  mRetain = compute_retain();
}

// --- Simple setters ---

void ConditionLogic::set_source(NodeId sourceNode, String sourceName)
{
  mSourceNode = std::move(sourceNode);
  mSourceName = std::move(sourceName);
}

void ConditionLogic::set_condition_name(String name)
{
  mConditionName = std::move(name);
}

void ConditionLogic::set_condition_class(NodeId classId, LocalizedText className)
{
  mConditionClassId = std::move(classId);
  mConditionClassName = std::move(className);
}

void ConditionLogic::set_client_user_id(String userId)
{
  mClientUserId = std::move(userId);
}

void ConditionLogic::set_supports_filtered_retain(bool value)
{
  mSupportsFilteredRetain = value;
}

void ConditionLogic::set_last_event_id(ByteString eventId)
{
  mLastEventId = std::move(eventId);
}

// --- Event building ---

std::unique_ptr<BaseEvent> ConditionLogic::build_event() const
{
  auto event = std::make_unique<ConditionPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  return event;
}

void ConditionLogic::populate_condition_fields(ConditionPayload& event) const
{
  event.conditionClassId = mConditionClassId;
  event.conditionClassName = mConditionClassName;
  event.conditionName = mConditionName;
  event.branchId = mBranchId;
  event.retain = mRetain;
  event.supportsFilteredRetain = mSupportsFilteredRetain;
  event.clientUserId = mClientUserId;
  event.enabledState = mEnabledState;
  event.quality = mQualityState;
  event.lastSeverity = mLastSeverityState;
  event.comment = mCommentState;
}

// --- Protected accessors ---

bool ConditionLogic::enabled() const
{
  return mEnabled;
}

bool ConditionLogic::retained() const
{
  return mRetain;
}

uint16_t ConditionLogic::severity() const
{
  return mSeverity;
}

const StatusCode& ConditionLogic::quality() const
{
  // OPC 10000-9 5.5.2: Quality is not among the Variables that stay valid in the Disabled state, and
  // nothing updates it while the Condition is disabled, so the value held here is the one it had when
  // it was switched off. Reporting that is worse than reporting nothing - it is indistinguishable from
  // a live reading. The stored value is left alone so re-enabling restores it without re-evaluation.
  static const StatusCode disabled{Status::BadConditionDisabled};
  return mEnteredDisabled ? disabled : mQuality;
}

const ByteString& ConditionLogic::last_event_id() const
{
  return mLastEventId;
}

const TwoStateVariableState& ConditionLogic::enabled_state() const
{
  return mEnabledState;
}

const NodeId& ConditionLogic::source_node() const
{
  return mSourceNode;
}

const String& ConditionLogic::source_name() const
{
  return mSourceName;
}

// --- Protected helpers ---

void ConditionLogic::populate_base_fields(BaseEvent& event) const
{
  event.sourceNode = mSourceNode;
  event.sourceName = mSourceName;
  event.time = DateTime::now();
  event.severity = mSeverity;
  event.message = mComment;
  event.conditionClassId = mConditionClassId;
  event.conditionClassName = mConditionClassName;
}

bool ConditionLogic::recompute_retain_no_emit()
{
  const bool oldRetain = mRetain;
  mRetain = compute_retain();
  return oldRetain && !mRetain;
}

bool ConditionLogic::compute_retain() const
{
  return mEnabled;
}

ConditionStateTransition ConditionLogic::make_transition(bool stateChanged)
{
  const bool wasRetained = mRetain;
  recompute_retain_no_emit();

  ConditionStateTransition result;
  result.changed = stateChanged;

  // Emit when state changed while retained, OR on the Retain True->False edge
  if (stateChanged && (mRetain || wasRetained))
  {
    result.emitEvent = true;
  }

  return result;
}

void ConditionLogic::update_comment_state(const LocalizedText& comment)
{
  // A NULL comment (both locale and text empty) is ignored and leaves any existing comment
  // unchanged; an empty text WITH a locale is the explicit reset form and overwrites
  // (OPC 10000-9 5.5.6 / 5.7.3 / 5.7.4).
  if (comment.is_null())
  {
    return;
  }

  auto now = DateTime::now();
  mComment = comment;
  mCommentState.value = Variant{comment};
  mCommentState.sourceTimestamp = now;
}

ConditionStateTransition ConditionLogic::apply_method_comment(
  ConditionStateTransition transition, const LocalizedText& comment)
{
  if (transition.status.is_good())
  {
    update_comment_state(comment);
  }

  return transition;
}

void ConditionLogic::on_enabled()
{}

}  // namespace ua
