// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dialog_condition_logic.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_dialog_condition_payload.h"
#include "ua_status.h"
#include "ua_variant.h"

namespace ua
{

// --- Dialog operations ---

ConditionStateTransition DialogConditionLogic::activate_dialog(LocalizedText prompt)
{
  mPrompt = std::move(prompt);
  mDialogState.id = true;
  mDialogState.currentState = LocalizedText{"", "Active"};
  mDialogState.transitionTime = DateTime::now();

  return make_transition(true);
}

ConditionStateTransition DialogConditionLogic::respond(int32_t selectedResponse)
{
  if (!mDialogState.id)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadDialogNotActive};
    return result;
  }

  if (selectedResponse < 0 || selectedResponse >= mNumOptions)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadDialogResponseInvalid};
    return result;
  }

  mLastResponse = selectedResponse;
  mDialogState.id = false;
  mDialogState.currentState = LocalizedText{"", "Inactive"};
  mDialogState.transitionTime = DateTime::now();

  return make_transition(true);
}

ConditionStateTransition DialogConditionLogic::respond(int32_t selectedResponse, LocalizedText comment)
{
  if (!mDialogState.id)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadDialogNotActive};
    return result;
  }

  if (selectedResponse < 0 || selectedResponse >= mNumOptions)
  {
    ConditionStateTransition result;
    result.status = StatusCode{Status::BadDialogResponseInvalid};
    return result;
  }

  mLastResponse = selectedResponse;
  update_comment_state(comment);

  mDialogState.id = false;
  mDialogState.currentState = LocalizedText{"", "Inactive"};
  mDialogState.transitionTime = DateTime::now();

  return make_transition(true);
}

// --- Configuration ---

void DialogConditionLogic::set_response_options(int32_t numOptions)
{
  mNumOptions = numOptions;
  const auto optionCount = numOptions > 0 ? static_cast<size_t>(numOptions) : size_t{0};
  mResponseOptionSet = Array<LocalizedText>{Size{optionCount}};
}

void DialogConditionLogic::set_default_response(int32_t index)
{
  mDefaultResponse = index;
}

void DialogConditionLogic::set_ok_response(int32_t index)
{
  mOkResponse = index;
}

void DialogConditionLogic::set_cancel_response(int32_t index)
{
  mCancelResponse = index;
}

// --- Event building ---

std::unique_ptr<BaseEvent> DialogConditionLogic::build_event() const
{
  auto event = std::make_unique<DialogConditionPayload>();
  populate_base_fields(*event);
  populate_condition_fields(*event);

  // DialogConditionPayload-specific fields
  event->dialogState = mDialogState;
  event->prompt = mPrompt;
  event->responseOptionSet = mResponseOptionSet;
  event->defaultResponse = mDefaultResponse;
  event->okResponse = mOkResponse;
  event->cancelResponse = mCancelResponse;
  event->lastResponse = mLastResponse;

  return event;
}

// --- Protected ---

bool DialogConditionLogic::compute_retain() const
{
  return enabled() && mDialogState.id;
}

const TwoStateVariableState& DialogConditionLogic::dialog_state() const
{
  return mDialogState;
}

int32_t DialogConditionLogic::last_response() const
{
  return mLastResponse;
}

}  // namespace ua
