// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine_method_hook.h"

#include "ua_callback_safety.h"
#include "ua_to_result.h"

#include <exception>
#include <memory>
#include <utility>

namespace ua::server
{

void apply_state_machine_method_hook_async(CallResult applicationResult,
  StateMachineTransitionAction transitionAction, StateMachineMethodHookCompletion completion,
  Logger logger) noexcept
{
  auto finish = ua::detail::make_fire_once<CallResult>(
    [logger, completion = std::move(completion)](CallResult result) mutable
    { ua::detail::invoke_user_callback(logger, completion, std::move(result)); });
  if (!applicationResult.has_value())
  {
    finish(std::move(applicationResult));
    return;
  }

  // The code the application answered with (plain Good, a Good subcode or an Uncertain code) stays on the
  // answer the transition completes with.
  const StatusCode answeredCode = applicationResult.status_code();
  auto methodResult = std::make_shared<CallMethodResult>(std::move(applicationResult).value());
  auto transitionCompletion = ua::detail::make_fire_once<VoidResult>(
    [methodResult, answeredCode, finish](VoidResult transitionResult) mutable
    {
      if (transitionResult.is_bad())
      {
        methodResult->status_code() = transitionResult.status_code();
      }
      finish(CallResult{std::move(*methodResult), answeredCode});
    });
  try
  {
    transitionAction(transitionCompletion);
  }
  catch (...)
  {
    transitionCompletion(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua::server
