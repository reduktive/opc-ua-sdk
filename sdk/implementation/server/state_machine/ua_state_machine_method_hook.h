// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_METHOD_HOOK_H
#define UA_STATE_MACHINE_METHOD_HOOK_H

#include "ua_call_method_result.h"
#include "ua_logger.h"
#include "ua_result.h"

#include <functional>

namespace ua::server
{

using StateMachineTransitionAction = std::function<void(std::function<void(VoidResult)>)>;
using StateMachineMethodHookCompletion = std::function<void(CallResult)>;

void apply_state_machine_method_hook_async(CallResult applicationResult,
  StateMachineTransitionAction transitionAction, StateMachineMethodHookCompletion completion,
  Logger logger = {}) noexcept;

}  // namespace ua::server

#endif  // UA_STATE_MACHINE_METHOD_HOOK_H
