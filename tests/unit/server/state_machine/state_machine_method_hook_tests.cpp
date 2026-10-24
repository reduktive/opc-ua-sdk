// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine_method_hook.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace ua::server
{
namespace
{

CallMethodResult successful_application_result()
{
  CallMethodResult result;
  result.output_arguments().push_back(Variant{String{"first output"}});
  result.output_arguments().push_back(Variant{uint32_t{42U}});
  return result;
}

// @relation(AC-COMP-SVR-SM-RUNTIME-04-METHOD-HOOK, scope=function)
TEST(StateMachineMethodHookTest, FailedApplicationResultBypassesRuntimeUnchanged)
{
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("ApplicationFailure", "application method failed", "test")};
  const StatusCode failure{Status::BadInvalidArgument, detail};
  size_t actionCalls{0};
  std::vector<CallResult> completions;

  apply_state_machine_method_hook_async(
    CallResult{failure},
    [&actionCalls](std::function<void(VoidResult)>) { ++actionCalls; },
    [&completions](CallResult result) { completions.push_back(std::move(result)); });

  EXPECT_EQ(actionCalls, 0U);
  ASSERT_EQ(completions.size(), 1U);
  EXPECT_EQ(completions[0].status_code().value(), failure.value());
  EXPECT_EQ(completions[0].shared_detail(), detail);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-04-METHOD-HOOK, scope=function)
TEST(StateMachineMethodHookTest, RuntimeSuccessPreservesApplicationResult)
{
  auto application = successful_application_result();
  const auto expected = application;
  std::function<void(VoidResult)> runtimeCompletion;
  std::vector<CallResult> completions;

  apply_state_machine_method_hook_async(
    CallResult{std::move(application)},
    [&runtimeCompletion](std::function<void(VoidResult)> callback)
    { runtimeCompletion = std::move(callback); },
    [&completions](CallResult result) { completions.push_back(std::move(result)); });
  ASSERT_TRUE(runtimeCompletion);
  EXPECT_TRUE(completions.empty());

  runtimeCompletion(VoidResult{});

  ASSERT_EQ(completions.size(), 1U);
  ASSERT_TRUE(completions[0].is_good());
  EXPECT_EQ(completions[0].value(), expected);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-04-METHOD-HOOK, scope=function)
TEST(StateMachineMethodHookTest, RichRuntimeFailureReplacesStatusButPreservesOutputs)
{
  auto application = successful_application_result();
  const auto expectedOutputs = application.output_arguments();
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("RuntimeFailure", "state transition failed", "test")};
  const StatusCode failure{Status::BadConfigurationError, detail};
  std::function<void(VoidResult)> runtimeCompletion;
  std::vector<CallResult> completions;

  apply_state_machine_method_hook_async(
    CallResult{std::move(application)},
    [&runtimeCompletion](std::function<void(VoidResult)> callback)
    { runtimeCompletion = std::move(callback); },
    [&completions](CallResult result) { completions.push_back(std::move(result)); });
  ASSERT_TRUE(runtimeCompletion);
  runtimeCompletion(VoidResult{failure});

  ASSERT_EQ(completions.size(), 1U);
  ASSERT_TRUE(completions[0].is_good());
  EXPECT_EQ(completions[0].value().status_code().value(), failure.value());
  EXPECT_EQ(completions[0].value().status_code().shared_detail(), detail);
  EXPECT_EQ(completions[0].value().output_arguments(), expectedOutputs);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-04-METHOD-HOOK, scope=function)
TEST(StateMachineMethodHookTest, DuplicateRuntimeCompletionFinalizesOnce)
{
  std::function<void(VoidResult)> runtimeCompletion;
  size_t completions{0};

  apply_state_machine_method_hook_async(
    CallResult{successful_application_result()},
    [&runtimeCompletion](std::function<void(VoidResult)> callback)
    { runtimeCompletion = std::move(callback); },
    [&completions](CallResult) { ++completions; });
  ASSERT_TRUE(runtimeCompletion);
  runtimeCompletion(VoidResult{});
  runtimeCompletion(VoidResult{Status::BadInternalError});

  EXPECT_EQ(completions, 1U);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-04-METHOD-HOOK, scope=function)
TEST(StateMachineMethodHookTest, FireThenThrowCompletesOnceWithFirstResult)
{
  const auto expected = successful_application_result();
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("LateActionThrow", "transition action threw after completion", "test")};
  const StatusCode lateFailure{Status::BadInternalError, detail};
  std::vector<CallResult> completions;

  apply_state_machine_method_hook_async(
    CallResult{expected},
    [lateFailure](std::function<void(VoidResult)> runtimeCompletion)
    {
      runtimeCompletion(VoidResult{});
      throw UaException{lateFailure};
    },
    [&completions](CallResult result) { completions.push_back(std::move(result)); });

  ASSERT_EQ(completions.size(), 1U);
  ASSERT_TRUE(completions[0].is_good());
  EXPECT_EQ(completions[0].value(), expected);
}

}  // namespace
}  // namespace ua::server
