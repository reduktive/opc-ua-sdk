// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A RegisterNodes answer that reaches no Client is unregistered again, and the unregistration does not call
// the delegate back from inside its own answer (NR-4 release rule 2; delivery decision DL-14). The arms of
// the Session's registry that need its new API are in session_registered_nodes_tests.cpp.

#include <gtest/gtest.h>

#include "register_nodes_harness.h"

#include <variant>

using namespace ua;
using namespace ua::test::register_nodes;
using RegisterAnswer = ua::test::RegisterNodesRecordingNamespace::RegisterAnswer;

// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-01-RELEASE-FROM-A-CALLBACK-IS-POSTED, scope=function)
TEST(SessionRegisteredNodes, AReleaseStartedInsideADelegateAnswerIsPosted)
{
  RegisterNodesHarness harness;
  harness.first->answer_registers(RegisterAnswer::Hold);
  auto pending = harness.start_register({NodeId{harness.firstIndex, "N1"}}, /*timeoutHint=*/100);
  ASSERT_TRUE(wait_until([&harness] { return harness.first->held_register_answers() == 1u; }));
  const auto answer = pending.wait();
  ASSERT_TRUE(answer.has_value());
  const auto* fault = std::get_if<ServiceFault>(&*answer);
  ASSERT_NE(fault, nullptr) << "precondition: the request timed out";
  ASSERT_EQ(fault->response_header().service_result().as_status(), Status::BadTimeout);

  // The delegate answers on this thread, after the request ended.
  harness.first->release_register_answers();
  const auto returned = harness.first->returned();
  ASSERT_EQ(returned.size(), 1u);
  EXPECT_TRUE(wait_until([&harness, &returned] { return harness.first->unregistered() == returned; }))
    << "the late answer " << text(returned)
    << " was not unregistered; unregistered: " << text(harness.first->unregistered());
  EXPECT_FALSE(harness.first->unregistered_inside_a_register_answer())
    << "the delegate was asked to unregister from inside its own RegisterNodes answer";
}
