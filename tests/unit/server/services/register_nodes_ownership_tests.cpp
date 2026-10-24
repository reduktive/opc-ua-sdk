// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The NodeIds a RegisterNodes delegate returns belong to the Session whose response carries them, and are
// unregistered when no Client can unregister them any more: an answer whose request ended, a second answer,
// and what the Session still holds when it ends (Part 4 5.8.5.1; NR-4 release rule 2; delivery decision
// DL-14).
//
// The Session's end is what the server's Session does when it closes: it releases its registry
// (SessionInfo::registered_nodes()->release_all). That API is NR-70 F20's, so this file is listed in CMake
// when F20 is applied.

#include <gtest/gtest.h>

#include "register_nodes_harness.h"

#include "ua_session_registered_nodes.h"

#include <variant>
#include <vector>

using namespace ua;
using namespace ua::test::register_nodes;
using RegisterAnswer = ua::test::RegisterNodesRecordingNamespace::RegisterAnswer;

namespace
{

/// Ends the harness's Session as the server's Session does when it closes.
void end_session(RegisterNodesHarness& harness)
{
  harness.sessionInfo->registered_nodes()->release_all(harness.address_space().weak());
}

/// Whether @p nodeIds, in namespace @p index, are all still recorded as the Session's (taking them).
std::vector<bool> take(RegisterNodesHarness& harness, uint16_t index, const std::vector<NodeId>& nodeIds)
{
  return harness.sessionInfo->registered_nodes()->take(index, nodeIds);
}

}  // namespace

// @relation(AC-SVR-VIEW-REG-002-LATE-ANSWER-UNREGISTERED, scope=function)
TEST(RegisterNodesOwnership, AnAnswerAfterTheRequestEndedIsUnregistered)
{
  RegisterNodesHarness harness;
  harness.first->answer_registers(RegisterAnswer::Hold);
  harness.second->answer_registers(RegisterAnswer::Hold);
  harness.first->alias_next({NodeId{harness.firstIndex, "A1"}, NodeId{harness.firstIndex, "A2"}});
  harness.second->alias_next({NodeId{harness.secondIndex, "B1"}, NodeId{harness.secondIndex, "B2"}});

  // Ended by timeout while both answers are held.
  auto timedOut = harness.start_register(
    {NodeId{harness.firstIndex, "N1"}, NodeId{harness.secondIndex, "N1"}}, /*timeoutHint=*/100);
  ASSERT_TRUE(wait_until(
    [&harness] {
      return harness.first->held_register_answers() == 1u && harness.second->held_register_answers() == 1u;
    }));
  ASSERT_TRUE(timedOut.wait().has_value());
  harness.first->release_register_answers();
  harness.second->release_register_answers();

  // Ended by cancel while both answers are held.
  auto cancelled =
    harness.start_register({NodeId{harness.firstIndex, "N2"}, NodeId{harness.secondIndex, "N2"}});
  ASSERT_TRUE(wait_until(
    [&harness] {
      return harness.first->held_register_answers() == 1u && harness.second->held_register_answers() == 1u;
    }));
  cancelled.service->cancel();
  ASSERT_TRUE(cancelled.wait().has_value());
  harness.first->release_register_answers();
  harness.second->release_register_answers();

  for (const auto& [ns, name] : {std::pair{harness.first, "first"}, std::pair{harness.second, "second"}})
  {
    const auto returned = ns->returned();
    ASSERT_EQ(returned.size(), 2u);
    EXPECT_TRUE(wait_until([&ns, &returned]
      { return ns->unregistered_count(returned[0]) == 1u && ns->unregistered_count(returned[1]) == 1u; }))
      << "the " << name << " namespace returned " << text(returned) << " and was asked to unregister "
      << text(ns->unregistered());
  }
  EXPECT_EQ(take(harness, harness.firstIndex, harness.first->returned()), (std::vector<bool>{false, false}))
    << "a late answer was recorded as the Session's";
  EXPECT_EQ(take(harness, harness.secondIndex, harness.second->returned()), (std::vector<bool>{false, false}))
    << "a late answer was recorded as the Session's";
}

// @relation(AC-SVR-VIEW-REG-002-LATE-ANSWER-UNREGISTERED, scope=function)
TEST(RegisterNodesOwnership, AFailedRequestUnregistersEveryAnswerItRecorded)
{
  RegisterNodesHarness harness;
  harness.first->alias_next({NodeId{harness.firstIndex, "A1"}});
  // The second namespace fails the request: its answer does not match the request's size.
  harness.second->answer_registers(RegisterAnswer::OneTooMany);
  harness.second->alias_next({NodeId{harness.secondIndex, "B1"}, NodeId{harness.secondIndex, "B2"}});

  auto failed = harness.start_register({NodeId{harness.firstIndex, "N1"}, NodeId{harness.secondIndex, "N1"}});
  const auto answer = failed.wait();
  ASSERT_TRUE(answer.has_value());
  ASSERT_NE(std::get_if<ServiceFault>(&*answer), nullptr) << "precondition: the request failed";

  for (const auto& [ns, name] : {std::pair{harness.first, "first"}, std::pair{harness.second, "second"}})
  {
    const auto returned = ns->returned();
    ASSERT_FALSE(returned.empty());
    EXPECT_TRUE(wait_until(
      [&ns, &returned]
      {
        for (const auto& nodeId : returned)
        {
          if (ns->unregistered_count(nodeId) != 1u)
          {
            return false;
          }
        }
        return true;
      }))
      << "the " << name << " namespace returned " << text(returned) << " and was asked to unregister "
      << text(ns->unregistered());
  }
  EXPECT_EQ(take(harness, harness.firstIndex, harness.first->returned()), (std::vector<bool>{false}))
    << "an answer of the failed request was recorded as the Session's";
}

// @relation(AC-SVR-VIEW-REG-002-ANSWER-AFTER-RESPONSE-UNREGISTERED, scope=function)
TEST(RegisterNodesOwnership, AnAnswerAfterTheResponseWasSentIsUnregisteredAndNotRecorded)
{
  RegisterNodesHarness harness;
  const NodeId r1{harness.firstIndex, "R1"};
  const NodeId r2{harness.firstIndex, "R2"};
  harness.first->answer_registers(RegisterAnswer::NowAndKeep);
  harness.first->alias_next({r1, r2});

  const auto registered = harness.register_nodes({NodeId{harness.firstIndex, "N1"}});
  EXPECT_EQ(registered, (std::vector<NodeId>{r1}));

  harness.first->answer_kept_calls_again();
  EXPECT_TRUE(wait_until([&harness, &r2] { return harness.first->unregistered_count(r2) == 1u; }))
    << "R2, answered after the response, was not unregistered; unregistered: "
    << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(r1), 0u) << "R1, which the response carried, was unregistered";

  end_session(harness);
  EXPECT_TRUE(wait_until([&harness, &r1] { return harness.first->unregistered_count(r1) == 1u; }))
    << "the Session's end did not unregister R1; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(r2), 1u) << "R2 was unregistered again at the Session's end";
}

// @relation(AC-SVR-VIEW-REG-002-SECOND-ANSWER-UNREGISTERED, scope=function)
TEST(RegisterNodesOwnership, ADelegateThatAnswersTwiceHasItsSecondAnswerUnregistered)
{
  RegisterNodesHarness harness;
  const NodeId r1{harness.firstIndex, "R1"};
  const NodeId r2{harness.firstIndex, "R2"};
  harness.first->answer_registers(RegisterAnswer::Twice);
  harness.first->alias_next({r1, r2});

  const auto registered = harness.register_nodes({NodeId{harness.firstIndex, "N1"}});
  EXPECT_EQ(registered, (std::vector<NodeId>{r1}));
  EXPECT_TRUE(wait_until([&harness, &r2] { return harness.first->unregistered_count(r2) == 1u; }))
    << "the second answer R2 was not unregistered; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(r1), 0u);

  end_session(harness);
  EXPECT_TRUE(wait_until([&harness, &r1] { return harness.first->unregistered_count(r1) == 1u; }))
    << "the Session's end did not unregister R1; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(r2), 1u) << "R2 was unregistered again at the Session's end";
}

// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-02-REFUSED-UNREGISTER-KEEPS-IDS, scope=function)
TEST(RegisterNodesOwnership, ARefusedUnregisterLeavesTheIdsRegistered)
{
  RegisterNodesHarness harness;
  const NodeId x{harness.firstIndex, "N1"};
  const NodeId z{harness.firstIndex, "N2"};
  ASSERT_EQ(harness.register_nodes({x, z}), (std::vector<NodeId>{x, z}));

  harness.first->answer_unregisters(StatusCode{Status::BadInternalError});
  harness.unregister_nodes({x});
  harness.first->answer_unregisters(StatusCode{});
  harness.unregister_nodes({x});
  EXPECT_EQ(harness.first->unregistered_count(x), 2u) << "the retried UnregisterNodes was not forwarded";

  end_session(harness);
  EXPECT_TRUE(wait_until([&harness, &z] { return harness.first->unregistered_count(z) == 1u; }))
    << "the Session's end did not unregister Z; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(x), 2u) << "X was unregistered again at the Session's end";
}

// Part 4 section 5.8.5.2, Table 43: "The Server may return the NodeId from the request or a new (an alias)
// NodeId." A batch status that is not Bad leaves the response carrying the delegate's NodeIds, so they are
// the Session's whatever the severity (NR-4 release rule 2): UnregisterNodes forwards A1, and the Session's
// end unregisters A2 and not A1 again.
// @relation(AC-SVR-VIEW-REG-002-UNCERTAIN-BATCH-ALIASES-ARE-THE-SESSIONS, scope=function)
TEST(RegisterNodesOwnership, AnUncertainBatchsAliasesAreTheSessions)
{
  RegisterNodesHarness harness;
  const NodeId n1{harness.firstIndex, "N1"};
  const NodeId n2{harness.firstIndex, "N2"};
  const NodeId a1{harness.firstIndex, "A1"};
  const NodeId a2{harness.firstIndex, "A2"};
  harness.first->answer_batch_status(StatusCode{Status::Uncertain});
  harness.first->alias_next({a1, a2});

  EXPECT_EQ(harness.register_nodes({n1, n2}), (std::vector<NodeId>{a1, a2}))
    << "the response does not carry the delegate's NodeIds";

  EXPECT_EQ(harness.unregister_nodes({a1}).as_status(), Status::Good);
  EXPECT_EQ(harness.first->unregistered_count(a1), 1u)
    << "A1 was not forwarded at the UnregisterNodes; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(a2), 0u) << "A2 was unregistered before the Session's end";

  end_session(harness);
  EXPECT_TRUE(wait_until([&harness, &a2] { return harness.first->unregistered_count(a2) == 1u; }))
    << "the Session's end did not unregister A2; unregistered: " << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(a1), 1u) << "A1 was unregistered again at the Session's end";
}

// Part 4 section 5.8.6.1: "Servers shall simply unregister NodeIds that are known as registered NodeIds." An
// alias is unregistered by the namespace whose delegate returned it, whatever namespace its NodeId names
// (NR-4 release rules 2 and 3). Namespace 2 returns A and B in namespace 3's index; namespace 3 returns C,
// the control that a namespace's own alias still goes to it.
// @relation(AC-SVR-VIEW-URG-001-ALIAS-IN-ANOTHER-NAMESPACE-GOES-TO-ITS-REGISTRANT, scope=function)
TEST(RegisterNodesOwnership, AnAliasInAnotherNamespaceIsUnregisteredByItsRegistrant)
{
  RegisterNodesHarness harness;
  const NodeId n1{harness.firstIndex, "N1"};
  const NodeId n2{harness.firstIndex, "N2"};
  const NodeId n3{harness.secondIndex, "N3"};
  const NodeId a{harness.secondIndex, "A"};
  const NodeId b{harness.secondIndex, "B"};
  const NodeId c{harness.secondIndex, "C"};
  harness.first->alias_next({a, b});
  harness.second->alias_next({c});

  EXPECT_EQ(harness.register_nodes({n1, n2, n3}), (std::vector<NodeId>{a, b, c}));

  EXPECT_EQ(harness.unregister_nodes({a, c}).as_status(), Status::Good);
  EXPECT_EQ(harness.first->unregistered_count(a), 1u)
    << "A was not forwarded to namespace 2, whose delegate returned it; namespace 2 unregistered "
    << text(harness.first->unregistered());
  EXPECT_EQ(harness.second->unregistered_count(c), 1u)
    << "C was not forwarded to namespace 3; namespace 3 unregistered "
    << text(harness.second->unregistered());
  EXPECT_EQ(harness.second->unregistered_count(a), 0u)
    << "A was forwarded to namespace 3, the namespace of its index, which did not register it";

  end_session(harness);
  EXPECT_TRUE(wait_until([&harness, &b] { return harness.first->unregistered_count(b) == 1u; }))
    << "the Session's end did not unregister B at namespace 2; namespace 2 unregistered "
    << text(harness.first->unregistered());
  EXPECT_EQ(harness.first->unregistered_count(a), 1u) << "A was unregistered again at the Session's end";
  EXPECT_EQ(harness.second->unregistered_count(c), 1u) << "C was unregistered again at the Session's end";
  EXPECT_EQ(harness.second->unregistered_count(a), 0u);
  EXPECT_EQ(harness.second->unregistered_count(b), 0u) << "B was unregistered at namespace 3";
}

// Every SessionInfo is constructed with a registry; the stub's two constructors are both used.
// @relation(AC-COMP-SVR-SESSION-REGISTERED-NODES-01-EVERY-SESSION-HAS-A-REGISTRY, scope=function)
TEST(SessionRegisteredNodes, EverySessionInfoHasARegistry)
{
  for (const bool failClosedConstructor : {false, true})
  {
    RegisterNodesHarness harness{failClosedConstructor};
    const NodeId x{harness.firstIndex, "N1"};
    ASSERT_EQ(harness.register_nodes({x}), (std::vector<NodeId>{x}));
    end_session(harness);
    EXPECT_TRUE(wait_until([&harness, &x] { return harness.first->unregistered_count(x) == 1u; }))
      << (failClosedConstructor ? "the second" : "the first") << " constructor's Session did not unregister "
      << to_string(x) << " at its end";
  }
}
