// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the decode-and-defer decision core (ua::client::detail::TypeDeferGate, client design
// section 9.2 / section 9.8 override 2, GATED-LAZY).
//
// Covers the three ratified decisions: (1) eligibility - application-data responses may DEFER, security /
// handshake bodies StrictFail (fail closed, never a placeholder); (2) budget - over
// maxDistinctUnresolvedTypesPerMessage the message surfaces terminal placeholders and the decode still
// SUCCEEDS (never a hard failure), and re-decode is bounded to maxReDecodePasses = 1; (3) the advisory
// dedup set is LRU-bounded so a hostile server emitting many distinct types cannot grow it without limit.
//
// Falsifiability: a gate that defers a security body fails SecurityBodyStrictFailsClosed; one that fails
// (rather than places-holders) an over-budget app-data message fails OverBudgetPlaceholdersNotStrictFail;
// one with an unbounded advisory set fails AdvisoryDedupSetIsBounded.

#include "ua_type_defer_gate.h"

#include "ua_node_id.h"
#include "ua_type_resolution_policy.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::TypeDeferPolicy;
using ua::client::detail::DeferDecision;
using ua::client::detail::MessageClass;
using ua::client::detail::TypeDeferGate;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{1, identifier};
}

TypeDeferGate make_gate(std::size_t maxDistinct = 4, std::size_t dedupCap = 4, std::size_t redecodePasses = 1)
{
  TypeDeferPolicy policy;
  policy.maxDistinctUnresolvedTypesPerMessage = maxDistinct;
  policy.advisoryDedupCap = dedupCap;
  policy.maxReDecodePasses = redecodePasses;
  return TypeDeferGate{policy};
}

// ---- eligibility (the security boundary) ----

// @verifies CL-MI-030
// @relation(CL-MI-030, scope=function)
TEST(TypeDeferGate, ApplicationDataWithinBudgetDefers)
{
  auto gate = make_gate(/*maxDistinct=*/4);
  EXPECT_EQ(gate.classify(MessageClass::ApplicationData, 1), DeferDecision::Defer);
  EXPECT_EQ(gate.classify(MessageClass::ApplicationData, 4), DeferDecision::Defer);  // at the boundary
}

// @verifies CL-ATTR-013
// @relation(CL-ATTR-013, scope=function)
TEST(TypeDeferGate, SecurityBodyStrictFailsClosed)
{
  auto gate = make_gate();
  // A security/handshake body NEVER defers, even for a single unknown - fail closed (do not defer a
  // check on attacker-influenced bytes).
  EXPECT_EQ(gate.classify(MessageClass::SecurityCritical, 1), DeferDecision::StrictFail);
  EXPECT_EQ(gate.classify(MessageClass::SecurityCritical, 100), DeferDecision::StrictFail);
}

// ---- budget (DoS guard) ----

// @verifies CL-MI-030
// @relation(CL-MI-030, scope=function)
TEST(TypeDeferGate, OverBudgetPlaceholdersNotStrictFail)
{
  auto gate = make_gate(/*maxDistinct=*/4);
  // Over the distinct-type budget the app-data message surfaces terminal placeholders - it does NOT
  // fail (the decode still succeeds, section 9.8 override 2).
  const auto decision = gate.classify(MessageClass::ApplicationData, 5);
  EXPECT_EQ(decision, DeferDecision::Placeholder);
  EXPECT_NE(decision, DeferDecision::StrictFail);
}

// @verifies CL-MI-030
// @relation(CL-MI-030, scope=function)
TEST(TypeDeferGate, ReDecodeBudgetIsBoundedToOnePass)
{
  auto gate = make_gate(/*maxDistinct=*/4, /*dedupCap=*/4, /*redecodePasses=*/1);
  EXPECT_TRUE(gate.may_redecode(0));  // pass 0 permitted
  EXPECT_FALSE(gate.may_redecode(1));  // a second pass is refused (maxReDecodePasses = 1)
}

// ---- bounded advisory dedup (section 9.6.18.4) ----

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeDeferGate, AdvisoryCoalescesRepeatSightings)
{
  auto gate = make_gate();
  EXPECT_TRUE(gate.record_advisory_first_seen(node(500)));  // first time: fire
  EXPECT_FALSE(gate.record_advisory_first_seen(node(500)));  // repeat: coalesced
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeDeferGate, AdvisoryDedupSetIsBounded)
{
  auto gate = make_gate(/*maxDistinct=*/4, /*dedupCap=*/4);
  // A hostile server emitting many distinct fallback types must not grow the dedup structure without
  // limit - it is LRU-capped at advisoryDedupCap.
  for (std::uint32_t identifier = 0; identifier < 1000; ++identifier)
  {
    (void)gate.record_advisory_first_seen(node(identifier));
  }
  EXPECT_LE(gate.advisory_dedup_size(), 4U);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeDeferGate, EvictedAdvisoryFiresAgainCoarsening)
{
  auto gate = make_gate(/*maxDistinct=*/4, /*dedupCap=*/2);
  EXPECT_TRUE(gate.record_advisory_first_seen(node(1)));
  EXPECT_TRUE(gate.record_advisory_first_seen(node(2)));
  EXPECT_TRUE(gate.record_advisory_first_seen(node(3)));  // evicts LRU (node 1)
  EXPECT_TRUE(gate.record_advisory_first_seen(node(1)));  // re-seen after eviction: acceptable coarsening
  EXPECT_LE(gate.advisory_dedup_size(), 2U);
}

}  // namespace
