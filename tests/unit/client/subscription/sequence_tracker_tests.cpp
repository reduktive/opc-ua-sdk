// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::SequenceTracker (section 8.4 / CL-SUB-002, CL-SUB-017) -
// per-Subscription Publish sequence-number classification. The subtle parts: sequence 0 is never valid, the
// 32-bit counter wraps from max back to 1 (not 0), and gap vs. duplicate must stay correct across that wrap.
//
// Falsifiability: an "always InOrder" stub fails every Gap/Duplicate/Invalid case; a naive received+1
// advance (no wrap, no seq-0 skip) fails the wrap tests.
//
// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=file)

#include "ua_sequence_tracker.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::detail::SequenceClass;
using ua::client::detail::SequenceTracker;
using ua::client::detail::should_deliver;

constexpr std::uint32_t max = SequenceTracker::maxSequenceNumber;

TEST(SequenceTracker, FreshTrackerExpectsOne)
{
  EXPECT_EQ(SequenceTracker{}.next_expected(), 1u);
}

TEST(SequenceTracker, TransferredTrackerExpectsGivenNumber)
{
  EXPECT_EQ(SequenceTracker{100}.next_expected(), 100u);
}

TEST(SequenceTracker, ZeroIsAlwaysInvalid)
{
  EXPECT_EQ(SequenceTracker{}.classify(0), SequenceClass::Invalid);
  EXPECT_EQ(SequenceTracker{500}.classify(0), SequenceClass::Invalid);
}

TEST(SequenceTracker, ExpectedNumberIsInOrder)
{
  EXPECT_EQ(SequenceTracker{}.classify(1), SequenceClass::InOrder);
  EXPECT_EQ(SequenceTracker{42}.classify(42), SequenceClass::InOrder);
}

TEST(SequenceTracker, InOrderStreamAdvancesByOne)
{
  SequenceTracker tracker;
  for (std::uint32_t seq = 1; seq <= 5; ++seq)
  {
    EXPECT_EQ(tracker.classify(seq), SequenceClass::InOrder) << "seq " << seq;
    tracker.advance_past(seq);
    EXPECT_EQ(tracker.next_expected(), seq + 1);
  }
}

TEST(SequenceTracker, AheadNumberIsAGap)
{
  SequenceTracker tracker{5};
  EXPECT_EQ(tracker.classify(8), SequenceClass::Gap);  // missed 5,6,7
}

TEST(SequenceTracker, BehindNumberIsADuplicate)
{
  SequenceTracker tracker{5};
  EXPECT_EQ(tracker.classify(3), SequenceClass::Duplicate);  // already processed
  EXPECT_EQ(tracker.classify(4), SequenceClass::Duplicate);  // the just-acked one
}

// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=function)
TEST(SequenceTracker, AdvanceWrapsMaxToOneNotZero)
{
  SequenceTracker tracker{max};
  EXPECT_EQ(tracker.classify(max), SequenceClass::InOrder);
  tracker.advance_past(max);
  EXPECT_EQ(tracker.next_expected(), 1u) << "successor of the max sequence number must be 1, not 0";
}

TEST(SequenceTracker, InOrderAcrossTheWrap)
{
  SequenceTracker tracker{max};
  tracker.advance_past(max);  // now expecting 1
  EXPECT_EQ(tracker.classify(1), SequenceClass::InOrder);
  tracker.advance_past(1);
  EXPECT_EQ(tracker.next_expected(), 2u);
}

TEST(SequenceTracker, GapAcrossTheWrapIsAheadNotBehind)
{
  // Expecting max but 1 arrives: max was missed, and 1 is the next-after-wrap - a forward gap.
  SequenceTracker tracker{max};
  EXPECT_EQ(tracker.classify(1), SequenceClass::Gap);
}

TEST(SequenceTracker, OldNumberNearWrapIsDuplicateNotGap)
{
  // Expecting 1, but the old max arrives: it is far behind, a replay - NOT a gap despite max > 1.
  SequenceTracker tracker{1};
  EXPECT_EQ(tracker.classify(max), SequenceClass::Duplicate);
}

// should_deliver gates user dispatch on the classification (CL-SUB-002): only InOrder and Gap deliver;
// Duplicate (a replay the client already processed) and Invalid (seq 0, or the default assigned to an
// unknown/spoofed subscriptionId) must NOT reach user callbacks. Falsifies a delivery site that dispatches
// unconditionally (which double-delivers Duplicates and spoof-delivers Invalids).
TEST(SequenceTracker, ShouldDeliverGatesOnClassification)
{
  EXPECT_TRUE(should_deliver(SequenceClass::InOrder)) << "an in-order message must be delivered";
  EXPECT_TRUE(should_deliver(SequenceClass::Gap))
    << "a gap message's live payload is delivered as today (the in-order refinement is out of scope)";
  EXPECT_FALSE(should_deliver(SequenceClass::Duplicate))
    << "a duplicate (already-processed) message must not double-deliver";
  EXPECT_FALSE(should_deliver(SequenceClass::Invalid))
    << "an invalid (seq 0 / unknown subscription) message must not spoof-deliver";
}

}  // namespace
