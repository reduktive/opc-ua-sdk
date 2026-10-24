// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::AckQueue (CL-SUB-006 / CL-SUB-007) - Publish-acknowledgement
// batching across Subscriptions + the sticky-false retransmission-support latch.
//
// Falsifiability: a stub that never queues fails BatchesAcksAcrossSubscriptions; one that never latches
// fails FirstEmptyAvailableLatchesUnsupported; one that re-evaluates fails StickyFalseNeverFlipsBack.
//
// @verifies CL-SUB-006, CL-SUB-007
// @relation(CL-SUB-006, CL-SUB-007, scope=file)

#include "ua_ack_queue.h"

#include <gtest/gtest.h>

#include <vector>

namespace
{

using ua::client::detail::AckQueue;
using ua::client::detail::SubscriptionAcknowledgement;

TEST(AckQueue, BatchesAcksAcrossSubscriptionsThenDrains)
{
  AckQueue queue;
  queue.acknowledge(/*sub=*/1, /*seq=*/5, /*available=*/true);
  queue.acknowledge(/*sub=*/2, /*seq=*/3, /*available=*/true);
  EXPECT_EQ(queue.pending(), 2u);

  const auto acks = queue.drain();
  ASSERT_EQ(acks.size(), 2u);
  EXPECT_EQ(acks[0].subscriptionId, 1u);
  EXPECT_EQ(acks[0].sequenceNumber, 5u);
  EXPECT_EQ(acks[1].subscriptionId, 2u);
  EXPECT_EQ(acks[1].sequenceNumber, 3u);

  EXPECT_TRUE(queue.drain().empty()) << "drain empties the batch";
}

// @verifies CL-SUB-007
// @relation(CL-SUB-007, scope=function)
TEST(AckQueue, FirstEmptyAvailableLatchesUnsupportedAndSuppressesAck)
{
  AckQueue queue;
  queue.acknowledge(/*sub=*/7, /*seq=*/5, /*available=*/false);  // first response, empty available
  EXPECT_FALSE(queue.retransmission_supported(7));
  EXPECT_TRUE(queue.drain().empty()) << "acks are suppressed for a no-retransmission-queue Subscription";
}

TEST(AckQueue, FirstNonEmptyAvailableIsSupported)
{
  AckQueue queue;
  queue.acknowledge(/*sub=*/7, /*seq=*/5, /*available=*/true);
  EXPECT_TRUE(queue.retransmission_supported(7));
  EXPECT_EQ(queue.pending(), 1u);
}

TEST(AckQueue, StickyFalseNeverFlipsBack)
{
  AckQueue queue;
  queue.acknowledge(/*sub=*/7, /*seq=*/5, /*available=*/false);  // latch unsupported
  queue.acknowledge(/*sub=*/7, /*seq=*/6, /*available=*/true);  // a later non-empty response
  EXPECT_FALSE(queue.retransmission_supported(7)) << "the unsupported latch never flips back";
  EXPECT_TRUE(queue.drain().empty()) << "acks stay suppressed";
}

TEST(AckQueue, UndecidedSubscriptionReportsSupported)
{
  AckQueue queue;
  EXPECT_TRUE(queue.retransmission_supported(99)) << "an unseen Subscription is optimistically supported";
}

// @verifies CL-SUB-008
// @relation(CL-SUB-008, scope=function)
TEST(AckQueue, RemoveSubscriptionPurgesOnlyItsQueuedAndLatchedState)
{
  AckQueue queue;
  queue.acknowledge(/*sub=*/7, /*seq=*/5, /*available=*/true);
  queue.acknowledge(/*sub=*/8, /*seq=*/3, /*available=*/true);

  queue.remove_subscription(7);

  EXPECT_TRUE(queue.retransmission_supported(7)) << "the terminated Subscription's sticky state is released";
  const auto remaining = queue.drain();
  ASSERT_EQ(remaining.size(), 1u);
  EXPECT_EQ(remaining.front().subscriptionId, 8u);
}

}  // namespace
