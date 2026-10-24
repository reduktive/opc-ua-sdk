// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::BackoffPolicy::next (section 7.7 / section 8.3.4) - the reconnect backoff
// schedule. Contract: next(attempt) = clamp(base * factor^(attempt-1), base, max) scaled by +/-jitterPct.
//
// The required correctness property is SATURATION: with maxAttempts unset the attempt index is
// unbounded, and computing base_ms * factor^(attempt-1) as a raw power overflows int64 ms around
// attempt 54 and collapses the delay into a reconnect storm. next() must clamp to max as it scales.
//
// Falsifiability: a stub returning base fails DoublesUntilCap; an impl that computes the raw power
// first overflows and fails SaturatesAtMaxForHighAttempts (the delay would drop far below max); an
// impl that drops jitter fails JitterVariesAcrossCalls; one that mis-clamps fails NeverBelowBase.

#include "ua_reconnect_policy.h"

#include <gtest/gtest.h>

#include <chrono>
#include <set>

namespace
{

using namespace std::chrono_literals;
using ua::client::BackoffPolicy;

// A deterministic schedule (no jitter) so exact delays can be asserted.
BackoffPolicy deterministic()
{
  BackoffPolicy policy;
  policy.base = 1s;
  policy.max = 60s;
  policy.factor = 2.0;
  policy.jitterPct = 0.0;
  return policy;
}

TEST(BackoffPolicyNext, FirstAttemptIsBase)
{
  EXPECT_EQ(deterministic().next(1), 1000ms);
}

TEST(BackoffPolicyNext, AttemptZeroTreatedAsFirstAttempt)
{
  EXPECT_EQ(deterministic().next(0), 1000ms);
}

TEST(BackoffPolicyNext, DoublesEachAttemptUntilCap)
{
  auto policy = deterministic();
  EXPECT_EQ(policy.next(1), 1000ms);
  EXPECT_EQ(policy.next(2), 2000ms);
  EXPECT_EQ(policy.next(3), 4000ms);
  EXPECT_EQ(policy.next(4), 8000ms);
  EXPECT_EQ(policy.next(5), 16000ms);
  EXPECT_EQ(policy.next(6), 32000ms);
  EXPECT_EQ(policy.next(7), 60000ms);  // 64s clamped to the 60s ceiling
}

// The critical overflow guard: high attempt indices must saturate at max, never wrap into a storm.
TEST(BackoffPolicyNext, SaturatesAtMaxForHighAttempts)
{
  auto policy = deterministic();
  EXPECT_EQ(policy.next(54), 60000ms);
  EXPECT_EQ(policy.next(100), 60000ms);
  EXPECT_EQ(policy.next(1000), 60000ms);
  EXPECT_EQ(policy.next(100000), 60000ms);
}

TEST(BackoffPolicyNext, HonoursCustomFactor)
{
  auto policy = deterministic();
  policy.factor = 3.0;
  policy.max = 1000s;  // raise ceiling so the factor is visible
  EXPECT_EQ(policy.next(1), 1000ms);
  EXPECT_EQ(policy.next(2), 3000ms);
  EXPECT_EQ(policy.next(3), 9000ms);
}

// Defensive: a degenerate non-growing config (factor <= 1) must give a constant base delay and must
// NOT run an O(attempt) loop for a huge attempt index.
TEST(BackoffPolicyNext, FactorOfOneGivesConstantBaseAndBoundedWork)
{
  auto policy = deterministic();
  policy.factor = 1.0;
  EXPECT_EQ(policy.next(1), 1000ms);
  EXPECT_EQ(policy.next(10), 1000ms);
  EXPECT_EQ(policy.next(100000), 1000ms);
}

TEST(BackoffPolicyNext, JitterStaysWithinBounds)
{
  BackoffPolicy policy;
  policy.base = 1s;
  policy.max = 60s;
  policy.factor = 2.0;
  policy.jitterPct = 0.25;
  // Nominal for attempt 3 is 4000ms; jitter of +/-25% keeps it within [3000, 5000].
  for (int i = 0; i < 500; ++i)
  {
    const auto delay = policy.next(3);
    EXPECT_GE(delay, 3000ms) << "jittered delay fell below nominal*(1-jitterPct)";
    EXPECT_LE(delay, 5000ms) << "jittered delay rose above nominal*(1+jitterPct)";
  }
}

TEST(BackoffPolicyNext, JitterVariesAcrossCalls)
{
  BackoffPolicy policy;
  policy.jitterPct = 0.25;
  std::set<std::chrono::milliseconds::rep> seen;
  for (int i = 0; i < 100; ++i)
  {
    seen.insert(policy.next(3).count());
  }
  EXPECT_GT(seen.size(), 1u) << "jitter must produce varying delays, not a fixed value";
}

TEST(BackoffPolicyNext, NeverBelowBaseWithNegativeJitterHeadroom)
{
  // With base==max, the nominal is pinned at base; jitter must not drive the delay to zero/negative.
  BackoffPolicy policy;
  policy.base = 1s;
  policy.max = 1s;
  policy.jitterPct = 0.25;
  for (int i = 0; i < 500; ++i)
  {
    const auto delay = policy.next(10);
    EXPECT_GE(delay, 750ms);  // 1000ms * (1 - 0.25)
    EXPECT_LE(delay, 1250ms);  // 1000ms * (1 + 0.25)
  }
}

}  // namespace
