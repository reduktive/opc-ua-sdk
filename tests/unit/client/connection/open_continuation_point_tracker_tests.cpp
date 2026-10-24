// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_open_continuation_point_tracker.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace
{

using Tracker = ua::client::detail::OpenContinuationPointTracker;

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST(OpenContinuationPointTracker, CapQueuesAndReleasesInFifoOrder)
{
  Tracker tracker;
  tracker.set_limit(2);
  std::vector<std::string> events;

  EXPECT_EQ(tracker.acquire([&](bool granted) { events.push_back(granted ? "first" : "cancel-first"); }),
    Tracker::AcquireResult::Granted);
  tracker.complete_initial(1);
  EXPECT_EQ(tracker.acquire([&](bool granted) { events.push_back(granted ? "second" : "cancel-second"); }),
    Tracker::AcquireResult::Granted);
  tracker.complete_initial(1);
  EXPECT_EQ(tracker.acquire([&](bool granted) { events.push_back(granted ? "third" : "cancel-third"); }),
    Tracker::AcquireResult::Queued);
  EXPECT_EQ(tracker.acquire([&](bool granted) { events.push_back(granted ? "fourth" : "cancel-fourth"); }),
    Tracker::AcquireResult::Queued);

  EXPECT_EQ(events, (std::vector<std::string>{"first", "second"}));
  EXPECT_EQ(tracker.open_count(), 2u);
  EXPECT_EQ(tracker.queued_count(), 2u);

  tracker.replace(1, 0);
  EXPECT_EQ(events, (std::vector<std::string>{"first", "second", "third"}));
  tracker.complete_initial(0);
  EXPECT_EQ(events, (std::vector<std::string>{"first", "second", "third", "fourth"}));
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST(OpenContinuationPointTracker, ZeroLimitIsUnlimited)
{
  Tracker tracker;
  tracker.set_limit(0);
  std::size_t granted = 0;
  for (int index = 0; index < 20; ++index)
  {
    EXPECT_EQ(
      tracker.acquire([&](bool permit) { granted += permit ? 1u : 0u; }), Tracker::AcquireResult::Granted);
  }
  EXPECT_EQ(granted, 20u);
  EXPECT_EQ(tracker.in_flight_count(), 20u);
  EXPECT_EQ(tracker.queued_count(), 0u);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST(OpenContinuationPointTracker, ReplacementConsumesOldAndTracksNewPoint)
{
  Tracker tracker;
  tracker.set_limit(1);
  bool first = false;
  bool second = false;
  EXPECT_EQ(tracker.acquire([&](bool granted) { first = granted; }), Tracker::AcquireResult::Granted);
  tracker.complete_initial(1);
  EXPECT_EQ(tracker.acquire([&](bool granted) { second = granted; }), Tracker::AcquireResult::Queued);

  tracker.replace(1, 1);
  EXPECT_TRUE(first);
  EXPECT_FALSE(second) << "a replacement point still occupies the single slot";
  EXPECT_EQ(tracker.open_count(), 1u);

  tracker.replace(1, 0);
  EXPECT_TRUE(second);
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST(OpenContinuationPointTracker, RefreshAndFreshSessionResetDrainWhenCapacityAllows)
{
  Tracker tracker;
  tracker.set_limit(1);
  int grants = 0;
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { grants += granted ? 1 : 0; }), Tracker::AcquireResult::Granted);
  tracker.complete_initial(1);
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { grants += granted ? 1 : 0; }), Tracker::AcquireResult::Queued);

  tracker.set_limit(2);
  EXPECT_EQ(grants, 2) << "raising the advertised limit admits queued work";
  tracker.complete_initial(1);
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { grants += granted ? 1 : 0; }), Tracker::AcquireResult::Queued);
  tracker.reset(1);
  EXPECT_EQ(grants, 3) << "a fresh Session invalidates old points and admits the oldest waiter";
}

// @verifies CL-BASE-004
// @relation(CL-BASE-004, scope=function)
TEST(OpenContinuationPointTracker, QueueIsBoundedAndCancellationCompletesEveryWaiter)
{
  Tracker tracker{2};
  tracker.set_limit(1);
  std::vector<bool> outcomes;
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { outcomes.push_back(granted); }), Tracker::AcquireResult::Granted);
  tracker.complete_initial(1);
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { outcomes.push_back(granted); }), Tracker::AcquireResult::Queued);
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { outcomes.push_back(granted); }), Tracker::AcquireResult::Queued);
  EXPECT_EQ(
    tracker.acquire([&](bool granted) { outcomes.push_back(granted); }), Tracker::AcquireResult::QueueFull);

  tracker.cancel_all();
  ASSERT_EQ(outcomes.size(), 3u);
  EXPECT_TRUE(outcomes[0]);
  EXPECT_FALSE(outcomes[1]);
  EXPECT_FALSE(outcomes[2]);
  EXPECT_EQ(tracker.queued_count(), 0u);
}

}  // namespace
