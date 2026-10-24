// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The server-wide tally of sampling intervals in use: each Subscription reports the difference in its own
// per-interval counts, and the per-interval diagnostics are reconciled only when the SET of intervals in use
// changes. The generation is what tells them.

#include <gtest/gtest.h>

#include "ua_subscription_router.h"

#include <vector>

using ua::Duration;
using ua::server::SubscriptionRouter;

TEST(SubscriptionRouterIntervals, TheGenerationMovesOnlyWhenAnIntervalComesIntoOrGoesOutOfUse)
{
  SubscriptionRouter router;
  const auto start = router.sampling_intervals_in_use();
  EXPECT_TRUE(start.intervals.empty());

  // Subscription A: two items at 100 ms.
  router.update_sampling_intervals({}, {{100.0, 2}});
  const auto afterA = router.sampling_intervals_in_use();
  EXPECT_EQ(afterA.intervals, (std::vector<Duration>{100.0}));
  EXPECT_NE(afterA.generation, start.generation) << "100 ms came into use";

  // Subscription B: one item at 100 ms and one at 500 ms; then B moves its 500 ms item to 100 ms.
  router.update_sampling_intervals({}, {{100.0, 1}, {500.0, 1}});
  const auto afterB = router.sampling_intervals_in_use();
  EXPECT_EQ(afterB.intervals, (std::vector<Duration>{100.0, 500.0}));
  EXPECT_NE(afterB.generation, afterA.generation);

  router.update_sampling_intervals({{100.0, 1}, {500.0, 1}}, {{100.0, 2}});
  const auto afterModify = router.sampling_intervals_in_use();
  EXPECT_EQ(afterModify.intervals, (std::vector<Duration>{100.0}));
  EXPECT_NE(afterModify.generation, afterB.generation) << "500 ms went out of use";

  // A count changing at an interval still in use leaves the set, and the generation, alone.
  router.update_sampling_intervals({{100.0, 2}}, {{100.0, 5}});
  EXPECT_EQ(router.sampling_intervals_in_use().generation, afterModify.generation);

  // A leaving Subscription takes back exactly what it contributed: 100 ms stays while B still uses it.
  router.update_sampling_intervals({{100.0, 2}}, {});
  const auto afterALeaves = router.sampling_intervals_in_use();
  EXPECT_EQ(afterALeaves.intervals, (std::vector<Duration>{100.0}));
  EXPECT_EQ(afterALeaves.generation, afterModify.generation);

  router.update_sampling_intervals({{100.0, 5}}, {});
  const auto empty = router.sampling_intervals_in_use();
  EXPECT_TRUE(empty.intervals.empty());
  EXPECT_NE(empty.generation, afterALeaves.generation);
}
