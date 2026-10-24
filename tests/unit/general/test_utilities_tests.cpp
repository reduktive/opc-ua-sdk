// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

TEST(TestUtilities, CoverageBuildRetainsAFiniteExtendedPoolDrainWatchdog)
{
#if defined(UASDK_TSAN_INSTRUMENTED_TESTS)
  EXPECT_EQ(ua::test_utils::default_pool_drain_timeout(), std::chrono::seconds{45});
#elif defined(UASDK_COVERAGE_INSTRUMENTED_TESTS) || defined(UASDK_ASAN_INSTRUMENTED_TESTS)
  EXPECT_EQ(ua::test_utils::default_pool_drain_timeout(), std::chrono::seconds{15});
#else
  EXPECT_EQ(ua::test_utils::default_pool_drain_timeout(), std::chrono::seconds{5});
#endif
}

// The poll budget bounds a hang; it does not assert a latency. Instrumented builds therefore get a longer
// budget, but it stays finite so a genuinely-never-happens predicate still fails instead of hanging.
TEST(TestUtilities, InstrumentedBuildRetainsAFiniteExtendedPollBudget)
{
#if defined(UASDK_COVERAGE_INSTRUMENTED_TESTS) || defined(UASDK_TSAN_INSTRUMENTED_TESTS) || \
  defined(UASDK_ASAN_INSTRUMENTED_TESTS)
  EXPECT_EQ(ua::test_utils::default_poll_budget(), std::chrono::milliseconds{20000});
#else
  EXPECT_EQ(ua::test_utils::default_poll_budget(), std::chrono::milliseconds{5000});
#endif
}
