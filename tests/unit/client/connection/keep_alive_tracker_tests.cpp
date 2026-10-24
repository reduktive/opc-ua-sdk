// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::KeepAliveTracker (section 8.2A.6, CL-RECONN-009 / CL-SESS-025) -
// deciding when a KeepAlive poll outcome should trigger a reconnect (consecutive misses) or a shutdown-defer.
//
// Falsifiability: a stub that never acts fails FailureAtThresholdTriggersReconnect; one that never
// resets fails SuccessResetsMissCounter; one that ignores shutdown fails ShutdownTriggersDefer.
//
// @verifies CL-RECONN-009, CL-SESS-025
// @relation(CL-RECONN-009, CL-SESS-025, scope=file)

#include "ua_keep_alive_tracker.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::detail::KeepAliveAction;
using ua::client::detail::KeepAliveTracker;

TEST(KeepAliveTracker, FailuresBelowThresholdReturnNone)
{
  KeepAliveTracker tracker{3};
  EXPECT_EQ(tracker.on_read_failure(), KeepAliveAction::None);
  EXPECT_EQ(tracker.on_read_failure(), KeepAliveAction::None);
  EXPECT_EQ(tracker.consecutive_misses(), 2u);
}

TEST(KeepAliveTracker, FailureAtThresholdTriggersReconnect)
{
  KeepAliveTracker tracker{3};
  tracker.on_read_failure();
  tracker.on_read_failure();
  EXPECT_EQ(tracker.on_read_failure(), KeepAliveAction::TriggerReconnect);
}

TEST(KeepAliveTracker, SuccessResetsMissCounter)
{
  KeepAliveTracker tracker{3};
  tracker.on_read_failure();
  tracker.on_read_failure();
  EXPECT_EQ(tracker.on_read_success(/*shuttingDown=*/false), KeepAliveAction::None);
  EXPECT_EQ(tracker.consecutive_misses(), 0u);
  EXPECT_EQ(tracker.on_read_failure(), KeepAliveAction::None) << "the counter restarts after a success";
}

TEST(KeepAliveTracker, SuccessWithShutdownTriggersDefer)
{
  KeepAliveTracker tracker{3};
  EXPECT_EQ(tracker.on_read_success(/*shuttingDown=*/true), KeepAliveAction::TriggerShutdown);
}

TEST(KeepAliveTracker, ZeroThresholdIsTreatedAsOne)
{
  KeepAliveTracker tracker{0};
  EXPECT_EQ(tracker.on_read_failure(), KeepAliveAction::TriggerReconnect);
}

}  // namespace
