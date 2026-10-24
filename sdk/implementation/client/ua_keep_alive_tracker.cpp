// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_keep_alive_tracker.h"

#include <algorithm>

namespace ua::client::detail
{

KeepAliveTracker::KeepAliveTracker(std::size_t missedBeforeReconnect) noexcept
  : mThreshold(std::max<std::size_t>(1, missedBeforeReconnect))
{}

KeepAliveAction KeepAliveTracker::on_read_success(bool serverShuttingDown)
{
  mMisses = 0;  // a healthy poll clears the miss streak
  return serverShuttingDown ? KeepAliveAction::TriggerShutdown : KeepAliveAction::None;
}

KeepAliveAction KeepAliveTracker::on_read_failure()
{
  ++mMisses;
  // Trigger exactly on the poll that reaches the threshold; the KeepAliveTimer is disarmed for the
  // reconnect that follows, so no later failure re-triggers.
  return (mMisses == mThreshold) ? KeepAliveAction::TriggerReconnect : KeepAliveAction::None;
}

std::size_t KeepAliveTracker::consecutive_misses() const noexcept
{
  return mMisses;
}

}  // namespace ua::client::detail
