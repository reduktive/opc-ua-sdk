// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_KEEP_ALIVE_TRACKER_H
#define UA_KEEP_ALIVE_TRACKER_H

/// @file
/// @brief KeepAlive poll outcome tracking: when to trigger a reconnect / shutdown-defer (section 8.2A.6).
/// @ingroup client

#include <cstddef>

namespace ua::client::detail
{

/// What a KeepAlive poll outcome tells the Connection to do.
enum class KeepAliveAction
{
  /// Nothing - the connection is healthy (or not yet over the miss threshold).
  None,
  /// Consecutive misses reached the threshold - trigger a `KeepAliveMissed` reconnect (CL-RECONN-009).
  TriggerReconnect,
  /// The server reported it is shutting down - trigger a `ServerShutdown` deferred reconnect (CL-SESS-025).
  TriggerShutdown,
};

/// Tracks consecutive KeepAlive poll misses and server-shutdown detection (section 8.2A.6).
///
/// The KeepAliveTimer polls `Server.ServerStatus` on an interval; this tracks the outcome. A successful
/// poll resets the miss counter (and, if the server reports it is shutting down, signals a deferred
/// reconnect). A failed poll increments the counter; the poll that reaches `missedBeforeReconnect`
/// signals a `KeepAliveMissed` reconnect. Pure logic: the timer performs the read; the tracker only
/// decides.
class KeepAliveTracker
{
public:
  /// Constructs a tracker that triggers after @p missedBeforeReconnect consecutive missed polls.
  ///
  /// @param missedBeforeReconnect The consecutive-miss threshold (must be >= 1; 0 is treated as 1).
  explicit KeepAliveTracker(std::size_t missedBeforeReconnect) noexcept;

  /// Records a successful poll. Resets the miss counter.
  ///
  /// @param serverShuttingDown Whether the read's `ServerState` was `Shutdown`.
  /// @return @ref KeepAliveAction::TriggerShutdown if @p serverShuttingDown, else
  ///         @ref KeepAliveAction::None.
  KeepAliveAction on_read_success(bool serverShuttingDown);

  /// Records a failed poll (no response). Increments the miss counter.
  ///
  /// @return @ref KeepAliveAction::TriggerReconnect on the poll that reaches the threshold, else
  ///         @ref KeepAliveAction::None.
  KeepAliveAction on_read_failure();

  /// Returns the current consecutive-miss count.
  ///
  /// @return The number of consecutive missed polls.
  [[nodiscard]] std::size_t consecutive_misses() const noexcept;

private:
  std::size_t mThreshold;
  std::size_t mMisses = 0;
};

}  // namespace ua::client::detail

#endif  // UA_KEEP_ALIVE_TRACKER_H
