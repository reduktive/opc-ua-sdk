// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PUBLISH_PUMP_H
#define UA_PUBLISH_PUMP_H

/// @file
/// @brief Publish pipelining pump for the client SubscriptionsPipeline (section 8.4.4).
/// @ingroup client

#include <cstddef>

namespace ua::client::detail
{

/// Interface the @ref PublishPump issues Publish requests through (implemented by SubscriptionsPipeline).
class PublishPumpHost
{
public:
  PublishPumpHost() = default;
  PublishPumpHost(const PublishPumpHost&) = delete;
  PublishPumpHost& operator=(const PublishPumpHost&) = delete;
  PublishPumpHost(PublishPumpHost&&) = delete;
  PublishPumpHost& operator=(PublishPumpHost&&) = delete;
  virtual ~PublishPumpHost() = default;

  /// Sends one Publish request to the server.
  virtual void issue_publish() = 0;
};

/// The pump's operating state.
enum class PumpState
{
  /// Not pumping (before start / after stop).
  Idle,
  /// Pumping: keeps @ref PublishPump::target requests outstanding.
  Running,
  /// Paused after `Bad_TooManyPublishRequests`; issues nothing until the next response resumes it.
  Paused,
};

/// Keeps a pipeline of Publish requests outstanding for a Connection (single pump per Connection).
///
/// Always-on pipelining (CL-SUB-003): while running it keeps @ref target requests in flight - never
/// one, never waiting for a publishing-interval tick. The target is `max(2, ceil(items / 100))`
/// (CL-SUB-015). On a `Bad_TooManyPublishRequests` service result it transitions to `Paused` and issues
/// nothing; the next response flips it back to `Running` (CL-SUB-004). Pure logic: the host performs the
/// actual async send; the pump only decides how many to keep in flight.
class PublishPump
{
public:
  /// Constructs an `Idle` pump that issues through @p host (borrowed; must outlive the pump).
  ///
  /// @param host The interface Publish requests are issued through.
  explicit PublishPump(PublishPumpHost& host) noexcept;

  /// Starts pumping: `Idle` -> `Running`, and fills to @ref target.
  void start();

  /// Stops pumping: -> `Idle`. No further requests are issued until the next @ref start.
  void stop() noexcept;

  /// Resumes pumping after a reconnect: clears the outstanding count (any in-flight Publishes died with
  /// the dropped channel and will never be answered) and refills to @ref target on the fresh channel.
  ///
  /// Distinct from @ref start: it discards the stale outstanding accounting rather than adding to it, so
  /// a pump left with `outstanding == target` (its requests dropped while the Connection was
  /// reconnecting) is not stuck idle after recovery (CL-RECONN-004).
  void resume();

  /// Sets the total monitored-item count, recomputing @ref target; fills if running.
  ///
  /// @param totalMonitoredItems The Connection-wide monitored-item count.
  void set_monitored_item_count(std::size_t totalMonitoredItems);

  /// Accounts for a received Publish response and maintains the pipeline.
  ///
  /// Consumes one outstanding request; a `Bad_TooManyPublishRequests` service result pauses the pump,
  /// otherwise a paused pump resumes; a running pump then refills to @ref target.
  ///
  /// @param tooManyPublishRequests Whether the response's service result was `Bad_TooManyPublishRequests`.
  void on_publish_response(bool tooManyPublishRequests);

  /// Accounts for a Publish request that failed to send (transport error): consumes one outstanding
  /// request and refills if running. Does not pause.
  void on_publish_failed();

  /// Returns the current state.
  [[nodiscard]] PumpState state() const noexcept;

  /// Returns the number of Publish requests currently outstanding.
  [[nodiscard]] std::size_t outstanding() const noexcept;

  /// Returns the current target outstanding count.
  [[nodiscard]] std::size_t target() const noexcept;

private:
  void fill();

  PublishPumpHost& mHost;
  PumpState mState = PumpState::Idle;
  std::size_t mTarget = 2;
  std::size_t mOutstanding = 0;
};

}  // namespace ua::client::detail

#endif  // UA_PUBLISH_PUMP_H
