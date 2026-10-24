// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_DISPATCH_H
#define UA_CONNECTION_DISPATCH_H

/// @file
/// @brief Wire-op submit gate + reconnect pause/queue coordination (ConnectionImpl core, section 8.2A.5).
/// @ingroup client

#include "ua_logger.h"
#include "ua_pending_request_queue.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace ua::client::detail
{

/// The reconnect-coordination state of a Connection's dispatch gate (a projection of section 8.2A's states).
enum class DispatchState
{
  /// The session is up: wire ops dispatch straight through.
  Active,
  /// A reconnect is in flight: wire ops are queued (or fast-failed, per config) until Active returns.
  Reconnecting,
  /// Reconnect terminally failed: wire ops fail immediately; the queue was drained.
  Failed,
  /// The Connection is closed: wire ops fail immediately; the queue was drained.
  Closed,
};

/// Cross-strand snapshot of the dispatch gate (Rule 4; atomic-loaded by `info`).
struct DispatchInfo
{
  DispatchState state = DispatchState::Active;
  std::size_t pendingCount = 0;
};

/// The wire-op submit gate at the heart of ConnectionImpl (section 8.2A.5): routes each tier-1/2 wire call to
/// immediate dispatch, the reconnect pending-queue, or immediate failure, per the current state, and
/// flushes / drains the queue as the ReconnectionFSM changes state.
///
/// Strand-serialized: every public method posts to the private strand; cross-thread reads use `info`.
/// This is the reconnect-coordination core of ConnectionImpl - session bootstrap, KeepAlive, tier-0
/// dispatch, and FSM hosting layer on top in later slices.
class ConnectionDispatch : public std::enable_shared_from_this<ConnectionDispatch>
{
public:
  /// Creates a dispatch gate in the `Active` state.
  ///
  /// @param executor         The io_context executor for the private strand and callbacks.
  /// @param queueOnReconnect When true, ops submitted during reconnect are queued; when false they
  ///                         fail fast with `Bad_SessionNotActivated`.
  /// @param pendingQueueLimit Optional bound on the pending queue (oldest-evicted when exceeded).
  /// @param maxQueueAge      Stale-request budget for queued ops.
  /// @param logger           Logger for the exception-guarded async boundaries.
  /// @return A shared dispatch gate.
  [[nodiscard]] static std::shared_ptr<ConnectionDispatch> create(boost::asio::any_io_executor executor,
    bool queueOnReconnect, std::optional<std::size_t> pendingQueueLimit,
    std::chrono::steady_clock::duration maxQueueAge, ua::Logger logger);

  ConnectionDispatch(const ConnectionDispatch&) = delete;
  ConnectionDispatch& operator=(const ConnectionDispatch&) = delete;
  ConnectionDispatch(ConnectionDispatch&&) = delete;
  ConnectionDispatch& operator=(ConnectionDispatch&&) = delete;
  ~ConnectionDispatch() = default;

  /// Submits a wire op. Runs `request.dispatch` now (Active), queues it (Reconnecting + queueing), or
  /// completes `request.fail` with the reason the op cannot run (fail-fast / terminal state).
  ///
  /// @param request The wire op (its `dispatch` re-runs it; its `fail` completes the owed callback).
  void submit_async(PendingRequest request) noexcept;

  /// Transitions to `Reconnecting`: subsequent submits queue (or fail fast) until `notify_active_async`.
  void notify_reconnecting_async() noexcept;

  /// Transitions to `Active` and flushes the pending queue (FIFO dispatch; stale entries age out).
  void notify_active_async() noexcept;

  /// Transitions to the terminal `Failed` state and drains the queue with @p terminal.
  ///
  /// @param terminal The terminal status delivered to every queued op.
  void notify_failed_async(ua::StatusCode terminal) noexcept;

  /// Transitions to the terminal `Closed` state, draining the queue with `Bad_ConnectionClosed`.
  ///
  /// @param callback Receives `Good` once closed (on the executor).
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Returns the cross-strand state snapshot (atomic-load; any thread).
  ///
  /// @return The latest published @ref DispatchInfo.
  [[nodiscard]] std::shared_ptr<const DispatchInfo> info() const noexcept;

private:
  ConnectionDispatch(boost::asio::any_io_executor executor, bool queueOnReconnect,
    std::optional<std::size_t> pendingQueueLimit, std::chrono::steady_clock::duration maxQueueAge,
    ua::Logger logger);

  void publish_info();
  void route(PendingRequest request);  // strand: dispatch / queue / fail per mState

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  bool mQueueOnReconnect;

  DispatchState mState = DispatchState::Active;  // strand only
  PendingRequestQueue mQueue;  // strand only
  std::atomic<std::shared_ptr<const DispatchInfo>> mInfoSnapshot;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_DISPATCH_H
