// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PENDING_REQUEST_QUEUE_H
#define UA_PENDING_REQUEST_QUEUE_H

/// @file
/// @brief Bounded FIFO of wire calls queued while a Connection reconnects (client tier-1, section 8.2A.5).
/// @ingroup client

#include "ua_status_code.h"

#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <optional>
#include <string>

namespace ua::client::detail
{

/// One tier-1/2 wire call queued while the Connection is not `Active` (section 8.2A.5).
///
/// Exactly one of @ref dispatch (the reconnect reached `Active` - re-run the op) or @ref fail (the op
/// was evicted / aged out / the reconnect failed - complete the user callback with a bad status) is
/// invoked, exactly once, before the entry leaves the queue.
struct PendingRequest
{
  /// Re-runs the wire op against the recovered session (invoked on a successful flush).
  std::function<void()> dispatch;
  /// Completes the owed user callback with @p status (invoked on eviction / age-out / final drain).
  std::function<void(ua::StatusCode)> fail;
  /// When the request was enqueued (for the stale-request age-out).
  std::chrono::steady_clock::time_point enqueuedAt;
  /// A short label identifying the operation (diagnostics).
  std::string operationTag;
};

/// The outcome of an @ref PendingRequestQueue::enqueue, so the caller can raise the right advisory.
enum class EnqueueOutcome
{
  /// Queued below the advisory threshold.
  Queued,
  /// Queued, but the depth is at or above half the limit (raise a ~50%-fill advisory, section 9.6.14.1).
  QueuedNearLimit,
  /// Queued, but the depth exceeded the limit so the oldest entry was evicted (its `fail` was called).
  EvictedOldest,
};

/// A bounded FIFO of @ref PendingRequest, holding wire calls while a Connection reconnects (section 8.2A.5).
///
/// Enqueue is bounded by an optional limit (oldest-evicted when exceeded); flush dispatches fresh
/// entries FIFO and ages out entries older than the configured budget; drain completes every entry
/// with a terminal status. Every entry that leaves the queue has exactly one of its `dispatch` / `fail`
/// callbacks invoked exactly once.
class PendingRequestQueue
{
public:
  /// Constructs an empty queue.
  ///
  /// @param limit  Maximum depth; the oldest entry is evicted when an enqueue would exceed it. Unset =
  ///               unbounded (explicit opt-in).
  /// @param maxAge Stale-request budget: on flush, an entry older than this is aged out rather than
  ///               dispatched.
  PendingRequestQueue(std::optional<std::size_t> limit, std::chrono::steady_clock::duration maxAge);

  /// Appends @p request, evicting the oldest entry if the limit is exceeded.
  ///
  /// @param request The pending request to queue.
  /// @return Whether the depth is below the advisory threshold, at/above ~50%, or forced an eviction.
  EnqueueOutcome enqueue(PendingRequest request);

  /// Drains the entries present now: dispatches each that is within the age budget (FIFO), and ages the
  /// rest out with `Bad_Timeout`. Entries appended during dispatch remain for a later flush.
  ///
  /// @param now The reference time for the age-out comparison.
  void flush(std::chrono::steady_clock::time_point now);

  /// Fails every queued entry with @p status (FIFO) and empties the queue (final-failure drain).
  ///
  /// @param status The terminal status delivered to each owed callback.
  void drain(ua::StatusCode status);

  /// Returns the current depth.
  ///
  /// @return The number of queued entries.
  [[nodiscard]] std::size_t size() const noexcept;

  /// Returns whether the queue is empty.
  ///
  /// @return `true` if there are no queued entries.
  [[nodiscard]] bool empty() const noexcept;

private:
  std::optional<std::size_t> mLimit;
  std::chrono::steady_clock::duration mMaxAge;
  std::deque<PendingRequest> mQueue;
};

}  // namespace ua::client::detail

#endif  // UA_PENDING_REQUEST_QUEUE_H
