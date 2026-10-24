// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Lock-free per-service request latency statistics for the server. Private to the implementation
// (public API review D3, API-D3.3); ServerHealthSnapshot::latency publishes them by name.

#ifndef UA_REQUEST_LATENCY_TRACKER_H
#define UA_REQUEST_LATENCY_TRACKER_H

#include "ua_service_kind.h"
#include "ua_utilities.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace ua::server
{

/// Lightweight per-service request latency tracker using an exponential moving average.
///
/// Holds one independent statistics @ref Entry per @ref ServiceKind, sized from the enum, so every
/// service has a slot (API-D3.2). Latencies are recorded at service completion with relaxed atomics, so
/// reads and writes are lock-free and may race freely across threads; the published averages are
/// eventually-consistent observability figures, not exact measurements.
struct RequestLatencyTracker
{

  /// Lock-free latency statistics for a single service kind.
  ///
  /// All members are relaxed atomics: concurrent @ref record calls may interleave and produce
  /// slightly skewed averages, which is acceptable for observability. All durations are in
  /// microseconds.
  struct Entry
  {
    std::atomic<uint64_t> averageUs{0};  ///< Exponential moving average latency, in microseconds.
    std::atomic<uint64_t> maxUs{0};  ///< High-watermark latency, in microseconds; cleared by @ref reset.
    std::atomic<uint32_t> sampleCount{0};  ///< Number of samples recorded, used to seed the initial ramp-up.

    /// Folds one latency sample into the running statistics.
    ///
    /// Updates the moving average (alpha = 1/8), bumps the high watermark if exceeded, and
    /// increments the sample count, all with relaxed atomics. Safe to call concurrently from
    /// any thread; concurrent callers may interleave without external synchronization.
    ///
    /// @param duration Measured request latency for this service kind.
    void record(std::chrono::microseconds duration)
    {
      const auto us = numeric_cast<uint64_t>(duration.count());
      sampleCount.fetch_add(1, std::memory_order_relaxed);

      // Update EMA: alpha = 1/8 for fast convergence.
      auto current = averageUs.load(std::memory_order_relaxed);
      if (current == 0)
      {
        averageUs.store(us, std::memory_order_relaxed);
      }
      else
      {
        // EMA = current + (sample - current) / 8
        const auto newAvg =
          current + (us > current ? (us - current) / 8 : 0) - (us < current ? (current - us) / 8 : 0);
        averageUs.store(newAvg, std::memory_order_relaxed);
      }

      // Update high watermark (relaxed CAS loop).
      auto prevMax = maxUs.load(std::memory_order_relaxed);
      while (us > prevMax && !maxUs.compare_exchange_weak(prevMax, us, std::memory_order_relaxed))
      {
      }
    }

    /// Clears the average, high watermark, and sample count back to zero.
    ///
    /// Stores are relaxed and individually atomic but not applied as a single transaction, so a
    /// concurrent @ref record may observe a partially reset entry.
    void reset()
    {
      averageUs.store(0, std::memory_order_relaxed);
      maxUs.store(0, std::memory_order_relaxed);
      sampleCount.store(0, std::memory_order_relaxed);
    }
  };

  /// Per-service statistics, one per service, indexed by the service's enumerator.
  std::array<Entry, serviceKindCount> byService{};

  /// The statistics of @p kind.
  /// @param kind A service; not `Unknown`.
  /// @return Its entry.
  [[nodiscard]] const Entry& entry(ServiceKind kind) const
  {
    return byService.at(static_cast<std::size_t>(utils::to_underlying(kind)));
  }

  /// Records a latency sample for @p kind. A request of no known type (`Unknown`) has no slot and is not a
  /// service, so it is not recorded. Lock-free and safe to call concurrently from any thread.
  ///
  /// @param kind     The service the request was for.
  /// @param duration Measured request latency.
  void record(ServiceKind kind, std::chrono::microseconds duration)
  {
    if (kind == ServiceKind::Unknown)
    {
      return;
    }
    byService[static_cast<std::size_t>(utils::to_underlying(kind))].record(duration);
  }

  /// Resets the statistics of every service-kind slot to zero.
  ///
  /// Resets each @ref Entry independently; not atomic across slots, so a concurrent @ref record
  /// may land in an already-reset or not-yet-reset entry.
  void reset()
  {
    for (auto& e : byService)
    {
      e.reset();
    }
  }
};

}  // namespace ua::server

#endif  // UA_REQUEST_LATENCY_TRACKER_H
