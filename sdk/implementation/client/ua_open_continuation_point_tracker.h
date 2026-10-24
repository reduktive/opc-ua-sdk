// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OPEN_CONTINUATION_POINT_TRACKER_H
#define UA_OPEN_CONTINUATION_POINT_TRACKER_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>

namespace ua::client::detail
{

/// Strand-confined admission/accounting leaf for one family of per-Session continuation points.
///
/// The owner calls every method on its private strand. A callback receives `true` when its initial
/// service call may be issued and `false` when terminal cancellation rejects the queued call.
class OpenContinuationPointTracker final
{
public:
  enum class AcquireResult
  {
    Granted,
    Queued,
    QueueFull
  };

  using Admission = std::function<void(bool granted)>;

  explicit OpenContinuationPointTracker(std::size_t queueLimit = 1024);

  [[nodiscard]] AcquireResult acquire(Admission admission);
  void complete_initial(std::size_t openedContinuationPoints);
  void replace(std::size_t consumedContinuationPoints, std::size_t openedContinuationPoints);
  void set_limit(std::uint16_t limit);
  void reset(std::uint16_t limit);
  void cancel_all();

  [[nodiscard]] std::uint16_t limit() const noexcept;
  [[nodiscard]] std::size_t open_count() const noexcept;
  [[nodiscard]] std::size_t in_flight_count() const noexcept;
  [[nodiscard]] std::size_t queued_count() const noexcept;

private:
  [[nodiscard]] bool has_capacity() const noexcept;
  void drain();

  std::uint16_t mLimit = 0;
  std::size_t mOpen = 0;
  std::size_t mInFlight = 0;
  std::size_t mQueueLimit;
  std::deque<Admission> mQueued;
};

}  // namespace ua::client::detail

#endif  // UA_OPEN_CONTINUATION_POINT_TRACKER_H
