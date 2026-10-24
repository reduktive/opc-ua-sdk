// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_open_continuation_point_tracker.h"

#include <utility>

namespace ua::client::detail
{

OpenContinuationPointTracker::OpenContinuationPointTracker(std::size_t queueLimit) : mQueueLimit(queueLimit)
{}

OpenContinuationPointTracker::AcquireResult OpenContinuationPointTracker::acquire(Admission admission)
{
  if (!has_capacity())
  {
    if (mQueued.size() >= mQueueLimit)
    {
      return AcquireResult::QueueFull;
    }
    mQueued.push_back(std::move(admission));
    return AcquireResult::Queued;
  }
  ++mInFlight;
  admission(true);
  return AcquireResult::Granted;
}

void OpenContinuationPointTracker::complete_initial(std::size_t openedContinuationPoints)
{
  if (mInFlight != 0)
  {
    --mInFlight;
  }
  mOpen += openedContinuationPoints;
  drain();
}

void OpenContinuationPointTracker::replace(
  std::size_t consumedContinuationPoints, std::size_t openedContinuationPoints)
{
  mOpen = consumedContinuationPoints >= mOpen ? 0 : mOpen - consumedContinuationPoints;
  mOpen += openedContinuationPoints;
  drain();
}

void OpenContinuationPointTracker::set_limit(std::uint16_t limit)
{
  mLimit = limit;
  drain();
}

void OpenContinuationPointTracker::reset(std::uint16_t limit)
{
  mLimit = limit;
  mOpen = 0;
  mInFlight = 0;
  drain();
}

void OpenContinuationPointTracker::cancel_all()
{
  auto queued = std::exchange(mQueued, {});
  for (const auto& admission : queued)
  {
    admission(false);
  }
}

std::uint16_t OpenContinuationPointTracker::limit() const noexcept
{
  return mLimit;
}

std::size_t OpenContinuationPointTracker::open_count() const noexcept
{
  return mOpen;
}

std::size_t OpenContinuationPointTracker::in_flight_count() const noexcept
{
  return mInFlight;
}

std::size_t OpenContinuationPointTracker::queued_count() const noexcept
{
  return mQueued.size();
}

bool OpenContinuationPointTracker::has_capacity() const noexcept
{
  return mLimit == 0 || mOpen + mInFlight < mLimit;
}

void OpenContinuationPointTracker::drain()
{
  while (!mQueued.empty() && has_capacity())
  {
    auto admission = std::move(mQueued.front());
    mQueued.pop_front();
    ++mInFlight;
    admission(true);
  }
}

}  // namespace ua::client::detail
