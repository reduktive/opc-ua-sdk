// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_pending_request_queue.h"

#include "ua_status.h"

#include <deque>
#include <utility>

namespace ua::client::detail
{

PendingRequestQueue::PendingRequestQueue(
  std::optional<std::size_t> limit, std::chrono::steady_clock::duration maxAge)
  : mLimit(limit), mMaxAge(maxAge)
{}

EnqueueOutcome PendingRequestQueue::enqueue(PendingRequest request)
{
  mQueue.push_back(std::move(request));

  if (mLimit && mQueue.size() > *mLimit)
  {
    // Over the limit: evict the oldest (front) and complete its owed callback so nothing is dropped
    // silently. The chain's cause is carried by the fail lambda (CL-DIAG-001).
    PendingRequest oldest = std::move(mQueue.front());
    mQueue.pop_front();
    if (oldest.fail)
    {
      oldest.fail(ua::Status::BadResourceUnavailable);
    }
    return EnqueueOutcome::EvictedOldest;
  }

  // Advisory at ~50% fill (size * 2 >= limit), so the caller can warn before the queue saturates.
  if (mLimit && mQueue.size() * 2 >= *mLimit)
  {
    return EnqueueOutcome::QueuedNearLimit;
  }
  return EnqueueOutcome::Queued;
}

void PendingRequestQueue::flush(std::chrono::steady_clock::time_point now)
{
  // Take the entries present now; anything a dispatch re-enqueues lands in the freshly-empty mQueue and
  // is left for a later flush ("items added during drain land at the tail", section 8.2A.5).
  std::deque<PendingRequest> batch;
  batch.swap(mQueue);
  for (auto& entry : batch)
  {
    if (now - entry.enqueuedAt > mMaxAge)
    {
      if (entry.fail)
      {
        entry.fail(ua::Status::BadTimeout);  // stale-request budget exceeded (section 8.2A.5)
      }
    }
    else if (entry.dispatch)
    {
      entry.dispatch();
    }
  }
}

void PendingRequestQueue::drain(ua::StatusCode status)
{
  std::deque<PendingRequest> batch;
  batch.swap(mQueue);
  for (auto& entry : batch)
  {
    if (entry.fail)
    {
      entry.fail(status);
    }
  }
}

std::size_t PendingRequestQueue::size() const noexcept
{
  return mQueue.size();
}

bool PendingRequestQueue::empty() const noexcept
{
  return mQueue.empty();
}

}  // namespace ua::client::detail
