// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::PendingRequestQueue (section 8.2A.5) - the bounded FIFO of wire calls
// queued while a Connection reconnects. Contract: FIFO dispatch on flush, age-out of stale entries,
// oldest-evicted over the limit, fail-all on drain, and exactly-once completion (dispatch XOR fail).
//
// Falsifiability: a stub that never dispatches fails the flush-order test; one that never evicts fails
// the limit test; one that double-fires would show both a dispatch and a fail for the same tag.

#include "ua_pending_request_queue.h"

#include "ua_status.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using ua::client::detail::EnqueueOutcome;
using ua::client::detail::PendingRequest;
using ua::client::detail::PendingRequestQueue;

// A recorder shared across a test's requests; each request logs its dispatch or fail exactly once.
struct Recorder
{
  std::vector<std::string> log;

  PendingRequest make(std::string tag, std::chrono::steady_clock::time_point at)
  {
    PendingRequest request;
    request.dispatch = [this, tag]
    {
      log.push_back("dispatch:" + tag);
    };
    request.fail = [this, tag](ua::StatusCode status)
    {
      log.push_back("fail:" + tag + ":" + std::to_string(status.value()));
    };
    request.enqueuedAt = at;
    request.operationTag = tag;
    return request;
  }
};

const auto now = std::chrono::steady_clock::now();

TEST(PendingRequestQueue, EnqueueGrowsSize)
{
  Recorder rec;
  PendingRequestQueue queue{std::nullopt, 30s};
  EXPECT_TRUE(queue.empty());
  queue.enqueue(rec.make("a", now));
  queue.enqueue(rec.make("b", now));
  EXPECT_EQ(queue.size(), 2u);
  EXPECT_FALSE(queue.empty());
}

TEST(PendingRequestQueue, FlushDispatchesInFifoOrderAndEmpties)
{
  Recorder rec;
  PendingRequestQueue queue{std::nullopt, 30s};
  queue.enqueue(rec.make("a", now));
  queue.enqueue(rec.make("b", now));
  queue.enqueue(rec.make("c", now));

  queue.flush(now);

  EXPECT_EQ(rec.log, (std::vector<std::string>{"dispatch:a", "dispatch:b", "dispatch:c"}));
  EXPECT_TRUE(queue.empty());
}

TEST(PendingRequestQueue, FlushAgesOutStaleEntriesInsteadOfDispatching)
{
  Recorder rec;
  PendingRequestQueue queue{std::nullopt, 30s};
  queue.enqueue(rec.make("old", now - 60s));  // older than the 30s budget
  queue.enqueue(rec.make("fresh", now));

  queue.flush(now);

  ASSERT_EQ(rec.log.size(), 2u);
  EXPECT_EQ(rec.log[0], "fail:old:" + std::to_string(static_cast<uint32_t>(ua::Status::BadTimeout)));
  EXPECT_EQ(rec.log[1], "dispatch:fresh");
  EXPECT_TRUE(queue.empty());
}

TEST(PendingRequestQueue, DrainFailsEveryEntryInFifoOrder)
{
  Recorder rec;
  PendingRequestQueue queue{std::nullopt, 30s};
  queue.enqueue(rec.make("a", now));
  queue.enqueue(rec.make("b", now));

  queue.drain(ua::Status::BadConnectionClosed);

  const auto code = std::to_string(static_cast<uint32_t>(ua::Status::BadConnectionClosed));
  EXPECT_EQ(rec.log, (std::vector<std::string>{"fail:a:" + code, "fail:b:" + code}));
  EXPECT_TRUE(queue.empty());
}

TEST(PendingRequestQueue, EnqueueEvictsOldestWhenOverLimit)
{
  Recorder rec;
  PendingRequestQueue queue{/*limit=*/2, 30s};
  queue.enqueue(rec.make("a", now));
  queue.enqueue(rec.make("b", now));
  const auto third = queue.enqueue(rec.make("c", now));  // depth would be 3 > limit 2

  EXPECT_EQ(third, EnqueueOutcome::EvictedOldest);
  EXPECT_EQ(queue.size(), 2u);
  // The oldest (a) was evicted with Bad_ResourceUnavailable; b and c remain (dispatch on flush).
  ASSERT_EQ(rec.log.size(), 1u);
  EXPECT_EQ(
    rec.log[0], "fail:a:" + std::to_string(static_cast<uint32_t>(ua::Status::BadResourceUnavailable)));
}

TEST(PendingRequestQueue, EnqueueFlagsNearLimitAtHalfDepth)
{
  Recorder rec;
  PendingRequestQueue queue{/*limit=*/4, 30s};
  EXPECT_EQ(queue.enqueue(rec.make("a", now)), EnqueueOutcome::Queued);  // depth 1 (< 50%)
  EXPECT_EQ(queue.enqueue(rec.make("b", now)), EnqueueOutcome::QueuedNearLimit);  // depth 2 (== 50%)
}

TEST(PendingRequestQueue, CompletionIsExactlyOnce)
{
  Recorder rec;
  PendingRequestQueue queue{std::nullopt, 30s};
  queue.enqueue(rec.make("a", now));
  queue.flush(now);
  queue.drain(ua::Status::BadConnectionClosed);  // a already dispatched - must not fire again

  EXPECT_EQ(rec.log, (std::vector<std::string>{"dispatch:a"}));
}

}  // namespace
