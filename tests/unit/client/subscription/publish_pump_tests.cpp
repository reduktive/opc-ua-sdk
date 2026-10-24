// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::PublishPump (section 8.4.4) - the client Publish pipelining pump.
// Contract: keep target = max(2, ceil(items/100)) requests outstanding while Running (CL-SUB-003,
// CL-SUB-015); pause on Bad_TooManyPublishRequests and resume on the next response (CL-SUB-004).
//
// Falsifiability: a stub that never issues fails StartFillsToTarget; one that never pauses fails
// PauseOnTooManyPublishRequests; one that ignores item count fails TargetTracksMonitoredItemCount.
//
// @verifies CL-SUB-003, CL-SUB-004, CL-SUB-015
// @relation(CL-SUB-003, CL-SUB-004, CL-SUB-015, scope=file)

#include "ua_publish_pump.h"

#include <gtest/gtest.h>

namespace
{

using ua::client::detail::PublishPump;
using ua::client::detail::PublishPumpHost;
using ua::client::detail::PumpState;

struct CountingHost : public PublishPumpHost
{
  int issued = 0;

  void issue_publish() override
  {
    ++issued;
  }
};

// @verifies CL-SUB-003
// @relation(CL-SUB-003, scope=function)
TEST(PublishPump, StartFillsToDefaultTargetOfTwo)
{
  CountingHost host;
  PublishPump pump{host};
  EXPECT_EQ(pump.state(), PumpState::Idle);
  pump.start();
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.target(), 2u);
  EXPECT_EQ(host.issued, 2);
  EXPECT_EQ(pump.outstanding(), 2u);
}

TEST(PublishPump, TargetTracksMonitoredItemCount)
{
  CountingHost host;
  PublishPump pump{host};
  pump.set_monitored_item_count(250);  // ceil(250/100) = 3
  EXPECT_EQ(pump.target(), 3u);
  pump.start();
  EXPECT_EQ(host.issued, 3);
  pump.set_monitored_item_count(1000);  // ceil(1000/100) = 10
  EXPECT_EQ(pump.target(), 10u);
  EXPECT_EQ(host.issued, 10) << "raising the target while running fills the extra slots";
}

TEST(PublishPump, TargetNeverBelowTwo)
{
  CountingHost host;
  PublishPump pump{host};
  pump.set_monitored_item_count(0);
  EXPECT_EQ(pump.target(), 2u);
  pump.set_monitored_item_count(50);  // ceil(50/100) = 1, floored to 2
  EXPECT_EQ(pump.target(), 2u);
}

TEST(PublishPump, ResponseRefillsToTarget)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();  // 2 issued, 2 outstanding
  pump.on_publish_response(/*tooMany=*/false);
  EXPECT_EQ(pump.outstanding(), 2u) << "a response is consumed and a fresh Publish issued";
  EXPECT_EQ(host.issued, 3);
}

// @verifies CL-SUB-004
// @relation(CL-SUB-004, scope=function)
TEST(PublishPump, PauseOnTooManyPublishRequests)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();  // 2 issued, 2 outstanding
  pump.on_publish_response(/*tooMany=*/true);
  EXPECT_EQ(pump.state(), PumpState::Paused);
  EXPECT_EQ(host.issued, 2) << "a paused pump issues nothing";
  EXPECT_EQ(pump.outstanding(), 1u);
}

// The pause waits for an outstanding Publish to return; when the fault took the last one, nothing can
// return, so a single Publish is sent and the pump stays Paused rather than stopping for good.
// @relation(AC-CL-SUB-004-SERVICE-FAULT-PAUSES-THE-PUMP, scope=function)
TEST(PublishPump, APauseWithNothingOutstandingKeepsOnePublishOutstanding)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();  // 2 issued, 2 outstanding
  pump.on_publish_response(/*tooMany=*/true);  // Paused, 1 outstanding
  EXPECT_EQ(host.issued, 2);
  pump.on_publish_response(/*tooMany=*/true);  // the last one: 0 outstanding
  EXPECT_EQ(pump.state(), PumpState::Paused);
  EXPECT_EQ(pump.outstanding(), 1u) << "a paused pump with nothing outstanding can never resume";
  EXPECT_EQ(host.issued, 3);
  pump.on_publish_response(/*tooMany=*/false);
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u);
}

TEST(PublishPump, ResumeOnNextResponse)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  pump.on_publish_response(/*tooMany=*/true);  // -> Paused, 1 outstanding
  pump.on_publish_response(/*tooMany=*/false);  // -> Running, refill to target
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u);
}

TEST(PublishPump, StopIssuesNoMore)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  const int afterStart = host.issued;
  pump.stop();
  EXPECT_EQ(pump.state(), PumpState::Idle);
  pump.on_publish_response(/*tooMany=*/false);
  EXPECT_EQ(host.issued, afterStart) << "a stopped pump issues nothing on a late response";
}

TEST(PublishPump, FailedPublishRefillsWithoutPausing)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();  // 2 issued, 2 outstanding
  pump.on_publish_failed();
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u) << "a failed send is replaced to keep the pipeline full";
  EXPECT_EQ(host.issued, 3);
}

// CL-RECONN-004: after a reconnect, the Publishes counted in `outstanding` were sent on the dropped
// channel and will never be answered. Without `resume` the pump is stuck at `outstanding == target` and
// issues nothing (it waits on responses that never arrive); `resume` clears the stale count and refills
// on the fresh channel.
TEST(PublishPump, ResumeClearsStuckOutstandingAndRefills)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();  // 2 issued, outstanding == target == 2 (these die with the dropped channel)
  ASSERT_EQ(pump.outstanding(), 2u);
  ASSERT_EQ(host.issued, 2);

  pump.resume();
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u) << "refilled to target on the fresh channel";
  EXPECT_EQ(host.issued, 4) << "resume discarded the stale outstanding count and issued a fresh target";
}

// `resume` restarts a stopped pump (the pipeline stops the pump on entering Reconnecting, then resumes
// it once the Connection is Active again).
TEST(PublishPump, ResumeRestartsAStoppedPump)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  pump.stop();  // Idle (outstanding still 2 from the pre-drop fill)
  ASSERT_EQ(pump.state(), PumpState::Idle);

  pump.resume();
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u);
  EXPECT_EQ(host.issued, 4) << "resume from Idle clears the stale count and refills";
}

// The pipeline stops the pump when the link drops and, with no Subscription to resume for, leaves it
// stopped; the next CreateSubscription starts it. The Publishes counted before the stop went out on the
// dropped channel, so `start` from Idle must not count them.
TEST(PublishPump, StartAfterStopDoesNotCountTheStoppedPublishes)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  pump.stop();
  ASSERT_EQ(pump.outstanding(), 2u);

  pump.start();
  EXPECT_EQ(pump.state(), PumpState::Running);
  EXPECT_EQ(pump.outstanding(), 2u);
  EXPECT_EQ(host.issued, 4) << "start from Idle fills to target on the new channel";
}

// Every CreateSubscription calls `start`, so a second start while Running keeps the Publishes it has.
TEST(PublishPump, StartWhileRunningIssuesNothingMore)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  pump.start();
  EXPECT_EQ(pump.outstanding(), 2u);
  EXPECT_EQ(host.issued, 2) << "the Publishes already outstanding are still answered";
}

// A start while Paused keeps the count: those Publishes are queued at the server and will be answered.
TEST(PublishPump, StartWhilePausedKeepsTheOutstandingCount)
{
  CountingHost host;
  PublishPump pump{host};
  pump.start();
  pump.on_publish_response(/*tooMany=*/true);  // Paused, 1 outstanding
  ASSERT_EQ(pump.state(), PumpState::Paused);
  ASSERT_EQ(pump.outstanding(), 1u);

  pump.start();
  EXPECT_EQ(pump.outstanding(), 2u);
  EXPECT_EQ(host.issued, 3) << "only the shortfall to target is issued";
}

}  // namespace
