// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_publish_pump.h"

#include <algorithm>

namespace ua::client::detail
{

PublishPump::PublishPump(PublishPumpHost& host) noexcept : mHost(host)
{}

void PublishPump::start()
{
  // Starting a stopped pump discards its count, as resume() does: the pipeline stops the pump when the
  // channel drops or closes, and the Publishes sent on that channel are never answered. A Paused or
  // Running pump's Publishes are queued at the server and are still counted.
  if (mState == PumpState::Idle)
  {
    mOutstanding = 0;
  }
  mState = PumpState::Running;
  fill();
}

void PublishPump::stop() noexcept
{
  mState = PumpState::Idle;
}

void PublishPump::resume()
{
  // The Publishes counted in mOutstanding were sent on the channel that just dropped; their responses
  // will never arrive, so clear the count (rather than waiting on it) and refill on the fresh channel.
  mOutstanding = 0;
  mState = PumpState::Running;
  fill();
}

void PublishPump::set_monitored_item_count(std::size_t totalMonitoredItems)
{
  // target = max(2, ceil(items / 100)) (CL-SUB-015). Never below 2 (always-on pipelining, CL-SUB-003).
  mTarget = std::max<std::size_t>(2, (totalMonitoredItems + 99) / 100);
  if (mState == PumpState::Running)
  {
    fill();
  }
}

void PublishPump::on_publish_response(bool tooManyPublishRequests)
{
  if (mOutstanding > 0)
  {
    --mOutstanding;  // the response consumes the Publish it answers
  }
  if (mState == PumpState::Idle)
  {
    return;  // stopped - do not re-pump on a late response
  }
  if (tooManyPublishRequests)
  {
    mState = PumpState::Paused;  // CL-SUB-004: back off until the next response
    // With nothing outstanding no response can come to resume the pump, so one Publish is sent and the
    // pump stays Paused: OPC 10000-4 5.14.5.1 asks the Client to wait for an outstanding Publish, and
    // with none left the wait has nothing to end it.
    if (mOutstanding == 0)
    {
      mHost.issue_publish();
      ++mOutstanding;
    }
    return;
  }
  if (mState == PumpState::Paused)
  {
    mState = PumpState::Running;  // the next response resumes the pump
  }
  fill();
}

void PublishPump::on_publish_failed()
{
  if (mOutstanding > 0)
  {
    --mOutstanding;
  }
  if (mState == PumpState::Running)
  {
    fill();  // a failed send is replaced (not a server backpressure signal - do not pause)
  }
}

void PublishPump::fill()
{
  while (mState == PumpState::Running && mOutstanding < mTarget)
  {
    mHost.issue_publish();
    ++mOutstanding;
  }
}

PumpState PublishPump::state() const noexcept
{
  return mState;
}

std::size_t PublishPump::outstanding() const noexcept
{
  return mOutstanding;
}

std::size_t PublishPump::target() const noexcept
{
  return mTarget;
}

}  // namespace ua::client::detail
