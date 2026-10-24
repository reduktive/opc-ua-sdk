// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "liveness_watchdog.h"

#include <boost/asio/post.hpp>

namespace fuzz
{

LivenessWatchdog::LivenessWatchdog(boost::asio::any_io_executor executor, std::chrono::milliseconds deadline,
  std::chrono::milliseconds interval, std::function<void()> onStall)
  : mExecutor(std::move(executor)), mDeadline(deadline), mInterval(interval), mOnStall(std::move(onStall)),
    mState(std::make_shared<State>()), mThread([this] { loop(); })
{}

LivenessWatchdog::~LivenessWatchdog()
{
  {
    std::lock_guard<std::mutex> lock(mState->mutex);
    mState->stop = true;
  }
  mState->cv.notify_all();
  if (mThread.joinable())
  {
    mThread.join();
  }
}

void LivenessWatchdog::loop()
{
  auto state = mState;  // keep state alive for the duration of the loop
  std::unique_lock<std::mutex> lock(state->mutex);
  while (!state->stop)
  {
    const uint64_t seq = ++state->pingSeq;

    // Post a heartbeat onto the watched executor. It bumps pongSeq to `seq` when it runs.
    // Capture a shared_ptr to the state so a heartbeat still queued at destruction is safe.
    boost::asio::post(mExecutor,
      [state, seq]
      {
        std::lock_guard<std::mutex> handlerLock(state->mutex);
        if (seq > state->pongSeq)
        {
          state->pongSeq = seq;
        }
        state->cv.notify_all();
      });

    // Wait for the heartbeat to run, up to the deadline.
    const bool serviced =
      state->cv.wait_for(lock, mDeadline, [&state, seq] { return state->stop || state->pongSeq >= seq; });

    if (state->stop)
    {
      break;
    }
    if (!serviced)
    {
      // The heartbeat never ran within the deadline: the executor thread is wedged in a
      // synchronous call. Report once (typically aborts) and stop probing.
      lock.unlock();
      if (mOnStall)
      {
        mOnStall();
      }
      return;
    }

    // Serviced - wait the inter-probe interval (interruptible by stop).
    state->cv.wait_for(lock, mInterval, [&state] { return state->stop; });
  }
}

}  // namespace fuzz
