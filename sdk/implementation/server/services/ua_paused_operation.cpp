// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_paused_operation.h"

#include <cmath>

#include "ua_continuation_points.h"
#include "ua_callback_safety.h"

#include <utility>

namespace ua::server
{

std::optional<std::chrono::milliseconds> partial_result_delay(uint32_t timeoutHint, double fraction) noexcept
{
  if (timeoutHint == 0 || !(fraction > 0.0 && fraction < 1.0))
  {
    return std::nullopt;
  }
  const auto delay = static_cast<std::int64_t>(std::floor(static_cast<double>(timeoutHint) * fraction));
  return std::chrono::milliseconds{delay > 0 ? delay : 1};
}

PausedOperation::PausedOperation(std::shared_ptr<const void> keepAlive, std::function<void()> onRelease)
  : mKeepAlive(std::move(keepAlive)), mOnRelease(std::move(onRelease))
{}

bool PausedOperation::done() const
{
  const std::lock_guard<std::mutex> lock(mMutex);
  return mDone;
}

bool PausedOperation::released() const
{
  const std::lock_guard<std::mutex> lock(mMutex);
  return mReleased;
}

void PausedOperation::when_done(std::function<void()> notify)
{
  std::unique_lock<std::mutex> lock(mMutex);
  if (mReleased)
  {
    return;
  }
  if (!mDone)
  {
    mWaiters.push_back(std::move(notify));
    return;
  }
  lock.unlock();
  notify();
}

void PausedOperation::release() noexcept
{
  std::function<void()> onRelease;
  std::shared_ptr<const void> keepAlive;
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mDone || mReleased)
    {
      return;
    }
    mReleased = true;
    mWaiters.clear();
    onRelease = std::move(mOnRelease);
    keepAlive = std::move(mKeepAlive);
  }
  if (onRelease)
  {
    ua::detail::invoke_user_callback(onRelease);
  }
  // keepAlive goes out of scope here. The caller is the Session (or a continuing request) releasing the
  // point, never the running work itself, so dropping the owner cannot destroy a frame mid-flight; a
  // handler of the owner that is running at this moment holds its own reference until it returns.
}

std::shared_ptr<const void> PausedOperation::mark_done(std::unique_lock<std::mutex> lock)
{
  if (mReleased || mDone)
  {
    return nullptr;
  }
  mDone = true;
  auto waiters = std::exchange(mWaiters, {});
  auto keepAlive = std::move(mKeepAlive);
  mOnRelease = nullptr;
  lock.unlock();
  for (auto& waiter : waiters)
  {
    ua::detail::invoke_user_callback(waiter);
  }
  return keepAlive;
}

void release_paused_operation(PausedOperation& operation) noexcept
{
  operation.release();
}

}  // namespace ua::server
