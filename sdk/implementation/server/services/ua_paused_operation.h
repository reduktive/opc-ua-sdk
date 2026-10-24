// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PAUSED_OPERATION_H
#define UA_PAUSED_OPERATION_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ua::server
{

/// The delay after which Browse, BrowseNext and HistoryRead answer with what they have: `timeoutHint`
/// times `fraction`, rounded down, at least one millisecond. Empty when `timeoutHint` is 0, which asks
/// for no timeout (OPC 10000-4 section 7.33).
std::optional<std::chrono::milliseconds> partial_result_delay(uint32_t timeoutHint, double fraction) noexcept;

/// An operation a service answered for before it finished, and handed to a continuation point.
///
/// When a Browse, BrowseNext or HistoryRead reaches its partial-result deadline, every operation still
/// running is answered with no results and a continuation point holding one of these (OPC 10000-4
/// sections 5.8.2 and 5.10.3.1). The operation keeps running in the service that started it; its
/// outcome is kept here and handed to the next request that continues the point. Releasing the point
/// (the Client releases it, it expires, it is freed for another, or the Session closes) calls
/// @ref release, which tells the running work to stop and lets the service that ran it go.
///
/// Thread-safe: the producing service completes it on its own strand while the Session or a
/// continuing request on another strand waits for it or releases it.
class PausedOperation
{
public:
  /// @param keepAlive Owner of the running work (the service that started it), held until the outcome
  ///                  arrives or the point is released, so the work outlives the request that started it.
  /// @param onRelease Called once if the point is released before the outcome arrives - the hook that
  ///                  sets the running call's cancellation flag. May be empty.
  PausedOperation(std::shared_ptr<const void> keepAlive, std::function<void()> onRelease);
  virtual ~PausedOperation() = default;

  PausedOperation(const PausedOperation&) = delete;
  PausedOperation& operator=(const PausedOperation&) = delete;
  PausedOperation(PausedOperation&&) = delete;
  PausedOperation& operator=(PausedOperation&&) = delete;

  /// Whether the outcome has arrived.
  [[nodiscard]] bool done() const;

  /// Whether the point was released before the outcome arrived.
  [[nodiscard]] bool released() const;

  /// Calls @p notify once the outcome has arrived: at once, on this thread, if it already has; otherwise
  /// on the thread that delivers it. Never called for an operation released first.
  void when_done(std::function<void()> notify);

  /// Nobody will read the outcome. Calls the release hook and drops the owner of the running work.
  /// Idempotent; does nothing once the outcome has arrived.
  void release() noexcept;

protected:
  /// Marks the outcome as arrived and wakes the waiters. The derived class stores the outcome under
  /// @ref mMutex before calling this. Returns the owner of the running work so the caller can let it go
  /// at a point where that cannot destroy the frame it is running in.
  std::shared_ptr<const void> mark_done(std::unique_lock<std::mutex> lock);

  mutable std::mutex mMutex;

private:
  bool mDone{false};
  bool mReleased{false};
  std::vector<std::function<void()>> mWaiters;
  std::shared_ptr<const void> mKeepAlive;
  std::function<void()> mOnRelease;
};

/// A paused operation whose outcome is an @p Outcome value, handed whole to the request that continues it.
template<typename Outcome>
class PausedResult final : public PausedOperation
{
public:
  using PausedOperation::PausedOperation;

  /// Stores the operation's outcome and wakes the request waiting for it.
  /// @return The owner of the running work, for the caller to let go off the frame it runs in.
  std::shared_ptr<const void> complete(Outcome outcome)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    mOutcome = std::move(outcome);
    return mark_done(std::move(lock));
  }

  /// Takes the outcome; empty if it has not arrived or was already taken.
  std::optional<Outcome> take()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return std::exchange(mOutcome, std::nullopt);
  }

private:
  std::optional<Outcome> mOutcome;
};

/// A cancellation flag shared by the items of one namespace call, set once every item of the call that
/// was handed to a continuation point has been released - a namespace answering several items in one
/// call is told to stop only when nobody wants any of them.
class SharedCallCancellation
{
public:
  explicit SharedCallCancellation(std::shared_ptr<std::atomic_bool> flag) : mFlag(std::move(flag))
  {}

  /// One more item of the call now waits in a continuation point.
  void add_paused_item() noexcept
  {
    mPaused.fetch_add(1, std::memory_order_relaxed);
  }

  /// One paused item was released; the last one sets the flag.
  void release_paused_item() noexcept
  {
    if (mPaused.fetch_sub(1, std::memory_order_acq_rel) == 1 && mFlag)
    {
      mFlag->store(true);
    }
  }

private:
  std::shared_ptr<std::atomic_bool> mFlag;
  std::atomic<std::size_t> mPaused{0};
};

}  // namespace ua::server

#endif  // !UA_PAUSED_OPERATION_H
