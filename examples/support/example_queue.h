// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_QUEUE_H
#define UASDK_EXAMPLE_QUEUE_H

/// @file
/// @brief A small hand-off queue between an SDK callback and the thread waiting for it.
///
/// This is thread plumbing, not OPC UA. It exists because an SDK callback runs on the SDK's own
/// executor and must not block: the callback appends a value and returns, and everything slow
/// happens on the thread that takes it.
///
/// That rule is an SDK lesson rather than a detail of this queue, so it is shown in the foreground:
/// `examples/client/subscriptions` registers the callback that feeds one of these, and says there
/// why it does nothing but append.

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <utility>

namespace examples
{

/// Values handed from a callback to the thread waiting for them, in arrival order.
template<typename T>
class Queue
{
public:
  /// Appends a value and wakes one waiter. Safe to call from a callback; never blocks.
  void push(T value)
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mValues.push_back(std::move(value));
    }
    mArrived.notify_one();
  }

  /// Waits up to @p budget for the next value.
  std::optional<T> take(std::chrono::milliseconds budget)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    if (!mArrived.wait_for(lock, budget, [this] { return !mValues.empty(); }))
    {
      return std::nullopt;
    }
    T value = std::move(mValues.front());
    mValues.pop_front();
    return value;
  }

  /// Waits for a value equal to @p wanted, discarding any that arrive before it.
  ///
  /// Useful where a Subscription reports an initial value, and later values, before the one an
  /// example is actually demonstrating.
  bool wait_for_value(const T& wanted, std::chrono::milliseconds budget)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
      const auto value = take(remaining);
      if (!value)
      {
        return false;
      }
      if (*value == wanted)
      {
        return true;
      }
    }
    return false;
  }

private:
  std::mutex mMutex;
  std::condition_variable mArrived;
  std::deque<T> mValues;
};

}  // namespace examples

#endif  // UASDK_EXAMPLE_QUEUE_H
