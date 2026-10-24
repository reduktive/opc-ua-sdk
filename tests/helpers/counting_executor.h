// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_COUNTING_EXECUTOR_H
#define UA_TESTS_HELPERS_COUNTING_EXECUTOR_H

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/execution.hpp>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>

namespace ua::test_helpers
{

/// Tracks outstanding work submitted through a CountingExecutor. Owned by
/// the test fixture; lives for the duration of the test.
class ExecutorIdleCounter
{
public:
  void begin() noexcept
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mCount;
  }

  void end() noexcept
  {
    bool notify = false;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      if (--mCount == 0)
      {
        notify = true;
      }
    }
    if (notify)
    {
      mCv.notify_all();
    }
  }

  /// Block until the outstanding count reaches zero, or `timeout` elapses.
  /// Returns true if idle was reached.
  bool wait_for_idle(std::chrono::milliseconds timeout)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCv.wait_for(lock, timeout, [this] { return mCount == 0; });
  }

private:
  std::mutex mMutex;
  std::condition_variable mCv;
  int mCount = 0;
};

namespace detail
{
/// RAII handle: ++counter at construction, --counter at destruction.
/// Move-only so the count is balanced even if asio moves the handler
/// internally, and end() fires even if the handler is dropped without
/// being invoked (e.g. on executor shutdown).
class CountedTaskGuard
{
public:
  explicit CountedTaskGuard(std::shared_ptr<ExecutorIdleCounter> counter) noexcept
    : mCounter(std::move(counter))
  {
    if (mCounter)
    {
      mCounter->begin();
    }
  }

  ~CountedTaskGuard() noexcept
  {
    if (mCounter)
    {
      mCounter->end();
    }
  }

  CountedTaskGuard(CountedTaskGuard&& other) noexcept : mCounter(std::move(other.mCounter))
  {}

  CountedTaskGuard& operator=(CountedTaskGuard&&) = delete;
  CountedTaskGuard(const CountedTaskGuard&) = delete;
  CountedTaskGuard& operator=(const CountedTaskGuard&) = delete;

private:
  std::shared_ptr<ExecutorIdleCounter> mCounter;
};
}  // namespace detail

/// Asio executor decorator that increments an ExecutorIdleCounter on every
/// submission and decrements when the submitted work is destroyed (either
/// after it runs, or when dropped on executor shutdown).
///
/// Forwards every query / require / prefer to the wrapped any_io_executor,
/// so the decorator satisfies the any_io_executor property set itself.
class CountingExecutor
{
public:
  CountingExecutor(boost::asio::any_io_executor inner, std::shared_ptr<ExecutorIdleCounter> counter)
    : mInner(std::move(inner)), mCounter(std::move(counter))
  {}

  template<typename F>
  void execute(F&& f) const
  {
    mInner.execute(
      [guard = detail::CountedTaskGuard{mCounter}, fn = std::forward<F>(f)]() mutable { std::move(fn)(); });
  }

  boost::asio::execution_context& query(boost::asio::execution::context_t) const noexcept
  {
    return boost::asio::query(mInner, boost::asio::execution::context);
  }

  template<typename Property>
  auto query(const Property& p) const
    noexcept(noexcept(boost::asio::query(std::declval<const boost::asio::any_io_executor&>(),
      p))) -> std::enable_if_t<boost::asio::can_query<boost::asio::any_io_executor, Property>::value,
             decltype(boost::asio::query(std::declval<const boost::asio::any_io_executor&>(), p))>
  {
    return boost::asio::query(mInner, p);
  }

  template<typename Property>
  auto require(const Property& p) const
    -> std::enable_if_t<boost::asio::can_require<boost::asio::any_io_executor, Property>::value,
      CountingExecutor>
  {
    return CountingExecutor{boost::asio::require(mInner, p), mCounter};
  }

  template<typename Property>
  auto prefer(const Property& p) const
    -> std::enable_if_t<boost::asio::can_prefer<boost::asio::any_io_executor, Property>::value,
      CountingExecutor>
  {
    return CountingExecutor{boost::asio::prefer(mInner, p), mCounter};
  }

  bool operator==(const CountingExecutor& other) const noexcept
  {
    return mInner == other.mInner && mCounter == other.mCounter;
  }

  bool operator!=(const CountingExecutor& other) const noexcept
  {
    return !(*this == other);
  }

private:
  boost::asio::any_io_executor mInner;
  std::shared_ptr<ExecutorIdleCounter> mCounter;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_COUNTING_EXECUTOR_H
