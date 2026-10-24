// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_ASYNC_TEST_RUNTIME_H
#define UA_TESTS_HELPERS_ASYNC_TEST_RUNTIME_H

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <chrono>
#include <future>
#include <thread>

#include <gtest/gtest.h>

namespace ua::test_helpers
{

/// Owns an `io_context` driven by a background runner thread, for tests that
/// need the SDK's async machinery live while the main thread drives the system
/// under test and asserts on it.
///
/// **Why this exists - the teardown contract.** Asio requires that an
/// `io_context` outlive every I/O object bound to it, and forbids destroying it
/// while work is still pending (documented in `ua_timer.h`). The naive teardown
///
/// ```
///   boost::asio::io_context ioc;
///   auto guard  = boost::asio::make_work_guard(ioc);
///   auto runner = std::thread([&]{ ioc.run(); });
///   // ... body ...
///   guard.reset();
///   ioc.stop();        // <-- ABANDONS queued work (does NOT drain it)
///   runner.join();
/// ```
///
/// violates that contract: `ioc.stop()` abandons queued handlers, and the
/// server/connection objects destroyed at scope exit then post *more* teardown
/// work (e.g. `~ServerImpl` -> `complete_shutdown` -> `close_async`) onto the
/// stopped context. When `~io_context` then destroys that parked, strand-bound
/// work it is undefined behaviour - observed as an intermittent heap-use-after-
/// free / SIGSEGV in the strand/timer service during shutdown tests.
///
/// This runtime fixes the contract two ways:
///  1. It **drains** rather than `stop()`s - it resets the work guard and lets
///     `run()` process every remaining handler to completion before the
///     `io_context` is destroyed (mirroring how the production reference server
///     tears down via `thread_pool::join()`).
///  2. Declared as the **first** local in a test, it is destroyed **last** - so
///     the runner thread is still live when the server/connection objects are
///     destroyed (earlier in reverse order), and their posted teardown work is
///     picked up and drained instead of being stranded.
///
/// Usage:
/// ```
///   AsyncTestRuntime runtime;
///   auto server = create_test_server_impl(runtime.executor());
///   // ... body ...
///   // No manual teardown: ~AsyncTestRuntime drains after ~server.
/// ```
class AsyncTestRuntime
{
public:
  explicit AsyncTestRuntime(std::chrono::seconds drainTimeout = std::chrono::seconds{10})
    : mDrainTimeout(drainTimeout), mWorkGuard(boost::asio::make_work_guard(mIoContext)),
      mRunner(
        [this]
        {
          mIoContext.run();
          mRunExited.set_value();
        })
  {}

  AsyncTestRuntime(const AsyncTestRuntime&) = delete;
  AsyncTestRuntime& operator=(const AsyncTestRuntime&) = delete;

  boost::asio::any_io_executor executor()
  {
    return mIoContext.get_executor();
  }

  boost::asio::io_context& context()
  {
    return mIoContext;
  }

  ~AsyncTestRuntime()
  {
    // Drop the work guard so run() returns once all work - including teardown
    // work posted by objects destroyed before this runtime - has drained.
    mWorkGuard.reset();

    // Bound the drain so a genuine async-work leak surfaces as a clear test
    // failure instead of an indefinite hang. On a clean teardown run() returns
    // promptly; the timeout path only fires on a real leak.
    auto runExited = mRunExited.get_future();
    if (runExited.wait_for(mDrainTimeout) == std::future_status::timeout)
    {
      ADD_FAILURE() << "AsyncTestRuntime: io_context did not drain within " << mDrainTimeout.count()
                    << "s - async work was still pending at teardown (leaked timer, "
                       "un-cancelled operation, or a handler awaiting a stalled fake).";
      // Last resort to unblock the join; the test has already failed.
      mIoContext.stop();
      runExited.wait();
    }
    mRunner.join();
  }

private:
  std::chrono::seconds mDrainTimeout;
  boost::asio::io_context mIoContext;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> mWorkGuard;
  std::promise<void> mRunExited;
  std::thread mRunner;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_ASYNC_TEST_RUNTIME_H
