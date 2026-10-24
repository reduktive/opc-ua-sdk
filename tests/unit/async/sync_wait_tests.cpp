// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::async::detail::blocking_call - the one way every *_sync API wrapper waits - and the
// on_executor_context predicate it refuses on. The contract under test:
//   * on_executor_context(ex) is true exactly when the calling thread is running the Asio execution
//     context that `ex` belongs to (the thread that would have to run the work that answers) - and false
//     for an external thread or a different context;
//   * blocking_call refuses there, returning BadWouldBlock with an ErrorDetail, before it starts the
//     operation;
//   * otherwise it starts the operation and returns its first answer, to a deadline when it has one, and
//     an operation that throws, answers twice, answers late or never answers cannot hang or corrupt the
//     caller.
//
// Falsifiability: without the guard, BlockingCall.RefusesOnItsExecutorWithoutStarting would block its one
// pool thread and never answer. If on_executor_context always returned false, the predicate tests fail
// cleanly (no hang); if it wrongly returned true off-context, the external-thread and different-context
// tests would see BadWouldBlock instead of the value.

#include "ua_sync_wait.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <future>
#include <utility>
#include <thread>

namespace
{

using ua::async::detail::on_executor_context;

boost::asio::any_io_executor executor_of(boost::asio::io_context& ctx)
{
  return boost::asio::any_io_executor{ctx.get_executor()};
}

// --- on_executor_context predicate ------------------------------------------

// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-01-IO-AND-THREAD-POOL, scope=function)
TEST(SyncWaitPredicate, TrueOnOwningContextThread)
{
  boost::asio::io_context ctx;
  bool observed = false;
  boost::asio::post(ctx, [&] { observed = on_executor_context(executor_of(ctx)); });
  ctx.run();
  EXPECT_TRUE(observed) << "a handler running on the io_context must see itself as on that context";
}

TEST(SyncWaitPredicate, FalseFromExternalThread)
{
  boost::asio::io_context ctx;
  // The test thread never runs ctx, so it is not on ctx's context.
  EXPECT_FALSE(on_executor_context(executor_of(ctx)));
}

TEST(SyncWaitPredicate, FalseForDifferentContextThread)
{
  boost::asio::io_context ctxA;
  boost::asio::io_context ctxB;
  bool observedBFromA = true;
  boost::asio::post(ctxA, [&] { observedBFromA = on_executor_context(executor_of(ctxB)); });
  ctxA.run();
  EXPECT_FALSE(observedBFromA) << "running on ctxA must not count as being on ctxB's context";
}

// Adversarial-review regression (section 3.1, security-robustness lens): querying an empty (default-
// constructed / moved-from) any_io_executor throws boost::asio::bad_executor; since
// on_executor_context is noexcept, an unguarded throw would std::terminate the process. The guard must
// treat an empty executor as "running nothing, so not a deadlock" and return false, never crash.
TEST(SyncWaitPredicate, EmptyExecutorReturnsFalse)
{
  boost::asio::any_io_executor empty;  // default-constructed: no target
  EXPECT_FALSE(on_executor_context(empty));
}

// Adversarial-review regression (section 3.1): the deadlock question must be answered layer-independently -
// a call issued from inside a strand that runs on the io_context is just as much a deadlock as one on
// the bare io_context executor. Passing the strand's own executor must still resolve to its io_context
// and report true (a target<io_context::executor_type>-based detector would miss this and hang).
TEST(SyncWaitPredicate, DetectsFromWithinStrandPassingStrandExecutor)
{
  boost::asio::io_context ctx;
  auto strand = boost::asio::make_strand(ctx);
  bool observed = false;
  boost::asio::post(strand, [&] { observed = on_executor_context(boost::asio::any_io_executor{strand}); });
  ctx.run();
  EXPECT_TRUE(observed)
    << "a call from within a strand, passing the strand's executor, must resolve to its io_context";
}

// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-01-IO-AND-THREAD-POOL, scope=function)
TEST(SyncWaitPredicate, TrueOnOwningThreadPoolThread)
{
  boost::asio::thread_pool pool{1};
  const boost::asio::any_io_executor executor{pool.get_executor()};
  EXPECT_FALSE(on_executor_context(executor));

  std::promise<bool> observedPromise;
  auto observedFuture = observedPromise.get_future();
  boost::asio::post(pool, [&] { observedPromise.set_value(on_executor_context(executor)); });

  EXPECT_TRUE(observedFuture.get()) << "a thread_pool handler must be recognised without an io_context cast";
  pool.join();
}

// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-01-IO-AND-THREAD-POOL, scope=function)
TEST(SyncWaitPredicate, DetectsFromWithinThreadPoolStrand)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  std::promise<bool> observedPromise;
  auto observedFuture = observedPromise.get_future();
  boost::asio::post(
    strand, [&] { observedPromise.set_value(on_executor_context(boost::asio::any_io_executor{strand})); });

  EXPECT_TRUE(observedFuture.get())
    << "a strand must resolve to its thread_pool execution context for deadlock detection";
  pool.join();
}

}  // namespace

// --- blocking_call (COMP-CORE-ASYNC-SYNC-WAIT-02) ----------------------------------------------------

// On its own executor a blocking call refuses and starts nothing; the operation's completion could only
// run on the thread that would be waiting for it.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-REFUSED-BEFORE-STARTING, scope=function)
TEST(BlockingCall, RefusesOnItsExecutorWithoutStarting)
{
  boost::asio::thread_pool pool{1};
  std::promise<std::pair<ua::StatusCode, bool>> observed;
  boost::asio::post(pool,
    [&]
    {
      bool started = false;
      auto result = ua::async::detail::blocking_call<ua::Result<int>>(pool.get_executor(),
        [&started](std::function<void(ua::Result<int>)> complete)
        {
          started = true;
          complete(ua::Result<int>{1});
        });
      observed.set_value({result.status_code(), started});
      if (result.shared_detail() == nullptr || result.shared_detail()->code != "WouldBlock")
      {
        ADD_FAILURE() << "the refusal carries the WouldBlock ErrorDetail";
      }
    });
  auto [status, started] = observed.get_future().get();
  pool.join();
  EXPECT_EQ(status.as_status(), ua::Status::BadWouldBlock);
  EXPECT_FALSE(started) << "the operation must not be started when the wait is refused";
}

// Control: from a thread that is not running the executor, the operation is started on the executor and
// its result returned.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-REFUSED-BEFORE-STARTING, scope=function)
TEST(BlockingCall, ReturnsTheOperationsResultFromAnExternalThread)
{
  boost::asio::thread_pool pool{1};
  auto result = ua::async::detail::blocking_call<ua::Result<int>>(pool.get_executor(),
    [&pool](std::function<void(ua::Result<int>)> complete)
    { boost::asio::post(pool, [complete = std::move(complete)] { complete(ua::Result<int>{42}); }); });
  pool.join();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 42);
}

// A deadline bounds the wait; the operation is not cancelled, and when it completes after the call has
// returned, its completion writes into state it shares, not into the returned frame.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-DEADLINE, scope=function)
TEST(BlockingCall, ADeadlineBoundsTheWaitAndALateCompletionIsHarmless)
{
  boost::asio::thread_pool pool{1};
  std::function<void(ua::Result<int>)> kept;
  const auto started = std::chrono::steady_clock::now();
  auto result = ua::async::detail::blocking_call<ua::Result<int>>(
    pool.get_executor(),
    [&kept](std::function<void(ua::Result<int>)> complete) { kept = std::move(complete); },
    std::chrono::milliseconds{100});
  const auto elapsed = std::chrono::steady_clock::now() - started;
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BlockingCallDeadline");
  EXPECT_GE(elapsed, std::chrono::milliseconds{100});
  ASSERT_TRUE(kept);
  kept(ua::Result<int>{7});  // late; must not fault
  kept(ua::Result<int>{8});  // and again
  pool.join();
}

// An exception from starting the operation becomes the result; nothing propagates.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-START-THROWS, scope=function)
TEST(BlockingCall, AnExceptionFromStartBecomesABadResult)
{
  boost::asio::thread_pool pool{1};
  auto result = ua::async::detail::blocking_call<ua::Result<int>>(pool.get_executor(),
    [](std::function<void(ua::Result<int>)>) { throw ua::UaException{ua::Status::BadInvalidArgument}; });
  pool.join();
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInvalidArgument);
}

// The first completion is the answer; a second is ignored rather than throwing promise_already_satisfied.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-FIRST-COMPLETION-WINS, scope=function)
TEST(BlockingCall, ASecondCompletionIsIgnored)
{
  boost::asio::thread_pool pool{1};
  auto result = ua::async::detail::blocking_call<ua::VoidResult>(pool.get_executor(),
    [](std::function<void(ua::VoidResult)> complete)
    {
      complete(ua::VoidResult{});
      complete(ua::VoidResult{ua::Status::BadInternalError});
    });
  pool.join();
  EXPECT_TRUE(result.is_good());
}

// Control for the refusal: a thread running ANOTHER execution context may wait, because a different
// context fulfils the operation.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-REFUSED-BEFORE-STARTING, scope=function)
TEST(BlockingCall, PermitsWaitingFromADifferentContext)
{
  boost::asio::thread_pool poolA{1};
  boost::asio::thread_pool poolB{1};
  std::promise<ua::Result<int>> observed;
  boost::asio::post(poolA,
    [&]
    {
      observed.set_value(ua::async::detail::blocking_call<ua::Result<int>>(poolB.get_executor(),
        [&poolB](std::function<void(ua::Result<int>)> complete)
        { boost::asio::post(poolB, [complete = std::move(complete)] { complete(ua::Result<int>{7}); }); }));
    });
  auto result = observed.get_future().get();
  poolA.join();
  poolB.join();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 7);
}

// The refusal is the same for an operation with no value.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-REFUSED-BEFORE-STARTING, scope=function)
TEST(BlockingCall, RefusesAVoidResultOnItsExecutor)
{
  boost::asio::io_context ctx;
  ua::VoidResult captured{};  // good sentinel; must be overwritten with the refusal
  boost::asio::post(ctx,
    [&]
    {
      captured = ua::async::detail::blocking_call<ua::VoidResult>(
        ctx.get_executor(), [](std::function<void(ua::VoidResult)> complete) { complete(ua::VoidResult{}); });
    });
  ctx.run();
  EXPECT_EQ(captured.status_code().as_status(), ua::Status::BadWouldBlock);
}

// An operation that releases its completion without calling it - a post dropped because its owner is
// gone - ends the wait with an error instead of leaving the caller blocked for ever. The wait runs on a
// detached thread so that a regression reports a hang rather than becoming one.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-02-RELEASED-COMPLETION, scope=function)
TEST(BlockingCall, AReleasedCompletionEndsTheWait)
{
  auto observed = std::make_shared<std::promise<ua::VoidResult>>();
  auto future = observed->get_future();
  std::thread(
    [observed]
    {
      boost::asio::thread_pool pool{1};
      observed->set_value(ua::async::detail::blocking_call<ua::VoidResult>(pool.get_executor(),
        [](std::function<void(ua::VoidResult)> complete) { auto released = std::move(complete); }));
      pool.join();
    })
    .detach();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "the caller is still blocked on an operation that can no longer answer";
  auto result = future.get();
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BlockingCallAbandoned");
}
