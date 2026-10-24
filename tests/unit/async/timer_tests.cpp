// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include <fmt/core.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>
#include "ua_timer.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/strand.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{
// Poll until `pred()` holds or `budget` elapses. Returns the wall-clock instant
// the predicate first held, or std::nullopt on timeout. Used instead of a fixed
// sleep + exact-count assertion: the moment a timer fires relative to a fixed
// wall-clock sample is inherently non-deterministic, and on Windows the timer
// wakeup is quantized to the ~15.6ms system tick - a 200ms timer can wake any
// time in [200ms, ~216ms]. Asserting an exact count after a 10ms-wide window is
// therefore a guaranteed flake there. Polling for the *event* (a fire happened)
// rather than racing the sample against the fire keeps the verification exact
// while being resolution-independent.
template<typename Predicate>
std::optional<std::chrono::steady_clock::time_point> wait_until(
  Predicate pred, std::chrono::steady_clock::duration budget = std::chrono::seconds{5})
{
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return std::chrono::steady_clock::now();
    }
    std::this_thread::sleep_for(2ms);
  }
  return std::nullopt;
}

// Deterministic "no premature fire" check for a timer.
//
// A fixed `sleep_for(...)` before the timer's deadline is only a *lower* bound on elapsed
// wall time: on a loaded box the sleep can overshoot the deadline, by which point the timer
// has legitimately fired - so an unconditional `EXPECT_EQ(count, 0)` / `EXPECT_FALSE(fired)`
// after the sleep is a guaranteed flake under CI contention (this is what made PeriodicTimer
// flaky). Instead, sample the fire indicator and the clock together (indicator first, so any
// observed fire happened-before the timestamp) and only assert "no fire yet" when the
// measured elapsed time is still inside `minTimeToFire`. `armed` must be captured immediately
// before the timer is scheduled, so it is no later than the timer's true arm instant and the
// guard is conservative. This never false-fails - a legitimate fire lands at/after the
// deadline, by which point the guard has skipped the check - yet still catches a genuine early
// fire (indicator set while the clock proves we are still within `minTimeToFire`).
//
// `Indicator` is an atomic flag/counter; any non-zero value means "fired". For a periodic
// timer `minTimeToFire` is its period; for a single-shot timer it is its delay.
template<typename Indicator>
void expect_no_premature_fire(const Indicator& fired, std::chrono::steady_clock::time_point armed,
  std::chrono::steady_clock::duration minTimeToFire, std::string_view what)
{
  const auto observed = fired.load();
  const auto sampledAt = std::chrono::steady_clock::now();
  if (sampledAt - armed < minTimeToFire)
  {
    EXPECT_FALSE(static_cast<bool>(observed)) << what << " fired before its deadline elapsed";
  }
}
}  // namespace

TEST(TimerTests, SimpleTimer)
{
  boost::asio::thread_pool threadPool;
  constexpr auto delay = 500ms;
  std::atomic<bool> elapsed{false};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_after(threadPool.get_executor(),
    delay,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      elapsed = true;
    });

  // Not before its deadline (measured-time guard, robust to an overshooting sleep), then it
  // must fire - wait for the event rather than racing a fixed sleep against handler dispatch.
  std::this_thread::sleep_for(delay - 100ms);
  expect_no_premature_fire(elapsed, armed, delay, "single-shot timer");
  ASSERT_TRUE(wait_until([&] { return elapsed.load(); }).has_value())
    << "single-shot timer never fired within the budget";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TimerTests, CancelledTimer)
{
  boost::asio::thread_pool threadPool;
  constexpr auto delay = 500ms;
  std::atomic<bool> elapsed{false};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_after(threadPool.get_executor(),
    delay,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      elapsed = true;
    });

  std::this_thread::sleep_for(delay - 200ms);
  timer.cancel();
  // The cancel only counts if it provably won the race against the deadline. Measure *after*
  // cancel() has returned: if we are still inside the first period then, the cancel landed
  // before any legal fire, so the timer must not have fired. If the sleep overshot the deadline
  // under load, skip the assertion rather than report a spurious failure (a fire then is correct
  // behaviour, not a bug).
  const bool cancelledInTime = std::chrono::steady_clock::now() - armed < delay;
  std::this_thread::sleep_for(300ms);
  if (cancelledInTime)
  {
    GTEST_ASSERT_FALSE(elapsed) << "timer fired despite being cancelled before its deadline";
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TimerTests, PeriodicTimer)
{
  boost::asio::thread_pool threadPool;
  constexpr auto period = 200ms;
  std::atomic<size_t> elapsed{0};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_every(threadPool.get_executor(),
    period,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      ++elapsed;
    });

  // Must not fire before one period has elapsed. Sleeping half a period and then
  // checking only when the *measured* elapsed time confirms we are still inside the
  // first period keeps this deterministic even when the sleep overshoots under load.
  std::this_thread::sleep_for(period / 2);
  expect_no_premature_fire(elapsed, armed, period, "periodic timer");

  // First fire: prove the timer fires at all (not zero on Windows).
  const auto firstFire = wait_until([&] { return elapsed.load() >= 1; });
  ASSERT_TRUE(firstFire.has_value()) << "periodic timer never fired within the budget";

  // Second fire: proves the timer re-arms (periodicity), and the gap between the
  // first and second fire must be at least ~one period - this is the real
  // "fires once per period, no burst/coalescing" guarantee, checked by elapsed
  // time rather than by a raced sample.
  const auto secondFire = wait_until([&] { return elapsed.load() >= 2; });
  ASSERT_TRUE(secondFire.has_value()) << "periodic timer did not re-arm for a second fire";
  EXPECT_GE(*secondFire - *firstFire, period - 50ms)
    << "consecutive fires were closer together than one period (burst/coalescing)";

  timer.cancel();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TimerTests, CancelledPeriodicTimer)
{
  boost::asio::thread_pool threadPool;
  constexpr auto period = 200ms;
  std::atomic<size_t> elapsed{0};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_every(threadPool.get_executor(),
    period,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      ++elapsed;
    });

  // No early fire (measured-time guard, see PeriodicTimer / expect_no_premature_fire).
  std::this_thread::sleep_for(period / 2);
  expect_no_premature_fire(elapsed, armed, period, "periodic timer");

  // Let it fire at least twice so cancel() is exercised against an actively
  // re-arming timer, not one that has yet to fire.
  ASSERT_TRUE(wait_until([&] { return elapsed.load() >= 2; }).has_value())
    << "periodic timer did not fire twice before cancellation";

  timer.cancel();
  // After cancel the count must stop advancing. Snapshot, wait several periods,
  // and assert no further fires landed.
  const size_t countAtCancel = elapsed.load();
  std::this_thread::sleep_for(3 * period);
  GTEST_ASSERT_EQ(elapsed.load(), countAtCancel) << "periodic timer fired after cancel()";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Move construction transfers the armed implementation, while move assignment first cancels the timer it
// replaces. Self-move is a no-op that retains the timer.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, MoveOperationsTransferOwnershipAndCancelReplacement)
{
  boost::asio::thread_pool threadPool{2};
  std::atomic<int> replacedFires{0};
  std::atomic<int> transferredFires{0};

  Timer source = Timer::schedule_after(
    threadPool.get_executor(), 1s, [&transferredFires](boost::system::error_code) { ++transferredFires; });
  Timer transferred = std::move(source);
  EXPECT_FALSE(source);
  EXPECT_TRUE(transferred);

  Timer destination = Timer::schedule_every(
    threadPool.get_executor(), 5ms, [&replacedFires](boost::system::error_code) { ++replacedFires; });
  ASSERT_TRUE(wait_until([&replacedFires] { return replacedFires.load() >= 1; }).has_value())
    << "the replacement control timer never armed";
  destination = std::move(transferred);
  EXPECT_FALSE(transferred);
  EXPECT_TRUE(destination);

  destination = std::move(destination);
  EXPECT_TRUE(destination);

  std::this_thread::sleep_for(20ms);
  const int settledFires = replacedFires.load();
  std::this_thread::sleep_for(20ms);
  EXPECT_EQ(replacedFires.load(), settledFires) << "move assignment must cancel the timer it replaces";
  EXPECT_EQ(transferredFires.load(), 0) << "the transferred timer fired before its original deadline";

  destination.cancel();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TimerTests, StrandSimpleTimer)
{
  boost::asio::thread_pool threadPool;
  auto strand = boost::asio::make_strand(threadPool.get_executor());

  constexpr auto delay = 500ms;
  std::atomic<bool> elapsed{false};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_after(strand,
    delay,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      elapsed = true;
    });

  // Not before its deadline (measured-time guard), then it must fire (wait for the event).
  std::this_thread::sleep_for(delay - 100ms);
  expect_no_premature_fire(elapsed, armed, delay, "strand single-shot timer");
  ASSERT_TRUE(wait_until([&] { return elapsed.load(); }).has_value())
    << "strand single-shot timer never fired within the budget";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Verifies fixed-grid framing: when a periodic notifier
// returns late, the next fire lands on the next grid slot (prev_target + N*period
// for the smallest N giving a future time), NOT at now + period. The latter would
// phase-shift the grid and break lockstep between timers on the same period.
TEST(TimerTests, PeriodicTimerFixedGridFraming)
{
  boost::asio::thread_pool threadPool{4};
  constexpr auto period = 100ms;
  constexpr auto blockingDuration = 350ms;  // > 3 grid slots

  std::mutex mutex;
  std::vector<std::chrono::steady_clock::time_point> fires;
  std::atomic<size_t> count{0};
  const auto start = std::chrono::steady_clock::now();

  auto timer = Timer::schedule_every(threadPool.get_executor(),
    period,
    [&](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      const auto idx = count.fetch_add(1);
      const auto stamp = std::chrono::steady_clock::now();
      {
        std::lock_guard<std::mutex> lock(mutex);
        fires.push_back(stamp);
      }
      if (idx == 0)
      {
        // First fire: block past the next two grid slots.
        std::this_thread::sleep_for(blockingDuration);
      }
    });

  std::this_thread::sleep_for(period + blockingDuration + 3 * period);
  timer.cancel();

  std::vector<std::chrono::steady_clock::time_point> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = fires;
  }
  ::ua::test_utils::drain_with_timeout(threadPool);

  ASSERT_GE(snapshot.size(), 2u) << "expected at least two fires";

  // fire 0 is at approximately start + period. fire 1 must land on the grid:
  // (fire1 - fire0) should be a positive integer multiple of period within
  // scheduling tolerance. Broken (phase-shifting) code yields a delta of
  // (period + blockingDuration), whose offset off the grid equals
  // blockingDuration % period = 50ms - far outside tolerance.
  const auto delta = snapshot[1] - snapshot[0];
  const auto deltaMs = std::chrono::duration_cast<std::chrono::milliseconds>(delta).count();
  const auto periodMs = std::chrono::duration_cast<std::chrono::milliseconds>(period).count();
  const auto remainder = deltaMs % periodMs;
  const auto distFromGrid = std::min(remainder, periodMs - remainder);
  constexpr auto onGridToleranceMs = 30;
  EXPECT_LT(distFromGrid, onGridToleranceMs)
    << "fire1-fire0 delta=" << deltaMs << "ms; expected a multiple of period=" << periodMs
    << "ms (start offset="
    << std::chrono::duration_cast<std::chrono::milliseconds>(snapshot[0] - start).count() << "ms)";
}

TEST(TimerTests, StrandPeriodicTimer)
{
  boost::asio::thread_pool threadPool;
  auto strand = boost::asio::make_strand(threadPool.get_executor());

  constexpr auto period = 200ms;
  std::atomic<size_t> elapsed{0};
  const auto armed = std::chrono::steady_clock::now();
  auto timer = Timer::schedule_every(strand,
    period,
    [&elapsed](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      ++elapsed;
    });

  // Same verification as PeriodicTimer, but armed via the strand overload:
  // no early fire, then fires periodically (>= one period between fires).
  std::this_thread::sleep_for(period / 2);
  expect_no_premature_fire(elapsed, armed, period, "strand periodic timer");

  const auto firstFire = wait_until([&] { return elapsed.load() >= 1; });
  ASSERT_TRUE(firstFire.has_value()) << "strand periodic timer never fired within the budget";

  const auto secondFire = wait_until([&] { return elapsed.load() >= 2; });
  ASSERT_TRUE(secondFire.has_value()) << "strand periodic timer did not re-arm for a second fire";
  EXPECT_GE(*secondFire - *firstFire, period - 50ms)
    << "consecutive fires were closer together than one period (burst/coalescing)";

  timer.cancel();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Notifiers passed via the strand overload must run strand-serialized. Three
// timers on the same strand with overlapping firing windows would run their
// notifiers concurrently on different pool threads if the strand binding were
// broken; with strand serialization the observed concurrency stays at 1.
TEST(TimerTests, StrandSerializesNotifierAcrossTimers)
{
  boost::asio::thread_pool threadPool{4};
  auto strand = boost::asio::make_strand(threadPool.get_executor());

  std::atomic<int> inFlight{0};
  std::atomic<int> maxConcurrent{0};
  std::atomic<int> fireCount{0};
  std::atomic<bool> stop{false};

  auto notifier = [&](boost::system::error_code ec)
  {
    if (ec || stop.load())
    {
      return;
    }
    int current = inFlight.fetch_add(1) + 1;
    int observed = maxConcurrent.load();
    while (current > observed && !maxConcurrent.compare_exchange_weak(observed, current))
    {
    }
    std::this_thread::sleep_for(20ms);
    inFlight.fetch_sub(1);
    fireCount.fetch_add(1);
  };

  auto t1 = Timer::schedule_every(strand, 5ms, notifier);
  auto t2 = Timer::schedule_every(strand, 5ms, notifier);
  auto t3 = Timer::schedule_every(strand, 5ms, notifier);

  std::this_thread::sleep_for(500ms);
  stop.store(true);
  t1.cancel();
  t2.cancel();
  t3.cancel();
  ::ua::test_utils::drain_with_timeout(threadPool);

  // Pool has 4 threads and 3 timers fire every 5ms while each notifier holds
  // for 20ms; without strand serialization we'd observe maxConcurrent up to 3.
  EXPECT_EQ(maxConcurrent.load(), 1);
  EXPECT_GT(fireCount.load(), 0);
}

// Hammers cancel() from the owning thread against a fast periodic timer that is
// continuously re-arming on a multi-threaded pool. cancel() now acts on the
// asio timer synchronously (under the Impl's mutex) rather than posting onto a
// private strand, so this is the test that proves the cancel-vs-rearm
// serialization holds without a strand. Run under TSan it must report no data
// race on the steady_timer; run under ASan it must report no use-after-free.
TEST(TimerTests, ConcurrentCancelStress)
{
  for (int iteration = 0; iteration < 300; ++iteration)
  {
    boost::asio::thread_pool threadPool{4};
    std::atomic<size_t> fires{0};
    auto timer = std::make_optional(Timer::schedule_every(threadPool.get_executor(),
      std::chrono::microseconds{50},
      [&fires](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }
        fires.fetch_add(1, std::memory_order_relaxed);
      }));

    // Give the timer a chance to arm and start re-arming on a pool thread, then
    // cancel concurrently with that re-arm. timer->cancel() acts synchronously;
    // timer.reset() then runs ~Impl (also synchronous) on this thread.
    std::this_thread::sleep_for(std::chrono::microseconds{200});
    timer->cancel();
    timer.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
}

// Races destruction against an in-flight notifier. A running on_expiry holds a
// strong self, so dropping the handle here cannot start ~Impl until the notifier
// returns - ~Impl then runs on the pool thread that was executing on_expiry.
// This exercises the synchronous ~Impl path on a thread other than the owner's,
// concurrently with the owner having already released its reference.
TEST(TimerTests, DestroyDuringNotifierStress)
{
  for (int iteration = 0; iteration < 100; ++iteration)
  {
    boost::asio::thread_pool threadPool{4};
    std::atomic<bool> inNotifier{false};
    auto timer = std::make_optional(Timer::schedule_every(threadPool.get_executor(),
      std::chrono::microseconds{50},
      [&inNotifier](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }
        inNotifier.store(true, std::memory_order_release);
        // Hold inside the notifier to widen the window where the owner drops the
        // handle while on_expiry is still on the stack.
        std::this_thread::sleep_for(std::chrono::microseconds{500});
      }));

    // Spin until a notifier is actually running, then drop the handle so ~Impl
    // is forced to wait for it and run on the pool thread.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{200};
    while (!inNotifier.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::yield();
    }
    timer.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
}

// cancel() invoked from inside the notifier (i.e. on the executor thread, with
// no mutex held by on_expiry at that point) must not deadlock and must stop the
// timer. Guards the callback-safety contract that the notifier runs outside the
// Impl mutex.
TEST(TimerTests, CancelFromWithinNotifier)
{
  boost::asio::thread_pool threadPool;
  std::atomic<size_t> fires{0};
  std::optional<Timer> timer;

  std::mutex timerMutex;
  {
    // Assign under the lock so the notifier (which reads `timer` under the same
    // lock) has a happens-before on the assignment even if it fires immediately.
    std::lock_guard<std::mutex> lock(timerMutex);
    timer = Timer::schedule_every(threadPool.get_executor(),
      5ms,
      [&](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }
        if (fires.fetch_add(1) == 0)
        {
          std::lock_guard<std::mutex> innerLock(timerMutex);
          if (timer)
          {
            timer->cancel();
          }
        }
      });
  }

  std::this_thread::sleep_for(200ms);
  // Exactly one fire should have landed before the in-notifier cancel stopped it.
  EXPECT_EQ(fires.load(), 1u) << "timer fired after cancelling itself from within the notifier";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// -- Cancellation is final (ua_timer.h: "the notifier is never invoked again once
//    cancel() has taken effect") ---------------------------------------------------
//
// These fix the contract a caller actually relies on: cancel the timer, then destroy
// whatever the notifier touches. The tests above this point assert only that a cancelled
// timer STOPS - CancelledTimer's notifier opens with `if (ec) return;`, so it discards the
// cancellation case by construction, and none of them would notice a notifier call that
// began after cancel() returned.

// A completion already dispatched when the cancel lands must be SUPPRESSED, not delivered.
// Hammers exactly that window: a periodic timer fast enough that a completion is nearly
// always in flight, cancelled repeatedly. The count sampled after cancel() returned must
// equal the count sampled at that instant, every round. cancel() and the sample run on the
// timer's strand: a notifier call already running when cancel() lands may finish after it
// returns (ua_timer.h), and on the strand none is running, so a later count can only come
// from a call that started after cancel() returned. Completions already dispatched queue
// behind it on the strand.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, CancelIsFinalNoNotifierCallStartsAfterCancelReturns)
{
  constexpr int rounds = 100;
  for (int round = 0; round < rounds; ++round)
  {
    boost::asio::thread_pool threadPool{4};
    auto strand = boost::asio::make_strand(threadPool.get_executor());
    std::atomic<int> ticks{0};
    {
      Timer periodic =
        Timer::schedule_every(strand, 200us, [&ticks](boost::system::error_code) { ticks.fetch_add(1); });
      std::this_thread::sleep_for(3ms);  // let the timer get going and completions queue up
      std::promise<int> cancelled;
      boost::asio::post(strand,
        [&]
        {
          periodic.cancel();
          cancelled.set_value(ticks.load());
        });
      const int atCancel = cancelled.get_future().get();
      std::this_thread::sleep_for(5ms);  // any suppressed completion would land in here
      ASSERT_EQ(ticks.load(), atCancel) << "notifier ran after cancel() returned (round " << round << ")";
    }
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
}

// Cancellation delivers NO callback of its own: the notifier must never be invoked with
// operation_aborted (nor with any error code) as a result of cancel(). This is the claim the
// book's async-model chapter makes, and the reason nothing may wait for a cancel callback.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, CancelDeliversNoNotifierCallback)
{
  boost::asio::thread_pool threadPool{2};
  auto strand = boost::asio::make_strand(threadPool.get_executor());
  std::atomic<int> errorCalls{0};
  std::atomic<int> anyCalls{0};
  {
    Timer periodic = Timer::schedule_every(strand,
      60s,  // long enough that only a cancellation could ever invoke the notifier
      [&errorCalls, &anyCalls](boost::system::error_code ec)
      {
        anyCalls.fetch_add(1);
        if (ec)
        {
          errorCalls.fetch_add(1);
        }
      });
    periodic.cancel();
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_EQ(anyCalls.load(), 0) << "cancel() invoked the notifier; it must not";
  EXPECT_EQ(errorCalls.load(), 0) << "cancel() delivered an operation_aborted callback";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A notifier already RUNNING when the cancel lands cannot be suppressed - it has started -
// and cancel() does NOT wait for it. A handler completing after the call that stopped it is
// ordinary asynchronous behaviour; blocking to prevent it would make cancel() and ~Timer()
// as slow as the notifier and deadlock whenever a notifier waits on the cancelling thread.
// So: cancel() returns promptly, and the in-flight call is free to finish afterwards.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, CancelDoesNotBlockOnAnInFlightNotifier)
{
  constexpr auto notifierWork = 300ms;
  boost::asio::thread_pool threadPool{4};
  auto strand = boost::asio::make_strand(threadPool.get_executor());
  std::atomic<bool> notifierEntered{false};
  std::atomic<bool> notifierFinished{false};
  {
    Timer periodic = Timer::schedule_every(strand,
      5ms,
      [&notifierEntered, &notifierFinished, notifierWork](boost::system::error_code)
      {
        notifierEntered = true;
        std::this_thread::sleep_for(notifierWork);
        notifierFinished = true;
      });

    ASSERT_TRUE(wait_until([&notifierEntered] { return notifierEntered.load(); }).has_value())
      << "the notifier never started; the test cannot exercise the in-flight case";

    const auto cancelStarted = std::chrono::steady_clock::now();
    periodic.cancel();
    const auto cancelTook = std::chrono::steady_clock::now() - cancelStarted;

    EXPECT_LT(cancelTook, notifierWork / 2)
      << "cancel() blocked on the in-flight notifier; it must return promptly";
    // The in-flight call finishing after cancel() returned is permitted, and expected.
    EXPECT_TRUE(wait_until([&notifierFinished] { return notifierFinished.load(); }).has_value())
      << "the in-flight notifier never completed";
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// ~Timer() cancels, so it carries the same non-blocking contract: destroying a Timer must not
// stall on a notifier that happens to be running.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, DestructorDoesNotBlockOnAnInFlightNotifier)
{
  constexpr auto notifierWork = 300ms;
  boost::asio::thread_pool threadPool{4};
  auto strand = boost::asio::make_strand(threadPool.get_executor());
  std::atomic<bool> notifierEntered{false};
  std::chrono::steady_clock::duration destructionTook{};
  {
    Timer periodic = Timer::schedule_every(strand,
      5ms,
      [&notifierEntered, notifierWork](boost::system::error_code)
      {
        notifierEntered = true;
        std::this_thread::sleep_for(notifierWork);
      });
    ASSERT_TRUE(wait_until([&notifierEntered] { return notifierEntered.load(); }).has_value());

    const auto destructionStarted = std::chrono::steady_clock::now();
    {
      Timer doomed = std::move(periodic);
    }  // ~Timer() here
    destructionTook = std::chrono::steady_clock::now() - destructionStarted;
  }
  EXPECT_LT(destructionTook, notifierWork / 2) << "~Timer() blocked on the in-flight notifier";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A notifier that cancels its own timer must not deadlock - it is the in-flight call, and
// cancel() must never wait on one. CancelFromWithinNotifier above covers the fire count;
// this covers the liveness, and fails by hanging rather than by asserting, so it runs on
// its own thread with a bounded join.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, CancelFromWithinNotifierDoesNotDeadlock)
{
  std::atomic<bool> completed{false};
  std::thread runner(
    [&completed]
    {
      boost::asio::thread_pool threadPool{2};
      auto strand = boost::asio::make_strand(threadPool.get_executor());
      auto timer = std::make_shared<std::optional<Timer>>();
      std::mutex timerMutex;
      std::atomic<int> fires{0};
      {
        std::lock_guard lock(timerMutex);
        *timer = Timer::schedule_every(strand,
          5ms,
          [timer, &timerMutex, &fires](boost::system::error_code)
          {
            std::lock_guard innerLock(timerMutex);
            if (fires.fetch_add(1) == 0 && timer->has_value())
            {
              (*timer)->cancel();  // must not wait for this very call to finish
            }
          });
      }
      std::this_thread::sleep_for(100ms);
      {
        std::lock_guard lock(timerMutex);
        timer->reset();
      }
      ::ua::test_utils::drain_with_timeout(threadPool);
      completed = true;
    });
  const bool finished = wait_until([&completed] { return completed.load(); }, 10s).has_value();
  runner.join();
  EXPECT_TRUE(finished) << "cancel() from within the notifier deadlocked waiting for itself";
}

// cancel() is idempotent and callable from any thread. Several threads cancelling the same
// timer at once must all return, and none may observe a notifier call afterwards.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, ConcurrentCancelsAllReturnAndAreFinal)
{
  boost::asio::thread_pool threadPool{4};
  auto strand = boost::asio::make_strand(threadPool.get_executor());
  std::atomic<int> ticks{0};
  Timer periodic =
    Timer::schedule_every(strand, 500us, [&ticks](boost::system::error_code) { ticks.fetch_add(1); });
  std::this_thread::sleep_for(5ms);

  std::atomic<int> returned{0};
  std::vector<std::thread> cancellers;
  cancellers.reserve(4);
  for (int i = 0; i < 4; ++i)
  {
    cancellers.emplace_back(
      [&periodic, &returned]
      {
        periodic.cancel();  // idempotent: only the first does the work, all must return
        returned.fetch_add(1);
      });
  }
  for (auto& canceller : cancellers)
  {
    canceller.join();
  }
  const int atCancel = ticks.load();
  EXPECT_EQ(returned.load(), 4) << "a concurrent cancel() failed to return";
  std::this_thread::sleep_for(10ms);
  const int settled = ticks.load();
  EXPECT_LE(settled - atCancel, 1) << "more than the in-flight notifier ran after cancel()";
  std::this_thread::sleep_for(10ms);
  EXPECT_EQ(ticks.load(), settled) << "the notifier kept running after cancel()";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A one-shot cancelled around its own deadline is the tightest version of the race: the
// completion may already be dispatched with a success code when the cancel lands. Whatever
// the interleaving, a call must never begin after cancel() has returned.
// @relation(AC-COMP-SDK-POST-TIMER-CANCEL, scope=function)
TEST(TimerTests, CancelRacingAOneShotDeadlineIsStillFinal)
{
  constexpr int rounds = 200;
  for (int round = 0; round < rounds; ++round)
  {
    boost::asio::thread_pool threadPool{2};
    auto strand = boost::asio::make_strand(threadPool.get_executor());
    std::atomic<int> fires{0};
    {
      Timer oneShot =
        Timer::schedule_after(strand, 1ms, [&fires](boost::system::error_code) { fires.fetch_add(1); });
      std::this_thread::sleep_for(std::chrono::microseconds{900 + (round % 5) * 50});
      oneShot.cancel();
      const int atCancel = fires.load();
      std::this_thread::sleep_for(3ms);
      // The admitted-and-in-flight call may land; a suppressed one may not, and a one-shot
      // can never fire twice regardless.
      ASSERT_LE(fires.load() - atCancel, 1)
        << "more than one notifier call landed after cancel() (round " << round << ")";
      ASSERT_LE(fires.load(), 1) << "one-shot fired more than once";
    }
    ::ua::test_utils::drain_with_timeout(threadPool);
  }
}
