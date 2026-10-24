// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.12 (ConditionInstance) - shelve-timer arming,
// expiration, and cancellation discipline.
//
// These pins lock the externally-observable behaviour of the `mShelveTimer`
// member set up by `process_timer_commands` (`ua_condition_instance.cpp`,
// case `StartShelveTimer` near :346-371). The {b} flip will migrate
// `shared_from_this` captures to `weak_from_this()` and may restructure
// `apply_transition`'s timer-command processing into a continuation; both must
// preserve:
//   - `timed_shelve_async` fires its callback synchronously after arming the
//     timer (callback does NOT wait for the timer duration).
//   - The timer's lambda calls `on_shelve_timer_expired()` and re-applies the
//     resulting transition when it fires naturally.
//   - The destructor cancels the armed timer (RAII via `Timer`),
//     so a destructed instance produces no further timer-driven events.
//   - `close_async` cancels the armed timer explicitly, with the same outcome.
//
// What is pinned (4 pins):
//   TS-A: TimedShelveAsyncArmsShelveTimerSynchronouslyAndFiresCallbackGood
//   TS-B: TimedShelveTimerExpirationUnshelvesAlarmAndEmitsAdditionalEvent
//   TS-D: DropLastSharedPtrCancelsShelveTimerNoExtraEventAfterDuration
//   TS-E: CloseAsyncCancelsArmedShelveTimerNoExtraEventAfterDuration
//
// Pins NOT covered (and why):
//   TS-C (cancel-on-renewal of `mShelveTimer` via back-to-back timed_shelve)
//     - `AlarmConditionLogic::timed_shelve` returns `BadConditionAlreadyShelved`
//     when already shelved (`ua_alarm_condition_logic.cpp:160`), so a second
//     `timed_shelve_async` does NOT produce a fresh `StartShelveTimer` command
//     and the `.cancel()` at `ua_condition_instance.cpp:348` is unreachable
//     through the public API. The cancel-via-CancelShelveTimer path is exercised
//     by TS-D / TS-E. Pinning the unreachable .cancel() would be testing dead
//     code.
//   TS-F (`mOnDelayTimer` / `mOffDelayTimer` weak-self) - no production logic
//     pushes `StartOnDelay` / `StartOffDelay` commands today (verified by
//     `grep -rn "TimerCommand::Kind::Start"` on `sdk/implementation/address_space/conditions/`).
//     The plumbing exists in `ua_condition_instance.cpp` but the trigger
//     producer doesn't, so behaviour is not externally driveable. TS-D / TS-E
//     cover the same family of weak-capture discipline for the one timer that
//     IS reachable (`mShelveTimer`).

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "ua_alarm_condition_logic.h"
#include "ua_byte_string.h"
#include "ua_condition_instance.h"
#include "ua_condition_state_snapshot.h"
#include "ua_sinks.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_string.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

class FakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    auto count = ++emitCount;
    if (event.eventId.empty())
    {
      const auto id = static_cast<uint8_t>(count);
      event.eventId = ByteString{std::vector<uint8_t>{id}};
    }
  }

  std::atomic<int> emitCount{0};
};

class ConditionInstanceTimedShelvePin : public ::testing::Test
{
protected:
  void SetUp() override
  {}

  void TearDown() override
  {
    mPool.join();
  }

  std::shared_ptr<ConditionInstance> create_active_alarm()
  {
    auto instance = ConditionInstance::create(mPool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      NodeId{1, 2000u},
      NodeId{1, 200u},
      String{"PinAlarmSource"},
      mSink);
    instance->enable_sync();
    instance->activate_sync(/*severity=*/500);
    return instance;
  }

  // boost::asio::thread_pool declared FIRST so it destructs LAST. TearDown() calls abort()
  // before any other locals destruct (test infrastructure rule).
  boost::asio::thread_pool mPool{2};
  std::shared_ptr<FakeEventSink> mSink = std::make_shared<FakeEventSink>();
};

// Spin-wait helper - polls the predicate on the main test thread until it
// becomes true or timeout elapses. Polling is on the immutable snapshot
// pointer's mutable booleans, which the strand thread mutates; bool reads are
// torn-but-tolerable for test observation. Returns whether the predicate
// became true.
template<typename Pred>
bool wait_for(Pred predicate, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return predicate();
}

}  // namespace

// ---------------------------------------------------------------------------
// Pin TS-A: timed_shelve_async fires its callback synchronously (no wait
// for the timer duration to elapse) and the snapshot's
// suppressed_or_shelved flag flips true.
// ---------------------------------------------------------------------------
//
// Property: `timed_shelve_async` posts to the strand, calls
// `mLogic->timed_shelve(durationMs)` synchronously, runs `apply_transition`
// (which arms `mShelveTimer` via `process_timer_commands`), and fires the
// caller's callback inline at the end of the strand turn - without waiting
// for the timer to expire. Falsifies a regression where the {b} restructure
// chained the callback onto the timer's expiration continuation by mistake.

TEST_F(ConditionInstanceTimedShelvePin, TimedShelveAsyncArmsShelveTimerSynchronouslyAndFiresCallbackGood)
{
  auto instance = create_active_alarm();
  ASSERT_FALSE(instance->snapshot()->suppressed_or_shelved());

  // Use a long duration so the test fails if the callback is mistakenly
  // chained to the timer expiration. 5s is well over the ~200ms wait below.
  std::promise<VoidResult> shelvePromise;
  const auto callbackStart = std::chrono::steady_clock::now();
  instance->timed_shelve_async(/*durationMs=*/5000.0,
    [&shelvePromise](VoidResult result) { shelvePromise.set_value(std::move(result)); });

  auto result = shelvePromise.get_future().get();
  const auto elapsed = std::chrono::steady_clock::now() - callbackStart;

  EXPECT_TRUE(result.is_good()) << "timed_shelve_async should succeed against active alarm";
  EXPECT_LT(elapsed, std::chrono::milliseconds{2000})
    << "callback must fire well before the requested 5000ms duration - synchronous arming";
  EXPECT_TRUE(instance->snapshot()->suppressed_or_shelved())
    << "snapshot must reflect shelved state immediately after callback";

  // Cancel the armed 5s timer cleanly via close_async before TearDown.
  instance->close_sync();
}

// ---------------------------------------------------------------------------
// Pin TS-B: when the shelve timer expires naturally, the lambda calls
// on_shelve_timer_expired() and re-applies the transition, which un-shelves
// the alarm and emits another event.
// ---------------------------------------------------------------------------
//
// Property: the timer-fire lambda at ua_condition_instance.cpp:352-370
// executes on the strand, dispatches into the alarm logic, and runs
// `apply_transition` on the resulting transition. Falsifies a regression
// where the lambda no longer re-applies the transition (e.g. {b}-flip moves
// the apply_transition call out of the lambda by mistake).

TEST_F(ConditionInstanceTimedShelvePin, TimedShelveTimerExpirationUnshelvesAlarmAndEmitsAdditionalEvent)
{
  auto instance = create_active_alarm();
  // After enable+activate, baseline emits are: 1 for the activate event
  // (alarm became retained) plus any earlier emit. We capture the count just
  // before the shelve so the assertion below is independent of those.
  const int baseline = mSink->emitCount.load();

  // Arm the timer with a short duration so we can wait for it.
  std::promise<VoidResult> shelvePromise;
  instance->timed_shelve_async(
    /*durationMs=*/50.0, [&shelvePromise](VoidResult result) { shelvePromise.set_value(std::move(result)); });
  ASSERT_TRUE(shelvePromise.get_future().get().is_good());
  ASSERT_TRUE(instance->snapshot()->suppressed_or_shelved());
  // Shelving emits one event; +1 over baseline.
  const int afterShelveEmits = mSink->emitCount.load();
  EXPECT_EQ(afterShelveEmits, baseline + 1);

  // Wait for the timer to fire and unshelve the alarm.
  const bool unshelved =
    wait_for([&] { return !instance->snapshot()->suppressed_or_shelved(); }, std::chrono::milliseconds{1000});
  EXPECT_TRUE(unshelved) << "timer expiration must un-shelve the alarm via on_shelve_timer_expired";
  EXPECT_GT(mSink->emitCount.load(), afterShelveEmits)
    << "timer-driven transition must emit at least one additional event";
}

// ---------------------------------------------------------------------------
// Pin TS-D: dropping the last shared_ptr to a ConditionInstance with an
// armed shelve timer cancels the timer cleanly - the timer's lambda must
// not run on_shelve_timer_expired (no further events) and must not crash.
// ---------------------------------------------------------------------------
//
// Property: ConditionInstance's destructor (via RAII member destruction of
// `mShelveTimer` - a `Timer`) cancels the timer. The timer's
// lambda either fires with non-Ok ec (cancelled) and exits at the early
// check, or its `me.lock()` returns null and exits at the second check.
// Either way, no apply_transition runs and no UAF occurs. Falsifies a
// regression where the timer-arming code holds a strong self-reference (so
// the destructor never runs) or where the lambda lacks the weak-self guard.
// Run under ASan (`sanitizer / gcc-asan` CI) for UAF detection.

TEST_F(ConditionInstanceTimedShelvePin, DropLastSharedPtrCancelsShelveTimerNoExtraEventAfterDuration)
{
  int afterShelveEmits;
  {
    auto instance = create_active_alarm();
    std::promise<VoidResult> shelvePromise;
    instance->timed_shelve_async(/*durationMs=*/50.0,
      [&shelvePromise](VoidResult result) { shelvePromise.set_value(std::move(result)); });
    ASSERT_TRUE(shelvePromise.get_future().get().is_good());
    afterShelveEmits = mSink->emitCount.load();
    // Local goes out of scope here, dropping the last strong reference.
  }

  // Wait long enough for the timer to fire if it had not been cancelled.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // No further events should be emitted - the timer was cancelled by the
  // instance destructor and the lambda's me.lock() returns null even if the
  // cancellation race somehow let it fire with ec==Ok.
  EXPECT_EQ(mSink->emitCount.load(), afterShelveEmits)
    << "destructed instance must not emit timer-driven events";
}

// ---------------------------------------------------------------------------
// Pin TS-E: close_async cancels an armed shelve timer explicitly. After
// close completes, the timer must not fire on_shelve_timer_expired.
// ---------------------------------------------------------------------------
//
// Property: close_async (`:2952-...`) cancels `mShelveTimer` directly at
// `:2969` before disabling the condition. The disable transition itself
// emits one event (because the condition was retained), so emit_count
// increments by 1 for close. Subsequent timer expiration must NOT add
// further emits. Falsifies a regression where close_async forgets to
// cancel the timer (e.g. a {b}-flip restructure that splits the cancel
// loop into a continuation and accidentally drops the shelve timer).

TEST_F(ConditionInstanceTimedShelvePin, CloseAsyncCancelsArmedShelveTimerNoExtraEventAfterDuration)
{
  auto instance = create_active_alarm();

  std::promise<VoidResult> shelvePromise;
  instance->timed_shelve_async(
    /*durationMs=*/50.0, [&shelvePromise](VoidResult result) { shelvePromise.set_value(std::move(result)); });
  ASSERT_TRUE(shelvePromise.get_future().get().is_good());

  instance->close_sync();
  const int afterClose = mSink->emitCount.load();

  // Wait long enough for the original 50ms timer to expire if not cancelled.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  EXPECT_EQ(mSink->emitCount.load(), afterClose)
    << "closed instance must not emit timer-driven events after close cancels the shelve timer";
}

}  // namespace ua::test::behaviour_pins
