// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_timer.h"

#include <boost/asio/error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <utility>

namespace ua
{

class Timer::Impl : public std::enable_shared_from_this<Impl>
{
public:
  static shared_ptr<Impl> create(boost::asio::any_io_executor executor, bool periodic,
    std::chrono::steady_clock::duration duration, Notifier notifier);

  ~Impl();

  // Resource owner (mutex + asio steady_timer); only ever held via shared_ptr. Non-copyable and
  // non-movable by design (C.67 / Rule-of-5 completion) - the mutex and timer cannot be relocated.
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;
  Impl(Impl&&) = delete;
  Impl& operator=(Impl&&) = delete;

  void cancel();

private:
  // mMutex serializes every access to mTimer (async_wait, cancel, expires_*).
  // Asio's waitable-timer state is unsynchronized and has no thread affinity:
  // it may be touched from any thread provided accesses never overlap. A mutex
  // provides exactly that serialization, so cancel() can act on mTimer
  // *synchronously* on the caller's thread rather than posting onto a private
  // strand. This keeps destruction synchronous (no work is ever parked on the
  // executor), so ~Impl never runs at io_context-teardown time against a
  // half-destroyed execution context.
  std::mutex mMutex;
  boost::asio::steady_timer mTimer;
  std::atomic<bool> mPeriodic;
  std::chrono::steady_clock::duration mDuration;
  Notifier mNotifier;
  // Guarded by mMutex, and read by on_expiry under the same lock before it admits a call:
  // that is what makes cancellation final rather than merely likely.
  bool mCancelled{false};

  Impl(boost::asio::any_io_executor executor, bool periodic, std::chrono::steady_clock::duration duration,
    Notifier notifier);

  void arm_initial();
  void arm_next_locked();  // precondition: mMutex held
  void on_expiry(const boost::system::error_code& ec);
};

Timer::Impl::Impl(boost::asio::any_io_executor executor, bool periodic,
  std::chrono::steady_clock::duration duration, Notifier notifier)
  : mTimer(executor), mPeriodic(periodic), mDuration(duration), mNotifier(std::move(notifier))
{}

Timer::Impl::~Impl()
{
  // Synchronously cancel owned I/O. A running on_expiry
  // holds a strong self (its outer weak.lock() succeeded), so the refcount is
  // >=1 and ~Impl cannot start concurrently with it; a merely queued completion
  // holds only weak and no-ops without touching mTimer. So when ~Impl runs no
  // other thread is inside a timer method - the lock is uncontended and the
  // cancel is safe. The executor must still outlive the Timer (asio's universal
  // I/O-object contract); destruction is now synchronous, so honouring that is
  // simply "drop the Timer handle before destroying the executor".
  const std::lock_guard lk(mMutex);
  // Boost 1.88 removed the non-throwing cancel(ec); basic_waitable_timer::cancel() now throws
  // boost::system::system_error on error. ~Impl is a noexcept destruction path, so an escaping
  // throw would std::terminate. Cancellation failure during teardown is benign (the timer is
  // being torn down regardless), so swallow it deliberately.
  try
  {
    mTimer.cancel();
  }
  catch (const boost::system::system_error& cancelError)
  {
    static_cast<void>(cancelError);  // no remedy and no Logger at this primitive; ignore deliberately
  }
}

shared_ptr<Timer::Impl> Timer::Impl::create(boost::asio::any_io_executor executor, bool periodic,
  std::chrono::steady_clock::duration duration, Notifier notifier)
{
  struct Wrapper : Impl
  {
    Wrapper(
      boost::asio::any_io_executor exec, bool per, std::chrono::steady_clock::duration dur, Notifier note)
      : Impl(std::move(exec), per, dur, std::move(note))
    {}
  };

  auto impl = make_shared<Wrapper>(std::move(executor), periodic, duration, std::move(notifier));
  impl->arm_initial();
  return impl;
}

void Timer::Impl::cancel()
{
  // Synchronous cancel under the mutex. mCancelled is the authoritative stop
  // flag re-checked by on_expiry under the same lock, so a re-arm decision that
  // races a cancel() can never resurrect a cancelled timer. mNotifier is
  // intentionally NOT cleared (it is immutable after construction and may be
  // running, lock-free, in a concurrent on_expiry).
  const std::lock_guard lk(mMutex);
  mPeriodic.store(false, std::memory_order_relaxed);
  mCancelled = true;
  // Boost 1.88 removed the non-throwing cancel(ec); basic_waitable_timer::cancel() now throws
  // boost::system::system_error on error. Impl::cancel() is reached from ~Timer (via
  // Timer::cancel()) - a noexcept destruction path where an escaping throw would std::terminate.
  // Swallow it: a cancellation failure during teardown is benign and there is no Result channel
  // on this primitive to report it through.
  try
  {
    mTimer.cancel();
  }
  catch (const boost::system::system_error& cancelError)
  {
    static_cast<void>(cancelError);  // no remedy and no Logger at this primitive; ignore deliberately
  }
}

void Timer::Impl::arm_initial()
{
  const std::lock_guard lk(mMutex);
  mTimer.expires_after(mDuration);
  arm_next_locked();
}

void Timer::Impl::arm_next_locked()
{
  // The completion handler captures weak_from_this() (7.2): if the Impl is
  // gone by the time it fires it no-ops without touching any member. The
  // handler re-enters on_expiry, which re-acquires mMutex itself, so issuing
  // async_wait while holding the lock here is safe (async_wait is non-blocking
  // and never invokes the handler inline).
  mTimer.async_wait(
    [weak = weak_from_this()](const boost::system::error_code& ec)
    {
      if (auto self = weak.lock())
      {
        self->on_expiry(ec);
      }
    });
}

void Timer::Impl::on_expiry(const boost::system::error_code& ec)
{
  // mNotifier is immutable after construction; invoke it WITHOUT holding mMutex
  // (callback-safety golden rule: never run a user callback under a lock, and
  // the notifier may itself call cancel()).
  if (!mNotifier)
  {
    return;
  }

  {
    const std::lock_guard lk(mMutex);
    // Cancellation is final: a cancelled timer never calls its notifier. A completion
    // already dispatched when the cancel landed still arrives here holding a strong self,
    // so without this check it would call the notifier after cancel() returned. cancel()
    // does NOT wait for a call already in progress - a handler completing after the call
    // that stopped it is ordinary asynchronous behaviour, and blocking to prevent it would
    // make both cancel() and ~Timer() as slow as the notifier, and deadlock whenever the
    // notifier waits on the cancelling thread.
    if (mCancelled)
    {
      return;
    }
  }

  mNotifier(ec);

  if (ec)
  {
    return;
  }
  if (!mPeriodic.load(std::memory_order_relaxed))
  {
    return;
  }

  const std::lock_guard lk(mMutex);
  // cancel() may have fired during the notifier call above; re-check under the
  // lock so a cancelled timer is never re-armed.
  if (mCancelled)
  {
    return;
  }

  // Fixed-grid framing: advance along the original
  // phase grid, skipping slots already in the past. Never `now + period` -
  // that phase-shifts the grid and breaks lockstep between independent
  // timers on the same period.
  auto next = mTimer.expiry() + mDuration;
  const auto now = std::chrono::steady_clock::now();
  while (next <= now)
  {
    next += mDuration;
  }
  mTimer.expires_at(next);
  arm_next_locked();
}

Timer::Timer(shared_ptr<Impl> impl) : mImpl(std::move(impl))
{}

Timer::Timer(Timer&& other) noexcept
  : mImpl(other.mImpl.exchange(shared_ptr<Impl>{}, std::memory_order_acq_rel))
{}

Timer& Timer::operator=(Timer&& other) noexcept
{
  if (this == &other)
  {
    return *this;
  }

  auto incoming = other.mImpl.exchange(shared_ptr<Impl>{}, std::memory_order_acq_rel);
  auto replaced = mImpl.exchange(std::move(incoming), std::memory_order_acq_rel);
  if (replaced)
  {
    replaced->cancel();
  }
  return *this;
}

Timer::~Timer()
{
  cancel();
}

void Timer::cancel()
{
  auto impl = mImpl.exchange(shared_ptr<Impl>{}, std::memory_order_acq_rel);
  if (impl)
  {
    impl->cancel();
  }
}

Timer::operator bool() const noexcept
{
  return static_cast<bool>(mImpl.load(std::memory_order_acquire));
}

Timer Timer::schedule_after(
  boost::asio::any_io_executor executor, std::chrono::steady_clock::duration delay, Notifier notifier)
{
  return Timer{Impl::create(std::move(executor), false, delay, std::move(notifier))};
}

Timer Timer::schedule_every(
  boost::asio::any_io_executor executor, std::chrono::steady_clock::duration period, Notifier notifier)
{
  return Timer{Impl::create(std::move(executor), true, period, std::move(notifier))};
}

}  // namespace ua
