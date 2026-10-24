// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Move-only RAII timer that fires a notifier on an Asio executor.
/// @ingroup async

#ifndef UA_TIMER_H
#define UA_TIMER_H

#include "ua_includes.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <functional>

namespace ua
{

/// A move-only RAII timer bound to an Asio executor.
///
/// Constructed only through the static factories @ref schedule_after (one-shot)
/// and @ref schedule_every (periodic), each of which arms a timer on the given
/// executor - typically a strand, in which case the notifier is serialized with
/// that strand's other work. A default-constructed `Timer` is empty (holds no
/// armed timer) and contextually converts to `false`. Destruction or @ref cancel
/// stops an armed timer; moving transfers ownership of the armed state.
///
/// **Executor lifetime:** the executor passed to @ref schedule_after /
/// @ref schedule_every must outlive the returned `Timer`. This is Asio's
/// universal contract for I/O objects - destroying the executor's underlying
/// `io_context` / `thread_pool` while a `Timer` is still alive is undefined
/// behaviour and may leak or use-after-free inside Asio internals.
///
/// **Fixed-grid framing:** @ref schedule_every fires on a fixed phase grid of
/// stride `period`. If the notifier returns later than the next scheduled fire,
/// slots already in the past are skipped - the grid is never phase-shifted to
/// `now + period`, and missed slots are never coalesced into a burst.
///
/// @ingroup async
class Timer
{
public:
  /// Notifier invoked on each expiry, on the bound executor.
  ///
  /// The `error_code` argument is falsy on a real expiry, which is the only way a
  /// notifier is reached: cancellation is final, so @ref cancel, destruction and
  /// re-arm do NOT deliver `operation_aborted` here - they deliver nothing at all.
  /// A non-empty code therefore reports an Asio-level failure rather than a
  /// cancellation, and ends a periodic schedule; a periodic timer re-arms only
  /// after a falsy code. The notifier runs without any internal lock held and may
  /// safely call @ref cancel on its own timer.
  ///
  /// @see cancel, for what a cancelled timer does and does not do.
  using Notifier = std::function<void(boost::system::error_code)>;

  /// Arms a one-shot timer that fires once after `delay`.
  ///
  /// @param executor Executor the notifier runs on; must outlive the returned
  ///                 timer (see executor-lifetime note on @ref Timer).
  /// @param delay    Duration from now until the single expiry.
  /// @param notifier Invoked once on expiry. NOT invoked if the timer is cancelled
  ///                 or destroyed first - cancellation is final and delivers no
  ///                 callback at all (see @ref cancel).
  /// @return An armed timer; let it expire, or cancel/destroy it to stop.
  /// @see schedule_every
  static Timer schedule_after(
    boost::asio::any_io_executor executor, std::chrono::steady_clock::duration delay, Notifier notifier);

  /// Arms a periodic timer that fires repeatedly on a fixed grid of stride
  /// `period`.
  ///
  /// Re-arming continues for as long as the notifier is invoked with a falsy
  /// `error_code`; see the fixed-grid framing note on @ref Timer for the
  /// missed-slot policy.
  ///
  /// @param executor Executor the notifier runs on; must outlive the returned
  ///                 timer (see executor-lifetime note on @ref Timer).
  /// @param period   Stride between successive grid slots.
  /// @param notifier Invoked on each expiry. NOT invoked when the timer is
  ///                 cancelled or destroyed - cancellation is final and delivers
  ///                 no callback at all (see @ref cancel).
  /// @return An armed periodic timer; cancel or destroy it to stop the schedule.
  /// @see schedule_after
  static Timer schedule_every(
    boost::asio::any_io_executor executor, std::chrono::steady_clock::duration period, Notifier notifier);

  /// Constructs an empty timer that holds no armed wait and converts to `false`.
  Timer() = default;

  /// Cancels any armed timer.
  ~Timer();

  Timer(const Timer&) = delete;
  Timer& operator=(const Timer&) = delete;

  /// Transfers the armed state; the moved-from timer becomes empty.
  /// @param other The timer whose armed state is transferred.
  Timer(Timer&& other) noexcept;

  /// Transfers the armed state, cancelling any timer this object already held;
  /// the moved-from timer becomes empty.
  /// @param other The timer whose armed state is transferred.
  /// @return Reference to this timer.
  Timer& operator=(Timer&& other) noexcept;

  /// Cancels the armed timer, if any, and leaves this object empty.
  ///
  /// Idempotent, non-blocking, and safe to call from any thread, including from
  /// within the notifier. Cancellation is final: a cancelled timer does not call
  /// its notifier. There is no cancellation callback - nothing is delivered to
  /// announce the cancel, so never wait for one - and a completion already
  /// dispatched when the cancel landed is suppressed rather than delivered.
  ///
  /// The one exception is the ordinary asynchronous one: a notifier already
  /// RUNNING when cancel() lands runs to completion, and may still be running
  /// after cancel() has returned. cancel() does not wait for it, so a notifier
  /// must own what it touches (capture weakly, or by value) rather than assume
  /// the cancelling thread has stopped it. No FURTHER call is ever made.
  ///
  /// After this call the object converts to `false`.
  void cancel();

  /// Returns `true` while this object holds an armed timer.
  explicit operator bool() const noexcept;

private:
  class Impl;
  explicit Timer(shared_ptr<Impl> impl);

  // cancel() is callable concurrently on one handle. Atomically detaching the shared owner lets exactly one
  // caller cancel and release the implementation while every racing caller observes an empty handle.
  std::atomic<shared_ptr<Impl>> mImpl;
};

}  // namespace ua

#endif  // UA_TIMER_H
