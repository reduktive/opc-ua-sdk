// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AWAIT_CALLBACK_H
#define UA_AWAIT_CALLBACK_H

/// @file
/// @brief Awaiting any of the SDK's callback interfaces from a @ref ua::async::Task.
///
/// Every `*_async` in the SDK has the same shape - hand it a completion, be called back whenever,
/// from any thread - and every one of them can be awaited through @ref await_callback without a
/// wrapper of its own.
///
/// The awaitable is a plain object in the awaiting frame, not a coroutine, so awaiting costs no
/// second frame. It starts the operation in `await_ready`, which means a collaborator answering on
/// the calling stack - what an in-memory namespace does for nearly every operation - leaves nothing
/// to suspend for: no suspension, no post, and no allocation.

#include "ua_coro.h"
#include "ua_on_strand.h"
#include "ua_logger.h"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <coroutine>
#include <exception>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

namespace ua::async
{

/// Whether an executor SERIALISES the work handed to it.
///
/// A requirement, not a preference, and now a compile error rather than a comment. This awaitable
/// keeps `TaskState::generation` and `TaskState::suspended` on whatever executor it is given, with
/// no lock; @ref ua::async::Task's join protocol keeps `continuation` there too. Given something
/// that does not serialise, the thread that suspends a task and the thread that answers it touch
/// both at once.
///
/// Measured, on the SDK's own headers: a body looping over awaits on a bare `thread_pool` executor
/// while another thread fires a stale completion reports two TSan races on `generation`, and is
/// clean when the ONLY change is wrapping that executor in a strand. A nested task joined the same
/// way reports seven, and lost a wake-up outright - the outer body never resumed and its caller was
/// never answered.
///
/// The type must SAY it serialises. A `boost::asio::any_io_executor` that happens to hold a strand
/// does not satisfy this, deliberately: the guarantee has to survive being passed through a
/// signature, and a type-erased executor cannot carry it.
///
/// Specialise for an executor that serialises by some other means.
template<typename E>
struct is_serialising_executor : std::false_type
{};

template<typename Inner>
struct is_serialising_executor<boost::asio::strand<Inner>> : std::true_type
{};

/// @see is_serialising_executor
template<typename E>
concept SerialisingExecutor = is_serialising_executor<std::decay_t<E>>::value;

/// Awaits one callback-shaped operation.
///
/// @tparam T        What the completion carries.
/// @tparam Strand   The task's strand type.
/// @tparam Initiate Invoked with the completion to hand the collaborator.
template<typename T, SerialisingExecutor Strand, typename Initiate>
class CallbackAwaitable
{
public:
  CallbackAwaitable(Strand strand, Logger logger, std::weak_ptr<const void> owner, Initiate initiate)
    : mStrand(std::move(strand)), mLogger(std::move(logger)), mOwner(std::move(owner)),
      mInitiate(std::move(initiate))
  {}

  /// Receives the awaiting task's state from its promise, before anything else is asked of this
  /// object. @see ua::async::detail::PromiseBase::await_transform
  void bind_state(const std::shared_ptr<TaskState>& state) noexcept
  {
    mState = state;
  }

  /// Retires this suspension when the awaitable itself goes.
  ///
  /// The awaitable is a temporary in the frame: its life ends with the `co_await` full-expression
  /// while the frame carries on. Nothing else bumps the generation until the NEXT await begins, so
  /// in between, a completion fired a second time would match a generation whose awaitable no longer
  /// exists - and the handler would take a destroyed mutex and write into frame storage the compiler
  /// has since reused for something else. Live memory, one strand: neither ASan nor TSan can see it.
  ///
  /// When every suspension in a body is a CallbackAwaitable that window is closed by the next
  /// `await_ready`, which is why it went unnoticed. A nested @ref Task suspends without one, and
  /// opens it. Retiring here makes "the generation matched" mean "the awaitable that set it is
  /// alive", which is what the resumption already assumes.
  ///
  /// Runs on the strand (end of the full-expression) or under the resumption's pin. On frame
  /// destruction the test below is TRUE and this is what retires the suspension: `Task::destroy()`
  /// deliberately does NOT bump the generation itself - see the comment there - because destroying
  /// the frame runs this destructor, and a bump in both places would be one no test could tell
  /// apart from the other.
  ~CallbackAwaitable()
  {
    if (mState && mGeneration != 0 && mState->generation == mGeneration)
    {
      mState->invalidate();
    }
  }

  CallbackAwaitable(const CallbackAwaitable&) = delete;
  CallbackAwaitable& operator=(const CallbackAwaitable&) = delete;
  CallbackAwaitable(CallbackAwaitable&&) = delete;
  CallbackAwaitable& operator=(CallbackAwaitable&&) = delete;

  /// Starts the operation and reports whether it has already answered.
  ///
  /// Started here rather than in the constructor because only by now is this object at its final
  /// address in the frame; a completion handed out earlier could capture an address that moves.
  bool await_ready() noexcept
  {
    // A NEW generation for every await, not merely for every task. Two awaits in one task would
    // otherwise share an identity, and the first one's completion - fired late - would be accepted
    // by the second as its own. The weak pointer cannot catch that: the task is very much alive.
    mGeneration = ++mState->generation;

    // Caught rather than guarded-and-dropped. `guarded` logs and swallows, which is right for a
    // continuation that has nowhere to report to - but an initiation that throws has never handed
    // the collaborator a completion, so nothing will ever resume this task. Swallowing turns a
    // throwing dependency accessor into a flow suspended forever, and a request that never
    // completes. Carried to await_resume instead, where it re-enters the body as an ordinary throw
    // at the point of the co_await, which is where the caller can contain it.
    try
    {
      mInitiate(completion());
    }
    catch (...)
    {
      mInitiationFailure = std::current_exception();
      return true;
    }

    const std::lock_guard<std::mutex> lock(mMutex);
    return mResult.has_value();
  }

  /// @return Whether the task really has to suspend; false when the answer arrived in the window
  ///         between @ref await_ready and here, in which case the task carries straight on.
  bool await_suspend(std::coroutine_handle<> awaiting) noexcept
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mResult.has_value())
    {
      return false;
    }
    mState->suspended = awaiting;
    return true;
  }

  /// @note Nothing here asks whether the task was withdrawn. That question belongs to the task and
  ///       is asked around EVERY `co_await` by @ref ua::async::detail::Withdrawable, which wraps
  ///       this awaitable and every other. Asking it again here would be a second answer to maintain
  ///       and would still leave every awaitable that is not this one unguarded, which is the defect
  ///       that placement exists to remove.
  T await_resume()
  {
    if (mInitiationFailure)
    {
      std::rethrow_exception(mInitiationFailure);
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    return std::move(*mResult);
  }

private:
  /// The completion handed to the collaborator.
  ///
  /// It carries a weak handle to the frame's OWNER, the task's state held strongly, the generation
  /// it suspended at, and a pointer to this awaitable. The pointer is NEVER dereferenced until the
  /// strand has confirmed that the owner is alive, that the task was not destroyed, and that this
  /// suspension is still the current one.
  ///
  /// The state is held strongly rather than weakly because, with the owner pinned across the whole
  /// resumption, a weak probe cannot answer anything the generation does not. It would only add a
  /// second way to be wrong: the concurrent case it appears to guard is not guarded by it - a lock
  /// can succeed while the frame it says nothing about is being freed - and the sequential case the
  /// generation already covers. Holding it strongly also stops its address being recycled by a later
  /// task while an older completion is still in flight.
  auto completion()
  {
    return [owner = mOwner,
             state = mState,
             generation = mGeneration,
             strand = mStrand,
             logger = mLogger,
             self = this](T value) mutable
    {
      // The ONE question that can be answered off the strand. The owner's control block is atomic by
      // construction; everything else this completion knows - the retired flag, the generation, the
      // suspended handle - is written on the strand and so is read there.
      //
      // An owner that has gone took the Task with it, so asking about the task first would report
      // `taskGone` for what is really `ownerGone`: the right outcome reached by the wrong question,
      // which is what @ref RejectionCounts exists to make visible. It also saves the hop.
      auto ownerAtCompletion = owner.lock();
      if (!ownerAtCompletion)
      {
        rejection_counts().ownerGone.fetch_add(1, std::memory_order_relaxed);
        return;
      }

      if (state->retired.load(std::memory_order_acquire))
      {
        // The task is already gone; there is nothing for a strand turn to decide.
        rejection_counts().taskGone.fetch_add(1, std::memory_order_relaxed);
        return;
      }

      // `owner` is COPIED into the posted handler, not moved out of this completion. A collaborator
      // that fires twice would otherwise find its own capture emptied by the first call and bail
      // before the generation is ever consulted - dropping the second firing for the wrong reason,
      // and leaving the protocol that is supposed to drop it untested.
      // dispatch, not post: when this fires on the strand - which it does whenever the collaborator
      // answers on the calling stack, because a task is started ON its strand - the handler below
      // runs INLINE. Nothing is queued, the task never suspends, and `await_ready` sees the value.
      // Off the strand it queues, which is the only safe thing to do with state the strand owns.
      // guarded: everything below is noexcept EXCEPT `self->mResult.emplace(std::move(value))` - a
      // throwing move constructor of T would otherwise escape an Asio handler and terminate the
      // process. A dependency accessor reached after teardown throws by design; meeting one must log
      // and stop, never take the server down.
      boost::asio::dispatch(strand,
        ua::async::guarded(logger,
          [owner, state, generation, logger, self, value = std::move(value)]() mutable
          {
            // PINNED FIRST, and held for the whole handler. Everything below - the generation check,
            // the write into the frame, the resume - is only sound while the frame cannot be destroyed
            // underneath it, and the frame is destroyed with the Task, which is owned by this. A
            // component does not choose where it is destroyed; holding its owner is what makes the
            // answer to "is this frame alive" still true by the time we act on it.
            //
            // Asked AGAIN rather than carried: a strong reference taken above and captured here would
            // keep the owner alive for as long as this handler sits in the queue, which is a component
            // held up by work nobody wants any more. The weak handle travels; the pin is taken where
            // it is needed and released with the turn that took it.
            auto pinned = owner.lock();
            if (!pinned)
            {
              // The owner is gone, so the Task it held is gone, so the frame is gone.
              rejection_counts().ownerGone.fetch_add(1, std::memory_order_relaxed);
              return;
            }
            if (state->retired.load(std::memory_order_acquire))
            {
              // The owner is alive but this task is not - it was destroyed on its own.
              rejection_counts().taskGone.fetch_add(1, std::memory_order_relaxed);
              return;
            }
            if (state->generation != generation)
            {
              // This suspension is over and a later one took its place.
              rejection_counts().staleGeneration.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            // The generation matched ON THE STRAND while the owner is pinned, so the frame - and this
            // awaitable inside it - is alive for as long as this handler runs.
            {
              const std::lock_guard<std::mutex> lock(self->mMutex);
              // Inline answers can arrive before await_ready returns, without changing generation.
              // Once accepted, the first result also excludes duplicates during that interval.
              if (self->mResult.has_value())
              {
                return;
              }
              self->mResult.emplace(std::move(value));
            }

            auto handle = state->suspended;
            if (!handle)
            {
              // Answered before the task suspended; await_suspend sees the value and carries on.
              rejection_counts().notSuspended.fetch_add(1, std::memory_order_relaxed);
              return;
            }
            state->suspended = {};
            rejection_counts().resumed.fetch_add(1, std::memory_order_relaxed);
            ua::async::guarded(std::move(logger), [handle] { handle.resume(); })();
          }));
    };
  }

  std::shared_ptr<TaskState> mState;
  Strand mStrand;
  Logger mLogger;
  /// Whatever owns this task, weakly. @see completion
  std::weak_ptr<const void> mOwner;
  Initiate mInitiate;

  std::mutex mMutex;
  std::optional<T> mResult;
  std::uint64_t mGeneration{0};
  /// A throw out of the initiation, carried to @ref await_resume. @see await_ready
  std::exception_ptr mInitiationFailure;
};

/// Awaits a callback-shaped operation from inside a @ref Task.
///
/// @tparam T       What the completion carries.
/// @param strand   The strand the task resumes on.
/// @param logger   Reports a throw from the initiation or the resumption.
/// @param owner     Weak handle to whatever owns the Task - for a component, its
///                  `weak_from_this()`. Held across the resumption so the frame cannot be destroyed
///                  between the check that proves it alive and the resume that relies on it. There
///                  is deliberately no overload without it: the caller that has nothing to name here
///                  has nothing keeping the frame alive either.
/// @param initiate  Invoked with the completion to hand the collaborator.
/// @return An awaitable yielding the completion's value.
///
/// @note There is no cancellation token here, and deliberately so. Withdrawal is a fact about the
///       task, not about one of its steps: the task's promise adopts the token of whatever the
///       coroutine belongs to, and every `co_await` is asked around it. A token passed per await
///       would be one more parameter to get right at every call site, and getting it wrong would
///       compile, pass, and quietly keep a withdrawn request working.
///       @see ua::async::detail::Withdrawable
template<typename T, SerialisingExecutor Strand, typename Initiate>
auto await_callback(Strand strand, Logger logger, std::weak_ptr<const void> owner, Initiate initiate)
{
  return CallbackAwaitable<T, Strand, Initiate>{
    std::move(strand), std::move(logger), std::move(owner), std::move(initiate)};
}

}  // namespace ua::async

#endif  // !UA_AWAIT_CALLBACK_H
