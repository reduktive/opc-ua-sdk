// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CORO_H
#define UA_CORO_H

/// @file
/// @brief A coroutine whose liveness travels with it.
///
/// The SDK's callback model states one rule for a continuation that may fire from any thread at any
/// time, including after the component that issued it is gone: capture the component weakly and ask
/// every question about it on its strand. @ref Task applies that rule to a coroutine frame.
///
/// The state a continuation needs - is this task still alive, is it suspended, is this suspension
/// still the current one - lives in a @ref TaskState owned by the coroutine's own promise. A
/// continuation carries `{weak_ptr, generation}` to it and nothing else that could outlive the
/// frame. Destroying the Task releases the state, so an outstanding continuation finds an expired
/// weak pointer and retires itself. There is no registry to index and no slot to thread through a
/// call; the one thing a continuation needs from outside is a weak handle to whatever owns the
/// Task, which it holds only for the moment it resumes - see the guarantee below.
///
/// @par What a caller must guarantee
/// A Task is owned by something `shared_ptr`-managed, and that owner's weak handle is what
/// @ref ua::async::await_callback is given. The generation check that proves a frame is alive is
/// made on the task's strand, and that proof is good only while nothing can destroy the frame
/// underneath it - so the resumption pins the owner across the check AND the resume. Pinning is
/// what makes this safe, not strand discipline: a component does not choose where it is destroyed,
/// its owner does, and in this SDK that is routinely a different strand. Everything else the
/// primitive handles itself.
///
/// @par Withdrawal
/// Existing and being wanted are different questions. A cancelled or timed-out request has already
/// answered its client while its tasks are still suspended, so the promise carries a cancellation
/// token - adopted from whatever the coroutine belongs to, never passed at a call site - and every
/// `co_await` is asked around it. @see detail::PromiseBase, detail::Withdrawable

#include "ua_exceptions.h"
#include "ua_logger.h"
#include "ua_on_strand.h"

#include <atomic>
#include <concepts>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

namespace ua::async
{

/// Thrown into a task whose initiator no longer wants its answer.
///
/// A request-scoped coroutine outlives nothing: its request can be cancelled, time out, or simply
/// finish while the task is suspended, and what resumes afterwards is a body whose whole purpose has
/// been withdrawn.
///
/// Thrown rather than reported, because a report can be ignored: the body unwinds at its next
/// suspension and its destructors run, with nothing for a caller to remember to check.
///
/// @par What a caller must guarantee
/// Every ROOT task catches it and does nothing. A root task is one nobody co_awaits - the tasks a
/// component starts and holds - and an exception that escapes one is stored in its promise and read
/// by nobody, which is a hang rather than an error.
///
/// A @ref ua::UaException carrying `Bad_OperationAbandoned`, whose own definition is "the
/// asynchronous operation was abandoned by the caller". Being a distinct TYPE is what lets a root
/// task say `catch (const Abandoned&)` and mean only this; carrying a STATUS is what makes the
/// answer truthful on the one path that matters - the SDK has some 6395 catch-alls, any of which
/// could absorb a withdrawal and convert it, and this way the client is told the operation was
/// abandoned rather than being told something false about an internal error.
class Abandoned : public UaException
{
public:
  Abandoned() : UaException{Status::BadOperationAbandoned, nullptr}
  {}
};

/// What a continuation is allowed to know about the task it belongs to.
///
/// Shared between a task's promise, which owns it, and the continuations it hands out, which hold it
/// weakly. Every field is written and read on the task's strand.
struct TaskState
{
  /// The suspended frame, when the task is waiting on a collaborator.
  std::coroutine_handle<> suspended{};

  /// Identifies the current suspension. A continuation captures the value it saw when it suspended;
  /// any mismatch means the suspension it belonged to is over and the resume must be dropped.
  ///
  /// A weak pointer answers "does this task still exist". It cannot answer "is this still the same
  /// suspension", because a task outlives any one of its awaits - so both are needed, and neither
  /// substitutes for the other.
  std::uint64_t generation{0};

  /// Set when the Task that owned this state was destroyed.
  ///
  /// A continuation holds this state STRONGLY, so it can always be read - which is what lets the
  /// generation below be the single liveness fact. That costs the one thing a weak pointer gave for
  /// free: "the task is gone" would otherwise be indistinguishable from "the task moved on", and the
  /// two are different diagnostics. @see RejectionCounts
  ///
  /// Atomic, and the only field here a continuation may read off the strand. That is what lets a
  /// completion for a task already destroyed be dropped where it fires, instead of queueing a strand
  /// turn to be told so. A read that races the store simply loses and queues one, and the strand
  /// re-asks under the owner pin - so the atomic buys the common case without being relied on for
  /// the decision.
  std::atomic<bool> retired{false};

  /// Retires every outstanding continuation for the current suspension.
  void invalidate() noexcept
  {
    ++generation;
    suspended = {};
  }
};

/// Why a completion did not resume the task it belonged to.
///
/// Counted, rather than merely happening, because "the task did not resume" is true of a protocol
/// that works and of several that do not. A test that only observes the outcome passes when a
/// completion is dropped for the wrong reason - which is not hypothetical: a completion that moved
/// its own weak pointer out on first use dropped its second firing on an empty pointer, before the
/// generation was ever consulted, and the test that was supposed to prove the generation check
/// worked passed anyway.
///
/// One relaxed increment per completion, against work measured in hundreds of nanoseconds.
struct RejectionCounts
{
  /// The frame's owner no longer exists, so neither does the frame. Counted separately from
  /// @ref taskGone because it is the only one of these answered without touching the task at all.
  std::atomic<std::uint64_t> ownerGone{0};

  /// The task no longer exists: it was destroyed and its state released.
  std::atomic<std::uint64_t> taskGone{0};

  /// The task exists, but this completion belongs to a suspension that has already ended.
  std::atomic<std::uint64_t> staleGeneration{0};

  /// Answered before the task suspended - which is what an inline answer looks like from here: the
  /// value is taken and the await carries straight on without ever suspending.
  std::atomic<std::uint64_t> notSuspended{0};

  /// Delivered, and the task resumed.
  std::atomic<std::uint64_t> resumed{0};
};

/// The process-wide counts. @see RejectionCounts
inline RejectionCounts& rejection_counts() noexcept
{
  static RejectionCounts counts;
  return counts;
}

namespace detail
{

/// Stops a task whose initiator no longer wants its answer.
///
/// Written as one function called from two places rather than as one check in one place, because
/// the two places guard different things and a gate mutation has to be able to remove either without
/// the other. @see Withdrawable
inline void throw_if_withdrawn(const std::atomic_bool* cancelled)
{
  if (cancelled && cancelled->load(std::memory_order_acquire))
  {
    throw Abandoned{};
  }
}

/// The awaiter behind an awaitable, however that awaitable chooses to provide one.
///
/// `co_await x` uses `x` itself when it has the three `await_*` members, and `x.operator co_await()`
/// when it has that instead - a nested @ref Task being the second kind. @ref PromiseBase::await_transform
/// has to wrap whichever it is, so it has to ask the language's own question. Only the MEMBER
/// operator is asked for, which the SDK's awaitables use; a free one would land in the else branch
/// and fail to compile on `await_ready`, which is a diagnosis rather than a silent miss.
///
/// The first kind comes back BY REFERENCE to the operand temporary, which outlives the whole
/// `co_await` full-expression - suspension included - so nothing is moved and nothing dangles. The
/// second is a fresh object and comes back by value.
template<typename Awaitable>
decltype(auto) get_awaiter(Awaitable&& awaitable)
{
  if constexpr (requires { std::forward<Awaitable>(awaitable).operator co_await(); })
  {
    return std::forward<Awaitable>(awaitable).operator co_await();
  }
  else
  {
    return (awaitable);
  }
}

/// One `co_await`, with the task's withdrawal asked around it.
///
/// Every `co_await` in a @ref Task is wrapped in one of these, whatever it was awaiting, by
/// @ref PromiseBase::await_transform - the one hook the language runs on the operand of every
/// `co_await` before anything else does. That placement is the point: "does anyone still want this
/// answer" is a question about the TASK, not about the operation, and a check that lives inside one
/// awaitable covers exactly the awaits that happen to use it.
///
/// This SDK asked inside `CallbackAwaitable` first, and it was correct only for as long as every
/// suspension in every body was a callback. The first awaitable to answer WITHOUT suspending - which
/// is the whole point of giving an interface a synchronous form - would have gone straight past it, and
/// silently: nothing fails to compile, nothing fails a test, and a withdrawn request keeps working
/// through every step its collaborators can answer locally.
///
/// Asked TWICE, because there are two windows and neither implies the other:
///   - before the step, so work nobody wants is never started at all;
///   - before its answer re-enters the body, because a withdrawal can arrive while suspended.
/// An awaitable that never suspends has no second window, so the first is the whole of its
/// protection - which is why @ref ReadyAwaitable carries no check of its own and must not grow one.
template<typename Awaiter>
class Withdrawable
{
public:
  Withdrawable(Awaiter&& awaiter, const std::atomic_bool* cancelled) noexcept
    : mAwaiter(std::forward<Awaiter>(awaiter)), mCancelled(cancelled)
  {}

  Withdrawable(const Withdrawable&) = delete;
  Withdrawable& operator=(const Withdrawable&) = delete;
  Withdrawable(Withdrawable&&) = delete;
  Withdrawable& operator=(Withdrawable&&) = delete;
  ~Withdrawable() = default;

  bool await_ready()
  {
    return mAwaiter.await_ready();
  }

  template<typename Promise>
  decltype(auto) await_suspend(std::coroutine_handle<Promise> awaiting)
  {
    return mAwaiter.await_suspend(awaiting);
  }

  decltype(auto) await_resume()
  {
    // Asked AHEAD of the awaiter, so that "nobody wants this answer any more" beats whatever the
    // step has to report - an error included. Whoever withdrew has already answered the client, and
    // reporting into state that is being torn down is worse than not reporting at all.
    throw_if_withdrawn(mCancelled);
    return mAwaiter.await_resume();
  }

private:
  /// Either a reference to the operand temporary or an awaiter held by value. @see get_awaiter
  Awaiter mAwaiter;
  /// Borrowed from the promise, which holds the token for the frame's whole life.
  const std::atomic_bool* mCancelled;
};

/// Deduces whether the awaiter is held by reference or by value. @see get_awaiter
template<typename Awaiter>
auto make_withdrawable(Awaiter&& awaiter, const std::atomic_bool* cancelled)
{
  return Withdrawable<Awaiter>{std::forward<Awaiter>(awaiter), cancelled};
}

/// The part of a promise that does not depend on what the task returns.
struct PromiseBase
{
  /// Created with the frame and released with it, which is what makes a continuation's weak pointer
  /// an accurate answer to "does this task still exist".
  std::shared_ptr<TaskState> state{std::make_shared<TaskState>()};

  /// Set when nobody wants this task's answer any more; null when the task cannot be withdrawn.
  ///
  /// Held by the task rather than passed to each await, because withdrawal is a fact about the task.
  /// A token threaded through every `co_await` is a parameter that can be omitted at one call site
  /// out of forty, and omitting it is silent.
  std::shared_ptr<const std::atomic_bool> cancelled;

  PromiseBase() = default;

  /// Adopts the cancellation token of whatever this coroutine belongs to.
  ///
  /// The compiler builds a promise from the coroutine's OWN argument list when that is viable and
  /// default-constructs it when it is not - and for a member coroutine the first of those arguments
  /// is `*this`. So a component that offers a `cancellation_token()` gives every one of its
  /// coroutines the token with nothing written at any call site and nothing to keep in step; one
  /// that belongs to nothing gets a null token and runs to completion, which is the right answer for
  /// a task that cannot be withdrawn.
  ///
  /// Adopted at CONSTRUCTION rather than set afterwards, because a Task starts eagerly: by the time
  /// the caller is holding the Task the body has already run to its first suspension, and a token
  /// handed over then would miss every await that had already begun - including all of them, for a
  /// body whose collaborators all answered inline.
  template<typename Owner, typename... Rest>
    requires requires(const Owner& owner) {
      { owner.cancellation_token() } -> std::convertible_to<std::shared_ptr<const std::atomic_bool>>;
    }
  explicit PromiseBase(const Owner& owner, Rest&...) : cancelled(owner.cancellation_token())
  {}

  /// Set when this task is being awaited by another, so finishing resumes the awaiting one.
  std::coroutine_handle<> continuation{};

  /// Escapes the body only if the task did not contain it itself.
  std::exception_ptr failure{};

  /// Eager: the body runs to its first real suspension on the caller's stack, so a collaborator
  /// that answers there costs no suspension at all.
  std::suspend_never initial_suspend() noexcept
  {
    return {};
  }

  /// Resumes whoever is awaiting this task, or suspends so the frame survives until its Task
  /// destroys it.
  struct FinalAwaiter
  {
    bool await_ready() const noexcept
    {
      return false;
    }

    template<typename Promise>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> finishing) noexcept
    {
      // Symmetric transfer: resuming the awaiting task by returning its handle keeps the two frames
      // from stacking, so a chain of nested tasks costs one stack frame rather than one per level.
      auto& promise = finishing.promise();
      promise.state->invalidate();
      if (promise.continuation)
      {
        return promise.continuation;
      }
      return std::noop_coroutine();
    }

    void await_resume() const noexcept
    {}
  };

  FinalAwaiter final_suspend() noexcept
  {
    return {};
  }

  /// Contains an exception that escaped the body.
  ///
  /// Recorded rather than rethrown here: a task being awaited hands it to its awaiter, and a root
  /// task reports it the way a posted continuation does. Aborting would break the rule
  /// @ref ua::async::guarded exists to state - a dependency accessor touched after teardown throws
  /// by design, and meeting one must log and stop, not take the process down.
  void unhandled_exception() noexcept
  {
    failure = std::current_exception();
  }

  /// Everything that is true of EVERY `co_await` in this task, applied to each of them.
  ///
  /// `await_transform` runs on the operand of every `co_await` before anything else does, which
  /// makes it the one place a rule can be stated once and hold for awaits that have not been written
  /// yet. Two rules live here:
  ///
  ///  - **Withdrawal.** Asked before the step is started, so work nobody wants is never begun, and
  ///    asked again around the answer by the wrapper below. @see Withdrawable
  ///  - **State.** A body cannot name its own state - the promise that owns it is what creates it -
  ///    and `await_ready` has no handle to reach it through, so the binding happens here. Awaitables
  ///    that do not want it, a nested Task among them, pass through untouched.
  ///
  /// Not `noexcept`: throwing here is how a withdrawal re-enters the body, as an ordinary throw at
  /// the point of the `co_await`, where the body's own containment can see it.
  template<typename Awaitable>
  auto await_transform(Awaitable&& awaitable)
  {
    throw_if_withdrawn(cancelled.get());
    if constexpr (requires(Awaitable& a, std::shared_ptr<TaskState>& s) { a.bind_state(s); })
    {
      awaitable.bind_state(state);
    }
    return make_withdrawable(get_awaiter(std::forward<Awaitable>(awaitable)), cancelled.get());
  }
};

}  // namespace detail

/// A coroutine that owns its frame and its own liveness.
///
/// @tparam T What the task produces; `void` for one that only acts.
template<typename T = void>
class Task
{
public:
  struct promise_type;

  Task() noexcept = default;

  explicit Task(std::coroutine_handle<promise_type> frame) noexcept : mFrame(frame)
  {}

  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;

  Task(Task&& other) noexcept : mFrame(std::exchange(other.mFrame, {}))
  {}

  Task& operator=(Task&& other) noexcept
  {
    if (this != &other)
    {
      destroy();
      mFrame = std::exchange(other.mFrame, {});
    }
    return *this;
  }

  /// Destroys the frame, including one suspended mid-task.
  ///
  /// Running the destructors of the locals in scope at the suspension point, and releasing the
  /// state so that every continuation still holding it weakly retires itself.
  ~Task()
  {
    destroy();
  }

  /// @return Whether this handle owns a frame.
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return static_cast<bool>(mFrame);
  }

  /// @return Whether the task has run to completion.
  [[nodiscard]] bool done() const noexcept
  {
    return mFrame && mFrame.done();
  }

  /// Awaits this task from another, propagating its value and any exception it did not contain.
  auto operator co_await() && noexcept
  {
    struct Awaiter
    {
      std::coroutine_handle<promise_type> frame;

      bool await_ready() const noexcept
      {
        // Eager start means a task whose collaborators all answered inline is already finished.
        return !frame || frame.done();
      }

      std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept
      {
        frame.promise().continuation = awaiting;
        return std::noop_coroutine();
      }

      T await_resume()
      {
        if (!frame)
        {
          // Awaiting a Task that owns no frame - default-constructed, or moved from. There is no
          // result to give, and manufacturing one would be worse than failing: for a `Result<T>` a
          // value-initialized T reads as Good with an empty value, so a read would report that the
          // namespace answered successfully with nothing. Thrown instead, where the awaiting body's
          // containment turns it into a Bad status for that operation.
          // Bare, with no ErrorDetail: this file is the SDK's lowest async layer and
          // `ua_exceptions.h` deliberately leaves ErrorDetail incomplete. UaException records its
          // own throw site, which together with this comment is what a maintainer needs - and the
          // condition is a programming error inside the SDK, never anything a client can provoke.
          throw UaException{Status::BadInternalError, nullptr};
        }
        auto& promise = frame.promise();
        if (promise.failure)
        {
          std::rethrow_exception(promise.failure);
        }
        if constexpr (!std::is_void_v<T>)
        {
          return std::move(promise.result).value();
        }
      }
    };

    return Awaiter{mFrame};
  }

  /// The task's state, for a caller that needs to retire it without destroying the Task.
  [[nodiscard]] std::shared_ptr<TaskState> state() const noexcept
  {
    if (!mFrame)
    {
      return nullptr;
    }
    return mFrame.promise().state;
  }

private:
  void destroy() noexcept
  {
    if (!mFrame)
    {
      return;
    }
    // Destroying the frame retires this task's continuations by itself: the awaitable at the
    // suspension point is a local of the frame, so its destructor runs and retires the generation it
    // took. An explicit invalidate() here as well was belt-and-braces that no test could distinguish,
    // and a mechanism nothing can tell you is broken is one nobody can maintain.
    //
    // The flag is not that. It is the difference between "this task is gone" and "this task moved
    // on", which a continuation cannot otherwise tell apart now that it holds the state strongly -
    // and a test asserts the distinction.
    mFrame.promise().state->retired.store(true, std::memory_order_release);
    mFrame.destroy();
    mFrame = {};
  }

  std::coroutine_handle<promise_type> mFrame{};
};

/// @cond
template<typename T>
struct Task<T>::promise_type : detail::PromiseBase
{
  promise_type() = default;
  using detail::PromiseBase::PromiseBase;

  std::optional<T> result;

  // Spelled out rather than leaning on the enclosing Task's injected-class-name. MSVC does not find
  // it from inside an out-of-class definition of a nested class, and reports the bare name as a
  // template needing arguments (C2955) - which then fails every Task<void> coroutine in the library
  // at its closing brace. gcc and clang resolve it, so the omission was invisible until Windows built.
  Task<T> get_return_object()
  {
    return Task<T>{std::coroutine_handle<promise_type>::from_promise(*this)};
  }

  template<typename U>
  void return_value(U&& value)
  {
    result.emplace(std::forward<U>(value));
  }
};

template<>
struct Task<void>::promise_type : detail::PromiseBase
{
  promise_type() = default;
  using detail::PromiseBase::PromiseBase;

  Task<void> get_return_object()
  {
    return Task<void>{std::coroutine_handle<promise_type>::from_promise(*this)};
  }

  void return_void()
  {}
};

/// @endcond

/// An answer that is already here, awaited like any other.
///
/// What an interface with a synchronous form yields when it does not have to go anywhere: no completion
/// object, no generation, no mutex, no strand hop, no suspension - one move, and the body carries
/// straight on. It exists so a fast path can be taken WITHOUT the body branching on it. The `if`
/// belongs in the one helper that knows whether the answer is local; a body that has to choose is a
/// body that can choose wrong, which is how per-node authorization was once bypassed here.
///
/// It carries no withdrawal check of its own, and must not grow one: every `co_await` in a Task is
/// already wrapped by @ref detail::Withdrawable, which asks before the step - and a step that never
/// suspends has no second window to ask in.
template<typename T>
class ReadyAwaitable
{
public:
  explicit ReadyAwaitable(T value) : mValue(std::move(value))
  {}

  bool await_ready() const noexcept
  {
    return true;
  }

  void await_suspend(std::coroutine_handle<>) const noexcept
  {}

  T await_resume()
  {
    return std::move(mValue);
  }

private:
  T mValue;
};

/// @return An awaitable yielding @p value without suspending. @see ReadyAwaitable
template<typename T>
ReadyAwaitable<std::decay_t<T>> ready(T&& value)
{
  return ReadyAwaitable<std::decay_t<T>>{std::forward<T>(value)};
}

}  // namespace ua::async

#endif  // !UA_CORO_H
