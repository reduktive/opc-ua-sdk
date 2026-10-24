// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SYNC_WAIT_H
#define UA_SYNC_WAIT_H

/// @file
/// @brief Deadlock-guarded blocking wait shared by every `*_sync` API wrapper.
/// @ingroup async

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_to_result.h"

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace ua::async::detail
{

/// Whether the calling thread is currently running the Asio execution context that @p ex belongs to.
///
/// This is the deadlock question for a synchronous wait: if the thread that is about to block
/// waiting for an asynchronous result is itself one of the threads running the execution context that must
/// execute the work producing that result, the wait can never complete - the blocked thread is the
/// one that would have run the completion. The registered Asio scheduler service's own dispatch predicate
/// answers the question, so there is no per-hop instrumentation and no cost until a `*_sync` wrapper
/// actually calls it.
///
/// @param ex Executor whose execution context is the one that would fulfil the pending result (the wrapping
///           component's own executor). An **empty** executor is tolerated and reports `false`
///           (it is running nothing).
/// @return `true` if blocking on @p ex's execution context from this thread would deadlock; `false` for an
///         external thread, a different recognised context, or an empty executor. An unrecognised non-empty
///         execution context also returns `true` conservatively, refusing the wait with BadWouldBlock.
/// @note Supports Asio `io_context`, `thread_pool`, `system_context`, and strands layered over them without
///       downcasting the non-polymorphic `execution_context` base.
[[nodiscard]] bool on_executor_context(const boost::asio::any_io_executor& ex) noexcept;

/// The @ref ua::ErrorDetail attached to a refused (would-deadlock) synchronous wait.
///
/// Carries the symbolic id `WouldBlock`, an actionable message, and @ref ua::Status::BadWouldBlock as
/// its cause, so the refusal is never a bare status code.
///
/// @return A shared, immutable ErrorDetail describing the refusal.
[[nodiscard]] std::shared_ptr<const ua::ErrorDetail> would_block_detail();

/// Starts an asynchronous operation and waits for its result, unless waiting would deadlock.
///
/// The one way a synchronous wrapper waits. On a thread running @p executor's execution context it returns
/// @ref ua::Status::BadWouldBlock with `would_block_detail` and does not start the operation: because it
/// starts the operation itself, it refuses before starting, and the order cannot be wrong. Otherwise it calls
/// @p start with a completion and returns the first result that completion delivers.
///
/// The completion owns the state it writes to, so it may run after this function has returned (after a
/// deadline, or from a delegate that answers twice): a second answer is ignored and a late one is
/// discarded, never written into the caller's stack. Only the completion owns that state, so an operation
/// that releases its completion without calling it (a post dropped because its owner is gone) ends the wait
/// with @ref ua::Status::BadInternalError instead of leaving the caller blocked.
///
/// @tparam ResultT A @ref ua::Result specialisation, the result the operation completes with.
/// @param executor Executor whose execution context fulfils the operation; used only to decide whether
///                 waiting here would deadlock. An empty executor never refuses.
/// @param start    Called once, from this thread, with a `std::function<void(ResultT)>` completion; it
///                 starts the operation. An exception it throws becomes the result.
/// @param deadline When set, how long to wait before returning @ref ua::Status::BadTimeout with an
///                 ErrorDetail; the operation itself is not cancelled.
/// @return The operation's result, or BadWouldBlock, BadTimeout, BadInternalError for a released
///         completion, or the status of an exception from @p start.
template<class ResultT, class Start>
[[nodiscard]] ResultT blocking_call(const boost::asio::any_io_executor& executor, Start&& start,
  std::optional<std::chrono::milliseconds> deadline = std::nullopt) noexcept;

/// A non-owning reference to the start function of a @ref blocking_call.
///
/// @ref blocking_call's body depends only on the result type, so it takes the start function through this
/// reference instead of as a template parameter: the body is then compiled once per result type in a
/// translation unit, not once per call site. Only the call operator below is compiled per call site. The
/// referenced function is called before @ref blocking_call returns, so it outlives the reference.
template<class ResultT>
class StartRef
{
public:
  /// References @p start, which must outlive this object.
  ///
  /// The address is stored without its const; the private `call` casts it back to `Start*`, whose const is
  /// the argument's own, so a const start function is only ever called as const.
  ///
  /// @tparam Start The start function's type, possibly const.
  /// @param start  The start function @ref blocking_call calls with its completion.
  template<class Start>
  explicit StartRef(Start& start) noexcept
    : mObject(const_cast<void*>(static_cast<const void*>(std::addressof(start)))), mCall(&call<Start>)
  {}

  /// Calls the referenced start function with @p complete.
  ///
  /// @param complete The completion the start function takes ownership of.
  void operator()(std::function<void(ResultT)>&& complete) const
  {
    mCall(mObject, std::move(complete));
  }

private:
  template<class Start>
  static void call(void* object, std::function<void(ResultT)>&& complete)
  {
    (*static_cast<Start*>(object))(std::move(complete));
  }

  void* mObject;
  void (*mCall)(void*, std::function<void(ResultT)>&&);
};

/// The body of `blocking_call`, which depends on the result type only.
///
/// @tparam ResultT The @ref ua::Result specialisation the operation completes with.
/// @param executor As for `blocking_call`.
/// @param start    The start function, referenced through `StartRef`.
/// @param deadline As for `blocking_call`.
/// @return As for `blocking_call`.
template<class ResultT>
[[nodiscard]] ResultT blocking_call_body(const boost::asio::any_io_executor& executor, StartRef<ResultT> start,
  std::optional<std::chrono::milliseconds> deadline) noexcept
{
  static_assert(
    ua::is_result_v<ResultT>, "blocking_call returns the ua::Result the operation completes with");
  if (on_executor_context(executor))
  {
    return ResultT{ua::Status::BadWouldBlock, would_block_detail()};
  }
  try
  {
    struct State
    {
      std::promise<ResultT> promise;
      std::atomic_bool answered{false};
    };

    auto state = std::make_shared<State>();
    auto future = state->promise.get_future();
    // The state moves into the completion: the last copy released unanswered breaks the promise.
    std::function<void(ResultT)> complete = [state = std::move(state)](ResultT result)
    {
      if (!state->answered.exchange(true))
      {
        state->promise.set_value(std::move(result));
      }
    };
    start(std::move(complete));
    if (deadline.has_value() && future.wait_for(*deadline) != std::future_status::ready)
    {
      return ResultT{ua::Status::BadTimeout,
        ua::ErrorDetail::build("BlockingCallDeadline",
          "The operation did not complete within the blocking call's deadline; it was not cancelled",
          "ua::async")
          .context(ua::ContextKeys::limit, std::to_string(deadline->count()) + "ms")};
    }
    return future.get();
  }
  catch (const std::future_error& error)
  {
    if (error.code() != std::future_errc::broken_promise)
    {
      return ResultT{ua::exception_to_status_code(std::current_exception())};
    }
    return ResultT{ua::Status::BadInternalError,
      ua::ErrorDetail::build("BlockingCallAbandoned",
        "The operation released its completion without calling it, so it will never answer",
        "ua::async")};
  }
  catch (...)
  {
    return ResultT{ua::exception_to_status_code(std::current_exception())};
  }
}

template<class ResultT, class Start>
ResultT blocking_call(const boost::asio::any_io_executor& executor, Start&& start,
  std::optional<std::chrono::milliseconds> deadline) noexcept
{
  return blocking_call_body<ResultT>(executor, StartRef<ResultT>{start}, deadline);
}

}  // namespace ua::async::detail

#endif  // UA_SYNC_WAIT_H
