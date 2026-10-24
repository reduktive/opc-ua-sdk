// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Safe invocation helpers for user-supplied callbacks, plus the explicit
///        discard for a caught exception representing an expected, benign condition.
/// @ingroup general

#ifndef UA_CALLBACK_SAFETY_H
#define UA_CALLBACK_SAFETY_H

#include "ua_error_detail.h"
#include "ua_logger.h"

#include <atomic>
#include <concepts>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace ua::detail
{

/// Trait: whether @p T is a callback that can be *empty* in the "no callback was provided" sense - a
/// `std::function` specialization or a pointer-to-function. These are the only callable kinds whose
/// `operator bool` (or null test) means "unset", so they are the only ones @ref invoke_user_callback may
/// safely skip when empty. A capturing lambda or a stateful functor is deliberately NOT nullable: even one
/// that happens to be bool-convertible (a captureless lambda decays to a function pointer; a functor may
/// carry a *semantic* `operator bool`) must never be empty-skipped, so it is excluded here.
template<typename T>
struct is_nullable_callback
  : std::bool_constant<std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>>
{};

template<typename R, typename... A>
struct is_nullable_callback<std::function<R(A...)>> : std::true_type
{};

template<typename T>
/// The is nullable callback v.
inline constexpr bool is_nullable_callback_v = is_nullable_callback<T>::value;

/// Explicitly and deliberately discards the exception currently being handled.
///
/// Call this in the body of a `catch` that is intentionally non-propagating, where the caught
/// exception is the *expected* signal of an alternative outcome that the surrounding code already
/// handles by another path - for example: an optional attribute is unset (default applied), a
/// lookup-by-name legitimately fails (treated as "not present"), an optional value is unencodable
/// during a best-effort export, or a best-effort operation at a `noexcept` / Asio strand-handler
/// boundary has no caller to report to and must not let an exception escape.
///
/// Naming the disposition makes a deliberate non-propagation distinguishable from an accidental
/// empty `catch` that silently hides a bug. Use it *only* where the exception is genuinely the
/// expected signal of an alternative outcome - never to drop an error that a caller should learn
/// about; propagate those through `Result<T>` / `ErrorDetail`.
inline void ignore_expected_exception() noexcept
{}

/// Invokes a user-provided callback, catching and logging any exception it throws.
///
/// Use this at every SDK site that fires a user-supplied `std::function`
/// callback or event handler, so a throwing handler can never propagate an
/// exception across an SDK boundary (in particular, never out of an Asio
/// completion handler). If the callback throws, the exception is caught and a
/// warning is logged via @p logger; the call then returns normally.
///
/// @ingroup general
///
/// @tparam Callback Invocable type accepting @p args.
/// @tparam Args     Argument types forwarded to the callback.
/// @param logger Logger that receives a warning if the callback throws. Borrowed
///               for the duration of the call; not retained.
/// @param cb     Callback to invoke; forwarded and called exactly once.
/// @param args   Arguments forwarded to the callback.
/// @note Never throws: any exception escaping the callback is swallowed after
///       being logged.
/// @see invoke_user_callback(Callback&&, Args&&...)
template<typename Callback, typename... Args>
void invoke_user_callback(const Logger& logger, Callback&& cb, Args&&... args) noexcept
{
  // An empty callback means "no callback was provided" (a fire-and-forget caller, or a moved-from
  // single-shot). Invoking it would throw std::bad_function_call, which the catch below would swallow and
  // mislabel as "User callback threw" - so skip it. Only nullable callables (std::function / function
  // pointer) are checked; a lambda/functor is never "unset" and is always invoked.
  if constexpr (is_nullable_callback_v<std::decay_t<Callback>>)
  {
    if (!cb)
    {
      return;
    }
  }
  try
  {
    std::forward<Callback>(cb)(std::forward<Args>(args)...);
  }
  catch (const std::exception& ex)
  {
    try
    {
      logger.warning("User callback threw: {}", ex.what());
    }
    catch (...)
    {
      // Formatting or copying a log entry can fail. Reporting must not escape this callback boundary.
      ignore_expected_exception();
    }
  }
  catch (...)
  {
    try
    {
      logger.warning("User callback threw unknown exception");
    }
    catch (...)
    {
      // Retrying the same logger could repeat the failure, so finish containing the callback here.
      ignore_expected_exception();
    }
  }
}

/// Invokes a user-provided callback, silently swallowing any exception it throws.
///
/// Fallback overload for code paths with no @ref Logger available (e.g. generated
/// code). Identical to the logging overload except that an escaping exception is
/// discarded without being reported. Prefer the logging overload wherever a
/// @ref Logger is in scope. The first parameter is constrained away from @ref
/// Logger so a logger argument always selects the logging overload.
///
/// @tparam Callback Invocable type accepting @p args; must not be @ref Logger.
/// @tparam Args     Argument types forwarded to the callback.
/// @param cb   Callback to invoke; forwarded and called exactly once.
/// @param args Arguments forwarded to the callback.
/// @note Never throws: any exception escaping the callback is swallowed.
/// @see invoke_user_callback(const Logger&, Callback&&, Args&&...)
template<typename Callback, typename... Args>
  requires(!std::same_as<std::decay_t<Callback>, Logger>)
void invoke_user_callback(Callback&& cb, Args&&... args) noexcept
{
  // Empty callback = no callback provided (or a moved-from single-shot); invoking it would throw
  // std::bad_function_call. Skip it rather than swallow the throw. Only nullable callables (std::function /
  // function pointer) are checked; a lambda/functor is never "unset" and is always invoked.
  if constexpr (is_nullable_callback_v<std::decay_t<Callback>>)
  {
    if (!cb)
    {
      return;
    }
  }
  try
  {
    std::forward<Callback>(cb)(std::forward<Args>(args)...);
  }
  catch (...)
  {
    // No Logger in scope (this is the deliberate no-logger fallback overload); the callback owns
    // its own error handling and the exception must not cross this noexcept boundary.
    ignore_expected_exception();
  }
}

/// Wraps a callback so that at most one invocation reaches the underlying callable.
///
/// Returns a `std::function<void(T)>` that forwards the first call to @p cb and
/// silently drops every later call. The "fired" flag and the wrapped callable
/// are held in shared state, so the guard holds even across copies of the
/// returned function and concurrent calls from different threads: each call
/// performs an acquire-release `exchange(true)` on a shared `std::atomic<bool>`,
/// and only the one caller that observes the prior value `false` reaches @p cb.
///
/// Use at SDK sites where two paths legitimately race to fire the same callback
/// - e.g. a user-supplied handler that may invoke the callback or throw, paired
/// with a try/catch fallback that fires an error if the handler threw without
/// firing. Without this guard a fire-then-throw handler would double-fire the
/// underlying callable.
///
/// @tparam T Argument type the wrapped callback accepts (moved into @p cb).
/// @param cb Callback to guard; moved into the shared state and invoked at most
///           once. A null @p cb yields a wrapper that consumes its first call
///           and does nothing.
/// @return A fire-once wrapper around @p cb. Thread-safe to call from any thread.
template<typename T>
std::function<void(T)> make_fire_once(std::function<void(T)> cb)
{
  struct State
  {
    std::atomic<bool> fired{false};
    std::function<void(T)> cb;
  };

  auto state = std::make_shared<State>();
  state->cb = std::move(cb);
  return [state](T result)
  {
    if (!state->fired.exchange(true, std::memory_order_acq_rel) && state->cb)
    {
      state->cb(std::move(result));
    }
  };
}

/// The completion an `*_async` call uses when its caller passed none.
///
/// A caller that passes no callback is not cancelling the call: the work still runs, and its outcome is
/// logged rather than lost - a failure at Error with its StatusCode and ErrorDetail, any other outcome at
/// Debug. This is the fire-and-forget rule of the async design: a dropped result is logged first.
///
/// @tparam R        The completion's result type (`VoidResult` or a `Result<T>`).
/// @param done      The caller's callback; returned unchanged when it is set.
/// @param logger    Receives the outcome when @p done is empty.
/// @param operation Names the call in the log. Not copied: pass a string literal.
/// @return @p done, or a callable that logs the outcome.
template<typename R>
std::function<void(R)> completion_or_log(std::function<void(R)> done, Logger logger, const char* operation)
{
  if (done)
  {
    return done;
  }
  return [logger = std::move(logger), operation](R result)
  {
    const auto status = result.status_code();
    if (status.is_bad())
    {
      logger.error({{"operation", std::string_view{operation}}},
        "Call made without a completion callback failed: {}",
        describe(status));
      return;
    }
    logger.debug(
      {{"operation", std::string_view{operation}}}, "Call made without a completion callback completed");
  };
}

}  // namespace ua::detail

#endif  // !UA_CALLBACK_SAFETY_H
