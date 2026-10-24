// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Exception-to-Result and exception-to-StatusCode translation utilities for API boundaries.
/// @ingroup general

#ifndef UA_TO_RESULT_H
#define UA_TO_RESULT_H

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <concepts>
#include <new>
#include <string_view>
#include <type_traits>

namespace ua
{

/// Converts a captured exception into a rich @ref StatusCode carrying an @ref ErrorDetail.
///
/// The canonical converter for async boundaries (callbacks, strand lambdas, ASIO completion
/// handlers): catch with a single `catch (...)` and pass `std::current_exception()` here to obtain
/// a @ref StatusCode that implicitly converts to any `Result<T>` via `Result<T>(StatusCode)`. A
/// @ref UaException yields its original @ref StatusCode (lossless, with detail); `std::bad_alloc`
/// yields `BadOutOfMemory`; any other `std::exception` yields `BadInternalError` with its `what()`
/// text in the detail; any non-standard exception yields `BadInternalError` with a generic detail.
///
/// @param eptr Captured exception, typically from `std::current_exception()`. Must be non-null; the
///             current exception is rethrown internally to determine its type.
/// @return A rich @ref StatusCode mapped from the exception, with an attached @ref ErrorDetail.
///         If diagnostic construction fails, retains the mapped status and attaches an immutable
///         emergency detail with static storage. That alias allocates no ownership control block;
///         its use_count() is zero and it cannot be retained through a weak_ptr. Never throws.
/// Customers use it the same way in their own asynchronous handlers.
/// @see detail::to_result, detail::rethrow_as_ua_exception
/// @ingroup general
StatusCode exception_to_status_code(std::exception_ptr eptr) noexcept;

}  // namespace ua

namespace ua::detail
{

/// Invokes a callable and translates any thrown exception into a @ref Result.
///
/// The single translation boundary between SDK internals (which may throw) and the public,
/// callback-canonical API (which surfaces failure as a bad @ref Result). The callable's return
/// type @p T is deduced from `std::invoke_result_t<F>`; a `void`-returning callable yields a
/// `Result<void>`. Caught exceptions map to a bad @ref Result as follows: a @ref UaException
/// forwards its full @ref StatusCode (numeric code plus attached @ref ErrorDetail, lossless);
/// `std::bad_alloc` maps to `BadOutOfMemory`; any other `std::exception` maps to `BadInternalError`
/// carrying its `what()` text; any non-standard exception maps to `BadInternalError` with a generic
/// detail. Every failure carries an @ref ErrorDetail.
///
/// @tparam F Callable invocable with no arguments.
/// @param f  Callable to invoke; perfectly forwarded.
/// @return The callable's result on success, or a bad @ref Result carrying the mapped
///         @ref StatusCode and @ref ErrorDetail on failure. Never throws.
/// @see exception_to_status_code
/// @ingroup general
template<typename F>
auto to_result(F&& f) noexcept -> Result<std::invoke_result_t<F>>
{
  using T = std::invoke_result_t<F>;
  try
  {
    if constexpr (std::is_void_v<T>)
    {
      std::forward<F>(f)();
      return Result<void>{};
    }
    else
    {
      return std::forward<F>(f)();
    }
  }
  catch (...)
  {
    return Result<T>{exception_to_status_code(std::current_exception())};
  }
}

/// Re-throws the in-flight exception as a @ref UaException.
///
/// Normalises any exception to a @ref UaException at a `_sync` API boundary; invoke from within a
/// `catch (...)` block, e.g. `try { ... } catch (...) { rethrow_as_ua_exception(); }`. A
/// @ref UaException is re-thrown unchanged (preserving status, detail, and origin location);
/// `std::bad_alloc` becomes a `UaException{BadOutOfMemory}`; any other `std::exception` becomes a
/// `UaException{status}` carrying its `what()` text; a non-standard exception becomes a
/// `UaException{status}` with a generic detail.
///
/// @param status Status applied to non-@ref UaException, non-`bad_alloc` exceptions.
///               Defaults to `BadInternalError`.
/// @throws UaException always - the normalised exception.
/// @pre A C++ exception is currently being handled (this is called from a `catch` block).
/// @see exception_to_status_code
[[noreturn]] inline void rethrow_as_ua_exception(Status status = Status::BadInternalError)
{
  try
  {
    throw;
  }
  catch (const UaException&)
  {
    throw;
  }
  catch (const std::bad_alloc&)
  {
    throw UaException{
      Status::BadOutOfMemory, make_error_detail("BadAlloc", "Memory allocation failed", "rethrow")};
  }
  catch (const std::exception& e)
  {
    throw UaException{status,
      ErrorDetail::build("StdException", "Unhandled exception", "rethrow")
        .context(ua::ContextKeys::errorMessage, e.what())};
  }
  catch (...)
  {
    throw UaException{
      status, make_error_detail("UnknownException", "Non-standard exception caught", "rethrow")};
  }
}

/// Re-throws the in-flight exception as a @ref UaException with a caller-formatted message.
///
/// Behaves like the no-formatter overload, but builds the @ref ErrorDetail message for mapped
/// (non-@ref UaException) exceptions from @p formatMessage. The formatter is invoked with the
/// original `what()` text for a `std::exception`, or an empty `string_view` for a non-standard
/// exception, and its return value supplies the detail message. A @ref UaException is still
/// re-thrown unchanged and `std::bad_alloc` is still mapped to `BadOutOfMemory` without consulting
/// the formatter.
///
/// @tparam F             Callable invocable with a `std::string_view` (the original `what()`),
///                       returning the replacement message.
/// @param status         Status applied to the formatted exception.
/// @param formatMessage Message formatter; perfectly forwarded and invoked at most once.
/// @throws UaException always - the normalised exception.
/// @pre A C++ exception is currently being handled (this is called from a `catch` block).
/// @see exception_to_status_code
template<typename F>
  requires std::invocable<F, std::string_view>
[[noreturn]] inline void rethrow_as_ua_exception(Status status, F&& formatMessage)
{
  try
  {
    throw;
  }
  catch (const UaException&)
  {
    throw;
  }
  catch (const std::bad_alloc&)
  {
    throw UaException{
      Status::BadOutOfMemory, make_error_detail("BadAlloc", "Memory allocation failed", "rethrow")};
  }
  catch (const std::exception& e)
  {
    auto msg = std::forward<F>(formatMessage)(std::string_view{e.what()});
    throw UaException{status,
      ErrorDetail::build("StdException", "Unhandled std::exception", "rethrow")
        .context(ContextKeys::errorMessage, std::move(msg))};
  }
  catch (...)
  {
    auto msg = std::forward<F>(formatMessage)(std::string_view{});
    throw UaException{status,
      ErrorDetail::build("UnknownException", "Non-standard exception caught", "rethrow")
        .context(ua::ContextKeys::errorMessage, std::move(msg))};
  }
}

}  // namespace ua::detail

#endif  // !UA_TO_RESULT_H
