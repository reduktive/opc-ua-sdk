// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RESULT_H
#define UA_RESULT_H

/// @file
/// @brief Value-or-error result type for OPC UA operations.
/// @ingroup general

#include <cassert>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/container/small_vector.hpp>

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_status_code.h"
#include "ua_status_to_string.h"

namespace ua
{

template<typename T>
class Result;

namespace detail
{

/// The ErrorDetail of a result built with a value and a Bad status, which holds no value.
///
/// Built on first use and shared by every such result, so the misuse path allocates nothing after
/// the first time. The result's own status code names the code that was passed.
///
/// @return The shared "ValueWithBadStatus" detail.
inline const shared_ptr<const ErrorDetail>& value_with_bad_status_detail()
{
  static const shared_ptr<const ErrorDetail> detail = ErrorDetail::build("ValueWithBadStatus",
    "A result holding a value was given a Bad status; the value was discarded",
    "Result");
  return detail;
}

/// The result a value given with the Bad @p status becomes: @p status's code with the
/// "ValueWithBadStatus" detail and no value. A detail @p status already carries is kept as that detail's
/// cause, so it is not lost; only then is a detail allocated.
///
/// @param status The Bad status.
/// @return The status code of the result.
inline StatusCode value_with_bad_status(const StatusCode& status)
{
  if (!status.shared_detail())
  {
    return StatusCode{status.value(), value_with_bad_status_detail()};
  }
  return StatusCode{status.value(),
    ErrorDetail::build("ValueWithBadStatus",
      "A result holding a value was given a Bad status; the value was discarded",
      "Result")
      .cause(status.shared_detail())};
}

/// A result holding @p value with @p status, for any held type, `StatusCode` included.
///
/// @param value  The value.
/// @param status A Good or Uncertain status.
/// @return The result.
template<typename U>
Result<U> held(U value, StatusCode status);

/// @p result with the status `combined_status` gives for @p outer and @p result's own status.
///
/// @param result The result of a later step.
/// @param outer  The status of the earlier step, which held a value.
/// @return @p result, or a result holding its value (when it holds one) with @p outer.
template<typename R>
R carried(R result, const StatusCode& outer);

/// Throws a @ref UaException carrying @p status and its detail.
///
/// @param status The status thrown; not Good.
/// @param code   The ErrorDetail code used when @p status carries no detail of its own.
/// @param summary The ErrorDetail summary used when @p status carries no detail of its own.
[[noreturn]] inline void throw_status(const StatusCode& status, const char* code, const char* summary)
{
  if (status.is_good())
  {
    // Only a result whose class invariant was broken in a release build gets here.
    throw_empty_optional_check(Status::BadInternalError);
  }
  if (auto detail = status.shared_detail())
  {
    throw UaException{status.as_status(), std::move(detail)};
  }
  throw UaException{status.as_status(), ErrorDetail::build(code, summary, "Result").cause(status)};
}

}  // namespace detail

/// The result of an OPC UA operation: a @ref StatusCode, and a value of type @p T when there is one.
///
/// A Good result always holds a value; its status is plain Good or a Good subcode such as Good_Clamped.
/// An Uncertain result holds a value or not: the operation partly succeeded, and a value it holds "might
/// not be suitable for some purposes" (OPC 10000-4 7.39.1). A Bad result never holds one. has_value()
/// says whether a value is held; is_good(), is_uncertain() and is_bad() give the severity. Any
/// @ref ErrorDetail travels inside the StatusCode - Result has no separate detail field, so propagating a
/// Result preserves the detail without extra plumbing.
///
/// A value converts to a Good result and a @ref StatusCode (or @ref Status, via its implicit conversion)
/// to a Bad or Uncertain result without a value, so the type is the natural callback payload for the
/// `*_async` API variant and the natural return of the `try_*_sync` variant. A result holding a value
/// with a Good subcode or an Uncertain code is built from both.
///
/// @tparam T Held value type. See @ref Result<void> for the no-value case and @ref Result<StatusCode>
///           for the StatusCode-valued case.
/// @ingroup general
template<typename T>
class Result
{
public:
  /// Constructs a Good result holding @p value.
  ///
  /// Implicit, so a `T` converts directly to a `Result<T>` at a return site.
  ///
  /// @param value The held value; moved in.
  Result(T value) : mStatusCode(Status::Good), mValue(std::move(value))
  {}

  /// Constructs a result holding @p value whose status is @p status: a Good subcode, such as
  /// Good_Clamped or Good_CompletesAsynchronously, or an Uncertain code, such as
  /// Uncertain_LastUsableValue.
  ///
  /// The value comes first, so that no `(StatusCode, shared_ptr<const ErrorDetail>)` call can
  /// resolve to this constructor. The status is checked in every build: a Bad result holds no value,
  /// so for a Bad @p status the result is that code with the "ValueWithBadStatus" ErrorDetail of
  /// @ref detail::value_with_bad_status (whose cause is @p status's own detail when it has one), and
  /// @p value is discarded; debug builds also assert.
  ///
  /// @param value  The held value; moved in.
  /// @param status A Good or Uncertain status code.
  Result(T value, StatusCode status) : mStatusCode(std::move(status))
  {
    assert(!mStatusCode.is_bad() && "Result<T>(value, status) requires a status that is not Bad");
    if (!mStatusCode.is_bad())
    {
      mValue.emplace(std::move(value));
      return;
    }
    mStatusCode = detail::value_with_bad_status(mStatusCode);
  }

  /// Constructs a result holding no value from a Bad or Uncertain (possibly rich) StatusCode.
  ///
  /// Implicit, so a @ref StatusCode or @ref Status converts directly to a
  /// `Result<T>` at a return site. Any @ref ErrorDetail already attached to
  /// @p error is retained.
  ///
  /// @param error A Bad or Uncertain status.
  /// @pre @p error must not be Good - a Good result must hold a value (use the value
  ///      constructor). Enforced by a debug assertion; this constructor is `noexcept` so an
  ///      error-path Result can be built on a noexcept boundary with no chance of throwing.
  Result(StatusCode error) noexcept : mStatusCode(std::move(error))
  {
    // Programming-error contract, asserted not thrown: a throw here would escape callers' noexcept
    // error handlers -> std::terminate.
    assert(!mStatusCode.is_good() && "Result<T> error constructor requires a non-Good StatusCode");
  }

  /// Constructs a result holding no value from a StatusCode and a shared ErrorDetail.
  ///
  /// The detail is folded into the stored @ref StatusCode. If @p detail is null
  /// the StatusCode is used as-is; if both @p error already carries detail and a
  /// separate @p detail is supplied, the explicit @p detail wins.
  ///
  /// @param error  A Bad or Uncertain status.
  /// @param detail Error detail to attach; shared, not copied. May be null.
  /// @pre @p error must not be Good (enforced by a debug assertion).
  Result(StatusCode error, shared_ptr<const ErrorDetail> detail) noexcept
    : Result(detail ? StatusCode{error.value(), std::move(detail)} : std::move(error))
  {}

  /// Copy-constructs an independent result; any @ref ErrorDetail is shared, not cloned.
  Result(const Result&) = default;
  /// Move-constructs from another result, leaving it in a valid but unspecified state.
  Result(Result&&) noexcept = default;
  /// Copy-assigns; any @ref ErrorDetail is shared, not cloned.
  ///
  /// @return A reference to this result.
  Result& operator=(const Result&) = default;
  /// Move-assigns, leaving the source in a valid but unspecified state.
  ///
  /// @return A reference to this result.
  Result& operator=(Result&&) noexcept = default;
  /// Destroys the result, releasing the held value and any error detail.
  ~Result() = default;

  /// Returns true if the status is Good. A Good result always holds a value.
  ///
  /// @return `true` if the status is Good.
  [[nodiscard]] bool is_good() const noexcept
  {
    return mStatusCode.is_good();
  }

  /// Returns true if the status is Bad. A Bad result never holds a value.
  ///
  /// @return `true` if the status is Bad.
  [[nodiscard]] bool is_bad() const noexcept
  {
    return mStatusCode.is_bad();
  }

  /// Returns true if the status is Uncertain. An Uncertain result holds a value when it was built with
  /// one; has_value() says which.
  ///
  /// @return `true` if the status is Uncertain.
  [[nodiscard]] bool is_uncertain() const noexcept
  {
    return mStatusCode.is_uncertain();
  }

  /// Returns true if the status is Uncertain or Bad.
  ///
  /// @return `true` if the status is not Good.
  [[nodiscard]] bool is_not_good() const noexcept
  {
    return mStatusCode.is_not_good();
  }

  /// Returns true if the status is Good or Uncertain. It says nothing about the value: an Uncertain
  /// result may hold none, so test has_value() before value().
  ///
  /// @return `true` if the status is not Bad.
  [[nodiscard]] bool is_not_bad() const noexcept
  {
    return mStatusCode.is_not_bad();
  }

  /// Returns true if the status is Good or Bad.
  ///
  /// @return `true` if the status is not Uncertain.
  [[nodiscard]] bool is_not_uncertain() const noexcept
  {
    return mStatusCode.is_not_uncertain();
  }

  /// Returns true if a value is held: always for a Good result, for an Uncertain result when it was built
  /// with one, never for a Bad result.
  ///
  /// @return `true` if value() returns a value rather than throwing.
  [[nodiscard]] bool has_value() const noexcept
  {
    return mValue.has_value();
  }

  /// Returns true if the status is Good; equivalent to is_good(). An Uncertain result holding a value is
  /// false here: a caller that uses uncertain values tests has_value().
  ///
  /// @return `true` if the result is Good; equivalent to is_good().
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return is_good();
  }

  /// Returns the status code: plain Good, a Good subcode or an Uncertain code when a value is held; an
  /// Uncertain or Bad code otherwise.
  ///
  /// @return The status code.
  [[nodiscard]] StatusCode status_code() const noexcept
  {
    return mStatusCode;
  }

  /// Returns the attached error detail, or null if none.
  ///
  /// Null when the status carries no detail. The pointer is owned by this Result and is valid only for
  /// its lifetime; use shared_detail() to extend ownership.
  ///
  /// @return The attached error detail, or null if none.
  [[nodiscard]] const ErrorDetail* error_detail() const noexcept
  {
    return mStatusCode.detail();
  }

  /// Returns the attached error detail as a shared pointer (null if none).
  ///
  /// Cheap to share without copying the detail.
  ///
  /// @return The attached error detail as a shared pointer, or null if none.
  [[nodiscard]] const shared_ptr<const ErrorDetail>& shared_detail() const noexcept
  {
    return mStatusCode.shared_detail();
  }

  /// Returns a reference to the held value, whatever the status: an Uncertain result's value too.
  ///
  /// @return The held value.
  /// @throws UaException carrying status_code() and any error detail if no value is held (a Bad
  ///         result, or an Uncertain result built without one).
  [[nodiscard]] const T& value() const&
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return *mValue;
  }

  /// Returns a mutable reference to the held value, whatever the status: an Uncertain result's value too.
  ///
  /// @return The held value.
  /// @throws UaException carrying status_code() and any error detail if no value is held.
  [[nodiscard]] T& value() &
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return *mValue;
  }

  /// Moves the held value out of this Result, whatever the status: an Uncertain result's value too.
  ///
  /// @return The held value, moved.
  /// @throws UaException carrying status_code() and any error detail if no value is held.
  [[nodiscard]] T&& value() &&
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return std::move(*mValue);
  }

  /// Returns the held value, otherwise @p fallback.
  ///
  /// @param fallback Value returned when no value is held.
  /// @return The held value (an Uncertain result's too), otherwise @p fallback.
  [[nodiscard]] T value_or(const T& fallback) const&
  {
    if (mValue.has_value())
    {
      return *mValue;
    }
    return fallback;
  }

  /// Returns the held value (moved), otherwise @p fallback.
  ///
  /// @param fallback Value returned when no value is held.
  /// @return The held value (moved; an Uncertain result's too), otherwise @p fallback.
  [[nodiscard]] T value_or(T fallback) &&
  {
    if (mValue.has_value())
    {
      return std::move(*mValue);
    }
    // No std::move: `fallback` is a by-value parameter, so returning it already moves. GCC 12
    // rejects the explicit move as -Werror=redundant-move; later GCCs dropped the warning for
    // parameters, which is why only the oldest supported compiler saw this.
    return fallback;
  }

  /// Maps the held value through @p f, keeping this result's status.
  ///
  /// When a value is held, applies @p f to it and returns a `Result<U>` holding @p f's return with this
  /// result's status code and detail: a Good subcode or an Uncertain code is carried over. When none is
  /// held, the status code (with any detail) is forwarded unchanged. Use and_then() when @p f itself
  /// returns a Result.
  ///
  /// @tparam F Callable taking `const T&`.
  /// @param f Transformation applied to the held value.
  /// @return `Result<U>` where `U` is the return type of @p f.
  template<typename F>
  [[nodiscard]] auto transform(F&& f) const& -> Result<std::invoke_result_t<F, const T&>>
  {
    using U = std::invoke_result_t<F, const T&>;
    if (!mValue.has_value())
    {
      return Result<U>{mStatusCode};
    }
    return detail::held<U>(std::invoke(std::forward<F>(f), *mValue), mStatusCode);
  }

  /// Maps the held value through @p f, keeping this result's status (rvalue overload).
  ///
  /// @tparam F Callable taking `T&&`.
  /// @param f Transformation applied to the moved held value.
  /// @return `Result<U>` where `U` is the return type of @p f.
  template<typename F>
  [[nodiscard]] auto transform(F&& f) && -> Result<std::invoke_result_t<F, T&&>>
  {
    using U = std::invoke_result_t<F, T&&>;
    if (!mValue.has_value())
    {
      return Result<U>{std::move(mStatusCode)};
    }
    return detail::held<U>(std::invoke(std::forward<F>(f), std::move(*mValue)), std::move(mStatusCode));
  }

  /// Chains a Result-returning operation onto the held value (monadic bind).
  ///
  /// When a value is held, applies @p f to it and returns @p f's result with the status
  /// `detail::combined_status` gives for this result's status and @p f's: a plain Good from @p f takes
  /// this result's Good subcode or Uncertain code, the worse severity of the two is kept, and when both
  /// carry a subcode of the same severity @p f's is kept. In that last case @p f's code replaces this
  /// result's (a Good subcode by a Good subcode, for example), and the replaced code is not logged: a Result
  /// has no logger. A service that puts two codes into one answer logs the replaced one itself. When none
  /// is held, the status code (with any detail) is forwarded unchanged. Use transform() when @p f returns a
  /// plain value rather than a Result.
  ///
  /// @tparam F Callable taking `const T&` and returning some `Result<U>`.
  /// @param f Operation applied to the held value.
  /// @return The `Result<U>` produced by @p f with the combined status, or this result's status forwarded.
  template<typename F>
  [[nodiscard]] auto and_then(F&& f) const& -> std::invoke_result_t<F, const T&>
  {
    using ResultU = std::invoke_result_t<F, const T&>;
    if (!mValue.has_value())
    {
      return ResultU{mStatusCode};
    }
    return detail::carried(std::invoke(std::forward<F>(f), *mValue), mStatusCode);
  }

  /// Chains a Result-returning operation onto the held value (rvalue overload).
  ///
  /// @tparam F Callable taking `T&&` and returning some `Result<U>`.
  /// @param f Operation applied to the moved held value.
  /// @return The `Result<U>` produced by @p f with the combined status, or this result's status forwarded.
  template<typename F>
  [[nodiscard]] auto and_then(F&& f) && -> std::invoke_result_t<F, T&&>
  {
    using ResultU = std::invoke_result_t<F, T&&>;
    if (!mValue.has_value())
    {
      return ResultU{std::move(mStatusCode)};
    }
    return detail::carried(std::invoke(std::forward<F>(f), std::move(*mValue)), mStatusCode);
  }

  /// Maps the status of a result holding no value through @p f; a result holding a value is returned
  /// unchanged.
  ///
  /// When no value is held, applies @p f to the @ref StatusCode and returns a Result built from the
  /// mapped status; when a value is held, the value and its status (plain Good, a Good subcode or an
  /// Uncertain code) are forwarded unchanged.
  ///
  /// @tparam F Callable taking a @ref StatusCode and returning a value usable to
  ///           construct a `Result<T>` (typically a StatusCode).
  /// @param f Mapping applied to the status.
  /// @return This result when it holds a value, otherwise a Result built from @p f's output.
  template<typename F>
  [[nodiscard]] Result transform_error(F&& f) const&
  {
    if (mValue.has_value())
    {
      return *this;  // the value and its status, a Good subcode or an Uncertain code included
    }
    return std::invoke(std::forward<F>(f), mStatusCode);
  }

  /// Maps the status of a result holding no value through @p f (rvalue overload).
  ///
  /// @tparam F Callable taking a @ref StatusCode and returning a value usable to
  ///           construct a `Result<T>`.
  /// @param f Mapping applied to the status.
  /// @return This result when it holds a value, otherwise a Result built from @p f's output.
  template<typename F>
  [[nodiscard]] Result transform_error(F&& f) &&
  {
    if (mValue.has_value())
    {
      return std::move(*this);  // the value and its status, a Good subcode or an Uncertain code included
    }
    return std::invoke(std::forward<F>(f), mStatusCode);
  }

private:
  template<typename U>
  friend class Result;

  [[noreturn]] void throw_without_value() const
  {
    detail::throw_status(mStatusCode, "ResultAccessedWithoutValue", "Result accessed without value");
  }

  StatusCode mStatusCode;
  std::optional<T> mValue;
};

/// A @ref Result whose held value is itself a @ref StatusCode.
///
/// Explicit specialization for the case `T == StatusCode`, needed because the
/// primary template's value constructor `Result(T value)` and error constructor
/// `Result(StatusCode error)` would have identical signatures here (e.g. a
/// property whose DataType is StatusCode, such as
/// `TransactionDiagnosticsType.Result`).
///
/// The single-argument @ref StatusCode constructor still means **no value**, exactly
/// as for every other `Result<T>`, so generic error paths - including the
/// generated sync-wrapper `catch` that returns `exception_to_status_code(...)` -
/// are unchanged. A result holding a StatusCode value is built explicitly
/// via with_value(). The primary template is untouched.
///
/// @see Result, with_value
template<>
class Result<StatusCode>
{
public:
  /// Constructs a good result holding @p value.
  ///
  /// The explicit factory for a StatusCode-valued success, distinguishing it from
  /// the single-argument error constructor.
  ///
  /// @param value The held StatusCode value.
  /// @return A good `Result<StatusCode>` carrying @p value.
  [[nodiscard]] static Result with_value(StatusCode value)
  {
    return Result{ValueTag{}, std::move(value), StatusCode{Status::Good}};
  }

  /// Constructs a result holding @p value whose status is a Good subcode or an Uncertain code.
  ///
  /// The status is checked in every build: a Bad result holds no value, so for a Bad @p status the
  /// result is that code with the "ValueWithBadStatus" ErrorDetail of @ref detail::value_with_bad_status
  /// (whose cause is @p status's own detail when it has one), and @p value is discarded; debug builds
  /// also assert.
  ///
  /// @param value  The held StatusCode value.
  /// @param status A Good or Uncertain status code.
  /// @return A `Result<StatusCode>` holding @p value with @p status, or the Bad result.
  [[nodiscard]] static Result with_value(StatusCode value, StatusCode status)
  {
    assert(
      !status.is_bad() && "Result<StatusCode>::with_value(value, status) requires a status that is not Bad");
    if (!status.is_bad())
    {
      return Result{ValueTag{}, std::move(value), std::move(status)};
    }
    return Result{detail::value_with_bad_status(status)};
  }

  /// Constructs a result holding no value from a Bad or Uncertain (possibly rich) StatusCode.
  ///
  /// The single-argument form means **no value**; use with_value() for a result holding a StatusCode
  /// value. Any @ref ErrorDetail attached to @p error is retained.
  ///
  /// @param error A Bad or Uncertain status.
  /// @pre @p error must not be Good - use with_value() for a good StatusCode-valued result.
  ///      Enforced by a debug assertion; `noexcept` so error paths cannot throw on construction.
  Result(StatusCode error) noexcept : mStatusCode(std::move(error))
  {
    // Asserted not thrown: a throw here would escape callers' noexcept error handlers ->
    // std::terminate.
    assert(!mStatusCode.is_good() && "Result<StatusCode> error constructor requires a non-Good StatusCode");
  }

  /// Constructs an error result from a StatusCode and a shared ErrorDetail.
  ///
  /// @param error  The error status; must not be Good.
  /// @param detail Error detail to attach; shared, not copied. May be null.
  /// @pre @p error must not be Good (enforced by a debug assertion).
  Result(StatusCode error, shared_ptr<const ErrorDetail> detail) noexcept
    : Result(detail ? StatusCode{error.value(), std::move(detail)} : std::move(error))
  {}

  /// Copy-constructs an independent result; any @ref ErrorDetail is shared, not cloned.
  Result(const Result&) = default;
  /// Move-constructs from another result, leaving it in a valid but unspecified state.
  Result(Result&&) noexcept = default;
  /// Copy-assigns; any @ref ErrorDetail is shared, not cloned.
  ///
  /// @return A reference to this result.
  Result& operator=(const Result&) = default;
  /// Move-assigns, leaving the source in a valid but unspecified state.
  ///
  /// @return A reference to this result.
  Result& operator=(Result&&) noexcept = default;
  /// Destroys the result, releasing the held value and any error detail.
  ~Result() = default;

  /// Returns true if the status is Good. A Good result always holds a value.
  ///
  /// @return `true` if the status is Good.
  [[nodiscard]] bool is_good() const noexcept
  {
    return mStatusCode.is_good();
  }

  /// Returns true if the status is Bad. A Bad result never holds a value.
  ///
  /// @return `true` if the status is Bad.
  [[nodiscard]] bool is_bad() const noexcept
  {
    return mStatusCode.is_bad();
  }

  /// Returns true if the status is Uncertain; has_value() says whether a value is held.
  ///
  /// @return `true` if the status is Uncertain.
  [[nodiscard]] bool is_uncertain() const noexcept
  {
    return mStatusCode.is_uncertain();
  }

  /// Returns true if the status is Uncertain or Bad.
  ///
  /// @return `true` if the status is not Good.
  [[nodiscard]] bool is_not_good() const noexcept
  {
    return mStatusCode.is_not_good();
  }

  /// Returns true if the status is Good or Uncertain; test has_value() before value().
  ///
  /// @return `true` if the status is not Bad.
  [[nodiscard]] bool is_not_bad() const noexcept
  {
    return mStatusCode.is_not_bad();
  }

  /// Returns true if the status is Good or Bad.
  ///
  /// @return `true` if the status is not Uncertain.
  [[nodiscard]] bool is_not_uncertain() const noexcept
  {
    return mStatusCode.is_not_uncertain();
  }

  /// Returns true if a value is held: always for a Good result, for an Uncertain result when it was built
  /// with one, never for a Bad result.
  ///
  /// @return `true` if value() returns a value rather than throwing.
  [[nodiscard]] bool has_value() const noexcept
  {
    return mValue.has_value();
  }

  /// Returns true if the status is Good; equivalent to is_good().
  ///
  /// @return `true` if the result is Good; equivalent to is_good().
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return is_good();
  }

  /// Returns the status code: plain Good, a Good subcode or an Uncertain code when a value is held; an
  /// Uncertain or Bad code otherwise.
  ///
  /// @note This returns the *outcome* status, not the held StatusCode value; use value() for the
  ///       latter.
  ///
  /// @return The status code.
  [[nodiscard]] StatusCode status_code() const noexcept
  {
    return mStatusCode;
  }

  /// Returns the attached error detail, or null if none.
  ///
  /// The pointer is owned by this Result and valid only for its lifetime.
  ///
  /// @return The attached error detail, or null if none.
  [[nodiscard]] const ErrorDetail* error_detail() const noexcept
  {
    return mStatusCode.detail();
  }

  /// Returns the attached error detail as a shared pointer (null if none).
  ///
  /// @return The attached error detail as a shared pointer, or null if none.
  [[nodiscard]] const shared_ptr<const ErrorDetail>& shared_detail() const noexcept
  {
    return mStatusCode.shared_detail();
  }

  /// Returns a reference to the held StatusCode value, whatever the status.
  ///
  /// @return The held StatusCode value.
  /// @throws UaException carrying status_code() and any error detail if no value is held.
  [[nodiscard]] const StatusCode& value() const&
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return *mValue;
  }

  /// Returns a mutable reference to the held StatusCode value, whatever the status.
  ///
  /// @return The held StatusCode value.
  /// @throws UaException carrying status_code() and any error detail if no value is held.
  [[nodiscard]] StatusCode& value() &
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return *mValue;
  }

  /// Moves the held StatusCode value out of this Result, whatever the status.
  ///
  /// @return The held StatusCode value, moved.
  /// @throws UaException carrying status_code() and any error detail if no value is held.
  [[nodiscard]] StatusCode&& value() &&
  {
    if (!mValue.has_value())
    {
      throw_without_value();
    }
    return std::move(*mValue);
  }

  /// Returns the held value, otherwise @p fallback.
  ///
  /// @param fallback StatusCode returned when no value is held.
  /// @return The held value, otherwise @p fallback.
  [[nodiscard]] StatusCode value_or(StatusCode fallback) const&
  {
    return mValue.has_value() ? *mValue : fallback;
  }

  /// Returns the held value (moved), otherwise @p fallback.
  ///
  /// @param fallback StatusCode returned when no value is held.
  /// @return The held value (moved), otherwise @p fallback.
  [[nodiscard]] StatusCode value_or(StatusCode fallback) &&
  {
    return mValue.has_value() ? std::move(*mValue) : fallback;
  }

private:
  struct ValueTag
  {};

  Result(ValueTag, StatusCode value, StatusCode status)
    : mStatusCode(std::move(status)), mValue(std::move(value))
  {}

  [[noreturn]] void throw_without_value() const
  {
    detail::throw_status(mStatusCode, "ResultAccessedWithoutValue", "Result accessed without value");
  }

  StatusCode mStatusCode;
  std::optional<StatusCode> mValue;
};

/// A @ref Result with no held value: success or error only.
///
/// Specialization for operations that either succeed or fail with a
/// @ref StatusCode and optional @ref ErrorDetail. Default-constructed is good;
/// constructing from a @ref StatusCode or @ref Status yields a good result for a
/// Good code (plain Good or a subcode, which is kept) and an error otherwise.
///
/// @see Result, VoidResult
template<>
class Result<void>
{
public:
  /// Constructs a good (success) result.
  Result() : mStatusCode(Status::Good)
  {}

  /// Constructs a result whose status is @p status: good when the code is Good (plain Good or a
  /// subcode such as Good_Clamped), an error otherwise.
  ///
  /// Implicit, so a @ref StatusCode or @ref Status converts directly to a
  /// `Result<void>` at a return site: `return Status::GoodClamped;` returns a good result that
  /// keeps the subcode. Any @ref ErrorDetail attached to @p status is retained. `noexcept` so error
  /// paths cannot throw on construction.
  ///
  /// @param status The status of the result.
  Result(StatusCode status) noexcept : mStatusCode(std::move(status))
  {}

  /// Constructs a result from a StatusCode and a shared ErrorDetail.
  ///
  /// The detail is folded into the stored @ref StatusCode. If @p detail is null
  /// the StatusCode is used as-is; if both @p status already carries detail and a
  /// separate @p detail is supplied, the explicit @p detail wins. Good when @p status is Good.
  ///
  /// @param status The status of the result.
  /// @param detail Error detail to attach; shared, not copied. May be null.
  Result(StatusCode status, shared_ptr<const ErrorDetail> detail) noexcept
    : Result(detail ? StatusCode{status.value(), std::move(detail)} : std::move(status))
  {}

  /// Constructs a GOOD result that carries an informational @ref ErrorDetail - for example the
  /// certificate validation errors a Good verdict suppressed (OPC 10000-4 section 6.1.3: they are
  /// "always reported via auditing").
  ///
  /// @param detail The detail to carry; may be null (then this is a plain good result).
  /// @return A good result whose @ref shared_detail is @p detail.
  [[nodiscard]] static Result good_with_detail(shared_ptr<const ErrorDetail> detail) noexcept
  {
    Result result;
    result.mStatusCode = StatusCode{Status::Good, std::move(detail)};
    return result;
  }

  /// Copy-constructs an independent result; any @ref ErrorDetail is shared, not cloned.
  Result(const Result&) = default;
  /// Move-constructs from another result, leaving it in a valid but unspecified state.
  Result(Result&&) noexcept = default;
  /// Copy-assigns; any @ref ErrorDetail is shared, not cloned.
  ///
  /// @return A reference to this result.
  Result& operator=(const Result&) = default;
  /// Move-assigns, leaving the source in a valid but unspecified state.
  ///
  /// @return A reference to this result.
  Result& operator=(Result&&) noexcept = default;
  /// Destroys the result, releasing any error detail.
  ~Result() = default;

  /// Returns true if the operation succeeded (status is Good).
  ///
  /// @return `true` if the status is Good.
  [[nodiscard]] bool is_good() const noexcept
  {
    return mStatusCode.is_good();
  }

  /// Returns true if the status is Bad.
  ///
  /// @return `true` if the status is Bad.
  [[nodiscard]] bool is_bad() const noexcept
  {
    return mStatusCode.is_bad();
  }

  /// Returns true if the status is Uncertain.
  ///
  /// @return `true` if the status is Uncertain.
  [[nodiscard]] bool is_uncertain() const noexcept
  {
    return mStatusCode.is_uncertain();
  }

  /// Returns true if the status is Uncertain or Bad.
  ///
  /// @return `true` if the status is not Good.
  [[nodiscard]] bool is_not_good() const noexcept
  {
    return mStatusCode.is_not_good();
  }

  /// Returns true if the status is Good or Uncertain.
  ///
  /// @return `true` if the status is not Bad.
  [[nodiscard]] bool is_not_bad() const noexcept
  {
    return mStatusCode.is_not_bad();
  }

  /// Returns true if the status is Good or Bad.
  ///
  /// @return `true` if the status is not Uncertain.
  [[nodiscard]] bool is_not_uncertain() const noexcept
  {
    return mStatusCode.is_not_uncertain();
  }

  /// Returns true if the operation succeeded; equivalent to is_good().
  ///
  /// @return `true` if the result is good; equivalent to is_good().
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return is_good();
  }

  /// Returns the status code: plain Good or a Good subcode on success, an Uncertain or Bad code
  /// otherwise.
  ///
  /// @return The status code.
  [[nodiscard]] StatusCode status_code() const noexcept
  {
    return mStatusCode;
  }

  /// Returns the attached error detail, or null if none.
  ///
  /// The pointer is owned by this Result and valid only for its lifetime.
  ///
  /// @return The attached error detail, or null if none.
  [[nodiscard]] const ErrorDetail* error_detail() const noexcept
  {
    return mStatusCode.detail();
  }

  /// Returns the attached error detail as a shared pointer (null if none).
  ///
  /// @return The attached error detail as a shared pointer, or null if none.
  [[nodiscard]] const shared_ptr<const ErrorDetail>& shared_detail() const noexcept
  {
    return mStatusCode.shared_detail();
  }

  /// Throws unless the status is Good; a no-op on success.
  ///
  /// The `Result<void>` analogue of value(): use it to surface an Uncertain or Bad status as an
  /// exception when ignoring the success case.
  ///
  /// @throws UaException carrying status_code() and any error detail if the status is not Good.
  void value() const
  {
    if (is_good())
    {
      return;
    }
    if (auto detail = mStatusCode.shared_detail())
    {
      throw UaException{mStatusCode.as_status(), std::move(detail)};
    }
    throw UaException{mStatusCode.as_status(),
      ErrorDetail::build("ResultAccessedWithoutValue", "Result accessed without value", "Result")
        .cause(mStatusCode)};
  }

private:
  template<typename U>
  friend class Result;

  StatusCode mStatusCode;
};

/// Convenience alias for @ref Result<void> - an operation that succeeds or fails
/// with no value.
using VoidResult = Result<void>;

namespace detail
{

template<typename U>
Result<U> held(U value, StatusCode status)
{
  if constexpr (std::is_same_v<U, StatusCode>)
  {
    return Result<StatusCode>::with_value(std::move(value), std::move(status));
  }
  else
  {
    return Result<U>{std::move(value), std::move(status)};
  }
}

template<typename R>
R carried(R result, const StatusCode& outer)
{
  if (!outer_status_answered(outer, result.status_code()))
  {
    return result;
  }
  if constexpr (std::is_same_v<R, Result<void>>)
  {
    return R{outer};
  }
  else
  {
    if (!result.has_value())
    {
      return R{outer};
    }
    return held(std::move(result).value(), outer);
  }
}

/// The value of @p result when its status is Good; throws a @ref UaException carrying the status and
/// its detail otherwise, an Uncertain result holding a value included.
///
/// What a throwing `*_sync` form returns: it has no place for an Uncertain code, so it gives only a Good
/// answer's value. A Good subcode is not returned; the form's `try_` variant returns it.
///
/// @param result The result of the `try_` variant.
/// @return The held value.
/// @throws UaException carrying the status and its detail when the status is not Good.
template<typename T>
T good_value(Result<T>&& result)
{
  if (result.has_value() && !result.is_good())
  {
    throw_status(result.status_code(),
      "ResultNotGood",
      "The answer is not Good, so the throwing form gives no value; its try_ form gives the value");
  }
  return std::move(result).value();
}

}  // namespace detail

/// Outcome of a batch operation: a batch-level status plus per-item results.
///
/// A batch carries two distinct layers of status. The batch-level
/// @ref batchStatus reports whether the request as a whole was accepted and
/// processed; the per-item @ref items report the individual outcomes once it
/// was. The two are independent - a good batch may still contain bad items.
///
/// When `batchStatus.is_good()` the batch itself was accepted and @ref items
/// holds the per-item results, each of which may independently be good or bad.
///
/// When `batchStatus.is_bad()` the batch failed as a whole (e.g. authorization
/// denied, malformed request, pre-flight service failure). @ref items may be
/// empty, and any @ref ErrorDetail attached to @ref batchStatus describes the
/// batch-level cause.
///
/// @tparam T Per-item result type stored in @ref items.
/// @see Result, VoidResult
/// @ingroup general
template<typename T>
struct BatchResult
{
  /// Batch-level outcome: good if the request as a whole was accepted.
  ///
  /// On failure carries the @ref ErrorDetail describing the batch-level cause;
  /// on success the individual outcomes are reported in @ref items.
  VoidResult batchStatus;

  /// Per-item results, in request order.
  ///
  /// Populated only when @ref batchStatus is good; may be empty when the batch
  /// failed as a whole. Each element may independently be good or bad.
  ///
  /// Small-buffer-optimised: batches of four or fewer - a single-node resolution, one monitoring
  /// item, one authorization subject - carry their results inside this object and allocate nothing.
  /// The interface is `std::vector`'s, so no call site distinguishes the two.
  boost::container::small_vector<T, 4> items;
};

/// Trait detecting whether @p T is a `Result<U>` for some `U`.
///
/// `is_result<T>::value` is true exactly when @p T is a @ref Result
/// specialization. See is_result_v for the variable-template shorthand.
///
/// @tparam T Type under inspection.
template<typename T>
// Mirrors the std:: type-trait convention (snake_case + `_v`), so it reads like the standard
// traits it sits alongside; deliberately exempt from the CamelCase class rule.
// NOLINTNEXTLINE(readability-identifier-naming)
struct is_result : std::false_type
{};

/// Specialization recognising any `Result<U>` as a Result.
///
/// @tparam U Held value type of the matched Result.
template<typename U>
// NOLINTNEXTLINE(readability-identifier-naming) -- see the is_result primary template above
struct is_result<Result<U>> : std::true_type
{};

/// Variable-template shorthand for `is_result<T>::value`.
///
/// @tparam T Type under inspection.
template<typename T>
// NOLINTNEXTLINE(readability-identifier-naming) -- mirrors the std:: `_v` trait-alias convention
inline constexpr bool is_result_v = is_result<T>::value;

}  // namespace ua

#endif  // !UA_RESULT_H
