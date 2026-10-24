// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The SDK exception type and argument-checking helpers for the synchronous API surface.
/// @ingroup general

#ifndef UA_EXCEPTIONS_H
#define UA_EXCEPTIONS_H

#include <functional>
#include <memory>
#include <string>
#include <stdexcept>
#ifdef __cpp_lib_source_location
#include <source_location>
#else
#include "boost/assert/source_location.hpp"
#endif
#include "ua_defines.h"
#include "ua_status.h"

namespace ua
{

class StatusCode;
struct ErrorDetail;

/// Bare 32-bit wire-format StatusCode value.
///
/// Duplicated here to avoid including `ua_status_code.h`, which would create a
/// cycle via `ua_includes.h`. Must match @ref ua::StatusCodeValue in
/// `ua_status_code.h`.
using StatusCodeValue = std::uint32_t;

/// Source location type used to capture throw sites.
///
/// Aliases `std::source_location` when the standard library provides it,
/// otherwise `boost::source_location`. Used as the defaulted trailing argument
/// of the throwing helpers so the call site is recorded automatically.
#ifdef __cpp_lib_source_location
using source_location = std::source_location;
/// Expands to the `source_location` of the current call site.
#define UA_CURRENT_LOCATION source_location::current()
#else
using source_location = boost::source_location;
/// Expands to the `source_location` of the current call site.
#define UA_CURRENT_LOCATION BOOST_CURRENT_LOCATION
#endif

/// The exception thrown by the SDK's throwing (`*_sync`) API surface.
///
/// Carries the full @ref StatusCode that caused the failure, including any
/// attached @ref ErrorDetail and the source location of the throw site. The
/// throwing `*_sync` convenience wrappers raise this on failure; the
/// callback-canonical `*_async` and `try_*_sync` variants never throw and
/// instead surface failures through @ref Result.
/// @ingroup general
class UaException : public std::exception
{
public:
  /// Constructs from a rich StatusCode that may carry an @ref ErrorDetail.
  ///
  /// @param status   The failing StatusCode, including any attached detail.
  /// @param location The throw site; defaults to the caller's location.
  explicit UaException(StatusCode status, source_location location = UA_CURRENT_LOCATION);

  /// Constructs from a bare Status paired with a separately held detail.
  ///
  /// @param status   The symbolic failure code.
  /// @param detail   The associated @ref ErrorDetail; may be null.
  /// @param location The throw site; defaults to the caller's location.
  UaException(
    Status status, std::shared_ptr<const ErrorDetail> detail, source_location location = UA_CURRENT_LOCATION);

  ~UaException() override;

  /// Move-constructs from @p other, transferring its status, detail, location, and message.
  ///
  /// @param other Exception to move from; left in a valid but unspecified state.
  UaException(UaException&& other) noexcept;
  /// Move-assigns from @p other, transferring its status, detail, location, and message.
  ///
  /// @param other Exception to move from; left in a valid but unspecified state.
  /// @return @c *this.
  UaException& operator=(UaException&& other) noexcept;

  /// Copy-constructs an independent exception; the @ref ErrorDetail is shared, not cloned.
  UaException(const UaException&) = default;
  /// Copy-assigns; the @ref ErrorDetail is shared, not cloned.
  ///
  /// @return @c *this.
  UaException& operator=(const UaException&) = default;

  /// Returns the bare symbolic Status, masked to the high 16 bits.
  ///
  /// Convenience for callers that only need the symbolic code. The underlying
  /// StatusCode may carry low-16-bit flags (overflow, semantics/structure
  /// changed, severity) that this getter discards.
  ///
  /// @return The high-16-bit symbolic code.
  /// @see status_code
  [[nodiscard]] Status status() const;

  /// Returns the full 32-bit StatusCode, including any attached @ref ErrorDetail.
  ///
  /// Use this for lossless propagation of the failure.
  ///
  /// @return The complete StatusCode.
  /// @see status
  [[nodiscard]] StatusCode status_code() const noexcept;

  /// Returns a non-owning pointer to the attached @ref ErrorDetail.
  ///
  /// @return The detail, or `nullptr` if none is attached. Valid only while
  ///         this exception is alive.
  [[nodiscard]] const ErrorDetail* detail() const noexcept;

  /// Returns the shared @ref ErrorDetail for handoff into a @ref Result.
  ///
  /// @return The shared detail, or an empty pointer if none is attached.
  [[nodiscard]] std::shared_ptr<const ErrorDetail> take_detail() const noexcept;

  /// Returns the human-readable message for this exception.
  ///
  /// @return A null-terminated message owned by this exception.
  [[nodiscard]] const char* what() const noexcept override
  {
    return mWhat.c_str();
  }

private:
  StatusCodeValue mStatus;
  std::shared_ptr<const ErrorDetail> mDetail;
  source_location mLocation;
  std::string mWhat;
};

/// Throws a `UaException` reporting a failed null-pointer check.
///
/// Out-of-line backend for the pointer `check` overloads, defined where
/// `ErrorDetail` is complete.
///
/// @param throwStatus The Status carried by the thrown exception.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException always.
/// @see check
[[noreturn]] void throw_null_pointer_check(
  Status throwStatus, source_location location = UA_CURRENT_LOCATION);

/// Throws a `UaException` reporting a disengaged `std::optional`.
///
/// @param throwStatus The Status carried by the thrown exception.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException always.
/// @see check
[[noreturn]] void throw_empty_optional_check(
  Status throwStatus, source_location location = UA_CURRENT_LOCATION);

/// Throws a `UaException` reporting an empty `std::function`.
///
/// @param throwStatus The Status carried by the thrown exception.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException always.
/// @see check
[[noreturn]] void throw_empty_function_check(
  Status throwStatus, source_location location = UA_CURRENT_LOCATION);

/// Throws unless the given raw pointer is non-null.
///
/// @param pointer     The pointer to validate; not retained.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p pointer is null.
inline void check(const auto* pointer, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (pointer == nullptr)
  {
    throw_null_pointer_check(throwStatus, location);
  }
}

/// Throws unless the given `std::unique_ptr` holds an object.
///
/// @param pointer     The owning pointer to validate; not retained.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p pointer is empty.
template<typename T>
void check(const std::unique_ptr<T>& pointer, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (!pointer)
  {
    throw_null_pointer_check(throwStatus, location);
  }
}

/// Throws unless the given `std::shared_ptr` holds an object.
///
/// @param pointer     The shared pointer to validate; not retained.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p pointer is empty.
template<typename T>
void check(const std::shared_ptr<T>& pointer, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (!pointer)
  {
    throw_null_pointer_check(throwStatus, location);
  }
}

/// Throws unless the given `std::optional` is engaged.
///
/// @param value       The optional to validate.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p value is disengaged.
template<typename T>
void check(const std::optional<T>& value, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (!value.has_value())
  {
    throw_empty_optional_check(throwStatus, location);
  }
}

/// Throws unless the given `std::function` is callable.
///
/// @param value       The function wrapper to validate; not retained.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p value is empty.
template<class R, class... Args>
void check(const std::function<R(Args...)>& value, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (!value)
  {
    throw_empty_function_check(throwStatus, location);
  }
}

/// Throws unless the given condition holds.
///
/// @param value       The condition that must be `true`.
/// @param throwStatus The Status raised on failure. Defaults to
///                    `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p value is `false`.
void check_true(bool value, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION);

}  // namespace ua

#endif  //! UA_EXCEPTIONS_H
