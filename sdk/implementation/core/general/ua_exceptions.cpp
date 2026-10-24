// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "ua_status_code.h"
#include "ua_status_to_string.h"
#include "ua_to_result.h"
#include "fmt/format.h"

namespace ua
{

namespace
{

// Constant initialization requires no allocator; GCC and Clang constant-initialize this storage, and MSVC,
// whose std::string cannot be constant-initialized, initializes it before main, where its short strings need
// no allocation. The union deliberately leaves its variant member undestroyed, so exception translation
// remains valid from later static destructors too.
union ExceptionDiagnosticStorage
{
  const ErrorDetail value;

  constexpr ExceptionDiagnosticStorage()
    : value{.code = "DiagnosticOOM",
        .summary = "No memory",
        .detail = {},
        .source = "Exception",
        .innerStatus = utils::to_underlying(Status::Good),
        .cause = {},
        .context = {}}
  {}

  ExceptionDiagnosticStorage(const ExceptionDiagnosticStorage&) = delete;
  ExceptionDiagnosticStorage(ExceptionDiagnosticStorage&&) = delete;
  ExceptionDiagnosticStorage& operator=(const ExceptionDiagnosticStorage&) = delete;
  ExceptionDiagnosticStorage& operator=(ExceptionDiagnosticStorage&&) = delete;

  ~ExceptionDiagnosticStorage()
  {}
};

const ExceptionDiagnosticStorage exceptionDiagnosticStorage;
// Cache the member address before destruction; translation never accesses the enclosing union again.
constexpr const ErrorDetail* exceptionDiagnostic = &exceptionDiagnosticStorage.value;

std::string format_what(StatusCodeValue status, const ErrorDetail* detail, const source_location& loc)
{
  const StatusCode sc{status};
  if (detail && !detail->summary.empty())
  {
    return fmt::format("{} [{}] in file {} in function {} at line:column {}:{}",
      detail->summary,
      to_string(sc.as_status()),
      loc.file_name(),
      loc.function_name(),
      loc.line(),
      loc.column());
  }
  return fmt::format("[{}] in file {} in function {} at line:column {}:{}",
    to_string(sc.as_status()),
    loc.file_name(),
    loc.function_name(),
    loc.line(),
    loc.column());
}

}  // namespace

StatusCode exception_to_status_code(std::exception_ptr eptr) noexcept
{
  Status mappedStatus = Status::BadInternalError;
  try
  {
    // Calling the converter here would recurse.
    // nosemgrep: dual-catch-blocks -- The converter must distinguish exception types.
    try
    {
      std::rethrow_exception(eptr);
    }
    catch (const UaException& ex)
    {
      return ex.status_code();
    }
    catch (const std::bad_alloc&)
    {
      mappedStatus = Status::BadOutOfMemory;
      return StatusCode{
        mappedStatus, make_error_detail("BadAlloc", "Memory allocation failed", "exception_to_status_code")};
    }
    catch (const std::exception& ex)
    {
      return StatusCode{mappedStatus,
        ErrorDetail::build("StdException", "Unhandled std::exception", "exception_to_status_code")
          .context(ContextKeys::errorMessage, ex.what())};
    }
    catch (...)
    {
      return StatusCode{mappedStatus,
        make_error_detail("UnknownException", "Non-standard exception caught", "exception_to_status_code")};
    }
  }
  catch (...)
  {
    // An alias with an empty owner has no control-block allocation. The pointee has static storage
    // and is never destroyed; copying this shared_ptr is safe even while every allocation fails.
    return StatusCode{mappedStatus,
      std::shared_ptr<const ErrorDetail>{std::shared_ptr<const ErrorDetail>{}, exceptionDiagnostic}};
  }
}

UaException::UaException(StatusCode status, source_location location)
  : mStatus(status.value()), mDetail(status.shared_detail()), mLocation(location),
    mWhat(format_what(mStatus, mDetail.get(), mLocation))
{}

UaException::UaException(Status status, std::shared_ptr<const ErrorDetail> detail, source_location location)
  : mStatus(utils::to_underlying(status)), mDetail(std::move(detail)), mLocation(location),
    mWhat(format_what(mStatus, mDetail.get(), mLocation))
{}

UaException::~UaException() = default;

UaException::UaException(UaException&& other) noexcept = default;

UaException& UaException::operator=(UaException&& other) noexcept = default;

Status UaException::status() const
{
  return StatusCode{mStatus}.as_status();
}

StatusCode UaException::status_code() const noexcept
{
  return StatusCode{mStatus, mDetail};
}

const ErrorDetail* UaException::detail() const noexcept
{
  return mDetail.get();
}

std::shared_ptr<const ErrorDetail> UaException::take_detail() const noexcept
{
  return mDetail;
}

void throw_null_pointer_check(Status throwStatus, source_location location)
{
  throw UaException{throwStatus,
    make_error_detail("NullPointer", "Null pointer passed where a valid pointer was required", "check"),
    location};
}

void throw_empty_optional_check(Status throwStatus, source_location location)
{
  throw UaException{
    throwStatus, make_error_detail("EmptyOptional", "Optional variable is empty", "check"), location};
}

void throw_empty_function_check(Status throwStatus, source_location location)
{
  throw UaException{throwStatus,
    make_error_detail("EmptyFunction", "std::function contains no callable target", "check"),
    location};
}

void check_true(bool value, Status throwStatus, source_location location)
{
  if (!value)
  {
    throw UaException{throwStatus,
      make_error_detail("PreconditionFailed", "Boolean precondition check failed", "check"),
      location};
  }
}

}  // namespace ua
