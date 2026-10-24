// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LOG_EXCEPTION_H
#define UA_LOG_EXCEPTION_H

#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include "fmt/format.h"

namespace ua
{

namespace detail
{

/// Emit a log record with `{site}` as the message at the given level.
/// Always a single `switch`; callers hand in prebuilt structured fields.
inline void emit_site_log(
  const Logger& logger, LogLevel level, std::initializer_list<LogField> fields, const char* site)
{
  switch (level)
  {
  case LogLevel::Trace:
    logger.trace(fields, "{}", site);
    break;
  case LogLevel::Debug:
    logger.debug(fields, "{}", site);
    break;
  case LogLevel::Info:
    logger.info(fields, "{}", site);
    break;
  case LogLevel::Warning:
    logger.warning(fields, "{}", site);
    break;
  case LogLevel::Error:
    logger.error(fields, "{}", site);
    break;
  case LogLevel::Critical:
    logger.critical(fields, "{}", site);
    break;
  }
}

/// Format a {status, error?} structured log. Shared by `log_exception` and
/// `log_batch_failure` - `status_code` and `detail` are the only varying inputs.
inline void log_status_and_detail(const Logger& logger, LogLevel level, const char* site, StatusCode status,
  const shared_ptr<const ErrorDetail>& detail)
{
  if (!logger.is_enabled(level))
    return;

  auto statusStr = to_string(status);
  if (detail)
  {
    auto detailStr = to_string(*detail);
    emit_site_log(
      logger, level, {{"status", std::string_view{statusStr}}, {"error", std::string_view{detailStr}}}, site);
  }
  else
  {
    emit_site_log(logger, level, {{"status", std::string_view{statusStr}}}, site);
  }
}

}  // namespace detail

/// Log a rich StatusCode at the given level with structured status/error fields.
/// Use this at catch sites to capture ErrorDetail before it is lost.
inline void log_exception(const Logger& logger, LogLevel level, const char* site, const StatusCode& er)
{
  detail::log_status_and_detail(logger, level, site, er, er.shared_detail());
}

/// Convenience overload: extract StatusCode from exception_ptr, then log.
inline void log_exception(const Logger& logger, LogLevel level, const char* site, std::exception_ptr eptr)
{
  auto er = ::ua::exception_to_status_code(std::move(eptr));
  log_exception(logger, level, site, er);
}

/// Convenience overload: log at Error level (the common case for unexpected exceptions).
inline void log_exception(const Logger& logger, const char* site, std::exception_ptr eptr)
{
  log_exception(logger, LogLevel::Error, site, std::move(eptr));
}

/// Log a delegate-returned batch-level failure with its StatusCode and optional
/// ErrorDetail. Use this at services where a namespace/delegate may fail a whole
/// batch (e.g. backend unavailable) - that failure would otherwise be silent on
/// the server side since it does not throw.
inline void log_batch_failure(
  const Logger& logger, LogLevel level, const char* site, const VoidResult& result)
{
  detail::log_status_and_detail(logger, level, site, result.status_code(), result.shared_detail());
}

/// Convenience overload: log at Warning level (the common case for delegate-returned batch failures).
inline void log_batch_failure(const Logger& logger, const char* site, const VoidResult& result)
{
  log_batch_failure(logger, LogLevel::Warning, site, result);
}

}  // namespace ua

#endif  // !UA_LOG_EXCEPTION_H
