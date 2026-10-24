// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Logging severity levels and their textual names.
/// @ingroup general

#ifndef UA_LOG_LEVEL_H
#define UA_LOG_LEVEL_H

#include <cstdint>
#include <string_view>

namespace ua
{

/// Severity of a log record, ordered from most to least verbose.
///
/// The enumerators increase in severity from @ref LogLevel::Trace to
/// @ref LogLevel::Critical, so a level filter can compare with `>=` to admit a
/// record at or above a configured threshold.
/// @ingroup general
enum class LogLevel : uint8_t
{
  Trace,  ///< Finest-grained diagnostic detail; high-volume tracing.
  Debug,  ///< Diagnostic information useful while developing or debugging.
  Info,  ///< Normal operational events worth recording.
  Warning,  ///< An unexpected condition that did not prevent operation.
  Error,  ///< A failure that aborted the current operation.
  Critical  ///< A severe failure threatening continued operation.
};

/// Returns the lowercase textual name of a log level.
///
/// The returned view refers to a static string literal and remains valid for
/// the lifetime of the program.
///
/// @param level Level to name.
/// @return The level's name (e.g. `"info"`), or `"unknown"` if @p level is not
///         a defined enumerator.
constexpr std::string_view to_string(LogLevel level) noexcept
{
  switch (level)
  {
  case LogLevel::Trace:
    return "trace";
  case LogLevel::Debug:
    return "debug";
  case LogLevel::Info:
    return "info";
  case LogLevel::Warning:
    return "warning";
  case LogLevel::Error:
    return "error";
  case LogLevel::Critical:
    return "critical";
  }
  return "unknown";
}

}  // namespace ua

#endif  // UA_LOG_LEVEL_H
