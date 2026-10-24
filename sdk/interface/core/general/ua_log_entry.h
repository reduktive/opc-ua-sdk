// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Structured log record passed from the logging facade to log sinks.
/// @ingroup general

#ifndef UA_LOG_ENTRY_H
#define UA_LOG_ENTRY_H

#include "ua_log_level.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace ua
{

/// A typed value attached to a structured log field.
///
/// Holds one of the supported scalar kinds. A string value is stored as a
/// non-owning `std::string_view`: the referenced characters are owned by the
/// caller and must outlive the `LogField` that carries them.
using LogValue = std::variant<std::string_view, int64_t, uint64_t, uint32_t, double, bool>;

/// A single structured key/value pair attached to a log entry.
///
/// Both members are non-owning views into caller-owned storage; a LogField does
/// not extend the lifetime of the data it references and must not outlive it.
/// @ingroup general
struct LogField
{
  std::string_view key;  ///< Non-owning field name; storage is owned by the caller.
  LogValue value;  ///< The field's typed value (see @ref LogValue).
};

/// A structured log record handed to a @ref LogSink for emission.
///
/// The view members (@ref category, @ref fields) and any string in @ref fields
/// reference caller-owned storage that need only remain valid for the duration
/// of the @ref LogSink::log() call; sinks that retain data beyond that call must
/// copy it. @ref message is owned by the entry itself.
/// @ingroup general
/// @see LogSink, LogField, LogLevel
struct LogEntry
{
  LogLevel level;  ///< Severity of the record.
  std::string_view category;  ///< Non-owning logical source/category name; caller-owned storage.
  std::string message;  ///< The fully formatted, owned message text.
  std::span<const LogField> fields;  ///< Non-owning view of the structured fields; caller-owned.
};

}  // namespace ua

#endif  // UA_LOG_ENTRY_H
