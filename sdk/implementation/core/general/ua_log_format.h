// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Shared formatter that renders a @ref ua::LogEntry as a single text line.
/// @ingroup general

#ifndef UA_LOG_FORMAT_H
#define UA_LOG_FORMAT_H

#include "ua_log_entry.h"

#include <string>

namespace ua::detail
{

/// Renders @p entry as a single formatted log line, including the trailing newline.
///
/// The line has the form
/// `<timestamp> [<level>] [<category>] <key>=<value> ... <message>\n`, where the timestamp is
/// the local wall-clock time at which the entry is processed. String field values containing a
/// space are quoted with `"` so they cannot bleed into adjacent fields.
///
/// This is the single source of truth shared by every text-line @ref LogSink (console, file, ...)
/// so their output is identical.
///
/// @param entry Log entry to render; referenced only for the duration of the call.
/// @return The formatted line terminated by `\n`.
std::string format_log_line(const LogEntry& entry);

}  // namespace ua::detail

#endif  // UA_LOG_FORMAT_H
