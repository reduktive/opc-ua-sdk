// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Sink interface that receives structured log entries for emission.
/// @ingroup general

#ifndef UA_LOG_SINK_H
#define UA_LOG_SINK_H

#include "ua_log_entry.h"

namespace ua
{

/// A destination that emits structured log entries.
///
/// Implementations forward each @ref LogEntry to a backend (console, file,
/// syslog, test buffer, ...). The logging facade may invoke @ref log() concurrently
/// from any thread, so implementations must be thread-safe.
/// @ingroup general
/// @see LogEntry, LogLevel
class LogSink
{
public:
  LogSink() = default;
  virtual ~LogSink() = default;

  /// Non-copyable, non-movable: a sink is a polymorphic interface held by
  /// pointer/reference and never sliced through a by-value copy or move.
  LogSink(const LogSink&) = delete;
  LogSink& operator=(const LogSink&) = delete;
  LogSink(LogSink&&) = delete;
  LogSink& operator=(LogSink&&) = delete;

  /// Emits a single structured log entry.
  ///
  /// Called by the logging facade for each record that passes the active level
  /// filter. May be invoked concurrently from any thread; implementations must be
  /// thread-safe. The entry and its view members reference caller-owned storage
  /// that is only guaranteed valid for the duration of this call - a sink that
  /// retains the record beyond the call must copy what it needs (see @ref LogEntry).
  ///
  /// @param entry The record to emit; valid only for the duration of the call.
  virtual void log(const LogEntry& entry) = 0;
};

}  // namespace ua

#endif  // UA_LOG_SINK_H
