// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Concrete LogSink implementations that write formatted log entries to
///        the console and to a file.
/// @ingroup general

#ifndef UA_LOG_SINK_IMPLEMENTATIONS_H
#define UA_LOG_SINK_IMPLEMENTATIONS_H

#include "ua_log_sink.h"

#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace ua
{

/// A LogSink that writes each entry as a single formatted text line to standard error.
///
/// Each entry is rendered as `<timestamp> [<level>] [<category>] <key>=<value> ... <message>`,
/// where the timestamp is the local wall-clock time at which the entry is processed. String
/// field values containing spaces are quoted so they cannot bleed into adjacent fields. The
/// formatted line is written to `stderr`.
///
/// Stateless and thread-safe: instances hold no mutable state and may be shared and invoked
/// concurrently from any thread.
/// @see LogSink
/// @ingroup general
class ConsoleLogSink : public LogSink
{
public:
  /// Writes @p entry as one formatted line to `stderr`.
  ///
  /// Safe to call concurrently from any thread.
  ///
  /// @param entry Log entry to render; referenced only for the duration of the call.
  void log(const LogEntry& entry) override;
};

/// A LogSink that writes each entry as a single formatted text line to a file.
///
/// Each entry is rendered exactly as @ref ConsoleLogSink renders it -
/// `<timestamp> [<level>] [<category>] <key>=<value> ... <message>` - using the same shared
/// formatter, so file and console output are byte-for-byte identical. String field values
/// containing a space are quoted so they cannot bleed into adjacent fields. Each line is
/// flushed immediately so a crash cannot lose the most recently written entries.
///
/// Stateful and thread-safe: the sink owns the underlying `std::ofstream` and serializes every
/// @ref log() write with an internal mutex, so it may be shared and invoked concurrently from
/// any thread. Because it owns a file stream and a mutex it is neither copyable nor movable.
///
/// @par Error handling
/// The constructor opens the target file and **throws** @ref UaException (carrying an
/// @ref ErrorDetail with the file path) if the file cannot be opened. A successfully constructed
/// instance is therefore guaranteed to have an open file; the open failure is never silently
/// swallowed.
///
/// @see ConsoleLogSink, LogSink
/// @ingroup general
class FileLogSink : public LogSink
{
public:
  /// Opens @p path and creates a sink that appends or truncates per @p append.
  ///
  /// @param path   Filesystem path of the log file to write. Parent directories must already
  ///               exist; the file itself is created if missing.
  /// @param append When `true` (the default) new entries are appended to any existing content;
  ///               when `false` the file is truncated on open.
  /// @throws UaException If the file cannot be opened for writing. The exception carries an
  ///         @ref ErrorDetail whose context includes the offending path.
  explicit FileLogSink(std::string_view path, bool append = true);

  /// Flushes and closes the underlying file.
  ~FileLogSink() override = default;

  FileLogSink(const FileLogSink&) = delete;
  FileLogSink& operator=(const FileLogSink&) = delete;
  FileLogSink(FileLogSink&&) = delete;
  FileLogSink& operator=(FileLogSink&&) = delete;

  /// Writes @p entry as one formatted line to the file and flushes it.
  ///
  /// Safe to call concurrently from any thread; writes are serialized by an internal mutex.
  ///
  /// @param entry Log entry to render; referenced only for the duration of the call.
  void log(const LogEntry& entry) override;

private:
  std::mutex mMutex;
  std::ofstream mStream;
};

}  // namespace ua

#endif  // UA_LOG_SINK_IMPLEMENTATIONS_H
