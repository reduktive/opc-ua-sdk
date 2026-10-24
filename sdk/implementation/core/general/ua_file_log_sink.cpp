// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_log_sink_implementations.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_log_format.h"

#include <ios>

namespace ua
{

FileLogSink::FileLogSink(std::string_view path, bool append)
{
  // Binary mode: write exactly the bytes the formatter produces. Without it, Windows text mode
  // translates '\n' to '\r\n', so the on-disk content would not match the formatter output
  // byte-for-byte (the formatter owns line endings). See FileLogSink.ContentMatchesFormatterByteForByte.
  const auto mode = std::ios::out | std::ios::binary | (append ? std::ios::app : std::ios::trunc);
  mStream.open(std::string{path}, mode);
  if (!mStream.is_open())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("LogFileOpenFailed", "Could not open log file for writing", "FileLogSink")
        .context(ContextKeys::filePath, std::string{path})};
  }
}

void FileLogSink::log(const LogEntry& entry)
{
  auto line = detail::format_log_line(entry);

  const std::lock_guard lock{mMutex};
  mStream << line;
  mStream.flush();
}

}  // namespace ua
