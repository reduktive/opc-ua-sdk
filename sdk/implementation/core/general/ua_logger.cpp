// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_logger.h"

namespace ua
{

Logger::Logger(
  std::shared_ptr<LogSink> sink, std::shared_ptr<std::atomic<LogLevel>> level, std::string category)
  : mSink(std::move(sink)), mLevel(std::move(level)), mCategory(std::move(category))
{}

Logger Logger::with_category(std::string category) const
{
  return Logger{mSink, mLevel, std::move(category)};
}

void Logger::write(LogEntry entry) const
{
  // A user-supplied LogSink::log is not noexcept, and Logger emit methods are fired from inside Asio
  // completion handlers and noexcept functions throughout the SDK; a throwing sink would otherwise
  // unwind out of io_context::run() -> std::terminate. Swallow it here. This deliberately does NOT use
  // ua::detail::invoke_user_callback: that helper reports a throwing callback via logger.warning(...)
  // -> write() -> mSink->log(), which would re-enter the same throwing sink and recurse. A bare
  // swallow is the correct primitive (mirrors invoke_user_callback's own no-logger fallback overload).
  // nosemgrep: catch-all-empty-body (deliberate: re-logging a throwing sink would recurse into it, per above)
  try
  {
    mSink->log(entry);
  }
  catch (...)
  {
    // A throwing sink must never cross this boundary; swallow without re-logging (would recurse).
  }
}

}  // namespace ua
