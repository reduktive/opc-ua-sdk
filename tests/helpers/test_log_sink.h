// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef TEST_LOG_SINK_H
#define TEST_LOG_SINK_H

#include "ua_log_level.h"
#include "ua_log_sink.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ua_log_entry.h"
#include "ua_logger.h"

namespace ua::test_helpers
{

/// A LogSink that buffers log entries per test. On test pass the buffer is
/// discarded; on test failure the buffered entries are dumped to stderr.
///
/// The TestLogListener (a GTest TestEventListener) drives the clear/flush
/// lifecycle. Set the environment variable SDK_TEST_LOG=1 to force all log
/// output to stderr regardless of test outcome.
class TestLogSink : public LogSink
{
public:
  explicit TestLogSink(bool alwaysPrint);

  void log(const LogEntry& entry) override;

  /// Discard all buffered entries.
  void clear();

  /// Format and print all buffered entries to stderr, then clear.
  void flush_to_stderr();

private:
  struct StoredEntry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::string formatted;
  };

  std::mutex mMutex;
  std::vector<StoredEntry> mEntries;
  bool mAlwaysPrint;
};

/// Returns the global TestLogSink instance. Created on first call.
/// Call this from test fixtures when wiring up set_log_sink().
std::shared_ptr<TestLogSink> test_log_sink();

/// Register the TestLogListener with GTest and create the global sink.
/// Call once from main() before RUN_ALL_TESTS().
void install_test_log_listener();

// wire_test_log_sink() was removed: the log sink is now installed at construction via the logSink
// argument of Server::create() / CoreClient::create() (there is no runtime set_log_sink). Tests that want
// the buffering test sink pass `test_log_sink()` (with LogLevel::Debug) into create() directly.

}  // namespace ua::test_helpers

namespace ua::test
{

/// A recording sink for a unit test that asserts on what a component logs: logger() hands out a
/// Logger bound to it at Trace level, count() reports the entries recorded at one level.
class TestLogSink
{
public:
  /// A Logger that writes into this sink (every level enabled).
  [[nodiscard]] ua::Logger logger() const
  {
    return ua::Logger{mSink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
  }

  /// The number of entries recorded at @p level.
  [[nodiscard]] std::size_t count(LogLevel level) const
  {
    std::lock_guard lock{mSink->mutex};
    std::size_t n = 0;
    for (const auto entryLevel : mSink->levels)
    {
      n += entryLevel == level ? 1u : 0u;
    }
    return n;
  }

private:
  struct Recorder : LogSink
  {
    void log(const LogEntry& entry) override
    {
      std::lock_guard lock{mutex};
      levels.push_back(entry.level);
    }

    std::mutex mutex;
    std::vector<LogLevel> levels;
  };

  std::shared_ptr<Recorder> mSink = std::make_shared<Recorder>();
};

}  // namespace ua::test

#endif  // TEST_LOG_SINK_H
