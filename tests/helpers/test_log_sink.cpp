// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "test_log_sink.h"

#include "ua_log_level.h"

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <ctime>

namespace ua::test_helpers
{

namespace
{

std::string format_entry(const LogEntry& entry)
{
  auto now = std::chrono::system_clock::now();

  // Format the timestamp from broken-down integer fields rather than a chrono format spec. The chrono
  // "%S" / "%H:%M:%S" formatter unconditionally instantiates fmt's write_floating_seconds path, whose
  // internal FMT_STRING (basic_format_string<char, double, int&>) is evaluated at compile time
  // regardless of the value's precision; clang-20's stricter consteval rejects it (fmt 10.2.1) even for
  // a whole-second time_point, while clang-19 tolerates it. Extracting Y/M/D/H/M/S via fmt::gmtime (a
  // thread-safe std::tm wrapper, UTC) and formatting only integers keeps the floating-seconds formatter
  // out of the translation unit, so this compiles on every supported compiler. Mirrors ua_log_format.cpp.
  auto seconds = std::chrono::floor<std::chrono::seconds>(now);
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
  std::tm utc = fmt::gmtime(std::chrono::system_clock::to_time_t(seconds));

  auto line = fmt::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03d} [{:>8}] [{}]",
    utc.tm_year + 1900,
    utc.tm_mon + 1,
    utc.tm_mday,
    utc.tm_hour,
    utc.tm_min,
    utc.tm_sec,
    millis,
    to_string(entry.level),
    entry.category);

  for (const auto& field : entry.fields)
  {
    line += fmt::format(" {}=", field.key);
    std::visit(
      [&line](const auto& v)
      {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::string_view>)
        {
          if (v.find(' ') != std::string_view::npos)
            line += fmt::format("\"{}\"", v);
          else
            line += fmt::format("{}", v);
        }
        else
        {
          line += fmt::format("{}", v);
        }
      },
      field.value);
  }

  line += fmt::format(" {}\n", entry.message);
  return line;
}

/// GTest listener that drives the TestLogSink lifecycle.
class TestLogListener : public ::testing::EmptyTestEventListener
{
public:
  explicit TestLogListener(std::shared_ptr<TestLogSink> sink) : mSink(std::move(sink))
  {}

  void OnTestStart(const ::testing::TestInfo& /*info*/) override
  {
    mSink->clear();
  }

  void OnTestEnd(const ::testing::TestInfo& info) override
  {
    if (info.result()->Failed())
    {
      mSink->flush_to_stderr();
    }
    else
    {
      mSink->clear();
    }
  }

private:
  std::shared_ptr<TestLogSink> mSink;
};

std::shared_ptr<TestLogSink> gGlobalSink;

}  // namespace

TestLogSink::TestLogSink(bool alwaysPrint) : mAlwaysPrint(alwaysPrint)
{}

void TestLogSink::log(const LogEntry& entry)
{
  auto formatted = format_entry(entry);

  if (mAlwaysPrint)
  {
    fmt::print(stderr, "{}", formatted);
    return;
  }

  std::lock_guard lock(mMutex);
  mEntries.push_back(StoredEntry{
    .level = entry.level,
    .category = std::string(entry.category),
    .message = entry.message,
    .formatted = std::move(formatted),
  });
}

void TestLogSink::clear()
{
  std::lock_guard lock(mMutex);
  mEntries.clear();
}

void TestLogSink::flush_to_stderr()
{
  std::lock_guard lock(mMutex);
  if (!mEntries.empty())
  {
    fmt::print(stderr, "--- SDK log output for failed test ---\n");
    for (const auto& entry : mEntries)
    {
      fmt::print(stderr, "{}", entry.formatted);
    }
    fmt::print(stderr, "--- end SDK log output ---\n");
  }
  mEntries.clear();
}

std::shared_ptr<TestLogSink> test_log_sink()
{
  if (!gGlobalSink)
  {
    const char* envVar = std::getenv("SDK_TEST_LOG");
    bool alwaysPrint = envVar && std::string_view(envVar) == "1";
    gGlobalSink = std::make_shared<TestLogSink>(alwaysPrint);
  }
  return gGlobalSink;
}

void install_test_log_listener()
{
  auto sink = test_log_sink();
  auto& listeners = ::testing::UnitTest::GetInstance()->listeners();
  listeners.Append(new TestLogListener(std::move(sink)));
}

}  // namespace ua::test_helpers
