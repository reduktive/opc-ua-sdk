// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_result.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace ua;

namespace
{

/// Keeps the level, message and "operation" field of every entry it is given.
class RecordingSink : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string message;
    std::string operation;
  };

  void log(const LogEntry& entry) override
  {
    Entry kept{entry.level, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      if (field.key == "operation" && std::holds_alternative<std::string_view>(field.value))
      {
        kept.operation = std::string{std::get<std::string_view>(field.value)};
      }
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(kept));
  }

  std::vector<Entry> entries()
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  std::mutex mMutex;
  std::vector<Entry> mEntries;
};

Logger make_logger(std::shared_ptr<LogSink> sink)
{
  return Logger{std::move(sink), std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST(CompletionOrLog, ASuppliedCallbackIsReturnedAndNothingIsLogged)
{
  auto sink = std::make_shared<RecordingSink>();
  std::optional<VoidResult> delivered;
  auto done = detail::completion_or_log(std::function<void(VoidResult)>{[&delivered](VoidResult result)
                                          {
                                            delivered.emplace(std::move(result));
                                          }},
    make_logger(sink),
    "op");

  done(VoidResult{StatusCode{Status::BadNodeIdUnknown}});

  ASSERT_TRUE(delivered.has_value());
  EXPECT_EQ(delivered->status_code(), StatusCode{Status::BadNodeIdUnknown});
  EXPECT_TRUE(sink->entries().empty());
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST(CompletionOrLog, WithoutACallbackAFailureIsLoggedAtErrorWithItsStatusAndDetail)
{
  auto sink = std::make_shared<RecordingSink>();
  auto done =
    detail::completion_or_log(std::function<void(Result<int>)>{}, make_logger(sink), "Thing::do_async");
  ASSERT_TRUE(done);

  const StatusCode failure{
    Status::BadNodeIdUnknown, ErrorDetail::build("NoSuchNode", "The node is gone", "Test")};
  done(Result<int>{failure});

  const auto entries = sink->entries();
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].level, LogLevel::Error);
  EXPECT_EQ(entries[0].operation, "Thing::do_async");
  EXPECT_NE(entries[0].message.find(describe(failure)), std::string::npos) << entries[0].message;
  EXPECT_NE(entries[0].message.find("NoSuchNode"), std::string::npos) << entries[0].message;
}

// @relation(AC-SVR-DIAG-004-NULL-COMPLETION-STILL-RUNS-AND-LOGS, scope=function)
TEST(CompletionOrLog, WithoutACallbackASuccessIsLoggedAtDebug)
{
  auto sink = std::make_shared<RecordingSink>();
  auto done =
    detail::completion_or_log(std::function<void(VoidResult)>{}, make_logger(sink), "Thing::do_async");

  done(VoidResult{});

  const auto entries = sink->entries();
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].level, LogLevel::Debug);
  EXPECT_EQ(entries[0].operation, "Thing::do_async");
}

}  // namespace
