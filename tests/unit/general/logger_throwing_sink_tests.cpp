// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Regression: a user-supplied LogSink::log is not noexcept, and Logger emit methods are fired from
// inside Asio completion handlers and noexcept functions throughout the SDK. A throwing sink must be
// swallowed inside Logger::write (ua_logger.cpp), never escape to unwind out of io_context::run() ->
// std::terminate. write() deliberately uses a bare try/catch rather than ua::detail::invoke_user_callback
// (whose logging overload would re-enter the same throwing sink and recurse).

#include <gtest/gtest.h>

#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <string_view>

using namespace ua;

namespace
{

// A LogSink whose log() always throws - the hostile case Logger::write must contain.
class ThrowingLogSink : public LogSink
{
public:
  void log(const LogEntry&) override
  {
    mCalls.fetch_add(1, std::memory_order_relaxed);
    throw std::runtime_error("log sink failure");
  }

  [[nodiscard]] int calls() const
  {
    return mCalls.load(std::memory_order_relaxed);
  }

private:
  std::atomic<int> mCalls{0};
};

Logger make_logger(std::shared_ptr<LogSink> sink)
{
  // Minimum level Trace admits every emit level so write() (and thus the sink) is actually reached.
  return Logger{std::move(sink), std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
}

}  // namespace

TEST(LoggerThrowingSink, EveryEmitLevelSwallowsAThrowingSink)
{
  auto sink = std::make_shared<ThrowingLogSink>();
  const Logger logger = make_logger(sink);

  EXPECT_NO_THROW(logger.trace("boom {}", 1));
  EXPECT_NO_THROW(logger.debug("boom {}", 2));
  EXPECT_NO_THROW(logger.info("boom {}", 3));
  EXPECT_NO_THROW(logger.warning("boom {}", 4));
  EXPECT_NO_THROW(logger.error("boom {}", 5));
  EXPECT_NO_THROW(logger.critical("boom {}", 6));

  // The guard must SWALLOW the throw, not skip the sink: prove the sink really ran each time.
  EXPECT_EQ(sink->calls(), 6) << "Logger::write must invoke the sink and catch its exception";
}

TEST(LoggerThrowingSink, StructuredFieldEmitAlsoSwallows)
{
  auto sink = std::make_shared<ThrowingLogSink>();
  const Logger logger = make_logger(sink);

  EXPECT_NO_THROW(logger.error({LogField{"key", std::string_view{"value"}}}, "structured boom"));
  EXPECT_EQ(sink->calls(), 1);
}
