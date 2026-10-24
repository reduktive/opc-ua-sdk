// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::async::guarded - the noexcept exception-consuming wrapper
// for our own async continuations. The contract under test:
//   * a continuation that throws must NOT propagate out of the wrapper (the
//     wrapper is the thing that stands between a throwing continuation and the
//     noexcept Asio completion boundary that would otherwise std::terminate);
//   * the swallowed exception must be logged at Error level (no silent discard);
//   * for a UaException the structured {status, error} fields are recorded;
//   * a non-throwing continuation runs normally, forwards its args, and logs
//     nothing.
//
// Falsifiability: if guarded did not catch, the throwing cases would terminate
// the test process (an escaping throw from a noexcept lambda) or propagate out
// of cb(...) and fail the EXPECT_NO_THROW. If it caught but did not log, the
// recorded-entry assertions would fail.

#include "ua_on_strand.h"

#include "ua_exceptions.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace
{

// A LogSink that records every entry so the test can assert what was logged.
class RecordingSink : public ua::LogSink
{
public:
  struct Record
  {
    ua::LogLevel level;
    std::string message;
    std::vector<std::string> fieldKeys;
  };

  void log(const ua::LogEntry& entry) override
  {
    std::lock_guard<std::mutex> lock{mMutex};
    Record record{entry.level, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      record.fieldKeys.emplace_back(field.key);
    }
    mRecords.push_back(std::move(record));
  }

  std::vector<Record> records()
  {
    std::lock_guard<std::mutex> lock{mMutex};
    return mRecords;
  }

private:
  std::mutex mMutex;
  std::vector<Record> mRecords;
};

// Builds a Logger wired to a fresh RecordingSink at Trace level (so every level
// passes the filter). Returns both so the test can inspect what was recorded.
std::pair<ua::Logger, std::shared_ptr<RecordingSink>> make_recording_logger()
{
  auto sink = std::make_shared<RecordingSink>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  return {ua::Logger{sink, level, "test.guarded"}, sink};
}

bool has_error_record(const std::vector<RecordingSink::Record>& records)
{
  for (const auto& record : records)
  {
    if (record.level == ua::LogLevel::Error)
      return true;
  }
  return false;
}

}  // namespace

TEST(Guarded, UaExceptionIsCaughtAndLoggedWithStatusField)
{
  auto [logger, sink] = make_recording_logger();

  auto wrapped =
    ua::async::guarded(logger, []() { throw ua::UaException{ua::Status::BadInvalidState, nullptr}; });

  // Must not propagate - the whole point of the wrapper.
  EXPECT_NO_THROW(wrapped());

  auto records = sink->records();
  ASSERT_FALSE(records.empty()) << "the swallowed exception must be logged, never silently discarded";

  bool sawStatusField = false;
  bool sawErrorLevel = false;
  for (const auto& record : records)
  {
    if (record.level == ua::LogLevel::Error)
    {
      sawErrorLevel = true;
      for (const auto& key : record.fieldKeys)
      {
        if (key == "status")
          sawStatusField = true;
      }
    }
  }
  EXPECT_TRUE(sawErrorLevel) << "UaException must be logged at Error level";
  EXPECT_TRUE(sawStatusField) << "the ErrorDetail-aware path must record the StatusCode in a 'status' field";
}

TEST(Guarded, StdExceptionIsCaughtAndLogged)
{
  auto [logger, sink] = make_recording_logger();

  auto wrapped = ua::async::guarded(logger, []() { throw std::runtime_error{"boom"}; });

  EXPECT_NO_THROW(wrapped());

  EXPECT_TRUE(has_error_record(sink->records()))
    << "a std::exception thrown by a continuation must be caught and logged at Error level";
}

TEST(Guarded, NonStdExceptionIsCaughtAndLogged)
{
  auto [logger, sink] = make_recording_logger();

  auto wrapped = ua::async::guarded(logger, []() { throw 42; });

  EXPECT_NO_THROW(wrapped());

  EXPECT_TRUE(has_error_record(sink->records()))
    << "a non-std throw (catch(...)) must still be caught and logged";
}

TEST(Guarded, NonThrowingContinuationRunsAndLogsNothing)
{
  auto [logger, sink] = make_recording_logger();

  int ran = 0;
  auto wrapped = ua::async::guarded(logger, [&ran]() { ++ran; });

  EXPECT_NO_THROW(wrapped());

  EXPECT_EQ(ran, 1) << "the continuation must run when it does not throw";
  EXPECT_TRUE(sink->records().empty()) << "a successful continuation must not log anything";
}

TEST(Guarded, ForwardsProducerArgumentsToHandler)
{
  auto [logger, sink] = make_recording_logger();

  int seen = 0;
  auto wrapped = ua::async::guarded(logger, [&seen](int value) { seen = value; });

  EXPECT_NO_THROW(wrapped(7));

  EXPECT_EQ(seen, 7) << "guarded must forward the producer's arguments to the handler";
  EXPECT_TRUE(sink->records().empty());
}

TEST(Guarded, ThrowFromAStrandPostDoesNotTerminateAndIsLogged)
{
  // The real escape path: a throwing continuation posted to a strand runs at a
  // noexcept Asio completion boundary. Without guarded this would std::terminate
  // the process. With guarded it is caught and logged on the worker thread.
  auto [logger, sink] = make_recording_logger();

  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());

  boost::asio::post(strand,
    ua::async::guarded(logger, []() { throw ua::UaException{ua::Status::BadInvalidState, nullptr}; }));

  ::ua::test_utils::drain_with_timeout(pool);
  ::ua::test_utils::drain_with_timeout(pool);

  EXPECT_TRUE(has_error_record(sink->records()))
    << "the exception thrown on the strand must be caught and logged, not terminate the process";
}
