// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_log_sink_implementations.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_logger.h"
#include "ua_to_result.h"

#include <atomic>
#include <functional>

using namespace ua;

namespace
{

/// LogSink that records warnings for test verification.
class RecordingSink : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    std::lock_guard lk(mMutex);
    mEntries.push_back(Entry{entry.level, entry.message});
  }

  struct Entry
  {
    LogLevel level;
    std::string message;
  };

  std::vector<Entry> entries() const
  {
    std::lock_guard lk(mMutex);
    return mEntries;
  }

  bool has_warning_containing(const std::string& substr) const
  {
    std::lock_guard lk(mMutex);
    for (const auto& e : mEntries)
    {
      if (e.level == LogLevel::Warning && e.message.find(substr) != std::string::npos)
        return true;
    }
    return false;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

Logger make_test_logger(std::shared_ptr<RecordingSink> sink)
{
  auto level = std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace);
  return Logger{std::move(sink), std::move(level), "test"};
}

}  // namespace

// --- to_result tests ---

TEST(ToResult, ReturnsValueOnSuccess)
{
  auto result = ua::detail::to_result([] { return 42; });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 42);
}

TEST(ToResult, ReturnsVoidOnSuccess)
{
  auto result = ua::detail::to_result([] {});
  EXPECT_TRUE(result.is_good());
}

TEST(ToResult, CatchesUaException)
{
  auto result = ua::detail::to_result([]() -> int
    { throw UaException{Status::BadNodeIdUnknown, make_error_detail("TestError", "test", "Test")}; });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
}

TEST(ToResult, CatchesUaExceptionVoid)
{
  auto result = ua::detail::to_result([] { throw UaException{Status::BadTimeout, nullptr}; });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadTimeout);
}

TEST(ToResult, CatchesBadAlloc)
{
  auto result = ua::detail::to_result([]() -> int { throw std::bad_alloc{}; });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadOutOfMemory);
}

TEST(ToResult, CatchesStdException)
{
  auto result = ua::detail::to_result([]() -> int { throw std::runtime_error("oops"); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.status_code().detail(), nullptr);
  EXPECT_EQ(result.status_code().detail()->code, "StdException");
  const auto& context = result.status_code().detail()->context;
  ASSERT_EQ(context.size(), 1U);
  EXPECT_EQ(context[0].key, ContextKeys::errorMessage.value());
  EXPECT_EQ(context[0].value, "oops");
}

TEST(ToResult, CatchesUnknownException)
{
  auto result = ua::detail::to_result([]() -> int { throw 42; });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
}

// --- exception_to_status_code tests ---

// Covers SVR-DIAG-007 (coverage-audit retag).
TEST(ExceptionToResult, ExtractsUaExceptionStatus)
{
  std::exception_ptr eptr;
  try
  {
    throw UaException{Status::BadNodeIdUnknown, nullptr};
  }
  catch (...)
  {
    eptr = std::current_exception();
  }
  auto er = ua::exception_to_status_code(eptr);
  EXPECT_EQ(er.as_status(), Status::BadNodeIdUnknown);
}

TEST(ExceptionToResult, MapsBadAllocToOutOfMemory)
{
  std::exception_ptr eptr;
  try
  {
    throw std::bad_alloc{};
  }
  catch (...)
  {
    eptr = std::current_exception();
  }
  auto er = ua::exception_to_status_code(eptr);
  EXPECT_EQ(er.as_status(), Status::BadOutOfMemory);
}

TEST(ExceptionToResult, MapsUnknownToInternalError)
{
  std::exception_ptr eptr;
  try
  {
    throw std::runtime_error("oops");
  }
  catch (...)
  {
    eptr = std::current_exception();
  }
  auto er = ua::exception_to_status_code(eptr);
  EXPECT_EQ(er.as_status(), Status::BadInternalError);
}

TEST(ExceptionToResult, ImplicitlyConvertsToResultVoid)
{
  std::exception_ptr eptr;
  try
  {
    throw UaException{Status::BadTimeout, make_error_detail("TestError", "test detail", "Test")};
  }
  catch (...)
  {
    eptr = std::current_exception();
  }
  VoidResult result = ua::exception_to_status_code(eptr);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadTimeout);
}

TEST(ExceptionToResult, ImplicitlyConvertsToResultInt)
{
  std::exception_ptr eptr;
  try
  {
    throw UaException{Status::BadNodeIdUnknown, nullptr};
  }
  catch (...)
  {
    eptr = std::current_exception();
  }
  Result<int> result = ua::exception_to_status_code(eptr);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
}

// --- invoke_user_callback tests ---

TEST(InvokeUserCallback, InvokesNormally)
{
  int called = 0;
  ua::detail::invoke_user_callback([&](int v) { called = v; }, 42);
  EXPECT_EQ(called, 42);
}

TEST(InvokeUserCallback, CatchesExceptionFromCallback)
{
  // Should not throw or crash
  ua::detail::invoke_user_callback([] { throw std::runtime_error("user error"); });
}

TEST(InvokeUserCallback, LogsWarningOnStdException)
{
  auto sink = std::make_shared<RecordingSink>();
  auto logger = make_test_logger(sink);

  ua::detail::invoke_user_callback(logger, [] { throw std::runtime_error("user error"); });

  EXPECT_TRUE(sink->has_warning_containing("user error"));
}

TEST(InvokeUserCallback, LogsWarningOnUnknownException)
{
  auto sink = std::make_shared<RecordingSink>();
  auto logger = make_test_logger(sink);

  ua::detail::invoke_user_callback(logger, [] { throw 42; });

  EXPECT_TRUE(sink->has_warning_containing("unknown exception"));
}

TEST(InvokeUserCallback, NoLoggerOverloadSwallowsSilently)
{
  // Should not throw or crash - exceptions silently swallowed
  ua::detail::invoke_user_callback([] { throw std::runtime_error("swallowed"); });
}

TEST(InvokeUserCallback, LoggerOverloadInvokesNormally)
{
  auto sink = std::make_shared<RecordingSink>();
  auto logger = make_test_logger(sink);

  int called = 0;
  ua::detail::invoke_user_callback(logger, [&](int v) { called = v; }, 42);
  EXPECT_EQ(called, 42);
  EXPECT_TRUE(sink->entries().empty());  // No warnings logged on success
}

// An empty std::function callback means "no callback was provided" (or a moved-from single-shot).
// Invoking it would throw std::bad_function_call, which the logger overload previously caught and
// MISLABELED as "User callback threw". It must now be skipped: no invocation, no warning.
TEST(InvokeUserCallback, EmptyStdFunctionCallbackSkippedLoggerOverload)
{
  auto sink = std::make_shared<RecordingSink>();
  auto logger = make_test_logger(sink);

  const std::function<void(int)> empty;  // default-constructed -> empty
  ua::detail::invoke_user_callback(logger, empty, 42);

  EXPECT_TRUE(sink->entries().empty()) << "an empty callback must be skipped, not caught-and-logged";
  EXPECT_FALSE(sink->has_warning_containing("User callback threw"));
}

// The no-logger overload must also skip an empty callback without a throw crossing its noexcept boundary.
TEST(InvokeUserCallback, EmptyStdFunctionCallbackSkippedNoLoggerOverload)
{
  const std::function<void()> empty;
  ua::detail::invoke_user_callback(empty);  // must not throw / crash
  SUCCEED();
}

// The empty-skip guard must not over-skip: a non-empty std::function callback is still invoked.
TEST(InvokeUserCallback, NonEmptyStdFunctionCallbackStillInvoked)
{
  int called = 0;
  const std::function<void(int)> cb = [&](int v)
  {
    called = v;
  };
  ua::detail::invoke_user_callback(cb, 7);
  EXPECT_EQ(called, 7);
}

// The empty-skip must target only NULLABLE callables (std::function / function pointer), never an
// arbitrary bool-convertible callable. A stateful functor with a *semantic* operator bool that returns
// false is NOT "unset" and must still be invoked - proves the guard uses a nullable-callback trait, not a
// broad is_constructible_v<bool, ...> check (which would wrongly skip it).
TEST(InvokeUserCallback, SemanticBoolFunctorIsNotEmptySkipped)
{
  struct FalsyFunctor
  {
    int* called;

    explicit operator bool() const  // semantic false, NOT a "no callback" signal
    {
      return false;
    }

    void operator()() const
    {
      ++*called;
    }
  };

  int called = 0;
  const FalsyFunctor functor{&called};
  ua::detail::invoke_user_callback(functor);
  EXPECT_EQ(called, 1) << "a bool-convertible non-nullable functor must be invoked, not empty-skipped";
}
