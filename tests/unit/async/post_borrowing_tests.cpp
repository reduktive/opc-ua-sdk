// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_on_strand.h"

#include "test_log_sink.h"
#include "ua_error_detail.h"
#include "ua_result.h"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <functional>
#include <atomic>
#include <barrier>
#include <cstdlib>
#include <latch>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

struct BorrowedOwner : std::enable_shared_from_this<BorrowedOwner>
{};

struct LvalueOnlyCompletion
{
  std::unique_ptr<int> value;
  unsigned* completions;

  void operator()(ua::VoidResult result) &
  {
    EXPECT_TRUE(result.is_good());
    EXPECT_EQ(*value, 42);
    ++*completions;
  }

  void operator()(ua::VoidResult) && = delete;
};

class ThrowingPostHandler
{
public:
  ThrowingPostHandler(std::shared_ptr<std::atomic_bool> failMoves, std::exception_ptr exception) noexcept
    : mFailMoves(std::move(failMoves)), mException(std::move(exception))
  {}

  ThrowingPostHandler(ThrowingPostHandler&& other)
    : mFailMoves(other.mFailMoves), mException(other.mException)
  {
    if (mFailMoves->load())
    {
      std::rethrow_exception(mException);
    }
  }

  ThrowingPostHandler(const ThrowingPostHandler&) = delete;
  ThrowingPostHandler& operator=(const ThrowingPostHandler&) = delete;
  ThrowingPostHandler& operator=(ThrowingPostHandler&&) = delete;
  ~ThrowingPostHandler() = default;

  void operator()(BorrowedOwner&, std::function<void(ua::VoidResult)> completion) &
  {
    completion(ua::VoidResult{});
  }

private:
  std::shared_ptr<std::atomic_bool> mFailMoves;
  std::exception_ptr mException;
};

}  // namespace

// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION, scope=function)
TEST(PostBorrowingCompletion, SuccessRunsOnTheExecutorAndCompletesOnce)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned handlers = 0;
  unsigned completions = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_TRUE(result.is_good());
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [&](BorrowedOwner& actualOwner, auto completion)
    {
      EXPECT_EQ(&actualOwner, owner.get());
      ++handlers;
      completion(ua::VoidResult{});
    });
  post();
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 0U);
  context.run();
  EXPECT_EQ(handlers, 1U);
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ExpiredOwnerBeforePostingReceivesTheExactFallback)
{
  boost::asio::io_context context;
  auto owner = std::make_shared<BorrowedOwner>();
  const std::weak_ptr<BorrowedOwner> weak = owner;
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("Gone", "Owner was destroyed", "PostBorrowingTest");
  const ua::StatusCode fallback{ua::Status::BadShutdown, detail};
  unsigned handlers = 0;
  unsigned completions = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_EQ(result.status_code(), fallback);
      EXPECT_EQ(result.status_code().shared_detail(), detail);
    },
    ua::VoidResult{fallback},
    [&](BorrowedOwner&, auto) { ++handlers; });
  owner.reset();
  EXPECT_TRUE(weak.expired());
  post();
  context.run();
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ExpiredOwnerAfterPostingReceivesTheFallback)
{
  boost::asio::io_context context;
  auto owner = std::make_shared<BorrowedOwner>();
  unsigned handlers = 0;
  unsigned completions = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadShutdown});
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [&](BorrowedOwner&, auto) { ++handlers; });
  post();
  owner.reset();
  context.run();
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ThrowingHandlerPreservesTheExactRichFailure)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  ua::test::TestLogSink sink;
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("DependencyFailed", "Dependency refused the operation", "PostBorrowingTest");
  const ua::StatusCode failure{ua::Status::BadResourceUnavailable, detail};
  const ua::UaException exception{failure};
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    sink.logger(),
    [&](ua::Result<int> result)
    {
      ++completions;
      EXPECT_EQ(result.status_code(), failure);
      EXPECT_EQ(result.status_code().shared_detail(), detail);
    },
    ua::Result<int>{ua::Status::BadShutdown},
    [&](BorrowedOwner&, auto) { throw exception; })();
  EXPECT_NO_THROW(context.run());
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(sink.count(ua::LogLevel::Error), 1U);
}

TEST(PostBorrowingCompletion, StatusCodePayloadPreservesTheExactRichFailure)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("DependencyFailed", "Dependency refused the operation", "PostBorrowingTest");
  const ua::StatusCode failure{ua::Status::BadResourceUnavailable, detail};
  const ua::UaException exception{failure};
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::StatusCode result)
    {
      ++completions;
      EXPECT_EQ(result, failure);
      EXPECT_EQ(result.shared_detail(), detail);
    },
    ua::StatusCode{ua::Status::BadShutdown},
    [&](BorrowedOwner&, auto) { throw exception; })();
  EXPECT_NO_THROW(context.run());
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, NonStatusMoveOnlyPayloadUsesTheFallbackAndLogsTheFailure)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  ua::test::TestLogSink sink;
  auto fallback = std::make_unique<int>(42);
  const int* expected = fallback.get();
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    sink.logger(),
    [&](std::unique_ptr<int> result)
    {
      ++completions;
      EXPECT_EQ(result.get(), expected);
      ASSERT_NE(result, nullptr);
      EXPECT_EQ(*result, 42);
    },
    std::move(fallback),
    [](BorrowedOwner&, auto) { throw std::runtime_error{"Dependency failed"}; })();
  context.run();
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(sink.count(ua::LogLevel::Error), 1U);
}

TEST(PostBorrowingCompletion, AHandlerThatCompletesThenThrowsCannotCompleteAgain)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_TRUE(result.is_good());
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto completion)
    {
      completion(ua::VoidResult{});
      throw std::runtime_error{"After completion"};
    })();
  EXPECT_NO_THROW(context.run());
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ADeferredDuplicateCannotCompleteAgain)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  std::function<void(ua::VoidResult)> deferred;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult) { ++completions; },
    ua::VoidResult{ua::Status::BadShutdown},
    [&](BorrowedOwner&, std::function<void(ua::VoidResult)> completion)
    {
      deferred = completion;
      completion(ua::VoidResult{});
    })();
  context.run();
  ASSERT_TRUE(deferred);
  deferred(ua::VoidResult{});
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ThrowingUserCompletionIsContainedAndNotRetried)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  ua::test::TestLogSink sink;
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    sink.logger(),
    [&](ua::VoidResult)
    {
      ++completions;
      throw std::runtime_error{"User completion failed"};
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto completion) { completion(ua::VoidResult{}); })();
  EXPECT_NO_THROW(context.run());
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(sink.count(ua::LogLevel::Warning), 1U);
}

TEST(PostBorrowingCompletion, OriginalCompletionMayBeMoveOnly)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  auto owned = std::make_unique<int>(42);
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [owned = std::move(owned), &completions](ua::VoidResult result)
    {
      ++completions;
      EXPECT_TRUE(result.is_good());
      EXPECT_EQ(*owned, 42);
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto completion) { completion(ua::VoidResult{}); })();
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ACompletionCanDestroyItsCallingRelay)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  std::function<void(ua::VoidResult)> deferred;
  auto lifetime = std::make_shared<int>(42);
  const std::weak_ptr<int> weak = lifetime;
  unsigned completions = 0;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [lifetime, &deferred, &completions](ua::VoidResult)
    {
      deferred = {};
      EXPECT_EQ(*lifetime, 42);
      ++completions;
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [&](BorrowedOwner&, std::function<void(ua::VoidResult)> completion)
    { deferred = std::move(completion); })();
  lifetime.reset();
  context.run();
  ASSERT_TRUE(deferred);
  EXPECT_FALSE(weak.expired());
  deferred(ua::VoidResult{});
  EXPECT_EQ(completions, 1U);
  EXPECT_FALSE(deferred);
  EXPECT_TRUE(weak.expired());
}

TEST(PostBorrowingCompletion, AStatusFallbackPreservesTheCanonicalResultPayload)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  std::function<void(ua::Result<int>)> completion = [&](ua::Result<int> result)
  {
    ++completions;
    ASSERT_TRUE(result.is_good());
    EXPECT_EQ(result.value(), 42);
  };
  ua::async::post_borrowing(owner.get(),
    context.get_executor(),
    ua::Logger{},
    std::move(completion),
    ua::StatusCode{ua::Status::BadShutdown},
    [](BorrowedOwner&, std::function<void(ua::Result<int>)> callback) { callback(ua::Result<int>{42}); })();
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, EmptyCompletionViolatesTheDocumentedPrecondition)
{
  EXPECT_DEBUG_DEATH(
    {
      boost::asio::io_context context;
      auto owner = std::make_shared<BorrowedOwner>();
      std::function<void(ua::VoidResult)> completion;
      auto post = ua::async::post_borrowing(owner.get(),
        context.get_executor(),
        ua::Logger{},
        std::move(completion),
        ua::VoidResult{ua::Status::BadShutdown},
        [](BorrowedOwner&, auto callback) { callback(ua::VoidResult{}); });
      owner.reset();
      post();
      context.run();
    },
    "empty completion");
}

// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION, scope=function)
TEST(PostBorrowingCompletion, NullOwnerPreservesTheOriginalCompletionAndRichFallback)
{
  boost::asio::io_context context;
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("Gone", "Owner was destroyed", "PostBorrowingTest");
  const ua::StatusCode status{ua::Status::BadShutdown, detail};
  ua::VoidResult fallback{status};
  unsigned completions = 0;
  unsigned handlers = 0;
  std::function<void(ua::VoidResult)> completion = [&](ua::VoidResult result)
  {
    ++completions;
    EXPECT_EQ(result.status_code(), status);
    EXPECT_EQ(result.status_code().shared_detail(), detail);
  };

  try
  {
    static_cast<void>(ua::async::post_borrowing(static_cast<BorrowedOwner*>(nullptr),
      context.get_executor(),
      ua::Logger{},
      std::move(completion),
      std::move(fallback),
      [&](BorrowedOwner&, auto) { ++handlers; }));
    ADD_FAILURE() << "null owner was accepted";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status(), ua::Status::BadInvalidArgument);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "NullPointer");
  }

  EXPECT_EQ(context.poll(), 0U);
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 0U);
  ASSERT_TRUE(completion);
  EXPECT_EQ(fallback.status_code(), status);
  EXPECT_EQ(fallback.status_code().shared_detail(), detail);
  completion(std::move(fallback));
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, MoveOnlyCompletionMayRequireLvalueInvocation)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  ua::async::post_borrowing(owner.get(),
    context.get_executor(),
    ua::Logger{},
    LvalueOnlyCompletion{std::make_unique<int>(42), &completions},
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto callback) { callback(ua::VoidResult{}); })();
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, CompletionAndHandlerFailureRaceToOneRichResult)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("DependencyFailed", "Dependency refused the operation", "PostBorrowingTest");
  const ua::StatusCode failure{ua::Status::BadResourceUnavailable, detail};
  const ua::UaException exception{failure};
  std::barrier start{2};
  std::latch ready{1};
  std::mutex resultsMutex;
  std::vector<ua::Result<int>> results;
  std::function<void(ua::Result<int>)> deferred;
  ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::Result<int> result)
    {
      const std::lock_guard lock(resultsMutex);
      results.push_back(std::move(result));
    },
    ua::Result<int>{ua::Status::BadShutdown},
    [&](BorrowedOwner&, std::function<void(ua::Result<int>)> callback)
    {
      deferred = std::move(callback);
      ready.count_down();
      start.arrive_and_wait();
      throw exception;
    })();
  std::thread execution([&] { context.run(); });
  ready.wait();
  std::thread delivery(
    [&]
    {
      start.arrive_and_wait();
      deferred(ua::Result<int>{42});
    });
  execution.join();
  delivery.join();
  ASSERT_EQ(results.size(), 1U);
  if (results.front().is_good())
  {
    EXPECT_EQ(results.front().value(), 42);
  }
  else
  {
    EXPECT_EQ(results.front().status_code(), failure);
    EXPECT_EQ(results.front().status_code().shared_detail(), detail);
  }
}

TEST(PostBorrowingCompletion, HandlerCannotRetainTheProducerThatOwnsItsCallbacks)
{
  using Producer = std::pair<std::function<void()>, std::function<void(ua::VoidResult)>>;
  for (const bool ownerGone : {false, true})
  {
    boost::asio::io_context context;
    auto owner = std::make_shared<BorrowedOwner>();
    auto producer = std::make_shared<Producer>();
    const std::weak_ptr<Producer> weak = producer;
    unsigned completions = 0;
    producer->first = ua::async::post_borrowing(
      owner.get(),
      context.get_executor(),
      ua::Logger{},
      [&](ua::VoidResult result)
      {
        ++completions;
        EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadShutdown});
      },
      ua::VoidResult{ua::Status::BadShutdown},
      [producer](BorrowedOwner&, std::function<void(ua::VoidResult)> callback)
      { producer->second = std::move(callback); });
    if (ownerGone)
    {
      owner.reset();
    }
    producer->first();
    context.run();
    producer.reset();
    EXPECT_TRUE(weak.expired());
    if (ownerGone)
    {
      EXPECT_EQ(completions, 1U);
    }
    else
    {
      EXPECT_EQ(completions, 0U);
    }
  }
}

TEST(PostBorrowingCompletion, CompletionStateDoesNotRetainItsLoggerInACycle)
{
  boost::asio::io_context context;
  auto owner = std::make_shared<BorrowedOwner>();
  auto sink = std::make_shared<ua::test_helpers::TestLogSink>(false);
  const std::weak_ptr<ua::LogSink> weakSink = sink;
  ua::Logger logger{sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "LifetimeTest"};
  unsigned completions = 0;
  {
    auto post = ua::async::post_borrowing(
      owner.get(),
      context.get_executor(),
      std::move(logger),
      [&](ua::VoidResult) { ++completions; },
      ua::VoidResult{ua::Status::BadShutdown},
      [](BorrowedOwner&, auto callback) { callback(ua::VoidResult{}); });
    sink.reset();
    EXPECT_FALSE(weakSink.expired());
    owner.reset();
    post();
    context.run();
    EXPECT_EQ(completions, 1U);
  }
  EXPECT_TRUE(weakSink.expired());
}

TEST(PostBorrowingCompletion, AThrowingHandlerMoveCompletesWithTheExactRichFailure)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  auto failMoves = std::make_shared<std::atomic_bool>(false);
  const std::shared_ptr<const ua::ErrorDetail> detail =
    ua::make_error_detail("HandlerMoveFailed", "Moving the continuation failed", "PostBorrowingTest");
  const ua::StatusCode failure{ua::Status::BadResourceUnavailable, detail};
  const auto exception = std::make_exception_ptr(ua::UaException{failure});
  unsigned completions = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_EQ(result.status_code(), failure);
      EXPECT_EQ(result.status_code().shared_detail(), detail);
    },
    ua::VoidResult{ua::Status::BadShutdown},
    ThrowingPostHandler{failMoves, exception});
  failMoves->store(true);
  EXPECT_NO_THROW(post());
  context.run();
  EXPECT_EQ(completions, 1U);
}

// A Handler whose move throws while the helper is being built fails the construction before the caller's
// completion is consumed: the caller still holds it and can answer with it.
// @relation(AC-COMP-SDK-POST-COMPLETION-CONSTRUCTION-HANDLER-MOVE-FAILURE, scope=function)
TEST(PostBorrowingCompletion, AThrowingHandlerMoveDuringConstructionLeavesTheCallerCompletionUsable)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  auto failMoves = std::make_shared<std::atomic_bool>(true);
  const ua::StatusCode failure{ua::Status::BadResourceUnavailable,
    ua::make_error_detail("HandlerMoveFailed", "Moving the continuation failed", "PostBorrowingTest")};
  unsigned completions = 0;
  std::function<void(ua::VoidResult)> completion = [&](ua::VoidResult result)
  {
    ++completions;
    EXPECT_TRUE(result.is_good());
  };
  bool constructionThrew = false;
  try
  {
    auto post = ua::async::post_borrowing(owner.get(),
      context.get_executor(),
      ua::Logger{},
      std::move(completion),
      ua::VoidResult{ua::Status::BadShutdown},
      ThrowingPostHandler{failMoves, std::make_exception_ptr(ua::UaException{failure})});
    post();
  }
  catch (const ua::UaException& exception)
  {
    constructionThrew = true;
    EXPECT_EQ(exception.status_code(), failure);
  }
  EXPECT_TRUE(constructionThrew);
  context.run();
  EXPECT_EQ(completions, 0U) << "nothing was posted, so nothing answered";
  ASSERT_TRUE(completion) << "the failed construction consumed the caller's completion";
  completion(ua::VoidResult{});
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ProducerArgumentsAreOwnedUntilTheExecutorRuns)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  unsigned handlers = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_TRUE(result.is_good());
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [&](BorrowedOwner&, auto completion, std::unique_ptr<int> number, std::string text)
    {
      ++handlers;
      ASSERT_NE(number, nullptr);
      EXPECT_EQ(*number, 42);
      EXPECT_EQ(text, std::string(128, 'p'));
      completion(ua::VoidResult{});
    });
  auto number = std::make_unique<int>(42);
  std::string text(128, 'p');
  post(std::move(number), text);
  EXPECT_EQ(number, nullptr);
  text.clear();
  EXPECT_EQ(handlers, 0U);
  EXPECT_EQ(completions, 0U);
  context.run();
  EXPECT_EQ(handlers, 1U);
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ExpiredOwnerStillCompletesWhenTheProducerSuppliesArguments)
{
  boost::asio::io_context context;
  auto owner = std::make_shared<BorrowedOwner>();
  unsigned completions = 0;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadShutdown});
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto, std::unique_ptr<int>) { ADD_FAILURE() << "expired owner was invoked"; });
  owner.reset();
  post(std::make_unique<int>(42));
  EXPECT_EQ(completions, 0U);
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, AThrowingProducerArgumentMovePreservesTheExactRichFailure)
{
  boost::asio::io_context context;
  const auto owner = std::make_shared<BorrowedOwner>();
  const std::shared_ptr<const ua::ErrorDetail> originalDetail =
    ua::make_error_detail("ProducerArgumentMove", "Producer argument move failed", "PostBorrowingTest");
  const ua::StatusCode original{ua::Status::BadResourceUnavailable, originalDetail};
  const auto exception = std::make_exception_ptr(ua::UaException{original});
  const auto failMoves = std::make_shared<std::atomic_bool>(false);
  ThrowingPostHandler argument{failMoves, exception};
  unsigned completions = 0;
  ua::StatusCode observed;
  auto post = ua::async::post_borrowing(
    owner.get(),
    context.get_executor(),
    ua::Logger{},
    [&](ua::VoidResult result)
    {
      ++completions;
      observed = result.status_code();
    },
    ua::VoidResult{ua::Status::BadShutdown},
    [](BorrowedOwner&, auto, ThrowingPostHandler) { ADD_FAILURE() << "failed argument was delivered"; });
  failMoves->store(true);
  EXPECT_NO_THROW(post(std::move(argument)));
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(observed.value(), original.value());
  EXPECT_EQ(observed.shared_detail(), originalDetail);
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(PostBorrowingCompletion, ThrowingArgumentMovesAfterEnqueueCannotEscapeTheExecutor)
{
  EXPECT_EXIT((
                []
                {
                  boost::asio::io_context context;
                  const auto owner = std::make_shared<BorrowedOwner>();
                  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
                    "HandlerArgumentMove", "Handler argument move failed", "PostBorrowingTest");
                  const ua::StatusCode failure{ua::Status::BadResourceUnavailable, detail};
                  const auto failMoves = std::make_shared<std::atomic_bool>(false);
                  ThrowingPostHandler argument{failMoves, std::make_exception_ptr(ua::UaException{failure})};
                  unsigned completions = 0;
                  unsigned handlers = 0;
                  ua::StatusCode observed;
                  auto post = ua::async::post_borrowing(
                    owner.get(),
                    context.get_executor(),
                    ua::Logger{},
                    [&](ua::VoidResult result)
                    {
                      ++completions;
                      observed = result.status_code();
                    },
                    ua::VoidResult{ua::Status::BadShutdown},
                    [&](BorrowedOwner&, auto, ThrowingPostHandler) { ++handlers; });
                  post(std::move(argument));
                  failMoves->store(true);
                  context.run();
                  std::_Exit(completions == 1 && handlers == 0 && observed == failure &&
                                 observed.shared_detail() == detail
                               ? EXIT_SUCCESS
                               : EXIT_FAILURE);
                }()),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}

TEST(PostBorrowingCompletion, QueuedHandlerMovesCannotEscapeTheExecutor)
{
  EXPECT_EXIT((
                []
                {
                  boost::asio::io_context context;
                  const auto owner = std::make_shared<BorrowedOwner>();
                  const auto failMoves = std::make_shared<std::atomic_bool>(false);
                  ThrowingPostHandler handler{
                    failMoves, std::make_exception_ptr(std::runtime_error("handler move"))};
                  unsigned completions = 0;
                  ua::StatusCode observed{ua::Status::BadShutdown};
                  auto post = ua::async::post_borrowing(
                    owner.get(),
                    context.get_executor(),
                    ua::Logger{},
                    [&](ua::VoidResult result)
                    {
                      ++completions;
                      observed = result.status_code();
                    },
                    ua::VoidResult{ua::Status::BadShutdown},
                    std::move(handler));
                  post();
                  failMoves->store(true);
                  context.run();
                  std::_Exit(completions == 1 && observed.is_good() ? EXIT_SUCCESS : EXIT_FAILURE);
                }()),
    ::testing::ExitedWithCode(EXIT_SUCCESS),
    "");
}
