// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_core_client.h"
#include "ua_exceptions.h"
#include "test_utilities.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <thread>
#include <utility>

#include "test_components.h"

namespace
{
using namespace std::chrono_literals;

ua::client::CreateConfig make_config()
{
  return {.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::test_utils::create_test_config(),
    .client = {}};
}

// `CoreClient::create` requires an executor that is ALREADY being serviced by a running thread.
// That is the API contract, and it is documented on the factory.
//
// This test is not about the contract being right; it is about what happens when a caller breaks
// it. Reading the certificate store posts to the store's strand, so on an executor nobody is
// running the read can never complete. It used to wait on that read with no deadline, and a broken
// precondition became a permanent hang with nothing to diagnose - the failure mode gives the caller
// no clue which of their two lines was wrong.
//
// It now waits with a deadline (10 s, documented on the factory) and throws Bad_Timeout, so the
// contract is ENFORCED rather than merely stated.
//
// The whole thing runs on a detached thread behind a bounded wait: if this ever regresses to
// hanging, the test must report that, not join it.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-03-CREATE-DEADLINE, scope=function)
TEST(ClientCreateExecutorPrecondition, ThrowsRatherThanHangingOnAnExecutorNobodyIsRunning)
{
  auto outcome =
    std::make_shared<std::promise<std::pair<std::exception_ptr, std::chrono::steady_clock::duration>>>();
  auto future = outcome->get_future();

  std::thread(
    [outcome]
    {
      // Constructed but never run(): nothing will ever service this executor.
      auto ioc = std::make_shared<boost::asio::io_context>();
      try
      {
        auto configuration = make_config();
        auto components = ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()};
        const auto before = std::chrono::steady_clock::now();
        std::exception_ptr failure;
        try
        {
          auto client = ua::client::CoreClient::create(
            ioc->get_executor(), std::move(configuration), std::move(components));
        }
        catch (...)
        {
          failure = std::current_exception();
        }
        outcome->set_value({std::move(failure), std::chrono::steady_clock::now() - before});
      }
      catch (...)
      {
        outcome->set_value({std::current_exception(), std::chrono::steady_clock::duration::zero()});
      }
    })
    .detach();

  // Comfortably past the 10s internal deadline, and far short of "forever".
  ASSERT_EQ(future.wait_for(40s), std::future_status::ready)
    << "CoreClient::create hung on an executor nobody is running. The precondition is the caller's "
       "to meet, but breaking it must produce a diagnosable error, not a hang";
  const auto [failure, elapsed] = future.get();
  ASSERT_NE(failure, nullptr) << "CoreClient::create unexpectedly returned a client";
  try
  {
    std::rethrow_exception(failure);
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status_code(), ua::Status::BadTimeout);
  }
  catch (...)
  {
    FAIL() << "CoreClient::create did not report the required UaException";
  }
  EXPECT_GE(elapsed, 10s) << "the factory must wait for its documented deadline before timing out";
}

// create() called from a handler on a one-thread executor: the caller is the only worker, so the
// certificate read could never run. It is refused at once with Bad_WouldBlock, not after the 10 s
// deadline. A regression to waiting would still end (at the deadline), so the bounded wait reports it.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-03-CREATE-REFUSED, scope=function)
TEST(ClientCreateExecutorPrecondition, RefusesAtOnceOnItsOwnExecutor)
{
  boost::asio::thread_pool pool{1};
  std::promise<std::pair<ua::StatusCode, std::chrono::steady_clock::duration>> outcome;
  boost::asio::post(pool,
    [&]
    {
      const auto before = std::chrono::steady_clock::now();
      auto created = ua::client::CoreClient::try_create(pool.executor(),
        make_config(),
        ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
      outcome.set_value({created.status_code(), std::chrono::steady_clock::now() - before});
    });
  auto future = outcome.get_future();
  ASSERT_EQ(future.wait_for(40s), std::future_status::ready);
  const auto [status, elapsed] = future.get();
  pool.join();
  EXPECT_EQ(status.as_status(), ua::Status::BadWouldBlock);
  EXPECT_LT(elapsed, 5s) << "the refusal must come before the wait, not at its deadline";
}

// Control for the refusal: the same call from a thread outside the pool succeeds.
// (SucceedsPromptlyOnARunningExecutor below.)

// The contract SATISFIED: a thread_pool's workers are running before create is called, which is the
// canonical usage the precondition describes. This must stay fast and must not throw - the deadline
// above must never fire on a healthy executor.
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-03-CREATE-REFUSED, scope=function)
// @relation(AC-COMP-CORE-ASYNC-SYNC-WAIT-03-CREATE-DEADLINE, scope=function)
TEST(ClientCreateExecutorPrecondition, SucceedsPromptlyOnARunningExecutor)
{
  boost::asio::thread_pool pool{2};

  const auto before = std::chrono::steady_clock::now();
  EXPECT_NO_THROW({
    auto client = ua::client::CoreClient::create(pool.executor(),
      make_config(),
      ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
  });
  const auto elapsed = std::chrono::steady_clock::now() - before;

  EXPECT_LT(elapsed, 5s) << "create on a running executor must not go anywhere near the 10s deadline";

  pool.stop();
  pool.join();
}
}  // namespace
