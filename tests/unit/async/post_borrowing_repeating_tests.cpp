// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::async::post_borrowing_repeating and the weak_ptr overload of post_borrowing.
//
// The required property is MULTI-SHOT delivery: post_borrowing_repeating fires its handler once
// per invocation of the returned callable, unlike the single-shot post_borrowing / post_owning, which
// move the handler into the posted work on first use. Violating this contract is exactly what silently
// dropped every ConditionRefresh event after the first when register_event_monitored_item was wrongly
// built on the single-shot post_borrowing.

#include "ua_on_strand.h"

#include "ua_logger.h"

#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <memory>

namespace
{

struct Widget : std::enable_shared_from_this<Widget>
{};

}  // namespace

// Load-bearing: invoking the returned callable N times must fire the handler N times. A single-shot
// helper would move the handler out on the first call and drop (or crash on) every later delivery.
// The handler captures a shared_ptr (as the real event callback captured its filter) so that a
// single-shot move would null the capture - making this test genuinely falsifiable.
TEST(PostBorrowingRepeating, FiresOncePerInvocation)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  auto widget = std::make_shared<Widget>();
  auto counter = std::make_shared<std::atomic<int>>(0);

  auto deliver = ua::async::post_borrowing_repeating(
    widget.get(), strand, ua::Logger{}, [counter](Widget& /*self*/) { counter->fetch_add(1); });

  deliver();
  deliver();
  deliver();
  pool.join();

  EXPECT_EQ(counter->load(), 3)
    << "post_borrowing_repeating must fire the handler once per invocation (multi-shot)";
}

// Producer arguments are forwarded to the handler after the live Self&, on every delivery.
TEST(PostBorrowingRepeating, ForwardsArgumentsOnEachDelivery)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  auto widget = std::make_shared<Widget>();
  auto sum = std::make_shared<std::atomic<int>>(0);

  auto deliver = ua::async::post_borrowing_repeating(
    widget.get(), strand, ua::Logger{}, [sum](Widget& /*self*/, int value) { sum->fetch_add(value); });

  deliver(10);
  deliver(20);
  deliver(12);
  pool.join();

  EXPECT_EQ(sum->load(), 42);
}

// Weak lifetime: after the borrowed component is destroyed, a delivery no-ops instead of crashing.
TEST(PostBorrowingRepeating, DropsDeliveryAfterSelfDestroyed)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  auto widget = std::make_shared<Widget>();
  auto counter = std::make_shared<std::atomic<int>>(0);

  auto deliver = ua::async::post_borrowing_repeating(
    widget.get(), strand, ua::Logger{}, [counter](Widget&) { counter->fetch_add(1); });

  widget.reset();  // self gone before any delivery
  deliver();
  pool.join();

  EXPECT_EQ(counter->load(), 0) << "a delivery after self is destroyed must no-op";
}

// The weak_ptr overload borrows a sibling's lifetime via an explicit weak_ptr and forwards args.
TEST(PostBorrowingWeakPtr, FiresWithLiveTargetAndForwardsArgs)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  auto target = std::make_shared<Widget>();
  std::atomic<int> got{0};

  ua::async::post_borrowing(std::weak_ptr<Widget>{target},
    strand,
    ua::Logger{},
    [&got](Widget& /*self*/, int value) { got.store(value); })(42);
  pool.join();

  EXPECT_EQ(got.load(), 42);
}

// The weak_ptr overload no-ops when the borrowed target is already gone.
TEST(PostBorrowingWeakPtr, NoOpsWhenTargetGone)
{
  boost::asio::thread_pool pool{1};
  auto strand = boost::asio::make_strand(pool.get_executor());
  auto target = std::make_shared<Widget>();
  std::atomic<int> got{0};

  auto post = ua::async::post_borrowing(
    std::weak_ptr<Widget>{target}, strand, ua::Logger{}, [&got](Widget&, int value) { got.store(value); });
  target.reset();
  post(7);
  pool.join();

  EXPECT_EQ(got.load(), 0) << "no-op when the borrowed target is gone";
}
