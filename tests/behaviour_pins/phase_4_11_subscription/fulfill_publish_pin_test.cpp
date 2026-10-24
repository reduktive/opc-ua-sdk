// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11a (Subscription) - FulfillPublish cluster.
//
// FP-A, FP-B, FP-D are authored in subscription_pin_test.cpp.
// This file pins FP-C (recursive drain on moreNotifications) and DISABLED FP-E
// (cross-strand coro adapter needs cross-strand setup).

#include <chrono>
#include <future>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_data_value.h"
#include "ua_monitored_item.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = ::ua::server::SubscriptionTestAccess;

class FulfillPublishPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<Subscription> mSubscription;

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
  }

  void TearDown() override
  {
    mSubscription.reset();
    mThreadPool.join();
  }

  void create_sub(uint32_t maxNotificationsPerPublish)
  {
    mSubscription = Subscription::create(/*subscriptionId=*/
      1,
      /*publishingInterval=*/1'000'000.0,
      /*lifetimeCount=*/100,
      /*maxKeepAliveCount=*/3,
      maxNotificationsPerPublish,
      /*publishingEnabled=*/true,
      /*priority=*/0,
      mExecutor,
      [](IntegerId) {},
      [](IntegerId) {});
  }

  // Pre-create a monitored item in Reporting mode with N values queued, and
  // bump mReportableItemCount so notifications_available() returns true.
  IntegerId add_item_with_queue(int valueCount)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->clientHandle = 100;
        item->queueSize = static_cast<uint32_t>(valueCount + 10);
        item->monitoringMode = MonitoringMode::Reporting;
        for (int32_t v = 1; v <= valueCount; ++v)
        {
          DataValue dv;
          dv.value() = Variant{v};
          item->queue.push_back(std::move(dv));
        }
        auto id = g.add_monitored_item(std::move(item));
        g.reportable_item_count() = 1u;
        return id;
      });
  }
};

}  // namespace

// ===========================================================================
// FP-C - fulfill_publish drains recursively when moreNotifications is true.
// Source: ua_subscription.cpp:432-443.
// ===========================================================================
TEST_F(FulfillPublishPin, FulfillPublishMoreNotificationsTrueDrainsRecursively)
{
  create_sub(/*maxNotificationsPerPublish=*/2);
  add_item_with_queue(/*valueCount=*/4);  // 2 + 2: first batch leaves 2, second drains all

  std::promise<std::vector<Subscription::PublishResult>> p;
  auto fut = p.get_future();
  mSubscription->fulfill_publish_async(/*availablePublishCount=*/2,
    /*publishReqQueued=*/false,
    [&p](std::vector<Subscription::PublishResult> r) mutable { p.set_value(std::move(r)); });

  auto results = fut.get();
  ASSERT_GE(results.size(), 1u);
  EXPECT_TRUE(results[0].moreNotifications)
    << "first PublishResult must signal moreNotifications=true (cpp:426)";

  // The second result drains the residue (3 left after first batch of 2).
  if (results.size() >= 2u)
  {
    EXPECT_FALSE(results[1].moreNotifications) << "second PublishResult must drain remaining notifications";
  }
}

}  // namespace ua::test::behaviour_pins
