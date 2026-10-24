// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_orphaned_subscription_store.h"
#include "ua_subscription.h"

#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace ua::server;

namespace
{

class OrphanedSubscriptionStoreTest : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::shared_ptr<Subscription> make_subscription(IntegerId id)
  {
    return Subscription::create(
      id,
      /*publishingInterval=*/1000.0,
      /*lifetimeCount=*/100,
      /*maxKeepAliveCount=*/3,
      /*maxNotificationsPerPublish=*/0,
      /*publishingEnabled=*/true,
      /*priority=*/0,
      mThreadPool.get_executor(),
      [](IntegerId) {},
      [](IntegerId) {});
  }

  OrphanedSubscription make_entry(IntegerId id)
  {
    OrphanedSubscription entry;
    entry.subscription = make_subscription(id);
    return entry;
  }

  boost::asio::thread_pool mThreadPool;
};

}  // namespace

TEST_F(OrphanedSubscriptionStoreTest, ParkPastCapDropsOldest)
{
  OrphanedSubscriptionStore store{/*maxEntries=*/2};

  store.park(1, make_entry(1));
  store.park(2, make_entry(2));
  ASSERT_EQ(store.size(), 2u);

  // Third park exceeds the cap -> the oldest (id 1) is dropped.
  store.park(3, make_entry(3));

  EXPECT_EQ(store.size(), 2u);
  EXPECT_FALSE(store.contains(1));
  EXPECT_TRUE(store.contains(2));
  EXPECT_TRUE(store.contains(3));
}

TEST_F(OrphanedSubscriptionStoreTest, RemoveFreesACapSlot)
{
  OrphanedSubscriptionStore store{/*maxEntries=*/2};

  store.park(1, make_entry(1));
  store.park(2, make_entry(2));
  store.remove(1);  // frees a slot and clears id 1 from the FIFO order

  // id 2 is now the oldest; parking id 3 (back to cap) then id 4 must drop id 2, not the removed id 1.
  store.park(3, make_entry(3));
  store.park(4, make_entry(4));

  EXPECT_EQ(store.size(), 2u);
  EXPECT_FALSE(store.contains(2));
  EXPECT_TRUE(store.contains(3));
  EXPECT_TRUE(store.contains(4));
}

TEST_F(OrphanedSubscriptionStoreTest, ReparkDoesNotConsumeExtraCapacity)
{
  OrphanedSubscriptionStore store{/*maxEntries=*/2};

  store.park(1, make_entry(1));
  store.park(2, make_entry(2));
  store.park(1, make_entry(1));  // re-park existing id: replace in place, no eviction

  EXPECT_EQ(store.size(), 2u);
  EXPECT_TRUE(store.contains(1));
  EXPECT_TRUE(store.contains(2));
}
