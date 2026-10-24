// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "access_control_test_support.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include "ua_address_space.h"

#include "ua_data_change_notification.h"
#include "ua_sample_sink_impl.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

using STA = SubscriptionTestAccess;

namespace
{

/// Test fixture that provides a real boost::asio::thread_pool and boost::asio::any_io_executor.
class SubscriptionTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test:subscription", mExecutor));
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    auto accessNode =
      mAddressSpace->try_create_node_sync(NodeId{1, uint32_t{68000}}, NodeClass::Variable, {});
    ASSERT_TRUE(accessNode);
    mAccessNode = accessNode.value();
  }

  void TearDown() override
  {
    // Ensure subscriptions are destroyed before thread pool stops.
    mSubscription.reset();
    mSecurityContext.reset();
    mAccessNode.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void grant_test_read_access(MonitoredItem& item)
  {
    ASSERT_TRUE(mAddressSpace.has_value());
    ASSERT_TRUE(mAccessNode.has_value());
    item.accessSecurityContext = mSecurityContext;
    item.accessAddressSpace = mAddressSpace->weak();
    item.accessControlNode = *mAccessNode;
    item.itemToMonitor.node_id() = mAccessNode->get_node_id();
    item.itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::Value);
    const auto identity = mSecurityContext->access_identity();
    ASSERT_NE(identity, nullptr);
    item.accessSnapshot = MonitoredAccessSnapshot{identity->key(),
      AccessControl::Verdict{.subject = mAccessNode->get_node_id(),
        .operation = AccessOperation::Read,
        .permitted = true,
        .mask = PermissionType{PermissionType::Bit::Read},
        .cause = StatusCode{Status::Good}}};
  }

  /// Create a subscription with common test defaults.
  /// Uses short publishing interval (50ms) for fast tests.
  std::shared_ptr<Subscription> create_subscription(double publishingInterval = 50.0,
    uint32_t lifetimeCount = 100, uint32_t maxKeepAliveCount = 3, uint32_t maxNotificationsPerPublish = 0,
    bool publishingEnabled = true, uint8_t priority = 0)
  {
    mSubscription = Subscription::create(
      next_id(),
      publishingInterval,
      lifetimeCount,
      maxKeepAliveCount,
      maxNotificationsPerPublish,
      publishingEnabled,
      priority,
      mExecutor,
      [this](IntegerId subId) { on_ready(subId); },
      [this](IntegerId subId) { on_expired(subId); });
    return mSubscription;
  }

  std::vector<StatusCode> set_mode_blocking(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode)
  {
    std::promise<std::vector<StatusCode>> completion;
    auto result = completion.get_future();
    mSubscription->set_monitoring_mode_async(std::move(monitoredItemIds),
      newMode,
      [&completion](std::vector<StatusCode> statuses) { completion.set_value(std::move(statuses)); });
    return result.get();
  }

  /// Wait for the ready callback to be invoked at least `count` times.
  bool wait_for_ready(int count = 1, std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lock(mMutex);
    return mReadyCv.wait_for(lock, timeout, [&] { return mReadyCount >= count; });
  }

  /// Wait for the expired callback to be invoked.
  bool wait_for_expired(std::chrono::milliseconds timeout = 5000ms)
  {
    std::unique_lock lock(mMutex);
    return mExpiredCv.wait_for(lock, timeout, [&] { return mExpiredCount > 0; });
  }

  /// Add a monitored item with a pre-enqueued value (for testing notification assembly).
  IntegerId add_item_with_value(DataValue value, MonitoringMode mode = MonitoringMode::Reporting)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        item->enqueue_initial(std::move(value));
        return g.add_monitored_item(std::move(item));
      });
  }

  /// Add a monitored item without any queued value.
  IntegerId add_empty_item(MonitoringMode mode = MonitoringMode::Reporting)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        grant_test_read_access(*item);
        return g.add_monitored_item(std::move(item));
      });
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<Subscription> mSubscription;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  std::optional<NodeAccessor> mAccessNode;

  // Callback tracking
  std::mutex mMutex;
  std::condition_variable mReadyCv;
  std::condition_variable mExpiredCv;
  int mReadyCount{0};
  int mExpiredCount{0};
  IntegerId mLastReadySubId{0};
  IntegerId mLastExpiredSubId{0};

private:
  IntegerId mNextId{1};

  IntegerId next_id()
  {
    return mNextId++;
  }

  void on_ready(IntegerId subId)
  {
    std::lock_guard lock(mMutex);
    ++mReadyCount;
    mLastReadySubId = subId;
    mReadyCv.notify_all();
  }

  void on_expired(IntegerId subId)
  {
    std::lock_guard lock(mMutex);
    ++mExpiredCount;
    mLastExpiredSubId = subId;
    mExpiredCv.notify_all();
  }
};

}  // namespace

// ============================================================================
// Construction and basic properties
// ============================================================================

TEST_F(SubscriptionTest, CreateReturnsValidSubscription)
{
  auto sub = create_subscription();
  ASSERT_NE(sub, nullptr);
  EXPECT_EQ(sub->id(), 1u);
  EXPECT_EQ(sub->get_info().priority, 0u);
  EXPECT_EQ(sub->get_info().publishingInterval, 50.0);
}

TEST_F(SubscriptionTest, InitialStateHasNoNotifications)
{
  auto sub = create_subscription();
  EXPECT_FALSE(sub->get_info().hasNotifications);
}

TEST_F(SubscriptionTest, InitialMonitoredItemCountIsZero)
{
  auto sub = create_subscription();
  STA::on_strand(*sub, [&](auto& g) { EXPECT_EQ(g.monitored_items().size(), 0u); });
}

// ============================================================================
// Monitored item management
// ============================================================================

TEST_F(SubscriptionTest, AddMonitoredItemAssignsId)
{
  auto sub = create_subscription();
  auto id = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->clientHandle = 42;
      return g.add_monitored_item(std::move(item));
    });
  EXPECT_EQ(id, 1u);
  STA::on_strand(*sub, [&](auto& g) { EXPECT_EQ(g.monitored_items().size(), 1u); });
}

TEST_F(SubscriptionTest, AddMultipleMonitoredItemsAssignsSequentialIds)
{
  auto sub = create_subscription();
  auto [id1, id2] = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item1 = std::make_unique<MonitoredItem>();
      auto item2 = std::make_unique<MonitoredItem>();
      auto i1 = g.add_monitored_item(std::move(item1));
      auto i2 = g.add_monitored_item(std::move(item2));
      return std::make_pair(i1, i2);
    });
  EXPECT_EQ(id1, 1u);
  EXPECT_EQ(id2, 2u);
}

TEST_F(SubscriptionTest, RemoveMonitoredItemReturnsTrueForExisting)
{
  auto sub = create_subscription();
  auto id = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      return g.add_monitored_item(std::move(item));
    });
  auto removed = STA::on_strand(*sub, [&](auto& g) { return g.remove_monitored_item(id); });
  EXPECT_TRUE(removed);
  STA::on_strand(*sub, [&](auto& g) { EXPECT_EQ(g.monitored_items().size(), 0u); });
}

TEST_F(SubscriptionTest, RemoveMonitoredItemReturnsFalseForNonExisting)
{
  auto sub = create_subscription();
  auto removed = STA::on_strand(*sub, [&](auto& g) { return g.remove_monitored_item(999); });
  EXPECT_FALSE(removed);
}

TEST_F(SubscriptionTest, FindMonitoredItemReturnsPointer)
{
  auto sub = create_subscription();
  auto id = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->clientHandle = 77;
      return g.add_monitored_item(std::move(item));
    });
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* found = g.find_monitored_item(id);
      ASSERT_NE(found, nullptr);
      EXPECT_EQ(found->clientHandle, 77u);
    });
}

TEST_F(SubscriptionTest, FindMonitoredItemReturnsNullForMissing)
{
  auto sub = create_subscription();
  STA::on_strand(*sub, [&](auto& g) { EXPECT_EQ(g.find_monitored_item(999), nullptr); });
}

// ============================================================================
// Sample reception
// ============================================================================

TEST_F(SubscriptionTest, OnSamplesReceivedEnqueuesFilteredValues)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  // Post a sample batch.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      DataValue dv;
      dv.value() = Variant{42};
      std::vector<std::pair<IntegerId, DataValue>> batch;
      batch.emplace_back(id, std::move(dv));
      g.on_samples_received(std::move(batch));

      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->has_reportable_notifications());
    });
}

TEST_F(SubscriptionTest, OnSamplesReceivedIgnoresUnknownIds)
{
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      DataValue dv;
      dv.value() = Variant{42};
      std::vector<std::pair<IntegerId, DataValue>> batch;
      batch.emplace_back(IntegerId{999}, std::move(dv));
      // Should not crash.
      g.on_samples_received(std::move(batch));
    });
}

TEST_F(SubscriptionTest, OnSampleInvalidatedEnqueuesErrorStatus)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.on_sample_invalidated(id, StatusCode{Status::BadNodeIdUnknown});

      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->has_reportable_notifications());
    });
}

// ============================================================================
// Timer-driven state transitions (SVR-SUB-GEN-080: first cycle keep-alive)
// ============================================================================

// @relation(SVR-SUB-GEN-080, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, FirstCycleSignalsReadyForKeepAlive)
{
  // SVR-SUB-GEN-080: subscription must send keep-alive on first cycle if no notifications.
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Wait for the first timer-driven ready signal.
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  std::lock_guard lock(mMutex);
  EXPECT_EQ(mLastReadySubId, sub->id());
}

TEST_F(SubscriptionTest, TimerSignalsReadyWhenNotificationsAvailable)
{
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Add an item with a queued value.
  add_item_with_value(DataValue{Variant{42}});

  ASSERT_TRUE(wait_for_ready(1, 500ms));
}

// ============================================================================
// Notification assembly (SVR-SUB-GEN-090, SVR-SUB-GEN-091)
// ============================================================================

// @relation(AC-SVR-SUB-GEN-090-QUEUE-ORDER-PRESERVED, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, Gen090_NotificationsInQueueOrder)
{
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 10;
      item->enqueue_initial(DataValue{Variant{1}});
      item->evaluate_and_enqueue(DataValue{Variant{2}});
      item->evaluate_and_enqueue(DataValue{Variant{3}});
      g.add_monitored_item(std::move(item));
    });

  auto results = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });

  ASSERT_EQ(results.size(), 1u);
  auto& msg = results[0].message;
  ASSERT_EQ(msg.notification_data().size(), 1u);

  auto* dcn = dynamic_cast<DataChangeNotification*>(msg.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);
  ASSERT_EQ(dcn->monitored_items().size(), 3u);

  // Verify queue order: values 1, 2, 3.
  EXPECT_EQ(dcn->monitored_items()[0].value().value(), Variant{1});
  EXPECT_EQ(dcn->monitored_items()[1].value().value(), Variant{2});
  EXPECT_EQ(dcn->monitored_items()[2].value().value(), Variant{3});
}

// @relation(SVR-SUB-GEN-091, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, Gen091_SameTypeGroupedIntoOneElement)
{
  // All DataChange notifications should be in a single DataChangeNotification.
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      // Add two items, each with one notification.
      auto item1 = std::make_unique<MonitoredItem>();
      item1->monitoringMode = MonitoringMode::Reporting;
      item1->clientHandle = 10;
      item1->enqueue_initial(DataValue{Variant{100}});
      g.add_monitored_item(std::move(item1));

      auto item2 = std::make_unique<MonitoredItem>();
      item2->monitoringMode = MonitoringMode::Reporting;
      item2->clientHandle = 20;
      item2->enqueue_initial(DataValue{Variant{200}});
      g.add_monitored_item(std::move(item2));
    });

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  auto& msg = results[0].message;

  // Should be exactly one DataChangeNotification in the notificationData array.
  ASSERT_EQ(msg.notification_data().size(), 1u);

  auto* dcn = dynamic_cast<DataChangeNotification*>(msg.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);

  // Both items' notifications grouped together.
  EXPECT_EQ(dcn->monitored_items().size(), 2u);
}

// @relation(SVR-SUB-GEN-092, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, Gen092_PublishTimeSetToNow)
{
  auto sub = create_subscription();

  add_item_with_value(DataValue{Variant{42}});

  auto before = DateTime::now();
  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });
  auto after = DateTime::now();

  ASSERT_EQ(results.size(), 1u);
  auto publishTime = results[0].message.publish_time();

  // publishTime should be between before and after.
  EXPECT_GE(publishTime, before);
  EXPECT_LE(publishTime, after);
}

// ============================================================================
// Triggering (Part 4 section 5.12.1.6): a Sampling link reports only when its
// triggering item fires in the *same* publish cycle. A trigger pulse flushes
// the link's currently-queued notifications and nothing more - it must not
// leak into a later cycle and release a sample the trigger never gated.
// ============================================================================

TEST_F(SubscriptionTest, TriggerPulseDoesNotLeakToLaterCycle)
{
  auto sub = create_subscription();

  IntegerId triggerId = 0;
  IntegerId linkId = 0;
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto trigger = std::make_unique<MonitoredItem>();
      trigger->monitoringMode = MonitoringMode::Reporting;
      trigger->clientHandle = 10;
      trigger->queueSize = 10;
      grant_test_read_access(*trigger);
      triggerId = g.add_monitored_item(std::move(trigger));

      auto link = std::make_unique<MonitoredItem>();
      link->monitoringMode = MonitoringMode::Sampling;
      link->clientHandle = 20;
      link->queueSize = 10;
      grant_test_read_access(*link);
      linkId = g.add_monitored_item(std::move(link));

      g.set_triggering(triggerId, std::vector<IntegerId>{linkId}, std::vector<IntegerId>{});
    });

  auto sampleOne = [&](IntegerId id, int v)
  {
    STA::on_strand(*sub,
      [&](auto& g)
      {
        DataValue dv;
        dv.value() = Variant{v};
        std::vector<std::pair<IntegerId, DataValue>> batch;
        batch.emplace_back(id, std::move(dv));
        g.on_samples_received(std::move(batch));
      });
  };

  auto publish = [&]()
  {
    return STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });
  };

  // Cycle A: only the trigger changes. It fires, but the link's queue is empty,
  // so the pulse has nothing to flush. Only the trigger is reported.
  sampleOne(triggerId, 1);
  {
    auto results = publish();
    ASSERT_EQ(results.size(), 1u);
    ASSERT_EQ(results[0].message.notification_data().size(), 1u);
    auto* dcn = dynamic_cast<DataChangeNotification*>(results[0].message.notification_data()[0].get());
    ASSERT_NE(dcn, nullptr);
    ASSERT_EQ(dcn->monitored_items().size(), 1u);
    EXPECT_EQ(dcn->monitored_items()[0].client_handle(), 10u);  // trigger only
  }

  // Cycle B: only the link changes; the trigger does NOT fire. A Sampling link
  // must not report on the spent pulse from Cycle A - this cycle is a keep-alive.
  sampleOne(linkId, 2);
  {
    auto results = publish();
    ASSERT_EQ(results.size(), 1u);
    EXPECT_TRUE(results[0].message.notification_data().empty())
      << "Sampling link reported without its trigger firing this cycle (stale trigger pulse).";
  }

  // Cycle C: the trigger fires again, flushing the link's queued Cycle-B sample
  // alongside it - the data was preserved, only gated on a real trigger fire.
  sampleOne(triggerId, 3);
  {
    auto results = publish();
    ASSERT_EQ(results.size(), 1u);
    ASSERT_EQ(results[0].message.notification_data().size(), 1u);
    auto* dcn = dynamic_cast<DataChangeNotification*>(results[0].message.notification_data()[0].get());
    ASSERT_NE(dcn, nullptr);
    EXPECT_EQ(dcn->monitored_items().size(), 2u);  // trigger + flushed link
  }
}

// ============================================================================
// Keep-alive message (section 3.7)
// ============================================================================

// @relation(SVR-SUB-GEN-021, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, KeepAliveMessageHasEmptyNotificationData)
{
  auto sub = create_subscription();

  // No monitored items -> no notifications -> keep-alive.
  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].message.notification_data().empty());
  EXPECT_FALSE(results[0].moreNotifications);
}

// @relation(SVR-SUB-GEN-021, scope=function)
TEST_F(SubscriptionTest, KeepAliveSequenceNumberNotIncremented)
{
  auto sub = create_subscription();

  auto seqBefore = STA::on_strand(*sub, [&](auto& g) { return g.peek_sequence_number(); });

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].message.sequence_number(), seqBefore);

  // Sequence number should still be the same (not incremented).
  auto seqAfter = STA::on_strand(*sub, [&](auto& g) { return g.peek_sequence_number(); });
  EXPECT_EQ(seqAfter, seqBefore);
}

// @relation(SVR-SUB-GEN-040, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, RealNotificationIncrementsSequenceNumber)
{
  auto sub = create_subscription();

  auto seqBefore = STA::on_strand(*sub, [&](auto& g) { return g.peek_sequence_number(); });

  add_item_with_value(DataValue{Variant{42}});

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].message.sequence_number(), seqBefore);

  // Sequence number should now be incremented.
  auto seqAfter = STA::on_strand(*sub, [&](auto& g) { return g.peek_sequence_number(); });
  EXPECT_EQ(seqAfter, seqBefore + 1);
}

// ============================================================================
// MaxNotificationsPerPublish limiting
// ============================================================================

TEST_F(SubscriptionTest, MaxNotificationsPerPublishLimitsNotifications)
{
  // maxNotificationsPerPublish = 2, but we have 5 queued.
  auto sub = create_subscription(50.0, 100, 3, 2);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 10;
      for (int i = 0; i < 5; ++i)
      {
        item->enqueue_initial(DataValue{Variant{i}});
      }
      g.add_monitored_item(std::move(item));
    });

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  auto& msg = results[0].message;
  ASSERT_EQ(msg.notification_data().size(), 1u);

  auto* dcn = dynamic_cast<DataChangeNotification*>(msg.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);

  // Only 2 notifications should have been drained.
  EXPECT_EQ(dcn->monitored_items().size(), 2u);
  // There should be more notifications remaining.
  EXPECT_TRUE(results[0].moreNotifications);
}

TEST_F(SubscriptionTest, ZeroMaxNotificationsPerPublishMeansUnlimited)
{
  // maxNotificationsPerPublish = 0 (unlimited).
  auto sub = create_subscription(50.0, 100, 3, 0);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 100;
      for (int i = 0; i < 50; ++i)
      {
        item->enqueue_initial(DataValue{Variant{i}});
      }
      g.add_monitored_item(std::move(item));
    });

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  auto* dcn = dynamic_cast<DataChangeNotification*>(results[0].message.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);
  EXPECT_EQ(dcn->monitored_items().size(), 50u);
  EXPECT_FALSE(results[0].moreNotifications);
}

// ============================================================================
// Modify subscription
// ============================================================================

TEST_F(SubscriptionTest, ModifyUpdatesPublishingInterval)
{
  auto sub = create_subscription(100.0);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.modify(200.0, 20, 5, 0, 1);
      EXPECT_EQ(sub->get_info().publishingInterval, 200.0);
      EXPECT_EQ(sub->get_info().priority, 1u);
      EXPECT_EQ(g.max_keep_alive_count(), 5u);
      EXPECT_EQ(g.lifetime_count(), 20u);
    });
}

// ============================================================================
// Set publishing mode
// ============================================================================

// @relation(SVR-SUB-GEN-022, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, SetPublishingModeDisablesNotifications)
{
  auto sub = create_subscription(50.0);

  add_item_with_value(DataValue{Variant{42}});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publishing_mode(false);
      EXPECT_FALSE(g.publishing_enabled());
    });
}

// @verifies AC-SVR-SUB-GEN-111-ROW19-CLEARS-MORENOTIFICATIONS
TEST_F(SubscriptionTest, SetPublishingModeClearsMoreNotificationsDispatchGate)
{
  auto sub = create_subscription(50.0, 100, 3, 1);

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 10;
      item->enqueue_initial(DataValue{Variant{1}});
      item->evaluate_and_enqueue(DataValue{Variant{2}});
      item->evaluate_and_enqueue(DataValue{Variant{3}});
      guard.add_monitored_item(std::move(item));

      auto firstResponse = guard.fulfill_publish(1);
      ASSERT_EQ(firstResponse.size(), 1u);
      ASSERT_TRUE(firstResponse.front().moreNotifications);
      ASSERT_TRUE(sub->get_info().readyToPublish);

      guard.set_publishing_mode(true);
    });

  const auto afterModeChange = sub->get_info();
  EXPECT_TRUE(afterModeChange.hasNotifications) << "row 19 retains the pending Notification batch";
  EXPECT_FALSE(afterModeChange.readyToPublish)
    << "row 19 clears MoreNotifications until the next publishing-timer expiry";
}

// @verifies AC-SVR-SUB-GEN-111-ROW19-CLEARS-MORENOTIFICATIONS
TEST_F(SubscriptionTest, SetPublishingModePreservesTimerGrantedDelivery)
{
  auto sub = create_subscription(50.0, 100, 3, 0, false);
  add_item_with_value(DataValue{Variant{42}});

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      guard.set_publish_req_queued(false);
      guard.on_publishing_timer_expired();
    });
  ASSERT_TRUE(sub->get_info().readyToPublish) << "the first publishing cycle grants a send slot";

  auto results = STA::on_strand(*sub,
    [&](auto& guard)
    {
      guard.set_publishing_mode(true);
      EXPECT_TRUE(sub->get_info().readyToPublish)
        << "SetPublishingMode must not withdraw a timer-granted slot";
      return guard.fulfill_publish(1);
    });

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results.front().message.notification_data().size(), 1u)
    << "the retained queue must remain deliverable after publishing is enabled";
}

// A publishing-timer expiry between a MoreNotifications response and SetPublishingMode grants a send slot
// of its own and moves the Subscription to Late, where later expiries grant nothing new. Withdrawing that
// slot with the continuation's leaves every later Publish unanswered (weekly-ci-green pipeline 2964959201).
// @verifies AC-SVR-SUB-GEN-111-ROW19-CLEARS-MORENOTIFICATIONS
TEST_F(SubscriptionTest, SetPublishingModePreservesTheSlotALateSubscriptionHolds)
{
  auto sub = create_subscription(50.0, 100, 3, 1);

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 10;
      item->enqueue_initial(DataValue{Variant{1}});
      item->evaluate_and_enqueue(DataValue{Variant{2}});
      item->evaluate_and_enqueue(DataValue{Variant{3}});
      guard.add_monitored_item(std::move(item));

      auto firstResponse = guard.fulfill_publish(1);
      ASSERT_EQ(firstResponse.size(), 1u);
      ASSERT_TRUE(firstResponse.front().moreNotifications);

      guard.set_publish_req_queued(false);
      guard.on_publishing_timer_expired();
      ASSERT_EQ(guard.publishing_state(), Subscription::PublishingState::Late);

      guard.set_publishing_mode(true);
      EXPECT_EQ(guard.publishing_state(), Subscription::PublishingState::Late)
        << "row 19 does not change the state";
    });

  EXPECT_TRUE(sub->get_info().readyToPublish)
    << "a Late Subscription answers the next Publish at once, and no later expiry grants a slot again";
}

// ============================================================================
// Close
// ============================================================================

TEST_F(SubscriptionTest, CloseCleanUpResources)
{
  auto sub = create_subscription(50.0);
  add_item_with_value(DataValue{Variant{42}});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.close();
      EXPECT_EQ(g.monitored_items().size(), 0u);
      EXPECT_FALSE(sub->get_info().hasNotifications);
    });
}

TEST_F(SubscriptionTest, CloseIsIdempotent)
{
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.close();
      g.close();  // Should not crash.
    });
}

TEST_F(SubscriptionTest, OperationsAfterCloseAreNoOps)
{
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.close();

      // on_samples_received after close should not crash.
      std::vector<std::pair<IntegerId, DataValue>> batch;
      batch.emplace_back(IntegerId{1}, DataValue{Variant{42}});
      g.on_samples_received(std::move(batch));

      // fulfill_publish after close returns empty.
      auto results = g.fulfill_publish(1);
      EXPECT_TRUE(results.empty());
    });
}

// ============================================================================
// SampleSink integration
// ============================================================================

TEST_F(SubscriptionTest, SampleSinkPostsBatchToSubscriptionStrand)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  ASSERT_NE(sink, nullptr);

  // Push a batch via the SampleSink (simulating namespace push).
  DataValue dv;
  dv.value() = Variant{99};
  std::vector<std::pair<IntegerId, DataValue>> batch;
  batch.emplace_back(id, std::move(dv));
  sink->push(std::move(batch));

  // Flush the subscription strand to ensure the push has been processed.
  STA::on_strand(*sub, [](auto&) {});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->has_reportable_notifications());
    });
}

TEST_F(SubscriptionTest, SampleSinkDetachStopsDelivery)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  sink->detach();

  // Push after detach should be silently dropped.
  DataValue dv;
  dv.value() = Variant{99};
  std::vector<std::pair<IntegerId, DataValue>> batch;
  batch.emplace_back(id, std::move(dv));
  sink->push(std::move(batch));

  // Flush the subscription strand to ensure the push (if any) has been processed.
  STA::on_strand(*sub, [](auto&) {});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->has_reportable_notifications());
    });
}

// ============================================================================
// SemanticsChanged sink routing (CTT Data Access Analog 008)
// ============================================================================

// The mark_semantics_changed sink verb posts to the subscription strand and arms the target item.
TEST_F(SubscriptionTest, MarkSemanticsChangedArmsMonitoredItem)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  ASSERT_NE(sink, nullptr);

  sink->mark_semantics_changed(id);

  // Flush the subscription strand to ensure the post has been processed.
  STA::on_strand(*sub, [](auto&) {});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_TRUE(item->pendingSemanticChange);
    });
}

// After detach the verb is silently dropped (no arming).
TEST_F(SubscriptionTest, MarkSemanticsChangedAfterDetachIsDropped)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  sink->detach();

  sink->mark_semantics_changed(id);
  STA::on_strand(*sub, [](auto&) {});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->pendingSemanticChange);
    });
}

// Full polled path at the subscription layer (mirrors 008 mechanically, minus the namespace
// capability): arm via the sink, then deliver an unchanged-within-deadband sample via the sink.
// The published DataChange carries Good|SemanticsChanged and the flag clears on publish.
TEST_F(SubscriptionTest, SemanticsChangedPolledDeliveryCarriesBitThroughPublish)
{
  auto sub = create_subscription();

  auto id = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 77;
      item->queueSize = 1;
      item->trigger = DataChangeTrigger::StatusValue;
      item->deadbandType = DeadbandType::Absolute;
      item->deadbandValue = 10.0;
      grant_test_read_access(*item);
      item->enqueue_initial(DataValue{Variant{50.0}});
      return g.add_monitored_item(std::move(item));
    });

  // Publish #1 drains the initial value (no bit) and caches it as lastSentValue.
  auto first = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });
  ASSERT_EQ(first.size(), 1u);

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });

  // Semantics changed: arming synthesizes a bit-carrying sample from the cache now; a subsequent
  // unchanged-within-deadband sample (|51-50|<10) overwrites the queueSize-1 slot, still carrying
  // the bit (re-flagged on enqueue).
  sink->mark_semantics_changed(id);
  std::vector<std::pair<IntegerId, DataValue>> batch;
  batch.emplace_back(id, DataValue{Variant{51.0}});
  sink->push(std::move(batch));
  STA::on_strand(*sub, [](auto&) {});

  // Publish #2 carries the bit.
  auto second = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });
  ASSERT_EQ(second.size(), 1u);

  auto* dcn = dynamic_cast<DataChangeNotification*>(second[0].message.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);
  ASSERT_EQ(dcn->monitored_items().size(), 1u);
  const auto& published = dcn->monitored_items()[0].value();
  ASSERT_TRUE(published.status().has_value());
  EXPECT_TRUE(published.status()->semantics_changed());
  EXPECT_TRUE(published.status()->is_good());

  // The flag cleared when the bit-carrying value was published.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(id);
      ASSERT_NE(item, nullptr);
      EXPECT_FALSE(item->pendingSemanticChange);
    });
}

// Exception-reported item (no tick coming): mark_semantics_changed synthesizes a bit-carrying
// sample from the item's cache, with NO intervening sample push, and it publishes.
TEST_F(SubscriptionTest, SemanticsChangedExceptionItemSynthesizesFromCache)
{
  auto sub = create_subscription();

  auto id = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 88;
      item->queueSize = 10;
      item->enqueue_initial(DataValue{Variant{3.5}});
      return g.add_monitored_item(std::move(item));
    });

  // Publish #1 caches lastSentValue (3.5).
  auto first = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });
  ASSERT_EQ(first.size(), 1u);

  // Semantics changed - no sample push follows (exception item, value didn't move).
  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  sink->mark_semantics_changed(id);
  STA::on_strand(*sub, [](auto&) {});

  // Publish #2 carries the synthesized cached value with the bit.
  auto second = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });
  ASSERT_EQ(second.size(), 1u);

  auto* dcn = dynamic_cast<DataChangeNotification*>(second[0].message.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);
  ASSERT_EQ(dcn->monitored_items().size(), 1u);
  const auto& published = dcn->monitored_items()[0].value();
  EXPECT_EQ(published.value().as<double>(), 3.5);
  ASSERT_TRUE(published.status().has_value());
  EXPECT_TRUE(published.status()->semantics_changed());
}

// Disabling a monitored item clears a pending SemanticsChanged arming (it must not leak across a
// disable/re-enable - the queue it would flag is gone).
TEST_F(SubscriptionTest, SemanticsChangedClearedOnDisable)
{
  auto sub = create_subscription();
  auto id = add_empty_item();

  auto sink = STA::on_strand(*sub, [&](auto& g) { return g.sample_sink(); });
  sink->mark_semantics_changed(id);
  STA::on_strand(*sub, [](auto&) {});

  EXPECT_TRUE(
    STA::on_strand(*sub, [&](auto& g) { return g.find_monitored_item(id)->pendingSemanticChange; }));
  const auto results = set_mode_blocking({id}, MonitoringMode::Disabled);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results.front(), StatusCode{Status::Good});
  EXPECT_FALSE(
    STA::on_strand(*sub, [&](auto& g) { return g.find_monitored_item(id)->pendingSemanticChange; }));
}

// ============================================================================
// Lifetime expiry
// ============================================================================

// @relation(SVR-SUB-GEN-030, SVR-SUB-GEN-032, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, SubscriptionExpiresAfterLifetimeCountCycles)
{
  // Very short interval (10ms), lifetime count of 3 -> expires after ~30ms.
  auto sub = create_subscription(10.0, 3, 1, 0, true, 0);

  ASSERT_TRUE(wait_for_expired(2000ms));

  std::lock_guard lock(mMutex);
  EXPECT_EQ(mLastExpiredSubId, sub->id());
}

// A non-Publish Service call that references the subscription resets the lifetime
// counter (Part 4 section 5.13.1.1 h): the SubscriptionsPipeline service handlers invoke
// on_service_call_async() for exactly this reason. Without resets, a 10ms-interval /
// lifetime-10 subscription expires after ~100ms; periodic service calls must keep it
// alive well beyond that. (UACTT Subscription Basic 063.)
TEST_F(SubscriptionTest, ServiceCallResetsLifetimeAndPreventsExpiry)
{
  auto sub = create_subscription(10.0, 10, 1, 0, true, 0);  // ~100ms unmanaged lifetime

  // Issue a service call every ~30ms (3 ticks) for ~300ms - three times the
  // unmanaged lifetime. The counter never approaches expiry because each call
  // resets it.
  for (int i = 0; i < 10; ++i)
  {
    std::this_thread::sleep_for(30ms);
    sub->on_service_call_async();
  }

  {
    std::lock_guard lock(mMutex);
    EXPECT_EQ(mExpiredCount, 0) << "service calls did not extend the subscription lifetime";
  }

  // Once the service calls stop, the subscription does expire - proving the timer
  // was decrementing all along and the resets, not a stalled timer, kept it alive.
  EXPECT_TRUE(wait_for_expired(2000ms));
}

// ============================================================================
// Publish request queued flag
// ============================================================================

TEST_F(SubscriptionTest, SetPublishReqQueuedIsReadableFromTimerCallback)
{
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // The first timer tick should see publishReqQueued=true and signal ready.
  ASSERT_TRUE(wait_for_ready(1, 500ms));
}

// ============================================================================
// Phase 3A: State Machine Transitions
// ============================================================================

// @relation(SVR-SUB-GEN-011, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, NormalWithNotifications_SignalsReady)
{
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Add item with a queued data value.
  add_item_with_value(DataValue{Variant{42}});

  // Timer fires at 50ms and should signal ready because notifications are available.
  ASSERT_TRUE(wait_for_ready(1, 2000ms));
}

TEST_F(SubscriptionTest, NormalNoNotificationsNoMessageSent_SignalsReady)
{
  // No monitored items at all. First cycle guarantee: must send keep-alive.
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // First timer cycle should signal ready even without notifications (first cycle keep-alive).
  ASSERT_TRUE(wait_for_ready(1, 2000ms));
}

TEST_F(SubscriptionTest, NormalNoNotificationsMessageSent_TransitionsToKeepAlive)
{
  auto sub = create_subscription(50.0);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Wait for first cycle (keep-alive due to no notifications).
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // Dispatch the publish to set mMessageSent = true.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  // With mMessageSent=true and no notifications, the next timer tick transitions to KeepAlive.
  // Wait for the keep-alive countdown to fire a second ready signal, proving the
  // subscription passed through KeepAlive state.
  ASSERT_TRUE(wait_for_ready(2, 2000ms));

  auto state = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  EXPECT_EQ(state, Subscription::PublishingState::KeepAlive);
}

// @relation(SVR-SUB-GEN-012, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, NormalNoPublishReqQueued_TransitionsToLate)
{
  auto sub = create_subscription(50.0);
  // Deliberately do NOT set publish_req_queued.
  add_item_with_value(DataValue{Variant{42}});

  // Timer fires, notifications available, but no publish request queued -> Late.
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  auto state = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  EXPECT_EQ(state, Subscription::PublishingState::Late);
}

TEST_F(SubscriptionTest, LateTimerFire_StaysLate)
{
  auto sub = create_subscription(50.0);
  // No publish request queued -> will go to Late.
  add_item_with_value(DataValue{Variant{42}});

  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // Confirm we're in Late state.
  auto state1 = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  ASSERT_EQ(state1, Subscription::PublishingState::Late);

  // Late does not re-signal ready (it just restarts the timer), so there is
  // no deterministic event to synchronize on. Sleep for 3x the timer interval
  // then flush the strand to ensure any timer-posted work completed.
  std::this_thread::sleep_for(150ms);
  STA::on_strand(*sub, [](auto&) {});

  // Should still be Late.
  auto state2 = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  EXPECT_EQ(state2, Subscription::PublishingState::Late);
}

// @relation(SVR-SUB-GEN-020, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, KeepAliveCountdown_SendsKeepAlive)
{
  // maxKeepAliveCount=2: after entering KeepAlive, countdown from 2.
  // At counter=2 first tick decrements to 1; second tick: counter<=1 signals ready.
  auto sub = create_subscription(50.0, 100, 2);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // First cycle: signals ready (first cycle guarantee).
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // Dispatch to set messageSent=true.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  // Next timer: transitions to KeepAlive with counter=2.
  // Then two more ticks: counter->1, then counter<=1 -> signals ready.
  // Wait for the keep-alive ready signal (2nd ready).
  ASSERT_TRUE(wait_for_ready(2, 2000ms));

  auto keepAliveCounter = STA::on_strand(*sub, [&](auto& g) { return g.keep_alive_counter(); });
  // After keep-alive send, counter resets to maxKeepAliveCount.
  EXPECT_EQ(keepAliveCounter, 2u);
}

// @relation(SVR-SUB-GEN-023, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, KeepAliveWithNotifications_TransitionsToNormal)
{
  // When in KeepAlive and notifications become available, the subscription
  // should signal ready (transitioning through Normal). We verify this by
  // confirming a second ready signal fires after adding notifications in KeepAlive,
  // and that dispatching the publish produces the expected notification.
  auto sub = create_subscription(50.0, 100, 3);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // First cycle: signals ready.
  ASSERT_TRUE(wait_for_ready(1, 500ms));
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  // Wait for transition to KeepAlive.
  std::this_thread::sleep_for(150ms);

  auto stateBeforeAdd = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  ASSERT_EQ(stateBeforeAdd, Subscription::PublishingState::KeepAlive);

  // Now add a notification while in KeepAlive.
  add_item_with_value(DataValue{Variant{99}});

  // Wait for next timer tick which should see notifications and signal ready.
  ASSERT_TRUE(wait_for_ready(2, 2000ms));

  // Verify the notification is deliverable by dispatching a publish.
  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });
  ASSERT_EQ(results.size(), 1u);
  // Should contain the notification data (not a keep-alive).
  EXPECT_FALSE(results[0].message.notification_data().empty());
}

// ============================================================================
// Phase 3B: Lifetime Management
// ============================================================================

// @relation(SVR-SUB-GEN-031, scope=function)
TEST_F(SubscriptionTest, PublishDispatchResetsLifetime)
{
  auto sub = create_subscription(50.0, 100, 3);

  add_item_with_value(DataValue{Variant{42}});

  // Dispatch a publish.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  auto lifetimeCounter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(lifetimeCounter, 100u);
}

// @relation(SVR-SUB-GEN-031, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, ServiceCallResetsLifetime)
{
  auto sub = create_subscription(50.0, 100, 3);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Wait for a timer tick to decrement lifetime.
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // on_service_call resets lifetime.
  STA::on_strand(*sub, [&](auto& g) { g.on_service_call(); });

  auto lifetimeCounter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(lifetimeCounter, 100u);
}

// @relation(SVR-SUB-GEN-031, scope=function)
TEST_F(SubscriptionTest, ModifyResetsLifetimeAndRestartsTimer)
{
  auto sub = create_subscription(50.0, 100, 3);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Wait for a timer tick to decrement lifetime.
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // Modify resets lifetime counter.
  STA::on_strand(*sub, [&](auto& g) { g.modify(50.0, 200, 3, 0, 0); });

  auto lifetimeCounter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(lifetimeCounter, 200u);
}

// @relation(SVR-SUB-GEN-031, scope=function)
TEST_F(SubscriptionTest, SetPublishingModeResetsLifetime)
{
  auto sub = create_subscription(50.0, 100, 3);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // Wait for a timer tick to decrement lifetime.
  ASSERT_TRUE(wait_for_ready(1, 500ms));

  // SetPublishingMode resets lifetime.
  STA::on_strand(*sub, [&](auto& g) { g.set_publishing_mode(false); });

  auto lifetimeCounter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(lifetimeCounter, 100u);
}

// @relation(SVR-SUB-GEN-031, scope=function)
TEST_F(SubscriptionTest, LifetimeCounterResetsWhenPublishReqQueued)
{
  // Create subscription with large lifetime so it won't expire during the test.
  auto sub = create_subscription(50.0, 100, 3);

  // Decrement lifetime by simulating a timer tick without publish requests.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(false);
      g.on_publishing_timer_expired();
    });

  auto counter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(counter, 99u) << "Lifetime should decrement when no publish requests are queued";

  // Now set publish req queued and tick again - counter should reset to initial value.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      g.on_publishing_timer_expired();
    });

  counter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(counter, 100u) << "Lifetime should reset when publish requests are queued";
}

TEST_F(SubscriptionTest, LifetimeCounterDoesNotExpireWhenPublishReqQueued)
{
  // Create subscription with lifetime of 2 - would expire in 2 ticks without publish requests.
  auto sub = create_subscription(50.0, 2, 1);

  // Tick with publish requests queued - counter should reset, not decrement.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      g.on_publishing_timer_expired();
      g.on_publishing_timer_expired();
      g.on_publishing_timer_expired();
    });

  // Subscription should still be alive - counter was reset each time.
  auto counter = STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); });
  EXPECT_EQ(counter, 2u) << "Lifetime should never expire while publish requests are queued";
}

// ============================================================================
// Phase 3C: Sequence Numbers
// ============================================================================

// @relation(SVR-SUB-GEN-042, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, SequenceNumberStartsAtOne)
{
  auto sub = create_subscription();

  auto seq = STA::on_strand(*sub, [&](auto& g) { return g.peek_sequence_number(); });
  EXPECT_EQ(seq, 1u);
}

// Covers SVR-SUB-GEN-043 (coverage-audit retag).
// @relation(SVR-SUB-GEN-041, SVR-SUB-GEN-043, SVR-SUB-GEN-126, scope=function)
TEST_F(SubscriptionTest, SequenceNumberWrapsToOneNotZero)
{
  auto sub = create_subscription();

  STA::on_strand(*sub,
    [&](auto& g)
    {
      // Set sequence number near UINT32_MAX.
      g.next_sequence_number() = std::numeric_limits<uint32_t>::max();

      // Allocate: should return UINT32_MAX and advance to 1.
      uint32_t allocated = g.allocate_sequence_number();
      EXPECT_EQ(allocated, std::numeric_limits<uint32_t>::max());

      // Next peek should be 1, not 0.
      EXPECT_EQ(g.peek_sequence_number(), 1u);
    });
}

TEST_F(SubscriptionTest, PeekDoesNotIncrement)
{
  auto sub = create_subscription();

  auto [seq1, seq2] = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto s1 = g.peek_sequence_number();
      auto s2 = g.peek_sequence_number();
      return std::make_pair(s1, s2);
    });
  EXPECT_EQ(seq1, seq2);
}

// ============================================================================
// Phase 3D: Publish Dispatch Details
// ============================================================================

TEST_F(SubscriptionTest, PublishDispatchedSetsMessageSent)
{
  auto sub = create_subscription();

  // Initially messageSent is false.
  auto sentBefore = STA::on_strand(*sub, [&](auto& g) { return g.message_sent(); });
  EXPECT_FALSE(sentBefore);

  add_item_with_value(DataValue{Variant{42}});

  // Dispatch a publish.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  auto sentAfter = STA::on_strand(*sub, [&](auto& g) { return g.message_sent(); });
  EXPECT_TRUE(sentAfter);
}

TEST_F(SubscriptionTest, PublishDispatchedWithMoreNotifications_SignalsReady)
{
  // maxNotificationsPerPublish=1, but 3 items queued -> more notifications remain.
  auto sub = create_subscription(50.0, 100, 3, 1);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->clientHandle = 10;
      item->queueSize = 10;
      item->enqueue_initial(DataValue{Variant{1}});
      item->evaluate_and_enqueue(DataValue{Variant{2}});
      item->evaluate_and_enqueue(DataValue{Variant{3}});
      g.add_monitored_item(std::move(item));
    });

  auto results = STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].moreNotifications);

  // The subscription should have signaled ready again for remaining items.
  // Check that ready count incremented (signal_ready is called internally).
  ASSERT_TRUE(wait_for_ready(1, 500ms));
}

TEST_F(SubscriptionTest, PublishDispatchedNoNotifications_GoesKeepAlive)
{
  auto sub = create_subscription();

  add_item_with_value(DataValue{Variant{42}});

  // Dispatch: drains the single notification.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  auto state = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });

  // After dispatching with no remaining notifications, should go to Normal
  // (fulfill_publish sets Normal when !moreNotifications).
  EXPECT_EQ(state, Subscription::PublishingState::Normal);

  // Dispatch again with no notifications -> keep-alive.
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  state = STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); });
  EXPECT_EQ(state, Subscription::PublishingState::KeepAlive);
}

TEST_F(SubscriptionTest, PublishingDisabledDoesNotSignalReadyForNotifications)
{
  // When publishingEnabled=false, the timer-driven state machine should not
  // signal ready due to available notifications. Only keep-alive signals
  // should fire. Verify that adding a notification while disabled does not
  // cause an extra ready signal beyond the keep-alive cadence.
  auto sub = create_subscription(50.0, 100, 3, 0, false);
  STA::on_strand(*sub, [&](auto& g) { g.set_publish_req_queued(true); });

  // First cycle: signals ready (first cycle guarantee, mMessageSent=false).
  ASSERT_TRUE(wait_for_ready(1, 500ms));
  STA::on_strand(*sub, [&](auto& g) { g.fulfill_publish(1); });

  // Now add notifications. With publishing disabled, the Normal->ready path
  // checks "mPublishingEnabled && notificationsAvailable" which is false.
  // The only ready signals should come from keep-alive countdown.
  add_item_with_value(DataValue{Variant{42}});

  // In KeepAlive with maxKeepAliveCount=3, keep-alive fires after 3 ticks
  // (at ~150ms). With just 2 ticks (~100ms) no extra signal should arrive
  // beyond the first one we already consumed.
  EXPECT_FALSE(wait_for_ready(2, 100ms));
}

// ===========================================================================
// SetSubscriptionDurable (Part 4 section 5.13.9)
// ===========================================================================

namespace
{
/// Drive set_durable on the strand and return (status, revisedLifetimeInHours). The limits default
/// to the SubscriptionLimits defaults (durable enabled, 24h max, 10k durable queue ceiling).
std::pair<StatusCode, uint32_t> call_set_durable(
  Subscription& sub, uint32_t lifetimeInHours, ServerConfig::SubscriptionLimits subscriptionLimits = {})
{
  StatusCode status{Status::Bad};
  uint32_t revised = 0;
  STA::on_strand(sub,
    [&](auto& g)
    {
      g.set_durable(lifetimeInHours,
        subscriptionLimits,
        [&](StatusCode s, uint32_t r)
        {
          status = s;
          revised = r;
        });
    });
  return {status, revised};
}
}  // namespace

TEST_F(SubscriptionTest, SetDurableMarksSubscriptionAndRevisesLifetimeHours)
{
  // 1000ms publishing interval, lifetimeCount=30, maxKeepAliveCount=3.
  create_subscription(1000.0, 30, 3);

  auto [status, revised] = call_set_durable(*mSubscription, 5);
  EXPECT_TRUE(status.is_good()) << "0x" << std::hex << status.as_uint32();
  EXPECT_EQ(revised, 5u);

  bool durable = STA::on_strand(*mSubscription, [&](auto& g) { return g.durable(); });
  EXPECT_TRUE(durable);

  // Lifetime count recomputed from 5h: (5 * 3600 * 1000) / 1000ms = 18000 cycles.
  uint32_t lifetimeCount = STA::on_strand(*mSubscription, [&](auto& g) { return g.lifetime_count(); });
  EXPECT_EQ(lifetimeCount, 18000u);
}

TEST_F(SubscriptionTest, SetDurableClampsZeroLifetimeToOneHour)
{
  create_subscription(500.0, 30, 3);
  auto [status, revised] = call_set_durable(*mSubscription, 0);
  EXPECT_TRUE(status.is_good());
  EXPECT_EQ(revised, 1u);  // 0 -> at least 1 hour (CTT 003)
}

TEST_F(SubscriptionTest, SetDurableClampsHugeLifetimeToServerMaximum)
{
  create_subscription(500.0, 30, 3);
  auto [status, revised] = call_set_durable(*mSubscription, std::numeric_limits<uint32_t>::max());
  EXPECT_TRUE(status.is_good());
  EXPECT_EQ(revised, 24u);  // capped at the default maxDurableSubscriptionLifetimeHours (CTT 002)
}

TEST_F(SubscriptionTest, SetDurableRevisesLifetimeToConfiguredMaximum)
{
  create_subscription(500.0, 30, 3);

  // A non-default (lower) configured maximum must be the cap, proving the value comes from config and
  // not a hard-coded constant.
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxDurableSubscriptionLifetimeHours = 2;

  auto [status, revised] = call_set_durable(*mSubscription, 10, subLimits);
  EXPECT_TRUE(status.is_good());
  EXPECT_EQ(revised, 2u);
}

TEST_F(SubscriptionTest, SetDurableRefusedWhenDisabled)
{
  create_subscription(500.0, 30, 3);

  ServerConfig::SubscriptionLimits subLimits;
  subLimits.durableSubscriptionsEnabled = false;

  auto [status, revised] = call_set_durable(*mSubscription, 5, subLimits);
  EXPECT_EQ(status.as_uint32(), static_cast<uint32_t>(Status::BadServiceUnsupported));
  EXPECT_EQ(revised, 0u);

  bool durable = STA::on_strand(*mSubscription, [&](auto& g) { return g.durable(); });
  EXPECT_FALSE(durable);
}

TEST_F(SubscriptionTest, SetDurablePreservesLifetimeInvariantForLongIntervals)
{
  // Large publishing interval (1 hour): 1h durable window -> < 3xmaxKeepAliveCount cycles.
  // Lifetime count must still satisfy lifetimeCount >= 3 x maxKeepAliveCount.
  create_subscription(3'600'000.0, 30, 10);
  auto [status, revised] = call_set_durable(*mSubscription, 1);
  EXPECT_TRUE(status.is_good());
  EXPECT_EQ(revised, 1u);

  uint32_t lifetimeCount = STA::on_strand(*mSubscription, [&](auto& g) { return g.lifetime_count(); });
  EXPECT_GE(lifetimeCount, 30u);  // 3 x maxKeepAliveCount(10)
}

TEST_F(SubscriptionTest, SetDurableFailsWithBadInvalidStateWhenMonitoredItemsPresent)
{
  create_subscription(500.0, 30, 3);
  add_empty_item();  // a monitored item now exists

  auto [status, revised] = call_set_durable(*mSubscription, 5);
  EXPECT_EQ(status.as_uint32(), static_cast<uint32_t>(Status::BadInvalidState));
  EXPECT_EQ(revised, 0u);

  bool durable = STA::on_strand(*mSubscription, [&](auto& g) { return g.durable(); });
  EXPECT_FALSE(durable);
}
