// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-SVR-NAMESPACE-CALLS-17 rule 2: a sample sink's mark_structure_changed makes the monitored item set the
// StructureChanged bit on one data change notification, and when the notification carrying it is discarded by
// a queue overflow, the next notification in the queue carries it (OPC 10000-4 7.39.1 Table 180; NR-68 item
// 10).

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_data_change_notification.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_sample_sink_impl.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;

using STA = SubscriptionTestAccess;

namespace
{

/// A Subscription with one data monitored item that the server's own read access allows, so that a sample
/// pushed through the Subscription's sink is queued as the sampler's samples are.
class SampleSinkStructureChanged : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test:structure-changed-sink", mExecutor));
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    auto accessNode =
      mAddressSpace->try_create_node_sync(NodeId{1, uint32_t{68100}}, NodeClass::Variable, {});
    ASSERT_TRUE(accessNode);
    mAccessNode = accessNode.value();
    // A publishing interval far beyond the test, so that only the test's Publish drains the queue.
    mSubscription = Subscription::create(
      IntegerId{1}, 10000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  void TearDown() override
  {
    mSubscription.reset();
    mSecurityContext.reset();
    mAccessNode.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// Adds a Reporting data item on a Value with @p queueSize, discarding the oldest unless @p discardOldest
  /// is false, and returns its id.
  IntegerId add_data_item(uint32_t queueSize, bool discardOldest = true, uint32_t clientHandle = 7)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = MonitoringMode::Reporting;
        item->clientHandle = clientHandle;
        item->queueSize = queueSize;
        item->discardOldest = discardOldest;
        item->trigger = DataChangeTrigger::StatusValue;
        item->deadbandType = DeadbandType::None;
        item->accessSecurityContext = mSecurityContext;
        item->accessAddressSpace = mAddressSpace->weak();
        item->accessControlNode = *mAccessNode;
        item->itemToMonitor.node_id() = mAccessNode->get_node_id();
        item->itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::Value);
        const auto identity = mSecurityContext->access_identity();
        item->accessSnapshot = MonitoredAccessSnapshot{identity->key(),
          AccessControl::Verdict{.subject = mAccessNode->get_node_id(),
            .operation = AccessOperation::Read,
            .permitted = true,
            .mask = PermissionType{PermissionType::Bit::Read},
            .cause = StatusCode{Status::Good}}};
        return g.add_monitored_item(std::move(item));
      });
  }

  /// Pushes @p value for @p id through @p sink, as one sampling tick does.
  static void push(SampleSink& sink, IntegerId id, int32_t value)
  {
    std::vector<std::pair<IntegerId, DataValue>> batch;
    batch.emplace_back(id, DataValue{Variant{value}});
    sink.push(std::move(batch));
  }

  /// Modifies the item @p id to @p queueSize through the Subscription's ModifyMonitoredItems entry, as the
  /// service calls it, keeping its client handle, its 100 ms interval and @p discardOldest; returns the
  /// item's result status.
  StatusCode modify_queue_size(IntegerId id, uint32_t clientHandle, uint32_t queueSize, bool discardOldest)
  {
    MonitoredItemModifyRequest item;
    item.monitored_item_id() = id;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 100.0;
    item.requested_parameters().queue_size() = queueSize;
    item.requested_parameters().discard_oldest() = discardOldest;
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_modify().push_back(std::move(item));

    ServerConfig::ServerCapabilities capabilities;
    capabilities.minSupportedSampleRate = 0;
    capabilities.maxMonitoredItemsQueueSize = 1000u;
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemModifyResult>>>();
    auto future = promise->get_future();
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      capabilities,
      ServerConfig::SubscriptionLimits{},
      [promise](std::vector<MonitoredItemModifyResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
    {
      return StatusCode{Status::BadTimeout};
    }
    const auto results = future.get();
    return results.size() == 1u ? results[0].status_code() : StatusCode{Status::BadInternalError};
  }

  /// Takes one Publish and answers the notifications it carries for the item with @p clientHandle.
  std::vector<DataValue> publish_for(uint32_t clientHandle)
  {
    auto published = STA::on_strand(*mSubscription,
      [](auto& g)
      {
        g.set_publish_req_queued(true);
        return g.fulfill_publish(1);
      });
    std::vector<DataValue> values;
    for (const auto& result : published)
    {
      for (const auto& data : result.message.notification_data())
      {
        const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
        if (change == nullptr)
          continue;
        for (const auto& notification : change->monitored_items())
        {
          if (notification.client_handle() == clientHandle)
            values.push_back(notification.value());
        }
      }
    }
    return values;
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<Subscription> mSubscription;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  std::optional<NodeAccessor> mAccessNode;
};

}  // namespace

// Queue size 2, discard oldest: 1 and 2 are queued, the item is marked, then 3, 4 and 5 arrive, each pushing
// the oldest out. Whichever notification the mark set the bit on (2, or 3), it was discarded, so 4 carries
// it.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-CARRIED-THROUGH-QUEUE-OVERFLOW, scope=function)
TEST_F(SampleSinkStructureChanged, CarriedThroughQueueOverflow)
{
  const IntegerId id = add_data_item(2);
  // The interface a namespace and its monitoring helper hold.
  const std::shared_ptr<SampleSink> sink =
    STA::on_strand(*mSubscription, [](auto& g) { return g.sample_sink(); });
  ASSERT_NE(sink, nullptr);

  push(*sink, id, 1);
  push(*sink, id, 2);
  sink->mark_structure_changed(id);
  push(*sink, id, 3);
  push(*sink, id, 4);
  push(*sink, id, 5);
  STA::on_strand(*mSubscription, [](auto&) {});

  auto published = STA::on_strand(*mSubscription,
    [](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });
  ASSERT_EQ(published.size(), 1u);
  ASSERT_FALSE(published[0].message.notification_data().empty());
  const auto* change =
    dynamic_cast<DataChangeNotification*>(published[0].message.notification_data()[0].get());
  ASSERT_NE(change, nullptr);
  ASSERT_EQ(change->monitored_items().size(), 2u);

  const DataValue& fourth = change->monitored_items()[0].value();
  const DataValue& fifth = change->monitored_items()[1].value();
  ASSERT_NE(fourth.value().try_as<int32_t>(), nullptr);
  ASSERT_NE(fifth.value().try_as<int32_t>(), nullptr);
  EXPECT_EQ(*fourth.value().try_as<int32_t>(), 4);
  EXPECT_EQ(*fifth.value().try_as<int32_t>(), 5);
  EXPECT_TRUE(fourth.status().has_value() && fourth.status()->structure_changed())
    << "4 does not carry StructureChanged: " << (fourth.status() ? to_string(*fourth.status()) : "no status");
  EXPECT_FALSE(fifth.status().has_value() && fifth.status()->structure_changed())
    << "5 carries StructureChanged: " << to_string(*fifth.status());
}

// Case 1: queue size 3, discard oldest; 1 and 2 queued, the item marked, 3 queued, then the queue shrunk to
// 1, which keeps 3 alone. Case 2: the same with discardOldest false, shrunk to 2, which keeps 1 and the
// latest, 3. The modify deletes queued notifications as an overflow does, so the bit reaches one that is
// kept.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-CARRIED-THROUGH-A-QUEUE-SHRINK, scope=function)
TEST_F(SampleSinkStructureChanged, CarriedThroughAQueueShrink)
{
  const std::shared_ptr<SampleSink> sink =
    STA::on_strand(*mSubscription, [](auto& g) { return g.sample_sink(); });
  ASSERT_NE(sink, nullptr);
  const auto carriesTheBit = [](const DataValue& value)
  {
    return value.status().has_value() && value.status()->structure_changed();
  };
  const auto int32Of = [](const DataValue& value)
  {
    const auto* held = value.value().try_as<int32_t>();
    return held != nullptr ? *held : -1;
  };

  // Case 1.
  const uint32_t discardOldestHandle = 31;
  const IntegerId discardOldest = add_data_item(3, true, discardOldestHandle);
  push(*sink, discardOldest, 1);
  push(*sink, discardOldest, 2);
  sink->mark_structure_changed(discardOldest);
  push(*sink, discardOldest, 3);
  STA::on_strand(*mSubscription, [](auto&) {});
  const StatusCode shrunkToOne = modify_queue_size(discardOldest, discardOldestHandle, 1, true);
  ASSERT_EQ(shrunkToOne.as_status(), Status::Good) << to_string(shrunkToOne);

  const auto kept = publish_for(discardOldestHandle);
  ASSERT_EQ(kept.size(), 1u) << "case 1 published " << kept.size() << " notifications";
  EXPECT_EQ(int32Of(kept[0]), 3);
  EXPECT_TRUE(carriesTheBit(kept[0])) << "case 1: 3 does not carry StructureChanged: "
                                      << (kept[0].status() ? to_string(*kept[0].status()) : "no status");

  // Case 2.
  const uint32_t discardNewestHandle = 32;
  const IntegerId discardNewest = add_data_item(3, false, discardNewestHandle);
  push(*sink, discardNewest, 1);
  push(*sink, discardNewest, 2);
  sink->mark_structure_changed(discardNewest);
  push(*sink, discardNewest, 3);
  STA::on_strand(*mSubscription, [](auto&) {});
  const StatusCode shrunkToTwo = modify_queue_size(discardNewest, discardNewestHandle, 2, false);
  ASSERT_EQ(shrunkToTwo.as_status(), Status::Good) << to_string(shrunkToTwo);

  const auto bothKept = publish_for(discardNewestHandle);
  ASSERT_EQ(bothKept.size(), 2u) << "case 2 published " << bothKept.size() << " notifications";
  std::size_t marked = 0;
  for (const auto& value : bothKept)
  {
    if (carriesTheBit(value))
    {
      ++marked;
      EXPECT_NE(int32Of(value), 1) << "case 2: the notification holding 1 carries StructureChanged";
    }
  }
  EXPECT_EQ(marked, 1u) << "case 2: " << marked << " of the two notifications carry StructureChanged (values "
                        << int32Of(bothKept[0]) << ", " << int32Of(bothKept[1]) << ")";
}
