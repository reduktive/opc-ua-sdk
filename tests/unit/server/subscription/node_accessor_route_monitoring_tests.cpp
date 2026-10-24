// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The initial value of a monitored item with an IndexRange is that range of the source's value,
/// applied once (a guard of COMP-ADDRSP-ACCESSOR-ROUTE-05 item 1).
///
/// The Subscription is driven as the pipeline drives it: CreateMonitoredItems through its asynchronous entry,
/// the value read from a Variable's read handler, and the notifications taken by fulfill_publish.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_numeric_range_parser.h"
#include "ua_value_source.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;

namespace
{

/// The first DataChange notification of the item with @p clientHandle among @p published, if any.
template<typename Published>
std::optional<DataValue> first_notification_of(const Published& published, uint32_t clientHandle)
{
  for (const auto& result : published)
  {
    for (const auto& data : result.message.notification_data())
    {
      const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
      if (change == nullptr)
      {
        continue;
      }
      for (const auto& notification : change->monitored_items())
      {
        if (notification.client_handle() == clientHandle)
        {
          return notification.value();
        }
      }
    }
  }
  return std::nullopt;
}

}  // namespace

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-05-A-RANGED-MONITORED-ITEMS-INITIAL-VALUE-IS-NARROWED-ONCE, scope=function)
TEST(NodeAccessorRoute, ARangedMonitoredItemsInitialValueIsNarrowedOnce)
{
  constexpr uint32_t clientHandle = 7;
  boost::asio::thread_pool pool{4};
  auto executor = pool.get_executor();
  {
    auto addressSpace = AddressSpace::create("urn:test:node-accessor-route-monitoring", executor);
    auto securityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(addressSpace);
    ServerConfig::ServerCapabilities capabilities;
    capabilities.minSupportedSampleRate = 0;
    capabilities.maxMonitoredItemsQueueSize = 1000u;
    ServerConfig::SubscriptionLimits subscriptionLimits;
    auto subscription =
      Subscription::create(1, 1'000'000.0, 100, 3, 0, true, 0, executor, [](IntegerId) {}, [](IntegerId) {});

    const NodeId variableId{1, "accessor-route-monitoring:V"};
    auto created = addressSpace.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    auto variable = created.value();
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    variable.set_access_level(accessLevel);
    auto* source = variable->external_value_source();
    ASSERT_NE(source, nullptr);
    auto reads = std::make_shared<std::atomic<int>>(0);
    ASSERT_TRUE(source
                  ->set_value_source(make_value_source(
                    [reads](const ValueSource::ReadContext&,
                      const Node&,
                      const ReadValueId& read,
                      std::function<void(DataValueResult)>
                        complete)
                    {
                      reads->fetch_add(1);
                      DataValue value;
                      value.value() = Variant{Array<int32_t>{10, 20, 30, 40}};
                      ua::index_range_utils::apply_to_value(value, read.index_range());
                      complete(DataValueResult{std::move(value)});
                    }))
                  .is_good());

    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = variableId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.item_to_monitor().index_range() = "1:2";
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 100.0;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    subscription->create_monitored_items_async(std::move(request),
      addressSpace,
      capabilities,
      subscriptionLimits,
      securityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<MonitoredItemCreateResult> results) { promise->set_value(std::move(results)); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the create did not answer";
    const auto results = future.get();
    ASSERT_EQ(results.size(), 1u);
    ASSERT_TRUE(results[0].status_code().is_good()) << to_string(results[0].status_code());

    std::optional<DataValue> first;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!first.has_value() && std::chrono::steady_clock::now() < deadline)
    {
      const auto published = STA::on_strand(*subscription,
        [](auto& guard)
        {
          guard.set_publish_req_queued(true);
          return guard.fulfill_publish(1);
        });
      first = first_notification_of(published, clientHandle);
      if (!first.has_value())
      {
        std::this_thread::sleep_for(5ms);
      }
    }
    ASSERT_TRUE(first.has_value()) << "the item reported nothing";
    EXPECT_TRUE(!first->status().has_value() || first->status()->is_good())
      << "the first notification has the status " << to_string(*first->status());
    ASSERT_TRUE(first->value().is_array()) << "the first notification holds " << to_string(first->value());
    const auto& range = first->value().as<Array<int32_t>>();
    ASSERT_EQ(static_cast<std::size_t>(range.size()), 2u)
      << "the first notification holds " << to_string(first->value()) << ", not the range 1:2";
    EXPECT_EQ(range[0], 20);
    EXPECT_EQ(range[1], 30);
    EXPECT_GT(reads->load(), 0) << "the value was not read from the handler";

    subscription.reset();
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
