// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Client tier-1 ConnectionImpl subscription integration test (data-change happy path, section 8.2A /
/// section 8.4).
///
/// Drives the internal `ua::client::detail::ConnectionImpl` orchestrator against a real TestServer over
/// ephemeral TCP: it performs the tier-0 connect (open_channel / create_session / activate) to obtain an
/// activated session, hands it to a `ConnectionImpl`, creates a subscription + a data-change monitored
/// item through the orchestrator, writes a new value, and asserts the notification is delivered to the
/// registered data callback through the SubscriptionsPipeline (the Publish pump auto-runs on the pool).

#include "compliance_helpers.h"

#include "ua_connection_impl.h"

#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_logger.h"
#include "ua_modify_subscription_response.h"
#include "ua_node_id.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <chrono>
#include <cstdint>
#include <future>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionState;

using namespace std::chrono_literals;

namespace
{

/// Builds a WriteRequest setting one node's Value attribute to @p value.
WriteRequest make_int32_write(const NodeId& node, std::int32_t value)
{
  WriteRequest request;
  WriteValue writeValue;
  writeValue.node_id() = node;
  writeValue.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
  writeValue.value() = DataValue{Variant{value}};
  request.nodes_to_write().push_back(std::move(writeValue));
  return request;
}

/// Runs the bootstrap and blocks until it completes, returning the outcome.
VoidResult start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Closes the orchestrator and blocks until it completes.
VoidResult close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Creates a subscription through the orchestrator and blocks until complete.
Result<std::uint32_t> create_subscription_and_wait(ConnectionImpl& connection, double publishingInterval)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_subscription_async(
    publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Thread-safe sink for data-change DataValues delivered to the monitored-item callback.
class DataValueSink
{
public:
  void push(DataValue value)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mValues.push_back(std::move(value));
  }

  std::vector<DataValue> snapshot() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mValues;
  }

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

}  // namespace

using ConnectionImplSubscription = ComplianceWithNodes;

// ---------------------------------------------------------------------------
// A subscription + data-change monitored item created through the orchestrator
// delivers a DataChange notification for a freshly-written value (section 8.4).
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplSubscription, DataChangeNotificationDelivered)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_SUB"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());
  ASSERT_EQ(connection->info()->state, ConnectionState::Active);

  auto subResult = create_subscription_and_wait(*connection, 100.0);
  ASSERT_TRUE(subResult.is_good()) << "create_subscription failed: 0x" << std::hex
                                   << subResult.status_code().as_uint32();
  const std::uint32_t subscriptionId = subResult.value();

  auto sink = std::make_shared<DataValueSink>();
  const std::uint32_t clientHandle = 1;

  std::promise<Result<std::uint32_t>> miPromise;
  auto miFuture = miPromise.get_future();
  connection->create_monitored_item_async(
    subscriptionId,
    mWritableVariableId,
    clientHandle,
    [sink](DataValue value) { sink->push(std::move(value)); },
    [&miPromise](Result<std::uint32_t> result) { miPromise.set_value(std::move(result)); });
  auto miResult = miFuture.get();
  ASSERT_TRUE(miResult.is_good()) << "create_monitored_item failed: 0x" << std::hex
                                  << miResult.status_code().as_uint32();

  // Write a new value; the server samples it and the pump carries the notification back.
  const std::int32_t writtenValue = 13579;
  std::promise<Result<WriteResponse>> writePromise;
  auto writeFuture = writePromise.get_future();
  connection->write_async(make_int32_write(mWritableVariableId, writtenValue),
    [&writePromise](Result<WriteResponse> result) { writePromise.set_value(std::move(result)); });
  auto writeResult = writeFuture.get();
  ASSERT_TRUE(writeResult.is_good());
  ASSERT_EQ(writeResult.value().results().size(), 1u);
  ASSERT_TRUE(writeResult.value().results()[0].is_good());

  // Poll (bounded) until the written value is delivered through the pipeline. The pump auto-runs on the
  // pool, so no manual publish is needed. An initial-value notification may arrive first; accept the one
  // matching the written value.
  bool received = false;
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& value : sink->snapshot())
    {
      if (value.value().is_int32() && value.value().as<std::int32_t>() == writtenValue)
      {
        received = true;
        break;
      }
    }
    if (received)
    {
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(received) << "data-change notification for the written value was never delivered";

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);
}

// ---------------------------------------------------------------------------
// A Subscription + monitored item created through the orchestrator can be torn
// down again via DeleteMonitoredItems + DeleteSubscriptions (section 8.4).
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplSubscription, SubscriptionAndMonitoredItemLifecycleDelete)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_SUB_DELETE"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto subResult = create_subscription_and_wait(*connection, 100.0);
  ASSERT_TRUE(subResult.is_good());
  const std::uint32_t subscriptionId = subResult.value();

  std::promise<Result<std::uint32_t>> miPromise;
  auto miFuture = miPromise.get_future();
  connection->create_monitored_item_async(
    subscriptionId,
    mWritableVariableId,
    /*clientHandle=*/1,
    [](DataValue) {},
    [&miPromise](Result<std::uint32_t> result) { miPromise.set_value(std::move(result)); });
  auto miResult = miFuture.get();
  ASSERT_TRUE(miResult.is_good());
  const std::uint32_t monitoredItemId = miResult.value();

  // Delete the monitored item.
  std::promise<Result<DeleteMonitoredItemsResponse>> deleteMiPromise;
  auto deleteMiFuture = deleteMiPromise.get_future();
  connection->delete_monitored_item_async(subscriptionId,
    monitoredItemId,
    /*clientHandle=*/1,
    [&deleteMiPromise](Result<DeleteMonitoredItemsResponse> result)
    { deleteMiPromise.set_value(std::move(result)); });
  auto deleteMiResult = deleteMiFuture.get();
  ASSERT_TRUE(deleteMiResult.is_good())
    << "delete monitored item failed: 0x" << std::hex << deleteMiResult.status_code().as_uint32();
  ASSERT_EQ(deleteMiResult.value().results().size(), 1u);
  EXPECT_TRUE(deleteMiResult.value().results()[0].is_good());

  // Delete the subscription.
  std::promise<Result<DeleteSubscriptionsResponse>> deleteSubPromise;
  auto deleteSubFuture = deleteSubPromise.get_future();
  connection->delete_subscription_async(subscriptionId,
    [&deleteSubPromise](Result<DeleteSubscriptionsResponse> result)
    { deleteSubPromise.set_value(std::move(result)); });
  auto deleteSubResult = deleteSubFuture.get();
  ASSERT_TRUE(deleteSubResult.is_good())
    << "delete subscription failed: 0x" << std::hex << deleteSubResult.status_code().as_uint32();
  ASSERT_EQ(deleteSubResult.value().results().size(), 1u);
  EXPECT_TRUE(deleteSubResult.value().results()[0].is_good());

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// A subscription created through the orchestrator can have its parameters
// modified and its publishing mode toggled against a real server (section 8.4,
// CL-SUB-011 / CL-SUB-010).
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplSubscription, SubscriptionModifyAndSetPublishingMode)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_SUB_MODIFY"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto subResult = create_subscription_and_wait(*connection, 100.0);
  ASSERT_TRUE(subResult.is_good());
  const std::uint32_t subscriptionId = subResult.value();

  // Modify the publishing interval on the live subscription.
  std::promise<Result<ModifySubscriptionResponse>> modifyPromise;
  auto modifyFuture = modifyPromise.get_future();
  connection->modify_subscription_async(subscriptionId,
    /*publishingInterval=*/250.0,
    [&modifyPromise](Result<ModifySubscriptionResponse> result)
    { modifyPromise.set_value(std::move(result)); });
  auto modifyResult = modifyFuture.get();
  ASSERT_TRUE(modifyResult.is_good())
    << "modify subscription failed: 0x" << std::hex << modifyResult.status_code().as_uint32();
  EXPECT_GT(modifyResult.value().revised_publishing_interval(), 0.0);

  // Disable publishing on the live subscription.
  std::promise<Result<SetPublishingModeResponse>> setPromise;
  auto setFuture = setPromise.get_future();
  connection->set_publishing_mode_async(subscriptionId,
    /*publishingEnabled=*/false,
    [&setPromise](Result<SetPublishingModeResponse> result) { setPromise.set_value(std::move(result)); });
  auto setResult = setFuture.get();
  ASSERT_TRUE(setResult.is_good()) << "set publishing mode failed: 0x" << std::hex
                                   << setResult.status_code().as_uint32();
  ASSERT_EQ(setResult.value().results().size(), 1u);
  EXPECT_TRUE(setResult.value().results()[0].is_good());

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}
