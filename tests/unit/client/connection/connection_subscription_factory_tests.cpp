// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-1 ConnectionSubscriptionFactory leaf. The gone-connection paths assert the
// manufactured status and ErrorDetail source; the live paths drive a real ConnectionImpl over FakeSessionOps
// and prove that request fields and results cross the shim unchanged.

#include "fake_session_ops.h"

#include "async_test_runtime.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_connection_subscription_factory.h"
#include "ua_client_monitored_item.h"
#include "ua_create_subscription_response.h"
#include "ua_logger.h"
#include "ua_reconnect_policy.h"
#include "ua_result.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <utility>

namespace
{

using namespace std::chrono_literals;

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::MonitoredItemResult;
using ua::client::MonitorRequest;
using ua::client::Session;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionSubscriptionFactory;
using ua::client::detail::KeepAlivePolicy;
using ua::client::detail::SubscriptionCreated;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

class ConnectionSubscriptionFactoryTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;

  std::shared_ptr<ConnectionImpl> make_active_connection(const std::shared_ptr<FakeSessionOps>& session)
  {
    auto reopen = std::make_shared<FakeReopen>();
    ua::client::ReconnectPolicy policy;
    policy.backoff.base = 1ms;
    policy.backoff.max = 1ms;
    policy.backoff.jitterPct = 0.0;
    auto connection = ConnectionImplTestAccess::create_with_ops(mRuntime.executor(),
      session,
      ConnectionConfig{},
      ua::Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      policy,
      KeepAlivePolicy{/*interval=*/0ms, /*missedBeforeReconnect=*/3});

    std::promise<VoidResult> started;
    auto startedFuture = started.get_future();
    connection->start_async([&started](VoidResult result) mutable { started.set_value(std::move(result)); });
    EXPECT_TRUE(startedFuture.get().is_good());
    return connection;
  }

  static Result<SubscriptionCreated> create_and_wait(
    ConnectionSubscriptionFactory& factory, double interval, bool publishingEnabled)
  {
    std::promise<Result<SubscriptionCreated>> completed;
    auto future = completed.get_future();
    factory.create_subscription_managed_async(interval,
      publishingEnabled,
      [&completed](Result<SubscriptionCreated> result) mutable { completed.set_value(std::move(result)); });
    return future.get();
  }

  static MonitoredItemResult monitor_and_wait(
    ConnectionSubscriptionFactory& factory, std::uint32_t subscriptionId, MonitorRequest request)
  {
    std::promise<MonitoredItemResult> completed;
    auto future = completed.get_future();
    factory.monitor_data_change_async(
      subscriptionId,
      std::move(request),
      [](ua::client::DataChangeEvent) {},
      [&completed](MonitoredItemResult result) mutable { completed.set_value(std::move(result)); });
    return future.get();
  }
};

TEST_F(ConnectionSubscriptionFactoryTest, CreateWhenConnectionGoneCarriesSourceTaggedError)
{
  auto factory = ConnectionSubscriptionFactory::create({});

  const auto result = create_and_wait(*factory, 250.0, true);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadConnectionClosed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.subscription_factory.connection_gone");
}

TEST_F(ConnectionSubscriptionFactoryTest, MonitorWhenConnectionGoneCarriesSourceTaggedError)
{
  auto factory = ConnectionSubscriptionFactory::create({});
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 42};

  const auto result = monitor_and_wait(*factory, 7, std::move(request));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadConnectionClosed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.subscription_factory.connection_gone");
}

TEST_F(ConnectionSubscriptionFactoryTest, LiveCreateForwardsRequestAndResult)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->publish.set_hold(true);
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 73;
  response.revised_publishing_interval() = 275.0;
  response.revised_lifetime_count() = 300;
  response.revised_max_keep_alive_count() = 10;
  session->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});
  auto connection = make_active_connection(session);
  auto factory = ConnectionSubscriptionFactory::create(connection);

  const auto result = create_and_wait(*factory, 250.0, false);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().subscriptionId, 73u);
  EXPECT_EQ(result.value().revisedPublishingInterval, 275.0);
  EXPECT_FALSE(result.value().publishingEnabled);
  ASSERT_EQ(session->createSubscription.call_count(), 1u);
  const auto requests = session->createSubscription.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].requested_publishing_interval(), 250.0);
  EXPECT_FALSE(requests[0].publishing_enabled());
}

TEST_F(ConnectionSubscriptionFactoryTest, LiveMonitorForwardsRequestAndReturnsMonitoredItem)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->publish.set_hold(true);
  ua::CreateSubscriptionResponse subscriptionResponse;
  subscriptionResponse.subscription_id() = 73;
  subscriptionResponse.revised_publishing_interval() = 250.0;
  subscriptionResponse.revised_lifetime_count() = 300;
  subscriptionResponse.revised_max_keep_alive_count() = 10;
  session->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{std::move(subscriptionResponse)});
  auto connection = make_active_connection(session);
  auto factory = ConnectionSubscriptionFactory::create(connection);
  ASSERT_TRUE(create_and_wait(*factory, 250.0, true).is_good());

  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 42};
  request.samplingIntervalMs = 125.0;
  request.queueSize = 9;

  const auto result = monitor_and_wait(*factory, 73, std::move(request));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(session->createMonitoredItems.call_count(), 1u);
  const auto requests = session->createMonitoredItems.requests();
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].subscription_id(), 73u);
  ASSERT_EQ(requests[0].items_to_create().size(), 1u);
  EXPECT_EQ(requests[0].items_to_create()[0].item_to_monitor().node_id(), ua::NodeId(2, 42));
  EXPECT_EQ(requests[0].items_to_create()[0].requested_parameters().sampling_interval(), 125.0);
  EXPECT_EQ(requests[0].items_to_create()[0].requested_parameters().queue_size(), 9u);
}

}  // namespace

// A session-CHANGED reconnect recreates each Subscription under a NEW server id, and the connection
// re-keys the pipeline, the retained tuning, the monitored-item owner routing and the event
// subscriber's trackers. The PUBLIC handle used to be the one thing left behind: SubscriptionImpl is
// owned by the handle and the connection held no reference to it, so a handle the application kept
// across the outage carried the dead id, and every operation routed through it - modify, set
// publishing mode, add a monitored item, delete, condition refresh - came back
// Bad_SubscriptionIdInvalid, while notifications arrived normally because those route through the
// pipeline, which WAS re-keyed. The book documented that as a defect and told readers to throw the
// handle away and make a new one.
//
// SCOPE, stated rather than implied. This drives the re-key interface directly, because the suite has no
// harness that can force a real drop-and-recreate - the subscription-modify matrix records the same
// limitation as RECONNECT-HARNESS-BLOCKED. So this arm proves the mechanism carries a live handle
// forward and prunes a dead one; it does NOT prove the commit site calls it. That call sits beside
// the four re-keys it accompanies in reconnect_commit and is covered by inspection only until a
// reconnect harness exists.
// @relation(AC-COMP-SDK-POST-SUBSCRIPTION-REKEY, scope=function)
TEST_F(ConnectionSubscriptionFactoryTest, RecreateRekeysLiveSubscriptionHandlesAndPrunesDeadOnes)
{
  auto session = std::make_shared<FakeSessionOps>();
  session->publish.set_hold(true);
  ua::CreateSubscriptionResponse response;
  response.subscription_id() = 41;
  response.revised_publishing_interval() = 500.0;
  session->createSubscription.set_result(Result<ua::CreateSubscriptionResponse>{std::move(response)});
  auto connection = make_active_connection(session);
  auto factory = ConnectionSubscriptionFactory::create(connection);

  const auto created = create_and_wait(*factory, 500.0, true);
  ASSERT_TRUE(created.is_good());
  ASSERT_EQ(created.value().subscriptionId, 41u);

  // Build the public handle through the same interface the connection machinery uses, which is what
  // registers its id cell with the connection.
  auto handle = ua::client::detail::SubscriptionFactory::create(connection, 41u, 500.0, true);
  ASSERT_EQ(handle.server_subscription_id(), 41u);

  // A second handle destroyed before the re-key: its cell must be pruned, not dereferenced.
  {
    auto doomed = ua::client::detail::SubscriptionFactory::create(connection, 42u, 500.0, true);
    ASSERT_EQ(doomed.server_subscription_id(), 42u);
  }

  connection->rekey_subscription_id_cells(41u, 9001u);

  // The live handle now addresses the recreated Subscription.
  EXPECT_EQ(handle.server_subscription_id(), 9001u);

  // A re-key naming an id this handle does not carry leaves it alone. Without the
  // compare-exchange this would overwrite every registered cell with the last new id.
  connection->rekey_subscription_id_cells(42u, 9002u);
  EXPECT_EQ(handle.server_subscription_id(), 9001u);
}
