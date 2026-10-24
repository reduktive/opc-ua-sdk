// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "deferred_namespace.h"
#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_error_detail.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_default_namespace.h"
#include "ua_session_security.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

#include "access_control_test_support.h"

#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

using STA = SubscriptionTestAccess;

namespace
{

class ReplaySecurityContext final : public SessionSecurityContext
{
public:
  NodeId session_id() const override
  {
    return NodeId{1, 1u};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return endpointSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return userIdentity;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return accessIdentity;
  }

  std::shared_ptr<const EndpointSecurityContext> endpointSecurity{
    std::make_shared<EndpointSecurityContext>()};
  std::shared_ptr<const UserIdentity> userIdentity{std::make_shared<UserIdentity>()};
  std::shared_ptr<const AccessIdentity> accessIdentity;
};

class MonitoredItemServicesTest : public ::testing::Test
{
protected:
  struct DeferredMonitoredItem
  {
    std::shared_ptr<ua::test::DeferredNamespace> owningNamespace;
    NodeId nodeId;
    IntegerId monitoredItemId{0};
  };

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();

    mAddressSpace = AddressSpace::create("urn:test", mExecutor);
    mAddressSpace->create_node_sync(NodeId{0, 1000}, NodeClass::Variable);
    mAddressSpace->create_node_sync(NodeId{0, 1001}, NodeClass::Variable);
    mAddressSpace->create_node_sync(NodeId{0, 1002}, NodeClass::Variable);

    mSecurityContext = std::make_shared<ReplaySecurityContext>();
    mSecurityContext->accessIdentity = ua::test_helpers::configure_test_access(
      *mAddressSpace, mSecurityContext->userIdentity, mSecurityContext->endpointSecurity);
  }

  void TearDown() override
  {
    if (mSubscription)
    {
      STA::on_strand(*mSubscription, [](auto& subscription) { subscription.close(); });
    }
    mSubscription.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription =
      Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    mSubscription->configure_access_recheck(
      std::chrono::milliseconds{0}, mSecurityContext, mAddressSpace->weak(), {});
    STA::on_strand(*mSubscription, [](auto&) {});
    return mSubscription;
  }

  /// @p node is resolved by the caller on the test thread: this runs on the Subscription's strand, where
  /// a blocking lookup is refused.
  void grant_test_read_access(MonitoredItem& item, const NodeId& nodeId, NodeAccessor node)
  {
    item.accessControlNode = std::move(node);
    item.accessSecurityContext = mSecurityContext;
    item.accessAddressSpace = mAddressSpace->weak();
    const auto identity = mSecurityContext->access_identity();
    ASSERT_NE(identity, nullptr);
    item.accessSnapshot = MonitoredAccessSnapshot{identity->key(),
      AccessControl::Verdict{.subject = nodeId,
        .operation = AccessOperation::Read,
        .permitted = true,
        .mask = PermissionType{PermissionType::Bit::Read},
        .cause = StatusCode{Status::Good}}};
  }

  /// Add a test monitored item with the given mode and return its ID.
  IntegerId add_test_item(
    MonitoringMode mode = MonitoringMode::Reporting, uint32_t queueSize = 5, NodeId nodeId = NodeId{0, 1000})
  {
    auto node = mAddressSpace->try_find_node_sync(nodeId).value();
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->queueSize = queueSize;
        item->discardOldest = true;
        item->itemToMonitor.node_id() = nodeId;
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        item->namespaceIndex = 0;
        grant_test_read_access(*item, nodeId, node);
        return g.add_monitored_item(std::move(item));
      });
  }

  /// Enqueue a value directly into a monitored item.
  void enqueue_value(IntegerId itemId, int32_t value)
  {
    STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto* item = g.find_monitored_item(itemId);
        ASSERT_NE(item, nullptr);
        DataValue dv;
        dv.value() = Variant{value};
        dv.source_timestamp() = DateTime::now();
        item->enqueue_initial(std::move(dv));
      });
  }

  /// Call modify_monitored_items_async and block on the main test thread for
  /// the callback to fire. Tests previously called the private coroutine via
  /// SubscriptionTestAccess; that was retired by the 4.11b ModifyFlow flip.
  std::vector<MonitoredItemModifyResult> modify_blocking(ModifyMonitoredItemsRequest request)
  {
    std::promise<std::vector<MonitoredItemModifyResult>> p;
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [&p](std::vector<MonitoredItemModifyResult> results) { p.set_value(std::move(results)); });
    return p.get_future().get();
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

  DeferredMonitoredItem add_deferred_monitored_item(int32_t cachedValue)
  {
    auto owningNamespace =
      ua::test::DeferredNamespace::create("urn:test:set-monitoring-mode:deferred", mExecutor);
    const uint16_t namespaceIndex = mAddressSpace->add_namespace_sync(owningNamespace);
    const NodeId nodeId{namespaceIndex, uint32_t{1000}};
    if (!owningNamespace->create_node(nodeId, NodeClass::Variable))
      throw std::logic_error{"test namespace could not create the monitored Node"};

    const auto identity = mSecurityContext->access_identity();
    if (!identity)
      throw std::logic_error{"test Session has no access identity"};
    owningNamespace->grant(identity->key(), nodeId, ua::test_helpers::all_permissions());
    const IntegerId monitoredItemId = add_test_item(MonitoringMode::Reporting, 5, nodeId);
    STA::on_strand(*mSubscription,
      [&](auto& guard)
      {
        auto* item = guard.find_monitored_item(monitoredItemId);
        const DataValue retained{Variant{cachedValue}};
        item->lastSentValue = retained;
        item->lastUserIndependentValue = retained;
      });
    return DeferredMonitoredItem{std::move(owningNamespace), nodeId, monitoredItemId};
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<ReplaySecurityContext> mSecurityContext;
  std::shared_ptr<Subscription> mSubscription;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

// =============================================================================
// ModifyMonitoredItems tests
// =============================================================================

TEST_F(MonitoredItemServicesTest, ModifyExistingItemReturnsRevisedParams)
{
  auto sub = create_subscription();
  auto itemId = add_test_item();

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = itemId;
  modReq.requested_parameters().sampling_interval() = 500;
  modReq.requested_parameters().queue_size() = 10;
  modReq.requested_parameters().discard_oldest() = true;
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good());
  EXPECT_GT(results[0].revised_sampling_interval(), 0);
  EXPECT_EQ(results[0].revised_queue_size(), 10u);
}

TEST_F(MonitoredItemServicesTest, ModifyNonExistentItemReturnsBad)
{
  auto sub = create_subscription();

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = 999;
  modReq.requested_parameters().sampling_interval() = 500;
  modReq.requested_parameters().queue_size() = 5;
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(MonitoredItemServicesTest, ModifyReducesQueueSizeDiscardOldest)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting, 10);

  // Enqueue several values.
  for (int32_t v = 1; v <= 5; ++v)
  {
    enqueue_value(itemId, v);
  }

  // Verify queue has 5 entries.
  auto queueBefore = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      return item->queue.size();
    });
  EXPECT_EQ(queueBefore, 5u);

  // Modify to reduce queue size to 2 (discardOldest=true).
  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = itemId;
  modReq.requested_parameters().sampling_interval() = 1000;
  modReq.requested_parameters().queue_size() = 2;
  modReq.requested_parameters().discard_oldest() = true;
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good());
  EXPECT_EQ(results[0].revised_queue_size(), 2u);

  // Verify queue was trimmed to 2 from front (discardOldest).
  auto [queueAfter, lastValue] = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      Variant lv;
      if (!item->queue.empty())
      {
        lv = item->queue.back().value();
      }
      return std::make_pair(item->queue.size(), lv);
    });
  EXPECT_EQ(queueAfter, 2u);
  EXPECT_EQ(lastValue, Variant{int32_t{5}});  // Most recent value preserved.
}

TEST_F(MonitoredItemServicesTest, ModifyReducesQueueSizeDiscardNewest)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting, 10);

  // Enqueue several values.
  for (int32_t v = 1; v <= 5; ++v)
  {
    enqueue_value(itemId, v);
  }

  // Modify to reduce queue size to 2 (discardOldest=false -> discard newest).
  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = itemId;
  modReq.requested_parameters().sampling_interval() = 1000;
  modReq.requested_parameters().queue_size() = 2;
  modReq.requested_parameters().discard_oldest() = false;
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good());

  auto [queueAfter, firstValue] = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      Variant fv;
      if (!item->queue.empty())
      {
        fv = item->queue.front().value();
      }
      return std::make_pair(item->queue.size(), fv);
    });
  EXPECT_EQ(queueAfter, 2u);
  EXPECT_EQ(firstValue, Variant{int32_t{1}});  // Oldest values preserved.
}

TEST_F(MonitoredItemServicesTest, ModifyMixedResults)
{
  auto sub = create_subscription();
  auto validId = add_test_item();

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  // Item 0: valid
  MonitoredItemModifyRequest modReq0;
  modReq0.monitored_item_id() = validId;
  modReq0.requested_parameters().sampling_interval() = 500;
  modReq0.requested_parameters().queue_size() = 5;
  request.items_to_modify().push_back(std::move(modReq0));

  // Item 1: non-existent
  MonitoredItemModifyRequest modReq1;
  modReq1.monitored_item_id() = 999;
  modReq1.requested_parameters().sampling_interval() = 500;
  modReq1.requested_parameters().queue_size() = 5;
  request.items_to_modify().push_back(std::move(modReq1));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 2u);
  EXPECT_TRUE(results[0].status_code().is_good());
  EXPECT_EQ(results[1].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(MonitoredItemServicesTest, ModifyUpdatesFilter)
{
  auto sub = create_subscription();
  auto itemId = add_test_item();

  // Create a modify request with a DataChangeFilter.
  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = itemId;
  modReq.requested_parameters().sampling_interval() = 1000;
  modReq.requested_parameters().queue_size() = 5;
  modReq.requested_parameters().discard_oldest() = true;
  // No filter (use defaults) - just verify it succeeds.
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good());
}

// =============================================================================
// SetMonitoringMode tests
// =============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-014, scope=function)
TEST_F(MonitoredItemServicesTest, SetModeDisabledClearsQueue)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting);

  // Enqueue a value.
  enqueue_value(itemId, 42);

  // Verify queue has entries.
  auto queueBefore = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      return item->queue.size();
    });
  EXPECT_GT(queueBefore, 0u);

  // Set to Disabled.
  auto results = set_mode_blocking({itemId}, MonitoringMode::Disabled);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  // Verify queue cleared.
  auto queueAfter = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      return item->queue.size();
    });
  EXPECT_EQ(queueAfter, 0u);
}

// @relation(SVR-MI-GEN-014, scope=function)
TEST_F(MonitoredItemServicesTest, SetModeSamplingDoesNotClearQueue)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting);

  enqueue_value(itemId, 42);

  auto results = set_mode_blocking({itemId}, MonitoringMode::Sampling);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  // Queue should still have values.
  auto queueAfter = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      return item->queue.size();
    });
  EXPECT_GT(queueAfter, 0u);
}

// SVR-MI-GEN-060: re-enabling a previously Disabled item must report an initial value (the queue was
// cleared on Disable). Regression for CTT Monitor Queueing 005.
TEST_F(MonitoredItemServicesTest, SetModeReenableFromDisabledReportsInitialValue)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting);

  // Simulate a value the client was already sent (drain sets lastSentValue in the real flow).
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      const DataValue cachedValue{Variant{int32_t{42}}};
      item->lastSentValue = cachedValue;
      item->lastUserIndependentValue = cachedValue;
    });

  // Disable -> clears the live queue (SVR-MI-GEN-014).
  set_mode_blocking({itemId}, MonitoringMode::Disabled);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* itemDisabled = g.find_monitored_item(itemId);
      ASSERT_EQ(itemDisabled->queue.size(), 0u) << "Disable should clear the queue";
    });

  // Re-enable to Reporting -> must re-enqueue an initial value so the next Publish carries it.
  auto results = set_mode_blocking({itemId}, MonitoringMode::Reporting);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      ASSERT_TRUE(item->has_reportable_notifications())
        << "Re-enabling a Disabled item must yield an initial data change";
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.front().value(), Variant{int32_t{42}});
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-REAUTHORIZES, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-REAUTHORIZES
TEST_F(MonitoredItemServicesTest, SetModeReenableReauthorizesTheCachedValue)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting);

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto* item = guard.find_monitored_item(itemId);
      const DataValue cachedValue{Variant{int32_t{42}}};
      item->lastSentValue = cachedValue;
      item->lastUserIndependentValue = cachedValue;
    });

  set_mode_blocking({itemId}, MonitoringMode::Disabled);

  auto node = mAddressSpace->try_find_node_sync(NodeId{0, 1000}).value();
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Read);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  auto results = set_mode_blocking({itemId}, MonitoringMode::Reporting);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results.front(), StatusCode{Status::Good});
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(itemId);
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(item->queue.front().value().empty())
        << "the previously permitted value leaked after revocation";
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-ASYNC-MISS, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-ASYNC-MISS
TEST_F(MonitoredItemServicesTest, SetModeReenableWaitsForNonCachingPermissionResolution)
{
  auto sub = create_subscription();
  auto deferredItem = add_deferred_monitored_item(42);
  const auto disabled = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  const auto identity = mSecurityContext->access_identity();
  ASSERT_NE(identity, nullptr);
  deferredItem.owningNamespace->forget(identity->key(), deferredItem.nodeId);
  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::Read);
  deferredItem.owningNamespace->set_async_permissions(
    identity->key(), deferredItem.nodeId, deniedPermissions);
  deferredItem.owningNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  std::atomic<size_t> callbackCount{0};
  std::promise<std::vector<StatusCode>> completion;
  auto completed = completion.get_future();
  sub->set_monitoring_mode_async({deferredItem.monitoredItemId},
    MonitoringMode::Reporting,
    [&callbackCount, &completion](std::vector<StatusCode> results)
    {
      callbackCount.fetch_add(1, std::memory_order_relaxed);
      completion.set_value(std::move(results));
    });

  ASSERT_TRUE(deferredItem.owningNamespace->wait_for_pending_resolutions());
  EXPECT_EQ(completed.wait_for(20ms), std::future_status::timeout);
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(deferredItem.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->monitoringMode, MonitoringMode::Disabled);
      EXPECT_TRUE(item->queue.empty());
    });

  deferredItem.owningNamespace->complete_pending_resolutions();
  ASSERT_EQ(completed.wait_for(2s), std::future_status::ready);
  const auto results = completed.get();
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results.front(), StatusCode{Status::Good});
  deferredItem.owningNamespace->wait_idle();
  STA::on_strand(*sub, [](auto&) {});

  EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(deferredItem.owningNamespace->permission_questions(), 1u);
  const auto calls = deferredItem.owningNamespace->effective_permissions_calls();
  ASSERT_EQ(calls.size(), 1u);
  ASSERT_TRUE(calls.front().nodes.has_value());
  ASSERT_EQ(calls.front().nodes->size(), 1u);
  EXPECT_EQ(calls.front().nodes->front(), deferredItem.nodeId);

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(deferredItem.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->monitoringMode, MonitoringMode::Reporting);
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(item->queue.front().value().empty());
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-INFRASTRUCTURE-FAILS-CLOSED, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-INFRASTRUCTURE-FAILS-CLOSED
TEST_F(MonitoredItemServicesTest, SetModeReenableMissingContextFailsClosedRichly)
{
  auto sub = create_subscription();
  const IntegerId itemId = add_test_item(MonitoringMode::Reporting);
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto* item = guard.find_monitored_item(itemId);
      const DataValue retained{Variant{int32_t{45}}};
      item->lastSentValue = retained;
      item->lastUserIndependentValue = retained;
    });
  const auto disabled = set_mode_blocking({itemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  mSecurityContext.reset();
  const auto reenabled = set_mode_blocking({itemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  EXPECT_EQ(reenabled.front(), StatusCode{Status::Good});
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 1u);
      const auto& denied = item->queue.front();
      EXPECT_EQ(denied.status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(denied.value().empty());
      ASSERT_TRUE(denied.status().has_value());
      ASSERT_NE(denied.status()->shared_detail(), nullptr);
      EXPECT_EQ(denied.status()->shared_detail()->code, "SetMonitoringModeAuthorizationContextUnavailable");
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-INFRASTRUCTURE-FAILS-CLOSED, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-INFRASTRUCTURE-FAILS-CLOSED
TEST_F(MonitoredItemServicesTest, SetModeReenableMissingNodeFailsClosedRichly)
{
  auto sub = create_subscription();
  const NodeId nodeId{0, 1000};
  const IntegerId itemId = add_test_item(MonitoringMode::Reporting, 5, nodeId);
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto* item = guard.find_monitored_item(itemId);
      const DataValue retained{Variant{int32_t{46}}};
      item->lastSentValue = retained;
      item->lastUserIndependentValue = retained;
    });
  const auto disabled = set_mode_blocking({itemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(nodeId, false).is_good());

  const auto reenabled = set_mode_blocking({itemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  EXPECT_EQ(reenabled.front(), StatusCode{Status::Good});
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 1u);
      const auto& denied = item->queue.front();
      EXPECT_EQ(denied.status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(denied.value().empty());
      ASSERT_TRUE(denied.status().has_value());
      const auto detail = denied.status()->shared_detail();
      ASSERT_NE(detail, nullptr);
      EXPECT_EQ(detail->code, "SetMonitoringModeSubjectResolutionFailed");
      EXPECT_EQ(StatusCode{detail->innerStatus}, StatusCode{Status::BadNodeIdUnknown});
      ASSERT_NE(detail->cause, nullptr);
      EXPECT_EQ(detail->cause->code, "NodeNotFound");
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-SINGLE-FLIGHT, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-SINGLE-FLIGHT
TEST_F(MonitoredItemServicesTest, SetModeReenableRejectsConcurrentFlowWithoutReordering)
{
  auto sub = create_subscription();
  auto deferredItem = add_deferred_monitored_item(43);
  const auto disabled = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  const auto identity = mSecurityContext->access_identity();
  ASSERT_NE(identity, nullptr);
  deferredItem.owningNamespace->forget(identity->key(), deferredItem.nodeId);
  deferredItem.owningNamespace->set_async_permissions(
    identity->key(), deferredItem.nodeId, ua::test_helpers::all_permissions());
  deferredItem.owningNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  deferredItem.owningNamespace->set_duplicate_completion(true);

  std::atomic<size_t> callbackCount{0};
  std::promise<std::vector<StatusCode>> firstCompletion;
  auto firstCompleted = firstCompletion.get_future();
  sub->set_monitoring_mode_async({deferredItem.monitoredItemId},
    MonitoringMode::Reporting,
    [&callbackCount, &firstCompletion](std::vector<StatusCode> results)
    {
      const size_t invocation = callbackCount.fetch_add(1, std::memory_order_relaxed);
      if (invocation == 0)
        firstCompletion.set_value(std::move(results));
    });
  ASSERT_TRUE(deferredItem.owningNamespace->wait_for_pending_resolutions());

  const auto secondResults = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Reporting);
  ASSERT_EQ(secondResults.size(), 1u);
  EXPECT_EQ(secondResults.front(), StatusCode{Status::BadInvalidState});
  EXPECT_EQ(
    STA::on_strand(*sub,
      [&](auto& guard) { return guard.find_monitored_item(deferredItem.monitoredItemId)->monitoringMode; }),
    MonitoringMode::Disabled);

  deferredItem.owningNamespace->complete_pending_resolutions();
  ASSERT_EQ(firstCompleted.wait_for(2s), std::future_status::ready);
  const auto firstResults = firstCompleted.get();
  ASSERT_EQ(firstResults.size(), 1u);
  EXPECT_EQ(firstResults.front(), StatusCode{Status::Good});
  deferredItem.owningNamespace->wait_idle();
  STA::on_strand(*sub, [](auto&) {});

  EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* item = guard.find_monitored_item(deferredItem.monitoredItemId);
      ASSERT_NE(item, nullptr);
      EXPECT_EQ(item->monitoringMode, MonitoringMode::Reporting);
      ASSERT_EQ(item->queue.size(), 1u);
      EXPECT_EQ(item->queue.front().value(), Variant{int32_t{43}});
    });
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-SINGLE-FLIGHT, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-SINGLE-FLIGHT
TEST_F(MonitoredItemServicesTest, SetModeReenableRejectsOverlappingAccessRefresh)
{
  auto sub = create_subscription();
  auto deferredItem = add_deferred_monitored_item(47);
  const auto disabled = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  const auto identity = mSecurityContext->access_identity();
  ASSERT_NE(identity, nullptr);
  deferredItem.owningNamespace->forget(identity->key(), deferredItem.nodeId);
  deferredItem.owningNamespace->set_async_permissions(
    identity->key(), deferredItem.nodeId, ua::test_helpers::all_permissions());
  deferredItem.owningNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);

  std::promise<VoidResult> refreshCompletion;
  auto refreshed = refreshCompletion.get_future();
  sub->reauthorize_all_async(
    [&refreshCompletion](VoidResult result) { refreshCompletion.set_value(std::move(result)); });
  ASSERT_TRUE(deferredItem.owningNamespace->wait_for_pending_resolutions());

  const auto reenabled = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Reporting);
  ASSERT_EQ(reenabled.size(), 1u);
  EXPECT_EQ(reenabled.front(), StatusCode{Status::BadInvalidState});
  EXPECT_NE(reenabled.front().shared_detail(), nullptr);
  EXPECT_EQ(
    STA::on_strand(*sub,
      [&](auto& guard) { return guard.find_monitored_item(deferredItem.monitoredItemId)->monitoringMode; }),
    MonitoringMode::Disabled);

  deferredItem.owningNamespace->complete_pending_resolutions();
  ASSERT_EQ(refreshed.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(refreshed.get().is_good());
  deferredItem.owningNamespace->wait_idle();
}

// @relation(AC-SVR-AUTHZ-016-REENABLE-CLOSE-LIFETIME, scope=function)
// @verifies AC-SVR-AUTHZ-016-REENABLE-CLOSE-LIFETIME
TEST_F(MonitoredItemServicesTest, SetModeReenableCloseCompletesOnceAndRejectsLatePermissionResult)
{
  auto sub = create_subscription();
  auto deferredItem = add_deferred_monitored_item(44);
  const auto disabled = set_mode_blocking({deferredItem.monitoredItemId}, MonitoringMode::Disabled);
  ASSERT_EQ(disabled.size(), 1u);
  ASSERT_EQ(disabled.front(), StatusCode{Status::Good});

  const auto identity = mSecurityContext->access_identity();
  ASSERT_NE(identity, nullptr);
  deferredItem.owningNamespace->forget(identity->key(), deferredItem.nodeId);
  deferredItem.owningNamespace->set_async_permissions(
    identity->key(), deferredItem.nodeId, ua::test_helpers::all_permissions());
  deferredItem.owningNamespace->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  deferredItem.owningNamespace->set_duplicate_completion(true);

  std::atomic<size_t> callbackCount{0};
  std::promise<std::vector<StatusCode>> completion;
  auto completed = completion.get_future();
  sub->set_monitoring_mode_async({deferredItem.monitoredItemId},
    MonitoringMode::Reporting,
    [&callbackCount, &completion](std::vector<StatusCode> results)
    {
      const size_t invocation = callbackCount.fetch_add(1, std::memory_order_relaxed);
      if (invocation == 0)
        completion.set_value(std::move(results));
    });
  ASSERT_TRUE(deferredItem.owningNamespace->wait_for_pending_resolutions());

  std::promise<void> closeCompletion;
  auto closed = closeCompletion.get_future();
  sub->close_async([&closeCompletion] { closeCompletion.set_value(); });
  ASSERT_EQ(closed.wait_for(2s), std::future_status::ready);
  ASSERT_EQ(completed.wait_for(2s), std::future_status::ready);
  const auto results = completed.get();
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results.front(), StatusCode{Status::BadSubscriptionIdInvalid});

  deferredItem.owningNamespace->complete_pending_resolutions();
  deferredItem.owningNamespace->wait_idle();
  STA::on_strand(*sub, [](auto&) {});
  EXPECT_EQ(callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_TRUE(STA::on_strand(*sub, [](auto& guard) { return guard.monitored_items().empty(); }));
}

// @relation(AC-SVR-AUTHZ-016-RESEND-REAUTHORIZES, scope=function)
// @verifies AC-SVR-AUTHZ-016-RESEND-REAUTHORIZES
TEST_F(MonitoredItemServicesTest, ResendInitialValuesReauthorizesEveryCachedValue)
{
  auto sub = create_subscription();
  const auto deniedId = add_test_item(MonitoringMode::Reporting, 5, NodeId{0, 1000});
  const auto allowedId = add_test_item(MonitoringMode::Reporting, 5, NodeId{0, 1001});

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      DataValue deniedValue{Variant{int32_t{41}}};
      deniedValue.status() = StatusCode{Status::Good};
      guard.find_monitored_item(deniedId)->lastSentValue = deniedValue;
      guard.find_monitored_item(deniedId)->lastUserIndependentValue = std::move(deniedValue);

      DataValue allowedValue{Variant{int32_t{42}}};
      allowedValue.status() = StatusCode{Status::Good};
      guard.find_monitored_item(allowedId)->lastSentValue = allowedValue;
      guard.find_monitored_item(allowedId)->lastUserIndependentValue = std::move(allowedValue);
    });

  auto deniedNode = mAddressSpace->try_find_node_sync(NodeId{0, 1000}).value();
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Read);
  ua::test_helpers::set_test_node_permissions(deniedNode, permissions);

  sub->configure_access_recheck(
    std::chrono::milliseconds{0}, mSecurityContext, mAddressSpace->weak(), std::weak_ptr<EventBus>{});
  std::promise<VoidResult> completion;
  auto completed = completion.get_future();
  sub->resend_initial_values_async(
    [&completion](VoidResult result) { completion.set_value(std::move(result)); });
  ASSERT_EQ(completed.wait_for(std::chrono::seconds{2}), std::future_status::ready);
  EXPECT_TRUE(completed.get().is_good());

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      const auto* denied = guard.find_monitored_item(deniedId);
      ASSERT_EQ(denied->queue.size(), 1u);
      EXPECT_EQ(denied->queue.front().status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(denied->queue.front().value().empty()) << "the revoked cached value leaked";

      const auto* allowed = guard.find_monitored_item(allowedId);
      ASSERT_EQ(allowed->queue.size(), 1u);
      EXPECT_EQ(allowed->queue.front().status(), StatusCode{Status::Good});
      EXPECT_EQ(allowed->queue.front().value(), Variant{int32_t{42}});
    });
}

TEST_F(MonitoredItemServicesTest, SetModeNonExistentItemReturnsBad)
{
  auto sub = create_subscription();

  auto results = set_mode_blocking({IntegerId{999}}, MonitoringMode::Reporting);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(MonitoredItemServicesTest, SetModeMixedResults)
{
  auto sub = create_subscription();
  auto validId = add_test_item(MonitoringMode::Reporting);

  std::vector<IntegerId> ids{validId, IntegerId{999}};
  auto results = set_mode_blocking(std::move(ids), MonitoringMode::Sampling);

  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});
  EXPECT_EQ(results[1], StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(MonitoredItemServicesTest, SetModeSameModeSameIsNoop)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting);

  enqueue_value(itemId, 42);

  auto results = set_mode_blocking({itemId}, MonitoringMode::Reporting);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  // Queue should be unchanged.
  auto queueAfter = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      return item->queue.size();
    });
  EXPECT_GT(queueAfter, 0u);
}

// =============================================================================
// SetTriggering tests
// =============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-080, scope=function)
TEST_F(MonitoredItemServicesTest, SetTriggeringAddValidLink)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item();
  auto triggeredId = add_test_item();

  auto result = STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{});
    });

  EXPECT_TRUE(result.removeResults.empty());
  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::Good});
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-080, SVR-MI-GEN-106, scope=function)
TEST_F(MonitoredItemServicesTest, SetTriggeringAddNonExistentTriggeredItem)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item();

  auto result = STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{IntegerId{999}}, std::vector<IntegerId>{});
    });

  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-088, scope=function)
TEST_F(MonitoredItemServicesTest, SetTriggeringRemoveExistingLink)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item();
  auto triggeredId = add_test_item();

  // Add the link first.
  STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{});
    });

  // Remove the link.
  auto result = STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{}, std::vector<IntegerId>{triggeredId});
    });

  ASSERT_EQ(result.removeResults.size(), 1u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::Good});
}

// @relation(SVR-MI-GEN-106, scope=function)
TEST_F(MonitoredItemServicesTest, SetTriggeringRemoveNonExistentLink)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item();

  auto result = STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{}, std::vector<IntegerId>{IntegerId{999}});
    });

  ASSERT_EQ(result.removeResults.size(), 1u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(MonitoredItemServicesTest, SetTriggeringRemoveThenReAddSameLink)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item();
  auto triggeredId = add_test_item();

  // Add the link.
  STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{});
    });

  // Remove and re-add in single call (SVC-SetTrig-002: remove processed before add).
  auto result = STA::on_strand(*sub,
    [&](auto& g)
    {
      return g.set_triggering(
        triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{triggeredId});
    });

  ASSERT_EQ(result.removeResults.size(), 1u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::Good});

  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::Good});
}

// Covers SVR-MI-GEN-106 (coverage-audit retag).
// @relation(SVR-MI-GEN-080, scope=function)
TEST_F(MonitoredItemServicesTest, SetTriggeringNonExistentTriggeringItem)
{
  auto sub = create_subscription();
  auto triggeredId = add_test_item();

  auto result = STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(IntegerId{999}, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{});
    });

  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
  // Part 4 Table 79: an invalid triggeringItemId is a service-level failure - the pipeline turns this
  // flag into a ServiceFault carrying Bad_MonitoredItemIdInvalid.
  EXPECT_TRUE(result.triggeringItemInvalid);
}

// Part 4 section 5.12.5: SetTriggering operates inside a single Subscription. Publishing is per Subscription,
// so a link naming an item of another Subscription could never fire - there is no queue in this
// Subscription for it to enter. MonitoredItem ids are unique only per Subscription, so an
// implementation that resolves the id against a server-wide registry (or against the first
// Subscription that happens to own that id) accepts the link and records a relationship that is dead
// on arrival.
// @verifies AC-SVR-MI-GEN-080-TRIGGERING-SAME-SUBSCRIPTION
TEST_F(MonitoredItemServicesTest, TriggeringLinkToAnItemOfAnotherSubscriptionIsRefused)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item(MonitoringMode::Reporting);

  // A second Subscription, given two items so that its second id is one this Subscription does not
  // own (ids restart at 1 per Subscription).
  auto other =
    Subscription::create(2, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});

  auto addItemTo = [&](Subscription& target, MonitoringMode mode)
  {
    return STA::on_strand(target,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->queueSize = 5;
        item->discardOldest = true;
        item->itemToMonitor.node_id() = NodeId{0, 1001};
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        item->namespaceIndex = 0;
        return g.add_monitored_item(std::move(item));
      });
  };

  addItemTo(*other, MonitoringMode::Sampling);
  const auto foreignId = addItemTo(*other, MonitoringMode::Sampling);

  // Give the foreign item something queued, so that if a cross-Subscription link did fire it would be
  // visible as a reportable notification rather than silently inert.
  STA::on_strand(*other,
    [&](auto& g)
    {
      auto* foreign = g.find_monitored_item(foreignId);
      ASSERT_NE(foreign, nullptr);
      DataValue dv;
      dv.value() = Variant{int32_t{11}};
      dv.source_timestamp() = DateTime::now();
      foreign->enqueue_initial(std::move(dv));
    });

  // The target must genuinely be foreign, or the refusal proves nothing.
  const bool foreignIsUnknownHere =
    STA::on_strand(*sub, [&](auto& g) { return g.find_monitored_item(foreignId) == nullptr; });
  ASSERT_TRUE(foreignIsUnknownHere) << "the id under test must not also exist in this Subscription";

  auto result = STA::on_strand(*sub,
    [&](auto& g)
    { return g.set_triggering(triggeringId, std::vector<IntegerId>{foreignId}, std::vector<IntegerId>{}); });

  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
  EXPECT_FALSE(result.triggeringItemInvalid) << "the triggering item is local; only the target is foreign";

  // No cross-Subscription relationship was created: removing it now reports there was nothing there.
  auto removal = STA::on_strand(*sub,
    [&](auto& g)
    { return g.set_triggering(triggeringId, std::vector<IntegerId>{}, std::vector<IntegerId>{foreignId}); });
  ASSERT_EQ(removal.removeResults.size(), 1u);
  EXPECT_EQ(removal.removeResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});

  // ...and firing the triggering item leaves the foreign item untriggered in its own Subscription.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      DataValue dv;
      dv.value() = Variant{int32_t{7}};
      dv.source_timestamp() = DateTime::now();
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(triggeringId, std::move(dv));
      g.on_samples_received(std::move(samples));
    });

  STA::on_strand(*other,
    [&](auto& g)
    {
      auto* foreign = g.find_monitored_item(foreignId);
      ASSERT_NE(foreign, nullptr);
      EXPECT_FALSE(foreign->triggeredReportPending)
        << "no cross-Subscription triggering relationship may exist";
      EXPECT_FALSE(foreign->has_reportable_notifications())
        << "a Sampling-mode item in another Subscription must stay unreportable";
    });

  other.reset();  // destroy before the pool drain in TearDown
}

// =============================================================================
// Diagnostics policy and immediate application of Modify
// =============================================================================

// Part 4 section 5.12.2: the RequestHeader.returnDiagnostics supplied at CreateMonitoredItems is captured on
// the MonitoredItem and replaced by a later ModifyMonitoredItems; that per-item policy governs the
// DiagnosticInfo carried by subsequent Publish notifications. Every other header flag applies to its
// own request, so a plausible implementation reads it per call - but a Publish response carries no
// per-item context to read it from, so an item that never captured the mask can only ever emit the
// server default.
// @verifies AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY
TEST_F(MonitoredItemServicesTest, DiagnosticsPolicyFollowsTheMostRecentCreateOrModify)
{
  auto sub = create_subscription();

  // Service- and operation-level diagnostics requested at Create.
  constexpr uint32_t createMask = 0x0000003Fu;
  constexpr uint32_t laterMask = 0x0000000Au;

  CreateMonitoredItemsRequest createRequest;
  createRequest.request_header().return_diagnostics() = createMask;
  createRequest.subscription_id() = 1;
  createRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemCreateRequest itemReq;
  itemReq.item_to_monitor().node_id() = NodeId{0, 1000};
  itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  itemReq.monitoring_mode() = MonitoringMode::Reporting;
  itemReq.requested_parameters().client_handle() = 7;
  itemReq.requested_parameters().sampling_interval() = 1000;
  itemReq.requested_parameters().queue_size() = 5;
  itemReq.requested_parameters().discard_oldest() = true;
  createRequest.items_to_create().push_back(std::move(itemReq));

  std::promise<std::vector<MonitoredItemCreateResult>> created;
  sub->create_monitored_items_async(std::move(createRequest),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&created](std::vector<MonitoredItemCreateResult> results) { created.set_value(std::move(results)); });
  auto createResults = created.get_future().get();

  ASSERT_EQ(createResults.size(), 1u);
  ASSERT_TRUE(createResults[0].status_code().is_good());
  const auto itemId = createResults[0].monitored_item_id();

  uint32_t maskAfterCreate = 0;
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      maskAfterCreate = item->diagnosticInfoMask;
    });
  EXPECT_EQ(maskAfterCreate, createMask)
    << "the Create header's returnDiagnostics must be captured as the item's diagnostic policy";

  // Modify with the flag cleared - the item's policy must follow the Modify.
  ModifyMonitoredItemsRequest clearRequest;
  clearRequest.request_header().return_diagnostics() = 0u;
  clearRequest.subscription_id() = 1;
  clearRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest clearMod;
  clearMod.monitored_item_id() = itemId;
  clearMod.requested_parameters().client_handle() = 7;
  clearMod.requested_parameters().sampling_interval() = 1000;
  clearMod.requested_parameters().queue_size() = 5;
  clearMod.requested_parameters().discard_oldest() = true;
  clearRequest.items_to_modify().push_back(std::move(clearMod));

  auto clearResults = modify_blocking(std::move(clearRequest));
  ASSERT_EQ(clearResults.size(), 1u);
  ASSERT_TRUE(clearResults[0].status_code().is_good());

  uint32_t maskAfterClear = ~0u;
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      maskAfterClear = item->diagnosticInfoMask;
    });
  EXPECT_EQ(maskAfterClear, 0u) << "a Modify with the flag clear must replace the captured policy";

  // ...and a further Modify re-arms it, so the policy tracks the latest Create/Modify in both
  // directions rather than merely decaying to the default.
  ModifyMonitoredItemsRequest rearmRequest;
  rearmRequest.request_header().return_diagnostics() = laterMask;
  rearmRequest.subscription_id() = 1;
  rearmRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest rearmMod;
  rearmMod.monitored_item_id() = itemId;
  rearmMod.requested_parameters().client_handle() = 7;
  rearmMod.requested_parameters().sampling_interval() = 1000;
  rearmMod.requested_parameters().queue_size() = 5;
  rearmMod.requested_parameters().discard_oldest() = true;
  rearmRequest.items_to_modify().push_back(std::move(rearmMod));

  auto rearmResults = modify_blocking(std::move(rearmRequest));
  ASSERT_EQ(rearmResults.size(), 1u);
  ASSERT_TRUE(rearmResults[0].status_code().is_good());

  uint32_t maskAfterRearm = 0;
  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);
      maskAfterRearm = item->diagnosticInfoMask;
    });
  EXPECT_EQ(maskAfterRearm, laterMask) << "the most recent Modify governs the item's diagnostic policy";
}

// Part 4 section 5.12.3: modified parameters take effect as soon as practical, and at the latest within one
// further sampling/publishing cycle - never only on a delete-and-recreate. A plausible implementation
// stores the revised values on the item but keeps evaluating samples against the parameters it
// captured when the item was built, so the client sees the revised values echoed in the response while
// the old filter is still doing the filtering.
// @verifies AC-SVR-MI-GEN-098-MODIFY-IMMEDIATE
TEST_F(MonitoredItemServicesTest, ModifiedSamplingIntervalAndFilterGovernTheVeryNextSample)
{
  auto sub = create_subscription();
  auto itemId = add_test_item(MonitoringMode::Reporting, 5);

  // Baseline the deadband will be measured against.
  enqueue_value(itemId, 100);

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto dataChangeFilter = std::make_unique<DataChangeFilter>();
  dataChangeFilter->trigger() = DataChangeTrigger::StatusValue;
  dataChangeFilter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  dataChangeFilter->deadband_value() = 10.0;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = itemId;
  modReq.requested_parameters().sampling_interval() = 500;
  modReq.requested_parameters().queue_size() = 5;
  modReq.requested_parameters().discard_oldest() = true;
  modReq.requested_parameters().filter() = std::move(dataChangeFilter);
  request.items_to_modify().push_back(std::move(modReq));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  ASSERT_TRUE(results[0].status_code().is_good());
  EXPECT_GT(results[0].revised_sampling_interval(), 0);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(itemId);
      ASSERT_NE(item, nullptr);

      // The revised interval reported to the client is the one the item is running.
      EXPECT_DOUBLE_EQ(item->samplingInterval, results[0].revised_sampling_interval());
      EXPECT_GT(item->samplingInterval, 0.0);
      EXPECT_EQ(item->deadbandType, DeadbandType::Absolute);
      EXPECT_DOUBLE_EQ(item->deadbandValue, 10.0);

      // The new filter governs the next sample - no recreate and no further cycle needed.
      DataValue insideDeadband;
      insideDeadband.value() = Variant{int32_t{105}};
      insideDeadband.source_timestamp() = DateTime::now();
      EXPECT_FALSE(item->evaluate_and_enqueue(std::move(insideDeadband)))
        << "a change inside the newly-set deadband must already be filtered out";

      DataValue outsideDeadband;
      outsideDeadband.value() = Variant{int32_t{200}};
      outsideDeadband.source_timestamp() = DateTime::now();
      EXPECT_TRUE(item->evaluate_and_enqueue(std::move(outsideDeadband)))
        << "a change beyond the newly-set deadband must still be reported";
    });
}

// Part 4 section 5.12.3: shrinking queueSize discards the excess under the item's own discard policy - the
// same policy that governs runtime overflow (section 5.12.1.5), where the tail slot always carries the most
// recent value. A plausible implementation trims from a single end for both policies, which for a
// discardOldest=FALSE client throws away the newest value - exactly the one the tail slot exists to
// hold - while that client chose the policy to protect its earliest history.
// @verifies AC-SVR-MI-GEN-099-QUEUE-SHRINK
TEST_F(MonitoredItemServicesTest, ShrinkingAQueueDiscardsTheExcessUnderTheConfiguredDiscardPolicy)
{
  auto sub = create_subscription();
  auto discardOldestId = add_test_item(MonitoringMode::Reporting, 8);
  auto discardNewestId = add_test_item(MonitoringMode::Reporting, 8);

  for (int32_t v = 1; v <= 8; ++v)
  {
    enqueue_value(discardOldestId, v);
    enqueue_value(discardNewestId, v);
  }

  auto queueValues = [&](IntegerId id)
  {
    return STA::on_strand(*sub,
      [&](auto& g)
      {
        std::vector<Variant> values;
        auto* item = g.find_monitored_item(id);
        if (item != nullptr)
        {
          for (auto& queued : item->queue)
          {
            values.push_back(queued.value());
          }
        }
        return values;
      });
  };

  ASSERT_EQ(queueValues(discardOldestId).size(), 8u) << "the queue must be full before the shrink";
  ASSERT_EQ(queueValues(discardNewestId).size(), 8u) << "the queue must be full before the shrink";

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest oldestMod;
  oldestMod.monitored_item_id() = discardOldestId;
  oldestMod.requested_parameters().sampling_interval() = 1000;
  oldestMod.requested_parameters().queue_size() = 3;
  oldestMod.requested_parameters().discard_oldest() = true;
  request.items_to_modify().push_back(std::move(oldestMod));

  MonitoredItemModifyRequest newestMod;
  newestMod.monitored_item_id() = discardNewestId;
  newestMod.requested_parameters().sampling_interval() = 1000;
  newestMod.requested_parameters().queue_size() = 3;
  newestMod.requested_parameters().discard_oldest() = false;
  request.items_to_modify().push_back(std::move(newestMod));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 2u);
  EXPECT_TRUE(results[0].status_code().is_good());
  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[0].revised_queue_size(), 3u);
  EXPECT_EQ(results[1].revised_queue_size(), 3u);

  // discardOldest=TRUE: the newest three survive.
  auto oldestQueue = queueValues(discardOldestId);
  ASSERT_EQ(oldestQueue.size(), 3u);
  EXPECT_EQ(oldestQueue[0], Variant{int32_t{6}});
  EXPECT_EQ(oldestQueue[1], Variant{int32_t{7}});
  EXPECT_EQ(oldestQueue[2], Variant{int32_t{8}});

  // discardOldest=FALSE: the oldest two survive plus the latest value, which the tail slot holds
  // under that policy.
  auto newestQueue = queueValues(discardNewestId);
  ASSERT_EQ(newestQueue.size(), 3u);
  EXPECT_EQ(newestQueue[0], Variant{int32_t{1}});
  EXPECT_EQ(newestQueue[1], Variant{int32_t{2}});
  EXPECT_EQ(newestQueue[2], Variant{int32_t{8}})
    << "discardOldest=FALSE discards the just-replaced tail, never the latest value";
}

// =============================================================================
// SetTriggering ordering and per-operation results
// =============================================================================

// Part 4 section 5.12.5: linksToRemove is processed before linksToAdd, which is how a client atomically
// replaces a link set. An item named in both lists must therefore be linked afterwards. Both orders
// return Good for both rows, so only the surviving state distinguishes them - an implementation that
// adds first and removes second leaves the link gone while reporting complete success.
// @verifies AC-SVR-MI-GEN-104-REMOVE-BEFORE-ADD
TEST_F(MonitoredItemServicesTest, SetTriggeringLeavesAnItemNamedInBothListsLinked)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item(MonitoringMode::Reporting);
  auto triggeredId = add_test_item(MonitoringMode::Sampling);

  // A Sampling-mode item with something queued is unreportable until it is triggered.
  enqueue_value(triggeredId, 55);

  STA::on_strand(*sub,
    [&](auto& g) {
      return g.set_triggering(triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{});
    });

  auto result = STA::on_strand(*sub,
    [&](auto& g)
    {
      return g.set_triggering(
        triggeringId, std::vector<IntegerId>{triggeredId}, std::vector<IntegerId>{triggeredId});
    });

  ASSERT_EQ(result.removeResults.size(), 1u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::Good});
  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::Good});

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* triggered = g.find_monitored_item(triggeredId);
      ASSERT_NE(triggered, nullptr);
      ASSERT_FALSE(triggered->triggeredReportPending) << "the item must not start out triggered";
    });

  // The link survives the call: firing the triggering item reports the linked one.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      DataValue dv;
      dv.value() = Variant{int32_t{9}};
      dv.source_timestamp() = DateTime::now();
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(triggeringId, std::move(dv));
      g.on_samples_received(std::move(samples));
    });

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* triggered = g.find_monitored_item(triggeredId);
      ASSERT_NE(triggered, nullptr);
      EXPECT_TRUE(triggered->triggeredReportPending)
        << "removes run before adds, so the re-added link must exist afterwards";
      EXPECT_TRUE(triggered->has_reportable_notifications());
    });
}

// Part 4 section 5.12.5.4: an unknown item to link is an operation-level failure reported in its own slot -
// the sibling rows are unaffected and keep their positions. A plausible implementation either aborts
// the batch at the first unknown id or compacts the results to the rows it processed, in both cases
// mis-attributing the failure and losing the link the client did ask for.
// @verifies AC-SVR-MI-GEN-106-SETTRIGGERING-OPERATION-CODE
TEST_F(MonitoredItemServicesTest, UnknownItemToLinkFailsInItsOwnSlotWithoutAffectingTheOthers)
{
  auto sub = create_subscription();
  auto triggeringId = add_test_item(MonitoringMode::Reporting);
  auto triggeredId = add_test_item(MonitoringMode::Sampling);

  enqueue_value(triggeredId, 33);

  // The unknown id is named FIRST, so a batch that aborts on failure never reaches the valid row.
  auto result = STA::on_strand(*sub,
    [&](auto& g)
    {
      return g.set_triggering(
        triggeringId, std::vector<IntegerId>{IntegerId{999}, triggeredId}, std::vector<IntegerId>{});
    });

  EXPECT_FALSE(result.triggeringItemInvalid) << "an unknown item to link is not a service-level failure";
  ASSERT_EQ(result.addResults.size(), 2u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
  EXPECT_EQ(result.addResults[1], StatusCode{Status::Good});

  // The valid link was really made, not merely reported Good.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      DataValue dv;
      dv.value() = Variant{int32_t{4}};
      dv.source_timestamp() = DateTime::now();
      std::vector<std::pair<IntegerId, DataValue>> samples;
      samples.emplace_back(triggeringId, std::move(dv));
      g.on_samples_received(std::move(samples));
    });

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto* triggered = g.find_monitored_item(triggeredId);
      ASSERT_NE(triggered, nullptr);
      EXPECT_TRUE(triggered->triggeredReportPending)
        << "the row that named an existing item must still have been linked";
      EXPECT_TRUE(triggered->has_reportable_notifications());
    });
}

// Part 4 section 5.12.2: the RequestHeader.returnDiagnostics supplied at CreateMonitoredItems is captured on
// the MonitoredItem, replaced by a later ModifyMonitoredItems, and is what governs the DiagnosticInfo
// carried by that item's subsequent Publish notifications - the Publish request header does not decide
// it. Every other header flag applies to its own request, so a plausible implementation reads the mask
// per call and stores nothing on the item; the give-away is that two items created under different
// Create headers then cannot differ, because there is only one per-request value to read and a Publish
// response carries no per-item context to read it from.
// @verifies AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY
TEST_F(MonitoredItemServicesTest, EachItemKeepsTheDiagnosticPolicyOfItsOwnLatestCreateOrModify)
{
  auto sub = create_subscription();

  // Three distinct masks, so no assertion below can pass on a coincidence with the server default.
  constexpr uint32_t firstMask = 0x0000003Fu;
  constexpr uint32_t secondMask = 0x00000001u;
  constexpr uint32_t replacementMask = 0x0000000Au;

  auto createItemWithDiagnostics = [&](uint32_t mask, const NodeId& nodeId, uint32_t clientHandle)
  {
    CreateMonitoredItemsRequest createRequest;
    createRequest.request_header().return_diagnostics() = mask;
    createRequest.subscription_id() = 1;
    createRequest.timestamps_to_return() = TimestampsToReturn::Both;

    MonitoredItemCreateRequest itemReq;
    itemReq.item_to_monitor().node_id() = nodeId;
    itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    itemReq.monitoring_mode() = MonitoringMode::Reporting;
    itemReq.requested_parameters().client_handle() = clientHandle;
    itemReq.requested_parameters().sampling_interval() = 1000;
    itemReq.requested_parameters().queue_size() = 5;
    itemReq.requested_parameters().discard_oldest() = true;
    createRequest.items_to_create().push_back(std::move(itemReq));

    std::promise<std::vector<MonitoredItemCreateResult>> created;
    sub->create_monitored_items_async(std::move(createRequest),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      nullptr,
      std::weak_ptr<EventBus>{},
      nullptr,
      [&created](std::vector<MonitoredItemCreateResult> results) { created.set_value(std::move(results)); });
    return created.get_future().get();
  };

  auto readPolicy = [&](IntegerId id, uint32_t& out)
  {
    STA::on_strand(*sub,
      [&](auto& g)
      {
        auto* item = g.find_monitored_item(id);
        ASSERT_NE(item, nullptr);
        out = item->diagnosticInfoMask;
      });
  };

  auto firstResults = createItemWithDiagnostics(firstMask, NodeId{0, 1000}, 7);
  ASSERT_EQ(firstResults.size(), 1u);
  ASSERT_TRUE(firstResults[0].status_code().is_good());
  const auto firstId = firstResults[0].monitored_item_id();

  auto secondResults = createItemWithDiagnostics(secondMask, NodeId{0, 1001}, 8);
  ASSERT_EQ(secondResults.size(), 1u);
  ASSERT_TRUE(secondResults[0].status_code().is_good());
  const auto secondId = secondResults[0].monitored_item_id();

  ASSERT_NE(firstId, secondId) << "the two items must be distinct for their policies to be compared";

  uint32_t firstPolicy = 0;
  uint32_t secondPolicy = 0;
  readPolicy(firstId, firstPolicy);
  readPolicy(secondId, secondPolicy);

  EXPECT_EQ(firstPolicy, firstMask)
    << "the Create header's returnDiagnostics must be captured as that item's diagnostic policy";
  EXPECT_EQ(secondPolicy, secondMask)
    << "the second Create header governs the second item, not the first item's mask";
  EXPECT_NE(firstPolicy, secondPolicy)
    << "two items created under different headers cannot share one diagnostic policy";

  // A Modify replaces the policy of the item it names - and only of that item.
  ModifyMonitoredItemsRequest modifyRequest;
  modifyRequest.request_header().return_diagnostics() = replacementMask;
  modifyRequest.subscription_id() = 1;
  modifyRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest modReq;
  modReq.monitored_item_id() = firstId;
  modReq.requested_parameters().client_handle() = 7;
  modReq.requested_parameters().sampling_interval() = 1000;
  modReq.requested_parameters().queue_size() = 5;
  modReq.requested_parameters().discard_oldest() = true;
  modifyRequest.items_to_modify().push_back(std::move(modReq));

  auto modifyResults = modify_blocking(std::move(modifyRequest));
  ASSERT_EQ(modifyResults.size(), 1u);
  ASSERT_TRUE(modifyResults[0].status_code().is_good());

  uint32_t firstPolicyAfterModify = 0;
  uint32_t secondPolicyAfterModify = 0;
  readPolicy(firstId, firstPolicyAfterModify);
  readPolicy(secondId, secondPolicyAfterModify);

  EXPECT_EQ(firstPolicyAfterModify, replacementMask)
    << "the most recent Modify governs the modified item's diagnostic policy";
  EXPECT_EQ(secondPolicyAfterModify, secondMask) << "an untouched item keeps the policy from its own Create";
}

// Part 4 section 5.12.3: shrinking queueSize discards the over-cap notifications under the item's own
// discardOldest policy - the same policy that governs runtime overflow (section 5.12.1.5), where under
// discardOldest=FALSE the tail slot is the one replaced and therefore always holds the most recent
// value. A plausible implementation trims from a single end for both policies, which under
// discardOldest=FALSE throws the newest value away, so a queue shrunk to N ends up holding something a
// queue that had always been N under the identical sample stream would never hold.
// @verifies AC-SVR-MI-GEN-099-QUEUE-SHRINK
TEST_F(MonitoredItemServicesTest, ShrinkingAQueueLeavesWhatTheSameDiscardPolicyLeavesOnOverflow)
{
  auto sub = create_subscription();

  auto addItem = [&](uint32_t queueSize, bool discardOldest)
  {
    auto node = mAddressSpace->try_find_node_sync(NodeId{0, 1000}).value();
    return STA::on_strand(*sub,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = MonitoringMode::Reporting;
        item->queueSize = queueSize;
        item->discardOldest = discardOldest;
        item->itemToMonitor.node_id() = NodeId{0, 1000};
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        item->namespaceIndex = 0;
        return g.add_monitored_item(std::move(item));
      });
  };

  auto queueValues = [&](IntegerId id)
  {
    return STA::on_strand(*sub,
      [&](auto& g)
      {
        std::vector<Variant> values;
        auto* item = g.find_monitored_item(id);
        if (item != nullptr)
        {
          for (auto& queued : item->queue)
          {
            values.push_back(queued.value());
          }
        }
        return values;
      });
  };

  // Reference items: born at the target size, so the surviving set is decided purely by the runtime
  // overflow path under each policy. The shrink must land on the same set.
  const auto referenceOldest = addItem(3, true);
  const auto referenceNewest = addItem(3, false);

  // Items that are shrunk from eight to three by ModifyMonitoredItems.
  const auto shrinkOldest = addItem(8, true);
  const auto shrinkNewest = addItem(8, false);

  for (int32_t v = 1; v <= 8; ++v)
  {
    enqueue_value(referenceOldest, v);
    enqueue_value(referenceNewest, v);
    enqueue_value(shrinkOldest, v);
    enqueue_value(shrinkNewest, v);
  }

  const auto expectedOldest = queueValues(referenceOldest);
  const auto expectedNewest = queueValues(referenceNewest);
  ASSERT_EQ(expectedOldest.size(), 3u) << "the discardOldest=TRUE reference must be capped at three";
  ASSERT_EQ(expectedNewest.size(), 3u) << "the discardOldest=FALSE reference must be capped at three";
  ASSERT_EQ(queueValues(shrinkOldest).size(), 8u) << "the queue must be full before the shrink";
  ASSERT_EQ(queueValues(shrinkNewest).size(), 8u) << "the queue must be full before the shrink";

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest oldestMod;
  oldestMod.monitored_item_id() = shrinkOldest;
  oldestMod.requested_parameters().sampling_interval() = 1000;
  oldestMod.requested_parameters().queue_size() = 3;
  oldestMod.requested_parameters().discard_oldest() = true;
  request.items_to_modify().push_back(std::move(oldestMod));

  MonitoredItemModifyRequest newestMod;
  newestMod.monitored_item_id() = shrinkNewest;
  newestMod.requested_parameters().sampling_interval() = 1000;
  newestMod.requested_parameters().queue_size() = 3;
  newestMod.requested_parameters().discard_oldest() = false;
  request.items_to_modify().push_back(std::move(newestMod));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 2u);
  ASSERT_TRUE(results[0].status_code().is_good());
  ASSERT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[0].revised_queue_size(), 3u);
  EXPECT_EQ(results[1].revised_queue_size(), 3u);

  // discardOldest=TRUE: the newest three survive.
  const auto shrunkOldestQueue = queueValues(shrinkOldest);
  ASSERT_EQ(shrunkOldestQueue.size(), 3u);
  EXPECT_EQ(shrunkOldestQueue[0], Variant{int32_t{6}});
  EXPECT_EQ(shrunkOldestQueue[1], Variant{int32_t{7}});
  EXPECT_EQ(shrunkOldestQueue[2], Variant{int32_t{8}});
  for (size_t i = 0; i < shrunkOldestQueue.size(); ++i)
  {
    EXPECT_EQ(shrunkOldestQueue[i], expectedOldest[i])
      << "the shrink must leave what runtime overflow under discardOldest=TRUE leaves, at index " << i;
  }

  // discardOldest=FALSE: the oldest two survive plus the latest value, which is what the replaced
  // tail slot holds under that policy.
  const auto shrunkNewestQueue = queueValues(shrinkNewest);
  ASSERT_EQ(shrunkNewestQueue.size(), 3u);
  EXPECT_EQ(shrunkNewestQueue[0], Variant{int32_t{1}});
  EXPECT_EQ(shrunkNewestQueue[1], Variant{int32_t{2}});
  EXPECT_EQ(shrunkNewestQueue[2], Variant{int32_t{8}})
    << "discardOldest=FALSE discards the just-replaced tail, never the latest value";
  for (size_t i = 0; i < shrunkNewestQueue.size(); ++i)
  {
    EXPECT_EQ(shrunkNewestQueue[i], expectedNewest[i])
      << "the shrink must leave what runtime overflow under discardOldest=FALSE leaves, at index " << i;
  }
}

// Part 4 section 5.12.2: the returnDiagnostics captured at Create (and replaced by a later Modify) is
// sticky per MonitoredItem. Subscription assembly is deliberately security-policy agnostic: it
// forwards a lazily allocated, item-aligned mask vector only when a drained status has ErrorDetail.
// SubscriptionsPipeline owns the later security-gated DiagnosticInfo projection into the response
// header's string-table domain. The two fulfill_publish calls below are identical, so only the
// item's captured policy distinguishes the observations.
//
// Table 165 permits an empty diagnosticInfos list when nothing is requested or available. The rich
// status closes the availability arm; this component test verifies the exact metadata handed to the
// observable pipeline test without doing string-table or security work on the Subscription strand.
// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST_F(MonitoredItemServicesTest, PublishAssemblyCarriesTheItemsLatestStickyDiagnosticMask)
{
  auto sub = create_subscription();

  // Every service- and operation-level diagnostic bit defined by the RequestHeader table.
  constexpr uint32_t allDiagnostics = 0x000003FFu;

  CreateMonitoredItemsRequest createRequest;
  createRequest.request_header().return_diagnostics() = allDiagnostics;
  createRequest.subscription_id() = 1;
  createRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemCreateRequest itemReq;
  itemReq.item_to_monitor().node_id() = NodeId{0, 1000};
  itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  itemReq.monitoring_mode() = MonitoringMode::Reporting;
  itemReq.requested_parameters().client_handle() = 7;
  itemReq.requested_parameters().sampling_interval() = 1000;
  itemReq.requested_parameters().queue_size() = 5;
  itemReq.requested_parameters().discard_oldest() = true;
  createRequest.items_to_create().push_back(std::move(itemReq));

  std::promise<std::vector<MonitoredItemCreateResult>> created;
  sub->create_monitored_items_async(std::move(createRequest),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&created](std::vector<MonitoredItemCreateResult> results) { created.set_value(std::move(results)); });
  auto createResults = created.get_future().get();

  ASSERT_EQ(createResults.size(), 1u);
  ASSERT_TRUE(createResults[0].status_code().is_good());
  const auto itemId = createResults[0].monitored_item_id();

  // Give the item something genuinely diagnostic to report: a Bad status carrying vendor detail, the
  // sole source a DiagnosticInfo can be built from.
  auto invalidate = [&]
  {
    STA::on_strand(*sub,
      [&](auto& g)
      {
        g.on_sample_invalidated(itemId,
          StatusCode{Status::BadNodeIdUnknown,
            make_error_detail("MonitoredNodeRemoved",
              "monitored node left the address space",
              "node id 0:1000 was deleted while the item was reporting",
              "test.subscription")});
      });
  };
  invalidate();
  // A second eligible notification proves lazy metadata growth remains aligned after the first
  // candidate has allocated the vector.
  invalidate();

  auto whileSet = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });

  ASSERT_EQ(whileSet.size(), 1u);
  ASSERT_EQ(whileSet[0].message.notification_data().size(), 1u)
    << "the queued sample must actually be published for its diagnostics to be observable";
  auto* setDcn = dynamic_cast<DataChangeNotification*>(whileSet[0].message.notification_data()[0].get());
  ASSERT_NE(setDcn, nullptr);
  ASSERT_FALSE(setDcn->monitored_items().empty());
  ASSERT_EQ(whileSet[0].dataChangeDiagnosticMasks.size(), setDcn->monitored_items().size());

  bool sawDiagnosableStatus = false;
  for (size_t index = 0; index < setDcn->monitored_items().size(); ++index)
  {
    const auto& notification = setDcn->monitored_items()[index];
    const auto& status = notification.value().status();
    if (status.has_value() && !status->is_good() && status->detail() != nullptr)
    {
      sawDiagnosableStatus = true;
      EXPECT_EQ(whileSet[0].dataChangeDiagnosticMasks[index], allDiagnostics);
    }
  }
  ASSERT_TRUE(sawDiagnosableStatus)
    << "the published notification must carry the Bad status and its detail, or there is nothing "
       "available to diagnose and an empty list would be permitted";

  EXPECT_TRUE(setDcn->diagnostic_infos().empty())
    << "Subscription assembly must leave security-gated projection to SubscriptionsPipeline";

  // A Modify with the flag clear replaces the captured policy.
  ModifyMonitoredItemsRequest clearRequest;
  clearRequest.request_header().return_diagnostics() = 0u;
  clearRequest.subscription_id() = 1;
  clearRequest.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest clearMod;
  clearMod.monitored_item_id() = itemId;
  clearMod.requested_parameters().client_handle() = 7;
  clearMod.requested_parameters().sampling_interval() = 1000;
  clearMod.requested_parameters().queue_size() = 5;
  clearMod.requested_parameters().discard_oldest() = true;
  clearRequest.items_to_modify().push_back(std::move(clearMod));

  auto clearResults = modify_blocking(std::move(clearRequest));
  ASSERT_EQ(clearResults.size(), 1u);
  ASSERT_TRUE(clearResults[0].status_code().is_good());

  // The same stimulus again - only the item's policy has changed.
  invalidate();

  auto whileClear = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });

  ASSERT_EQ(whileClear.size(), 1u);
  ASSERT_EQ(whileClear[0].message.notification_data().size(), 1u)
    << "the second sample must also be published, or the comparison is vacuous";
  auto* clearDcn = dynamic_cast<DataChangeNotification*>(whileClear[0].message.notification_data()[0].get());
  ASSERT_NE(clearDcn, nullptr);
  ASSERT_FALSE(clearDcn->monitored_items().empty());

  EXPECT_TRUE(whileClear[0].dataChangeDiagnosticMasks.empty());

  EXPECT_TRUE(clearDcn->diagnostic_infos().empty())
    << "after a Modify with the flag clear the item's notifications must carry no DiagnosticInfo";
}

// Part 4 section 5.12.3: the notifications that survive a queueSize shrink are the ones the item's
// discardOldest policy keeps - and it is the Publish response, not the internal queue, that the client
// judges that by. Under discardOldest=FALSE the tail slot is the one runtime overflow replaces, so it
// holds the most recent sample and the shrink must keep it; an implementation that trims from a single
// end for both policies publishes the oldest three and silently drops the latest value the client was
// waiting for. Publishing also proves the trim left the subscription's reportable bookkeeping intact,
// which an in-place queue inspection cannot see.
// @verifies AC-SVR-MI-GEN-099-QUEUE-SHRINK
TEST_F(MonitoredItemServicesTest, AShrunkQueuePublishesExactlyWhatItsDiscardPolicyKept)
{
  auto sub = create_subscription();

  constexpr IntegerId oldestHandle = 21;
  constexpr IntegerId newestHandle = 22;

  auto addItem = [&](uint32_t queueSize, bool discardOldest, IntegerId clientHandle)
  {
    auto node = mAddressSpace->try_find_node_sync(NodeId{0, 1000}).value();
    return STA::on_strand(*sub,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = MonitoringMode::Reporting;
        item->queueSize = queueSize;
        item->discardOldest = discardOldest;
        item->clientHandle = clientHandle;
        item->itemToMonitor.node_id() = NodeId{0, 1000};
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        item->namespaceIndex = 0;
        grant_test_read_access(*item, NodeId{0, 1000}, node);
        return g.add_monitored_item(std::move(item));
      });
  };

  const auto discardOldestId = addItem(8, true, oldestHandle);
  const auto discardNewestId = addItem(8, false, newestHandle);

  // Fill both queues through the sampling entry point, so the queues are built by the same path that
  // decides overflow rather than by the fixture.
  for (int32_t v = 1; v <= 8; ++v)
  {
    STA::on_strand(*sub,
      [&](auto& g)
      {
        DataValue toOldest;
        toOldest.value() = Variant{v};
        toOldest.source_timestamp() = DateTime::now();

        DataValue toNewest;
        toNewest.value() = Variant{v};
        toNewest.source_timestamp() = DateTime::now();

        std::vector<std::pair<IntegerId, DataValue>> samples;
        samples.emplace_back(discardOldestId, std::move(toOldest));
        samples.emplace_back(discardNewestId, std::move(toNewest));
        g.on_samples_received(std::move(samples));
      });
  }

  auto queueDepth = [&](IntegerId id)
  {
    return STA::on_strand(*sub,
      [&](auto& g)
      {
        auto* item = g.find_monitored_item(id);
        if (!item)
          return size_t{0};
        return item->queue.size();
      });
  };

  ASSERT_EQ(queueDepth(discardOldestId), 8u) << "the queue must be full before the shrink";
  ASSERT_EQ(queueDepth(discardNewestId), 8u) << "the queue must be full before the shrink";

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemModifyRequest oldestMod;
  oldestMod.monitored_item_id() = discardOldestId;
  oldestMod.requested_parameters().client_handle() = oldestHandle;
  oldestMod.requested_parameters().sampling_interval() = 1000;
  oldestMod.requested_parameters().queue_size() = 3;
  oldestMod.requested_parameters().discard_oldest() = true;
  request.items_to_modify().push_back(std::move(oldestMod));

  MonitoredItemModifyRequest newestMod;
  newestMod.monitored_item_id() = discardNewestId;
  newestMod.requested_parameters().client_handle() = newestHandle;
  newestMod.requested_parameters().sampling_interval() = 1000;
  newestMod.requested_parameters().queue_size() = 3;
  newestMod.requested_parameters().discard_oldest() = false;
  request.items_to_modify().push_back(std::move(newestMod));

  auto results = modify_blocking(std::move(request));

  ASSERT_EQ(results.size(), 2u);
  ASSERT_TRUE(results[0].status_code().is_good());
  ASSERT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[0].revised_queue_size(), 3u);
  EXPECT_EQ(results[1].revised_queue_size(), 3u);

  auto published = STA::on_strand(*sub,
    [&](auto& g)
    {
      g.set_publish_req_queued(true);
      return g.fulfill_publish(1);
    });

  ASSERT_EQ(published.size(), 1u);
  ASSERT_EQ(published[0].message.notification_data().size(), 1u)
    << "both shrunk items must still be reportable after the trim";
  auto* dcn = dynamic_cast<DataChangeNotification*>(published[0].message.notification_data()[0].get());
  ASSERT_NE(dcn, nullptr);
  ASSERT_FALSE(dcn->monitored_items().empty());

  std::vector<Variant> oldestPublished;
  std::vector<Variant> newestPublished;
  for (const auto& notification : dcn->monitored_items())
  {
    if (notification.client_handle() == oldestHandle)
    {
      oldestPublished.push_back(notification.value().value());
    }
    else if (notification.client_handle() == newestHandle)
    {
      newestPublished.push_back(notification.value().value());
    }
  }

  // discardOldest=TRUE: the newest three are published, in order.
  ASSERT_EQ(oldestPublished.size(), 3u) << "a shrink to three must publish exactly three notifications";
  EXPECT_EQ(oldestPublished[0], Variant{int32_t{6}});
  EXPECT_EQ(oldestPublished[1], Variant{int32_t{7}});
  EXPECT_EQ(oldestPublished[2], Variant{int32_t{8}});

  // discardOldest=FALSE: the oldest two are published plus the latest value, which is what the
  // replaced tail slot holds under that policy.
  ASSERT_EQ(newestPublished.size(), 3u) << "a shrink to three must publish exactly three notifications";
  EXPECT_EQ(newestPublished[0], Variant{int32_t{1}});
  EXPECT_EQ(newestPublished[1], Variant{int32_t{2}});
  EXPECT_EQ(newestPublished[2], Variant{int32_t{8}})
    << "discardOldest=FALSE discards the just-replaced tail, never the latest value";
}

}  // namespace
