// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11a (Subscription) - CreateMonitoredItems cluster.
//
// Production: sdk/implementation/server/subscription/ua_subscription.cpp:798-1212.

#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_namespace.h"
#include "stubs.h"

#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_create_monitored_items_request.h"
#include "ua_monitored_item.h"
#include "ua_monitored_item_create_request.h"
#include "ua_namespace_monitoring.h"
#include "ua_server_configuration.h"
#include "ua_server_counters.h"
#include "ua_subscription.h"
#include <boost/asio/thread_pool.hpp>

#include "test_components.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;

class CreateMonitoredItemsPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<test_helpers::FakeNamespace> mFakeNs;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;
  std::shared_ptr<ServerSummaryCounters> mSummaryCounters;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;

  std::thread::id mTestThreadId;
  static constexpr uint16_t sFakeNsIndex = 2;

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mTestThreadId = std::this_thread::get_id();

    mFakeNs = test_helpers::FakeNamespace::create("urn:test:cmi-fake-ns");
    mAddressSpace.emplace(test_helpers::make_address_space_with_fake_namespace(mExecutor, mFakeNs));
    mSummaryCounters = std::make_shared<ServerSummaryCounters>();
    mCapabilities.minSupportedSampleRate = 0;
    mCapabilities.maxMonitoredItemsQueueSize = 1000u;

    mSubscription = Subscription::create(/*subscriptionId=*/
      1,
      /*publishingInterval=*/1'000'000.0,
      /*lifetimeCount=*/100,
      /*maxKeepAliveCount=*/3,
      /*maxNotificationsPerPublish=*/0,
      /*publishingEnabled=*/true,
      /*priority=*/0,
      mExecutor,
      [](IntegerId) {},
      [](IntegerId) {});
  }

  void TearDown() override
  {
    mSubscription.reset();
    mAddressSpace.reset();
    mFakeNs.reset();
    mSummaryCounters.reset();
    mThreadPool.join();
  }

  static MonitoredItemCreateRequest make_item(NodeId nodeId, uint32_t clientHandle = 100,
    uint16_t /*nsIndex*/ = sFakeNsIndex, double samplingInterval = 1000.0, uint32_t queueSize = 5)
  {
    MonitoredItemCreateRequest req;
    req.item_to_monitor().node_id() = std::move(nodeId);
    req.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.monitoring_mode() = MonitoringMode::Reporting;
    req.requested_parameters().client_handle() = clientHandle;
    req.requested_parameters().sampling_interval() = samplingInterval;
    req.requested_parameters().queue_size() = queueSize;
    req.requested_parameters().discard_oldest() = true;
    return req;
  }

  static CreateMonitoredItemsRequest make_request(std::vector<MonitoredItemCreateRequest> items)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& it : items)
      request.items_to_create().push_back(std::move(it));
    return request;
  }

  // Drive create_monitored_items_async without security/event-bus wiring.
  std::vector<MonitoredItemCreateResult> drive_create(
    CreateMonitoredItemsRequest request, std::shared_ptr<SessionSecurityContext> securityContext = nullptr)
  {
    std::promise<std::vector<MonitoredItemCreateResult>> p;
    auto fut = p.get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      std::move(securityContext),
      /*eventBus=*/std::weak_ptr<EventBus>{},
      mSummaryCounters,
      [&p](std::vector<MonitoredItemCreateResult> r) mutable { p.set_value(std::move(r)); });
    return fut.get();
  }
};

}  // namespace

// ===========================================================================
// CMI-C - Bad request parameters yield validation status.
// Source: ua_subscription.cpp:864-874.
// ===========================================================================
TEST_F(CreateMonitoredItemsPin, Phase1ValidateRejectsBadRequestParameters)
{
  // monitoring_mode = invalid value triggers validate_and_build_monitored_item rejection.
  auto badItem = make_item(NodeId{sFakeNsIndex, 100u});
  badItem.monitoring_mode() = static_cast<MonitoringMode>(99);

  auto results = drive_create(make_request({std::move(badItem)}));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_bad())
    << "validate_and_build_monitored_item failure must surface in result (cpp:868)";
  // No namespace dispatch happened.
  EXPECT_EQ(mFakeNs->pending_create_monitoring_count(), 0u);
}

// ===========================================================================
// CMI-G - Unknown namespace index -> all items in that group take BadNodeIdUnknown.
// Source: ua_subscription.cpp:954-965.
// ===========================================================================
TEST_F(CreateMonitoredItemsPin, Phase2NamespaceUnknownAllItemsInGroupTakeBadNodeIdUnknown)
{
  // Use a namespace index 99 that does NOT exist in the address space.
  auto item1 = make_item(NodeId{99, 100u});
  auto item2 = make_item(NodeId{99, 101u});
  auto results = drive_create(make_request({std::move(item1), std::move(item2)}));

  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadNodeIdUnknown}) << "cpp:961";
  EXPECT_EQ(results[1].status_code(), StatusCode{Status::BadNodeIdUnknown});
  EXPECT_EQ(mFakeNs->pending_create_monitoring_count(), 0u)
    << "unknown namespace must not park any create_monitoring";
}

// ===========================================================================
// CMI-Q - Threading affinity: callback fires on the subscription strand.
// Source: ua_subscription.cpp callback path. Drives a no-namespace request so the
// terminal callback fires synchronously after Phase 1.
// ===========================================================================
TEST_F(CreateMonitoredItemsPin, CompletionDeliversCallbackOnSubscriptionStrand)
{
  auto badItem = make_item(NodeId{sFakeNsIndex, 100u});
  badItem.monitoring_mode() = static_cast<MonitoringMode>(99);  // rejected at Phase 1

  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  mSubscription->create_monitored_items_async(make_request({std::move(badItem)}),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    mSummaryCounters,
    [&p](std::vector<MonitoredItemCreateResult>) mutable { p.set_value(std::this_thread::get_id()); });

  auto callbackTid = fut.get();
  EXPECT_NE(callbackTid, mTestThreadId)
    << "create completion must run on the subscription strand thread, not the test thread";
  EXPECT_NE(callbackTid, std::thread::id{});
}

}  // namespace ua::test::behaviour_pins
