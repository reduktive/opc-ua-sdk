// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for the SetSubscriptionDurable method (Part 4 section 5.13.9).
///
/// Mirrors the UACTT `Subscription Durable` conformance unit. Verifies the full
/// client -> server -> session -> subscription flow:
///   - Success returns a single output: RevisedLifetimeInHours (>= 1)
///   - lifetimeInHours = 0 is revised up to at least 1 hour
///   - Unknown subscription -> BadSubscriptionIdInvalid
///   - Subscription owned by another session -> BadUserAccessDenied
///   - Subscription that already has monitored items -> BadInvalidState
///   - A durable subscription accepts a large monitored-item queue (10,000)

#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"

#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_method_id.h"
#include "ua_object_id.h"

using namespace ua;
using namespace ua::client;

// ===========================================================================
// Helpers
// ===========================================================================

static uint32_t create_test_subscription(Session& session, double interval = 500.0)
{
  CreateSubscriptionRequest req;
  req.requested_publishing_interval() = interval;
  req.requested_lifetime_count() = 100;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  req.publishing_enabled() = true;
  req.priority() = 0;

  auto resp = session.subscriptions().create_subscription_sync(std::move(req));
  return resp.subscription_id();
}

static MonitoredItemCreateResult create_single_mi(
  Session& session, uint32_t subId, const NodeId& nodeId, uint32_t queueSize)
{
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 50.0;
  params.queue_size() = queueSize;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(rv);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = session.monitored_items().create_monitored_items_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

/// Call SetSubscriptionDurable via the Call service and return the operation-level result.
static CallMethodResult call_set_subscription_durable(
  Session& session, uint32_t subscriptionId, uint32_t lifetimeInHours)
{
  Array<Variant> args;
  args.push_back(Variant{subscriptionId});
  args.push_back(Variant{lifetimeInHours});

  CallMethodRequest methodReq;
  methodReq.object_id() = NodeId{ObjectId::Server};
  methodReq.method_id() = NodeId{MethodId::Server_SetSubscriptionDurable};
  methodReq.input_arguments() = std::move(args);

  CallRequest req;
  req.methods_to_call().push_back(std::move(methodReq));

  auto resp = session.methods().call_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  return std::move(resp.results()[0]);
}

// ===========================================================================
// Tests
// ===========================================================================

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_Success_ReturnsRevisedLifetimeHours)
{
  auto subId = create_test_subscription(*mSession);

  auto callResult = call_set_subscription_durable(*mSession, subId, 5);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good())
    << "0x" << std::hex << callResult.status_code().as_uint32();

  ASSERT_EQ(callResult.output_arguments().size(), 1u);
  EXPECT_EQ(callResult.output_arguments()[0].as<uint32_t>(), 5u);
}

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_ZeroLifetimeRevisedToAtLeastOneHour)
{
  auto subId = create_test_subscription(*mSession);

  auto callResult = call_set_subscription_durable(*mSession, subId, 0);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good());
  ASSERT_EQ(callResult.output_arguments().size(), 1u);
  EXPECT_GE(callResult.output_arguments()[0].as<uint32_t>(), 1u);
}

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_BadSubscriptionIdInvalid)
{
  auto callResult = call_set_subscription_durable(*mSession, 99999, 5);
  EXPECT_THAT(callResult, ::ua::test_helpers::HasStatus(Status::BadSubscriptionIdInvalid));
}

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_BadInvalidStateWhenMonitoredItemsPresent)
{
  auto subId = create_test_subscription(*mSession);
  auto miResult = create_single_mi(*mSession, subId, mWritableVariableId, 1);
  ASSERT_TRUE(miResult.status_code().is_good());

  auto callResult = call_set_subscription_durable(*mSession, subId, 5);
  EXPECT_THAT(callResult, ::ua::test_helpers::HasStatus(Status::BadInvalidState));
}

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_BadUserAccessDeniedFromOtherSession)
{
  // Subscription owned by the fixture session.
  auto subId = create_test_subscription(*mSession);

  // A second session on a separate channel must not be able to make it durable.
  auto channelB = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionB = channelB.create_session_sync({.sessionName = "DurableOtherSession"});
  sessionB.activate_sync();

  auto callResult = call_set_subscription_durable(sessionB, subId, 5);
  EXPECT_THAT(callResult, ::ua::test_helpers::HasStatus(Status::BadUserAccessDenied));

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();
}

TEST_F(ComplianceWithNodes, SetSubscriptionDurable_AllowsLargeMonitoredItemQueue)
{
  auto subId = create_test_subscription(*mSession);

  auto callResult = call_set_subscription_durable(*mSession, subId, 1);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good());

  // A non-durable subscription caps the queue at 1000; durable lifts it so a 10,000 buffer survives.
  auto miResult = create_single_mi(*mSession, subId, mWritableVariableId, 10000);
  ASSERT_TRUE(miResult.status_code().is_good()) << "0x" << std::hex << miResult.status_code().as_uint32();
  EXPECT_EQ(miResult.revised_queue_size(), 10000u);
}
