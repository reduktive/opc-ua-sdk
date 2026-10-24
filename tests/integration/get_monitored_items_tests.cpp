// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for the GetMonitoredItems method (Part 5, Section 9.1).
///
/// Verifies the full client -> server -> session -> subscription flow:
///   - Returns correct server/client handle arrays for configured monitored items
///   - Returns BadSubscriptionIdInvalid for unknown subscriptions
///   - Returns empty arrays for a subscription with no monitored items
///   - Returns correct handles after partial deletion of monitored items

#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"

#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_method_id.h"
#include "ua_object_id.h"

#include <algorithm>

using namespace ua;
using namespace ua::client;

// ===========================================================================
// Helpers
// ===========================================================================

static uint32_t create_test_subscription(Session& session, double interval = 50.0)
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
  Session& session, uint32_t subId, const NodeId& nodeId, uint32_t clientHandle)
{
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = clientHandle;
  params.sampling_interval() = 50.0;
  params.queue_size() = 1;
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

/// Call GetMonitoredItems via the Call service and return the operation-level result.
static CallMethodResult call_get_monitored_items(Session& session, uint32_t subscriptionId)
{
  Array<Variant> args;
  args.push_back(Variant{subscriptionId});

  CallMethodRequest methodReq;
  methodReq.object_id() = NodeId{ObjectId::Server};
  methodReq.method_id() = NodeId{MethodId::Server_GetMonitoredItems};
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

// @relation(SVR-BASE-024, scope=function)
TEST_F(ComplianceWithNodes, GetMonitoredItems_ReturnsHandlesForConfiguredItems)
{
  auto subId = create_test_subscription(*mSession);

  // Create 3 monitored items with distinct client handles.
  struct Expected
  {
    uint32_t serverHandle;
    uint32_t clientHandle;
  };

  std::vector<Expected> expected;

  for (uint32_t ch = 100; ch <= 102; ++ch)
  {
    auto result = create_single_mi(*mSession, subId, mWritableVariableId, ch);
    ASSERT_TRUE(result.status_code().is_good()) << "0x" << std::hex << result.status_code().as_uint32();
    expected.push_back({static_cast<uint32_t>(result.monitored_item_id()), ch});
  }

  // Call GetMonitoredItems.
  auto callResult = call_get_monitored_items(*mSession, subId);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good())
    << "0x" << std::hex << callResult.status_code().as_uint32();

  ASSERT_EQ(callResult.output_arguments().size(), 2u);
  auto serverHandles = callResult.output_arguments()[0].as<Array<uint32_t>>();
  auto clientHandles = callResult.output_arguments()[1].as<Array<uint32_t>>();

  ASSERT_EQ(serverHandles.size(), expected.size());
  ASSERT_EQ(clientHandles.size(), expected.size());

  // The arrays are parallel - build pairs and sort both expected and actual for comparison.
  std::vector<std::pair<uint32_t, uint32_t>> actualPairs;
  for (size_t i = 0; i < serverHandles.size(); ++i)
  {
    actualPairs.emplace_back(serverHandles[i], clientHandles[i]);
  }

  std::vector<std::pair<uint32_t, uint32_t>> expectedPairs;
  for (auto& e : expected)
  {
    expectedPairs.emplace_back(e.serverHandle, e.clientHandle);
  }

  std::sort(actualPairs.begin(), actualPairs.end());
  std::sort(expectedPairs.begin(), expectedPairs.end());
  EXPECT_EQ(actualPairs, expectedPairs);
}

TEST_F(ComplianceWithNodes, GetMonitoredItems_BadSubscriptionIdInvalid)
{
  auto callResult = call_get_monitored_items(*mSession, 99999);
  EXPECT_THAT(callResult, ::ua::test_helpers::HasStatus(Status::BadSubscriptionIdInvalid));
}

TEST_F(ComplianceWithNodes, GetMonitoredItems_EmptySubscription)
{
  auto subId = create_test_subscription(*mSession);

  auto callResult = call_get_monitored_items(*mSession, subId);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good());
  ASSERT_EQ(callResult.output_arguments().size(), 2u);

  auto serverHandles = callResult.output_arguments()[0].as<Array<uint32_t>>();
  auto clientHandles = callResult.output_arguments()[1].as<Array<uint32_t>>();
  EXPECT_EQ(serverHandles.size(), 0u);
  EXPECT_EQ(clientHandles.size(), 0u);
}

TEST_F(ComplianceWithNodes, GetMonitoredItems_AfterDeleteReflectsRemainingItems)
{
  auto subId = create_test_subscription(*mSession);

  // Create 3 items.
  auto r1 = create_single_mi(*mSession, subId, mWritableVariableId, 10);
  auto r2 = create_single_mi(*mSession, subId, mWritableVariableId, 20);
  auto r3 = create_single_mi(*mSession, subId, mWritableVariableId, 30);
  ASSERT_TRUE(r1.status_code().is_good());
  ASSERT_TRUE(r2.status_code().is_good());
  ASSERT_TRUE(r3.status_code().is_good());

  // Delete the middle item.
  DeleteMonitoredItemsRequest delReq;
  delReq.subscription_id() = subId;
  delReq.monitored_item_ids().push_back(r2.monitored_item_id());
  auto delResp = mSession->monitored_items().delete_monitored_items_sync(std::move(delReq));
  ASSERT_EQ(delResp.results().size(), 1u);
  ASSERT_TRUE(delResp.results()[0].is_good());

  // GetMonitoredItems should return only the remaining 2 items.
  auto callResult = call_get_monitored_items(*mSession, subId);
  ASSERT_TRUE(StatusCode{callResult.status_code()}.is_good());
  ASSERT_EQ(callResult.output_arguments().size(), 2u);

  auto serverHandles = callResult.output_arguments()[0].as<Array<uint32_t>>();
  auto clientHandles = callResult.output_arguments()[1].as<Array<uint32_t>>();
  ASSERT_EQ(serverHandles.size(), 2u);
  ASSERT_EQ(clientHandles.size(), 2u);

  std::vector<std::pair<uint32_t, uint32_t>> actual;
  for (size_t i = 0; i < serverHandles.size(); ++i)
  {
    actual.emplace_back(serverHandles[i], clientHandles[i]);
  }
  std::sort(actual.begin(), actual.end());

  std::vector<std::pair<uint32_t, uint32_t>> expected = {
    {static_cast<uint32_t>(r1.monitored_item_id()), 10},
    {static_cast<uint32_t>(r3.monitored_item_id()), 30},
  };
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(actual, expected);
}

// Part 5 section 9.1 / Part 4 section 5.12: GetMonitoredItems is a Server-Object Method, so the
// SubscriptionId arrives as an ordinary input argument rather than through the Session-scoped Subscription
// service set. An implementation that resolves the id against a server-wide subscription registry - the
// natural way to write the handler - answers any authenticated caller and hands one Session's
// monitored-item handles to another. The check that the invoking Session owns the named Subscription
// is what makes the disclosure impossible; the client's own restraint is not a security control.
// @verifies AC-SVR-MI-GEN-095-GETMONITOREDITEMS-OWNING-SESSION
TEST_F(ComplianceWithNodes, GetMonitoredItems_RefusedForSubscriptionOwnedByAnotherSession)
{
  // The fixture Session owns a Subscription that actually carries monitored items - otherwise a
  // refusal would be indistinguishable from an empty answer.
  auto subId = create_test_subscription(*mSession);
  auto r1 = create_single_mi(*mSession, subId, mWritableVariableId, 501);
  auto r2 = create_single_mi(*mSession, subId, mWritableVariableId, 502);
  ASSERT_TRUE(r1.status_code().is_good()) << "0x" << std::hex << r1.status_code().as_uint32();
  ASSERT_TRUE(r2.status_code().is_good()) << "0x" << std::hex << r2.status_code().as_uint32();

  // A second, fully activated Session on its own channel - authenticated, but not the owner.
  auto channelB = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto sessionB = channelB.create_session_sync({.sessionName = "GetMIOtherSession"});
  sessionB.activate_sync();

  auto foreignResult = call_get_monitored_items(sessionB, subId);

  // Conjunct 1: the call is refused. The requirement permits either ownership StatusCode.
  EXPECT_TRUE(foreignResult.status_code().is_bad())
    << "GetMonitoredItems succeeded for a Subscription owned by another Session";
  EXPECT_TRUE(
    foreignResult.status_code().as_uint32() == StatusCode{Status::BadUserAccessDenied}.as_uint32() ||
    foreignResult.status_code().as_uint32() == StatusCode{Status::BadSubscriptionIdInvalid}.as_uint32())
    << "0x" << std::hex << foreignResult.status_code().as_uint32();

  // Conjunct 2: and no handle data reaches the non-owning caller.
  EXPECT_EQ(foreignResult.output_arguments().size(), 0u)
    << "a refused GetMonitoredItems still returned output arguments";

  (void)sessionB.try_close_sync();
  (void)channelB.try_close_sync();

  // The refusal must be scoped to the foreign Session, not a blanket failure: the owner still gets
  // its own handles back, which is also what proves there was something to disclose above.
  auto ownerResult = call_get_monitored_items(*mSession, subId);
  ASSERT_TRUE(ownerResult.status_code().is_good())
    << "0x" << std::hex << ownerResult.status_code().as_uint32();
  ASSERT_EQ(ownerResult.output_arguments().size(), 2u);

  auto ownerServerHandles = ownerResult.output_arguments()[0].as<Array<uint32_t>>();
  auto ownerClientHandles = ownerResult.output_arguments()[1].as<Array<uint32_t>>();
  ASSERT_EQ(ownerServerHandles.size(), 2u);
  ASSERT_EQ(ownerClientHandles.size(), 2u);

  std::vector<std::pair<uint32_t, uint32_t>> ownerPairs;
  for (size_t i = 0; i < ownerServerHandles.size(); ++i)
  {
    ownerPairs.emplace_back(ownerServerHandles[i], ownerClientHandles[i]);
  }
  std::sort(ownerPairs.begin(), ownerPairs.end());

  std::vector<std::pair<uint32_t, uint32_t>> ownerExpected = {
    {static_cast<uint32_t>(r1.monitored_item_id()), 501},
    {static_cast<uint32_t>(r2.monitored_item_id()), 502},
  };
  std::sort(ownerExpected.begin(), ownerExpected.end());
  EXPECT_EQ(ownerPairs, ownerExpected);
}
