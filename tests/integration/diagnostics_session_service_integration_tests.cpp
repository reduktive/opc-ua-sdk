// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Behavioural executable-spec for the per-session diagnostics counters (SessionDiagnosticsDataType:
/// the aggregate totalRequestCount plus one {count, errorCount} per Service), read via
/// `Server::session_health_snapshots()` (SessionHealthSnapshot, ua_server_health.h).
///
/// Companion to diagnostics_server_summary_integration_tests.cpp. Every test DRIVES a real Service
/// through the client and asserts the exact counter DELTA - it never `.store()`s a counter and reads
/// it back. A dispatched Service is counted regardless of whether it succeeds (Session::execute_service
/// increments totalCount at dispatch), so a minimal / failing request is enough to prove the writer:
/// if the counter does not move, that is a dead writer, not a wrong test.
///
/// Inert-by-design fields (documented in ua_server_counters.h) are asserted to STAY 0: the Query
/// counters (Query is unimplemented) and unauthorizedRequestCount (per-item authorization is not a
/// whole-request rejection).

#include "compliance_helpers.h"

#include "ua_server_health.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitoring_parameters.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include "ua_attribute_id.h"
#include "ua_monitoring_mode.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

using Clock = std::chrono::steady_clock;
using ServiceCount = SessionHealthSnapshot::ServiceCount;
using CountMember = ServiceCount SessionHealthSnapshot::*;

/// The snapshot for the single live compliance session ("ComplianceTest"). There is normally exactly
/// one session; fall back to the first entry.
std::optional<SessionHealthSnapshot> find_session(Server& server)
{
  auto snapshots = server.session_health_snapshots();
  for (const auto& s : snapshots)
  {
    if (s.sessionName == "ComplianceTest")
      return s;
  }
  if (!snapshots.empty())
    return snapshots.front();
  return std::nullopt;
}

/// Poll the session snapshot until `predicate` holds or `budget` elapses; return the final snapshot.
/// Counters lag the client call slightly (posted onto server strands), so a wired counter needs a
/// brief retry; a dead one exhausts the budget with no movement.
template<typename Predicate>
SessionHealthSnapshot wait_for_session(Server& server, Predicate predicate, std::chrono::milliseconds budget)
{
  auto snapshot = find_session(server);
  const auto deadline = Clock::now() + budget;
  while ((!snapshot.has_value() || !predicate(*snapshot)) && Clock::now() < deadline)
  {
    std::this_thread::sleep_for(20ms);
    snapshot = find_session(server);
  }
  return snapshot.value_or(SessionHealthSnapshot{});
}

}  // namespace

class SessionDiagnosticsFields : public ComplianceWithNodes
{
protected:
  /// Assert that running `drive` once increments exactly the per-service counter `member` by one.
  /// `drive` sends one request of that Service (minimal is fine - dispatch is what counts).
  void expect_dispatched(const char* name, CountMember member, const std::function<void()>& drive)
  {
    Server& server = mServer.server();
    auto before = find_session(server);
    ASSERT_TRUE(before.has_value()) << "no live session snapshot";
    const uint32_t baseline = (before.value().*member).total;

    drive();

    const auto after = wait_for_session(
      server, [&](const SessionHealthSnapshot& s) { return (s.*member).total > baseline; }, 2s);
    EXPECT_EQ((after.*member).total - baseline, 1u)
      << name << ".total did not increment by exactly 1 - a dispatched Service must be counted";
  }
};

// ===========================================================================
// Attribute / view / method / node-management services - minimal requests.
// ===========================================================================
TEST_F(SessionDiagnosticsFields, CoreServicesAreCounted)
{
  expect_dispatched(
    "read", &SessionHealthSnapshot::read, [&] { (void)mSession->attributes().try_read_sync(ReadRequest{}); });
  expect_dispatched("write",
    &SessionHealthSnapshot::write,
    [&] { (void)mSession->attributes().try_write_sync(WriteRequest{}); });
  expect_dispatched("historyRead",
    &SessionHealthSnapshot::historyRead,
    [&] { (void)mSession->attributes().try_history_read_sync(HistoryReadRequest{}); });
  expect_dispatched("historyUpdate",
    &SessionHealthSnapshot::historyUpdate,
    [&] { (void)mSession->attributes().try_history_update_sync(HistoryUpdateRequest{}); });

  expect_dispatched("browse",
    &SessionHealthSnapshot::browse,
    [&] { (void)mSession->view().try_browse_sync(BrowseRequest{}); });
  expect_dispatched("browseNext",
    &SessionHealthSnapshot::browseNext,
    [&] { (void)mSession->view().try_browse_next_sync(BrowseNextRequest{}); });
  expect_dispatched("translateBrowsePaths",
    &SessionHealthSnapshot::translateBrowsePaths,
    [&] { (void)mSession->view().try_translate_browse_paths_sync(TranslateBrowsePathsToNodeIdsRequest{}); });
  expect_dispatched("registerNodes",
    &SessionHealthSnapshot::registerNodes,
    [&] { (void)mSession->view().try_register_nodes_sync(RegisterNodesRequest{}); });
  expect_dispatched("unregisterNodes",
    &SessionHealthSnapshot::unregisterNodes,
    [&] { (void)mSession->view().try_unregister_nodes_sync(UnregisterNodesRequest{}); });

  expect_dispatched(
    "call", &SessionHealthSnapshot::call, [&] { (void)mSession->methods().try_call_sync(CallRequest{}); });

  expect_dispatched("addNodes",
    &SessionHealthSnapshot::addNodes,
    [&] { (void)mSession->node_management().try_add_nodes_sync(AddNodesRequest{}); });
  expect_dispatched("addReferences",
    &SessionHealthSnapshot::addReferences,
    [&] { (void)mSession->node_management().try_add_references_sync(AddReferencesRequest{}); });
  expect_dispatched("deleteNodes",
    &SessionHealthSnapshot::deleteNodes,
    [&] { (void)mSession->node_management().try_delete_nodes_sync(DeleteNodesRequest{}); });
  expect_dispatched("deleteReferences",
    &SessionHealthSnapshot::deleteReferences,
    [&] { (void)mSession->node_management().try_delete_references_sync(DeleteReferencesRequest{}); });
}

// ===========================================================================
// Subscription + monitored-item services - driven against one real subscription
// so Publish returns promptly (a keep-alive) instead of long-polling.
// ===========================================================================
TEST_F(SessionDiagnosticsFields, SubscriptionAndMonitoredItemServicesAreCounted)
{
  // A real subscription with a fast keep-alive, so a Publish returns a keep-alive within ~1 interval.
  CreateSubscriptionRequest createSub;
  createSub.requested_publishing_interval() = 100.0;
  createSub.requested_lifetime_count() = 100;
  createSub.requested_max_keep_alive_count() = 1;
  createSub.publishing_enabled() = true;
  uint32_t subscriptionId = 0;
  expect_dispatched("createSubscription",
    &SessionHealthSnapshot::createSubscription,
    [&]
    {
      auto result = mSession->subscriptions().try_create_subscription_sync(createSub);
      if (result.is_good())
        subscriptionId = result.value().subscription_id();
    });
  ASSERT_NE(subscriptionId, 0u) << "need a real subscription to drive the subscription/MI services";

  // A monitored item on the writable variable.
  MonitoredItemCreateRequest itemToCreate;
  itemToCreate.item_to_monitor().node_id() = mWritableVariableId;
  itemToCreate.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  itemToCreate.monitoring_mode() = MonitoringMode::Reporting;
  itemToCreate.requested_parameters().sampling_interval() = 100.0;
  itemToCreate.requested_parameters().queue_size() = 1;
  itemToCreate.requested_parameters().discard_oldest() = true;
  CreateMonitoredItemsRequest createItems;
  createItems.subscription_id() = subscriptionId;
  createItems.items_to_create().push_back(itemToCreate);

  expect_dispatched("createMonitoredItems",
    &SessionHealthSnapshot::createMonitoredItems,
    [&] { (void)mSession->monitored_items().try_create_monitored_items_sync(createItems); });
  expect_dispatched("modifyMonitoredItems",
    &SessionHealthSnapshot::modifyMonitoredItems,
    [&]
    { (void)mSession->monitored_items().try_modify_monitored_items_sync(ModifyMonitoredItemsRequest{}); });
  expect_dispatched("setMonitoringMode",
    &SessionHealthSnapshot::setMonitoringMode,
    [&] { (void)mSession->monitored_items().try_set_monitoring_mode_sync(SetMonitoringModeRequest{}); });
  expect_dispatched("setTriggering",
    &SessionHealthSnapshot::setTriggering,
    [&] { (void)mSession->monitored_items().try_set_triggering_sync(SetTriggeringRequest{}); });
  expect_dispatched("deleteMonitoredItems",
    &SessionHealthSnapshot::deleteMonitoredItems,
    [&]
    { (void)mSession->monitored_items().try_delete_monitored_items_sync(DeleteMonitoredItemsRequest{}); });

  expect_dispatched("modifySubscription",
    &SessionHealthSnapshot::modifySubscription,
    [&] { (void)mSession->subscriptions().try_modify_subscription_sync(ModifySubscriptionRequest{}); });
  expect_dispatched("setPublishingMode",
    &SessionHealthSnapshot::setPublishingMode,
    [&] { (void)mSession->subscriptions().try_set_publishing_mode_sync(SetPublishingModeRequest{}); });
  expect_dispatched("publish",
    &SessionHealthSnapshot::publish,
    [&] { (void)mSession->subscriptions().try_publish_sync(PublishRequest{}); });
  expect_dispatched("republish",
    &SessionHealthSnapshot::republish,
    [&] { (void)mSession->subscriptions().try_republish_sync(RepublishRequest{}); });
  expect_dispatched("transferSubscriptions",
    &SessionHealthSnapshot::transferSubscriptions,
    [&] { (void)mSession->subscriptions().try_transfer_subscriptions_sync(TransferSubscriptionsRequest{}); });
  expect_dispatched("deleteSubscriptions",
    &SessionHealthSnapshot::deleteSubscriptions,
    [&] { (void)mSession->subscriptions().try_delete_subscriptions_sync(DeleteSubscriptionsRequest{}); });
}

// ===========================================================================
// Aggregate + errorCount.
// ===========================================================================
TEST_F(SessionDiagnosticsFields, TotalRequestCountAndErrorCountAreCounted)
{
  Server& server = mServer.server();

  // A valid Read: totalRequests.total moves and totalRequests.errors does NOT.
  {
    auto before = find_session(server).value();
    ReadRequest goodRead;
    ReadValueId toRead;
    toRead.node_id() = mWritableVariableId;
    toRead.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    goodRead.nodes_to_read().push_back(std::move(toRead));
    (void)mSession->attributes().try_read_sync(std::move(goodRead));

    auto after = wait_for_session(
      server,
      [&](const SessionHealthSnapshot& s) { return s.totalRequests.total > before.totalRequests.total; },
      2s);
    EXPECT_GE(after.totalRequests.total - before.totalRequests.total, 1u) << "totalRequestCount not counted";
    EXPECT_EQ(after.read.errors, before.read.errors) << "a successful Read must not increment read.errors";
  }

  // An empty Read is a whole-request rejection (BadNothingToDo ServiceFault): read.errors AND
  // totalRequests.errors must move.
  {
    auto before = find_session(server).value();
    (void)mSession->attributes().try_read_sync(ReadRequest{});
    auto after = wait_for_session(
      server, [&](const SessionHealthSnapshot& s) { return s.read.errors > before.read.errors; }, 2s);
    EXPECT_EQ(after.read.errors - before.read.errors, 1u)
      << "a service-level Read rejection must increment read.errors";
    EXPECT_GE(after.totalRequests.errors - before.totalRequests.errors, 1u)
      << "a service-level rejection must increment totalRequests.errors";
  }

  // Browse and HistoryRead complete on their OWN response variants (not response_received), so their
  // errorCount must be wired there too. An empty request is a whole-request BadNothingToDo ServiceFault.
  {
    auto before = find_session(server).value();
    (void)mSession->view().try_browse_sync(BrowseRequest{});
    auto after = wait_for_session(
      server, [&](const SessionHealthSnapshot& s) { return s.browse.errors > before.browse.errors; }, 2s);
    EXPECT_EQ(after.browse.errors - before.browse.errors, 1u)
      << "a service-level Browse rejection must increment browse.errors";
  }
  {
    auto before = find_session(server).value();
    (void)mSession->attributes().try_history_read_sync(HistoryReadRequest{});
    auto after = wait_for_session(
      server,
      [&](const SessionHealthSnapshot& s) { return s.historyRead.errors > before.historyRead.errors; },
      2s);
    EXPECT_EQ(after.historyRead.errors - before.historyRead.errors, 1u)
      << "a service-level HistoryRead rejection must increment historyRead.errors";
  }
}

// ===========================================================================
// Inert-by-design fields: they must STAY 0 across ordinary activity.
// ===========================================================================
TEST_F(SessionDiagnosticsFields, InertCountersStayZero)
{
  Server& server = mServer.server();

  // Drive a spread of ordinary requests.
  (void)mSession->attributes().try_read_sync(ReadRequest{});
  (void)mSession->view().try_browse_sync(BrowseRequest{});
  (void)mSession->subscriptions().try_create_subscription_sync(CreateSubscriptionRequest{});

  const auto snap =
    wait_for_session(server, [](const SessionHealthSnapshot& s) { return s.totalRequests.total > 0; }, 2s);

  // unauthorizedRequestCount is request-level and inert-by-design: this SDK authorizes per-item, so a
  // per-item denial is not a rejected request (see ua_server_counters.h). It must be 0.
  EXPECT_EQ(snap.unauthorizedRequestCount, 0u)
    << "unauthorizedRequestCount must stay 0: per-item authorization is not a whole-request rejection";

  // Query is not implemented in this SDK, so its per-service counters never move.
  EXPECT_EQ(snap.queryFirst.total, 0u) << "QueryFirst is unimplemented; its counter must stay 0";
  EXPECT_EQ(snap.queryNext.total, 0u) << "QueryNext is unimplemented; its counter must stay 0";
}
