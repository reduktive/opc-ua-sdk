// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Behavioural integration tests for the SubscriptionDiagnosticsDataType counter fields exposed under
/// Server.ServerDiagnostics.SubscriptionDiagnosticsArray (OPC 10000-5 6.3.7 / OPC 10000-4 SubscriptionInfo).
///
/// Each test drives the REAL client-facing service that mutates a counter (ModifySubscription,
/// SetPublishingMode, Publish, Republish, CreateMonitoredItems, SetMonitoringMode, writes, event emission)
/// and then asserts the exact observable delta on the per-subscription diagnostics node - never storing a
/// value and reading it back. Counter writes are posted on the subscription strand, so every read is
/// retried-until-snapshot (the ModifyCount template: ~50 x 40ms).
///
/// Read channel. The node manager's fieldTable now wires all 31 field children to live read handlers, so
/// every field is readable as an individual HasComponent child Variable (CHILD read). Reading the child
/// therefore also regression-guards that wiring. The per-subscription node's OWN Value is the whole struct
/// (ROOT read); Test A cross-checks child == root for all 12 previously-frozen fields to prove the fix
/// end to end.
///
/// Scope: Tests A-F. The transfer counters (transferRequestCount / transferredTo{Same,Alt}ClientCount,
/// Tests G/H) need a secured two-session harness and are authored separately.

#include "compliance_helpers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_session_attribute_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"

#include "ua_attribute_id.h"
#include "ua_base_event.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_change_notification.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_generic_event.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_notification_message.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_server_configuration.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_simple_attribute_operand.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

using namespace ua;
using namespace ua::client;

namespace
{

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Browse / retry helpers (copied from subscription_diagnostics_nodes_tests.cpp - file-local there, so not
// shared; reproduced here rather than promoted to keep the diagnostics-node browsing self-contained).
// ---------------------------------------------------------------------------

/// Browse the SubscriptionDiagnosticsArray for the HasComponent child whose BrowseName is `subId`.
/// Returns {childNodeId, typeDefinitionNodeId} if found.
std::optional<std::pair<NodeId, NodeId>> find_diag_child(Session& session, uint32_t subId)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = session.view().browse_sync(std::move(req));
  if (resp.results().empty())
    return std::nullopt;
  const std::string target = std::to_string(subId);
  for (const auto& ref : resp.results()[0].references())
  {
    if (std::string{ref.browse_name().name()} == target)
      return std::make_pair(ref.node_id().node_id(), ref.type_definition().node_id());
  }
  return std::nullopt;
}

/// Retry find_diag_child until present (true) or absent (false), within a short timeout.
std::optional<std::pair<NodeId, NodeId>> wait_for_diag_child(
  Session& session, uint32_t subId, bool wantPresent)
{
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    auto found = find_diag_child(session, subId);
    if (found.has_value() == wantPresent)
      return found;
    std::this_thread::sleep_for(40ms);
  }
  return find_diag_child(session, subId);
}

/// Browse `parent` for the HasComponent child named `browseName`; return its NodeId. No retry: the
/// per-subscription node is linked into the array only after all its children are built, so once the
/// node is found its field children are already present.
std::optional<NodeId> find_field_node(Session& session, const NodeId& parent, std::string_view browseName)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = parent;
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = session.view().browse_sync(std::move(req));
  if (resp.results().empty())
    return std::nullopt;
  for (const auto& ref : resp.results()[0].references())
  {
    if (std::string{ref.browse_name().name()} == browseName)
      return ref.node_id().node_id();
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Typed value readers - read a node's Value attribute and decode it.
// ---------------------------------------------------------------------------

DataValue read_value_dv(Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;
  auto resp = session.attributes().read_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  if (resp.results().empty())
    return {};
  return resp.results()[0];
}

uint32_t read_uint32(Session& session, const NodeId& nodeId)
{
  return read_value_dv(session, nodeId).value().as<uint32_t>();
}

bool read_bool(Session& session, const NodeId& nodeId)
{
  return read_value_dv(session, nodeId).value().as<bool>();
}

double read_double(Session& session, const NodeId& nodeId)
{
  return read_value_dv(session, nodeId).value().as<double>();
}

uint8_t read_byte(Session& session, const NodeId& nodeId)
{
  return read_value_dv(session, nodeId).value().as<uint8_t>();
}

NodeId read_nodeid(Session& session, const NodeId& nodeId)
{
  return read_value_dv(session, nodeId).value().as<NodeId>();
}

/// ROOT read: the per-subscription diagnostics node's OWN Value is the whole struct. Decodes
/// non-throwingly; a null pointer (value is not the struct) is a hard failure.
SubscriptionDiagnosticsDataType read_root_struct(Session& session, const NodeId& rootNodeId)
{
  auto dv = read_value_dv(session, rootNodeId);
  const auto* decoded = dv.value().try_as<SubscriptionDiagnosticsDataType>();
  EXPECT_NE(decoded, nullptr) << "root SubscriptionDiagnostics Value did not decode as "
                                 "SubscriptionDiagnosticsDataType";
  if (decoded == nullptr)
    return {};
  return *decoded;
}

// ---------------------------------------------------------------------------
// CHILD readers - browse `root` for the named field child, then read it typed. Combine find + read so
// each test site is one call. A missing child is a hard failure (not a silent frozen-0 read).
// ---------------------------------------------------------------------------

uint32_t read_child_u32(Session& session, const NodeId& root, std::string_view name)
{
  auto node = find_field_node(session, root, name);
  EXPECT_TRUE(node.has_value()) << "diagnostics field child not found: " << name;
  return node ? read_uint32(session, *node) : 0u;
}

bool read_child_bool(Session& session, const NodeId& root, std::string_view name)
{
  auto node = find_field_node(session, root, name);
  EXPECT_TRUE(node.has_value()) << "diagnostics field child not found: " << name;
  return node ? read_bool(session, *node) : false;
}

double read_child_double(Session& session, const NodeId& root, std::string_view name)
{
  auto node = find_field_node(session, root, name);
  EXPECT_TRUE(node.has_value()) << "diagnostics field child not found: " << name;
  return node ? read_double(session, *node) : 0.0;
}

uint8_t read_child_byte(Session& session, const NodeId& root, std::string_view name)
{
  auto node = find_field_node(session, root, name);
  EXPECT_TRUE(node.has_value()) << "diagnostics field child not found: " << name;
  return node ? read_byte(session, *node) : uint8_t{0};
}

NodeId read_child_nodeid(Session& session, const NodeId& root, std::string_view name)
{
  auto node = find_field_node(session, root, name);
  EXPECT_TRUE(node.has_value()) << "diagnostics field child not found: " << name;
  return node ? read_nodeid(session, *node) : NodeId{};
}

// ---------------------------------------------------------------------------
// poll_until - retry-until-snapshot. Reads via `readFn` until `pred(value)` holds or the attempt budget
// is exhausted, then returns the last value (the caller asserts). Mirrors the ~50 x 40ms ModifyCount
// template; every counter read in these tests goes through this so strand-post lag never false-fails.
// ---------------------------------------------------------------------------

template<typename ReadFn, typename Pred>
auto poll_until(ReadFn readFn, Pred pred, int attempts = 60, std::chrono::milliseconds interval = 40ms)
{
  auto value = readFn();
  for (int attempt = 0; attempt < attempts && !pred(value); ++attempt)
  {
    std::this_thread::sleep_for(interval);
    value = readFn();
  }
  return value;
}

// ---------------------------------------------------------------------------
// Minimal valid EventFilter (one select clause) so an event MonitoredItem is accepted and events project.
// ---------------------------------------------------------------------------

EventFilter make_min_event_filter()
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, "Message"});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(std::move(clause));
  return filter;
}

/// True if `dc` carries a MonitoredItemNotification for `clientHandle` whose Int32 value equals `value`.
bool data_change_carries(const DataChangeNotification& dc, uint32_t clientHandle, int32_t value)
{
  for (const auto& mi : dc.monitored_items())
  {
    if (mi.client_handle() != clientHandle)
      continue;
    const auto* decoded = mi.value().value().try_as<int32_t>();
    if (decoded != nullptr && *decoded == value)
      return true;
  }
  return false;
}

}  // namespace

// ===========================================================================
// Fixtures
// ===========================================================================

// ComplianceWithNodes (None endpoint) covers Tests A-E.
class SubscriptionDiagnosticsFields : public ComplianceWithNodes
{};

// Test F needs a shrunk retransmission queue: mMaxPublishRequestsPerSession = 1 makes
// mMaxRetransmissionQueueSize = 2 (2 x pending publish requests), so a 3rd unacked message evicts the
// oldest, which the pipeline records as a discarded message.
class SubscriptionDiagnosticsShrunkQueue : public ComplianceWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.subscriptionLimits.maxPublishRequestsPerSession = 1;
  }
};

// ===========================================================================
// Test A - IdentityConfigAndInitialGauges
// Fields 20-26, 29, 30, 31 + initial 27, 28 + child==root cross-check of the 12 previously-frozen fields.
// ===========================================================================

TEST_F(SubscriptionDiagnosticsFields, IdentityConfigAndInitialGauges)
{
  // A minute between publishing cycles: the cross-check below compares one read of the root struct with
  // later reads of each child, so a cycle that elapsed between them, on a loaded host, could move a gauge
  // such as LatePublishRequestCount and make the two reads disagree.
  auto resp = mSession->subscriptions().create_subscription_sync(
    ua::test_helpers::build_subscription_request({.publishingInterval = 60000.0,
      .lifetimeCount = 100,
      .keepAliveCount = 10,
      .maxNotificationsPerPublish = 777,
      .publishingEnabled = true,
      .priority = 0}));
  const uint32_t subId = resp.subscription_id();

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value()) << "No SubscriptionDiagnostics child for subscription " << subId;
  const NodeId rootId = child->first;

  // --- Identity / configuration (CHILD reads) ---
  EXPECT_EQ(read_child_u32(*mSession, rootId, "SubscriptionId"), subId);

  const NodeId sessionId = read_child_nodeid(*mSession, rootId, "SessionId");
  EXPECT_FALSE(sessionId.is_null()) << "SessionId diagnostic must be a real session NodeId";
  EXPECT_EQ(sessionId, mSession->session_id());

  EXPECT_EQ(read_child_byte(*mSession, rootId, "Priority"), uint8_t{0});
  EXPECT_DOUBLE_EQ(
    read_child_double(*mSession, rootId, "PublishingInterval"), resp.revised_publishing_interval());
  EXPECT_EQ(read_child_u32(*mSession, rootId, "MaxKeepAliveCount"), resp.revised_max_keep_alive_count());
  EXPECT_EQ(read_child_u32(*mSession, rootId, "MaxLifetimeCount"), resp.revised_lifetime_count());
  EXPECT_EQ(read_child_u32(*mSession, rootId, "MaxNotificationsPerPublish"), 777u);
  EXPECT_TRUE(read_child_bool(*mSession, rootId, "PublishingEnabled"));

  // --- Initial gauges ---
  EXPECT_EQ(read_child_u32(*mSession, rootId, "MonitoredItemCount"), 0u);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "DisabledMonitoredItemCount"), 0u);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "NextSequenceNumber"), 1u);

  // --- Create-time current-gauge determinism (ROOT read) ---
  const auto root = read_root_struct(*mSession, rootId);
  EXPECT_EQ(root.current_keep_alive_count(), 0u);
  EXPECT_EQ(root.current_lifetime_count(), resp.revised_lifetime_count());

  // --- child == root cross-check for the 12 previously-frozen fields ---
  // Proves the fieldTable fix end to end: each of these field children now reflects the live struct
  // value rather than a frozen instantiated 0. CurrentLifetimeCount is non-zero (== revised lifetime),
  // so this comparison genuinely falsifies a regression of the wiring for at least that field.
  struct FrozenField
  {
    std::string_view name;
    uint32_t (*get)(const SubscriptionDiagnosticsDataType&);
  };

  const std::array<FrozenField, 12> frozenFields{{
    {"EnableCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.enable_count();
      }},
    {"DisableCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.disable_count();
      }},
    {"TransferRequestCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.transfer_request_count();
      }},
    {"TransferredToSameClientCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.transferred_to_same_client_count();
      }},
    {"TransferredToAltClientCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.transferred_to_alt_client_count();
      }},
    {"EventNotificationsCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.event_notifications_count();
      }},
    {"UnacknowledgedMessageCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.unacknowledged_message_count();
      }},
    {"LatePublishRequestCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.late_publish_request_count();
      }},
    {"DiscardedMessageCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.discarded_message_count();
      }},
    {"EventQueueOverflowCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.event_queue_overflow_count();
      }},
    {"CurrentKeepAliveCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.current_keep_alive_count();
      }},
    {"CurrentLifetimeCount",
      [](const SubscriptionDiagnosticsDataType& d)
      {
        return d.current_lifetime_count();
      }},
  }};
  for (const auto& field : frozenFields)
  {
    EXPECT_EQ(read_child_u32(*mSession, rootId, field.name), field.get(root))
      << "child != root for previously-frozen field " << field.name;
  }

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// ===========================================================================
// Test B - ModifyAndPublishingMode
// Fields 1 (modifyCount), 2 (enableCount), 3 (disableCount), 4 (publishingEnabled); re-confirms 22.
// Modify is performed LAST, with publishing disabled: it carries no publishingEnabled, so the mode stays
// disabled, and it must NOT bump enableCount.
// ===========================================================================

TEST_F(SubscriptionDiagnosticsFields, ModifyAndPublishingMode)
{
  const uint32_t subId = ua::test_helpers::create_subscription(*mSession,
    {.publishingInterval = 200.0, .lifetimeCount = 100, .keepAliveCount = 10, .publishingEnabled = true});

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  const NodeId rootId = child->first;

  // Baseline: creation does not touch enable/disable/modify counters.
  EXPECT_EQ(read_child_u32(*mSession, rootId, "EnableCount"), 0u);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "DisableCount"), 0u);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "ModifyCount"), 0u);
  EXPECT_TRUE(read_child_bool(*mSession, rootId, "PublishingEnabled"));

  // SetPublishingMode(false) -> publishingEnabled flips, disableCount == 1.
  ua::test_helpers::set_publishing_mode(*mSession, subId, /*enabled=*/false);
  EXPECT_FALSE(poll_until([&] { return read_child_bool(*mSession, rootId, "PublishingEnabled"); },
    [](bool enabled) { return !enabled; }));
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "DisableCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);

  // SetPublishingMode(true) -> publishingEnabled flips back, enableCount == 1.
  ua::test_helpers::set_publishing_mode(*mSession, subId, /*enabled=*/true);
  EXPECT_TRUE(poll_until([&] { return read_child_bool(*mSession, rootId, "PublishingEnabled"); },
    [](bool enabled) { return enabled; }));
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "EnableCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);

  // SetPublishingMode(false) again -> disableCount == 2.
  ua::test_helpers::set_publishing_mode(*mSession, subId, /*enabled=*/false);
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "DisableCount"); },
              [](uint32_t count) { return count >= 2; }),
    2u);

  // ModifySubscription LAST: modifyCount == 1, priority == 7, publishingEnabled still false (the request has
  // no publishingEnabled, Part 4 5.14.3), and enableCount stays 1 (Modify does not call
  // record_publishing_mode) - falsifies "Modify bumps enable".
  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = subId;
  modReq.requested_publishing_interval() = 400.0;
  modReq.requested_lifetime_count() = 100;
  modReq.requested_max_keep_alive_count() = 10;
  modReq.max_notifications_per_publish() = 0;
  modReq.priority() = 7;
  auto modResp = mSession->subscriptions().modify_subscription_sync(std::move(modReq));
  (void)modResp;

  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "ModifyCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);
  EXPECT_EQ(poll_until([&] { return read_child_byte(*mSession, rootId, "Priority"); },
              [](uint8_t priority) { return priority == 7; }),
    uint8_t{7});
  EXPECT_FALSE(read_child_bool(*mSession, rootId, "PublishingEnabled"))
    << "ModifySubscription must not change the publishing mode";
  EXPECT_EQ(read_child_u32(*mSession, rootId, "EnableCount"), 1u)
    << "ModifySubscription must not increment EnableCount";

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// ===========================================================================
// Test C - MonitoredItemGauges
// Fields 27 (monitoredItemCount), 28 (disabledMonitoredItemCount). Both edges of each gauge are driven.
// ===========================================================================

TEST_F(SubscriptionDiagnosticsFields, MonitoredItemGauges)
{
  const uint32_t subId = ua::test_helpers::create_subscription(*mSession);

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  const NodeId rootId = child->first;

  // Create three monitored items on a readable node (distinct client handles).
  const NodeId monitoredNode{VariableId::Server_ServerStatus_CurrentTime};
  CreateMonitoredItemsRequest miReq;
  miReq.subscription_id() = subId;
  miReq.timestamps_to_return() = TimestampsToReturn::Both;
  for (uint32_t handle = 1; handle <= 3; ++handle)
  {
    ReadValueId rv;
    rv.node_id() = monitoredNode;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    MonitoringParameters params;
    params.client_handle() = handle;
    params.sampling_interval() = 200.0;
    params.queue_size() = 1;
    params.discard_oldest() = true;

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);
    miReq.items_to_create().push_back(std::move(item));
  }
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 3u);
  std::array<uint32_t, 3> itemIds{};
  for (size_t index = 0; index < 3; ++index)
  {
    ASSERT_TRUE(miResp.results()[index].status_code().is_good())
      << "MI " << index << " create failed: 0x" << std::hex
      << miResp.results()[index].status_code().as_uint32();
    itemIds[index] = miResp.results()[index].monitored_item_id();
  }

  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "MonitoredItemCount"); },
              [](uint32_t count) { return count >= 3; }),
    3u);

  // Disable two -> disabledMonitoredItemCount == 2.
  {
    SetMonitoringModeRequest req;
    req.subscription_id() = subId;
    req.monitoring_mode() = MonitoringMode::Disabled;
    req.monitored_item_ids().push_back(itemIds[0]);
    req.monitored_item_ids().push_back(itemIds[1]);
    auto resp = mSession->monitored_items().set_monitoring_mode_sync(std::move(req));
    ASSERT_EQ(resp.results().size(), 2u);
    EXPECT_TRUE(resp.results()[0].is_good());
    EXPECT_TRUE(resp.results()[1].is_good());
  }
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "DisabledMonitoredItemCount"); },
              [](uint32_t count) { return count >= 2; }),
    2u);

  // Re-enable one -> disabledMonitoredItemCount drops to 1 (falsifies a write-once gauge).
  {
    SetMonitoringModeRequest req;
    req.subscription_id() = subId;
    req.monitoring_mode() = MonitoringMode::Reporting;
    req.monitored_item_ids().push_back(itemIds[0]);
    auto resp = mSession->monitored_items().set_monitoring_mode_sync(std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good());
  }
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "DisabledMonitoredItemCount"); },
              [](uint32_t count) { return count <= 1; }),
    1u);

  // Delete one -> monitoredItemCount drops to 2.
  {
    DeleteMonitoredItemsRequest req;
    req.subscription_id() = subId;
    req.monitored_item_ids().push_back(itemIds[2]);
    auto resp = mSession->monitored_items().delete_monitored_items_sync(std::move(req));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].is_good());
  }
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "MonitoredItemCount"); },
              [](uint32_t count) { return count <= 2; }),
    2u);

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// ===========================================================================
// Test D - PublishNotificationsRepublishLifecycle
// Fields 11 (publishRequestCount), 12 (dataChangeNotificationsCount), 14 (notificationsCount),
// 29 (nextSequenceNumber), 15 (unacknowledgedMessageCount), 5/6 (republish request counts),
// 7 (republishMessageCount).
// ===========================================================================

TEST_F(SubscriptionDiagnosticsFields, PublishNotificationsRepublishLifecycle)
{
  const uint32_t subId = ua::test_helpers::create_subscription(*mSession,
    {.publishingInterval = 100.0, .lifetimeCount = 100, .keepAliveCount = 10, .publishingEnabled = true});

  auto miResp =
    mSession->monitored_items().create_monitored_items_sync(ua::test_helpers::build_create_mi_request(
      subId, mWritableVariableId, {.clientHandle = 1, .queueSize = 1}));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  const NodeId rootId = child->first;

  // First Publish carries the initial value; keep its sequence number so we can ack it out of the
  // retransmission queue and leave only the post-write message unacknowledged (unacked == 1).
  auto resp0 = mSession->subscriptions().publish_sync(PublishRequest{});
  const uint32_t initialSeq = resp0.notification_message().sequence_number();

  // Write a distinct value, then poll Publish (acking the initial seq each round) for the data change.
  constexpr int32_t newValue = 4242;
  mSession->attributes().write_sync(
    ua::test_helpers::WriteRequestBuilder{}.write(mWritableVariableId, Variant{newValue}).build());

  uint32_t dataSeq = 0;
  for (int attempt = 0; attempt < 60 && dataSeq == 0; ++attempt)
  {
    PublishRequest req;
    SubscriptionAcknowledgement ack;
    ack.subscription_id() = subId;
    ack.sequence_number() = initialSeq;
    req.subscription_acknowledgements().push_back(std::move(ack));

    auto result = mSession->subscriptions().try_publish_sync(std::move(req));
    if (result.is_good() && result.value().response_header().service_result().is_good())
    {
      const auto* dc = ua::test_helpers::as_data_change(result.value());
      if (dc != nullptr && data_change_carries(*dc, /*handle=*/1, newValue))
        dataSeq = result.value().notification_message().sequence_number();
    }
    if (dataSeq == 0)
      std::this_thread::sleep_for(40ms);
  }
  ASSERT_NE(dataSeq, 0u) << "did not receive the post-write data change";

  // Cumulative publish / notification counters advanced.
  EXPECT_GE(poll_until([&] { return read_child_u32(*mSession, rootId, "PublishRequestCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);
  const uint32_t dataChangeCount =
    poll_until([&] { return read_child_u32(*mSession, rootId, "DataChangeNotificationsCount"); },
      [](uint32_t count) { return count >= 1; });
  EXPECT_GE(dataChangeCount, 1u);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "NotificationsCount"), dataChangeCount)
    << "with no events, NotificationsCount tracks DataChangeNotificationsCount";
  EXPECT_GT(poll_until([&] { return read_child_u32(*mSession, rootId, "NextSequenceNumber"); },
              [](uint32_t seq) { return seq > 1; }),
    1u);

  // Exactly the post-write message is retained un-acked.
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "UnacknowledgedMessageCount"); },
              [](uint32_t count) { return count == 1; }),
    1u);

  // Republish a bogus sequence number: request counters advance in lock-step, message count does not.
  const uint32_t reqBefore = read_child_u32(*mSession, rootId, "RepublishRequestCount");
  const uint32_t msgReqBefore = read_child_u32(*mSession, rootId, "RepublishMessageRequestCount");
  const uint32_t msgBefore = read_child_u32(*mSession, rootId, "RepublishMessageCount");
  {
    RepublishRequest req;
    req.subscription_id() = subId;
    req.retransmit_sequence_number() = 99999u;
    auto result = mSession->subscriptions().try_republish_sync(std::move(req));
    // A miss returns Bad_MessageNotAvailable (service fault); the request counter still increments.
    (void)result;
  }
  const uint32_t reqAfterMiss =
    poll_until([&] { return read_child_u32(*mSession, rootId, "RepublishRequestCount"); },
      [&](uint32_t count) { return count >= reqBefore + 1; });
  EXPECT_EQ(reqAfterMiss, reqBefore + 1);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "RepublishMessageRequestCount"), msgReqBefore + 1)
    << "RepublishMessageRequestCount tracks RepublishRequestCount";
  EXPECT_EQ(read_child_u32(*mSession, rootId, "RepublishMessageCount"), msgBefore)
    << "a Republish miss must not increment RepublishMessageCount";

  // Republish the real, queued sequence number: message count advances and the message comes back.
  {
    RepublishRequest req;
    req.subscription_id() = subId;
    req.retransmit_sequence_number() = dataSeq;
    auto resp = mSession->subscriptions().republish_sync(std::move(req));
    EXPECT_EQ(resp.notification_message().sequence_number(), dataSeq);
  }
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "RepublishMessageCount"); },
              [&](uint32_t count) { return count >= msgBefore + 1; }),
    msgBefore + 1);
  EXPECT_EQ(read_child_u32(*mSession, rootId, "RepublishRequestCount"), reqBefore + 2)
    << "the valid Republish also increments the request counter";

  // Acknowledge the retained message -> unacknowledgedMessageCount returns to 0.
  ua::test_helpers::acknowledge(*mSession, subId, dataSeq);
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "UnacknowledgedMessageCount"); },
              [](uint32_t count) { return count == 0; }),
    0u);

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// ===========================================================================
// Test E - OverflowAndLateCluster
// Fields 16 (latePublishRequestCount), 18 (monitoringQueueOverflowCount), 19 (eventQueueOverflowCount).
// Invariant: NO PublishRequest is issued in this test - a single publish drains the queues (defeating both
// overflow counters) and clears the late state.
// ===========================================================================

TEST_F(SubscriptionDiagnosticsFields, OverflowAndLateCluster)
{
  const uint32_t subId = ua::test_helpers::create_subscription(*mSession,
    {.publishingInterval = 100.0, .lifetimeCount = 200, .keepAliveCount = 10, .publishingEnabled = true});

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  const NodeId rootId = child->first;

  // Data monitored item: queueSize >= 2 so overflow sets the bit (queueSize==1 is replace-in-place).
  auto dataMiResp =
    mSession->monitored_items().create_monitored_items_sync(ua::test_helpers::build_create_mi_request(subId,
      mWritableVariableId,
      {.clientHandle = 1, .samplingInterval = 100.0, .queueSize = 2, .discardOldest = true}));
  ASSERT_EQ(dataMiResp.results().size(), 1u);
  ASSERT_TRUE(dataMiResp.results()[0].status_code().is_good());
  const uint32_t dataQueue = dataMiResp.results()[0].revised_queue_size();

  // Event monitored item on the Server object.
  auto eventMiReq = ua::test_helpers::build_create_mi_request(subId,
    NodeId{ObjectId::Server},
    std::make_unique<EventFilter>(make_min_event_filter()),
    {.attribute = AttributeId::EventNotifier, .clientHandle = 2, .samplingInterval = 0.0, .queueSize = 1});
  auto eventMiResp = mSession->monitored_items().create_monitored_items_sync(std::move(eventMiReq));
  ASSERT_EQ(eventMiResp.results().size(), 1u);
  ASSERT_TRUE(eventMiResp.results()[0].status_code().is_good())
    << "event MI create failed: 0x" << std::hex << eventMiResp.results()[0].status_code().as_uint32();
  const uint32_t eventQueue = eventMiResp.results()[0].revised_queue_size();

  // Drive data overflow: (queueSize + 1) distinct writes spaced ~2x samplingInterval apart so each is
  // sampled distinctly and the queue overflows.
  for (uint32_t i = 0; i < dataQueue + 1; ++i)
  {
    mSession->attributes().write_sync(ua::test_helpers::WriteRequestBuilder{}
                                        .write(mWritableVariableId, Variant{static_cast<int32_t>(5000 + i)})
                                        .build());
    std::this_thread::sleep_for(220ms);
  }

  // Drive event overflow: (queueSize + 2) events emitted back-to-back, no publish in between.
  for (uint32_t i = 0; i < eventQueue + 2; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowLateCluster";
    event.message = LocalizedText{"", "overflow " + std::to_string(i)};
    event.severity = 100;
    mServer.server().emit_event(event);
  }

  // No Publish is ever issued. Overflow counters are refreshed into the snapshot by update_info on the
  // sampling / event-delivery strand; latePublishRequestCount is a cumulative counter bumped when the
  // subscription first transitions to Late (first publishing tick with no message sent and no publish
  // request queued).
  EXPECT_GE(poll_until([&] { return read_child_u32(*mSession, rootId, "MonitoringQueueOverflowCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);
  EXPECT_GE(poll_until([&] { return read_child_u32(*mSession, rootId, "EventQueueOverflowCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);
  EXPECT_EQ(poll_until([&] { return read_child_u32(*mSession, rootId, "LatePublishRequestCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// ===========================================================================
// Test F - DiscardedMessageCount (shrunk retransmission queue)
// Field 17 (discardedMessageCount). With bound 2, a 3rd unacked message evicts the oldest -> discard.
// ===========================================================================

TEST_F(SubscriptionDiagnosticsShrunkQueue, DiscardedMessageCount)
{
  const uint32_t subId = ua::test_helpers::create_subscription(*mSession,
    {.publishingInterval = 100.0, .lifetimeCount = 100, .keepAliveCount = 10, .publishingEnabled = true});

  auto miResp =
    mSession->monitored_items().create_monitored_items_sync(ua::test_helpers::build_create_mi_request(
      subId, mWritableVariableId, {.clientHandle = 1, .queueSize = 10}));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  const NodeId rootId = child->first;

  // Loop: write a distinct value, then Publish (never ack) until the data change lands. Each retained
  // data message occupies a retransmission slot; the 3rd overflows the bound-2 queue and evicts (discards)
  // the oldest. Four rounds guarantees at least one eviction. Never acknowledge inside the loop - any ack
  // erases the message before it can be evicted, defeating the counter.
  for (int32_t round = 0; round < 4; ++round)
  {
    const int32_t value = 6000 + round;
    mSession->attributes().write_sync(
      ua::test_helpers::WriteRequestBuilder{}.write(mWritableVariableId, Variant{value}).build());

    bool landed = false;
    for (int attempt = 0; attempt < 60 && !landed; ++attempt)
    {
      auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
      if (result.is_good() && result.value().response_header().service_result().is_good())
      {
        const auto* dc = ua::test_helpers::as_data_change(result.value());
        if (dc != nullptr && data_change_carries(*dc, /*handle=*/1, value))
          landed = true;
      }
      if (!landed)
        std::this_thread::sleep_for(40ms);
    }
    ASSERT_TRUE(landed) << "data change for value " << value << " never delivered";
  }

  EXPECT_GE(poll_until([&] { return read_child_u32(*mSession, rootId, "DiscardedMessageCount"); },
              [](uint32_t count) { return count >= 1; }),
    1u);

  ua::test_helpers::delete_subscription(*mSession, subId);
}

// Row: SubscriptionLimits::maxNotificationsPerPublish - the SERVER cap
// (configuration coverage matrix section 12b - DEMOTED by the mutation spot-check).
//
// Distinct from `SubscriptionConfig::maxNotificationsPerPublish`, the CLIENT request field, which
// `IdentityConfigAndInitialGauges` above covers by requesting 777 and reading it back. Same name, opposite
// direction: the client asks, the server caps. The spot-check found the SERVER half uncovered - ignoring
// the cap left every subscription test green - which is exactly the gap a shared name hides, because a
// reviewer sees "MaxNotificationsPerPublish" asserted and moves on.
//
// The revised value is not in the CreateSubscription response (Part 4 returns only interval, lifetime and
// keep-alive), so the diagnostics node is the oracle - the same node the client-side row reads.
class SubscriptionDiagnosticsCappedNotifications : public SubscriptionDiagnosticsFields
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.subscriptionLimits.maxNotificationsPerPublish = 11;  // default: unset (no cap)
  }
};

// DEFAULT (unset): the request is honoured as asked - which is precisely what the 777 assertion above
// shows on a server with no cap configured.
TEST_F(SubscriptionDiagnosticsCappedNotifications, RequestAboveTheServerCapIsRevisedDown)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    ua::test_helpers::build_subscription_request({.publishingInterval = 500.0,
      .lifetimeCount = 100,
      .keepAliveCount = 10,
      .maxNotificationsPerPublish = 900,  // far above the configured cap
      .publishingEnabled = true,
      .priority = 0}));

  auto child = wait_for_diag_child(*mSession, resp.subscription_id(), /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  EXPECT_EQ(read_child_u32(*mSession, child->first, "MaxNotificationsPerPublish"), 11u)
    << "a request above the server cap must be revised down to it; with the cap unset the server honours "
       "the request as asked (777 in the row above)";
}

// Control: a request INSIDE the cap must be left alone, so the row tests a ceiling rather than a server
// that overwrites every request with its own number.
TEST_F(SubscriptionDiagnosticsCappedNotifications, RequestInsideTheServerCapIsHonoured)
{
  auto resp = mSession->subscriptions().create_subscription_sync(
    ua::test_helpers::build_subscription_request({.publishingInterval = 500.0,
      .lifetimeCount = 100,
      .keepAliveCount = 10,
      .maxNotificationsPerPublish = 4,
      .publishingEnabled = true,
      .priority = 0}));

  auto child = wait_for_diag_child(*mSession, resp.subscription_id(), /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());
  EXPECT_EQ(read_child_u32(*mSession, child->first, "MaxNotificationsPerPublish"), 4u)
    << "a request inside the cap must be honoured unchanged";
}
