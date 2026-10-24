// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for the per-subscription SubscriptionDiagnosticsType child nodes hung off
/// Server.ServerDiagnostics.SubscriptionDiagnosticsArray (OPC 10000-5 section 6.3.7).
///
/// Mirrors UACTT Base Info Diagnostics 011 (and unblocks Subscription Durable 012): browse the array
/// for a HasComponent child whose BrowseName is the SubscriptionId, walk to a field, read its live
/// value, and confirm it tracks the subscription (ModifyCount increments after ModifySubscription).
/// Node creation/removal is asynchronous, so lookups retry briefly.

#include "compliance_helpers.h"
#include "subscription.h"
#include "matchers.h"

#include "ua_session_attribute_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"

#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"

#include "ua_node_accessor.h"
#include "ua_referencetype_id.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

#include "fmt/format.h"

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <thread>

using namespace ua;
using namespace ua::client;

namespace
{

uint32_t create_diagnostics_subscription(Session& session)
{
  CreateSubscriptionRequest req;
  req.requested_publishing_interval() = 500.0;
  req.requested_lifetime_count() = 100;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  req.publishing_enabled() = true;
  req.priority() = 0;
  return session.subscriptions().create_subscription_sync(std::move(req)).subscription_id();
}

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
  using namespace std::chrono_literals;
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
/// node is linked into the array only after all its children are built (atomic visibility), so once
/// the per-subscription node is found, its field children must already be present.
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

/// The SamplingIntervalDiagnosticsArray's HasComponent children by BrowseName: NodeId and TypeDefinition.
std::map<std::string, std::pair<NodeId, NodeId>> sampling_interval_children(Session& session)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{VariableId::Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  std::map<std::string, std::pair<NodeId, NodeId>> children;
  auto resp = session.view().browse_sync(std::move(req));
  if (resp.results().empty())
    return children;
  for (const auto& ref : resp.results()[0].references())
    children.emplace(std::string{ref.browse_name().name()},
      std::make_pair(ref.node_id().node_id(), ref.type_definition().node_id()));
  return children;
}

/// The BrowseName a per-interval node carries: the interval in milliseconds, as a number.
std::string interval_name(double interval)
{
  return fmt::format("{}", interval);
}

uint32_t read_uint32(Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Both;
  auto resp = session.attributes().read_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  return resp.results()[0].value().as<uint32_t>();
}

}  // namespace

TEST_F(ComplianceWithNodes, SubscriptionDiagnostics_PerSubscriptionNodeExistsWithCorrectType)
{
  auto subId = create_diagnostics_subscription(*mSession);

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value()) << "No SubscriptionDiagnostics child for subscription " << subId;
  EXPECT_EQ(child->second, NodeId{VariableTypeId::SubscriptionDiagnosticsType});
}

TEST_F(ComplianceWithNodes, SubscriptionDiagnostics_ModifyCountIncrementsAfterModify)
{
  auto subId = create_diagnostics_subscription(*mSession);

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/true);
  ASSERT_TRUE(child.has_value());

  auto modifyCountNode = find_field_node(*mSession, child->first, "ModifyCount");
  ASSERT_TRUE(modifyCountNode.has_value()) << "ModifyCount field child not found";

  EXPECT_EQ(read_uint32(*mSession, *modifyCountNode), 0u);

  // ModifySubscription bumps the subscription's ModifyCount diagnostic.
  ModifySubscriptionRequest modReq;
  modReq.subscription_id() = subId;
  modReq.requested_publishing_interval() = 1000.0;
  modReq.requested_lifetime_count() = 100;
  modReq.requested_max_keep_alive_count() = 10;
  modReq.max_notifications_per_publish() = 0;
  modReq.priority() = 0;
  auto modResp = mSession->subscriptions().modify_subscription_sync(std::move(modReq));
  (void)modResp;

  // The diagnostic update is posted on the subscription strand; retry the read briefly.
  using namespace std::chrono_literals;
  uint32_t modifyCount = 0;
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    modifyCount = read_uint32(*mSession, *modifyCountNode);
    if (modifyCount >= 1)
      break;
    std::this_thread::sleep_for(40ms);
  }
  EXPECT_GE(modifyCount, 1u) << "ModifyCount did not increment after ModifySubscription";
}

TEST_F(ComplianceWithNodes, SubscriptionDiagnostics_NodeRemovedWhenSubscriptionDeleted)
{
  auto subId = create_diagnostics_subscription(*mSession);
  ASSERT_TRUE(wait_for_diag_child(*mSession, subId, /*wantPresent=*/true).has_value());

  DeleteSubscriptionsRequest delReq;
  delReq.subscription_ids().push_back(subId);
  auto delResp = mSession->subscriptions().delete_subscriptions_sync(std::move(delReq));
  (void)delResp;

  auto child = wait_for_diag_child(*mSession, subId, /*wantPresent=*/false);
  EXPECT_FALSE(child.has_value()) << "SubscriptionDiagnostics child outlived its subscription";
}

// OPC 10000-5 6.3.6: the SamplingIntervalDiagnosticsArray has one SamplingIntervalDiagnosticsType component
// per sampling interval in use, named by the interval (the CTT's Base Info Diagnostics 004). The CTT browses
// straight after CreateMonitoredItems returns, without retrying, so the nodes must already be there.
TEST_F(ComplianceWithNodes, SamplingIntervalDiagnostics_OneNodePerIntervalInUseAsSoonAsTheItemsExist)
{
  auto subId = create_diagnostics_subscription(*mSession);
  std::vector<double> revised;
  std::vector<uint32_t> itemIds;
  for (const double requested : {1300.0, 2600.0})
  {
    auto resp = mSession->monitored_items().create_monitored_items_sync(
      ua::test_helpers::build_create_mi_request(subId, mWritableVariableId, {.samplingInterval = requested}));
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].status_code().is_good());
    revised.push_back(resp.results()[0].revised_sampling_interval());
    itemIds.push_back(resp.results()[0].monitored_item_id());
  }

  auto children = sampling_interval_children(*mSession);
  for (const double interval : revised)
  {
    const auto it = children.find(interval_name(interval));
    ASSERT_NE(it, children.end()) << "no SamplingIntervalDiagnostics node named " << interval_name(interval);
    EXPECT_EQ(it->second.second, NodeId{VariableTypeId::SamplingIntervalDiagnosticsType});
    auto count = find_field_node(*mSession, it->second.first, "SampledMonitoredItemsCount");
    ASSERT_TRUE(count.has_value());
    EXPECT_GE(read_uint32(*mSession, *count), 1u)
      << "the node reports the MonitoredItems sampled at its interval";
  }

  // Deleting the items takes their intervals' nodes with them, again by the time the service answers.
  DeleteMonitoredItemsRequest del;
  del.subscription_id() = subId;
  for (const auto id : itemIds)
    del.monitored_item_ids().push_back(id);
  (void)mSession->monitored_items().delete_monitored_items_sync(std::move(del));
  children = sampling_interval_children(*mSession);
  for (const double interval : revised)
    EXPECT_EQ(children.count(interval_name(interval)), 0u)
      << "the node for " << interval_name(interval) << " outlived the last MonitoredItem using it";
}

// Part 5 6.3.3: "When diagnostics are turned off ... Dynamic diagnostic Nodes (such as the Session Nodes)
// will not appear in the AddressSpace." The per-interval nodes are such nodes: they go when the EnabledFlag
// is set false and return, for the intervals then in use, when it is set true.
TEST_F(ComplianceWithNodes, SamplingIntervalDiagnostics_NodesFollowTheEnabledFlag)
{
  auto subId = create_diagnostics_subscription(*mSession);
  auto resp = mSession->monitored_items().create_monitored_items_sync(
    ua::test_helpers::build_create_mi_request(subId, mWritableVariableId, {.samplingInterval = 1700.0}));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good());
  const auto name = interval_name(resp.results()[0].revised_sampling_interval());
  ASSERT_EQ(sampling_interval_children(*mSession).count(name), 1u);

  const auto setEnabled = [this](bool enabled)
  {
    auto node = mServer.server().address_space().find_node_sync(
      NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(Variant{enabled});
  };
  const auto eventually = [this, &name](bool present)
  {
    for (int attempt = 0; attempt < 50; ++attempt)
    {
      if ((sampling_interval_children(*mSession).count(name) == 1u) == present)
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    return false;
  };

  setEnabled(false);
  EXPECT_TRUE(eventually(false)) << "with diagnostics disabled the per-interval node must go";
  setEnabled(true);
  EXPECT_TRUE(eventually(true)) << "enabled again, the node for the interval still in use must return";
}

// Part 5 sections 6.3.3 and 12.9, Table 240: enabling resets collection, while cumulative Session and
// Subscription counts include their current counts. A closed Session supplies history that the reset
// must remove without changing the counts of the resources still open.
TEST_F(ComplianceWithNodes, ReEnablingDiagnosticsKeepsTheCountsOfWhatIsOpen)
{
  (void)create_diagnostics_subscription(*mSession);
  const auto readCount = [this](VariableId id)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = NodeId{id};
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    auto resp = mSession->attributes().read_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    if (resp.results().size() != 1u)
    {
      return uint32_t{0xFFFFFFFF};
    }
    const auto& value = resp.results()[0];
    EXPECT_TRUE(value.status().value_or(StatusCode{Status::Good}).is_good());
    const auto* count = value.value().try_as<uint32_t>();
    EXPECT_NE(count, nullptr);
    return count ? *count : uint32_t{0xFFFFFFFF};
  };
  const auto sessions =
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount);
  const auto subscriptions =
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount);
  ASSERT_GE(sessions, 1u);
  ASSERT_GE(subscriptions, 1u);

  auto closedSession = mChannel->create_session_sync({.sessionName = "DiagnosticsResetHistory"});
  closedSession.activate_sync();
  ASSERT_TRUE(closedSession.try_close_sync().is_good());
  ASSERT_EQ(
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount), sessions);
  ASSERT_GT(
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount), sessions)
    << "the reset must remove closed Session history";

  auto flag = mServer.server()
                .address_space()
                .find_node_sync(NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag})
                .as<VariableAccessor>();
  ASSERT_TRUE(flag.has_value());
  flag->write_value_sync(Variant{false});
  flag->write_value_sync(Variant{true});

  EXPECT_EQ(
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount), sessions);
  EXPECT_EQ(readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount),
    subscriptions);
  EXPECT_EQ(
    readCount(VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount), sessions)
    << "reset removes closed Session history and still includes the current Sessions";
}

// A Write to EnabledFlag answers once every open Session's diagnostics object matches it, so a Client
// that browses SessionsDiagnosticsSummary after the response finds one object per Session (Part 5
// 6.3.4). The sequence is the CTT's Base Info Diagnostics 018, which sends each Write as soon as the
// last is answered; 019 browses straight after and counts Sessions from the result.
TEST_F(ComplianceWithNodes, AnAnsweredEnabledFlagWriteLeavesOneObjectPerSession)
{
  auto second = mChannel->create_session_sync({.sessionName = "SecondSessionForToggling"});
  second.activate_sync();

  for (const bool enabled : {false, true, false, true, true, false, true})
  {
    WriteRequest req;
    WriteValue wv;
    wv.node_id() = NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag};
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    wv.value() = DataValue{Variant{enabled}};
    req.nodes_to_write().push_back(std::move(wv));
    auto resp = mSession->attributes().write_sync(std::move(req));
    ASSERT_EQ(resp.results().size(), 1U);
    ASSERT_TRUE(resp.results()[0].is_good()) << to_string(resp.results()[0]);
  }

  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = false;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));
  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1U);

  std::map<std::string, int> objectsPerSession;
  for (const auto& reference : resp.results()[0].references())
  {
    if (reference.type_definition().node_id() == NodeId{ObjectTypeId::SessionDiagnosticsObjectType})
      ++objectsPerSession[std::string{static_cast<std::string_view>(reference.browse_name().name())}];
  }
  EXPECT_EQ(objectsPerSession.size(), 2U) << "both open Sessions are listed";
  for (const auto& [name, count] : objectsPerSession)
    EXPECT_EQ(count, 1) << name << " has " << count << " diagnostics objects";
  (void)second.try_close_sync();
}

// The Write answers only once every Session has caught up, not merely once the change has started: with
// many Sessions, removing or creating their objects takes longer than a Browse round trip, so a Browse sent
// on the response finds the objects as the flag says.
TEST_F(ComplianceWithNodes, AnEnabledFlagWriteIsAnsweredOnceEverySessionHasCaughtUp)
{
  constexpr size_t extraSessions = 16;
  std::vector<ua::client::Session> extra;
  for (size_t i = 0; i < extraSessions; ++i)
  {
    extra.push_back(mChannel->create_session_sync({.sessionName = "CatchUp" + std::to_string(i)}));
    extra.back().activate_sync();
  }
  const auto writeFlag = [this](bool enabled)
  {
    WriteRequest req;
    WriteValue wv;
    wv.node_id() = NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag};
    wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    wv.value() = DataValue{Variant{enabled}};
    req.nodes_to_write().push_back(std::move(wv));
    auto resp = mSession->attributes().write_sync(std::move(req));
    ASSERT_EQ(resp.results().size(), 1U);
    ASSERT_TRUE(resp.results()[0].is_good()) << to_string(resp.results()[0]);
  };
  const auto sessionObjects = [this]
  {
    BrowseRequest req;
    BrowseDescription desc;
    desc.node_id() = NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary};
    desc.browse_direction() = BrowseDirection::Forward;
    desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    desc.include_subtypes() = false;
    desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
    req.nodes_to_browse().push_back(std::move(desc));
    auto resp = mSession->view().browse_sync(std::move(req));
    size_t count = 0;
    for (const auto& reference : resp.results()[0].references())
    {
      if (reference.type_definition().node_id() == NodeId{ObjectTypeId::SessionDiagnosticsObjectType})
        ++count;
    }
    return count;
  };

  for (int round = 0; round < 3; ++round)
  {
    writeFlag(false);
    EXPECT_EQ(sessionObjects(), 0U) << "round " << round << ": objects remain after disabling";
    writeFlag(true);
    EXPECT_EQ(sessionObjects(), extraSessions + 1) << "round " << round << ": objects missing after enabling";
  }
  for (auto& session : extra)
    (void)session.try_close_sync();
}
