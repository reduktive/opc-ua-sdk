// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Event Service Set Compliance Integration Tests
///
/// Tests covering OPC UA event model, EventNotifier attributes, Server Object
/// event requirements, and BaseEventType property semantics.
///
/// Groups:
///   1 (EVT_FND/EVT_ATTR): Event Model & EventNotifier attribute checks
///   3 (EVT_SRV): Server Object event requirements
///   4 (EVT_BET): BaseEventType property semantics
///   5 (EVT_MON): Event Monitoring Setup
///   8 (EVT_NTF): EventNotificationList

#include "ua_alarm_condition_logic.h"
#include "ua_condition_instance.h"
#include "ua_conditions.h"
#include "compliance_helpers.h"
#include "ua_default_namespace.h"
#include "ua_namespace_service_delegates.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_view_services.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_base_event.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_value.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_event_filter.h"
#include "ua_event_field_list.h"
#include "ua_event_notification_list.h"
#include "ua_event_notifier_type.h"
#include "ua_filter_operator.h"
#include "ua_generic_event.h"
#include "ua_literal_operand.h"
#include "ua_method_id.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_notification_message.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_variable_id.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_attribute_operand.h"
#include "ua_content_filter_result.h"
#include "ua_element_operand.h"
#include "ua_event_filter_result.h"
#include "ua_simple_attribute_operand.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_string.h"

#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_server_configuration.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include "ua_well_known_role_permissions.h"

#include <algorithm>
#include <chrono>
#include <initializer_list>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// Helpers
// ===========================================================================

static SimpleAttributeOperand make_select_clause(const String& fieldName,
  NodeId typeDefId = NodeId{ObjectTypeId::BaseEventType},
  uint32_t attrId = static_cast<uint32_t>(AttributeId::Value))
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = std::move(typeDefId);
  clause.browse_path().push_back(QualifiedName{0, fieldName});
  clause.attribute_id() = attrId;
  return clause;
}

static Array<SimpleAttributeOperand> make_standard_select_clauses()
{
  Array<SimpleAttributeOperand> clauses;
  clauses.push_back(make_select_clause("EventId"));
  clauses.push_back(make_select_clause("EventType"));
  clauses.push_back(make_select_clause("SourceNode"));
  clauses.push_back(make_select_clause("SourceName"));
  clauses.push_back(make_select_clause("Time"));
  clauses.push_back(make_select_clause("ReceiveTime"));
  clauses.push_back(make_select_clause("Message"));
  clauses.push_back(make_select_clause("Severity"));
  return clauses;
}

static EventFilter make_event_filter(
  Array<SimpleAttributeOperand> selectClauses = {}, ContentFilter whereClause = {})
{
  EventFilter filter;
  if (selectClauses.empty())
    filter.select_clauses() = make_standard_select_clauses();
  else
    filter.select_clauses() = std::move(selectClauses);
  filter.where_clause() = std::move(whereClause);
  return filter;
}

static CreateMonitoredItemsRequest make_event_mi_request(uint32_t subscriptionId, const NodeId& nodeId,
  EventFilter filter, uint32_t clientHandle = 1, uint32_t queueSize = 10, bool discardOldest = true)
{
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);

  MonitoringParameters params;
  params.client_handle() = clientHandle;
  params.sampling_interval() = 0;
  params.queue_size() = queueSize;
  params.discard_oldest() = discardOldest;
  params.filter() = std::make_unique<EventFilter>(std::move(filter));

  MonitoredItemCreateRequest miReq;
  miReq.item_to_monitor() = std::move(rv);
  miReq.monitoring_mode() = MonitoringMode::Reporting;
  miReq.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subscriptionId;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(miReq));
  return req;
}

// Emit `event` on the server, then drain the subscription's publish queue until
// at least one EventFieldList arrives or the timeout elapses. Wraps the helper
// `collect_events(...)` so the 25 call sites in this file can stay as-is.
//
// The subscriptionId argument was absent in the pre-migration signature; we add
// it because `collect_events` filters by sub. Call sites that have only one
// active subscription pass `mSubscriptionId` from the fixture.
static std::vector<EventFieldList> emit_and_receive_events(server::Server& server, Session& session,
  uint32_t subscriptionId, BaseEvent& event,
  std::chrono::milliseconds timeout = std::chrono::milliseconds{500})
{
  server.emit_event(event);
  return collect_events(session, subscriptionId, {.minCount = 1, .timeout = timeout});
}

static uint8_t read_event_notifier_raw(Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = session.attributes().read_sync(std::move(req));
  EXPECT_EQ(resp.results().size(), 1u);
  if (!resp.results()[0].status().has_value() || resp.results()[0].status()->is_good())
  {
    auto val = resp.results()[0].value().as<uint8_t>();
    return val;
  }
  return 0;
}

static ContentFilter make_of_type_where_clause(const NodeId& typeId)
{
  LiteralOperand operand;
  operand.value() = Variant{typeId};

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> operandRef;
  operandRef = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(operand)));
  element.filter_operands().push_back(std::move(operandRef));

  ContentFilter cf;
  cf.elements().push_back(std::move(element));
  return cf;
}

// The shared TestServer maps its anonymous test identity to SecurityAdmin. That Role deliberately
// does not imply ReceiveEvents, so tests whose subject is event behaviour must author the ordinary
// per-Node permission on both Table-37 subjects. Preserve the NodeSet's other Role entries and every
// other SecurityAdmin bit: this fixture setup must not turn into a parallel authorization bypass.
static void grant_shared_test_identity_event_delivery(
  server::Server& server, std::initializer_list<NodeId> subjects)
{
  const NodeId roleId = well_known_role_node_id(WellKnownRole::SecurityAdmin);
  for (const auto& subject : subjects)
  {
    auto node = server.address_space().find_node_sync(subject);
    auto permissions = node.get_role_permissions().value_or(std::vector<RolePermissionType>{});
    const auto found = std::find_if(permissions.begin(),
      permissions.end(),
      [&roleId](const RolePermissionType& entry) { return entry.role_id() == roleId; });
    if (found != permissions.end())
    {
      found->permissions().set(PermissionType::Bit::ReceiveEvents);
    }
    else
    {
      auto rolePermissions = make_well_known_role_permission(
        WellKnownRole::SecurityAdmin, well_known_role_permissions(WellKnownRole::SecurityAdmin));
      rolePermissions.permissions().set(PermissionType::Bit::ReceiveEvents);
      permissions.push_back(std::move(rolePermissions));
    }
    node.set_role_permissions(std::move(permissions));
  }
}

// ===========================================================================
// Fixtures
// ===========================================================================

class ComplianceEventBase : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    ComplianceWithSession::configure_server();
    grant_shared_test_identity_event_delivery(
      mServer.server(), {NodeId{ObjectId::Server}, NodeId{ObjectTypeId::BaseEventType}});
  }

  void SetUp() override
  {
    ComplianceWithSession::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  }

  void TearDown() override
  {
    if (mSession)
    {
      delete_subscription(*mSession, mSubscriptionId);
    }
    ComplianceWithSession::TearDown();
  }

  uint32_t mSubscriptionId{0};
};

class ComplianceEventWithNodes : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    grant_shared_test_identity_event_delivery(
      mServer.server(), {NodeId{ObjectId::Server}, NodeId{ObjectTypeId::BaseEventType}});

    // Event-enabled object with SubscribeToEvents
    mEventSourceId = NodeId{mTestNamespaceIndex, uint32_t{5000}};
    auto eventNode = addressSpace.create_node_sync(mEventSourceId, NodeClass::Object);
    auto eventObj = eventNode.as<ObjectAccessor>();
    ASSERT_TRUE(eventObj.has_value());
    eventObj->set_browse_name(QualifiedName{mTestNamespaceIndex, "EventSource"});
    eventObj->set_display_name(LocalizedText{"", "EventSource"});
    eventObj->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

    // HasNotifier from Server Object to event source
    auto serverNode = addressSpace.find_node_sync(NodeId{ObjectId::Server});
    serverNode.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, mEventSourceId);

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mEventSourceId);

    // Object without SubscribeToEvents
    mNoEventObjectId = NodeId{mTestNamespaceIndex, uint32_t{5001}};
    auto noEventNode = addressSpace.create_node_sync(mNoEventObjectId, NodeClass::Object);
    auto noEventObj = noEventNode.as<ObjectAccessor>();
    ASSERT_TRUE(noEventObj.has_value());
    noEventObj->set_browse_name(QualifiedName{mTestNamespaceIndex, "NoEventObject"});
    noEventObj->set_display_name(LocalizedText{"", "NoEventObject"});
    noEventObj->set_event_notifier(EventNotifierType{});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mNoEventObjectId);
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  }

  void TearDown() override
  {
    if (mSession)
    {
      delete_subscription(*mSession, mSubscriptionId);
    }
    ComplianceWithNodes::TearDown();
  }

  NodeId mEventSourceId;
  NodeId mNoEventObjectId;
  uint32_t mSubscriptionId{0};
};

// ===========================================================================
// Group 1: Event Model & EventNotifier (6 tests) - ComplianceWithSession
// ===========================================================================

// EVT_FND_001: Server Object has EventNotifier with SubscribeToEvents bit set
// @relation(AC-SVR-EVT-FND-001-AT-LEAST-ONE-NOTIFIER, scope=function)
TEST_F(ComplianceWithSession, EVT_FND_001_ServerExposesEventNotifier)
{
  auto raw = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
  EventNotifierType en{raw};
  EXPECT_TRUE(en.test(EventNotifierType::Bit::SubscribeToEvents))
    << "Server Object EventNotifier should have SubscribeToEvents bit set, got: " << static_cast<int>(raw);
}

// EVT_ATTR_001: Objects have EventNotifier attribute readable
// @relation(SVR-EVT-ATTR-001, scope=function)
TEST_F(ComplianceWithSession, EVT_ATTR_001_EventNotifierMandatoryOnObjects)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{ObjectId::Server};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  // Should not return BadAttributeIdInvalid (0x80860000)
  if (resp.results()[0].status().has_value())
  {
    EXPECT_NE(resp.results()[0].status()->as_uint32(), 0x80860000u)
      << "EventNotifier attribute should be readable on Objects";
  }
}

// EVT_ATTR_004: Views have EventNotifier attribute readable
// Part 3, Section 5.4, Table 10: EventNotifier is Mandatory on View NodeClass.
// The ViewsFolder (i=87) is an Object, not a View. We browse it for actual View children.
// If no Views exist in the address space, the requirement is vacuously satisfied.
// @relation(SVR-EVT-ATTR-004, scope=function)
TEST_F(ComplianceWithSession, EVT_ATTR_004_EventNotifierMandatoryOnViews)
{
  // Browse ViewsFolder for any View children
  BrowseRequest browseReq;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::ViewsFolder};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.include_subtypes() = true;
  desc.node_class_mask() = static_cast<uint32_t>(NodeClass::View);
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  browseReq.nodes_to_browse().push_back(std::move(desc));

  auto browseResp = mSession->view().browse_sync(std::move(browseReq));
  ASSERT_TRUE(browseResp.response_header().service_result().is_good());
  ASSERT_EQ(browseResp.results().size(), 1u);

  if (browseResp.results()[0].references().empty())
  {
    // No View nodes exist - requirement is vacuously satisfied
    SUCCEED() << "No View nodes found under ViewsFolder - requirement is vacuously met";
    return;
  }

  // Read EventNotifier on the first View found
  auto viewNodeId = browseResp.results()[0].references()[0].node_id().node_id();
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = viewNodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  // Should not return BadAttributeIdInvalid (0x80860000)
  if (resp.results()[0].status().has_value())
  {
    EXPECT_NE(resp.results()[0].status()->as_uint32(), 0x80860000u)
      << "EventNotifier attribute should be readable on View nodes";
  }
}

// EVT_ATTR_008: SubscribeToEvents bit (bit 0) set on Server Object
// @relation(SVR-EVT-ATTR-008, scope=function)
TEST_F(ComplianceWithSession, EVT_ATTR_008_SubscribeToEventsBitSet)
{
  auto raw = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
  EXPECT_TRUE((raw & 0x01) != 0)
    << "Server Object EventNotifier bit 0 (SubscribeToEvents) should be set, got: 0x" << std::hex
    << static_cast<int>(raw);
}

// EVT_ATTR_009: Reserved bit 1 is zero
// @relation(SVR-EVT-ATTR-009, scope=function)
TEST_F(ComplianceWithSession, EVT_ATTR_009_ReservedBit1AlwaysZero)
{
  auto raw = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
  EXPECT_EQ(raw & 0x02, 0u) << "EventNotifier reserved bit 1 should be zero, got: 0x" << std::hex
                            << static_cast<int>(raw);
}

// EVT_ATTR_012: Reserved bits 4-7 are zero
// @relation(SVR-EVT-ATTR-012, scope=function)
TEST_F(ComplianceWithSession, EVT_ATTR_012_ReservedBits4to7AlwaysZero)
{
  auto raw = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
  EXPECT_EQ(raw & 0xF0, 0u) << "EventNotifier reserved bits 4-7 should be zero, got: 0x" << std::hex
                            << static_cast<int>(raw);
}

// ===========================================================================
// Group 3: Server Object Event Requirements (4 tests) - ComplianceEventBase
// ===========================================================================

// EVT_SRV_001: Server Object EventNotifier set for event subscriptions
// @verifies AC-SVR-ADDRSP-015-EVENTING-NOTIFIER-EXISTS
TEST_F(ComplianceEventBase, EVT_SRV_001_ServerObjectIsRootNotifier)
{
  auto raw = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
  EventNotifierType en{raw};
  EXPECT_TRUE(en.test(EventNotifierType::Bit::SubscribeToEvents));
}

// EVT_SRV_002: Subscribe to Server Object -> receives all server events
TEST_F(ComplianceEventBase, EVT_SRV_002_AllEventsViaServerObject)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "Failed to create event MI: 0x" << std::hex << miResp.results()[0].status_code().as_uint32();

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "Test event for SRV_002"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_GE(events.size(), 1u) << "Should receive at least 1 event via Server Object subscription";
}

// EVT_SRV_003: EventTypesFolder contains only ObjectTypes
TEST_F(ComplianceEventBase, EVT_SRV_003_EventTypesObjectContainsOnlyObjectTypes)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::EventTypesFolder};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good());

  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.reference_type_id() == NodeId{ReferenceTypeId::Organizes})
    {
      EXPECT_EQ(ref.node_class(), NodeClass::ObjectType)
        << "EventTypesFolder child " << std::string{ref.browse_name().name()}
        << " should be ObjectType but is " << static_cast<int>(ref.node_class());
    }
  }
}

// EVT_SRV_004: BaseEventType reachable under EventTypesFolder
TEST_F(ComplianceEventBase, EVT_SRV_004_AllEventTypesExposed)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::EventTypesFolder};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), 1u);

  bool foundBaseEventType = false;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_id().node_id() == NodeId{ObjectTypeId::BaseEventType})
    {
      foundBaseEventType = true;
      break;
    }
  }
  EXPECT_TRUE(foundBaseEventType) << "BaseEventType should be under EventTypesFolder";
}

// ===========================================================================
// Group 4: BaseEventType Properties (7 tests) - ComplianceEventBase
// ===========================================================================
//
// Standard select clause order:
//   [0]=EventId, [1]=EventType, [2]=SourceNode, [3]=SourceName,
//   [4]=Time, [5]=ReceiveTime, [6]=Message, [7]=Severity

// EVT_BET_001: EventId always present as non-empty ByteString
TEST_F(ComplianceEventBase, EVT_BET_001_EventIdAlwaysPresent)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_001"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 0 = EventId (should be ByteString, non-empty)
  const auto& eventId = events[0].event_fields()[0];
  EXPECT_FALSE(eventId.empty()) << "EventId should not be null";
  auto bs = eventId.as<ByteString>();
  EXPECT_FALSE(bs.empty()) << "EventId should not be empty";
}

// EVT_BET_002: EventType always present as NodeId
TEST_F(ComplianceEventBase, EVT_BET_002_EventTypeAlwaysPresent)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_002"};
  event.severity = 200;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 1 = EventType (should be a NodeId)
  const auto& eventType = events[0].event_fields()[1];
  EXPECT_FALSE(eventType.empty()) << "EventType should not be null";
  auto typeId = eventType.as<NodeId>();
  EXPECT_EQ(typeId, NodeId{ObjectTypeId::BaseEventType});
}

// EVT_BET_003: EventId unique across events
TEST_F(ComplianceEventBase, EVT_BET_003_EventIdUnique)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit first event
  GenericEvent event1{NodeId{ObjectTypeId::BaseEventType}};
  event1.sourceNode = NodeId{ObjectId::Server};
  event1.sourceName = "Test";
  event1.message = LocalizedText{"", "BET_003_1"};
  event1.severity = 100;
  auto events1 = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event1);
  ASSERT_GE(events1.size(), 1u);

  // Emit second event
  GenericEvent event2{NodeId{ObjectTypeId::BaseEventType}};
  event2.sourceNode = NodeId{ObjectId::Server};
  event2.sourceName = "Test";
  event2.message = LocalizedText{"", "BET_003_2"};
  event2.severity = 200;
  auto events2 = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event2);
  ASSERT_GE(events2.size(), 1u);

  auto id1 = events1[0].event_fields()[0].as<ByteString>();
  auto id2 = events2[0].event_fields()[0].as<ByteString>();
  EXPECT_NE(id1, id2) << "EventId should be unique across events";
}

// EVT_BET_004: Time not altered by server
TEST_F(ComplianceEventBase, EVT_BET_004_TimeNotAltered)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Set an explicit time
  DateTime explicitTime{2025, 6, 15, 12, 0, 0.0};
  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_004"};
  event.severity = 100;
  event.time = explicitTime;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 4 = Time
  const auto& timeField = events[0].event_fields()[4];
  EXPECT_FALSE(timeField.empty()) << "Time should not be null";
  auto receivedTime = timeField.as<DateTime>();
  EXPECT_EQ(receivedTime, explicitTime) << "Server should not alter the Time field";
}

// EVT_BET_005: ReceiveTime always present
TEST_F(ComplianceEventBase, EVT_BET_005_ReceiveTimeAlwaysPresent)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_005"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 5 = ReceiveTime
  const auto& receiveTime = events[0].event_fields()[5];
  EXPECT_FALSE(receiveTime.empty()) << "ReceiveTime should not be null";
}

// EVT_BET_006: Message never null
TEST_F(ComplianceEventBase, EVT_BET_006_MessageNeverNull)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_006 test message"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 6 = Message
  const auto& message = events[0].event_fields()[6];
  EXPECT_FALSE(message.empty()) << "Message should not be null";
}

// EVT_BET_007: Severity between 1 and 1000
TEST_F(ComplianceEventBase, EVT_BET_007_SeverityRange1to1000)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "BET_007"};
  event.severity = 500;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Field 7 = Severity
  const auto& severity = events[0].event_fields()[7];
  EXPECT_FALSE(severity.empty()) << "Severity should not be null";
  auto sevVal = severity.as<uint16_t>();
  EXPECT_GE(sevVal, 1u) << "Severity should be >= 1";
  EXPECT_LE(sevVal, 1000u) << "Severity should be <= 1000";
}

// ===========================================================================
// Group 5: Event Monitoring Setup (13 tests) - ComplianceEventWithNodes
// ===========================================================================

// EVT_MON_001: Create event MI on Server Object, emit event, verify received
TEST_F(ComplianceEventWithNodes, EVT_MON_001_SubscribeToEventsViaEventNotifier)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "Failed to create event MI: 0x" << std::hex << miResp.results()[0].status_code().as_uint32();

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "Test";
  event.message = LocalizedText{"", "MON_001 event"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_GE(events.size(), 1u) << "Should receive at least 1 event via Server Object subscription";
}

// EVT_MON_001: Create event MI on object without SubscribeToEvents bit - should be rejected
// Covers SVR-MI-GEN-070 (coverage-audit retag).
TEST_F(ComplianceEventWithNodes, EVT_MON_001_SubscribeToEventsWithoutBit_Rejected)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, mNoEventObjectId, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  EXPECT_FALSE(miResp.results()[0].status_code().is_good())
    << "Creating event MI on object without SubscribeToEvents bit should fail, got: 0x" << std::hex
    << miResp.results()[0].status_code().as_uint32();
}

// EVT_MON_002: Event MI with samplingInterval=0 should succeed, revised should be 0
TEST_F(ComplianceEventWithNodes, EVT_MON_002_SamplingIntervalZeroForEvents)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  // samplingInterval is already 0 from make_event_mi_request
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  EXPECT_EQ(miResp.results()[0].revised_sampling_interval(), 0.0)
    << "Event MI sampling interval should be revised to 0";
}

// EVT_MON_003: Event MI created with EventNotifier attribute should be accepted
TEST_F(ComplianceEventWithNodes, EVT_MON_003_AttributeIdIsEventNotifier)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  // make_event_mi_request already sets AttributeId::EventNotifier
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "Event MI with EventNotifier attribute should be accepted, got: 0x" << std::hex
    << miResp.results()[0].status_code().as_uint32();
}

// EVT_MON_004: Event MI with queueSize=0 should return revised > 0
TEST_F(ComplianceEventWithNodes, EVT_MON_004_QueueSizeZeroReturnsDefault)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/0);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  EXPECT_GT(miResp.results()[0].revised_queue_size(), 0u)
    << "Requesting queueSize=0 should return a revised queue size > 0";
}

// EVT_MON_005: Huge queueSize should be revised down
TEST_F(ComplianceEventWithNodes, EVT_MON_005_QueueSizeRevisedWithinBounds)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/999999);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  EXPECT_LT(miResp.results()[0].revised_queue_size(), 999999u)
    << "Huge queueSize should be revised down by the server";
}

// EVT_MON_006: Event queue overflow generates EventQueueOverflowEventType
TEST_F(ComplianceEventWithNodes, EVT_MON_006_EventQueueOverflowEventGenerated)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Use revised queue size to ensure we emit enough events to overflow
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  // Emit events rapidly without publishing between them
  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MON_006 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Now publish and collect all events
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Check for EventQueueOverflowEventType in received events (field 1 = EventType)
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  bool foundOverflow = false;
  for (const auto& efl : collected)
  {
    if (efl.event_fields().size() > 1)
    {
      auto typeId = efl.event_fields()[1].as<NodeId>();
      if (typeId == overflowTypeId)
      {
        foundOverflow = true;
        break;
      }
    }
  }
  EXPECT_TRUE(foundOverflow) << "Should receive EventQueueOverflowEventType when queue overflows";
}

// EVT_MON_007: Overflow event is in addition to queueSize
TEST_F(ComplianceEventWithNodes, EVT_MON_007_OverflowEventInAdditionToQueueSize)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  // Emit events rapidly without publishing
  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MON_007 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Collect all events
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Total events should be revisedQueueSize + 1 (overflow event is extra)
  EXPECT_EQ(collected.size(), revisedQueueSize + 1)
    << "Total events in publish should be revisedQueueSize + 1 (overflow event is extra)";
}

// EVT_MON_008: With discardOldest=true, overflow event should be first in notification list
TEST_F(ComplianceEventWithNodes, EVT_MON_008_OverflowEventPositionDiscardOldest)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  // Emit events rapidly without publishing
  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MON_008 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Collect all events
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  ASSERT_GE(collected.size(), 1u);
  // With discardOldest=true, overflow event should be at index 0
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  ASSERT_GT(collected[0].event_fields().size(), 1u);
  auto firstEventType = collected[0].event_fields()[1].as<NodeId>();
  EXPECT_EQ(firstEventType, overflowTypeId)
    << "With discardOldest=true, overflow event should be first in notification list";
}

// EVT_MON_010: Notifications maintain emission order
TEST_F(ComplianceEventWithNodes, EVT_MON_010_NotificationsInQueueOrder)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/10);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit 3 events with severity 100, 200, 300
  for (uint16_t sev : {100, 200, 300})
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OrderTest";
    event.message = LocalizedText{"", "MON_010 sev=" + std::to_string(sev)};
    event.severity = sev;
    mServer.server().emit_event(event);
  }

  // Collect events
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (collected.size() >= 3)
      break;
  }

  ASSERT_GE(collected.size(), 3u) << "Should receive at least 3 events";

  // Field 7 = Severity. Verify order matches emission order.
  auto sev0 = collected[0].event_fields()[7].as<uint16_t>();
  auto sev1 = collected[1].event_fields()[7].as<uint16_t>();
  auto sev2 = collected[2].event_fields()[7].as<uint16_t>();
  EXPECT_EQ(sev0, 100u);
  EXPECT_EQ(sev1, 200u);
  EXPECT_EQ(sev2, 300u);
}

// EVT_MON_012: First sample reported immediately after MI creation
TEST_F(ComplianceEventWithNodes, EVT_MON_012_FirstSampleReportedImmediately)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Immediately emit event
  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "ImmediateTest";
  event.message = LocalizedText{"", "MON_012 immediate"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_GE(events.size(), 1u) << "First event should be reported immediately after MI creation";
}

// ===========================================================================
// Group 8: EventNotificationList (3 tests) - ComplianceEventBase
// ===========================================================================

// EVT_NTF_001: Field order matches select clauses
TEST_F(ComplianceEventBase, EVT_NTF_001_FieldOrderMatchesSelectClauses)
{
  // Create custom select clauses: [Severity, EventId, SourceName]
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("Severity"));
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("SourceName"));

  auto filter = make_event_filter(std::move(selectClauses));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "NTF001Source";
  event.message = LocalizedText{"", "NTF_001"};
  event.severity = 750;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);
  ASSERT_GE(events[0].event_fields().size(), 3u);

  // fields[0] = Severity (uint16_t)
  auto severityVal = events[0].event_fields()[0].as<uint16_t>();
  EXPECT_EQ(severityVal, 750u) << "fields[0] should be Severity";

  // fields[1] = EventId (ByteString, non-empty)
  auto eventId = events[0].event_fields()[1].as<ByteString>();
  EXPECT_FALSE(eventId.empty()) << "fields[1] should be EventId (ByteString)";

  // fields[2] = SourceName (String)
  auto sourceName = events[0].event_fields()[2].as<String>();
  EXPECT_EQ(sourceName, String{"NTF001Source"}) << "fields[2] should be SourceName";
}

// EVT_NTF_002: EventFieldList has exactly as many fields as select clauses
TEST_F(ComplianceEventBase, EVT_NTF_002_EventFieldsOneToOneWithSelect)
{
  // Select 3 fields
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("Severity"));
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("SourceName"));

  auto filter = make_event_filter(std::move(selectClauses));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "NTF002Source";
  event.message = LocalizedText{"", "NTF_002"};
  event.severity = 200;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_GE(events.size(), 1u);

  // Each EventFieldList should have exactly 3 event_fields
  for (size_t i = 0; i < events.size(); ++i)
  {
    EXPECT_EQ(events[i].event_fields().size(), 3u)
      << "EventFieldList[" << i << "] should have exactly 3 fields matching the 3 select clauses";
  }
}

// EVT_NTF_003: Multiple notifications maintain emission order
TEST_F(ComplianceEventBase, EVT_NTF_003_MultipleNotificationsInQueueOrder)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/10);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit 3 events rapidly with severity 100, 200, 300
  for (uint16_t sev : {100, 200, 300})
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "NTF003Source";
    event.message = LocalizedText{"", "NTF_003 sev=" + std::to_string(sev)};
    event.severity = sev;
    mServer.server().emit_event(event);
  }

  // Collect events
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (collected.size() >= 3)
      break;
  }

  ASSERT_GE(collected.size(), 3u) << "Should receive all 3 events";

  // Field 7 = Severity in standard select. Verify order.
  auto sev0 = collected[0].event_fields()[7].as<uint16_t>();
  auto sev1 = collected[1].event_fields()[7].as<uint16_t>();
  auto sev2 = collected[2].event_fields()[7].as<uint16_t>();
  EXPECT_EQ(sev0, 100u);
  EXPECT_EQ(sev1, 200u);
  EXPECT_EQ(sev2, 300u);
}

// ===========================================================================
// Group 6: EventFilter - Select Clauses (12 tests) - ComplianceEventBase
// ===========================================================================

// EVT_FLT_001: Filter match triggers notification
TEST_F(ComplianceEventBase, EVT_FLT_001_FilterMatchTriggersNotification)
{
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT001";
  event.message = LocalizedText{"", "FilterMatchTest"};
  event.severity = 500;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_FALSE(events.empty()) << "Should receive event notification when filter matches";
}

// EVT_FLT_002: Select clause fields appear in notification
TEST_F(ComplianceEventBase, EVT_FLT_002_SelectClauseFieldsInNotification)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("Severity"));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT002";
  event.message = LocalizedText{"", "SelectFieldsTest"};
  event.severity = 750;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive at least one event";
  ASSERT_EQ(events[0].event_fields().size(), 2u) << "Should have exactly 2 fields (EventId, Severity)";
  EXPECT_FALSE(events[0].event_fields()[0].empty()) << "EventId should not be null";
  EXPECT_FALSE(events[0].event_fields()[1].empty()) << "Severity should not be null";
  EXPECT_EQ(events[0].event_fields()[1].as<uint16_t>(), 750u);
}

// EVT_FLT_003: At least one select clause is required
TEST_F(ComplianceEventBase, EVT_FLT_003_AtLeastOneSelectClauseRequired)
{
  // Build EventFilter with empty select clauses
  EventFilter filter;
  filter.select_clauses() = Array<SimpleAttributeOperand>{};  // empty
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});

  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  EXPECT_FALSE(miResp.results()[0].status_code().is_good())
    << "Empty select clauses should be rejected (BadEventFilterInvalid or similar)";
}

// EVT_FLT_004: BaseEventType in typeDefinitionId resolves fields on subtypes
// Covers SVR-MI-EVT-002 (coverage-audit retag).
TEST_F(ComplianceEventBase, EVT_FLT_004_BaseEventTypeIgnoresTypeDefinitionId)
{
  // Select Severity with typeDefinitionId = BaseEventType
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("Severity", NodeId{ObjectTypeId::BaseEventType}));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit a BaseEventType event
  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT004";
  event.message = LocalizedText{"", "TypeDefTest"};
  event.severity = 300;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive event";
  ASSERT_GE(events[0].event_fields().size(), 1u);
  EXPECT_FALSE(events[0].event_fields()[0].empty()) << "Severity should resolve via BaseEventType";
  EXPECT_EQ(events[0].event_fields()[0].as<uint16_t>(), 300u);
}

// EVT_FLT_005: Browse path instance declarations shall be Object or Variable nodes.
// Tested by selecting a field that doesn't resolve to Object/Variable - should return null.
// Part 4, 7.22.3: "Each InstanceDeclaration in the browsePath shall be an Object or Variable Node."
// Covers SVR-EVT-FLT-007 (coverage-audit retag).
TEST_F(ComplianceEventBase, EVT_FLT_005_BrowsePathOnlyObjectOrVariable)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("NonExistentField"));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT005";
  event.message = LocalizedText{"", "BrowsePathTest"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive event";
  ASSERT_GE(events[0].event_fields().size(), 2u);
  EXPECT_TRUE(events[0].event_fields()[1].empty()) << "Non-existent field should return null Variant";
}

// EVT_FLT_006: EventId (Variable attribute) and SourceNode (NodeId property) both non-null
// Covers SVR-EVT-FLT-008, SVR-MI-EVT-003 (coverage-audit retag).
TEST_F(ComplianceEventBase, EVT_FLT_006_ValueAttributeForVariableNodeIdForObject)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("SourceNode"));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT006";
  event.message = LocalizedText{"", "ValueAttrTest"};
  event.severity = 200;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive event";
  ASSERT_GE(events[0].event_fields().size(), 2u);
  EXPECT_FALSE(events[0].event_fields()[0].empty()) << "EventId should be non-null";
  EXPECT_FALSE(events[0].event_fields()[1].empty()) << "SourceNode should be non-null";
}

// EVT_FLT_009: Null returned for missing/non-existent field
TEST_F(ComplianceEventBase, EVT_FLT_009_NullReturnedForMissingField)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("SomeNonExistentProperty"));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT009";
  event.message = LocalizedText{"", "MissingFieldTest"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive event";
  ASSERT_GE(events[0].event_fields().size(), 2u);
  EXPECT_TRUE(events[0].event_fields()[1].empty()) << "Non-existent property should return null Variant";
}

// EVT_FLT_014: Mandatory fields (EventId, EventType, ReceiveTime) never null
// Covers SVR-MI-EVT-014 (coverage-audit retag).
TEST_F(ComplianceEventBase, EVT_FLT_014_MandatoryFieldsNeverNull)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("EventType"));
  selectClauses.push_back(make_select_clause("ReceiveTime"));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT014";
  event.message = LocalizedText{"", "MandatoryFieldsTest"};
  event.severity = 400;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  ASSERT_FALSE(events.empty()) << "Should receive event";
  ASSERT_GE(events[0].event_fields().size(), 3u);
  EXPECT_FALSE(events[0].event_fields()[0].empty()) << "EventId must never be null";
  EXPECT_FALSE(events[0].event_fields()[1].empty()) << "EventType must never be null";
  EXPECT_FALSE(events[0].event_fields()[2].empty()) << "ReceiveTime must never be null";
}

// EVT_FLT_015: Select clauses validated on MI creation
TEST_F(ComplianceEventBase, EVT_FLT_015_SelectClausesValidatedOnCreate)
{
  Array<SimpleAttributeOperand> selectClauses;
  // Valid clause
  selectClauses.push_back(make_select_clause("EventId"));
  // Invalid clause: empty browse path
  SimpleAttributeOperand invalidClause;
  invalidClause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  // Leave browse_path empty - this is invalid for event field selection
  invalidClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  selectClauses.push_back(std::move(invalidClause));

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // The MI may still be created (Good) but with filter_result containing per-clause status
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  if (efr != nullptr)
  {
    // If EventFilterResult is returned, check select_clause_results
    ASSERT_GE(efr->select_clause_results().size(), 2u) << "Should have results for both select clauses";
    EXPECT_TRUE(efr->select_clause_results()[0].is_good()) << "First clause (EventId) should be Good";
    // Second clause (empty browse path) should have a non-Good status
    EXPECT_FALSE(efr->select_clause_results()[1].is_good())
      << "Invalid select clause should have non-Good status";
  }
  else
  {
    // If no EventFilterResult returned, the MI itself should have failed
    EXPECT_FALSE(miResp.results()[0].status_code().is_good())
      << "Either EventFilterResult with errors or MI rejection expected";
  }
}

// EVT_FLT_016: No errors for state-dependent optional fields
TEST_F(ComplianceEventBase, EVT_FLT_016_NoErrorsForStateDependent)
{
  Array<SimpleAttributeOperand> selectClauses;
  selectClauses.push_back(make_select_clause("EventId"));
  selectClauses.push_back(make_select_clause("LocalTime"));  // optional field

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(std::move(selectClauses), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // MI creation should succeed - state-dependent errors are deferred
  EXPECT_TRUE(miResp.results()[0].status_code().is_good())
    << "MI creation should succeed for optional/state-dependent fields";

  // If EventFilterResult is returned, selectClauseResults should all be Good
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  if (efr != nullptr && !efr->select_clause_results().empty())
  {
    for (size_t i = 0; i < efr->select_clause_results().size(); ++i)
    {
      EXPECT_TRUE(efr->select_clause_results()[i].is_good())
        << "Select clause result [" << i << "] should be Good for state-dependent fields";
    }
  }
}

// ===========================================================================
// Group 7: EventFilter - Where Clause (7 tests) - ComplianceEventBase
// ===========================================================================

// EVT_FLT_019: OfType operator is supported
TEST_F(ComplianceEventBase, EVT_FLT_019_OfTypeOperatorSupported)
{
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "OfType operator should be supported for event filtering";

  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT019";
  event.message = LocalizedText{"", "OfTypeTest"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_FALSE(events.empty()) << "OfType(BaseEventType) should match emitted BaseEventType event";
}

// EVT_FLT_020: Where clause validated on MI creation
TEST_F(ComplianceEventBase, EVT_FLT_020_WhereClauseValidatedOnCreate)
{
  // Build invalid where clause: OfType with no operands
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  // No operands - this is invalid (OfType requires exactly 1 operand)

  ContentFilter invalidWhere;
  invalidWhere.elements().push_back(std::move(element));

  auto filter = make_event_filter(make_standard_select_clauses(), std::move(invalidWhere));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // Either MI creation fails or filter_result contains where clause errors
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  if (efr != nullptr)
  {
    auto& wcResult = efr->where_clause_result();
    if (!wcResult.element_results().empty())
    {
      EXPECT_FALSE(wcResult.element_results()[0].status_code().is_good())
        << "OfType with no operands should produce error in where clause result";
    }
  }
  else
  {
    // MI itself should have failed
    EXPECT_FALSE(miResp.results()[0].status_code().is_good())
      << "Invalid where clause should be rejected at MI creation time";
  }
}

// EVT_FLT_021: AttributeOperand not allowed in EventFilter where clause
TEST_F(ComplianceEventBase, EVT_FLT_021_AttributeOperandNotAllowed)
{
  // Build where clause with OfType using an AttributeOperand instead of LiteralOperand
  AttributeOperand attrOp;
  attrOp.node_id() = NodeId{ObjectTypeId::BaseEventType};
  attrOp.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> operandRef;
  operandRef = std::unique_ptr<Structure>(std::make_unique<AttributeOperand>(std::move(attrOp)));
  element.filter_operands().push_back(std::move(operandRef));

  ContentFilter whereClause;
  whereClause.elements().push_back(std::move(element));

  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // Either MI creation fails or filter_result contains errors for the AttributeOperand
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  if (efr != nullptr)
  {
    auto& wcResult = efr->where_clause_result();
    if (!wcResult.element_results().empty())
    {
      // The element or its operand should report an error
      bool hasError = !wcResult.element_results()[0].status_code().is_good();
      if (!hasError && !wcResult.element_results()[0].operand_status_codes().empty())
      {
        hasError = !wcResult.element_results()[0].operand_status_codes()[0].is_good();
      }
      EXPECT_TRUE(hasError) << "AttributeOperand should be rejected in EventFilter where clause";
    }
  }
  else
  {
    EXPECT_FALSE(miResp.results()[0].status_code().is_good())
      << "AttributeOperand in EventFilter should be rejected";
  }
}

// EVT_FLT_022: Overflow event bypasses where clause
// The where clause filters for BaseEventType (matching emitted events) but NOT
// EventQueueOverflowEventType. Events fill the queue, causing overflow. The overflow
// event must still be delivered despite not matching the where clause.
TEST_F(ComplianceEventBase, EVT_FLT_022_OverflowEventBypassesWhereClause)
{
  // Filter for BaseEventType - emitted events match, but EventQueueOverflowEventType
  // is a subtype of BaseEventType so it would also match OfType(BaseEventType).
  // Instead, use a narrow where clause that matches only a specific subtype that we emit,
  // but would NOT match EventQueueOverflowEventType.
  // SystemEventType (i=2130) is a subtype of BaseEventType.
  // EventQueueOverflowEventType (i=3035) is also a subtype of BaseEventType but NOT of SystemEventType.
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::SystemEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit enough SystemEventType events to overflow the queue (size 2).
  for (int i = 0; i < 10; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::SystemEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "FLT022";
    event.message = LocalizedText{"", "OverflowBypass " + std::to_string(i)};
    event.severity = 100;
    mServer.server().emit_event(event);
  }

  // Collect all notifications.
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 10; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  ASSERT_FALSE(collected.empty()) << "Should receive events after overflow";

  // Check that at least one event is EventQueueOverflowEventType (i=3035).
  // EventType is at index 1 in standard select clauses.
  bool foundOverflow = false;
  for (const auto& efl : collected)
  {
    if (efl.event_fields().size() > 1 && !efl.event_fields()[1].empty())
    {
      auto eventType = efl.event_fields()[1].as<NodeId>();
      if (eventType == NodeId{ObjectTypeId::EventQueueOverflowEventType})
      {
        foundOverflow = true;
        break;
      }
    }
  }
  EXPECT_TRUE(foundOverflow) << "EventQueueOverflowEventType should bypass the where clause and be delivered";
}

// EVT_FLT_023: OfType matches subtypes
TEST_F(ComplianceEventBase, EVT_FLT_023_OfTypeMatchesSubtypes)
{
  // OfType(BaseEventType) should match all events since all event types are subtypes
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit a GenericEvent with a specific subtype (SystemEventType = 2130) - NOT BaseEventType itself.
  // OfType(BaseEventType) should match because SystemEventType is a subtype of BaseEventType.
  GenericEvent event{NodeId{ObjectTypeId::SystemEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT023";
  event.message = LocalizedText{"", "SubtypeMatchTest"};
  event.severity = 600;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_FALSE(events.empty()) << "OfType(BaseEventType) should match subtypes like SystemEventType";
}

// EVT_FLT_024: OfType with invalid NodeId returns false (no events match)
TEST_F(ComplianceEventBase, EVT_FLT_024_OfTypeInvalidNodeIdReturnsFalse)
{
  // Use a non-existent type NodeId
  NodeId bogusType{99, 99999};
  auto whereClause = make_of_type_where_clause(bogusType);
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // Per spec, OfType with a non-existent NodeId should evaluate to false at runtime,
  // not necessarily reject the filter at creation. However, server-side validation that
  // rejects early is also reasonable.
  if (!miResp.results()[0].status_code().is_good())
  {
    // Server chose to reject early - acceptable alternative behavior
    return;
  }

  // Emit event - where clause should always evaluate to false
  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = "FLT024";
  event.message = LocalizedText{"", "InvalidTypeTest"};
  event.severity = 100;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_TRUE(events.empty()) << "OfType with non-existent type should not match any events";
}

// EVT_FLT_025: OfType matches a DEEP subtype against an INTERMEDIATE parent type
// (not just BaseEventType). This is the discriminating subtype case: a runtime
// GenericEvent of AuditCreateSessionEventType must match OfType(AuditEventType)
// because AuditCreateSessionEventType  subset of  AuditSessionEventType  subset of  AuditEventType.
// The match is resolved against the server's address-space HasSubtype hierarchy
// (Part 4 section 7.7.3), exercising the full event-type chain - not just the root.
TEST_F(ComplianceEventBase, EVT_FLT_025_OfTypeMatchesDeepSubtypeOfIntermediateParent)
{
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::AuditEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // A grandchild of AuditEventType, emitted as a runtime GenericEvent.
  GenericEvent matching{NodeId{ObjectTypeId::AuditCreateSessionEventType}};
  matching.sourceNode = NodeId{ObjectId::Server};
  matching.sourceName = "FLT025";
  matching.message = LocalizedText{"", "DeepSubtypeMatch"};
  matching.severity = 600;
  auto matched = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, matching);
  EXPECT_FALSE(matched.empty()) << "OfType(AuditEventType) must match a runtime event of a deep subtype";

  // A System-branch event must NOT match OfType(AuditEventType).
  GenericEvent unrelated{NodeId{ObjectTypeId::SystemStatusChangeEventType}};
  unrelated.sourceNode = NodeId{ObjectId::Server};
  unrelated.sourceName = "FLT025b";
  unrelated.message = LocalizedText{"", "UnrelatedBranch"};
  unrelated.severity = 600;
  auto unmatched = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, unrelated);
  EXPECT_TRUE(unmatched.empty()) << "OfType(AuditEventType) must NOT match an unrelated (System) branch";
}

// EVT_FLT_026: OfType matches a CUSTOM event type registered at RUNTIME (after
// server start) as a subtype of a standard type. This is the core capability the
// address-space-resolved design adds over a baked/compile-time table: the event
// type does not exist at build time, has no C++ class (emitted as a GenericEvent),
// and its supertype chain is resolved lazily from the LIVE address space at
// dispatch. OfType(AuditEventType) must match it; an unrelated custom subtype must not.
TEST_F(ComplianceEventWithNodes, EVT_FLT_026_OfTypeMatchesRuntimeRegisteredCustomEventType)
{
  auto addressSpace = mServer.server().address_space();

  // Custom event type A: a runtime subtype of AuditEventType (NS0).
  const NodeId customAuditType{mTestNamespaceIndex, uint32_t{7500}};
  auto auditTypeNode = addressSpace.create_node_sync(customAuditType, NodeClass::ObjectType);
  auditTypeNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "CustomAuditEventType"});
  auditTypeNode.set_display_name(LocalizedText{"", "CustomAuditEventType"});
  // Inverse HasSubtype = "this type's super type is AuditEventType" (get_super_type_id).
  auditTypeNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::AuditEventType}, /*isForward=*/false);

  // Custom event type B: a runtime subtype of SystemEventType (different branch).
  const NodeId customSystemType{mTestNamespaceIndex, uint32_t{7501}};
  auto systemTypeNode = addressSpace.create_node_sync(customSystemType, NodeClass::ObjectType);
  systemTypeNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "CustomSystemEventType"});
  systemTypeNode.set_display_name(LocalizedText{"", "CustomSystemEventType"});
  systemTypeNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::SystemEventType}, /*isForward=*/false);

  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::AuditEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // A runtime GenericEvent of the custom Audit subtype - chain resolved from the
  // live address space at dispatch - must match OfType(AuditEventType).
  GenericEvent matching{customAuditType};
  matching.sourceNode = NodeId{ObjectId::Server};
  matching.sourceName = "FLT026a";
  matching.message = LocalizedText{"", "RuntimeCustomAuditSubtype"};
  matching.severity = 700;
  auto matched = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, matching);
  EXPECT_FALSE(matched.empty()) << "OfType(AuditEventType) must match a runtime-registered custom subtype";

  // A runtime GenericEvent of the custom System subtype must NOT match OfType(AuditEventType).
  GenericEvent unrelated{customSystemType};
  unrelated.sourceNode = NodeId{ObjectId::Server};
  unrelated.sourceName = "FLT026b";
  unrelated.message = LocalizedText{"", "RuntimeCustomSystemSubtype"};
  unrelated.severity = 700;
  auto unmatched = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, unrelated);
  EXPECT_TRUE(unmatched.empty())
    << "OfType(AuditEventType) must NOT match a runtime custom type from a different branch";
}

// ===========================================================================
// Group 9: ContentFilter (2 tests) - ComplianceEventBase
// ===========================================================================

// EVT_CF_001: No loops in element references
TEST_F(ComplianceEventBase, EVT_CF_001_NoLoopsInElementReferences)
{
  // Build ContentFilter with circular references:
  // Element 0: OfType, operand = ElementOperand(index=1)
  // Element 1: OfType, operand = ElementOperand(index=0)
  ElementOperand elemOp0;
  elemOp0.index() = 1;
  ContentFilterElement element0;
  element0.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> op0Ref;
  op0Ref = std::unique_ptr<Structure>(std::make_unique<ElementOperand>(std::move(elemOp0)));
  element0.filter_operands().push_back(std::move(op0Ref));

  ElementOperand elemOp1;
  elemOp1.index() = 0;
  ContentFilterElement element1;
  element1.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> op1Ref;
  op1Ref = std::unique_ptr<Structure>(std::make_unique<ElementOperand>(std::move(elemOp1)));
  element1.filter_operands().push_back(std::move(op1Ref));

  ContentFilter circularFilter;
  circularFilter.elements().push_back(std::move(element0));
  circularFilter.elements().push_back(std::move(element1));

  auto filter = make_event_filter(make_standard_select_clauses(), std::move(circularFilter));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // Should be rejected - circular element references are not allowed
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  bool rejected = !miResp.results()[0].status_code().is_good();
  if (efr != nullptr)
  {
    auto& wcResult = efr->where_clause_result();
    for (const auto& elemResult : wcResult.element_results())
    {
      if (!elemResult.status_code().is_good())
        rejected = true;
    }
  }
  EXPECT_TRUE(rejected) << "Circular element references in ContentFilter should be rejected";
}

// EVT_CF_002: Extra operands rejected
TEST_F(ComplianceEventBase, EVT_CF_002_ExtraOperandsRejected)
{
  // Build OfType element with 2 LiteralOperand operands (should only take 1)
  LiteralOperand operand1;
  operand1.value() = Variant{NodeId{ObjectTypeId::BaseEventType}};
  LiteralOperand operand2;
  operand2.value() = Variant{NodeId{ObjectTypeId::BaseEventType}};

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> ref1;
  ref1 = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(operand1)));
  element.filter_operands().push_back(std::move(ref1));
  RefStructure<Structure> ref2;
  ref2 = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(operand2)));
  element.filter_operands().push_back(std::move(ref2));

  ContentFilter badFilter;
  badFilter.elements().push_back(std::move(element));

  auto filter = make_event_filter(make_standard_select_clauses(), std::move(badFilter));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);

  // Should be rejected or report error for extra operand
  auto& filterResultRef = miResp.results()[0].filter_result();
  auto* efr = dynamic_cast<const EventFilterResult*>(filterResultRef.get());
  bool hasError = !miResp.results()[0].status_code().is_good();
  if (efr != nullptr)
  {
    auto& wcResult = efr->where_clause_result();
    for (const auto& elemResult : wcResult.element_results())
    {
      if (!elemResult.status_code().is_good())
        hasError = true;
    }
  }
  EXPECT_TRUE(hasError) << "OfType with extra operands should be rejected";
}

// ===========================================================================
// Group 2: Event Source & Notifier References (4 tests) - ComplianceEventWithNodes
// ===========================================================================

// EVT_REF_005: The SourceNode of HasEventSource references shall have SubscribeToEvents set.
// Part 3, 7.17: "The SourceNode of this ReferenceType shall be an Object or View that has
// its 'SubscribeToEvents' bit set within the EventNotifier Attribute."
TEST_F(ComplianceEventWithNodes, EVT_REF_005_HasEventSourceOnSubscribableObject)
{
  // Browse Server Object for HasEventSource references (it is a common source).
  // The SourceNode (Server Object) must have SubscribeToEvents set.
  BrowseRequest req;
  BrowseDescription bd;
  bd.node_id() = NodeId{ObjectId::Server};
  bd.browse_direction() = BrowseDirection::Forward;
  bd.reference_type_id() = NodeId{ReferenceTypeId::HasEventSource};
  bd.include_subtypes() = true;
  bd.result_mask() = static_cast<uint32_t>(BrowseResultMask::TargetInfo);
  req.nodes_to_browse().push_back(std::move(bd));
  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  if (!resp.results()[0].references().empty())
  {
    // The SOURCE node (Server Object) must have SubscribeToEvents bit set
    auto notifier = read_event_notifier_raw(*mSession, NodeId{ObjectId::Server});
    EventNotifierType en{notifier};
    EXPECT_TRUE(en.test(EventNotifierType::Bit::SubscribeToEvents))
      << "SourceNode of HasEventSource reference must have SubscribeToEvents bit set";
  }
  else
  {
    // Also check mEventSourceId as a potential source
    BrowseRequest req2;
    BrowseDescription bd2;
    bd2.node_id() = mEventSourceId;
    bd2.browse_direction() = BrowseDirection::Forward;
    bd2.reference_type_id() = NodeId{ReferenceTypeId::HasEventSource};
    bd2.include_subtypes() = true;
    bd2.result_mask() = static_cast<uint32_t>(BrowseResultMask::TargetInfo);
    req2.nodes_to_browse().push_back(std::move(bd2));
    auto resp2 = mSession->view().browse_sync(std::move(req2));
    if (resp2.results().size() == 1 && !resp2.results()[0].references().empty())
    {
      auto notifier = read_event_notifier_raw(*mSession, mEventSourceId);
      EventNotifierType en{notifier};
      EXPECT_TRUE(en.test(EventNotifierType::Bit::SubscribeToEvents))
        << "SourceNode of HasEventSource reference must have SubscribeToEvents bit set";
    }
  }
}

// EVT_REF_006: HasEventSource references have no cycles
TEST_F(ComplianceEventWithNodes, EVT_REF_006_HasEventSourceNoCycles)
{
  std::set<std::string> visited;
  std::vector<NodeId> queue;
  queue.push_back(mEventSourceId);
  bool hasCycle = false;
  int depth = 0;
  const int maxDepth = 10;

  while (!queue.empty() && depth < maxDepth)
  {
    std::vector<NodeId> nextQueue;
    for (const auto& nodeId : queue)
    {
      auto key =
        std::to_string(nodeId.namespace_index()) + ":" + std::to_string(nodeId.identifier().get_numeric());
      if (visited.count(key) > 0)
      {
        hasCycle = true;
        break;
      }
      visited.insert(key);

      BrowseRequest req;
      BrowseDescription bd;
      bd.node_id() = nodeId;
      bd.browse_direction() = BrowseDirection::Forward;
      bd.reference_type_id() = NodeId{ReferenceTypeId::HasEventSource};
      bd.include_subtypes() = true;
      bd.result_mask() = static_cast<uint32_t>(BrowseResultMask::TargetInfo);
      req.nodes_to_browse().push_back(std::move(bd));
      auto resp = mSession->view().browse_sync(std::move(req));
      if (resp.results().size() == 1)
      {
        for (const auto& ref : resp.results()[0].references())
        {
          nextQueue.push_back(ref.node_id().node_id());
        }
      }
    }
    if (hasCycle)
      break;
    queue = std::move(nextQueue);
    ++depth;
  }

  EXPECT_FALSE(hasCycle) << "HasEventSource reference graph should not contain cycles";
}

// EVT_REF_007: HasNotifier targets have SubscribeToEvents bit
TEST_F(ComplianceEventWithNodes, EVT_REF_007_HasNotifierTargetIsEventSource)
{
  // Browse Server Object for HasNotifier references (forward)
  BrowseRequest req;
  BrowseDescription bd;
  bd.node_id() = NodeId{ObjectId::Server};
  bd.browse_direction() = BrowseDirection::Forward;
  bd.reference_type_id() = NodeId{ReferenceTypeId::HasNotifier};
  bd.include_subtypes() = true;
  bd.result_mask() = static_cast<uint32_t>(BrowseResultMask::TargetInfo);
  req.nodes_to_browse().push_back(std::move(bd));
  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  // Each HasNotifier target should have EventNotifier with SubscribeToEvents
  ASSERT_FALSE(resp.results()[0].references().empty())
    << "Server Object should have at least one HasNotifier reference (our test setup adds one)";

  for (const auto& ref : resp.results()[0].references())
  {
    auto targetId = ref.node_id().node_id();
    auto notifier = read_event_notifier_raw(*mSession, targetId);
    EventNotifierType en{notifier};
    EXPECT_TRUE(en.test(EventNotifierType::Bit::SubscribeToEvents))
      << "HasNotifier target should have SubscribeToEvents bit set";
  }
}

// EVT_REF_008: HasNotifier propagates events
TEST_F(ComplianceEventWithNodes, EVT_REF_008_HasNotifierPropagatesEvents)
{
  // Create event MI on Server Object - events from HasNotifier targets should propagate
  auto whereClause = make_of_type_where_clause(NodeId{ObjectTypeId::BaseEventType});
  auto filter = make_event_filter(make_standard_select_clauses(), std::move(whereClause));
  auto miReq = make_event_mi_request(mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit event with source_node = mEventSourceId (which has HasNotifier from Server)
  GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
  event.sourceNode = mEventSourceId;
  event.sourceName = "REF008";
  event.message = LocalizedText{"", "NotifierPropagationTest"};
  event.severity = 500;

  auto events = emit_and_receive_events(mServer.server(), *mSession, mSubscriptionId, event);
  EXPECT_FALSE(events.empty())
    << "Event from HasNotifier source should propagate to Server Object subscription";
}

// ===========================================================================
// Fixture: ComplianceEventAudit - server with auditing enabled
// ===========================================================================

class ComplianceEventAudit : public ::testing::Test
{
protected:
  struct CapturedEvent
  {
    NodeId eventType;
    String sourceName;
    NodeId sourceNode;
    uint16_t severity{0};
    ByteString eventId;
  };

  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    server::ServerConfig serverCfg;
    serverCfg.auditingEnabled = true;

    server::CreateConfig createCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    auto logSink = test_log_sink();
    mServer.emplace(Server::create(mServerThreadPool.executor(),
      std::move(createCfg),
      server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
        .authenticator = std::make_shared<AnonymousAuthenticator>(),
        .roleConfiguration = RoleConfiguration::from_well_known_grants(
          {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}}),
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));

    // Set event listener to capture audit events
    mServer->set_event_listener(
      [this](const BaseEvent& event)
      {
        CapturedEvent captured;
        captured.eventType = event.eventType;
        captured.sourceName = event.sourceName;
        captured.sourceNode = event.sourceNode;
        captured.severity = event.severity;
        captured.eventId = event.eventId;
        std::lock_guard lock(mEventMutex);
        mCapturedEvents.push_back(std::move(captured));
      });

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = MessageSecurityMode::None;
    ep.securityPolicyId = SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(ep));

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
  }

  /// Get captured events (thread-safe copy)
  std::vector<CapturedEvent> captured_events()
  {
    std::lock_guard lock(mEventMutex);
    return mCapturedEvents;
  }

  /// Clear captured events
  void clear_captured_events()
  {
    std::lock_guard lock(mEventMutex);
    mCapturedEvents.clear();
  }

  /// Find captured events by event type
  std::vector<CapturedEvent> find_events_by_type(const NodeId& typeId)
  {
    std::lock_guard lock(mEventMutex);
    std::vector<CapturedEvent> result;
    for (const auto& e : mCapturedEvents)
    {
      if (e.eventType == typeId)
        result.push_back(e);
    }
    return result;
  }

  /// Wait briefly for events to be captured (async emission)
  void wait_for_events(int ms = 200)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  }

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<Server> mServer;
  server::ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::mutex mEventMutex;
  std::vector<CapturedEvent> mCapturedEvents;
};

// ===========================================================================
// Group 11: Standard Event Types (7 tests)
// ===========================================================================

// EVT_TYP_001: Overflow event SourceNode is Server Object
TEST_F(ComplianceEventBase, EVT_TYP_001_OverflowEventSourceIsServerObject)
{
  // Create MI with queueSize=2
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit 5 events rapidly to trigger overflow
  for (int i = 0; i < 5; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "TYP001";
    event.message = LocalizedText{"", "TYP_001 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Collect events via publish
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Find overflow event and check SourceNode (index 2)
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  bool foundOverflow = false;
  for (const auto& efl : collected)
  {
    if (efl.event_fields().size() > 2)
    {
      auto typeId = efl.event_fields()[1].as<NodeId>();
      if (typeId == overflowTypeId)
      {
        foundOverflow = true;
        auto sourceNode = efl.event_fields()[2].as<NodeId>();
        EXPECT_EQ(sourceNode, NodeId{ObjectId::Server})
          << "Overflow event SourceNode should be the Server Object";
        break;
      }
    }
  }

  EXPECT_TRUE(foundOverflow) << "no EventQueueOverflowEventType event was received after the queue "
                                "overflowed, so the server does not report the overflow it must";
}

// EVT_TYP_002: Overflow event SourceName is "Internal/EventQueueOverflow"
TEST_F(ComplianceEventBase, EVT_TYP_002_OverflowEventSourceName)
{
  // Create MI with queueSize=2
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  // Emit 5 events rapidly to trigger overflow
  for (int i = 0; i < 5; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "TYP002";
    event.message = LocalizedText{"", "TYP_002 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Collect events via publish
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Find overflow event and check SourceName (index 3)
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  bool foundOverflow = false;
  for (const auto& efl : collected)
  {
    if (efl.event_fields().size() > 3)
    {
      auto typeId = efl.event_fields()[1].as<NodeId>();
      if (typeId == overflowTypeId)
      {
        foundOverflow = true;
        auto sourceName = efl.event_fields()[3].as<String>();
        EXPECT_EQ(sourceName, String{"Internal/EventQueueOverflow"})
          << "Overflow event SourceName should be 'Internal/EventQueueOverflow'";
        break;
      }
    }
  }

  EXPECT_TRUE(foundOverflow) << "no EventQueueOverflowEventType event was received after the queue "
                                "overflowed, so the server does not report the overflow it must";
}

// EVT_TYP_007: Audit channel event SourceNode is Server Object
// @relation(SVR-AUDIT-012, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_TYP_007_AuditChannelSourceIsServerObject)
{
  clear_captured_events();

  // Open a channel - this should trigger audit events
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();

  auto events = captured_events();
  // Look for any audit event with sourceNode == Server
  bool foundAuditEvent = false;
  for (const auto& e : events)
  {
    // Check if this is an audit channel event (type 2060 or subtype)
    if (e.eventType == NodeId{ObjectTypeId::AuditOpenSecureChannelEventType} ||
        e.eventType == NodeId{ObjectTypeId::AuditChannelEventType})
    {
      foundAuditEvent = true;
      EXPECT_EQ(e.sourceNode, NodeId{ObjectId::Server})
        << "Audit channel event SourceNode should be the Server Object";
      break;
    }
  }

  EXPECT_TRUE(foundAuditEvent)
    << "Opening a channel should generate an audit channel event (AuditOpenSecureChannelEventType "
    << "or AuditChannelEventType) with SourceNode = Server Object. " << "Captured " << events.size()
    << " events total.";

  channel.close_sync();
}

// EVT_TYP_008: Audit channel event SourceName starts with "SecureChannel/"
// @relation(SVR-AUDIT-012, scope=function)
TEST_F(ComplianceEventAudit, EVT_TYP_008_AuditChannelSourceNameFormat)
{
  clear_captured_events();

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();

  auto events = captured_events();
  bool foundAuditChannelEvent = false;
  for (const auto& e : events)
  {
    if (e.eventType == NodeId{ObjectTypeId::AuditOpenSecureChannelEventType} ||
        e.eventType == NodeId{ObjectTypeId::AuditChannelEventType})
    {
      foundAuditChannelEvent = true;
      std::string name = std::string(e.sourceName);
      EXPECT_TRUE(name.find("SecureChannel/") == 0)
        << "Audit channel event SourceName should start with 'SecureChannel/', got: '" << name << "'";
      break;
    }
  }

  EXPECT_TRUE(foundAuditChannelEvent) << "no AuditChannelEventType event was captured for the channel open, "
                                         "so the server emits no audit channel event. Captured "
                                      << events.size() << " events total.";

  channel.close_sync();
}

// ===========================================================================
// Group 12: Audit Events (9 tests) - ComplianceEventAudit
// ===========================================================================

// EVT_AUD_003: Opening a secure channel emits an audit event
// @relation(SVR-EVT-AUD-001, SVR-EVT-AUD-003, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_003_OpenSecureChannelAuditEvent)
{
  clear_captured_events();

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();

  auto events = captured_events();
  bool foundChannelAudit = false;
  for (const auto& e : events)
  {
    // AuditOpenSecureChannelEventType = 2060 or AuditChannelEventType = 2059
    if (e.eventType == NodeId{ObjectTypeId::AuditOpenSecureChannelEventType} ||
        e.eventType == NodeId{ObjectTypeId::AuditChannelEventType})
    {
      foundChannelAudit = true;
      break;
    }
  }

  EXPECT_TRUE(foundChannelAudit) << "Opening a secure channel should emit an audit channel event. "
                                 << "Captured " << events.size() << " events.";

  channel.close_sync();
}

// EVT_AUD_004: Audit open secure channel event has correct type
// @relation(SVR-EVT-AUD-004, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_004_AuditOpenSecureChannelEventType)
{
  clear_captured_events();

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();

  // Specifically check for AuditOpenSecureChannelEventType (2060)
  auto openEvents = find_events_by_type(NodeId{ObjectTypeId::AuditOpenSecureChannelEventType});
  EXPECT_FALSE(openEvents.empty())
    << "Opening a secure channel should emit AuditOpenSecureChannelEventType (2060). " << "Captured "
    << captured_events().size() << " events total.";

  channel.close_sync();
}

// EVT_AUD_005: Closing a secure channel emits an audit event
// @relation(SVR-EVT-AUD-005, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_005_CloseSecureChannelAuditEvent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();
  clear_captured_events();

  channel.close_sync();
  wait_for_events();

  auto events = captured_events();
  bool foundCloseAudit = false;
  for (const auto& e : events)
  {
    // CloseSecureChannel should emit AuditChannelEventType (2059) or subtype,
    // but NOT AuditOpenSecureChannelEventType (2060) which is for open operations.
    if (e.eventType == NodeId{ObjectTypeId::AuditChannelEventType})
    {
      foundCloseAudit = true;
      break;
    }
  }

  // Per spec: Servers that support auditing "shall generate audit Events for ... successful
  // invocation of the ... CloseSecureChannel Services."
  EXPECT_TRUE(foundCloseAudit) << "CloseSecureChannel should emit AuditChannelEventType audit event. "
                               << "Captured " << events.size() << " events.";
}

// EVT_AUD_007: Session service operations emit audit events
// @relation(SVR-EVT-AUD-007, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_007_SessionServiceAuditEvents)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();
  clear_captured_events();

  auto session = channel.create_session_sync({.sessionName = "AuditTest007"});
  session.activate_sync();
  wait_for_events();

  auto events = captured_events();
  bool foundSessionAudit = false;
  for (const auto& e : events)
  {
    // AuditSessionEventType = 2069, AuditCreateSessionEventType = 2071,
    // AuditActivateSessionEventType = 2075
    if (e.eventType == NodeId{ObjectTypeId::AuditSessionEventType} ||
        e.eventType == NodeId{ObjectTypeId::AuditCreateSessionEventType} ||
        e.eventType == NodeId{ObjectTypeId::AuditActivateSessionEventType})
    {
      foundSessionAudit = true;
      break;
    }
  }

  EXPECT_TRUE(foundSessionAudit) << "Creating and activating a session should emit audit session events. "
                                 << "Captured " << events.size() << " events.";

  session.close_sync();
  channel.close_sync();
}

// EVT_AUD_008: CreateSession emits AuditCreateSessionEventType
// @relation(SVR-EVT-AUD-008, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_008_CreateSessionAuditEvent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  wait_for_events();
  clear_captured_events();

  auto session = channel.create_session_sync({.sessionName = "AuditTest008"});
  wait_for_events();

  auto createEvents = find_events_by_type(NodeId{ObjectTypeId::AuditCreateSessionEventType});
  EXPECT_FALSE(createEvents.empty()) << "CreateSession should emit AuditCreateSessionEventType (2071). "
                                     << "Captured " << captured_events().size() << " events total.";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// EVT_AUD_009: ActivateSession emits AuditActivateSessionEventType
// @relation(SVR-EVT-AUD-009, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_009_ActivateSessionAuditEvent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "AuditTest009"});
  wait_for_events();
  clear_captured_events();

  session.activate_sync();
  wait_for_events();

  auto activateEvents = find_events_by_type(NodeId{ObjectTypeId::AuditActivateSessionEventType});
  EXPECT_FALSE(activateEvents.empty()) << "ActivateSession should emit AuditActivateSessionEventType (2075). "
                                       << "Captured " << captured_events().size() << " events total.";

  session.close_sync();
  channel.close_sync();
}

// EVT_AUD_011: CloseSession emits audit event with SourceName "Session/CloseSession"
// @relation(SVR-EVT-AUD-011, SVR-AUDIT-029, scope=function)
TEST_F(ComplianceEventAudit, EVT_AUD_011_CloseSessionAuditEvent)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "AuditTest011"});
  session.activate_sync();
  wait_for_events();
  clear_captured_events();

  session.close_sync();
  wait_for_events();

  auto events = captured_events();
  bool foundCloseSession = false;
  for (const auto& e : events)
  {
    std::string name = std::string(e.sourceName);
    if (name.find("Session/CloseSession") != std::string::npos)
    {
      foundCloseSession = true;
      break;
    }
  }

  if (!foundCloseSession)
  {
    // Also check for any session audit event type
    bool foundAnySessionAudit = false;
    for (const auto& e : events)
    {
      if (e.eventType == NodeId{ObjectTypeId::AuditSessionEventType} ||
          e.eventType == NodeId{ObjectTypeId::AuditCreateSessionEventType} ||
          e.eventType == NodeId{ObjectTypeId::AuditActivateSessionEventType})
      {
        foundAnySessionAudit = true;
        break;
      }
    }
    if (!foundAnySessionAudit)
    {
      // Per spec: CloseSession "shall always be generated if a Session is terminated."
      EXPECT_TRUE(false) << "CloseSession should emit an audit session event. " << "Captured "
                         << events.size() << " events.";
    }
    else
    {
      // Found session audit event but not with expected source name
      EXPECT_TRUE(foundCloseSession)
        << "CloseSession audit event should have SourceName containing 'Session/CloseSession'. "
        << "Captured " << events.size() << " events.";
    }
  }

  channel.close_sync();
}

// ===========================================================================
// Group 10: Permissions (2 tests)
// ===========================================================================

// ===========================================================================
// Group 13: Model Change Events (1 test) - ComplianceEventBase
// ===========================================================================

// EVT_MCH_003: GeneralModelChangeEventType is exposed in the address space.
//
// Part 3 section 12.14 ("a Server shall support both ModelChangeEvents and the NodeVersion Property
// or neither") is a *behavioral* rule: a server that emits GeneralModelChangeEvents must
// maintain the NodeVersion Property on the affected nodes. Merely exposing the standard NS0
// GeneralModelChangeEventType is not itself "support" - it is the prerequisite that lets
// applications emit these events (via Server::emit_event) and lets clients subscribe to them
// OfType (the EventBus resolves the HasSubtype hierarchy from the address space, so the type
// node must be present). The behavioral invariant - emit => NodeVersion on the affected node -
// is exercised end-to-end in ComplianceModelChange.MODEL_CHANGE_001.
//
// This test guards only that the type is present and browsable.
TEST_F(ComplianceEventBase, EVT_MCH_003_ModelChangeEventTypeExposed)
{
  ReadRequest readReq;
  ReadValueId rv;
  rv.node_id() = NodeId{ObjectTypeId::GeneralModelChangeEventType};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::BrowseName);
  readReq.nodes_to_read().push_back(std::move(rv));
  readReq.timestamps_to_return() = TimestampsToReturn::Neither;
  auto readResp = mSession->attributes().read_sync(std::move(readReq));
  ASSERT_EQ(readResp.results().size(), 1u);

  const auto& result = readResp.results()[0];
  const bool good = !result.status().has_value() || result.status()->is_good();
  ASSERT_TRUE(good) << "GeneralModelChangeEventType must be exposed for OfType subscription matching";
  EXPECT_EQ(result.value().as<QualifiedName>().name(), String{"GeneralModelChangeEventType"});
}

// ===========================================================================
// Group 10: Event MonitoredItem Queue & EventNotifier (MI-GEN-*)
// ===========================================================================

// SVR-MI-GEN-070: Events are only available from nodes where the SubscribeToEvents
// bit of the EventNotifier attribute is set. Creating an event MI on a node
// without SubscribeToEvents must fail; creating one on a node with the bit set
// must succeed.
TEST_F(ComplianceEventWithNodes, MI_GEN_070_EventsRequireSubscribeToEventsBit)
{
  // 1. Attempt event MI on node WITHOUT SubscribeToEvents -> must fail.
  auto filter = make_event_filter();
  auto failReq = make_event_mi_request(mSubscriptionId, mNoEventObjectId, filter, /*clientHandle=*/1);
  auto failResp = mSession->monitored_items().create_monitored_items_sync(std::move(failReq));
  ASSERT_EQ(failResp.results().size(), 1u);
  EXPECT_TRUE(failResp.results()[0].status_code().is_bad())
    << "Creating event MI on node without SubscribeToEvents should fail, got: "
    << failResp.results()[0].status_code().as_uint32();

  // 2. Create event MI on node WITH SubscribeToEvents -> must succeed.
  auto okReq = make_event_mi_request(mSubscriptionId, mEventSourceId, filter, /*clientHandle=*/2);
  auto okResp = mSession->monitored_items().create_monitored_items_sync(std::move(okReq));
  ASSERT_EQ(okResp.results().size(), 1u);
  EXPECT_TRUE(okResp.results()[0].status_code().is_good())
    << "Creating event MI on node with SubscribeToEvents should succeed, got: "
    << okResp.results()[0].status_code().as_uint32();
}

// SVR-MI-GEN-032: For event monitored items, if the client requests queueSize=1,
// the server shall return the minimum event queue size it supports.
// The revised value must be >= 1 (a queue size of 0 is invalid for events).
TEST_F(ComplianceEventWithNodes, MI_GEN_032_EventQueueSizeOneRevisedToMinimum)
{
  auto filter = make_event_filter();
  auto req =
    make_event_mi_request(mSubscriptionId, mEventSourceId, filter, /*clientHandle=*/1, /*queueSize=*/1);
  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good())
    << "Failed to create event MI with queueSize=1: " << resp.results()[0].status_code().as_uint32();

  auto revisedQueueSize = resp.results()[0].revised_queue_size();
  EXPECT_GE(revisedQueueSize, 1u) << "Event MI revised queue size must be >= 1, got: " << revisedQueueSize;
}

// SVR-MI-GEN-033: For event monitored items, if the client requests queueSize=MaxUInt32,
// the server shall return the maximum event queue size it supports.
// The revised value must be > 0.
TEST_F(ComplianceEventWithNodes, MI_GEN_033_EventQueueSizeMaxRevisedToMaximum)
{
  auto filter = make_event_filter();
  auto req = make_event_mi_request(mSubscriptionId,
    mEventSourceId,
    filter,
    /*clientHandle=*/1,
    /*queueSize=*/std::numeric_limits<uint32_t>::max());
  auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good())
    << "Failed to create event MI with queueSize=MaxUInt32: " << resp.results()[0].status_code().as_uint32();

  auto revisedQueueSize = resp.results()[0].revised_queue_size();
  EXPECT_GT(revisedQueueSize, 0u) << "Event MI revised queue size for max request must be > 0";
}

// SVR-MI-GEN-034: If the requested event queueSize is within [min, max], the server
// returns the requested value. If outside, the server clamps to the nearest bound.
TEST_F(ComplianceEventWithNodes, MI_GEN_034_EventQueueSizeClamped)
{
  auto filter = make_event_filter();

  // Step 1: Determine minimum by requesting queueSize=1.
  auto minReq =
    make_event_mi_request(mSubscriptionId, mEventSourceId, filter, /*clientHandle=*/10, /*queueSize=*/1);
  auto minResp = mSession->monitored_items().create_monitored_items_sync(std::move(minReq));
  ASSERT_EQ(minResp.results().size(), 1u);
  ASSERT_TRUE(minResp.results()[0].status_code().is_good());
  uint32_t revisedMin = minResp.results()[0].revised_queue_size();

  // Step 2: Determine maximum by requesting queueSize=MaxUInt32.
  auto maxReq = make_event_mi_request(mSubscriptionId,
    mEventSourceId,
    filter,
    /*clientHandle=*/11,
    /*queueSize=*/std::numeric_limits<uint32_t>::max());
  auto maxResp = mSession->monitored_items().create_monitored_items_sync(std::move(maxReq));
  ASSERT_EQ(maxResp.results().size(), 1u);
  ASSERT_TRUE(maxResp.results()[0].status_code().is_good());
  uint32_t revisedMax = maxResp.results()[0].revised_queue_size();

  ASSERT_LE(revisedMin, revisedMax) << "Server minimum event queue size must be <= maximum";

  // Step 3: If min < max, request a value between them and verify it is returned exactly.
  if (revisedMin < revisedMax)
  {
    uint32_t midValue = revisedMin + 1;
    auto midReq =
      make_event_mi_request(mSubscriptionId, mEventSourceId, filter, /*clientHandle=*/12, midValue);
    auto midResp = mSession->monitored_items().create_monitored_items_sync(std::move(midReq));
    ASSERT_EQ(midResp.results().size(), 1u);
    ASSERT_TRUE(midResp.results()[0].status_code().is_good());
    uint32_t revisedMid = midResp.results()[0].revised_queue_size();
    EXPECT_EQ(revisedMid, midValue) << "Requested queueSize=" << midValue << " is within [" << revisedMin
                                    << ", " << revisedMax << "] but server returned " << revisedMid;
  }

  // Step 4: Request beyond maximum -> should clamp to max.
  if (revisedMax < std::numeric_limits<uint32_t>::max())
  {
    uint32_t beyondMax = revisedMax + 1;
    auto overReq =
      make_event_mi_request(mSubscriptionId, mEventSourceId, filter, /*clientHandle=*/13, beyondMax);
    auto overResp = mSession->monitored_items().create_monitored_items_sync(std::move(overReq));
    ASSERT_EQ(overResp.results().size(), 1u);
    ASSERT_TRUE(overResp.results()[0].status_code().is_good());
    uint32_t revisedOver = overResp.results()[0].revised_queue_size();
    EXPECT_EQ(revisedOver, revisedMax) << "Requested queueSize=" << beyondMax << " exceeds max=" << revisedMax
                                       << " but server returned " << revisedOver;
  }
}

// SVR-MI-GEN-072: When an event queue overflows, the server shall generate an
// EventQueueOverflowEventType notification.
TEST_F(ComplianceEventWithNodes, MI_GEN_072_EventQueueOverflowEventGenerated)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());

  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  // Emit events rapidly without publishing between them.
  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MI_GEN_072 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Publish and collect all events.
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Check for EventQueueOverflowEventType in received events (field 1 = EventType).
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  bool foundOverflow = false;
  for (const auto& efl : collected)
  {
    if (efl.event_fields().size() > 1)
    {
      auto typeId = efl.event_fields()[1].as<NodeId>();
      if (typeId == overflowTypeId)
      {
        foundOverflow = true;
        break;
      }
    }
  }
  EXPECT_TRUE(foundOverflow) << "Should receive EventQueueOverflowEventType when queue overflows";
}

// SVR-MI-GEN-073: The overflow event notification shall be added in addition to the
// configured queue size (queue may temporarily hold queueSize + 1 entries).
TEST_F(ComplianceEventWithNodes, MI_GEN_073_OverflowEventAdditionalToQueueSize)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  // Emit events rapidly without publishing.
  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MI_GEN_073 event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  // Collect all events.
  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  // Total events should be revisedQueueSize + 1 (overflow event is extra).
  EXPECT_EQ(collected.size(), revisedQueueSize + 1)
    << "Total events in publish should be revisedQueueSize + 1 (overflow event is extra)";
}

// SVR-MI-GEN-074: When discardOldest=true, the overflow event shall appear at the
// beginning of the queue; when discardOldest=false, it shall appear at the end.
TEST_F(ComplianceEventWithNodes, MI_GEN_074_OverflowEventPositionDiscardOldestFirst)
{
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/true);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MI_GEN_074a event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  ASSERT_GE(collected.size(), 1u);
  // With discardOldest=true, overflow event should be at index 0.
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  ASSERT_GT(collected[0].event_fields().size(), 1u);
  auto firstEventType = collected[0].event_fields()[1].as<NodeId>();
  EXPECT_EQ(firstEventType, overflowTypeId)
    << "With discardOldest=true, overflow event should be first in notification list";
}

TEST_F(ComplianceEventWithNodes, MI_GEN_074_OverflowEventPositionDiscardNewestLast)
{
  // Need a fresh subscription + MI with discardOldest=false.
  auto filter = make_event_filter();
  auto miReq = make_event_mi_request(mSubscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    /*clientHandle=*/1,
    /*queueSize=*/2,
    /*discardOldest=*/false);
  auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good());
  auto revisedQueueSize = miResp.results()[0].revised_queue_size();
  auto eventsToEmit = static_cast<int>(revisedQueueSize) + 3;

  for (int i = 0; i < eventsToEmit; ++i)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = "OverflowTest";
    event.message = LocalizedText{"", "MI_GEN_074b event " + std::to_string(i)};
    event.severity = static_cast<uint16_t>(100 + i * 100);
    mServer.server().emit_event(event);
  }

  std::vector<EventFieldList> collected;
  for (int attempt = 0; attempt < 15; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto resp = try_publish_once(*mSession);
    if (!resp)
      continue;
    auto* eventNotif = as_event_notification(*resp);
    if (eventNotif != nullptr)
    {
      for (const auto& efl : eventNotif->events())
        collected.push_back(efl);
    }
    if (!collected.empty())
      break;
  }

  ASSERT_GE(collected.size(), 1u);
  // With discardOldest=false, overflow event should be the last entry.
  NodeId overflowTypeId{ObjectTypeId::EventQueueOverflowEventType};
  auto& lastEvent = collected.back();
  ASSERT_GT(lastEvent.event_fields().size(), 1u);
  auto lastEventType = lastEvent.event_fields()[1].as<NodeId>();
  EXPECT_EQ(lastEventType, overflowTypeId)
    << "With discardOldest=false, overflow event should be last in notification list";
}

// ===========================================================================
// Row: ResourceLimits::eventDispatchQueueDepth (configuration coverage matrix section 11).
//
// Bounds the EventBus queue of not-yet-started dispatch tasks. A burst of emits faster than dispatch
// drains would otherwise grow it without limit, so at the cap the OLDEST pending dispatch is dropped -
// and a dropped dispatch never reaches any subscriber, which is what makes this peer-observable.
//
// THE ORACLE IS ON THE SUBSCRIBER, not on the server's internal counter: what matters to a client is that
// events it was subscribed to silently did not arrive. That silence is the field's cost, and asserting it
// is what stops the row from being an unverifiable memory claim.
//
// The monitored item's own queueSize is set well above the burst so the SUBSCRIPTION-side queue cannot be
// what discards them - otherwise this would measure `queueSize`, a different bound entirely.
// ===========================================================================
class ComplianceEventDispatchDepth : public ComplianceEventBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.resourceLimits.eventDispatchQueueDepth = 1;  // default is far larger
  }

  // Emit @p count events as fast as the calling thread can, then report how many reached the subscriber.
  std::size_t delivered_for_burst(std::size_t count)
  {
    auto miResult =
      mSession->monitored_items().create_monitored_items_sync(make_event_mi_request(mSubscriptionId,
        NodeId{ObjectId::Server},
        make_event_filter(),
        /*clientHandle=*/1,
        /*queueSize=*/500));
    EXPECT_TRUE(miResult.results()[0].status_code().is_good());

    for (std::size_t i = 0; i < count; ++i)
    {
      GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
      event.sourceNode = NodeId{ObjectId::Server};
      event.sourceName = String{"DispatchDepthProbe"};
      event.message = LocalizedText{"", "burst " + std::to_string(i)};
      event.severity = 100;
      mServer.server().emit_event(event);
    }

    return collect_events(*mSession, mSubscriptionId, {.minCount = count, .timeout = 3s}).size();
  }
};

// DEFAULT (large): the same burst is absorbed by the dispatch queue and every event reaches the
// subscriber.
TEST_F(ComplianceEventDispatchDepth, BurstBeyondTheDispatchQueueDepthLosesEvents)
{
  constexpr std::size_t burst = 40;
  const auto delivered = delivered_for_burst(burst);

  EXPECT_GT(delivered, 0u) << "the subscription must work at all - some events must arrive";
  EXPECT_LT(delivered, burst)
    << "with a dispatch queue depth of 1 a 40-event burst must lose events (" << delivered
    << " delivered); under the default depth the whole burst is absorbed and all 40 arrive";
}

// ResourceLimits::conditionBranchesPerCondition is NOT covered here. Branching had to be opted into
// (`AcknowledgeableConditionLogic::set_supports_branches`) before any branch was created at all, and with
// it enabled five unacknowledged toggles produced 20 events - all Retain=True. No eviction was observed at
// a configured cap of 2, so the Retain=False retraction the row needs never arrived. See the matrix entry:
// whether the configured cap reaches the per-condition logic is an open question, not a confirmed defect.

// ===========================================================================
// Group 14: EventNotifier attribute surface (EVT_ATTR) - swept over the whole
// hierarchy rather than over the Server Object alone.
// ===========================================================================

// Renders a NodeId for a failure message. `get_numeric()` throws on a non-numeric identifier, so the
// identifier type is checked before it is read.
static std::string describe_node_id(const NodeId& nodeId)
{
  std::string out = "ns=" + std::to_string(nodeId.namespace_index()) + ";";
  const auto& id = nodeId.identifier();
  if (id.is_numeric())
    out += "i=" + std::to_string(id.get_numeric());
  else if (id.is_string())
    out += "s=" + std::string{id.get_string()};
  else
    out += "<guid-or-opaque>";
  return out;
}

struct EventNotifierSweptNode
{
  NodeId nodeId;
  NodeClass nodeClass{NodeClass::Unspecified};
};

// Bounded breadth-first walk of the hierarchy from `start`, returning every Object and View reached
// (the start node itself is not included). Bounded because the criteria say "every Object" and the
// address space is not finite in practice: the cap keeps the sweep to one Browse round trip per
// visited node while still crossing NS0 (Root -> Objects/Types/Views -> Server -> its components) and
// the fixture's own namespace. Nodes hosted on another server are skipped - their attributes are not
// this server's obligation.
static std::vector<EventNotifierSweptNode> sweep_objects_and_views(
  Session& session, const NodeId& start, std::size_t maxNodes = 150)
{
  std::vector<EventNotifierSweptNode> found;
  std::set<NodeId> visited;
  std::vector<NodeId> frontier{start};
  visited.insert(start);

  while (!frontier.empty() && found.size() < maxNodes)
  {
    std::vector<NodeId> next;
    for (const auto& nodeId : frontier)
    {
      if (found.size() >= maxNodes)
        break;

      BrowseRequest req;
      BrowseDescription desc;
      desc.node_id() = nodeId;
      desc.browse_direction() = BrowseDirection::Forward;
      desc.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
      desc.include_subtypes() = true;
      desc.node_class_mask() =
        static_cast<uint32_t>(NodeClass::Object) | static_cast<uint32_t>(NodeClass::View);
      desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
      req.nodes_to_browse().push_back(std::move(desc));

      auto resp = session.view().browse_sync(std::move(req));
      if (resp.results().size() != 1 || !resp.results()[0].status_code().is_good())
        continue;

      for (const auto& ref : resp.results()[0].references())
      {
        if (ref.node_id().server_index() != 0 || !ref.node_id().namespace_uri().empty())
          continue;
        auto childId = ref.node_id().node_id();
        if (!visited.insert(childId).second)
          continue;
        found.push_back(EventNotifierSweptNode{childId, ref.node_class()});
        next.push_back(childId);
        if (found.size() >= maxNodes)
          break;
      }
    }
    frontier = std::move(next);
  }
  return found;
}

// Fixture adding the four notifier shapes the EVT_ATTR criteria need and that no NS0 node supplies:
// an Object whose EventNotifier was never set (the "not a notifier" case that must still expose the
// attribute), an Object carrying every DEFINED bit (so a reserved-bit assertion cannot pass merely
// because the server returns zero everywhere), and the same two shapes for the View NodeClass - the
// stock address space exposes no View at all, which is what makes the existing View check vacuous.
class ComplianceEventNotifierAttribute : public ComplianceEventWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceEventWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    auto viewsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder});

    // Object whose EventNotifier is never written by anybody.
    mUnsetNotifierObjectId = NodeId{mTestNamespaceIndex, uint32_t{5100}};
    auto unsetNode = addressSpace.create_node_sync(mUnsetNotifierObjectId, NodeClass::Object);
    unsetNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto unsetObject = unsetNode.as<ObjectAccessor>();
    ASSERT_TRUE(unsetObject.has_value());
    unsetObject->set_browse_name(QualifiedName{mTestNamespaceIndex, "UnsetNotifierObject"});
    unsetObject->set_display_name(LocalizedText{"", "UnsetNotifierObject"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mUnsetNotifierObjectId);

    // Object carrying every defined bit: 0 (SubscribeToEvents), 2 (HistoryRead), 3 (HistoryWrite).
    mAllDefinedBitsObjectId = NodeId{mTestNamespaceIndex, uint32_t{5101}};
    auto allBitsNode = addressSpace.create_node_sync(mAllDefinedBitsObjectId, NodeClass::Object);
    allBitsNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto allBitsObject = allBitsNode.as<ObjectAccessor>();
    ASSERT_TRUE(allBitsObject.has_value());
    allBitsObject->set_browse_name(QualifiedName{mTestNamespaceIndex, "AllDefinedBitsObject"});
    allBitsObject->set_display_name(LocalizedText{"", "AllDefinedBitsObject"});
    allBitsObject->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents,
      EventNotifierType::Bit::HistoryRead,
      EventNotifierType::Bit::HistoryWrite});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mAllDefinedBitsObjectId);

    // View whose EventNotifier is never written.
    mUnsetNotifierViewId = NodeId{mTestNamespaceIndex, uint32_t{5200}};
    auto unsetViewNode = addressSpace.create_node_sync(mUnsetNotifierViewId, NodeClass::View);
    unsetViewNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "UnsetNotifierView"});
    unsetViewNode.set_display_name(LocalizedText{"", "UnsetNotifierView"});
    viewsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mUnsetNotifierViewId);

    // View carrying every defined bit.
    mNotifierViewId = NodeId{mTestNamespaceIndex, uint32_t{5201}};
    auto notifierViewNode = addressSpace.create_node_sync(mNotifierViewId, NodeClass::View);
    notifierViewNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "NotifierView"});
    notifierViewNode.set_display_name(LocalizedText{"", "NotifierView"});
    auto notifierView = notifierViewNode.as<ViewAccessor>();
    ASSERT_TRUE(notifierView.has_value());
    notifierView->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents,
      EventNotifierType::Bit::HistoryRead,
      EventNotifierType::Bit::HistoryWrite});
    viewsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mNotifierViewId);
  }

  // The nodes whose EventNotifier byte is set by a path OTHER than this test: the Server Object
  // (written by the SDK itself) plus the fixture's notifier Object/View. A reserved-bit sweep that
  // saw only zero bytes would pass for the wrong reason, so these anchor it.
  std::vector<NodeId> known_notifiers() const
  {
    return {NodeId{ObjectId::Server}, mEventSourceId, mAllDefinedBitsObjectId, mNotifierViewId};
  }

  NodeId mUnsetNotifierObjectId;
  NodeId mAllDefinedBitsObjectId;
  NodeId mUnsetNotifierViewId;
  NodeId mNotifierViewId;
};

// Part 3 section 5.5: EventNotifier is Mandatory on the Object NodeClass - every Object exposes it, and an
// Object that is not a notifier exposes it as zero. The plausible implementation stores the byte only
// on the Objects that were configured as notifiers and answers Bad_AttributeIdInvalid for the rest,
// which a client cannot tell apart from having addressed the wrong Node.
// @verifies AC-SVR-EVT-ATTR-001-EVENTNOTIFIER-ON-OBJECTS
TEST_F(ComplianceEventNotifierAttribute, EveryObjectExposesTheEventNotifierAttribute)
{
  auto swept = sweep_objects_and_views(*mSession, NodeId{ObjectId::RootFolder});

  std::vector<NodeId> objectIds;
  for (const auto& node : swept)
  {
    if (node.nodeClass == NodeClass::Object)
      objectIds.push_back(node.nodeId);
  }
  // The fixture's own Objects, whichever depth the sweep reached.
  objectIds.push_back(mUnsetNotifierObjectId);
  objectIds.push_back(mAllDefinedBitsObjectId);
  objectIds.push_back(mEventSourceId);
  objectIds.push_back(mNoEventObjectId);
  objectIds.push_back(NodeId{ObjectId::Server});

  ASSERT_GE(objectIds.size(), 20u)
    << "the hierarchy sweep found only " << objectIds.size()
    << " Objects - too few for 'every Object' to mean anything; the walk itself is broken";

  ReadRequest req;
  for (const auto& nodeId : objectIds)
  {
    ReadValueId rv;
    rv.node_id() = nodeId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
    req.nodes_to_read().push_back(std::move(rv));
  }
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), objectIds.size());

  for (size_t i = 0; i < objectIds.size(); ++i)
  {
    const auto& result = resp.results()[i];
    const bool good = !result.status().has_value() || result.status()->is_good();
    EXPECT_TRUE(good) << "EventNotifier is mandatory on Objects but reading it on "
                      << describe_node_id(objectIds[i]) << " returned 0x" << std::hex
                      << (result.status().has_value() ? result.status()->as_uint32() : 0u) << std::dec;
    EXPECT_TRUE(result.value().is_uint8())
      << "EventNotifier on " << describe_node_id(objectIds[i]) << " must be present as a Byte";
  }

  // Second conjunct: zero - not absent, not bad - where the Object is not a notifier.
  ReadRequest unsetReq;
  ReadValueId unsetRv;
  unsetRv.node_id() = mUnsetNotifierObjectId;
  unsetRv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  unsetReq.nodes_to_read().push_back(std::move(unsetRv));
  unsetReq.timestamps_to_return() = TimestampsToReturn::Neither;
  auto unsetResp = mSession->attributes().read_sync(std::move(unsetReq));
  ASSERT_EQ(unsetResp.results().size(), 1u);
  const auto& unsetResult = unsetResp.results()[0];
  const bool unsetGood = !unsetResult.status().has_value() || unsetResult.status()->is_good();
  EXPECT_TRUE(unsetGood) << "an Object that is not a notifier must still expose EventNotifier";
  ASSERT_TRUE(unsetResult.value().is_uint8());
  EXPECT_EQ(unsetResult.value().as<uint8_t>(), 0u)
    << "an Object with no eventing must read EventNotifier as zero";
}

// Part 3 section 5.6: EventNotifier is Mandatory on the View NodeClass too. The stock address space contains
// no View, so an implementation that never wired the attribute for the View NodeClass is invisible
// until a View exists - this fixture creates two, one of which never had the byte written.
// @verifies AC-SVR-EVT-ATTR-004-EVENTNOTIFIER-ON-VIEWS
TEST_F(ComplianceEventNotifierAttribute, EveryViewExposesTheEventNotifierAttribute)
{
  BrowseRequest browseReq;
  BrowseDescription desc;
  desc.node_id() = NodeId{ObjectId::ViewsFolder};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.include_subtypes() = true;
  desc.node_class_mask() = static_cast<uint32_t>(NodeClass::View);
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  browseReq.nodes_to_browse().push_back(std::move(desc));

  auto browseResp = mSession->view().browse_sync(std::move(browseReq));
  ASSERT_TRUE(browseResp.response_header().service_result().is_good());
  ASSERT_EQ(browseResp.results().size(), 1u);

  std::vector<NodeId> viewIds;
  for (const auto& ref : browseResp.results()[0].references())
  {
    EXPECT_EQ(ref.node_class(), NodeClass::View);
    viewIds.push_back(ref.node_id().node_id());
  }
  ASSERT_FALSE(viewIds.empty()) << "the fixture organizes two Views under ViewsFolder; browsing found "
                                   "none, so nothing below would be exercised";

  bool sawUnsetView = false;
  bool sawNotifierView = false;
  for (const auto& viewId : viewIds)
  {
    if (viewId == mUnsetNotifierViewId)
      sawUnsetView = true;
    if (viewId == mNotifierViewId)
      sawNotifierView = true;
  }
  EXPECT_TRUE(sawUnsetView) << "the View that never had EventNotifier written must be browsable";
  EXPECT_TRUE(sawNotifierView) << "the notifier View must be browsable";

  ReadRequest req;
  for (const auto& viewId : viewIds)
  {
    ReadValueId rv;
    rv.node_id() = viewId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
    req.nodes_to_read().push_back(std::move(rv));
  }
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), viewIds.size());

  for (size_t i = 0; i < viewIds.size(); ++i)
  {
    const auto& result = resp.results()[i];
    const bool good = !result.status().has_value() || result.status()->is_good();
    EXPECT_TRUE(good) << "EventNotifier is mandatory on Views but reading it on "
                      << describe_node_id(viewIds[i]) << " returned 0x" << std::hex
                      << (result.status().has_value() ? result.status()->as_uint32() : 0u) << std::dec;
    EXPECT_TRUE(result.value().is_uint8())
      << "EventNotifier on View " << describe_node_id(viewIds[i]) << " must be present as a Byte";

    if (!result.value().is_uint8())
      continue;
    const auto raw = result.value().as<uint8_t>();
    if (viewIds[i] == mUnsetNotifierViewId)
    {
      EXPECT_EQ(raw, 0u) << "a View with no eventing must read EventNotifier as zero, not as absent";
    }
    else if (viewIds[i] == mNotifierViewId)
    {
      // The attribute really is the View's own byte, not a constant the read path invents.
      EXPECT_TRUE(EventNotifierType{raw}.test(EventNotifierType::Bit::SubscribeToEvents))
        << "the notifier View's EventNotifier must carry the bits it was configured with, got 0x" << std::hex
        << static_cast<int>(raw);
    }
  }
}

// Part 3 section 8: bit 0 (SubscribeToEvents) states whether the Node can be subscribed to for Events. It is
// the bit every browse for notifiers filters on, so it must PREDICT the outcome - an implementation
// that publishes the bit from one place and gates CreateMonitoredItems from another makes the whole
// notifier hierarchy untrustworthy for discovery.
// @verifies AC-SVR-EVT-ATTR-008-BIT-ZERO-SUBSCRIBE
TEST_F(ComplianceEventNotifierAttribute, SubscribeToEventsBitPredictsWhetherAnEventSubscriptionIsAccepted)
{
  auto bitZeroSet = [&](const NodeId& nodeId)
  {
    return (read_event_notifier_raw(*mSession, nodeId) & 0x01) != 0;
  };

  auto eventSubscriptionAccepted = [&](const NodeId& nodeId, uint32_t clientHandle)
  {
    auto req = make_event_mi_request(mSubscriptionId, nodeId, make_event_filter(), clientHandle);
    auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    return !resp.results().empty() && resp.results()[0].status_code().is_good();
  };

  // Two notifiers: the Server Object (bit set by the SDK) and the fixture's event source.
  EXPECT_TRUE(bitZeroSet(NodeId{ObjectId::Server})) << "Server Object must advertise bit 0";
  EXPECT_TRUE(bitZeroSet(mEventSourceId)) << "the event source must advertise bit 0";
  // Two non-notifiers: one explicitly zeroed, one that was never written at all.
  EXPECT_FALSE(bitZeroSet(mNoEventObjectId)) << "a non-notifier Object must not advertise bit 0";
  EXPECT_FALSE(bitZeroSet(mUnsetNotifierObjectId))
    << "an Object that was never made a notifier must not advertise bit 0";

  EXPECT_TRUE(eventSubscriptionAccepted(NodeId{ObjectId::Server}, /*clientHandle=*/101))
    << "bit 0 is set on the Server Object, so an event subscription on it must be accepted";
  EXPECT_TRUE(eventSubscriptionAccepted(mEventSourceId, /*clientHandle=*/102))
    << "bit 0 is set on the event source, so an event subscription on it must be accepted";
  EXPECT_FALSE(eventSubscriptionAccepted(mNoEventObjectId, /*clientHandle=*/103))
    << "bit 0 is clear, so an event subscription on this Object must be refused";
  EXPECT_FALSE(eventSubscriptionAccepted(mUnsetNotifierObjectId, /*clientHandle=*/104))
    << "bit 0 is clear, so an event subscription on this Object must be refused";
}

// Part 3 section 8 (Table 42): bit 1 of EventNotifier is reserved and must be zero. It sits between the two
// defined bits (0 = SubscribeToEvents, 2 = HistoryRead), so it is the bit an off-by-one in a shift or
// a mask sets by accident; a client written against a future revision that assigns it then reads a
// capability this server never had.
// @verifies AC-SVR-EVT-ATTR-009-BIT-ONE-RESERVED
TEST_F(ComplianceEventNotifierAttribute, ReservedBitOneIsClearOnEveryNotifier)
{
  auto swept = sweep_objects_and_views(*mSession, NodeId{ObjectId::RootFolder});

  std::vector<NodeId> nodeIds;
  for (const auto& node : swept)
    nodeIds.push_back(node.nodeId);
  for (const auto& nodeId : known_notifiers())
    nodeIds.push_back(nodeId);

  ASSERT_GE(nodeIds.size(), 20u) << "the hierarchy sweep found too few Objects/Views to be meaningful";

  ReadRequest req;
  for (const auto& nodeId : nodeIds)
  {
    ReadValueId rv;
    rv.node_id() = nodeId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
    req.nodes_to_read().push_back(std::move(rv));
  }
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), nodeIds.size());

  size_t notifierCount = 0;
  for (size_t i = 0; i < nodeIds.size(); ++i)
  {
    const auto& result = resp.results()[i];
    const bool good = !result.status().has_value() || result.status()->is_good();
    if (!good || !result.value().is_uint8())
      continue;
    const auto raw = result.value().as<uint8_t>();
    if (raw != 0)
      ++notifierCount;
    EXPECT_EQ(raw & 0x02, 0u) << "reserved bit 1 is set on " << describe_node_id(nodeIds[i])
                              << ", EventNotifier = 0x" << std::hex << static_cast<int>(raw) << std::dec;
  }

  // Without a single non-zero byte in the sample, "bit 1 is clear" would hold trivially.
  EXPECT_GE(notifierCount, 4u)
    << "only " << notifierCount
    << " notifiers were seen; the reserved-bit assertion must run against bytes that actually carry bits";
}

// Part 3 section 8 (Table 42): bits 4 to 7 of EventNotifier are reserved and must be zero - the encoder has
// to mask the upper nibble off. Asserting only that they are clear would also pass against a server
// that returned zero for everything, so the same sweep checks that the DEFINED bits survive on the
// nodes configured to carry them.
// @verifies AC-SVR-EVT-ATTR-012-RESERVED-BITS-ZERO
TEST_F(ComplianceEventNotifierAttribute, ReservedBitsFourToSevenAreClearOnEveryNotifier)
{
  auto swept = sweep_objects_and_views(*mSession, NodeId{ObjectId::RootFolder});

  std::vector<NodeId> nodeIds;
  for (const auto& node : swept)
    nodeIds.push_back(node.nodeId);
  for (const auto& nodeId : known_notifiers())
    nodeIds.push_back(nodeId);

  ASSERT_GE(nodeIds.size(), 20u) << "the hierarchy sweep found too few Objects/Views to be meaningful";

  ReadRequest req;
  for (const auto& nodeId : nodeIds)
  {
    ReadValueId rv;
    rv.node_id() = nodeId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
    req.nodes_to_read().push_back(std::move(rv));
  }
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_TRUE(resp.response_header().service_result().is_good());
  ASSERT_EQ(resp.results().size(), nodeIds.size());

  size_t notifierCount = 0;
  for (size_t i = 0; i < nodeIds.size(); ++i)
  {
    const auto& result = resp.results()[i];
    const bool good = !result.status().has_value() || result.status()->is_good();
    if (!good || !result.value().is_uint8())
      continue;
    const auto raw = result.value().as<uint8_t>();
    if (raw != 0)
      ++notifierCount;
    EXPECT_EQ(raw & 0xF0, 0u) << "reserved bits 4-7 are set on " << describe_node_id(nodeIds[i])
                              << ", EventNotifier = 0x" << std::hex << static_cast<int>(raw) << std::dec;
  }

  EXPECT_GE(notifierCount, 4u)
    << "only " << notifierCount
    << " notifiers were seen; the reserved-bit assertion must run against bytes that actually carry bits";

  // The defined bits (0, 2, 3) must survive the masking that clears 4-7 - otherwise a server that
  // zeroed the whole byte would satisfy the assertion above.
  const uint8_t allDefined = 0x0D;
  EXPECT_EQ(read_event_notifier_raw(*mSession, mAllDefinedBitsObjectId) & allDefined, allDefined)
    << "masking the reserved nibble must not disturb SubscribeToEvents/HistoryRead/HistoryWrite";
  EXPECT_EQ(read_event_notifier_raw(*mSession, mNotifierViewId) & allDefined, allDefined)
    << "the same must hold for the View NodeClass";
}

// Auditing is off by default (`ServerConfig::auditingEnabled`, "zero runtime cost"), so the
// audit record the obligation is about only exists on a Server that has opted in - which an
// aggregating Server, whose whole purpose here is to leave a correlatable trail, necessarily has.
class ComplianceAuditingEventWithNodes : public ComplianceEventWithNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceEventWithNodes::configure_server_config(cfg);
    cfg.auditingEnabled = true;
  }
};

// Part 3 section 4.6: the `auditEntryId` is the thread that links one Client's action across the servers
// that carry it out. When an aggregating Server relays a request upstream it maps the caller onto one
// of its own accounts, so the upstream Server's record names the aggregator rather than the person -
// and the AuditEntryId is then the only field that ties the two trails together.
//
// This SDK is not an aggregating Server: nothing under `sdk/` relays a request to an upstream peer.
// What it supplies is the half an aggregator is built out of, and that half is testable here. On
// ordinary Service requests the SDK stamps no `auditEntryId` of its own - the only stamping sites are
// `OpenSecureChannel` and the three Session lifecycle requests, and even those fill the field in only
// when it is empty (`ua_client_session_impl.cpp:2355-2356`). So the id an aggregator writes onto an
// outbound request is the id that goes on the wire, and it must arrive intact in the peer's audit
// record.
//
// That is what this drives, across a real Client-to-Server boundary: a distinctive id is placed on a
// Write the way an aggregator would place the one it received, and the AuditWriteUpdateEvent the
// Server emits is read back through a subscription. A stack that generated its own id, dropped the
// field, or truncated it would break the correlation silently - the Write would still succeed and
// both audit trails would still be written, each naming an action neither could be matched to.
// @verifies AC-SVR-ADDRSP-244-AGGREGATOR-FORWARDS-AUDITENTRYID
TEST_F(ComplianceAuditingEventWithNodes, AnAuditEntryIdSetByTheCallerReachesThePeersAuditRecordUnchanged)
{
  using namespace std::chrono_literals;

  // Deliberately not a value this stack could invent: an aggregator forwards an id allocated upstream.
  const String forwardedId{"urn:aggregator:upstream-trail:7f3a-2c91"};

  SimpleAttributeOperand auditEntrySelect;
  auditEntrySelect.type_definition_id() = NodeId{ObjectTypeId::AuditEventType};
  auditEntrySelect.browse_path().push_back(QualifiedName{0, "ClientAuditEntryId"});
  auditEntrySelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  SimpleAttributeOperand eventTypeSelect;
  eventTypeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventTypeSelect.browse_path().push_back(QualifiedName{0, "EventType"});
  eventTypeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(auditEntrySelect);
  filter.select_clauses().push_back(eventTypeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::AuditEventType});

  auto miId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  ASSERT_NE(miId, 0u);

  auto request = WriteRequestBuilder{}.write(mWritableVariableId, Variant{int32_t{8080}}).build();
  request.request_header().audit_entry_id() = forwardedId;
  auto writeResp = mSession->attributes().write_sync(std::move(request));
  ASSERT_FALSE(writeResp.results().empty());
  ASSERT_TRUE(writeResp.results()[0].is_good())
    << "the Write itself failed, so no audit record was produced to correlate: "
    << writeResp.results()[0].as_uint32();

  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_FALSE(events.empty())
    << "the Write emitted no Audit event, so nothing on this Server records the action the "
       "upstream trail would have to be matched against";

  std::vector<std::string> observed;
  bool matched = false;
  for (const auto& event : events)
  {
    if (event.event_fields().empty())
      continue;
    const auto& field = event.event_fields()[0];
    if (field.empty())
    {
      observed.emplace_back("(null)");
      continue;
    }
    const auto carried = std::string{string_view{field.as<String>()}};
    observed.push_back(carried);
    if (carried == std::string{string_view{forwardedId}})
      matched = true;
  }

  EXPECT_TRUE(matched)
    << "no Audit event carried the forwarded AuditEntryId. " << events.size()
    << " event(s) arrived carrying: " << (observed.empty() ? std::string{"nothing"} : observed.front())
    << ". The id the caller set is the only field linking this Server's record to the upstream one, "
       "and a record that does not carry it cannot be correlated at all";
}

// ===========================================================================
// RegisterNodes aliasing and the canonical NodeId in an audit record
// ===========================================================================

namespace
{

/// A namespace that aliases on RegisterNodes: a Client that registers a Node is handed a second,
/// Session-scoped NodeId, and `find_node` resolves that alias back to the very same Node. Two
/// NodeIds, one Node - which is what a registration handle is, and what makes the audit question
/// meaningful. A fake that returned a *different* Node would make an audit record naming it
/// unremarkable.
///
/// The default namespace echoes the request's NodeIds back unchanged
/// (`ua_register_nodes_service.cpp:299`), so on a stock deployment the registered id IS the canonical
/// id and Part 4 section 5.8.5.1's prohibition is satisfied because nothing differs. The aliasing case
/// exists only where a delegate returns different ids, which the service then takes verbatim
/// (`:389`) - so this is the only arrangement in which the obligation can fail.
class AliasingNamespace : public ua::default_ns::Namespace,
                          public ua::NamespaceRegisterNodesDelegate,
                          public std::enable_shared_from_this<AliasingNamespace>
{
public:
  static std::shared_ptr<AliasingNamespace> create(ua::string_view uri, boost::asio::any_io_executor ex)
  {
    return std::shared_ptr<AliasingNamespace>(new AliasingNamespace(uri, std::move(ex)));
  }

  std::shared_ptr<ua::NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return std::static_pointer_cast<ua::NamespaceRegisterNodesDelegate>(shared_from_this());
  }

  void register_nodes_async(
    const Context&, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override
  {
    ua::BatchResult<ua::NodeId> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      const ua::NodeId alias{item.nodeId.namespace_index(), mNextAlias++};
      {
        std::lock_guard<std::mutex> lock(mMutex);
        mAliasToCanonical.emplace(ua::to_string(alias), item.nodeId);
      }
      batch.items.push_back(alias);
    }
    callback(std::move(batch));
  }

  void unregister_nodes_async(
    const Context&, std::vector<Item>, UnregisterCompleteCallback callback) noexcept override
  {
    callback(ua::VoidResult{});
  }

  /// The resolution that makes the alias a handle rather than a distinct Node.
  ///
  /// `resolve_here` is the override point, not `find_nodes_async`. Both resolution routes - the
  /// synchronous `find_node` and the batch - answer from here and from nowhere else, so an alias
  /// resolves identically whichever one the caller took. Resolution logic placed in
  /// `find_nodes_async` would be answered straight past by `find_node`, which is the documented
  /// trap on `default_ns::Namespace::resolve_here`.
  ua::NodeResult resolve_here(const ua::NodeId& nodeId) override
  {
    ua::NodeId resolved = nodeId;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      auto it = mAliasToCanonical.find(ua::to_string(nodeId));
      if (it != mAliasToCanonical.end())
        resolved = it->second;
    }
    // Qualified: this is the in-memory store's own resolution, reached without re-entering the
    // override above.
    return ua::default_ns::Namespace::resolve_here(resolved);
  }

private:
  AliasingNamespace(ua::string_view uri, boost::asio::any_io_executor ex)
    : ua::default_ns::Namespace(uri, std::move(ex))
  {}

  mutable std::mutex mMutex;
  std::map<std::string, ua::NodeId> mAliasToCanonical;
  std::atomic<uint32_t> mNextAlias{900000};
};

}  // namespace

/// A Server with the aliasing namespace above, auditing on, and one writable Variable in it.
class ComplianceAliasedRegisterAuditTest : public ComplianceWithSession
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceWithSession::configure_server_config(cfg);
    cfg.auditingEnabled = true;
  }

  void configure_server() override
  {
    ComplianceWithSession::configure_server();
    auto addressSpace = mServer.server().address_space();

    mAliasingNamespace = AliasingNamespace::create("urn:test:aliasing", mServer.thread_pool().executor());
    mAliasNamespaceIndex = addressSpace.add_namespace_sync(mAliasingNamespace);

    mCanonicalNodeId = NodeId{mAliasNamespaceIndex, uint32_t{7000}};
    auto node = addressSpace.create_node_sync(mCanonicalNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mAliasNamespaceIndex, "AliasedWritable"});
    variable->set_display_name(LocalizedText{"", "AliasedWritable"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{ValueRank::scalar});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(int32_t{1});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mCanonicalNodeId);
  }

  void SetUp() override
  {
    ComplianceWithSession::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  }

  void TearDown() override
  {
    if (mSession)
      delete_subscription(*mSession, mSubscriptionId);
    ComplianceWithSession::TearDown();
  }

  std::shared_ptr<AliasingNamespace> mAliasingNamespace;
  uint16_t mAliasNamespaceIndex{0};
  NodeId mCanonicalNodeId;
  uint32_t mSubscriptionId{0};
};

// Part 4 section 5.8.5.1: "For the purpose of Auditing, Servers shall not use the registered NodeIds but only
// the canonical NodeIds which is the value of the NodeId Attribute."
//
// An audit record naming a Session-scoped alias is unreadable after the Session ends, which is every
// audit record by the time anyone reads it. The alias means nothing to the reader, resolves to nothing,
// and cannot be correlated with any other record about the same Node.
//
// The write-audit path takes its SourceNode straight from the request -
// `auditEvent.sourceNode = flow.nodeToWrite.node_id()`
// (`sdk/implementation/server/services/ua_attribute_service_set.cpp:2865`) - and nothing between the
// request arriving and the event being emitted resolves a registered id back to its canonical one. On
// a stock deployment that is harmless, because RegisterNodes echoes the request's ids unchanged and
// the two are the same value. It stops being harmless the moment a namespace delegate aliases, which
// is the arrangement the fixture above stages and the only one in which the obligation can fail.
// @verifies AC-SVR-VIEW-REG-003-AUDIT-CANONICAL-ID
TEST_F(ComplianceAliasedRegisterAuditTest, AWriteThroughARegisteredAliasIsAuditedAgainstTheCanonicalNodeId)
{
  using namespace std::chrono_literals;

  RegisterNodesRequest registerRequest;
  registerRequest.nodes_to_register().push_back(mCanonicalNodeId);
  auto registerResponse = mSession->view().register_nodes_sync(std::move(registerRequest));
  ASSERT_EQ(registerResponse.registered_node_ids().size(), 1u);
  const NodeId alias = registerResponse.registered_node_ids()[0];

  ASSERT_NE(alias, mCanonicalNodeId)
    << "the namespace did not alias, so this test's subject does not exist: the registered id and the "
       "canonical id are the same value and no substitution is possible";

  SimpleAttributeOperand sourceNodeSelect;
  sourceNodeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  sourceNodeSelect.browse_path().push_back(QualifiedName{0, "SourceNode"});
  sourceNodeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(sourceNodeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::AuditEventType});

  auto miId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  ASSERT_NE(miId, 0u);

  // The write goes through the alias, which is what a Client does with a registration.
  auto writeResp =
    mSession->attributes().write_sync(WriteRequestBuilder{}.write(alias, Variant{int32_t{99}}).build());
  ASSERT_FALSE(writeResp.results().empty());
  ASSERT_TRUE(writeResp.results()[0].is_good())
    << "the write through the alias failed with " << writeResp.results()[0].as_uint32()
    << ", so the alias is not a working handle and no audit record about it was produced";

  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_FALSE(events.empty()) << "the write produced no Audit event to inspect";

  std::vector<std::string> named;
  bool sawCanonical = false;
  bool sawAlias = false;
  for (const auto& event : events)
  {
    if (event.event_fields().empty() || event.event_fields()[0].empty())
      continue;
    const auto source = event.event_fields()[0].as<NodeId>();
    named.push_back(ua::to_string(source));
    if (source == mCanonicalNodeId)
      sawCanonical = true;
    if (source == alias)
      sawAlias = true;
  }

  EXPECT_FALSE(sawAlias)
    << "an Audit event names the registered alias " << ua::to_string(alias)
    << ". Part 4 section 5.8.5.1 forbids it, and the reason is that the alias is Session-scoped: once "
       "the Session ends the record names something that resolves to nothing and cannot be correlated "
       "with any other record about the same Node";
  EXPECT_TRUE(sawCanonical) << "no Audit event names the canonical NodeId " << ua::to_string(mCanonicalNodeId)
                            << ". " << named.size() << " event(s) arrived naming: "
                            << (named.empty() ? std::string{"nothing"} : named.front());
}

// Part 4 5.10.4.1 leaves the order undefined when one Write names the same Node and Attribute twice. The
// Server runs such a request in request order, so the Variable ends on the last value written - what the
// CTT's Monitor Triggering 015 expects when it writes one Variable through two MonitoredItems in one call.
// With auditing on and an Event subscriber present, each Value write first reads the old value for its
// AuditWriteUpdateEvent; run concurrently, the two operations then finished in either order and the
// Variable kept the earlier value.
TEST_F(ComplianceAuditingEventWithNodes, AWriteThatNamesOneVariableTwiceEndsOnTheLastValue)
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  const auto monitoredItemId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  ASSERT_NE(monitoredItemId, 0u) << "an Event subscriber is what gives the audit path something to do";

  for (int32_t round = 0; round < 20; ++round)
  {
    // As in Monitor Triggering 015, the first operation writes the value the Variable already holds.
    const int32_t first = 1000 + 2 * round;
    ASSERT_TRUE(mSession->attributes()
                  .write_sync(WriteRequestBuilder{}.write(mWritableVariableId, Variant{first}).build())
                  .results()[0]
                  .is_good());
    auto request = WriteRequestBuilder{}
                     .write(mWritableVariableId, Variant{first})
                     .write(mWritableVariableId, Variant{first + 1})
                     .build();
    auto resp = mSession->attributes().try_write_sync(std::move(request));
    ASSERT_TRUE(resp.is_good());
    ASSERT_EQ(resp.value().results().size(), 2u);
    ASSERT_TRUE(resp.value().results()[0].is_good() && resp.value().results()[1].is_good());

    ReadRequest read;
    ReadValueId target;
    target.node_id() = mWritableVariableId;
    target.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    read.nodes_to_read().push_back(std::move(target));
    auto value = mSession->attributes().read_sync(std::move(read));
    ASSERT_EQ(value.results().size(), 1u);
    const auto* written = value.results()[0].value().try_as<int32_t>();
    ASSERT_NE(written, nullptr);
    ASSERT_EQ(*written, first + 1) << "round " << round << ": the earlier value was applied last";
  }
}

// Part 5 section 6.4.25, AuditWriteUpdateEventType: "OldValue identifies the value that the Attribute
// contained before the write. If the IndexRange is provided, only the value of that range is shown." A
// Write of a range is audited with the old value of that range; an unranged Write, the control, with the
// whole value it replaced.
class WriteAudit : public ComplianceAuditingEventWithNodes
{};

// @relation(AC-SVR-EVT-AUD-016-RANGED-WRITE-OLDVALUE-NARROWED, scope=function)
TEST_F(WriteAudit, ARangedWriteAuditShowsOnlyTheRangesOldValue)
{
  using namespace std::chrono_literals;

  mServer.server()
    .address_space()
    .find_node_sync(mArrayVariableId)
    .as<VariableAccessor>()
    ->write_value_sync(Array<int32_t>{1, 2, 3, 4});

  EventFilter filter;
  const NodeId writeAuditType{ObjectTypeId::AuditWriteUpdateEventType};
  filter.select_clauses().push_back(make_select_clause("SourceNode"));
  filter.select_clauses().push_back(make_select_clause("OldValue", writeAuditType));
  filter.select_clauses().push_back(make_select_clause("NewValue", writeAuditType));
  filter.select_clauses().push_back(make_select_clause("IndexRange", writeAuditType));
  filter.select_clauses().push_back(make_select_clause("EventType"));
  filter.select_clauses().push_back(make_select_clause("SourceName"));
  filter.where_clause() = make_of_type_where_clause(writeAuditType);
  // A queue for both Events: the default of one keeps only an overflow Event when both are queued.
  const auto monitoredItemId = create_event_monitored_item(
    *mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter), {.queueSize = 16});
  ASSERT_NE(monitoredItemId, 0u);

  auto rangedResponse =
    mSession->attributes().write_sync(WriteRequestBuilder{}
                                        .write(mArrayVariableId, Variant{Array<int32_t>{20, 30}})
                                        .index_range(String{"1:2"})
                                        .build());
  ASSERT_EQ(rangedResponse.results().size(), 1u);
  ASSERT_THAT(rangedResponse.results()[0], HasStatus(Status::Good));

  auto whole = mSession->attributes().write_sync(
    WriteRequestBuilder{}.write(mArrayVariableId, Variant{Array<int32_t>{5, 6, 7, 8}}).build());
  ASSERT_EQ(whole.results().size(), 1u);
  ASSERT_THAT(whole.results()[0], HasStatus(Status::Good));

  std::vector<EventFieldList> audits;
  std::string received;
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (audits.size() < 2 && std::chrono::steady_clock::now() < deadline)
  {
    for (auto& event : collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 1s}))
    {
      received += "[";
      for (const auto& field : event.event_fields())
        received += to_string(field) + "; ";
      received += "] ";
      if (event.event_fields().size() == 6 && event.event_fields()[0] == Variant{mArrayVariableId})
        audits.push_back(std::move(event));
    }
  }
  ASSERT_EQ(audits.size(), 2u) << "each Write must raise one AuditWriteUpdateEventType Event; received "
                               << received;

  EXPECT_EQ(audits[0].event_fields()[1], (Variant{Array<int32_t>{2, 3}}))
    << "the ranged Write's OldValue is not the old value of the range it wrote: "
    << to_string(audits[0].event_fields()[1]);
  EXPECT_EQ(audits[0].event_fields()[2], (Variant{Array<int32_t>{20, 30}}))
    << to_string(audits[0].event_fields()[2]);
  EXPECT_EQ(audits[0].event_fields()[3], Variant{String{"1:2"}}) << to_string(audits[0].event_fields()[3]);

  EXPECT_EQ(audits[1].event_fields()[1], (Variant{Array<int32_t>{1, 20, 30, 4}}))
    << "the unranged Write's OldValue is not the whole value before it: "
    << to_string(audits[1].event_fields()[1]);
  EXPECT_TRUE(audits[1].event_fields()[3].empty())
    << "an unranged Write's IndexRange must be null, and an empty String is not: "
    << to_string(audits[1].event_fields()[3]);
}

// Part 4 section 7.11, Table 135, DataValue value: "If the StatusCode indicates an error then the value is to
// be ignored and the Server shall set it to null." Part 5 section 6.4.25 lets a Server that does not have the
// old value report null. A value whose status is Bad is one the Server ignores, so the audit of a Write over
// it records a null OldValue, with and without an IndexRange. The Bad DataValue is stored on the server side
// again before the second Write, because the ranged Write leaves a Good value.
// @relation(AC-SVR-EVT-AUD-016-BAD-OLDVALUE-AUDITED-AS-NULL, scope=function)
TEST_F(WriteAudit, ABadOldValueIsAuditedAsNull)
{
  using namespace std::chrono_literals;

  auto variable = mServer.server().address_space().find_node_sync(mArrayVariableId).as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  const auto storeBadValue = [&variable]
  {
    DataValue bad{Variant{Array<int32_t>{1, 2, 3, 4}}};
    bad.status() = StatusCode{Status::BadNoCommunication};
    variable->write_value_sync(std::move(bad));
  };

  EventFilter filter;
  const NodeId writeAuditType{ObjectTypeId::AuditWriteUpdateEventType};
  filter.select_clauses().push_back(make_select_clause("SourceNode"));
  filter.select_clauses().push_back(make_select_clause("OldValue", writeAuditType));
  filter.select_clauses().push_back(make_select_clause("NewValue", writeAuditType));
  filter.select_clauses().push_back(make_select_clause("IndexRange", writeAuditType));
  filter.where_clause() = make_of_type_where_clause(writeAuditType);
  // A queue for both Events: the default of one keeps only an overflow Event when both are queued.
  const auto monitoredItemId = create_event_monitored_item(
    *mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter), {.queueSize = 16});
  ASSERT_NE(monitoredItemId, 0u);

  // The old value is read before the Write is made, so what each audit records does not depend on whether the
  // Write is accepted; only that it answers.
  storeBadValue();
  auto ranged = mSession->attributes().write_sync(WriteRequestBuilder{}
                                                    .write(mArrayVariableId, Variant{Array<int32_t>{20, 30}})
                                                    .index_range(String{"1:2"})
                                                    .build());
  ASSERT_EQ(ranged.results().size(), 1u);
  storeBadValue();
  auto whole = mSession->attributes().write_sync(
    WriteRequestBuilder{}.write(mArrayVariableId, Variant{Array<int32_t>{5, 6, 7, 8}}).build());
  ASSERT_EQ(whole.results().size(), 1u);

  std::vector<EventFieldList> audits;
  std::string received;
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (audits.size() < 2 && std::chrono::steady_clock::now() < deadline)
  {
    for (auto& event : collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 1s}))
    {
      received += "[";
      for (const auto& field : event.event_fields())
        received += to_string(field) + "; ";
      received += "] ";
      if (event.event_fields().size() == 4 && event.event_fields()[0] == Variant{mArrayVariableId})
        audits.push_back(std::move(event));
    }
  }
  ASSERT_EQ(audits.size(), 2u) << "each Write must raise one AuditWriteUpdateEventType Event; received "
                               << received;

  EXPECT_TRUE(audits[0].event_fields()[1].empty())
    << "the ranged Write over a Bad value was audited with an OldValue: "
    << to_string(audits[0].event_fields()[1]);
  EXPECT_EQ(audits[0].event_fields()[2], (Variant{Array<int32_t>{20, 30}}))
    << to_string(audits[0].event_fields()[2]);
  EXPECT_EQ(audits[0].event_fields()[3], Variant{String{"1:2"}}) << to_string(audits[0].event_fields()[3]);

  EXPECT_TRUE(audits[1].event_fields()[1].empty())
    << "the unranged Write over a Bad value was audited with an OldValue: "
    << to_string(audits[1].event_fields()[1]);
  EXPECT_EQ(audits[1].event_fields()[2], (Variant{Array<int32_t>{5, 6, 7, 8}}))
    << to_string(audits[1].event_fields()[2]);
  EXPECT_TRUE(audits[1].event_fields()[3].empty())
    << "an unranged Write's IndexRange must be null: " << to_string(audits[1].event_fields()[3]);
}

// ===========================================================================
// EventClimb: which inverse References carry an Event to their source (NR-60, NR-70 F12)
// ===========================================================================

class EventClimb : public ComplianceEventWithNodes
{
protected:
  /// An Object in the test namespace with the SubscribeToEvents bit.
  void make_notifier(const NodeId& nodeId, const char* name)
  {
    auto node = mServer.server().address_space().create_node_sync(nodeId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    ASSERT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    object->set_display_name(LocalizedText{"", name});
    object->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  }

  /// A Reference of @p referenceType from @p source to @p target, with its inverse on @p target.
  void link(const NodeId& source, const NodeId& referenceType, const NodeId& target)
  {
    auto addressSpace = mServer.server().address_space();
    ASSERT_TRUE(addressSpace.find_node_sync(source)
                  .try_add_reference_sync(referenceType, ExpandedNodeId{target}, true)
                  .is_good())
      << to_string(source) << " -> " << to_string(target);
    ASSERT_TRUE(addressSpace.find_node_sync(target)
                  .try_add_reference_sync(referenceType, ExpandedNodeId{source}, false)
                  .is_good())
      << to_string(target) << " <- " << to_string(source);
  }

  /// An Event item on @p nodeId with @p clientHandle in the fixture's Subscription.
  void subscribe(const NodeId& nodeId, uint32_t clientHandle)
  {
    auto response = mSession->monitored_items().create_monitored_items_sync(
      make_event_mi_request(mSubscriptionId, nodeId, make_event_filter(), clientHandle));
    ASSERT_EQ(response.results().size(), 1u);
    ASSERT_TRUE(response.results()[0].status_code().is_good())
      << "the Event item on " << to_string(nodeId)
      << " was refused: " << to_string(response.results()[0].status_code());
  }

  /// Raises a BaseEventType Event whose SourceNode is @p source, and counts the notifications received per
  /// client handle, waiting long enough for an Event delivered where it should not be to arrive.
  std::map<uint32_t, std::size_t> raise_and_count(const NodeId& source)
  {
    GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
    event.sourceNode = source;
    event.sourceName = "ClimbSource";
    event.message = LocalizedText{"", "An Event for the climb"};
    event.severity = 100;
    mServer.server().emit_event(event);
    std::map<uint32_t, std::size_t> counts;
    for (const auto& notification :
      collect_events(*mSession, mSubscriptionId, {.minCount = 2, .timeout = std::chrono::milliseconds{1500}}))
      ++counts[notification.client_handle()];
    return counts;
  }
};

// Part 3 section 7.18 and 5.3.3.3 a): a subtype of HasNotifier inherits its delivery semantic. R is an
// application subtype of HasNotifier from P to S; Q, with no Reference to S, is the control.
// @relation(AC-SVR-ADDRSP-174-HASNOTIFIER-SUBTYPE-DELIVERS, scope=function)
TEST_F(EventClimb, AHasNotifierSubtypeDelivers)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId subtypeR{mTestNamespaceIndex, uint32_t{7800}};
  const NodeId notifierP{mTestNamespaceIndex, uint32_t{7801}};
  const NodeId sourceS{mTestNamespaceIndex, uint32_t{7802}};
  const NodeId unrelatedQ{mTestNamespaceIndex, uint32_t{7803}};
  auto referenceType = addressSpace.create_node_sync(subtypeR, NodeClass::ReferenceType);
  referenceType.set_browse_name(QualifiedName{mTestNamespaceIndex, "NotifiesApplication"});
  referenceType.set_display_name(LocalizedText{"", "NotifiesApplication"});
  link(NodeId{ReferenceTypeId::HasNotifier}, NodeId{ReferenceTypeId::HasSubtype}, subtypeR);
  make_notifier(notifierP, "NotifierP");
  make_notifier(sourceS, "SourceS");
  make_notifier(unrelatedQ, "UnrelatedQ");
  link(notifierP, subtypeR, sourceS);
  subscribe(notifierP, 1);
  subscribe(unrelatedQ, 2);

  const auto counts = raise_and_count(sourceS);

  EXPECT_EQ(counts.count(1) > 0 ? counts.at(1) : 0u, 1u)
    << "the Event at the target of an application subtype of HasNotifier did not reach its source";
  EXPECT_EQ(counts.count(2), 0u) << "the Event reached an Object with no Reference to its source";
}

// The Server Object is the root of the event hierarchy (Part 9 section 6.2); NR-60 does not continue the
// climb above it, and DL-46 keeps that for an Event whose SourceNode is the Server Object. The Server
// Object's own item is the control that each Event is delivered at the root.
// @relation(AC-SVR-ADDRSP-174-CLIMB-STOPS-AT-SERVER-OBJECT, scope=function)
TEST_F(EventClimb, AnObjectAboveTheServerObjectGetsNoEventFromAnUnrelatedSource)
{
  const NodeId serverObject{ObjectId::Server};
  const NodeId sourceS{mTestNamespaceIndex, uint32_t{7810}};
  const NodeId aboveX{mTestNamespaceIndex, uint32_t{7811}};
  make_notifier(sourceS, "ServerChildS");
  make_notifier(aboveX, "AboveServerX");
  link(serverObject, NodeId{ReferenceTypeId::HasNotifier}, sourceS);
  link(aboveX, NodeId{ReferenceTypeId::HasNotifier}, serverObject);
  subscribe(serverObject, 1);
  subscribe(aboveX, 2);

  const auto countsForS = raise_and_count(sourceS);

  EXPECT_EQ(countsForS.count(1) > 0 ? countsForS.at(1) : 0u, 1u)
    << "the Server Object did not receive the Event of S";
  EXPECT_EQ(countsForS.count(2), 0u)
    << "the climb from S continued above the Server Object to an Object that references it";

  const auto countsForServerObject = raise_and_count(serverObject);

  EXPECT_EQ(countsForServerObject.count(1) > 0 ? countsForServerObject.at(1) : 0u, 1u)
    << "the Server Object did not receive the Event whose SourceNode is the Server Object";
  EXPECT_EQ(countsForServerObject.count(2), 0u)
    << "the Event whose SourceNode is the Server Object climbed to an Object that references it";
}

// Part 9 section 6.2 links areas to their ConditionSources by HasNotifier and HasEventSource; a Variable
// source is reached only by HasEventSource (NR-60). B, with no Reference to V, is the control.
// @relation(AC-SVR-AC-085-AREA-RECEIVES-ITS-SOURCES-EVENTS, scope=function)
TEST_F(EventClimb, AnAreaLinkedByHasEventSourceReceivesItsSourcesEvents)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId areaA{mTestNamespaceIndex, uint32_t{7820}};
  const NodeId variableV{mTestNamespaceIndex, uint32_t{7821}};
  const NodeId otherB{mTestNamespaceIndex, uint32_t{7822}};
  make_notifier(areaA, "AreaA");
  make_notifier(otherB, "OtherB");
  link(NodeId{ObjectId::Server}, NodeId{ReferenceTypeId::HasNotifier}, areaA);
  auto variable = addressSpace.create_node_sync(variableV, NodeClass::Variable);
  variable.set_browse_name(QualifiedName{mTestNamespaceIndex, "SourceV"});
  variable.set_display_name(LocalizedText{"", "SourceV"});
  link(areaA, NodeId{ReferenceTypeId::HasEventSource}, variableV);
  subscribe(areaA, 1);
  subscribe(otherB, 2);

  const auto counts = raise_and_count(variableV);

  EXPECT_EQ(counts.count(1) > 0 ? counts.at(1) : 0u, 1u)
    << "the area did not receive the Event of the source it links by HasEventSource";
  EXPECT_EQ(counts.count(2), 0u) << "the Event reached an Object with no Reference to its source";
}

// ===========================================================================
// EventsInAView: a View delivers the Events of its members (NR-16, NR-28 rule 1, NR-70 F13)
// ===========================================================================

// Part 3 section 5.4: "A View that supports Events shall provide all Events that occur in any Object used as
// EventNotifier that is part of the content of the View." The content is the View's membership. V's members A
// and B are reachable in V's context from the View Node (A by Organizes, B from A by an application
// non-hierarchical ReferenceType); C lies below the View Node by Organizes and is not a member.
class EventsInAView : public EventClimb
{
protected:
  void SetUp() override
  {
    EventClimb::SetUp();
    auto addressSpace = mServer.server().address_space();
    mView = NodeId{mTestNamespaceIndex, uint32_t{7900}};
    mMemberA = NodeId{mTestNamespaceIndex, uint32_t{7901}};
    mMemberB = NodeId{mTestNamespaceIndex, uint32_t{7902}};
    mBelowC = NodeId{mTestNamespaceIndex, uint32_t{7903}};
    const NodeId nonHierarchicalR{mTestNamespaceIndex, uint32_t{7904}};

    auto referenceType = addressSpace.create_node_sync(nonHierarchicalR, NodeClass::ReferenceType);
    referenceType.set_browse_name(QualifiedName{mTestNamespaceIndex, "RelatesApplication"});
    referenceType.set_display_name(LocalizedText{"", "RelatesApplication"});
    link(NodeId{ReferenceTypeId::NonHierarchicalReferences},
      NodeId{ReferenceTypeId::HasSubtype},
      nonHierarchicalR);

    auto viewNode = addressSpace.create_node_sync(mView, NodeClass::View);
    auto view = viewNode.as<ViewAccessor>();
    ASSERT_TRUE(view.has_value());
    view->set_browse_name(QualifiedName{mTestNamespaceIndex, "EventView"});
    view->set_display_name(LocalizedText{"", "EventView"});
    view->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    link(NodeId{ObjectId::ViewsFolder}, NodeId{ReferenceTypeId::Organizes}, mView);
    make_notifier(mMemberA, "ViewMemberA");
    make_notifier(mMemberB, "ViewMemberB");
    make_notifier(mBelowC, "BelowViewC");
    link(mView, NodeId{ReferenceTypeId::Organizes}, mMemberA);
    link(mMemberA, nonHierarchicalR, mMemberB);
    link(mView, NodeId{ReferenceTypeId::Organizes}, mBelowC);
    ASSERT_TRUE(view->try_add_node_to_view_sync(mMemberA).is_good());
    ASSERT_TRUE(view->try_add_node_to_view_sync(mMemberB).is_good());
    subscribe(mView, 1);
  }

  /// Raises one Event on each of @p sources and returns the SourceNodes delivered through the View.
  std::set<NodeId> delivered_through_the_view(std::initializer_list<NodeId> sources)
  {
    for (const auto& source : sources)
    {
      GenericEvent event{NodeId{ObjectTypeId::BaseEventType}};
      event.sourceNode = source;
      event.sourceName = "ViewSource";
      event.message = LocalizedText{"", "An Event for the View"};
      event.severity = 100;
      mServer.server().emit_event(event);
    }
    std::set<NodeId> delivered;
    for (const auto& notification : collect_events(*mSession,
           mSubscriptionId,
           {.minCount = sources.size() + 1, .timeout = std::chrono::milliseconds{1500}}))
    {
      if (notification.client_handle() != 1 || notification.event_fields().size() < 3)
        continue;
      if (const auto* source = notification.event_fields()[2].try_as<NodeId>())
        delivered.insert(*source);
    }
    return delivered;
  }

  NodeId mView;
  NodeId mMemberA;
  NodeId mMemberB;
  NodeId mBelowC;
};

// B is a member reached from A by a non-hierarchical Reference, so nothing hierarchical leads to it from the
// View Node. The View's own Event and A's are the controls.
// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
TEST_F(EventsInAView, ANotifierInTheViewButNotBelowItsNodeDelivers)
{
  const auto delivered = delivered_through_the_view({mView, mMemberA, mMemberB});

  EXPECT_TRUE(delivered.contains(mView)) << "the View's own Event was not delivered";
  EXPECT_TRUE(delivered.contains(mMemberA)) << "the Event of member A was not delivered through the View";
  EXPECT_TRUE(delivered.contains(mMemberB))
    << "the Event of member B, which no hierarchical Reference from the View Node reaches, was not delivered";
}

// C lies below the View Node by Organizes but the View does not contain it. A's Event is the control that the
// View's item receives Events at all.
// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
TEST_F(EventsInAView, ANotifierBelowTheViewNodeButNotInTheViewDeliversNothing)
{
  const auto delivered = delivered_through_the_view({mMemberA, mBelowC});

  EXPECT_TRUE(delivered.contains(mMemberA)) << "the Event of member A was not delivered through the View";
  EXPECT_FALSE(delivered.contains(mBelowC))
    << "the Event of C, below the View Node but not a member, was delivered through the View";
}

// ===========================================================================
// CreateMonitoredItems of items on NodeIds the namespace does not hold (COMP-SVR-NAMESPACE-CALLS-13)
// ===========================================================================

class CreateEventItem : public ComplianceEventWithNodes
{
protected:
  /// A Value item on @p nodeId sampled at 50 ms.
  static MonitoredItemCreateRequest value_item(const NodeId& nodeId, uint32_t clientHandle)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = nodeId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 50.0;
    item.requested_parameters().queue_size() = 1;
    item.requested_parameters().discard_oldest() = true;
    return item;
  }

  /// The server handles GetMonitoredItems answers for @p subscriptionId, in ascending order.
  std::vector<uint32_t> items_held(uint32_t subscriptionId)
  {
    Array<Variant> arguments;
    arguments.push_back(Variant{subscriptionId});
    CallMethodRequest method;
    method.object_id() = NodeId{ObjectId::Server};
    method.method_id() = NodeId{MethodId::Server_GetMonitoredItems};
    method.input_arguments() = std::move(arguments);
    CallRequest request;
    request.methods_to_call().push_back(std::move(method));
    auto response = mSession->methods().call_sync(std::move(request));
    if (response.results().size() != 1u || !StatusCode{response.results()[0].status_code()}.is_good() ||
        response.results()[0].output_arguments().size() != 2u)
    {
      ADD_FAILURE() << "GetMonitoredItems did not answer the subscription's handles";
      return {};
    }
    const auto handles = response.results()[0].output_arguments()[0].as<Array<uint32_t>>();
    std::vector<uint32_t> held(handles.begin(), handles.end());
    std::sort(held.begin(), held.end());
    return held;
  }
};

// COMP-SVR-NAMESPACE-CALLS-13 rule 2, Part 4 5.12.2.4 Table 71 and 5.12.2.1: a data item and an event item on
// NodeIds the test namespace does not hold are refused Bad_NodeIdUnknown in the CreateMonitoredItems results
// and never become items of the Subscription; an item on a Variable it holds is created. The integration arm.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-UNKNOWN-NODE-REFUSES-A-DATA-OR-EVENT-ITEM, scope=function)
TEST_F(CreateEventItem, AnUnknownNodeIsBadNodeIdUnknown)
{
  const NodeId unknownData{mTestNamespaceIndex, uint32_t{99999}};
  const NodeId unknownNotifier{mTestNamespaceIndex, uint32_t{99998}};
  auto eventRequest = make_event_mi_request(mSubscriptionId, unknownNotifier, make_event_filter(), 2);
  CreateMonitoredItemsRequest request;
  request.subscription_id() = mSubscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_create().push_back(value_item(unknownData, 1));
  request.items_to_create().push_back(std::move(eventRequest.items_to_create()[0]));
  request.items_to_create().push_back(value_item(mWritableVariableId, 3));

  auto response = mSession->monitored_items().create_monitored_items_sync(std::move(request));

  ASSERT_EQ(response.results().size(), 3u);
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::BadNodeIdUnknown)
    << "row 1: " << to_string(response.results()[0].status_code());
  EXPECT_EQ(response.results()[1].status_code().as_status(), Status::BadNodeIdUnknown)
    << "row 2: " << to_string(response.results()[1].status_code());
  ASSERT_EQ(response.results()[2].status_code().as_status(), Status::Good)
    << "row 3: " << to_string(response.results()[2].status_code());
  EXPECT_EQ(items_held(mSubscriptionId),
    std::vector<uint32_t>{static_cast<uint32_t>(response.results()[2].monitored_item_id())})
    << "the Subscription holds an item of row 1 or row 2";
}
