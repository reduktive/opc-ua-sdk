// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 5 sections 6.4.31 and 6.4.33: a ModelChangeEvent or SemanticChangeEvent generated for the whole
// AddressSpace has the Server Object as its SourceNode and "Server" as its SourceName. The SDK generates both
// in that context only, so a Client subscribed to the Server Object receives them with those two fields, and
// a View's subscribers are owed none of them (Part 3 section 5.4).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_datatype_id.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_notifier_type.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// The fields every filter below selects, in this order.
constexpr std::size_t eventTypeField = 0;
constexpr std::size_t sourceNodeField = 1;
constexpr std::size_t sourceNameField = 2;

// An EventFilter selecting EventType, SourceNode and SourceName, restricted to `typeId` and its subtypes.
EventFilter context_fields_filter(const NodeId& typeId)
{
  EventFilter filter;
  for (const char* field : {"EventType", "SourceNode", "SourceName"})
  {
    SimpleAttributeOperand clause;
    clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    clause.browse_path().push_back(QualifiedName{uint16_t{0}, field});
    clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(clause));
  }
  LiteralOperand operand;
  operand.value() = Variant{typeId};
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  element.filter_operands().push_back(
    RefStructure<Structure>{std::make_unique<LiteralOperand>(std::move(operand))});
  filter.where_clause().elements().push_back(std::move(element));
  return filter;
}

// The collected Events carrying `clientHandle`.
std::vector<const EventFieldList*> events_for(
  const std::vector<EventFieldList>& events, uint32_t clientHandle)
{
  std::vector<const EventFieldList*> matching;
  for (const auto& event : events)
  {
    if (event.client_handle() == clientHandle)
      matching.push_back(&event);
  }
  return matching;
}

std::string source_name_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= sourceNameField)
    return "<SourceName not returned>";
  const auto* name = event.event_fields()[sourceNameField].try_as<String>();
  return name == nullptr ? std::string{"<SourceName not a String>"}
                         : std::string{static_cast<std::string_view>(*name)};
}

std::string source_node_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= sourceNodeField)
    return "<SourceNode not returned>";
  const auto* node = event.event_fields()[sourceNodeField].try_as<NodeId>();
  return node == nullptr ? std::string{"<SourceNode not a NodeId>"} : ua::to_string(*node);
}

class ModelChangeEventSource : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // A Variable carrying a NodeVersion Property: a change of its DataType is a model change the SDK
    // reports (Part 3 section 9.32.2).
    mVersionedVariableId = NodeId{mTestNamespaceIndex, uint32_t{7400}};
    const NodeId nodeVersionId{mTestNamespaceIndex, uint32_t{7401}};
    auto versioned = addressSpace.create_node_sync(mVersionedVariableId, NodeClass::Variable);
    versioned.set_browse_name(QualifiedName{mTestNamespaceIndex, "VersionedValue"});
    versioned.set_display_name(LocalizedText{"", "VersionedValue"});
    versioned.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto versionedVariable = versioned.as<VariableAccessor>();
    ASSERT_TRUE(versionedVariable.has_value());
    versionedVariable->set_data_type(NodeId{DataTypeId::Int32});
    versionedVariable->set_value_rank(ValueRank{ValueRank::scalar});
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mVersionedVariableId);
    versioned.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);

    auto nodeVersion = addressSpace.create_node_sync(nodeVersionId, NodeClass::Variable);
    nodeVersion.set_browse_name(QualifiedName{0, "NodeVersion"});
    nodeVersion.set_display_name(LocalizedText{"", "NodeVersion"});
    nodeVersion.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    auto nodeVersionVariable = nodeVersion.as<VariableAccessor>();
    ASSERT_TRUE(nodeVersionVariable.has_value());
    nodeVersionVariable->set_data_type(NodeId{DataTypeId::String});
    nodeVersionVariable->write_value_sync(String{"1"});
    versioned.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, nodeVersionId);
    nodeVersion.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{mVersionedVariableId}, /*isForward=*/false);

    // A Variable with a Property whose AccessLevel sets the SemanticChange bit (Part 3 section 5.6.2).
    const NodeId ownerId{mTestNamespaceIndex, uint32_t{7402}};
    mFlaggedPropertyId = NodeId{mTestNamespaceIndex, uint32_t{7403}};
    auto owner = addressSpace.create_node_sync(ownerId, NodeClass::Variable);
    owner.set_browse_name(QualifiedName{mTestNamespaceIndex, "SemanticallyDescribedValue"});
    owner.set_display_name(LocalizedText{"", "SemanticallyDescribedValue"});
    owner.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    if (auto variable = owner.as<VariableAccessor>())
    {
      variable->set_data_type(NodeId{DataTypeId::Double});
      variable->set_value_rank(ValueRank{ValueRank::scalar});
      variable->write_value_sync(double{1.0});
    }
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ownerId);
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);

    auto property = addressSpace.create_node_sync(mFlaggedPropertyId, NodeClass::Variable);
    property.set_browse_name(QualifiedName{mTestNamespaceIndex, "ScalingFactor"});
    property.set_display_name(LocalizedText{"", "ScalingFactor"});
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    auto propertyVariable = property.as<VariableAccessor>();
    ASSERT_TRUE(propertyVariable.has_value());
    propertyVariable->set_data_type(NodeId{DataTypeId::Double});
    propertyVariable->set_value_rank(ValueRank{ValueRank::scalar});
    propertyVariable->write_value_sync(double{1.0});
    propertyVariable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::SemanticChange});
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, mFlaggedPropertyId);
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{ownerId}, /*isForward=*/false);

    // A View whose EventNotifier sets SubscribeToEvents and whose content holds the versioned Variable. No
    // View in the SDK supports Events, so the test sets the EventNotifier itself.
    mViewId = NodeId{mTestNamespaceIndex, uint32_t{7404}};
    auto viewNode = addressSpace.create_node_sync(mViewId, NodeClass::View);
    viewNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "ModelChangeView"});
    viewNode.set_display_name(LocalizedText{"", "ModelChangeView"});
    addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mViewId);
    viewNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mVersionedVariableId);
    auto view = viewNode.as<ViewAccessor>();
    ASSERT_TRUE(view.has_value());
    view->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    ASSERT_TRUE(view->try_add_node_to_view_sync(mVersionedVariableId).is_good())
      << "the View could not be given the Variable whose change it is about";
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  }

  void TearDown() override
  {
    if (mSession)
      delete_subscription(*mSession, mSubscriptionId);
    ComplianceWithNodes::TearDown();
  }

  uint32_t monitor_events(const NodeId& notifier, const NodeId& eventType, uint32_t clientHandle)
  {
    return create_event_monitored_item(*mSession,
      mSubscriptionId,
      notifier,
      context_fields_filter(eventType),
      {.clientHandle = clientHandle, .samplingInterval = 0.0, .queueSize = 20});
  }

  // The application changes the DataType of the versioned Variable.
  void change_the_data_type()
  {
    auto variable =
      mServer.server().address_space().find_node_sync(mVersionedVariableId).as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Double});
  }

  // Asserts that `event` names the whole AddressSpace as its context: SourceNode i=2253, SourceName "Server".
  static void expect_server_context(const EventFieldList& event, const NodeId& eventType)
  {
    ASSERT_GT(event.event_fields().size(), sourceNameField)
      << "the Event did not return the three selected fields";
    const auto* type = event.event_fields()[eventTypeField].try_as<NodeId>();
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(*type, eventType);
    EXPECT_EQ(source_node_of(event), ua::to_string(NodeId{ObjectId::Server}));
    EXPECT_EQ(source_name_of(event), "Server")
      << "a change Event generated for the whole AddressSpace does not carry the SourceName \"Server\"";
  }

  NodeId mVersionedVariableId;
  NodeId mFlaggedPropertyId;
  NodeId mViewId;
  uint32_t mSubscriptionId{0};
};

constexpr uint32_t serverHandle = 51;
constexpr uint32_t viewHandle = 52;

}  // namespace

// @relation(AC-SVR-EVT-TYP-013-SOURCENODE-SERVER-OBJECT, scope=function)
// @relation(AC-SVR-EVT-TYP-014-SOURCENAME-SERVER, scope=function)
TEST_F(ModelChangeEventSource, SourceNameIsServer)
{
  ASSERT_NE(
    monitor_events(NodeId{ObjectId::Server}, NodeId{ObjectTypeId::GeneralModelChangeEventType}, serverHandle),
    0u);

  change_the_data_type();

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  const auto received = events_for(events, serverHandle);
  ASSERT_EQ(received.size(), 1u) << "the DataType change of a versioned Variable was not reported as one "
                                 << "GeneralModelChangeEvent through the Server Object";
  expect_server_context(*received.front(), NodeId{ObjectTypeId::GeneralModelChangeEventType});
}

// @relation(AC-SVR-EVT-TYP-016-SOURCENODE-SERVER-OBJECT, scope=function)
// @relation(AC-SVR-EVT-TYP-017-SOURCENAME-SERVER, scope=function)
TEST_F(ModelChangeEventSource, SemanticChangeEventSourceNameIsServer)
{
  ASSERT_NE(
    monitor_events(NodeId{ObjectId::Server}, NodeId{ObjectTypeId::SemanticChangeEventType}, serverHandle),
    0u);

  auto write =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mFlaggedPropertyId, Variant{double{2.5}}));
  ASSERT_THAT(write, WriteSucceeds())
    << "the flagged Property did not change, so no SemanticChangeEvent is owed";

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  const auto received = events_for(events, serverHandle);
  ASSERT_EQ(received.size(), 1u) << "the write of a SemanticChange-flagged Property was not reported as one "
                                 << "SemanticChangeEvent through the Server Object";
  expect_server_context(*received.front(), NodeId{ObjectTypeId::SemanticChangeEventType});
}

// The Server Object item in the same Subscription is the control: the change is reported, and only the View
// is not told.
// @relation(AC-SVR-EVT-ATTR-006-VIEW-MODELCHANGE-EVENTS, scope=function)
TEST_F(ModelChangeEventSource, AViewItemReceivesNoModelChangeEventForAChangeToItsContent)
{
  ASSERT_NE(monitor_events(mViewId, NodeId{ObjectTypeId::BaseModelChangeEventType}, viewHandle), 0u)
    << "the View refused an event MonitoredItem, so its silence below would mean nothing";
  ASSERT_NE(
    monitor_events(NodeId{ObjectId::Server}, NodeId{ObjectTypeId::GeneralModelChangeEventType}, serverHandle),
    0u);

  change_the_data_type();

  // Two are collected if the View is told, so the window stays open until the timeout when it is not.
  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 2, .timeout = 1s});
  const auto atServer = events_for(events, serverHandle);
  ASSERT_EQ(atServer.size(), 1u) << "the change was not reported through the Server Object, so the stimulus "
                                 << "never happened and the View's silence proves nothing";
  expect_server_context(*atServer.front(), NodeId{ObjectTypeId::GeneralModelChangeEventType});
  EXPECT_TRUE(events_for(events, viewHandle).empty())
    << "a ModelChangeEvent generated for the whole AddressSpace reached a View; its SourceNode is "
    << source_node_of(*events_for(events, viewHandle).front());
}
