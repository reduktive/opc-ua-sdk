// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 3 section 5.6.2, Table 13, NodeVersion: "changes to the DataType, ValueRank or ArrayDimensions
// Attributes of a Variable lead to an update of the NodeVersion Property", and section 9.32.2 ties each
// NodeVersion change to a ModelChangeEvent. ModelChangeStructureVerbMask has no verb for a ValueRank or
// ArrayDimensions change, so the Event is a BaseModelChangeEvent (section 9.32.5). A Client writes the
// Attributes through the Write service and subscribes to the Server Object; a repeated write and a Variable
// without NodeVersion are the controls.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_datatype_id.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
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

constexpr std::size_t eventTypeField = 0;
constexpr std::size_t sourceNodeField = 1;
constexpr std::size_t messageField = 2;
constexpr uint32_t serverHandle = 61;

// An EventFilter selecting EventType, SourceNode and Message of BaseModelChangeEventType and its subtypes.
EventFilter model_change_filter()
{
  EventFilter filter;
  for (const char* field : {"EventType", "SourceNode", "Message"})
  {
    SimpleAttributeOperand clause;
    clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    clause.browse_path().push_back(QualifiedName{uint16_t{0}, field});
    clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(clause));
  }
  LiteralOperand operand;
  operand.value() = Variant{NodeId{ObjectTypeId::BaseModelChangeEventType}};
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  element.filter_operands().push_back(
    RefStructure<Structure>{std::make_unique<LiteralOperand>(std::move(operand))});
  filter.where_clause().elements().push_back(std::move(element));
  return filter;
}

std::string event_type_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= eventTypeField)
    return "<EventType not returned>";
  const auto* type = event.event_fields()[eventTypeField].try_as<NodeId>();
  return type == nullptr ? std::string{"<EventType not a NodeId>"} : to_string(*type);
}

std::string message_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= messageField)
    return "<Message not returned>";
  const auto* message = event.event_fields()[messageField].try_as<LocalizedText>();
  return message == nullptr ? std::string{"<Message not a LocalizedText>"}
                            : std::string{static_cast<std::string_view>(message->text())};
}

std::string text(const std::vector<EventFieldList>& events)
{
  std::string out = "{";
  for (const auto& event : events)
  {
    out += (out.size() > 1 ? ", " : "") + event_type_of(event) + " \"" + message_of(event) + "\"";
  }
  return out + "}";
}

// Good when a Write item answered Good; otherwise names the status it answered.
::testing::AssertionResult written(const StatusCode& status)
{
  if (status.as_status() == Status::Good)
    return ::testing::AssertionSuccess();
  return ::testing::AssertionFailure() << "the Write answered " << to_string(status);
}

class ModelChangeOnAttributes : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    mVersionedId = NodeId{mTestNamespaceIndex, uint32_t{7500}};
    mNodeVersionId = NodeId{mTestNamespaceIndex, uint32_t{7501}};
    mUnversionedId = NodeId{mTestNamespaceIndex, uint32_t{7502}};
    add_shape_writable_variable(mVersionedId, "ReshapedVersioned");
    add_shape_writable_variable(mUnversionedId, "ReshapedUnversioned");

    auto versioned = addressSpace.find_node_sync(mVersionedId);
    auto nodeVersion = addressSpace.create_node_sync(mNodeVersionId, NodeClass::Variable);
    nodeVersion.set_browse_name(QualifiedName{0, "NodeVersion"});
    nodeVersion.set_display_name(LocalizedText{"", "NodeVersion"});
    nodeVersion.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    auto nodeVersionVariable = nodeVersion.as<VariableAccessor>();
    ASSERT_TRUE(nodeVersionVariable.has_value());
    nodeVersionVariable->set_data_type(NodeId{DataTypeId::String});
    versioned.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, mNodeVersionId);
    nodeVersion.add_reference_sync(
      NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{mVersionedId}, /*isForward=*/false);
    // Written after the link: the HasProperty is a Reference added to the Node, which advances the
    // NodeVersion the Node gains with it.
    nodeVersionVariable->write_value_sync(String{"1"});
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
    ASSERT_NE(create_event_monitored_item(*mSession,
                mSubscriptionId,
                NodeId{ObjectId::Server},
                model_change_filter(),
                {.clientHandle = serverHandle, .samplingInterval = 0.0, .queueSize = 20}),
      0u);
  }

  void TearDown() override
  {
    if (mSession)
      delete_subscription(*mSession, mSubscriptionId);
    ComplianceWithNodes::TearDown();
  }

  // A Scalar Int32 Variable under the test folder whose WriteMask allows ValueRank and ArrayDimensions
  // writes.
  void add_shape_writable_variable(const NodeId& nodeId, const char* name)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    node.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    node.set_display_name(LocalizedText{"", name});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{ValueRank::scalar});
    node.set_write_mask(
      AttributeWriteMask{AttributeWriteMask::Bit::ValueRank, AttributeWriteMask::Bit::ArrayDimensions});
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, nodeId);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);
  }

  std::string read_node_version()
  {
    const auto response = mSession->attributes().read_sync(read_value(mNodeVersionId));
    if (response.results().size() != 1)
      return "<no result>";
    const auto* version = response.results()[0].value().try_as<String>();
    return version == nullptr ? std::string{"<not a String>"}
                              : std::string{static_cast<std::string_view>(*version)};
  }

  StatusCode write(const NodeId& nodeId, Variant value, AttributeId attributeId)
  {
    const auto response =
      mSession->attributes().write_sync(WriteRequestBuilder().write(nodeId, std::move(value), attributeId));
    if (response.results().size() != 1)
      return StatusCode{Status::BadUnexpectedError};
    return response.results()[0];
  }

  static Variant one_dimension()
  {
    return Variant{int32_t{1}};
  }

  static Variant dimensions_of_four()
  {
    Array<uint32_t> dimensions;
    dimensions.payload() = {4};
    return Variant{std::move(dimensions)};
  }

  // The Events of the item after a write; when `expected` is zero the window stays open for the whole
  // timeout.
  std::vector<EventFieldList> events_after_a_write(std::size_t expected)
  {
    auto events = collect_events(*mSession,
      mSubscriptionId,
      {.minCount = expected == 0 ? 1u : expected, .timeout = expected == 0 ? 1s : 3s});
    std::vector<EventFieldList> atServer;
    for (auto& event : events)
    {
      if (event.client_handle() == serverHandle)
        atServer.push_back(std::move(event));
    }
    return atServer;
  }

  static void expect_base_model_change(const std::vector<EventFieldList>& events)
  {
    ASSERT_EQ(events.size(), 1u) << "the change raised " << text(events);
    EXPECT_EQ(event_type_of(events.front()), to_string(NodeId{ObjectTypeId::BaseModelChangeEventType}))
      << "the change raised " << text(events);
    const auto* source = events.front().event_fields().size() > sourceNodeField
                           ? events.front().event_fields()[sourceNodeField].try_as<NodeId>()
                           : nullptr;
    ASSERT_NE(source, nullptr);
    EXPECT_EQ(*source, NodeId{ObjectId::Server});
  }

  NodeId mVersionedId;
  NodeId mNodeVersionId;
  NodeId mUnversionedId;
  uint32_t mSubscriptionId{0};
};

}  // namespace

// @relation(AC-SVR-ADDRSP-262-VALUERANK-ARRAYDIMENSIONS-ADVANCE-NODEVERSION, scope=function)
TEST_F(ModelChangeOnAttributes, AValueRankWriteAdvancesNodeVersion)
{
  const auto before = read_node_version();
  ASSERT_EQ(before, "1") << "precondition: the NodeVersion is the String \"1\"";

  ASSERT_TRUE(written(write(mVersionedId, one_dimension(), AttributeId::ValueRank)));
  const auto afterChange = read_node_version();
  EXPECT_NE(afterChange, before) << "the ValueRank change left the NodeVersion unchanged";
  expect_base_model_change(events_after_a_write(1));

  ASSERT_TRUE(written(write(mVersionedId, one_dimension(), AttributeId::ValueRank)));
  EXPECT_EQ(read_node_version(), afterChange) << "the repeated ValueRank write changed the NodeVersion";
  const auto afterRepeat = events_after_a_write(0);
  EXPECT_TRUE(afterRepeat.empty()) << "the repeated ValueRank write raised " << text(afterRepeat);

  ASSERT_TRUE(written(write(mUnversionedId, one_dimension(), AttributeId::ValueRank)));
  const auto afterUnversioned = events_after_a_write(0);
  EXPECT_TRUE(afterUnversioned.empty())
    << "the Variable without NodeVersion raised " << text(afterUnversioned);
}

// @relation(AC-SVR-ADDRSP-262-VALUERANK-ARRAYDIMENSIONS-ADVANCE-NODEVERSION, scope=function)
TEST_F(ModelChangeOnAttributes, AnArrayDimensionsWriteAdvancesNodeVersion)
{
  // ArrayDimensions of {4} belong to a one-dimensional Variable: both Variables are made one-dimensional
  // first, and the Event and NodeVersion of that change are taken before the ArrayDimensions writes.
  ASSERT_TRUE(written(write(mVersionedId, one_dimension(), AttributeId::ValueRank)));
  ASSERT_TRUE(written(write(mUnversionedId, one_dimension(), AttributeId::ValueRank)));
  events_after_a_write(1);
  const auto before = read_node_version();

  ASSERT_TRUE(written(write(mVersionedId, dimensions_of_four(), AttributeId::ArrayDimensions)));
  EXPECT_NE(read_node_version(), before) << "the ArrayDimensions change left the NodeVersion unchanged";
  expect_base_model_change(events_after_a_write(1));

  ASSERT_TRUE(written(write(mUnversionedId, dimensions_of_four(), AttributeId::ArrayDimensions)));
  const auto afterUnversioned = events_after_a_write(0);
  EXPECT_TRUE(afterUnversioned.empty())
    << "the Variable without NodeVersion raised " << text(afterUnversioned);
}
