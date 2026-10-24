// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration test for SemanticChange event emission via a Variable's write handler.
///
/// SemanticChange is an application-level concern (like ModelChange): the SDK ships the
/// SemanticChangeEventType + the `Server::emit_event` primitive, and the application emits a
/// SemanticChangeEvent when a semantically-significant DataItem Property changes (Part 8 section 5.2 -
/// EURange / EngineeringUnits / ...). Here the emission lives in the EURange Property's *write
/// handler*: in this SDK a Variable's value flows through its handlers, so the write handler IS the
/// commit point - the emit is therefore non-optimistic (the value change has happened). The test
/// installs such a node, subscribes OfType SemanticChangeEventType, writes a new EURange, and
/// asserts the event arrives (which also proves SemanticChangeEventType i=2738 is in the address
/// space and the HasSubtype hierarchy resolves).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_base_data_variable.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_instance_utils.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_numeric_range_parser.h"
#include "ua_session_attribute_services.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_semantic_change_event_payload.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_server.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_value_source.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

// OfType where-clause: matches events whose EventType is `typeId` or a subtype, resolved via the
// address-space HasSubtype hierarchy at EventBus dispatch.
ContentFilter make_of_type_where_clause(const NodeId& typeId)
{
  LiteralOperand operand;
  operand.value() = Variant{typeId};

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  element.filter_operands().push_back(
    RefStructure<Structure>{std::make_unique<LiteralOperand>(std::move(operand))});

  ContentFilter filter;
  filter.elements().push_back(std::move(element));
  return filter;
}

// Emit a SemanticChangeEvent naming `affected` (of `affectedType`) as semantically changed.
void emit_semantic_change(server::Server& server, const NodeId& affected, const NodeId& affectedType)
{
  SemanticChangeEventPayload event;
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"ComplianceSemanticChange"};
  event.message = LocalizedText{"", String{"Semantic change: EURange updated"}};
  event.severity = 100;

  Array<RefStructure<Structure>> elements;
  elements.resize(1);
  auto entry = std::make_unique<SemanticChangeStructureDataType>();
  entry->affected() = affected;
  entry->affected_type() = affectedType;
  elements[0] = RefStructure<Structure>{std::move(entry)};
  event.changes = Variant{std::move(elements)};

  server.emit_event(event);
}

}  // namespace

class ComplianceSemanticChange : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    mAnalogItemId = NodeId{mTestNamespaceIndex, uint32_t{9700}};
    mEuRangeId = NodeId{mTestNamespaceIndex, uint32_t{9701}};

    // An AnalogItem Variable (the node whose semantics will change).
    auto analogNode = addressSpace.create_node_sync(mAnalogItemId, NodeClass::Variable);
    analogNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "ProcessValue"});
    analogNode.set_display_name(LocalizedText{"", "ProcessValue"});
    if (auto variable = analogNode.as<VariableAccessor>())
      variable->set_data_type(NodeId{DataTypeId::Double});
    analogNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mAnalogItemId);

    // Its EURange Property (a semantically-significant DataItem Property).
    auto euRangeNode = addressSpace.create_node_sync(mEuRangeId, NodeClass::Variable);
    euRangeNode.set_browse_name(QualifiedName{0, "EURange"});
    euRangeNode.set_display_name(LocalizedText{"", "EURange"});
    if (auto variable = euRangeNode.as<VariableAccessor>())
    {
      variable->set_data_type(NodeId{DataTypeId::Range});
      variable->set_access_level(
        AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    }
    euRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    analogNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, mEuRangeId);

    // In this SDK a Variable's value flows through its handlers (only VariableType nodes store
    // values), so EURange is backed by a handler-owned cell: the read handler serves the current
    // range and the write handler is the commit point. Installing BOTH handlers also pins them -
    // it prevents the lazy default-handler initialiser (triggered by a null read handler) from
    // clobbering our write handler on the first read. Emitting the SemanticChangeEvent from the
    // write handler is therefore non-optimistic (the value change has already happened). The cell
    // is mutex-guarded because the default node invokes the handlers outside its own lock. This
    // mirrors `AddressSpaceSeed::seed_data_access` in the real compliance_test_server binary.
    struct EuRangeCell
    {
      std::mutex mutex;
      DataValue value;
    };

    auto cell = std::make_shared<EuRangeCell>();
    {
      Range initialRange;
      initialRange.low() = 0.0;
      initialRange.high() = 100.0;
      cell->value = DataValue{Variant{initialRange}};
    }

    auto& server = mServer.server();
    const NodeId affected = mAnalogItemId;
    std::promise<VoidResult> installed;
    instance_utils::resolve_and_set_value_source_async(addressSpace,
      mEuRangeId,
      make_value_source(
        [cell](const ValueSource::ReadContext& /*context*/,
          const Node& /*node*/,
          const ReadValueId& read,
          std::function<void(DataValueResult)>
            done)
        {
          DataValue snapshot;
          {
            std::lock_guard<std::mutex> guard{cell->mutex};
            snapshot = cell->value;
          }
          index_range_utils::apply_to_value(snapshot, read.index_range());
          done(DataValueResult{std::move(snapshot)});
        },
        [cell, &server, affected](const ValueSource::WriteContext& /*context*/,
          const Node& /*node*/,
          const WriteValue& write,
          std::function<void(ValueSource::WriteResult)>
            done)
        {
          if (!write.index_range().empty())
          {
            done(ValueSource::WriteResult{StatusCode{Status::BadWriteNotSupported}});
            return;
          }
          {
            std::lock_guard<std::mutex> guard{cell->mutex};
            cell->value = write.value();
          }
          emit_semantic_change(server, affected, NodeId{VariableTypeId::AnalogItemType});
          done(ValueSource::Written{});
        }),
      [&installed](VoidResult result) { installed.set_value(std::move(result)); });
    installed.get_future().get();
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

  NodeId mAnalogItemId;
  NodeId mEuRangeId;
  uint32_t mSubscriptionId{0};
};

// SEMANTIC_CHANGE_001: writing the EURange Property runs its write handler, which emits a
// SemanticChangeEvent (matchable OfType SemanticChangeEventType) naming the affected AnalogItem.
// Covers SVR-BASE-023 (coverage-audit retag).
TEST_F(ComplianceSemanticChange, SEMANTIC_CHANGE_001_EURangeWriteEmitsSemanticChange)
{
  using namespace std::chrono_literals;

  SimpleAttributeOperand eventTypeSelect;
  eventTypeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventTypeSelect.browse_path().push_back(QualifiedName{0, "EventType"});
  eventTypeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(eventTypeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::SemanticChangeEventType});

  auto miId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  EXPECT_NE(miId, 0u);

  // Trigger: a client writes a new EURange - the attribute service invokes the node's write handler,
  // which emits the SemanticChangeEvent at the commit point.
  Range newRange;
  newRange.low() = 0.0;
  newRange.high() = 250.0;
  auto writeResponse =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mEuRangeId, Variant{newRange}));
  ASSERT_EQ(writeResponse.results().size(), 1u);
  EXPECT_TRUE(writeResponse.results()[0].is_good());

  // The SemanticChangeEvent arrives, carrying EventType = SemanticChangeEventType.
  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  ASSERT_GE(events.size(), 1u);
  ASSERT_GE(events[0].event_fields().size(), 1u);
  const auto& eventTypeField = events[0].event_fields()[0];
  EXPECT_FALSE(eventTypeField.empty()) << "EventType field should not be null";
  EXPECT_EQ(eventTypeField.as<NodeId>(), NodeId{ObjectTypeId::SemanticChangeEventType});

  // The handler-backed cell also serves reads: reading EURange back returns the value just written
  // (the read handler is pinned, so the first read did not clobber the write handler).
  auto readBack = mSession->attributes().read_sync(read_value(mEuRangeId));
  ASSERT_EQ(readBack.results().size(), 1u);
  const auto& readStatus = readBack.results()[0].status();
  EXPECT_TRUE(!readStatus.has_value() || readStatus->is_good()) << "EURange read should be Good";
  const auto* roundTripped = readBack.results()[0].value().try_as<Range>();
  ASSERT_NE(roundTripped, nullptr) << "EURange read should decode to a Range";
  EXPECT_DOUBLE_EQ(roundTripped->low(), 0.0);
  EXPECT_DOUBLE_EQ(roundTripped->high(), 250.0);
}
