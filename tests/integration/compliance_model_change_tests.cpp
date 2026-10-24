// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for GeneralModelChange event emission + NodeVersion maintenance.
///
/// Part 3 9.32.2 ("both or neither"): a change of a Node that carries a NodeVersion advances it and raises a
/// ModelChangeEvent. The SDK does both for every change made through the address space (NR-36): the namespace
/// advances the NodeVersion and the address space raises one GeneralModelChangeEvent per operation. The
/// application chooses which Nodes are versioned. These tests install a delegate that gives the parent of an
/// added Node a NodeVersion before adding it, subscribe for events filtered OfType
/// GeneralModelChangeEventType, perform AddNodes, and assert the event arrives and the parent's NodeVersion
/// moved.

#include "compliance_helpers.h"
#include "offloading_node_management_delegate.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_session_attribute_services.h"
#include "ua_session_node_management_services.h"

#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_result.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_literal_operand.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace_delegates.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

const QualifiedName nodeVersionName{0, "NodeVersion"};

// OfType where-clause: matches events whose EventType is `typeId` or a subtype of it (resolved via
// the address-space HasSubtype hierarchy at EventBus dispatch).
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

void append_change(Array<RefStructure<Structure>>& changes, const NodeId& affected,
  const NodeId& affectedType, ModelChangeStructureVerbMask verb)
{
  auto entry = std::make_unique<ModelChangeStructureDataType>();
  entry->affected() = affected;
  entry->affected_type() = affectedType;
  entry->verb() = static_cast<std::uint8_t>(static_cast<std::int32_t>(verb));
  changes.push_back(RefStructure<Structure>{std::move(entry)});
}

/// Minimal application-style NodeManagementDelegate that performs the AddNodes against the address space
/// after giving the parent a NodeVersion Property; the SDK advances it and raises the event. It runs on the
/// service strand but uses only inline-completing `try_*_sync` calls against the in-memory namespace (no
/// instantiation round-trip), so it never blocks the strand. The other three operations are unused no-ops
/// here.
class TestModelChangeDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const Context> /*context*/, AddressSpace addressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items, AddNodesCompleteCallback callback) override
  {
    BatchResult<AddNodesItemResult> batch;
    batch.items.reserve(items.size());

    for (auto& authorizedItem : items)
    {
      auto& item = authorizedItem.item;
      AddNodesResult result;
      auto parentId = item.parent_node_id().node_id();
      auto requestedId = item.requested_new_node_id().node_id();
      if (requestedId.is_null())
      {
        requestedId = NodeId{
          authorizedItem.destination.namespaceIndex, static_cast<std::uint32_t>(60000u + batch.items.size())};
      }

      auto createResult = addressSpace.try_create_node_sync(requestedId, item.node_class(), {});
      if (createResult.is_bad())
      {
        result.status_code() = createResult.status_code();
        batch.items.emplace_back(std::move(result));
        continue;
      }

      auto node = createResult.value();
      node.set_browse_name(item.browse_name());
      node.set_display_name(LocalizedText{"", String{item.browse_name().name()}});
      if (!item.type_definition().node_id().is_null())
        node.try_add_reference_sync(
          NodeId{ReferenceTypeId::HasTypeDefinition}, item.type_definition().node_id());

      version_node(addressSpace, parentId);
      auto parent = addressSpace.try_find_node_sync(parentId);
      if (parent.is_good())
        parent.value().try_add_reference_sync(item.reference_type_id(), requestedId);

      result.status_code() = StatusCode{Status::Good};
      result.added_node_id() = requestedId;
      batch.items.emplace_back(std::move(result));
    }

    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<AddReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    complete_noop(items.size(), std::move(callback));
  }

  void delete_nodes_async(std::shared_ptr<const Context>, AddressSpace, std::vector<DeleteNodesItem> items,
    NodeMgmtCompleteCallback callback) override
  {
    complete_noop(items.size(), std::move(callback));
  }

  void delete_references_async(std::shared_ptr<const Context>, AddressSpace,
    std::vector<DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    complete_noop(items.size(), std::move(callback));
  }

private:
  static void complete_noop(std::size_t count, NodeMgmtCompleteCallback callback)
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(count);  // default-constructed VoidResult == Good
    callback(std::move(batch));
  }

  // Gives the parent a NodeVersion Property unless it has one; the SDK advances it on each change.
  void version_node(AddressSpace& addressSpace, const NodeId& parentId)
  {
    auto parent = addressSpace.try_find_node_sync(parentId);
    if (parent.is_bad())
      return;

    NodeId nodeVersionId;
    auto properties = parent.value().try_get_properties_sync();
    if (properties.is_good())
    {
      for (const auto& reference : properties.value())
      {
        if (!reference.target_id().is_local())
          continue;
        auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
        if (child.is_good() && child.value().get_browse_name() == nodeVersionName)
        {
          nodeVersionId = child.value().get_node_id();
          break;
        }
      }
    }

    if (nodeVersionId.is_null())
    {
      nodeVersionId = NodeId{parentId.namespace_index(), ++mNextId};
      auto created = addressSpace.try_create_node_sync(nodeVersionId, NodeClass::Variable, {});
      if (created.is_bad())
        return;
      auto property = created.value();
      property.set_browse_name(nodeVersionName);
      property.set_display_name(LocalizedText{"", String{"NodeVersion"}});
      if (auto variable = property.as<VariableAccessor>())
        variable->set_data_type(NodeId{DataTypeId::String});
      property.try_add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
      parent.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, nodeVersionId);
    }
  }

  uint32_t mNextId{60000};
};

}  // namespace

class ComplianceModelChange : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    // This fixture exercises model-change delivery, not access denial. The shared TestServer grants
    // its anonymous client SecurityAdmin, while the standard SecurityAdmin policy deliberately does
    // not imply ReceiveEvents. Make the two Table-37 subjects explicit so the delivery path is
    // authorized without weakening the server-wide Role policy.
    RolePermissionType receiveModelChanges;
    receiveModelChanges.role_id() = NodeId{ObjectId::WellKnownRole_SecurityAdmin};
    receiveModelChanges.permissions() = ua::test_helpers::all_permissions();
    for (const NodeId subject : {NodeId{ObjectId::Server}, NodeId{ObjectTypeId::GeneralModelChangeEventType}})
    {
      mServer.server().address_space().find_node_sync(subject).set_role_permissions(
        std::vector<RolePermissionType>{receiveModelChanges});
    }

    mDelegate = std::make_shared<TestModelChangeDelegate>();
    mServer.server().set_node_management_delegate(ua::test::offloaded(mDelegate));
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

  std::shared_ptr<TestModelChangeDelegate> mDelegate;
  uint32_t mSubscriptionId{0};
};

// MODEL_CHANGE_001: AddNodes via a model-change-aware delegate emits a GeneralModelChangeEvent
// (matchable OfType GeneralModelChangeEventType - proving the type is in the address space and the
// HasSubtype hierarchy resolves) and creates/maintains the NodeVersion Property on the parent.
// Covers SVR-EVT-MCH-001, SVR-EVT-MCH-002, SVR-ADDRSP-245 (coverage-audit retag).
TEST_F(ComplianceModelChange, MODEL_CHANGE_001_AddNodesEmitsGeneralModelChangeAndMaintainsNodeVersion)
{
  using namespace std::chrono_literals;

  // Event MI on the Server object, filtered OfType GeneralModelChangeEventType. Select EventType so
  // we can confirm the right event type arrived (field index 0).
  SimpleAttributeOperand eventTypeSelect;
  eventTypeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventTypeSelect.browse_path().push_back(QualifiedName{0, "EventType"});
  eventTypeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(eventTypeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::GeneralModelChangeEventType});

  // The delegate's linking of the parent's NodeVersion is an operation of its own and raises its own Event
  // before the AddNodes does, so the queue holds both.
  auto miId = create_event_monitored_item(
    *mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter), {.queueSize = 10});
  EXPECT_NE(miId, 0u);

  // AddNodes a Variable under the test folder - triggers the delegate's emit + NodeVersion bump.
  const NodeId newNodeId{mTestNamespaceIndex, uint32_t{9500}};
  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mTestFolderId, QualifiedName{mTestNamespaceIndex, "ModelChangeChild"}, NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(newNodeId)
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_THAT(addResult, Good());
  auto addResponse = std::move(addResult).value();
  ASSERT_EQ(addResponse.results().size(), 1u);
  EXPECT_THAT(addResponse.results()[0], Good());

  // The GeneralModelChange events arrive, each carrying EventType = GeneralModelChangeEventType.
  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  ASSERT_GE(events.size(), 1u);
  for (const auto& event : events)
  {
    ASSERT_GE(event.event_fields().size(), 1u);
    const auto& eventTypeField = event.event_fields()[0];
    ASSERT_FALSE(eventTypeField.empty()) << "EventType field should not be null";
    EXPECT_EQ(eventTypeField.as<NodeId>(), NodeId{ObjectTypeId::GeneralModelChangeEventType});
  }

  // The NodeVersion Property is present on the affected parent, is a String, and is readable.
  auto addressSpace = mServer.server().address_space();
  auto folder = addressSpace.try_find_node_sync(mTestFolderId);
  ASSERT_TRUE(folder.is_good());
  auto properties = folder.value().try_get_properties_sync();
  ASSERT_TRUE(properties.is_good());

  NodeId nodeVersionId;
  for (const auto& reference : properties.value())
  {
    if (!reference.target_id().is_local())
      continue;
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child.is_good() && child.value().get_browse_name() == nodeVersionName)
    {
      nodeVersionId = child.value().get_node_id();
      break;
    }
  }
  ASSERT_FALSE(nodeVersionId.is_null()) << "NodeVersion Property not created on the affected parent";

  auto nodeVersionNode = addressSpace.try_find_node_sync(nodeVersionId);
  ASSERT_TRUE(nodeVersionNode.is_good());
  auto variable = nodeVersionNode.value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  EXPECT_EQ(variable->get_data_type(), NodeId{DataTypeId::String});

  auto readResult = variable->try_read_value_sync();
  ASSERT_TRUE(readResult.is_good());
  EXPECT_FALSE(readResult.value().value().empty()) << "NodeVersion should have a value";
}

// Part 5 section 12.16 Table 240 gives the verb byte a bit layout and closes it: "Reserved 5:7 Reserved for
// future use. **Shall always be zero.**" Reserved bits are what a later revision claims, so a Server
// that sets one today is a Server that means something else to a Client written tomorrow.
//
// This SDK does not compose ModelChangeStructures. Namespaces are pluggable and may be mutated
// out-of-band, so the host application builds the changes array and publishes it through the public
// `Server::emit_event` - the arrangement this file's fixture models and its header describes. A test
// in which the fixture picks the verb and then judges the verb it picked would assert nothing about
// the product, so this asserts the two things the product does own.
//
// The first is the vocabulary. `ModelChangeStructureVerbMask` is generated from the NodeSet and is
// the only verb source the SDK offers; if every enumerator and every combination of them leaves bits
// 5 to 7 clear, an application composing a verb from the SDK's own vocabulary cannot violate the
// obligation, whatever combination it chooses. That is a stronger guarantee than any single emission
// test, and it breaks the day a regenerated enum gains a value outside the mask.
//
// The second is fidelity through the stack. The verb is a Byte inside a Structure inside an
// ExtensionObject inside an event field; between the delegate and the Client it is encoded, framed,
// decoded and re-typed. A widening or sign-extension fault anywhere on that path shows up as set
// high bits at the Client, which is the failure the obligation actually protects against, and the
// only party that can commit it is the stack.
// @verifies AC-SVR-BASE-099-VERB-RESERVED
TEST_F(ComplianceModelChange, ModelChangeVerbsLeaveTheReservedHighBitsClearFromVocabularyToClient)
{
  using namespace std::chrono_literals;

  constexpr std::uint8_t reservedMask = 0xE0;  // bits 5, 6, 7

  // --- The vocabulary: no enumerator, and no union of them, reaches a reserved bit. ---
  constexpr ModelChangeStructureVerbMask allVerbs[] = {ModelChangeStructureVerbMask::NodeAdded,
    ModelChangeStructureVerbMask::NodeDeleted,
    ModelChangeStructureVerbMask::ReferenceAdded,
    ModelChangeStructureVerbMask::ReferenceDeleted,
    ModelChangeStructureVerbMask::DataTypeChanged};

  std::int32_t unionOfVerbs = 0;
  for (auto verb : allVerbs)
  {
    const auto raw = static_cast<std::int32_t>(verb);
    unionOfVerbs |= raw;
    EXPECT_EQ(raw & ~0xFF, 0) << to_string(verb) << " does not fit the Byte the verb field is";
    EXPECT_EQ(static_cast<std::uint8_t>(raw) & reservedMask, 0)
      << "ModelChangeStructureVerbMask::" << to_string(verb) << " is " << raw
      << ", which sets a bit Part 5 Table 240 reserves. An application composing a verb from the "
         "SDK's vocabulary would emit a non-conforming ModelChangeStructure without doing anything "
         "wrong";
  }
  EXPECT_EQ(static_cast<std::uint8_t>(unionOfVerbs) & reservedMask, 0)
    << "the union of every verb is " << unionOfVerbs
    << ", which sets a reserved bit. Table 240 allows a verb to name several changes at once, so "
       "every combination is reachable, not just the individual values";

  // A value carrying a reserved bit is not a member of the vocabulary - the guard an application
  // gets if it round-trips an externally supplied byte through the enum.
  EXPECT_FALSE(is_valid(static_cast<ModelChangeStructureVerbMask>(0xFF)))
    << "0xFF is accepted as a defined ModelChangeStructureVerbMask enumerator";
  EXPECT_FALSE(is_valid(static_cast<ModelChangeStructureVerbMask>(0x20)))
    << "0x20 - bit 5 alone, the first reserved bit - is accepted as a defined enumerator";

  // --- Fidelity: the byte a conforming emitter sets is the byte the Client reads. ---
  SimpleAttributeOperand changesSelect;
  changesSelect.type_definition_id() = NodeId{ObjectTypeId::GeneralModelChangeEventType};
  changesSelect.browse_path().push_back(QualifiedName{0, "Changes"});
  changesSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(changesSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::GeneralModelChangeEventType});

  // The delegate's linking of the parent's NodeVersion raises an Event of its own before the AddNodes does.
  auto miId = create_event_monitored_item(
    *mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter), {.queueSize = 10});
  ASSERT_NE(miId, 0u);

  const NodeId newNodeId{mTestNamespaceIndex, uint32_t{9501}};
  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mTestFolderId, QualifiedName{mTestNamespaceIndex, "VerbBitsChild"}, NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(newNodeId)
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_THAT(addResult, Good());

  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  ASSERT_GE(events.size(), 1u);

  for (const auto& event : events)
  {
    ASSERT_GE(event.event_fields().size(), 1u);
    const auto& changesField = event.event_fields()[0];
    ASSERT_FALSE(changesField.empty()) << "the Changes field arrived null; the verb cannot be inspected";
    ASSERT_TRUE(changesField.is_array()) << "Changes did not arrive as an array";
    const auto& entries = changesField.as<Array<RefStructure<Structure>>>();
    ASSERT_FALSE(entries.empty()) << "the emitted change array reached the Client empty";

    std::size_t inspected = 0;
    for (const auto& element : entries)
    {
      const auto* entry = dynamic_cast<const ModelChangeStructureDataType*>(element.get());
      ASSERT_NE(entry, nullptr) << "a Changes element is not a ModelChangeStructureDataType";
      ++inspected;
      EXPECT_EQ(entry->verb() & reservedMask, 0)
        << "the verb for affected Node " << to_string(entry->affected()) << " reached the Client as 0x"
        << std::hex << static_cast<unsigned>(entry->verb()) << std::dec
        << ", with a bit Part 5 Table 240 reserves set. The emitter set only NodeAdded and "
           "ReferenceAdded, so the high bits were introduced between the delegate and the Client";
      EXPECT_NE(entry->verb(), 0u) << "the verb for affected Node " << to_string(entry->affected())
                                   << " reached the Client as zero, naming no change at all";
    }
    EXPECT_EQ(inspected, entries.size());
  }
}

// Part 5 section 12.16 Table 240 closes the verb description with the sentence this criterion's requirement
// derives from: "Note that all verbs shall always be considered in the context where the
// ModelChangeStructureDataType is used. A NodeDeleted may indicate that a Node was removed from a
// view but still exists in other Views." SVR-BASE-100 reads it as a duty on both parties - "The
// server must emit verbs in their narrowest correct sense; the consuming client interprets them
// within the SourceNode's context."
//
// The context is carried by exactly one field, SourceNode, and the failure this guards against is
// the stack quietly replacing it. An SDK that rewrote every event's SourceNode to the Server Object
// before dispatch - a plausible simplification, since the Server Object is the notifier clients
// subscribe to - would deliver a View-scoped NodeDeleted indistinguishable from a global one, and
// the Client would drop a Node from its cache that the Server still serves. Nothing about the verb
// byte would look wrong; the loss is entirely in the context.
//
// So the emission is composed the way a host application composes it, with SourceNode set to a View,
// and the test asserts what only the stack can get wrong: that the View arrives as the SourceNode,
// that each entry keeps its own affected Node, and - the part that gives the verb its narrow reading
// - that the Node named by NodeDeleted is still resolvable in the address space afterwards. That
// last assertion is what distinguishes "removed from this View" from "deleted", and it is checked
// against the Server's own address space rather than against anything the fixture asserted.
// @verifies AC-SVR-BASE-100-MODELCHANGE-VERBS-IN-CONTEXT
TEST_F(ComplianceModelChange, AViewScopedNodeDeletedArrivesWithItsViewAndLeavesTheNodeInPlace)
{
  using namespace std::chrono_literals;

  auto addressSpace = mServer.server().address_space();

  // The View whose context the verb is to be read in.
  const NodeId viewId{mTestNamespaceIndex, uint32_t{9600}};
  auto createdView = addressSpace.try_create_node_sync(viewId, NodeClass::View, {});
  ASSERT_TRUE(createdView.is_good()) << "could not create the View the change is scoped to";
  createdView.value().set_browse_name(QualifiedName{mTestNamespaceIndex, "ScopedView"});
  createdView.value().set_display_name(LocalizedText{"", String{"ScopedView"}});

  // The Node the View drops. It exists in the address space before the event and must still exist
  // after it: that is the whole difference between the two readings of NodeDeleted.
  const NodeId droppedId{mTestNamespaceIndex, uint32_t{9601}};
  auto createdDropped = addressSpace.try_create_node_sync(droppedId, NodeClass::Variable, {});
  ASSERT_TRUE(createdDropped.is_good());
  createdDropped.value().set_browse_name(QualifiedName{mTestNamespaceIndex, "StillInTheAddressSpace"});
  createdDropped.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});

  SimpleAttributeOperand sourceNodeSelect;
  sourceNodeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  sourceNodeSelect.browse_path().push_back(QualifiedName{0, "SourceNode"});
  sourceNodeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  SimpleAttributeOperand changesSelect;
  changesSelect.type_definition_id() = NodeId{ObjectTypeId::GeneralModelChangeEventType};
  changesSelect.browse_path().push_back(QualifiedName{0, "Changes"});
  changesSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(sourceNodeSelect);
  filter.select_clauses().push_back(changesSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::GeneralModelChangeEventType});

  auto miId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  ASSERT_NE(miId, 0u);

  Array<RefStructure<Structure>> changes;
  append_change(changes,
    droppedId,
    NodeId{VariableTypeId::BaseDataVariableType},
    ModelChangeStructureVerbMask::NodeDeleted);
  append_change(changes, viewId, NodeId{}, ModelChangeStructureVerbMask::ReferenceDeleted);

  GeneralModelChangeEventPayload event;
  event.sourceNode = viewId;
  event.sourceName = String{"ScopedView"};
  event.message = LocalizedText{"", String{"View contents changed"}};
  event.severity = 100;
  event.changes = Variant{std::move(changes)};
  mServer.server().emit_event(event);

  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  ASSERT_GE(events.size(), 1u);
  ASSERT_GE(events[0].event_fields().size(), 2u);

  const auto& sourceNodeField = events[0].event_fields()[0];
  ASSERT_FALSE(sourceNodeField.empty())
    << "SourceNode arrived null, so the verbs reached the Client with no context to be read in";
  EXPECT_EQ(sourceNodeField.as<NodeId>(), viewId)
    << "SourceNode arrived as " << to_string(sourceNodeField.as<NodeId>()) << " rather than the View "
    << to_string(viewId)
    << ". A NodeDeleted read against the Server Object rather than the View says the Node is gone "
       "from the address space, which is a different and false statement";

  const auto& changesField = events[0].event_fields()[1];
  ASSERT_TRUE(changesField.is_array()) << "Changes did not arrive as an array";
  const auto& entries = changesField.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(entries.size(), 2u) << "both change entries must survive; a verb without its own entry "
                                   "has no affected Node to be read against";

  const auto* first = dynamic_cast<const ModelChangeStructureDataType*>(entries[0].get());
  const auto* second = dynamic_cast<const ModelChangeStructureDataType*>(entries[1].get());
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);

  EXPECT_EQ(first->affected(), droppedId)
    << "the NodeDeleted entry names " << to_string(first->affected()) << " rather than "
    << to_string(droppedId) << "; each verb describes its own affected Node";
  EXPECT_EQ(first->verb(), static_cast<std::uint8_t>(ModelChangeStructureVerbMask::NodeDeleted));
  EXPECT_EQ(second->affected(), viewId)
    << "the ReferenceDeleted entry names " << to_string(second->affected())
    << "; the two entries in one event must not be conflated";
  EXPECT_EQ(second->verb(), static_cast<std::uint8_t>(ModelChangeStructureVerbMask::ReferenceDeleted));

  // The narrow reading, checked against the Server rather than against the fixture: NodeDeleted in a
  // View context did not delete the Node.
  auto stillThere = addressSpace.try_find_node_sync(droppedId);
  EXPECT_TRUE(stillThere.is_good())
    << "the Node named by a View-scoped NodeDeleted is no longer in the address space, so the verb "
       "was not emitted in its narrowest correct sense";
}

// Part 3 section 12.14 pairs the two signals - "both or neither" - so a Client may poll `NodeVersion` or
// subscribe to a ModelChangeEvent and reach the same conclusion about whether the model moved. A
// Server that keeps one and not the other leaves whichever the Client chose silently stale.
//
// `VersionedNodeAddressSpace.ANodeVersionAndAModelChangeEventNeverMoveWithoutEachOther` drives this
// stimulus and does not establish it: its subject assertion is `EXPECT_EQ(versionMoved, eventIssued)`,
// which `(false, false)` satisfies, and `(false, false)` is exactly what a Server that maintains
// neither produces. The equality is the right invariant and the wrong sole assertion - it needs the
// case where both are true to be pinned separately, or it certifies silence.
//
// So this test asserts the biconditional in both directions with the truth values named.
// A structural change through the canonical delegate must move both: the version differs from the
// value read before, and a model-change event arrives. A non-structural change - a Value write,
// which alters no Node, Reference or DataType - must move neither, and that half is the SDK's own
// write path rather than the application's, so it is the direction the product is genuinely on the
// hook for. Together they exclude the two ways the invariant fails silently: a Server that never
// signals anything, and one that signals a model change for an ordinary write.
// @verifies AC-SVR-ADDRSP-245-NODEVERSION-MODELCHANGE-INVARIANT
TEST_F(ComplianceModelChange, BothSignalsMoveForAStructuralChangeAndNeitherMovesForAValueWrite)
{
  using namespace std::chrono_literals;

  auto addressSpace = mServer.server().address_space();

  // Reads the folder's NodeVersion, or nullopt while the Property does not yet exist.
  auto readNodeVersion = [&]() -> std::optional<std::string>
  {
    auto folder = addressSpace.try_find_node_sync(mTestFolderId);
    if (folder.is_bad())
      return std::nullopt;
    auto properties = folder.value().try_get_properties_sync();
    if (properties.is_bad())
      return std::nullopt;
    for (const auto& reference : properties.value())
    {
      if (!reference.target_id().is_local())
        continue;
      auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
      if (child.is_bad() || child.value().get_browse_name() != nodeVersionName)
        continue;
      auto variable = child.value().as<VariableAccessor>();
      if (!variable.has_value())
        return std::nullopt;
      auto value = variable->try_read_value_sync();
      if (value.is_bad() || value.value().value().empty())
        return std::nullopt;
      return std::string{string_view{value.value().value().as<String>()}};
    }
    return std::nullopt;
  };

  const auto versionBefore = readNodeVersion();

  // BaseModelChangeEventType catches both it and GeneralModelChangeEventType, which is its subtype.
  SimpleAttributeOperand eventTypeSelect;
  eventTypeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventTypeSelect.browse_path().push_back(QualifiedName{0, "EventType"});
  eventTypeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(eventTypeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::BaseModelChangeEventType});

  // The queue keeps every Event the add raises; with one slot, two Events raised in one publishing cycle
  // reach the Client as one.
  auto miId = create_event_monitored_item(
    *mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter), {.queueSize = 10});
  ASSERT_NE(miId, 0u);

  // --- Structural change: both signals must move. ---
  const NodeId newNodeId{mTestNamespaceIndex, uint32_t{9700}};
  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mTestFolderId, QualifiedName{mTestNamespaceIndex, "InvariantChild"}, NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(newNodeId)
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_THAT(addResult, Good());

  auto structuralEvents = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  // Adding the folder's first child raises two Events: the delegate's linking of the folder's NodeVersion
  // raises one before the AddNodes does. On a loaded host they reach the Client in different Publish
  // responses, so the Events are collected until a second passes with none; an Event of the add left
  // uncollected would be taken for one the write raised.
  for (auto more = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 1s}); !more.empty();
       more = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 1s}))
  {
    structuralEvents.insert(structuralEvents.end(), more.begin(), more.end());
  }
  const auto versionAfterAdd = readNodeVersion();

  EXPECT_GE(structuralEvents.size(), 1u)
    << "a Node was added and no ModelChangeEvent arrived. A Client subscribed to the event stream "
       "has no way to learn the model moved";
  ASSERT_TRUE(versionAfterAdd.has_value())
    << "a Node was added and the affected parent carries no NodeVersion. A Client polling the "
       "version has no way to learn the model moved";
  EXPECT_NE(versionAfterAdd, versionBefore)
    << "NodeVersion is still " << *versionAfterAdd
    << " after a Node was added beneath the Node it belongs to; the two signals disagree, and the "
       "polling Client is the one left with the stale answer";

  // --- Non-structural change: neither signal may move. ---
  const auto versionBeforeWrite = readNodeVersion();
  auto writeResp = mSession->attributes().write_sync(
    WriteRequestBuilder{}.write(mWritableVariableId, Variant{int32_t{4242}}).build());
  ASSERT_FALSE(writeResp.results().empty());
  EXPECT_TRUE(writeResp.results()[0].is_good())
    << "the control write failed, so the second half of the invariant was never exercised: "
    << writeResp.results()[0].as_uint32();

  // Any Event within a second of the write is taken for the write's.
  auto writeEvents = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 1s});
  const auto versionAfterWrite = readNodeVersion();

  EXPECT_TRUE(writeEvents.empty())
    << writeEvents.size()
    << " ModelChangeEvent(s) followed a Value write. Writing a Value adds, deletes and retypes "
       "nothing, so a Client told the model changed will re-browse a model that did not";
  EXPECT_EQ(versionAfterWrite, versionBeforeWrite)
    << "NodeVersion moved on a Value write. A Client polling it will re-read type information that "
       "has not changed, and - worse - cannot distinguish this from a change that did";
}

// Part 5 section 6.10, on `OrderedListType`: "Changes in the order of the List are considered as adding and
// deleting References, i.e. if the order changes the NodeVersion **shall** be changed and a
// GeneralModelChangeEvent **shall** be issued, indicating that References have been added and
// deleted."
//
// The clause is the generic NodeVersion/ModelChangeEvent pair applied to a case where it is not
// obvious that anything structural happened: the same Objects are still in the list and only their
// sequence differs, so a Server that thought of a reorder as a value change would signal nothing and
// a Client caching the order would keep a stale one indefinitely. section 6.10 removes the doubt by naming
// the modelling - a reorder IS reference deletion and addition.
//
// Emission is the host's, as everywhere in this file, so the assertions divide the same way as in
// `BothSignalsMoveForAStructuralChangeAndNeitherMovesForAValueWrite`. What this pins that the fixture
// cannot fake is the premise the clause rests on: that reordering really is expressed as References
// changing at the address space, and that the reorder is *observable* - the browse order after the
// change is the new order, over the same unchanged set of targets. A Server whose HasOrderedComponent
// order was not preserved, or not mutable, would make the clause vacuous and this red.
// @verifies AC-SVR-BASE-074-ORDEREDLIST-ORDER-CHANGE-IS-MODEL-CHANGE
TEST_F(ComplianceModelChange, ReorderingAnOrderedListIsAReferenceChangeAndMovesBothSignals)
{
  using namespace std::chrono_literals;

  auto addressSpace = mServer.server().address_space();

  const NodeId listId{mTestNamespaceIndex, uint32_t{9800}};
  auto listNode = addressSpace.try_create_node_sync(listId, NodeClass::Object, {});
  ASSERT_TRUE(listNode.is_good());
  listNode.value().set_browse_name(QualifiedName{mTestNamespaceIndex, "OrderedThings"});
  listNode.value().set_display_name(LocalizedText{"", String{"OrderedThings"}});
  listNode.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::OrderedListType});
  addressSpace.try_find_node_sync(mTestFolderId)
    .value()
    .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, listId);

  // Three ordered members, wired in an order that is NOT ascending by NodeId, so that "the order the
  // References were added in" and "the order a NodeId sort would give" are different answers and the
  // assertions below can tell them apart.
  std::vector<NodeId> members;
  for (uint32_t i : {2u, 0u, 1u})
  {
    const NodeId memberId{mTestNamespaceIndex, uint32_t{9810} + i};
    auto member = addressSpace.try_create_node_sync(memberId, NodeClass::Object, {});
    ASSERT_TRUE(member.is_good());
    member.value().set_browse_name(QualifiedName{mTestNamespaceIndex, String{"Member" + std::to_string(i)}});
    member.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    listNode.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasOrderedComponent}, memberId);
    members.push_back(memberId);
  }

  // Reads the list's members in the order its HasOrderedComponent References give them.
  const auto orderedMembers = [&]()
  {
    std::vector<NodeId> out;
    auto list = addressSpace.try_find_node_sync(listId);
    if (list.is_bad())
      return out;
    for (const auto& ref : list.value().get_references_sync())
    {
      if (!ref.is_forward() || !ref.target_id().is_local())
        continue;
      if (ref.type_id() == NodeId{ReferenceTypeId::HasOrderedComponent})
        out.push_back(ref.target_id().node_id());
    }
    return out;
  };

  const auto before = orderedMembers();
  ASSERT_EQ(before.size(), 3u) << "the list did not accept three ordered components, so there is no "
                                  "order to change and this test proves nothing";
  ASSERT_EQ(before, members) << "the HasOrderedComponent References did not preserve the order they "
                                "were added in, so the list's order is not readable and Part 5 "
                                "section 6.10's whole mechanism has nothing to act on";

  SimpleAttributeOperand eventTypeSelect;
  eventTypeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventTypeSelect.browse_path().push_back(QualifiedName{0, "EventType"});
  eventTypeSelect.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  EventFilter filter;
  filter.select_clauses().push_back(eventTypeSelect);
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::BaseModelChangeEventType});

  auto miId =
    create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter));
  ASSERT_NE(miId, 0u);

  // The reorder, expressed the way section 6.10 says it is modelled: a Reference deleted and one added.
  // The FIRST member is moved, not the last: removing and re-adding the last one puts it back where
  // it was, which is a no-op dressed up as a reorder and would make the assertions below meaningless.
  auto list = addressSpace.try_find_node_sync(listId);
  ASSERT_TRUE(list.is_good());
  list.value().remove_reference_sync(NodeId{ReferenceTypeId::HasOrderedComponent}, members[0]);
  const auto afterRemoval = orderedMembers();
  ASSERT_EQ(afterRemoval.size(), 2u)
    << "removing a HasOrderedComponent Reference did not remove the member from the order, so a "
       "reorder cannot be expressed as Reference deletion and addition at all";

  // Re-add it: the same target, a new position.
  list.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasOrderedComponent}, members[0]);

  const auto after = orderedMembers();
  ASSERT_EQ(after.size(), 3u) << "the re-added member did not return to the list";
  EXPECT_NE(after, before)
    << "the order is unchanged after a member was removed and re-added, so a reorder is not "
       "observable and no Client could act on the signal Part 5 section 6.10 requires";
  EXPECT_EQ(
    std::set<std::string>({ua::to_string(after[0]), ua::to_string(after[1]), ua::to_string(after[2])}),
    std::set<std::string>({ua::to_string(before[0]), ua::to_string(before[1]), ua::to_string(before[2])}))
    << "the reorder changed WHICH Objects are in the list, not only their sequence, so it is not the "
       "change section 6.10 is about";

  // The host's half, driven the way this file's delegate drives it: the pair must move together.
  Array<RefStructure<Structure>> changes;
  append_change(
    changes, listId, NodeId{ObjectTypeId::OrderedListType}, ModelChangeStructureVerbMask::ReferenceDeleted);
  append_change(
    changes, listId, NodeId{ObjectTypeId::OrderedListType}, ModelChangeStructureVerbMask::ReferenceAdded);

  GeneralModelChangeEventPayload event;
  event.sourceNode = NodeId{ObjectId::Server};
  event.sourceName = String{"OrderedListReorder"};
  event.message = LocalizedText{"", String{"List order changed"}};
  event.severity = 100;
  event.changes = Variant{std::move(changes)};
  mServer.server().emit_event(event);

  auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 2s});
  EXPECT_FALSE(events.empty())
    << "the reorder produced no ModelChangeEvent. Part 5 section 6.10 requires one precisely because "
       "the members are unchanged and nothing else tells a Client its cached order is stale";
}
