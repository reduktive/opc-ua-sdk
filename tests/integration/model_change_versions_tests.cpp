// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The SDK raises one ModelChangeEvent for each operation whose namespaces reported versioned Nodes (NR-36,
// NR-46, NR-55; NR-70 C2). The namespaces here are a real server's, the Writes and the events a Client's over
// the wire.

#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_add_nodes_result.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_datatype_id.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_simple_attribute_operand.h"
#include "ua_default_namespace.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_session_attribute_services.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#if __has_include("node_management_delegate.h")
#include "address_space_seed.h"
#include "node_management_delegate.h"
#include "ua_session_node_management_services.h"
#define UA_TEST_HAS_COMPLIANCE_DELEGATE 1
#endif

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

uint8_t verb(ModelChangeStructureVerbMask mask)
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

// An in-memory namespace that reports, as a namespace that keeps its versions elsewhere would, the source of
// each Reference it adds as a versioned Node; and that can hold its Value writes until the test releases
// them, then report each written Variable as versioned.
class ReportingNamespace final : public default_ns::Namespace
{
public:
  ReportingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    std::vector<NodeId> sources;
    for (const auto& change : changes)
    {
      sources.push_back(change.source);
    }
    default_ns::Namespace::add_references_async(request,
      changes,
      [sources = std::move(sources), complete = std::move(complete)](
        BatchResult<VoidResult> added, std::vector<VersionedNode>) mutable
      {
        std::vector<VersionedNode> versioned;
        for (std::size_t i = 0; i < added.items.size() && i < sources.size(); ++i)
        {
          if (added.items[i].is_good())
          {
            versioned.push_back(VersionedNode{sources[i], NodeId{ObjectTypeId::BaseObjectType}});
          }
        }
        complete(std::move(added), std::move(versioned));
      });
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    {
      const std::lock_guard lock{mMutexHeld};
      if (mHoldWrites)
      {
        std::vector<NodeId> written;
        for (const auto& item : items)
        {
          written.push_back(item.value.node_id());
        }
        mHeld.push_back(Held{std::move(written), std::move(complete)});
        mHeldChanged.notify_all();
        return;
      }
    }
    default_ns::Namespace::write_async(request, caller, items, std::move(complete));
  }

  void hold_writes()
  {
    const std::lock_guard lock{mMutexHeld};
    mHoldWrites = true;
  }

  // Waits until a held write has arrived.
  bool wait_for_held_write(std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutexHeld};
    return mHeldChanged.wait_for(lock, timeout, [this] { return !mHeld.empty(); });
  }

  // Answers the held writes Good, each written Variable reported as versioned.
  void release_writes()
  {
    std::vector<Held> held;
    {
      const std::lock_guard lock{mMutexHeld};
      held.swap(mHeld);
      mHoldWrites = false;
    }
    for (auto& write : held)
    {
      BatchResult<VoidResult> answers;
      answers.items.resize(write.nodes.size());
      std::vector<VersionedNode> versioned;
      for (const auto& node : write.nodes)
      {
        versioned.push_back(VersionedNode{node, NodeId{VariableTypeId::BaseDataVariableType}});
      }
      write.complete(std::move(answers), std::move(versioned));
    }
  }

private:
  struct Held
  {
    std::vector<NodeId> nodes;
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete;
  };

  std::mutex mMutexHeld;
  std::condition_variable mHeldChanged;
  bool mHoldWrites{false};
  std::vector<Held> mHeld;
};

class ModelChangeVersions : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    // The anonymous client of the TestServer holds SecurityAdmin, whose standard policy does not imply
    // ReceiveEvents: the event subjects (Table 37) grant it here.
    RolePermissionType receiveModelChanges;
    receiveModelChanges.role_id() = NodeId{ObjectId::WellKnownRole_SecurityAdmin};
    receiveModelChanges.permissions() = all_permissions();
    for (const NodeId subject : {NodeId{ObjectId::Server},
           NodeId{ObjectTypeId::GeneralModelChangeEventType},
           NodeId{ObjectTypeId::BaseModelChangeEventType}})
    {
      addressSpace.find_node_sync(subject).set_role_permissions(
        std::vector<RolePermissionType>{receiveModelChanges});
    }

    mReporting = std::make_shared<ReportingNamespace>(
      "urn:test:model-change-versions", mServer.thread_pool().executor());
    const uint16_t index = addressSpace.add_namespace_sync(mReporting);
    mReporting->set_namespace_defaults(test_namespace_role_permissions(), std::nullopt);
    mSource = NodeId{index, "Source"};
    mTarget = NodeId{index, "Target"};
    for (const auto& [id, name] : {std::pair{mSource, "Source"}, std::pair{mTarget, "Target"}})
    {
      auto object = addressSpace.create_node_sync(id, NodeClass::Object);
      object.set_browse_name(QualifiedName{index, name});
      object.set_display_name(LocalizedText{"", name});
      object.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    }
    mHeldVariable = NodeId{index, "HeldVariable"};
    auto held = addressSpace.create_node_sync(mHeldVariable, NodeClass::Variable);
    held.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = held.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{index, "HeldVariable"});
    variable->set_display_name(LocalizedText{"", "HeldVariable"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    // A versioned Object of the compliance namespace, whose NodeVersion a Client may write.
    mVersioned = NodeId{mTestNamespaceIndex, "Versioned"};
    mNodeVersion = NodeId{mTestNamespaceIndex, "Versioned.NodeVersion"};
    auto versioned = addressSpace.create_node_sync(mVersioned, NodeClass::Object);
    versioned.set_browse_name(QualifiedName{mTestNamespaceIndex, "Versioned"});
    versioned.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto property = addressSpace.create_node_sync(mNodeVersion, NodeClass::Variable);
    property.set_browse_name(QualifiedName{0, "NodeVersion"});
    property.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    auto version = property.as<VariableAccessor>();
    ASSERT_TRUE(version.has_value());
    version->set_data_type(NodeId{DataTypeId::String});
    version->write_value_sync(String{"1"});
    version->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    versioned.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, mNodeVersion);
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
    // Every ModelChangeEvent: field 0 its EventType, field 1 the Changes of a GeneralModelChangeEvent.
    SimpleAttributeOperand eventType;
    eventType.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    eventType.browse_path().push_back(QualifiedName{0, "EventType"});
    eventType.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    SimpleAttributeOperand changes;
    changes.type_definition_id() = NodeId{ObjectTypeId::GeneralModelChangeEventType};
    changes.browse_path().push_back(QualifiedName{0, "Changes"});
    changes.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    LiteralOperand ofType;
    ofType.value() = Variant{NodeId{ObjectTypeId::BaseModelChangeEventType}};
    ContentFilterElement element;
    element.filter_operator() = FilterOperator::OfType;
    element.filter_operands().push_back(
      RefStructure<Structure>{std::make_unique<LiteralOperand>(std::move(ofType))});
    EventFilter filter;
    filter.select_clauses().push_back(eventType);
    filter.select_clauses().push_back(changes);
    filter.where_clause().elements().push_back(std::move(element));
    ASSERT_NE(
      create_event_monitored_item(*mSession, mSubscriptionId, NodeId{ObjectId::Server}, std::move(filter)),
      0u);
  }

  void TearDown() override
  {
    if (mSession)
      delete_subscription(*mSession, mSubscriptionId);
    ComplianceWithNodes::TearDown();
  }

  // The entries of a GeneralModelChangeEvent's Changes field; empty for a BaseModelChangeEvent.
  static std::vector<const ModelChangeStructureDataType*> entries_of(const EventFieldList& event)
  {
    std::vector<const ModelChangeStructureDataType*> entries;
    if (event.event_fields().size() < 2 || !event.event_fields()[1].is_array())
      return entries;
    for (const auto& entry : event.event_fields()[1].as<Array<RefStructure<Structure>>>())
    {
      if (const auto* change = dynamic_cast<const ModelChangeStructureDataType*>(entry.get()))
        entries.push_back(change);
    }
    return entries;
  }

  static NodeId event_type_of(const EventFieldList& event)
  {
    return event.event_fields().empty() || event.event_fields()[0].empty()
             ? NodeId{}
             : event.event_fields()[0].as<NodeId>();
  }

  std::shared_ptr<ReportingNamespace> mReporting;
  NodeId mSource;
  NodeId mTarget;
  NodeId mHeldVariable;
  NodeId mVersioned;
  NodeId mNodeVersion;
  uint32_t mSubscriptionId{0};
};

// NR-36 rule 2: a namespace that reports a versioned Node through a member's output has the event raised for
// it, whatever namespace it is. The namespace here is not the one whose own versioning the SDK ships.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-REPORTED-NODE-IS-RAISED, scope=function)
TEST_F(ModelChangeVersions, AVersionedNodeInAnotherNamespaceRaisesTheEvent)
{
  auto source = mServer.server().address_space().find_node_sync(mSource);
  ASSERT_TRUE(
    source.try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mTarget}).is_good());

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_EQ(events.size(), 1u) << "the reported Node raised " << events.size() << " ModelChangeEvents";
  EXPECT_EQ(event_type_of(events[0]), NodeId{ObjectTypeId::GeneralModelChangeEventType});
  // The address space adds the Organizes' inverse half on the target too (NR-30 rule 2), which the namespace
  // reports as well.
  const auto entries = entries_of(events[0]);
  ASSERT_EQ(entries.size(), 2u);
  std::vector<NodeId> affected;
  for (const auto& entry : entries)
  {
    affected.push_back(entry->affected());
    EXPECT_EQ(entry->affected_type(), NodeId{ObjectTypeId::BaseObjectType});
    EXPECT_EQ(entry->verb(), verb(ModelChangeStructureVerbMask::ReferenceAdded));
  }
  std::sort(affected.begin(), affected.end());
  std::vector<NodeId> expected{mSource, mTarget};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(affected, expected);
}

// NR-46: a namespace that answers after the Client's request has timed out still has its versioned Nodes
// raised; the event does not depend on when the Client gave up.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-LATE-ANSWER-IS-RAISED, scope=function)
TEST_F(ModelChangeVersions, ACompletionAfterTheClientTimedOutStillRaisesTheEvent)
{
  mReporting->hold_writes();
  WriteRequest request = WriteRequestBuilder{}.write(mHeldVariable, Variant{int32_t{5}}).build();
  request.request_header().timeout_hint() = 500;
  const auto response = mSession->attributes().try_write_sync(std::move(request));
  ASSERT_TRUE(mReporting->wait_for_held_write(2s)) << "the write never reached the namespace";
  const bool answeredGood =
    response.is_good() && !response.value().results().empty() && response.value().results()[0].is_good();
  ASSERT_FALSE(answeredGood)
    << "the Write was answered Good before its namespace answered; the test has no subject";

  EXPECT_TRUE(collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 500ms}).empty())
    << "a ModelChangeEvent was raised while the namespace still held its write answer";
  mReporting->release_writes();

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_EQ(events.size(), 1u) << "the late answer raised " << events.size() << " ModelChangeEvents";
  // A Value write's versioned Node has no verb: the event is a BaseModelChangeEvent.
  EXPECT_EQ(event_type_of(events[0]), NodeId{ObjectTypeId::BaseModelChangeEventType});
}

// NR-36 rule 6 and Part 3 9.32.2: a NodeVersion a Client writes through the Write service is a NodeVersion
// change, which raises a ModelChangeEvent; no verb names it, so it is a BaseModelChangeEvent.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-A-WRITTEN-NODEVERSION-IS-RAISED, scope=function)
TEST_F(ModelChangeVersions, ANodeVersionWriteThroughTheWriteServiceRaisesABaseModelChangeEvent)
{
  const auto written =
    mSession->attributes().write_sync(WriteRequestBuilder{}.write(mNodeVersion, Variant{String{"7"}}));
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_TRUE(written.results()[0].is_good()) << to_string(written.results()[0]);

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_EQ(events.size(), 1u) << "the NodeVersion write raised " << events.size() << " ModelChangeEvents";
  EXPECT_EQ(event_type_of(events[0]), NodeId{ObjectTypeId::BaseModelChangeEventType});

  // The control: a Value write to a Variable that is not a NodeVersion raises nothing.
  const auto control =
    mSession->attributes().write_sync(WriteRequestBuilder{}.write(mWritableVariableId, Variant{int32_t{9}}));
  ASSERT_EQ(control.results().size(), 1u);
  ASSERT_TRUE(control.results()[0].is_good()) << to_string(control.results()[0]);
  EXPECT_TRUE(collect_events(*mSession, mSubscriptionId, {.minCount = 0, .timeout = 500ms}).empty());
}

#ifdef UA_TEST_HAS_COMPLIANCE_DELEGATE

class ComplianceServerModelChangeVersions : public ModelChangeVersions
{
protected:
  void configure_server() override
  {
    ModelChangeVersions::configure_server();
    // The delegate finds the compliance server's namespace by its URI to check a requested NodeId; the Nodes
    // added here are requested in no namespace and go under a Node of the test namespace.
    mServer.server().address_space().add_namespace_sync(default_ns::Namespace::create(
      std::string{ua::compliance_test_server::complianceNamespaceUri}, mServer.thread_pool().executor()));
    mServer.server().set_node_management_delegate(
      std::make_shared<ua::compliance_test_server::ComplianceNodeManagementDelegate>());
  }
};

// NR-36 "What it breaks" and Part 3 9.32.2 ("only those Nodes of the AddressSpace having a NodeVersion shall
// trigger a ModelChangeEvent"): the compliance server versions the parent of an added Node, not the added
// Node, so the event lists the parent's ReferenceAdded and no NodeAdded.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-ONLY-VERSIONED-NODES-ARE-LISTED, scope=function)
TEST_F(ComplianceServerModelChangeVersions, TheComplianceServerListsNodeAddedOnlyForVersionedNodes)
{
  const auto added = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mVersioned, QualifiedName{mTestNamespaceIndex, "Added"}, NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  ASSERT_EQ(added.value().results().size(), 1u);
  ASSERT_TRUE(added.value().results()[0].status_code().is_good())
    << to_string(added.value().results()[0].status_code());
  const NodeId addedId = added.value().results()[0].added_node_id();

  const auto events = collect_events(*mSession, mSubscriptionId, {.minCount = 1, .timeout = 3s});
  ASSERT_FALSE(events.empty()) << "the added Node raised no ModelChangeEvent for its versioned parent";
  bool parentListed = false;
  for (const auto& event : events)
  {
    for (const auto* entry : entries_of(event))
    {
      EXPECT_NE(entry->affected(), addedId)
        << "the unversioned added Node is listed, verb " << int{entry->verb()};
      parentListed =
        parentListed || (entry->affected() == mVersioned &&
                          (entry->verb() & verb(ModelChangeStructureVerbMask::ReferenceAdded)) != 0);
    }
  }
  EXPECT_TRUE(parentListed) << "the versioned parent's ReferenceAdded is not listed";
}

#endif

}  // namespace
