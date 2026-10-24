// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-SEMANTICS-01 item 2 and COMP-ADDRSP-CONFIGURATION-VERSION-01 item 2: a namespace of the
// application, derived from ua::Namespace rather than the in-memory one, that reports its own changes through
// its context gets the SemanticsChanged bit (NamespaceMonitoringSupport::property_value_changed) and its
// ConfigurationVersion advanced (NamespaceContext::constant_values_changed). A Client monitors and writes its
// Nodes over the wire.

#include "compliance_helpers.h"
#include "requests.h"
#include "sanitizer_budget.h"
#include "subscription.h"

#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_described_nodes.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_exceptions.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_namespace.h"
#include "ua_namespace_context.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_role_permission_type.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_session_attribute_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_view_services.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

// The suites SemanticsChanged and ConfigurationVersion also hold tests in
// semantic_change_and_configuration_version_tests.cpp, and gtest requires one fixture class per suite: each
// test registers the namespace it observes in its body.
using SemanticsChanged = ComplianceWithNodes;
using ConfigurationVersion = ComplianceWithNodes;
using SemanticChangeEvents = ComplianceWithNodes;

namespace
{

constexpr string_view helperNamespaceUri{"urn:test:semantics-helper"};
constexpr uint32_t levelIdentifier = 1;
constexpr uint32_t euRangeIdentifier = 2;
constexpr uint32_t setpointIdentifier = 3;
constexpr uint32_t itemHandle = 61;

/// A namespace derived from ua::Namespace, not the in-memory one. It holds its Nodes in its own map: their
/// Attributes in a DescribedNodes store, their Values and References beside them. It answers Browse, Read,
/// Write and monitoring of them itself, and its write path reports what a Write changed through its context:
/// each Value to the monitoring helper, each Value of a Property whose owner it holds through
/// property_value_changed (and semantics_changed when an Event is due), and a changed Constant Value through
/// constant_values_changed, after which it answers the Write.
class HelperNamespace final : public Namespace
{
public:
  explicit HelperNamespace(std::string uri) : mUri(std::move(uri))
  {}

  String uri() const override
  {
    return String{mUri};
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  /// Holds the Node @p description describes, with @p value as its first Value.
  void hold(const NodeDescription& description, std::optional<DataValue> value)
  {
    const std::lock_guard lock{mMutex};
    Entry& entry = mEntries[description.node_id()];
    entry.node = mStore.node_for(description);
    entry.value = std::move(value);
  }

  /// Gives the held Node @p source one half of a Reference.
  void hold_reference(const NodeId& source, ReferenceTypeId type, const NodeId& target, bool isForward)
  {
    const std::lock_guard lock{mMutex};
    mEntries[source].references.emplace_back(NodeId{type}, ExpandedNodeId{target}, isForward);
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchResult<NodeResult> answer;
    for (const auto& nodeId : nodeIds)
    {
      answer.items.push_back(found(nodeId));
    }
    complete(std::move(answer));
  }

  using Namespace::find_node;

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration>) override
  {
    return found(nodeId);
  }

  /// Every Reference the Node holds; a page holds at most `maxReferences`, and the resume token is the index
  /// of the next Reference.
  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    BatchResult<NodeReferencesResult> answer;
    for (const ReferenceQuery& query : queries)
    {
      std::vector<Reference> held;
      {
        const std::lock_guard lock{mMutex};
        const auto entry = mEntries.find(query.nodeId);
        if (entry == mEntries.end() || !entry->second.node)
        {
          answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
          continue;
        }
        held = entry->second.references;
      }
      const std::size_t first =
        std::min<std::size_t>(query.resumeToken.empty() ? 0U : query.resumeToken[0], held.size());
      const std::size_t last = query.maxReferences == 0
                                 ? held.size()
                                 : std::min<std::size_t>(held.size(), first + query.maxReferences);
      NodeReferences page;
      page.references =
        References{std::vector<Reference>(std::next(held.begin(), static_cast<std::ptrdiff_t>(first)),
          std::next(held.begin(), static_cast<std::ptrdiff_t>(last)))};
      if (last < held.size())
      {
        page.resumeToken = ByteString(1, static_cast<uint8_t>(last));
      }
      answer.items.emplace_back(std::move(page));
    }
    complete(std::move(answer));
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool setSourceTimestamp, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    for (const ValueReadItem& item : items)
    {
      std::optional<DataValue> value;
      {
        const std::lock_guard lock{mMutex};
        const auto entry = mEntries.find(item.value.node_id());
        if (entry == mEntries.end() || !entry->second.node)
        {
          answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
          continue;
        }
        value = entry->second.value.value_or(DataValue{});
      }
      if (!setSourceTimestamp)
      {
        value->source_timestamp().reset();
      }
      index_range_utils::apply_to_value(*value, item.value.index_range());
      answer.items.emplace_back(std::move(*value));
    }
    complete(std::move(answer));
  }

  /// Stores each Value written and reports the changes; another Attribute is not writable, nor is a range.
  void write_async(const RequestInfo&, const CallerInfo*, std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    struct Change
    {
      NodeId nodeId;
      DataValue value;
      shared_ptr<Node> node;
      std::optional<SemanticChangeReport> owner;
      bool initial{false};
    };

    BatchResult<VoidResult> answer;
    std::vector<Change> changes;
    std::vector<std::size_t> constantItems;
    {
      const std::lock_guard lock{mMutex};
      for (const ValueWriteItem& item : items)
      {
        const WriteValue& write = item.value;
        const auto entry = mEntries.find(write.node_id());
        if (entry == mEntries.end() || !entry->second.node)
        {
          answer.items.emplace_back(StatusCode{Status::BadNodeIdUnknown});
          continue;
        }
        if (static_cast<AttributeId>(write.attribute_id()) != AttributeId::Value)
        {
          answer.items.emplace_back(StatusCode{Status::BadNotWritable});
          continue;
        }
        if (!write.index_range().empty())
        {
          answer.items.emplace_back(StatusCode{Status::BadWriteNotSupported});
          continue;
        }
        Change change{
          write.node_id(), write.value(), entry->second.node, owner_of(entry->second), !entry->second.value};
        if (!change.value.source_timestamp())
        {
          change.value.source_timestamp() = DateTime::now();
        }
        entry->second.value = change.value;
        // A Constant Variable's first Value is not a change of it.
        if (!change.initial && is_constant(*change.node))
        {
          constantItems.push_back(answer.items.size());
        }
        answer.items.emplace_back();
        changes.push_back(std::move(change));
      }
    }

    std::vector<SemanticChangeReport> reports;
    for (const Change& change : changes)
    {
      context().monitoring().attribute_changed(change.nodeId, AttributeId::Value, change.value);
      if (!change.owner)
      {
        continue;
      }
      try
      {
        if (context().monitoring().property_value_changed(
              change.owner->affected, *change.node, change.initial))
        {
          reports.push_back(*change.owner);
        }
      }
      catch (const UaException&)
      {
        // A Property that can no longer be read changes nothing more.
      }
    }
    if (!reports.empty())
    {
      context().semantics_changed(reports);
    }
    if (constantItems.empty())
    {
      complete(std::move(answer), {});
      return;
    }

    // The Write is answered once ConfigurationVersion is advanced; a failed advance is each Constant item's
    // answer.
    struct Pending
    {
      BatchResult<VoidResult> answer;
      std::vector<std::size_t> constantItems;
      std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete;
    };

    auto pending =
      std::make_shared<Pending>(Pending{std::move(answer), std::move(constantItems), std::move(complete)});
    const VoidResult queued = context().constant_values_changed(
      [pending](VoidResult advanced)
      {
        if (advanced.is_bad())
        {
          for (const std::size_t index : pending->constantItems)
          {
            pending->answer.items[index] = advanced;
          }
        }
        pending->complete(std::move(pending->answer), {});
      });
    // A context that refuses the advance never calls the completion: the Write keeps its answers.
    if (queued.is_bad())
    {
      pending->complete(std::move(pending->answer), {});
    }
  }

  /// A Value item is fed by the write path's reports; an item on another Attribute is read at each tick.
  void create_monitoring_async(const RequestInfo&, const CallerInfo*,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override
  {
    using Helper = default_ns::NamespaceMonitoringSupport;
    std::vector<Helper::ResolvedMonitoringItem> resolved;
    for (const auto& item : items)
    {
      resolved.push_back(Helper::ResolvedMonitoringItem{item,
        item.attributeId == AttributeId::Value ? Helper::Delivery::Reported : Helper::Delivery::Sampled});
    }
    BatchResult<MonitoringCreateItemResult> answer;
    for (auto& created : context().monitoring().create_monitoring(resolved))
    {
      answer.items.push_back(std::move(created.result));
    }
    complete(std::move(answer));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    RolePermissionType anonymous;
    anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymous.permissions() = all_permissions();
    return std::vector<RolePermissionType>{std::move(anonymous)};
  }

private:
  struct Entry
  {
    shared_ptr<Node> node;
    std::optional<DataValue> value;
    std::vector<Reference> references;
  };

  shared_ptr<Node> lookup(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mMutex};
    const auto entry = mEntries.find(nodeId);
    return entry != mEntries.end() ? entry->second.node : nullptr;
  }

  NodeResult found(const NodeId& nodeId) const
  {
    auto node = lookup(nodeId);
    return node ? NodeResult{std::move(node)} : NodeResult{StatusCode{Status::BadNodeIdUnknown}};
  }

  /// The owner @p property names by its inverse HasProperty, with the owner's TypeDefinition, when this
  /// namespace holds the owner. Called with mMutex held.
  std::optional<SemanticChangeReport> owner_of(const Entry& property) const
  {
    for (const Reference& reference : property.references)
    {
      if (reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasProperty} ||
          !reference.target_id().is_local())
      {
        continue;
      }
      const auto owner = mEntries.find(reference.target_id().node_id());
      if (owner == mEntries.end() || !owner->second.node)
      {
        return std::nullopt;
      }
      SemanticChangeReport report{owner->first, NodeId{}};
      for (const Reference& ownerReference : owner->second.references)
      {
        if (ownerReference.is_forward() &&
            ownerReference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition})
        {
          report.affectedType = ownerReference.target_id().node_id();
        }
      }
      return report;
    }
    return std::nullopt;
  }

  static bool is_constant(const Node& node)
  {
    const NodeDescription description = node.attributes();
    const auto accessLevelEx = description.access_level_ex();
    return accessLevelEx && accessLevelEx->test(AccessLevelExType::Bit::Constant);
  }

  const std::string mUri;
  mutable std::mutex mMutex;
  DescribedNodes mStore;
  std::map<NodeId, Entry> mEntries;
};

Range make_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

/// Registers a HelperNamespace with @p addressSpace and gives it its Nodes, each with its first Value: the
/// AnalogItem Level (Double) with its EURange Property, and the Constant Variable Setpoint (Int32), both
/// under ObjectsFolder. Answers the namespace's index.
uint16_t register_helper_namespace(AddressSpace addressSpace)
{
  auto helper = std::make_shared<HelperNamespace>(std::string{helperNamespaceUri});
  const uint16_t index = addressSpace.add_namespace_sync(helper);
  const NodeId levelId{index, levelIdentifier};
  const NodeId euRangeId{index, euRangeIdentifier};
  const NodeId setpointId{index, setpointIdentifier};
  const NodeId objectsFolder{ObjectId::ObjectsFolder};
  const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

  helper->hold(NodeDescription::variable(levelId, QualifiedName{index, "Level"}, NodeId{DataTypeId::Double})
                 .with_access_level(readWrite),
    DataValue{Variant{double{50.0}}});
  helper->hold_reference(
    levelId, ReferenceTypeId::HasTypeDefinition, NodeId{VariableTypeId::AnalogItemType}, true);
  helper->hold_reference(levelId, ReferenceTypeId::HasComponent, objectsFolder, false);
  helper->hold_reference(levelId, ReferenceTypeId::HasProperty, euRangeId, true);

  // The SemanticChange flag makes a later change of the EURange raise a SemanticChangeEvent (OPC
  // 10000-3 5.6.2).
  helper->hold(NodeDescription::variable(euRangeId, QualifiedName{0, "EURange"}, NodeId{DataTypeId::Range})
                 .with_access_level(readWrite)
                 .with_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
                   AccessLevelExType::Bit::CurrentWrite,
                   AccessLevelExType::Bit::SemanticChange}),
    DataValue{Variant{make_range(0.0, 100.0)}});
  helper->hold_reference(
    euRangeId, ReferenceTypeId::HasTypeDefinition, NodeId{VariableTypeId::PropertyType}, true);
  helper->hold_reference(euRangeId, ReferenceTypeId::HasProperty, levelId, false);

  helper->hold(
    NodeDescription::variable(setpointId, QualifiedName{index, "Setpoint"}, NodeId{DataTypeId::Int32})
      .with_access_level(readWrite)
      .with_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
        AccessLevelExType::Bit::CurrentWrite,
        AccessLevelExType::Bit::Constant}),
    DataValue{Variant{int32_t{1}}});
  helper->hold_reference(
    setpointId, ReferenceTypeId::HasTypeDefinition, NodeId{VariableTypeId::BaseDataVariableType}, true);
  helper->hold_reference(setpointId, ReferenceTypeId::HasComponent, objectsFolder, false);

  auto objects = addressSpace.find_node_sync(objectsFolder);
  objects.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, levelId);
  objects.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, setpointId);
  return index;
}

/// The value of the item @p clientHandle in the next DataChange carrying one within @p timeout.
std::optional<DataValue> next_value_of(Session& session, uint32_t subscriptionId, uint32_t clientHandle,
  std::chrono::milliseconds timeout = test_utils::scaled(3s))
{
  const auto notification = wait_for_data_change(
    session,
    subscriptionId,
    [clientHandle](const DataChangeNotification& change)
    {
      return std::any_of(change.monitored_items().begin(),
        change.monitored_items().end(),
        [clientHandle](const auto& item) { return item.client_handle() == clientHandle; });
    },
    timeout);
  if (!notification)
  {
    return std::nullopt;
  }
  for (const auto& item : notification->monitored_items())
  {
    if (item.client_handle() == clientHandle)
    {
      return item.value();
    }
  }
  return std::nullopt;
}

/// The ConfigurationVersion of the NamespaceMetadata Object that Server.Namespaces holds for the namespace of
/// index @p index, whose BrowseName is `<index>:<uri>`; null when there is none.
NodeId configuration_version_of(Session& session, uint16_t index, const String& uri)
{
  auto response =
    session.view().try_translate_browse_paths_sync(TranslateBrowsePathsBuilder()
                                                     .path(NodeId{ObjectId::Server_Namespaces})
                                                     .step(QualifiedName{index, uri})
                                                     .step(QualifiedName{0, "ConfigurationVersion"}));
  if (response.is_bad() || response.value().results().size() != 1U)
  {
    return NodeId{};
  }
  const auto& result = response.value().results()[0];
  if (result.status_code().is_bad() || result.targets().empty())
  {
    return NodeId{};
  }
  return result.targets()[0].target_id().node_id();
}

/// Selects the Value of the field @p field of @p eventType.
SimpleAttributeOperand select_field(const NodeId& eventType, const char* field)
{
  SimpleAttributeOperand select;
  select.type_definition_id() = eventType;
  select.browse_path().push_back(QualifiedName{0, field});
  select.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  return select;
}

/// Monitors the Server Object's SemanticChangeEvents, selecting EventType and Changes.
uint32_t monitor_semantic_change_events(Session& session, uint32_t subscriptionId)
{
  LiteralOperand operand;
  operand.value() = Variant{NodeId{ObjectTypeId::SemanticChangeEventType}};
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  element.filter_operands().push_back(
    RefStructure<Structure>{std::make_unique<LiteralOperand>(std::move(operand))});
  EventFilter filter;
  filter.select_clauses().push_back(select_field(NodeId{ObjectTypeId::BaseEventType}, "EventType"));
  filter.select_clauses().push_back(select_field(NodeId{ObjectTypeId::SemanticChangeEventType}, "Changes"));
  filter.where_clause().elements().push_back(std::move(element));
  return create_event_monitored_item(session,
    subscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    {.samplingInterval = 0.0, .queueSize = 10});
}

/// The VersionTime @p version answers; nullopt when it answers none.
std::optional<uint32_t> read_version(Session& session, const NodeId& version)
{
  auto response = session.attributes().try_read_sync(read_value(version));
  if (response.is_bad() || response.value().results().size() != 1U)
  {
    return std::nullopt;
  }
  const auto* value = response.value().results()[0].value().try_as<uint32_t>();
  return value != nullptr ? std::optional<uint32_t>{*value} : std::nullopt;
}

}  // namespace

// A namespace that is not the in-memory one and calls property_value_changed on its write path gets the bit:
// a Client's write of its Variable's EURange sets SemanticsChanged on the Variable's item's next DataChange.
// @relation(AC-COMP-ADDRSP-SEMANTICS-01-ANOTHER-NAMESPACE-USING-THE-HELPER-SETS-THE-BIT, scope=function)
TEST_F(SemanticsChanged, AnotherNamespaceUsingTheHelperSetsTheBit)
{
  const uint16_t index = register_helper_namespace(mServer.server().address_space());
  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  auto created = mSession->monitored_items().try_create_monitored_items_sync(build_create_mi_request(
    subscriptionId, NodeId{index, levelIdentifier}, {.clientHandle = itemHandle, .samplingInterval = 50.0}));
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_EQ(created.value().results().size(), 1u);
  ASSERT_TRUE(created.value().results()[0].status_code().is_good())
    << to_string(created.value().results()[0].status_code());
  ASSERT_TRUE(next_value_of(*mSession, subscriptionId, itemHandle)) << "the item reported no initial value";

  // The EURange holds its first Value, so this write is a change of it.
  write_value_async(*mSession, NodeId{index, euRangeIdentifier}, Variant{make_range(0.0, 200.0)});

  const auto next = next_value_of(*mSession, subscriptionId, itemHandle);
  ASSERT_TRUE(next) << "no DataChange of the item after its EURange was written";
  EXPECT_TRUE(next->status().has_value() && next->status()->semantics_changed())
    << "the item's next DataChange carries no SemanticsChanged bit";
}

// OPC 10000-3 9.33.1, through a namespace that is not the in-memory one: its write path calls
// semantics_changed when property_value_changed answers that an event is due, and a Client's write of its
// AnalogItem's EURange, which has the SemanticChange flag and holds its first Value, raises one
// SemanticChangeEvent whose Changes name the AnalogItem and its TypeDefinition. Waiting for a second Event as
// long as for the first shows that only one arrives.
// @relation(AC-COMP-ADDRSP-SEMANTICS-02-ANOTHER-NAMESPACES-LATER-WRITE-RAISES-ONE-EVENT, scope=function)
TEST_F(SemanticChangeEvents, AnotherNamespacesLaterWriteRaisesOne)
{
  const uint16_t index = register_helper_namespace(mServer.server().address_space());
  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  ASSERT_NE(monitor_semantic_change_events(*mSession, subscriptionId), 0u);

  const auto written = mSession->attributes().write_sync(
    WriteRequestBuilder().write(NodeId{index, euRangeIdentifier}, Variant{make_range(0.0, 200.0)}));
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_TRUE(written.results()[0].is_good()) << to_string(written.results()[0]);

  const auto events =
    collect_events(*mSession, subscriptionId, {.minCount = 2, .timeout = test_utils::scaled(2s)});
  ASSERT_EQ(events.size(), 1u) << "SemanticChangeEvents for one write of the EURange";
  ASSERT_EQ(events[0].event_fields().size(), 2u);
  const auto* eventType = events[0].event_fields()[0].try_as<NodeId>();
  ASSERT_NE(eventType, nullptr) << "the Event carries no EventType";
  EXPECT_EQ(*eventType, NodeId{ObjectTypeId::SemanticChangeEventType});

  const auto& changesField = events[0].event_fields()[1];
  ASSERT_TRUE(changesField.is_array()) << "Changes did not arrive as an array";
  const auto& changes = changesField.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(changes.size(), 1u);
  const auto* change = dynamic_cast<const SemanticChangeStructureDataType*>(changes[0].get());
  ASSERT_NE(change, nullptr) << "the Changes entry is not a SemanticChangeStructureDataType";
  EXPECT_EQ(change->affected(), (NodeId{index, levelIdentifier}))
    << "Affected is " << to_string(change->affected());
  EXPECT_EQ(change->affected_type(), NodeId{VariableTypeId::AnalogItemType})
    << "AffectedType is " << to_string(change->affected_type());
}

// A namespace that is not the in-memory one and calls constant_values_changed when a Client changes its
// Constant Variable has its ConfigurationVersion advanced by the time the Write is answered.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-01-ANOTHER-NAMESPACES-CONSTANT-CHANGE-ADVANCES-ITS-VERSION, scope=function)
TEST_F(ConfigurationVersion, AnotherNamespacesConstantChangeAdvancesItsVersion)
{
  const uint16_t index = register_helper_namespace(mServer.server().address_space());
  const NodeId versionId = configuration_version_of(*mSession, index, String{helperNamespaceUri});
  ASSERT_FALSE(versionId.is_null())
    << "Server.Namespaces publishes no ConfigurationVersion for the namespace";
  const auto before = read_version(*mSession, versionId);
  ASSERT_TRUE(before.has_value()) << "ConfigurationVersion answers no VersionTime";

  // The Setpoint holds its first Value, so this write changes it.
  const auto written = mSession->attributes().write_sync(
    WriteRequestBuilder().write(NodeId{index, setpointIdentifier}, Variant{int32_t{2}}));
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_TRUE(written.results()[0].is_good()) << to_string(written.results()[0]);

  const auto after = read_version(*mSession, versionId);
  ASSERT_TRUE(after.has_value()) << "ConfigurationVersion answers no VersionTime after the Write";
  EXPECT_GT(*after, *before) << "ConfigurationVersion stayed at " << *before
                             << " when the Write of the Constant Variable was answered";
}
