// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-SEMANTICS and COMP-ADDRSP-CONFIGURATION-VERSION over the in-memory namespace, observed by a
// Client: the SemanticsChanged bit for an imported AnalogItem and for a Property added after the item was
// created, the SemanticChangeEvent of a flagged Property (none for its imported first Value, one for a later
// write), and one ConfigurationVersion advance for a Write of two Constant Variables.

#include "compliance_helpers.h"
#include "requests.h"
#include "sanitizer_budget.h"
#include "subscription.h"

#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_analog_item.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_eu_information.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_instantiation_options.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_memory_stream.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_role_permission_type.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_server.h"
#include "ua_session_attribute_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_view_services.h"
#include "ua_simple_attribute_operand.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_write_response.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

// The suites SemanticsChanged and ConfigurationVersion also hold tests in
// semantics_helper_namespace_tests.cpp, and gtest requires one fixture class per suite: each test sets up
// what it observes in its body.
using SemanticsChanged = ComplianceWithNodes;
using SemanticChangeEvents = ComplianceWithNodes;
using ConfigurationVersion = ComplianceWithNodes;

namespace
{

constexpr uint32_t itemHandle = 51;

constexpr string_view importedAnalogItemUri{"urn:test:semantics:imported-analog-item"};

/// An AnalogItemType Variable (ns=1;i=1) and its EURange Property (ns=1;i=2), which lists the inverse
/// HasProperty Reference to the Variable, as NodeSet files do.
constexpr string_view importedAnalogItemNodeSet = R"xml(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris>
    <Uri>urn:test:semantics:imported-analog-item</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="urn:test:semantics:imported-analog-item" Version="1.0.0" PublicationDate="2026-01-01T00:00:00Z">
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.03" PublicationDate="2023-12-15T00:00:00Z" />
    </Model>
  </Models>
  <UAVariable NodeId="ns=1;i=1" BrowseName="1:ImportedLevel" DataType="i=11">
    <DisplayName>ImportedLevel</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=2368</Reference>
      <Reference ReferenceType="i=47" IsForward="false">i=85</Reference>
      <Reference ReferenceType="i=46">ns=1;i=2</Reference>
    </References>
    <Value><uax:Double>50</uax:Double></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=2" BrowseName="0:EURange" ParentNodeId="ns=1;i=1" DataType="i=884" AccessLevel="3">
    <DisplayName>EURange</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=68</Reference>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=1</Reference>
    </References>
    <Value>
      <uax:ExtensionObject>
        <uax:TypeId><uax:Identifier>i=885</uax:Identifier></uax:TypeId>
        <uax:Body>
          <uax:Range><uax:Low>0</uax:Low><uax:High>100</uax:High></uax:Range>
        </uax:Body>
      </uax:ExtensionObject>
    </Value>
  </UAVariable>
</UANodeSet>)xml";

constexpr string_view flaggedPropertyUri{"urn:test:semantics:flagged-property"};

/// An Object (ns=1;i=1) of BaseObjectType with the Property Calibration (ns=1;i=2), whose AccessLevel 19 is
/// CurrentRead, CurrentWrite and SemanticChange, and which has a Value.
constexpr string_view flaggedPropertyNodeSet = R"xml(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris>
    <Uri>urn:test:semantics:flagged-property</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="urn:test:semantics:flagged-property" Version="1.0.0" PublicationDate="2026-01-01T00:00:00Z">
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.03" PublicationDate="2023-12-15T00:00:00Z" />
    </Model>
  </Models>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:Valve">
    <DisplayName>Valve</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=58</Reference>
      <Reference ReferenceType="i=35" IsForward="false">i=85</Reference>
      <Reference ReferenceType="i=46">ns=1;i=2</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=2" BrowseName="1:Calibration" ParentNodeId="ns=1;i=1" DataType="i=11" AccessLevel="19">
    <DisplayName>Calibration</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=68</Reference>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=1</Reference>
    </References>
    <Value><uax:Double>1.5</uax:Double></Value>
  </UAVariable>
</UANodeSet>)xml";

/// Imports @p xml into the server, each new namespace an in-memory one that grants the anonymous Session
/// every permission.
Result<NodeSetImportSummary> import_nodeset(TestServer& server, string_view xml)
{
  NodeSetImportOptions options;
  options.namespaceFactory = [executor = server.thread_pool().executor()](
                               string_view uri) -> shared_ptr<Namespace>
  {
    auto created = default_ns::Namespace::create(uri, executor);
    RolePermissionType anonymous;
    anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymous.permissions() = all_permissions();
    created->set_namespace_defaults(std::vector<RolePermissionType>{anonymous}, std::nullopt);
    return created;
  };
  const auto* bytes = reinterpret_cast<const std::byte*>(xml.data());
  memory_stream_device::ExternalReadOnly device{std::span<const std::byte>{bytes, xml.size()}};
  MemoryStream stream{device};
  return server.server().try_import_nodeset_sync(stream, std::move(options));
}

Range make_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

/// EngineeringUnits of the UNECE code @p unitId.
EUInformation make_units(int32_t unitId, const char* name)
{
  EUInformation units;
  units.namespace_uri() = String{"http://www.opcfoundation.org/UA/units/un/cefact"};
  units.unit_id() = unitId;
  units.display_name() = LocalizedText{"en", name};
  return units;
}

bool carries_semantics_changed(const DataValue& value)
{
  return value.status().has_value() && value.status()->semantics_changed();
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

/// Monitors @p node's Value as the item @p clientHandle and takes the item's initial value.
::testing::AssertionResult monitor_value(
  Session& session, uint32_t subscriptionId, const NodeId& node, uint32_t clientHandle)
{
  auto response = session.monitored_items().try_create_monitored_items_sync(
    build_create_mi_request(subscriptionId, node, {.clientHandle = clientHandle, .samplingInterval = 50.0}));
  if (response.is_bad() || response.value().results().size() != 1U)
  {
    return ::testing::AssertionFailure()
           << "CreateMonitoredItems failed: " << to_string(response.status_code());
  }
  const auto& created = response.value().results()[0].status_code();
  if (created.is_bad())
  {
    return ::testing::AssertionFailure() << "the item was refused: " << to_string(created);
  }
  if (!next_value_of(session, subscriptionId, clientHandle))
  {
    return ::testing::AssertionFailure() << "the item reported no initial value";
  }
  return ::testing::AssertionSuccess();
}

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
  EventFilter filter;
  filter.select_clauses().push_back(select_field(NodeId{ObjectTypeId::BaseEventType}, "EventType"));
  filter.select_clauses().push_back(select_field(NodeId{ObjectTypeId::SemanticChangeEventType}, "Changes"));
  filter.where_clause() = make_of_type_where_clause(NodeId{ObjectTypeId::SemanticChangeEventType});
  return create_event_monitored_item(session,
    subscriptionId,
    NodeId{ObjectId::Server},
    std::move(filter),
    {.samplingInterval = 0.0, .queueSize = 10});
}

/// The current time as a VersionTime: seconds since 2000-01-01 00:00 UTC (OPC 10000-4 7.44).
uint32_t version_time_now()
{
  constexpr int64_t versionTimeEpochInUnixSeconds = 946684800;
  const auto unixSeconds =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
  return static_cast<uint32_t>(unixSeconds - versionTimeEpochInUnixSeconds);
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

/// An Int32 Variable under ObjectsFolder, readable and writable, whose AccessLevelEx has the Constant bit. It
/// has no Value yet.
std::optional<VariableAccessor> create_constant_variable(
  AddressSpace addressSpace, const NodeId& nodeId, const char* name)
{
  auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  auto variable = node.as<VariableAccessor>();
  if (!variable)
  {
    return std::nullopt;
  }
  variable->set_browse_name(QualifiedName{nodeId.namespace_index(), name});
  variable->set_display_name(LocalizedText{"", name});
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->set_value_rank(ValueRank{ValueRank::scalar});
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  variable->set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
    AccessLevelExType::Bit::CurrentWrite,
    AccessLevelExType::Bit::Constant});
  addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, nodeId);
  node.add_reference_sync(
    NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}}, false);
  return variable;
}

}  // namespace

// OPC 10000-4 7.39.1 (Table 180): a change of an imported AnalogItem's EURange, which names its owner by its
// inverse HasProperty, sets SemanticsChanged on the item's next DataChange.
// @relation(AC-COMP-ADDRSP-SEMANTICS-01-AN-IMPORTED-ANALOG-ITEM-SETS-THE-BIT, scope=function)
TEST_F(SemanticsChanged, AnImportedAnalogItemSetsTheBitWhenItsEuRangeChanges)
{
  const auto imported = import_nodeset(mServer, importedAnalogItemNodeSet);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());
  const uint16_t index =
    mServer.server().address_space().namespace_array().get_namespace_index(importedAnalogItemUri);
  const NodeId analogId{index, uint32_t{1}};
  const NodeId euRangeId{index, uint32_t{2}};

  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  ASSERT_TRUE(monitor_value(*mSession, subscriptionId, analogId, itemHandle));

  write_value_async(*mSession, euRangeId, Variant{make_range(0.0, 200.0)});

  const auto next = next_value_of(*mSession, subscriptionId, itemHandle);
  ASSERT_TRUE(next) << "no DataChange of the item after its EURange was written";
  EXPECT_TRUE(carries_semantics_changed(*next))
    << "the item's next DataChange carries no SemanticsChanged bit";
}

// A semantic Property added to an AnalogItem after its Value was monitored marks the item too: the second
// write of the added EngineeringUnits sets SemanticsChanged on the item's next DataChange.
// @relation(AC-COMP-ADDRSP-SEMANTICS-01-A-PROPERTY-ADDED-LATER-SETS-THE-BIT, scope=function)
TEST_F(SemanticsChanged, APropertyAddedAfterTheItemWasCreatedSetsTheBit)
{
  auto addressSpace = mServer.server().address_space();
  const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;
  VariableInstantiationAttributes attributes{
    .dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar, .accessLevel = readWrite};
  // Only the Mandatory members are instantiated, so the AnalogItem has no EngineeringUnits.
  auto analog = AnalogItem::create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "LaterUnitsItem"},
    options,
    attributes);
  const NodeId analogId = analog.node_id();
  analog.release();
  auto analogVariable = addressSpace.find_node_sync(analogId).as<VariableAccessor>();
  ASSERT_TRUE(analogVariable.has_value());
  analogVariable->write_value_sync(double{50.0});

  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  ASSERT_TRUE(monitor_value(*mSession, subscriptionId, analogId, itemHandle));

  const NodeId unitsId{mTestNamespaceIndex, uint32_t{9810}};
  auto unitsNode = addressSpace.create_node_sync(unitsId, NodeClass::Variable);
  unitsNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
  auto units = unitsNode.as<VariableAccessor>();
  ASSERT_TRUE(units.has_value());
  units->set_browse_name(QualifiedName{0, "EngineeringUnits"});
  units->set_display_name(LocalizedText{"", "EngineeringUnits"});
  units->set_data_type(NodeId{DataTypeId::EUInformation});
  units->set_value_rank(ValueRank{ValueRank::scalar});
  units->set_access_level(readWrite);
  addressSpace.find_node_sync(analogId).add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, unitsId);
  unitsNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{analogId}, false);

  write_value_async(*mSession, unitsId, Variant{make_units(4408652, "degree Celsius")});
  // The first Value marks the item too; that DataChange is taken here.
  (void)next_value_of(*mSession, subscriptionId, itemHandle, test_utils::scaled(1s));
  write_value_async(*mSession, unitsId, Variant{make_units(4604232, "degree Fahrenheit")});

  const auto next = next_value_of(*mSession, subscriptionId, itemHandle);
  ASSERT_TRUE(next) << "no DataChange of the item after the EngineeringUnits added to it changed";
  EXPECT_TRUE(carries_semantics_changed(*next))
    << "the item's next DataChange carries no SemanticsChanged bit";
}

// OPC 10000-3 9.33.1: the Value a NodeSet import gives a Property with the SemanticChange flag is its first,
// not a change of it, so the import raises no SemanticChangeEvent.
// @relation(AC-COMP-ADDRSP-SEMANTICS-02-AN-IMPORTED-FLAGGED-PROPERTY-RAISES-NO-EVENT, scope=function)
TEST_F(SemanticChangeEvents, AnImportOfAFlaggedPropertyRaisesNone)
{
  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  ASSERT_NE(monitor_semantic_change_events(*mSession, subscriptionId), 0u);

  const auto imported = import_nodeset(mServer, flaggedPropertyNodeSet);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  const auto events =
    collect_events(*mSession, subscriptionId, {.minCount = 1, .timeout = test_utils::scaled(1s)});
  EXPECT_TRUE(events.empty()) << events.size() << " SemanticChangeEvent(s) arrived for the import";
}

// OPC 10000-3 9.33.1: a later write of the flagged Property raises one SemanticChangeEvent, whose Changes
// name the Object that owns the Property and the Object's TypeDefinition.
// @relation(AC-COMP-ADDRSP-SEMANTICS-02-A-LATER-WRITE-RAISES-ONE-EVENT, scope=function)
TEST_F(SemanticChangeEvents, ALaterWriteRaisesOne)
{
  const uint32_t subscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  ASSERT_NE(monitor_semantic_change_events(*mSession, subscriptionId), 0u);

  const auto imported = import_nodeset(mServer, flaggedPropertyNodeSet);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());
  const uint16_t index =
    mServer.server().address_space().namespace_array().get_namespace_index(flaggedPropertyUri);
  const NodeId objectId{index, uint32_t{1}};
  const NodeId propertyId{index, uint32_t{2}};

  const auto written =
    mSession->attributes().write_sync(WriteRequestBuilder().write(propertyId, Variant{double{2.5}}));
  ASSERT_EQ(written.results().size(), 1u);
  ASSERT_TRUE(written.results()[0].is_good()) << to_string(written.results()[0]);

  // Waits for a second Event as long as for the first, so that one that follows is seen.
  const auto events =
    collect_events(*mSession, subscriptionId, {.minCount = 2, .timeout = test_utils::scaled(2s)});
  ASSERT_EQ(events.size(), 1u) << "SemanticChangeEvents for one write of the flagged Property";
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
  EXPECT_EQ(change->affected(), objectId) << "Affected is " << to_string(change->affected());
  EXPECT_EQ(change->affected_type(), NodeId{ObjectTypeId::BaseObjectType})
    << "AffectedType is " << to_string(change->affected_type());
}

// OPC 10000-3 8.58: one Write request that changes two Constant Variables advances their namespace's
// ConfigurationVersion once; set ahead of the current VersionTime, it is then its Value plus 1.
// @relation(AC-COMP-ADDRSP-CONFIGURATION-VERSION-01-A-WRITE-OF-TWO-CONSTANT-VARIABLES-ADVANCES-IT-ONCE, scope=function)
TEST_F(ConfigurationVersion, AWriteOfTwoConstantVariablesAdvancesItOnce)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId firstId{mTestNamespaceIndex, uint32_t{7720}};
  const NodeId secondId{mTestNamespaceIndex, uint32_t{7721}};
  auto first = create_constant_variable(addressSpace, firstId, "FirstConstant");
  ASSERT_TRUE(first.has_value());
  auto second = create_constant_variable(addressSpace, secondId, "SecondConstant");
  ASSERT_TRUE(second.has_value());

  const NodeId versionId = configuration_version_of(*mSession, mTestNamespaceIndex, mTestNamespace->uri());
  ASSERT_FALSE(versionId.is_null()) << "the namespace publishes no ConfigurationVersion";
  auto version = addressSpace.find_node_sync(versionId).as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  const uint32_t ahead = version_time_now() + 100000U;
  version->write_value_sync(Variant{ahead});

  first->write_value_sync(int32_t{1});
  second->write_value_sync(int32_t{1});

  const auto written = mSession->attributes().write_sync(
    WriteRequestBuilder().write(firstId, Variant{int32_t{2}}).write(secondId, Variant{int32_t{2}}));
  ASSERT_EQ(written.results().size(), 2u);
  EXPECT_TRUE(written.results()[0].is_good()) << to_string(written.results()[0]);
  EXPECT_TRUE(written.results()[1].is_good()) << to_string(written.results()[1]);

  const auto after = read_version(*mSession, versionId);
  ASSERT_TRUE(after.has_value()) << "ConfigurationVersion answers no VersionTime";
  EXPECT_EQ(*after, ahead + 1U) << "ConfigurationVersion was set to " << ahead << " and is " << *after
                                << " after one Write of two Constant Variables";
}
