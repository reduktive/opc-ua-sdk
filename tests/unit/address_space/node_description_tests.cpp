// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-ADDRSP-NAMESPACE-INTERFACE-01: a NodeDescription is a handle to one immutable body, read from a
// named description only, and built from InitialAttributes by try_from_attributes.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_role_permission_type.h"
#include "ua_status.h"
#include "ua_structure_definition.h"
#include "ua_value_rank.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace ua;

// K13 (NR-21 rule 6): every reader returns a reference into the body and is deleted on an rvalue, so a
// reader cannot be called on a temporary description. Each concept asks whether the reader can be called
// on a description of the value category its argument names; `NodeDescription` is an rvalue and
// `NodeDescription&` a named description. The lvalue assertions are the control that the readers exist.
template<class Description>
concept ReadsNodeId =
  requires(Description&& description) { std::forward<Description>(description).node_id(); };
template<class Description>
concept ReadsBrowseName =
  requires(Description&& description) { std::forward<Description>(description).browse_name(); };
template<class Description>
concept ReadsDisplayName =
  requires(Description&& description) { std::forward<Description>(description).display_name(); };
template<class Description>
concept ReadsDescription =
  requires(Description&& description) { std::forward<Description>(description).description(); };
template<class Description>
concept ReadsDataType =
  requires(Description&& description) { std::forward<Description>(description).data_type(); };

static_assert(!ReadsNodeId<NodeDescription>, "node_id() must be deleted on a temporary description");
static_assert(!ReadsBrowseName<NodeDescription>, "browse_name() must be deleted on a temporary description");
static_assert(
  !ReadsDisplayName<NodeDescription>, "display_name() must be deleted on a temporary description");
static_assert(!ReadsDescription<NodeDescription>, "description() must be deleted on a temporary description");
static_assert(!ReadsDataType<NodeDescription>, "data_type() must be deleted on a temporary description");
static_assert(ReadsNodeId<NodeDescription&>, "node_id() must be callable on a named description");
static_assert(ReadsBrowseName<NodeDescription&>, "browse_name() must be callable on a named description");
static_assert(ReadsDisplayName<NodeDescription&>, "display_name() must be callable on a named description");
static_assert(ReadsDescription<NodeDescription&>, "description() must be callable on a named description");
static_assert(ReadsDataType<NodeDescription&>, "data_type() must be callable on a named description");

// The shape K13 names: a reader called on the prvalue `Node::attributes()` returns.
template<class NodeType>
concept ReadsBrowseNameStraightFromAttributes =
  requires(const NodeType& node) { node.attributes().browse_name(); };
static_assert(!ReadsBrowseNameStraightFromAttributes<Node>,
  "node->attributes().browse_name() must not compile: hold the description in a variable first");

namespace
{

const NodeId levelId{2, uint32_t{1}};

LocalizedText text(const char* locale, const char* value)
{
  return LocalizedText{LocaleId{locale}, String{value}};
}

}  // namespace

// NR-21 rules 1, 2 and 4: each with_ form builds a new body; the original and its copy are unchanged.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-MODIFIED-COPY-LEAVES-ORIGINAL, scope=function)
TEST(NodeDescriptionBody, AModifiedCopyLeavesTheOriginal)
{
  const NodeDescription original =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_display_name(text("en", "Level"));
  const NodeDescription copy = original;
  const NodeDescription renamed = original.with_display_name(text("en", "Tank level"));
  const NodeDescription described = renamed.with_description(text("en", "Metres"));

  for (const NodeDescription* unchanged : {&original, &copy})
  {
    EXPECT_EQ(unchanged->display_name(), text("en", "Level"));
    EXPECT_EQ(unchanged->description(), nullptr);
  }
  EXPECT_EQ(renamed.display_name(), text("en", "Tank level"));
  EXPECT_EQ(renamed.description(), nullptr);
  EXPECT_EQ(described.display_name(), text("en", "Tank level"));
  ASSERT_NE(described.description(), nullptr);
  EXPECT_EQ(*described.description(), text("en", "Metres"));

  for (const NodeDescription* each : {&original, &copy, &renamed, &described})
  {
    EXPECT_EQ(each->node_id(), levelId);
    EXPECT_EQ(each->browse_name(), (QualifiedName{2, "Level"}));
    ASSERT_NE(each->data_type(), nullptr);
    EXPECT_EQ(*each->data_type(), NodeId{DataTypeId::Double});
    ASSERT_TRUE(each->value_rank().has_value());
    EXPECT_EQ(each->value_rank()->as_int32(), ValueRank::scalar);
  }
}

// NR-21 rule 6 (K13): the static_asserts above are the arm; a reader that loses its deleted rvalue
// overload fails the build. The test case reads every attribute of a named description.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-READERS-DELETED-ON-RVALUES, scope=function)
TEST(NodeDescriptionReaders, AreDeletedOnRvalues)
{
  const NodeDescription named =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_display_name(text("en", "Level"))
      .with_description(text("en", "Metres"));

  EXPECT_EQ(named.node_id(), levelId);
  EXPECT_EQ(named.browse_name(), (QualifiedName{2, "Level"}));
  EXPECT_EQ(named.display_name(), text("en", "Level"));
  ASSERT_NE(named.description(), nullptr);
  EXPECT_EQ(*named.description(), text("en", "Metres"));
  ASSERT_NE(named.data_type(), nullptr);
  EXPECT_EQ(*named.data_type(), NodeId{DataTypeId::Double});
}

// NR-17 rule 1 and the 1.0 plan section 5.2.6 factory defaults: DisplayName the BrowseName's text, a Variable's
// AccessLevel CurrentRead and Historizing false, ValueRank Scalar, a Method's Executable true. The
// Method's given DisplayName is the control that a given attribute is kept.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-FROM-ATTRIBUTES-FILLS-DEFAULTS, scope=function)
TEST(NodeDescriptionBody, TryFromAttributesFillsTheFactoryDefaults)
{
  const NodeId pumpId{2, uint32_t{10}};
  const NodeId speedId{2, uint32_t{11}};
  const NodeId startId{2, uint32_t{12}};

  const auto pump = NodeDescription::try_from_attributes(
    pumpId, NodeClass::Object, {{AttributeId::BrowseName, Variant{QualifiedName{2, "Pump"}}}});
  ASSERT_TRUE(pump.is_good()) << to_string(pump.status_code());
  const NodeDescription& object = pump.value();
  EXPECT_EQ(object.node_id(), pumpId);
  EXPECT_EQ(object.node_class(), NodeClass::Object);
  EXPECT_EQ(object.display_name().text(), String{"Pump"});

  const auto speed = NodeDescription::try_from_attributes(speedId,
    NodeClass::Variable,
    {{AttributeId::BrowseName, Variant{QualifiedName{2, "Speed"}}},
      {AttributeId::DataType, Variant{NodeId{DataTypeId::Double}}}});
  ASSERT_TRUE(speed.is_good()) << to_string(speed.status_code());
  const NodeDescription& variable = speed.value();
  EXPECT_EQ(variable.node_id(), speedId);
  EXPECT_EQ(variable.node_class(), NodeClass::Variable);
  EXPECT_EQ(variable.display_name().text(), String{"Speed"});
  ASSERT_TRUE(variable.access_level().has_value());
  EXPECT_EQ(*variable.access_level(), AccessLevelType{AccessLevelType::Bit::CurrentRead});
  EXPECT_EQ(variable.historizing(), std::optional<bool>{false});
  ASSERT_TRUE(variable.value_rank().has_value());
  EXPECT_EQ(variable.value_rank()->as_int32(), ValueRank::scalar);

  const auto start = NodeDescription::try_from_attributes(startId,
    NodeClass::Method,
    {{AttributeId::BrowseName, Variant{QualifiedName{2, "Start"}}},
      {AttributeId::DisplayName, Variant{text("en", "Start the pump")}}});
  ASSERT_TRUE(start.is_good()) << to_string(start.status_code());
  const NodeDescription& method = start.value();
  EXPECT_EQ(method.node_id(), startId);
  EXPECT_EQ(method.node_class(), NodeClass::Method);
  EXPECT_EQ(method.display_name(), text("en", "Start the pump"));
  EXPECT_EQ(method.executable(), std::optional<bool>{true});
}

// The A1 header review's ruling of 2026-10-09 from Part 4 Table 183 and Table 24: an invalid or
// contradicted NodeClass is Bad_NodeClassInvalid, an attribute the NodeClass does not have
// Bad_NodeAttributesInvalid, a value of the wrong type Bad_TypeMismatch; each refusal carries an
// ErrorDetail and nothing throws.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-FROM-ATTRIBUTES-REFUSES-MISMATCH, scope=function)
TEST(NodeDescriptionBody, TryFromAttributesRefusesAMismatchedNodeClass)
{
  const NodeId nodeId{2, uint32_t{20}};
  const InitialAttribute browseName{AttributeId::BrowseName, Variant{QualifiedName{2, "Thing"}}};

  struct Case
  {
    const char* name;
    NodeClass nodeClass;
    InitialAttributes attributes;
    Status expected;
  };

  const Case cases[] = {
    {"(a) Unspecified", NodeClass::Unspecified, {browseName}, Status::BadNodeClassInvalid},
    {"(b) NodeClass Attribute says Variable",
      NodeClass::Object,
      {browseName, {AttributeId::NodeClass, Variant{static_cast<int32_t>(NodeClass::Variable)}}},
      Status::BadNodeClassInvalid},
    {"(c) DataType on an Object",
      NodeClass::Object,
      {browseName, {AttributeId::DataType, Variant{NodeId{DataTypeId::Double}}}},
      Status::BadNodeAttributesInvalid},
    {"(d) BrowseName as an Int32",
      NodeClass::Object,
      {{AttributeId::BrowseName, Variant{int32_t{7}}}},
      Status::BadTypeMismatch},
    {"(e) 3 is not a NodeClass", static_cast<NodeClass>(3), {browseName}, Status::BadNodeClassInvalid},
  };

  for (const auto& each : cases)
  {
    SCOPED_TRACE(each.name);
    std::optional<NodeDescriptionResult> result;
    EXPECT_NO_THROW(
      result.emplace(NodeDescription::try_from_attributes(nodeId, each.nodeClass, each.attributes)));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->is_bad());
    EXPECT_EQ(result->status_code().as_status(), each.expected) << to_string(result->status_code());
    EXPECT_NE(result->shared_detail(), nullptr);
  }
}

// The decided rule that an empty Variant counts as not given: a Value given empty to an Object, which has
// no Value Attribute, is skipped, not refused, and the description is the Object factory's.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-FROM-ATTRIBUTES-FILLS-DEFAULTS, scope=function)
TEST(NodeDescriptionBody, TryFromAttributesSkipsAnEmptyVariantForAnAttributeTheNodeClassLacks)
{
  const NodeId pumpId{2, uint32_t{13}};
  const auto result = NodeDescription::try_from_attributes(pumpId,
    NodeClass::Object,
    {{AttributeId::BrowseName, Variant{QualifiedName{2, "Pump"}}}, {AttributeId::Value, Variant{}}});
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  const NodeDescription& described = result.value();
  const NodeDescription factory = NodeDescription::object(pumpId, QualifiedName{2, "Pump"});

  EXPECT_EQ(described.node_class(), NodeClass::Object);
  EXPECT_EQ(described.value(), nullptr);
  for (auto id = static_cast<uint32_t>(AttributeId::NodeId);
       id <= static_cast<uint32_t>(AttributeId::AccessLevelEx);
       ++id)
  {
    const auto attributeId = static_cast<AttributeId>(id);
    SCOPED_TRACE(to_string(attributeId));
    const DataValueResult given = described.attribute(attributeId);
    const DataValueResult expected = factory.attribute(attributeId);
    EXPECT_EQ(given.status_code().as_status(), expected.status_code().as_status())
      << to_string(given.status_code());
    if (given.is_good() && expected.is_good())
    {
      EXPECT_EQ(given.value().value(), expected.value().value());
    }
  }
}

namespace
{

const NodeId operatorRole{1, uint32_t{9001}};

RolePermissionType grant(std::initializer_list<PermissionType::Bit> bits)
{
  RolePermissionType permission;
  permission.role_id() = operatorRole;
  permission.permissions() = PermissionType{bits};
  return permission;
}

}  // namespace

// Part 3 section 5.2.9 and Part 6 section 5.1.9, as the coordinator ruled on 2026-10-09: a null and an empty
// RolePermissions are the one write that removes the override, so role_permissions() answers null, not an
// empty list that would grant nothing. The one-entry array is the control that the write is applied.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-NULL-OR-EMPTY-ROLEPERMISSIONS-REMOVES-THE-OVERRIDE, scope=function)
TEST(NodeDescriptionBody, ANullOrEmptyRolePermissionsRemovesTheOverride)
{
  const NodeDescription original =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_role_permissions(std::vector<RolePermissionType>{grant({PermissionType::Bit::Browse})});
  const PermissionType browseAndRead{PermissionType::Bit::Browse, PermissionType::Bit::Read};

  const auto nulled = original.try_with_attribute(AttributeId::RolePermissions, Variant{});
  const auto emptied = original.try_with_attribute(
    AttributeId::RolePermissions, attribute_wire::role_permissions(std::vector<RolePermissionType>{}));
  const auto granted = original.try_with_attribute(AttributeId::RolePermissions,
    attribute_wire::role_permissions(
      std::vector<RolePermissionType>{grant({PermissionType::Bit::Browse, PermissionType::Bit::Read})}));

  ASSERT_TRUE(nulled.is_good()) << to_string(nulled.status_code());
  EXPECT_EQ(nulled.value().role_permissions(), nullptr);
  ASSERT_TRUE(emptied.is_good()) << to_string(emptied.status_code());
  EXPECT_EQ(emptied.value().role_permissions(), nullptr);
  ASSERT_TRUE(granted.is_good()) << to_string(granted.status_code());
  const auto* held = granted.value().role_permissions();
  ASSERT_NE(held, nullptr);
  ASSERT_EQ(held->size(), 1u);
  EXPECT_EQ((*held)[0].role_id(), operatorRole);
  EXPECT_EQ((*held)[0].permissions(), browseAndRead);

  const auto* kept = original.role_permissions();
  ASSERT_NE(kept, nullptr);
  ASSERT_EQ(kept->size(), 1u);
  EXPECT_EQ((*kept)[0].role_id(), operatorRole);
  EXPECT_EQ((*kept)[0].permissions(), PermissionType{PermissionType::Bit::Browse});

  // The same input means the same thing through every member: with_role_permissions given an empty list
  // removes the override too.
  const NodeDescription cleared = original.with_role_permissions(std::vector<RolePermissionType>{});
  EXPECT_EQ(cleared.role_permissions(), nullptr) << "with_role_permissions held an empty list";
}

// Part 6 section 5.1.9 and Part 3 section 5.6.2, as the coordinator ruled on 2026-10-09: a null and an empty
// ArrayDimensions both leave the description with no ArrayDimensions. {8} is the control that the write
// is applied.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-NULL-ARRAYDIMENSIONS-MEANS-NONE, scope=function)
TEST(NodeDescriptionBody, ANullArrayDimensionsMeansNone)
{
  const NodeDescription original =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_value_rank(ValueRank{1})
      .with_array_dimensions(std::vector<uint32_t>{4});

  const auto nulled = original.try_with_attribute(AttributeId::ArrayDimensions, Variant{});
  const auto emptied = original.try_with_attribute(
    AttributeId::ArrayDimensions, attribute_wire::array_dimensions(std::vector<uint32_t>{}));
  const auto resized = original.try_with_attribute(
    AttributeId::ArrayDimensions, attribute_wire::array_dimensions(std::vector<uint32_t>{8}));

  ASSERT_TRUE(nulled.is_good()) << to_string(nulled.status_code());
  EXPECT_EQ(nulled.value().array_dimensions(), nullptr);
  ASSERT_TRUE(emptied.is_good()) << to_string(emptied.status_code());
  EXPECT_EQ(emptied.value().array_dimensions(), nullptr);
  ASSERT_TRUE(resized.is_good()) << to_string(resized.status_code());
  ASSERT_NE(resized.value().array_dimensions(), nullptr);
  EXPECT_EQ(*resized.value().array_dimensions(), (std::vector<uint32_t>{8}));

  ASSERT_NE(original.array_dimensions(), nullptr);
  EXPECT_EQ(*original.array_dimensions(), (std::vector<uint32_t>{4}));

  // The same input means the same thing through every member: try_with_array_dimensions given an empty
  // list leaves no ArrayDimensions too.
  const NodeDescription three =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_value_rank(ValueRank{1})
      .with_array_dimensions(std::vector<uint32_t>{3});
  const auto none = three.try_with_array_dimensions(std::vector<uint32_t>{});
  ASSERT_TRUE(none.is_good()) << to_string(none.status_code());
  EXPECT_EQ(none.value().array_dimensions(), nullptr) << "try_with_array_dimensions held an empty list";
}

// Part 3 section 5.3.2: "If a ReferenceType is symmetric, the InverseName Attribute shall be omitted."
// try_with_attribute refuses an InverseName on a symmetric ReferenceType with the status try_reference_type
// answers for the same conflict; an empty Variant is not given and changes nothing.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-REFERENCE-TYPE-REFUSES-INVERSENAME-CONFLICT, scope=function)
TEST(NodeDescriptionBody, TryWithAttributeRefusesAnInverseNameOnASymmetricType)
{
  const auto made = NodeDescription::try_reference_type(
    NodeId{2, uint32_t{30}}, QualifiedName{2, "ConnectedTo"}, false, true, std::nullopt);
  ASSERT_TRUE(made.is_good()) << to_string(made.status_code());
  const NodeDescription& symmetric = made.value();

  std::optional<NodeDescriptionResult> named;
  std::optional<NodeDescriptionResult> emptied;
  EXPECT_NO_THROW(
    named.emplace(symmetric.try_with_attribute(AttributeId::InverseName, Variant{text("en", "Back")})));
  EXPECT_NO_THROW(emptied.emplace(symmetric.try_with_attribute(AttributeId::InverseName, Variant{})));
  ASSERT_TRUE(named.has_value());
  ASSERT_TRUE(emptied.has_value());

  EXPECT_EQ(named->status_code().as_status(), Status::BadInvalidArgument)
    << "a LocalizedText InverseName on a symmetric type: " << to_string(named->status_code());
  ASSERT_TRUE(emptied->is_good()) << "an empty Variant: " << to_string(emptied->status_code());
  const NodeDescription& unchanged = emptied->value();
  for (const NodeDescription* each : {&symmetric, &unchanged})
  {
    EXPECT_EQ(each->inverse_name(), nullptr);
    EXPECT_EQ(
      each->attribute(AttributeId::InverseName).status_code().as_status(), Status::BadAttributeIdInvalid)
      << to_string(each->attribute(AttributeId::InverseName).status_code());
  }
}

namespace
{

// The Attribute a refusal's ErrorDetail names, or "" when it carries none.
std::string named_attribute(const shared_ptr<const ErrorDetail>& detail)
{
  return detail ? test_utils::error_context(detail.get(), ContextKeys::nodeAttribute.value()) : std::string{};
}

}  // namespace

// NR-21 rule 3: attribute() reads the wire form the Read service returns, and refuses a Variable's Value,
// which is read through read_values_async, and an Attribute the description does not carry.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-ATTRIBUTE-READS-WIRE-FORM-OR-REFUSES, scope=function)
TEST(NodeDescriptionReaders, AttributeAnswersTheWireFormOrBadAttributeIdInvalid)
{
  const NodeDescription variable =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_display_name(text("en", "Level"))
      .with_access_level(
        AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
  const NodeDescription type = NodeDescription::variable_type(NodeId{2, uint32_t{40}},
    QualifiedName{2, "LevelType"},
    NodeId{DataTypeId::Int32},
    ValueRank{ValueRank::scalar})
                                 .with_value(DataValue{Variant{int32_t{5}}});

  const DataValueResult displayName = variable.attribute(AttributeId::DisplayName);
  ASSERT_TRUE(displayName.is_good()) << to_string(displayName.status_code());
  EXPECT_EQ(displayName.value().value(), Variant{text("en", "Level")});
  const DataValueResult accessLevel = variable.attribute(AttributeId::AccessLevel);
  ASSERT_TRUE(accessLevel.is_good()) << to_string(accessLevel.status_code());
  EXPECT_EQ(accessLevel.value().value(), Variant{uint8_t{3}});
  const DataValueResult typeValue = type.attribute(AttributeId::Value);
  ASSERT_TRUE(typeValue.is_good()) << to_string(typeValue.status_code());
  EXPECT_EQ(typeValue.value().value(), Variant{int32_t{5}});

  for (const AttributeId refused : {AttributeId::Value, AttributeId::Description, AttributeId::Executable})
  {
    SCOPED_TRACE(to_string(refused));
    const DataValueResult answer = variable.attribute(refused);
    ASSERT_TRUE(answer.is_bad());
    EXPECT_EQ(answer.status_code().as_status(), Status::BadAttributeIdInvalid)
      << to_string(answer.status_code());
    EXPECT_NE(answer.shared_detail(), nullptr);
  }
  EXPECT_EQ(
    named_attribute(variable.attribute(AttributeId::Value).shared_detail()), to_string(AttributeId::Value));
}

// NR-17 rule 1 and the 1.0 plan section 5.2.6: each factory gives its NodeClass's defaults and no optional
// Attribute, and an Attribute its NodeClass does not define (OPC 10000-3 5.3 to 5.8) reads absent.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-FACTORIES-BUILD-THEIR-NODECLASS-WITH-DEFAULTS, scope=function)
TEST(NodeDescriptionBody, EachFactoryBuildsItsNodeClassWithTheFactoryDefaults)
{
  const QualifiedName name{2, "N"};
  const auto reference =
    NodeDescription::try_reference_type(NodeId{2, uint32_t{57}}, name, false, false, text("en", "IsChildOf"));
  ASSERT_TRUE(reference.is_good()) << to_string(reference.status_code());

  struct Case
  {
    NodeDescription description;
    NodeId nodeId;
    NodeClass nodeClass;
    std::vector<AttributeId> defines;
  };

  const std::vector<Case> cases{
    {NodeDescription::object(NodeId{2, uint32_t{50}}, name),
      NodeId{2, uint32_t{50}},
      NodeClass::Object,
      {AttributeId::EventNotifier}},
    {NodeDescription::variable(NodeId{2, uint32_t{51}}, name, NodeId{DataTypeId::Double}),
      NodeId{2, uint32_t{51}},
      NodeClass::Variable,
      {AttributeId::Value,
        AttributeId::DataType,
        AttributeId::ValueRank,
        AttributeId::ArrayDimensions,
        AttributeId::AccessLevel,
        AttributeId::UserAccessLevel,
        AttributeId::MinimumSamplingInterval,
        AttributeId::Historizing,
        AttributeId::AccessLevelEx}},
    {NodeDescription::method(NodeId{2, uint32_t{52}}, name),
      NodeId{2, uint32_t{52}},
      NodeClass::Method,
      {AttributeId::Executable, AttributeId::UserExecutable}},
    {NodeDescription::object_type(NodeId{2, uint32_t{53}}, name),
      NodeId{2, uint32_t{53}},
      NodeClass::ObjectType,
      {AttributeId::IsAbstract}},
    {NodeDescription::variable_type(
       NodeId{2, uint32_t{54}}, name, NodeId{DataTypeId::Int32}, ValueRank{ValueRank::scalar}),
      NodeId{2, uint32_t{54}},
      NodeClass::VariableType,
      {AttributeId::Value,
        AttributeId::DataType,
        AttributeId::ValueRank,
        AttributeId::ArrayDimensions,
        AttributeId::IsAbstract}},
    {NodeDescription::data_type(NodeId{2, uint32_t{55}}, name),
      NodeId{2, uint32_t{55}},
      NodeClass::DataType,
      {AttributeId::IsAbstract, AttributeId::DataTypeDefinition}},
    {reference.value(),
      NodeId{2, uint32_t{57}},
      NodeClass::ReferenceType,
      {AttributeId::IsAbstract, AttributeId::Symmetric, AttributeId::InverseName}},
    {NodeDescription::view(NodeId{2, uint32_t{56}}, name),
      NodeId{2, uint32_t{56}},
      NodeClass::View,
      {AttributeId::ContainsNoLoops, AttributeId::EventNotifier}},
  };
  const AttributeId classAttributes[] = {AttributeId::IsAbstract,
    AttributeId::Symmetric,
    AttributeId::InverseName,
    AttributeId::ContainsNoLoops,
    AttributeId::EventNotifier,
    AttributeId::Value,
    AttributeId::DataType,
    AttributeId::ValueRank,
    AttributeId::ArrayDimensions,
    AttributeId::AccessLevel,
    AttributeId::UserAccessLevel,
    AttributeId::MinimumSamplingInterval,
    AttributeId::Historizing,
    AttributeId::Executable,
    AttributeId::UserExecutable,
    AttributeId::DataTypeDefinition,
    AttributeId::AccessLevelEx};

  for (const Case& each : cases)
  {
    const NodeDescription& described = each.description;
    SCOPED_TRACE(to_string(each.nodeClass));
    EXPECT_EQ(described.node_class(), each.nodeClass);
    EXPECT_EQ(described.node_id(), each.nodeId);
    EXPECT_EQ(described.browse_name(), name);
    EXPECT_EQ(described.display_name(), (LocalizedText{LocaleId{}, String{"N"}}));
    EXPECT_EQ(described.description(), nullptr);
    EXPECT_FALSE(described.write_mask().has_value());
    EXPECT_EQ(described.role_permissions(), nullptr);
    EXPECT_FALSE(described.access_restrictions().has_value());
    for (const AttributeId attributeId : classAttributes)
    {
      if (std::find(each.defines.begin(), each.defines.end(), attributeId) == each.defines.end())
      {
        EXPECT_EQ(described.attribute(attributeId).status_code().as_status(), Status::BadAttributeIdInvalid)
          << to_string(attributeId) << " is not an Attribute of the NodeClass";
      }
    }
  }

  const NodeDescription& object = cases[0].description;
  const NodeDescription& variable = cases[1].description;
  const NodeDescription& method = cases[2].description;
  const NodeDescription& variableType = cases[4].description;
  const NodeDescription& dataType = cases[5].description;
  const NodeDescription& referenceType = cases[6].description;
  const NodeDescription& view = cases[7].description;
  EXPECT_EQ(object.event_notifier(), std::optional<EventNotifierType>{EventNotifierType{uint8_t{0}}});
  EXPECT_EQ(view.event_notifier(), std::optional<EventNotifierType>{EventNotifierType{uint8_t{0}}});
  ASSERT_NE(variable.data_type(), nullptr);
  EXPECT_EQ(*variable.data_type(), NodeId{DataTypeId::Double});
  ASSERT_TRUE(variable.value_rank().has_value());
  EXPECT_EQ(variable.value_rank()->as_int32(), ValueRank::scalar);
  EXPECT_EQ(variable.access_level(),
    std::optional<AccessLevelType>{AccessLevelType{AccessLevelType::Bit::CurrentRead}});
  EXPECT_EQ(variable.historizing(), std::optional<bool>{false});
  EXPECT_EQ(variable.array_dimensions(), nullptr);
  EXPECT_FALSE(variable.minimum_sampling_interval().has_value());
  EXPECT_FALSE(variable.access_level_ex().has_value());
  EXPECT_EQ(method.executable(), std::optional<bool>{true});
  for (const std::size_t typed : {std::size_t{3}, std::size_t{4}, std::size_t{5}, std::size_t{6}})
  {
    EXPECT_EQ(cases[typed].description.is_abstract(), std::optional<bool>{false})
      << to_string(cases[typed].nodeClass);
  }
  ASSERT_NE(variableType.data_type(), nullptr);
  EXPECT_EQ(*variableType.data_type(), NodeId{DataTypeId::Int32});
  ASSERT_TRUE(variableType.value_rank().has_value());
  EXPECT_EQ(variableType.value_rank()->as_int32(), ValueRank::scalar);
  EXPECT_EQ(variableType.value(), nullptr);
  EXPECT_EQ(dataType.data_type_definition(), nullptr);
  EXPECT_EQ(referenceType.symmetric(), std::optional<bool>{false});
  ASSERT_NE(referenceType.inverse_name(), nullptr);
  EXPECT_EQ(*referenceType.inverse_name(), text("en", "IsChildOf"));
  EXPECT_EQ(view.contains_no_loops(), std::optional<bool>{false});
}

// NR-21 rule 6: moving copies the pointer, so a moved-from description still reads the body it was moved
// into, by construction and by assignment. Reading the moved-from description is the subject of the test.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-MOVED-FROM-READS-THE-SAME-BODY, scope=function)
TEST(NodeDescriptionBody, AMovedFromDescriptionReadsTheSameBody)
{
  NodeDescription described =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double});
  NodeDescription copied = described;
  const NodeDescription constructed{std::move(described)};
  NodeDescription assigned = NodeDescription::object(NodeId{2, uint32_t{42}}, QualifiedName{2, "Other"});
  assigned = std::move(copied);

  // NOLINTBEGIN(bugprone-use-after-move) - the moved-from descriptions are what this test reads.
  for (const auto& [from, to] :
    {std::pair<const NodeDescription*, const NodeDescription*>{&described, &constructed},
      std::pair<const NodeDescription*, const NodeDescription*>{&copied, &assigned}})
  {
    EXPECT_EQ(from->browse_name(), (QualifiedName{2, "Level"}));
    EXPECT_EQ(from->node_id(), levelId);
    ASSERT_NE(from->data_type(), nullptr);
    EXPECT_EQ(*from->data_type(), NodeId{DataTypeId::Double});
    EXPECT_EQ(&from->browse_name(), &to->browse_name()) << "the two descriptions read different bodies";
    EXPECT_EQ(from->node_id(), to->node_id());
    EXPECT_EQ(from->data_type(), to->data_type());
  }
  // NOLINTEND(bugprone-use-after-move)
}

// NR-17 rule 1 and Part 4 Table 24: a Session-derived Attribute and a Variable's Value are not part of a
// description; a VariableType's default Value is, given as its Variant or as a DataValue.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-FROM-ATTRIBUTES-REFUSES-SESSION-DERIVED-AND-VARIABLE-VALUE, scope=function)
TEST(NodeDescriptionBody, TryFromAttributesRefusesSessionDerivedAttributesAndAVariablesValue)
{
  const InitialAttribute level{AttributeId::BrowseName, Variant{QualifiedName{2, "Level"}}};
  const InitialAttribute levelType{AttributeId::BrowseName, Variant{QualifiedName{2, "LevelType"}}};

  struct Refused
  {
    const char* name;
    InitialAttribute given;
  };

  const Refused refused[] = {
    {"(a) UserAccessLevel", {AttributeId::UserAccessLevel, Variant{uint8_t{1}}}},
    {"(b) a Variable's Value", {AttributeId::Value, Variant{int32_t{7}}}},
  };
  for (const auto& each : refused)
  {
    SCOPED_TRACE(each.name);
    std::optional<NodeDescriptionResult> result;
    EXPECT_NO_THROW(result.emplace(
      NodeDescription::try_from_attributes(levelId, NodeClass::Variable, {level, each.given})));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->is_bad());
    EXPECT_EQ(result->status_code().as_status(), Status::BadNodeAttributesInvalid)
      << to_string(result->status_code());
    EXPECT_EQ(named_attribute(result->shared_detail()), to_string(each.given.first));
  }

  const NodeId typeId{2, uint32_t{43}};
  const Variant five{int32_t{5}};
  for (const auto& [name, given] : {std::pair<const char*, Variant>{"(c) the value's Variant", five},
         std::pair<const char*, Variant>{"(d) a DataValue", Variant{DataValue{five}}}})
  {
    SCOPED_TRACE(name);
    std::optional<NodeDescriptionResult> result;
    EXPECT_NO_THROW(result.emplace(NodeDescription::try_from_attributes(
      typeId, NodeClass::VariableType, {levelType, {AttributeId::Value, given}})));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->is_good()) << to_string(result->status_code());
    const NodeDescription& type = result->value();
    EXPECT_EQ(type.node_class(), NodeClass::VariableType);
    ASSERT_NE(type.value(), nullptr);
    EXPECT_EQ(type.value()->value(), five);
  }
}

// Part 3 section 5.3.2: a symmetric ReferenceType omits the InverseName and a non-symmetric one has one;
// try_reference_type refuses either contradiction and builds the consistent symmetric form.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-REFERENCE-TYPE-REFUSES-INVERSENAME-CONFLICT, scope=function)
TEST(NodeDescriptionBody, TryReferenceTypeRefusesAnInverseNameThatContradictsSymmetric)
{
  const QualifiedName name{2, "ConnectedTo"};
  std::optional<NodeDescriptionResult> symmetricNamed;
  std::optional<NodeDescriptionResult> asymmetricUnnamed;
  std::optional<NodeDescriptionResult> symmetricUnnamed;
  EXPECT_NO_THROW(symmetricNamed.emplace(NodeDescription::try_reference_type(
    NodeId{2, uint32_t{31}}, name, false, true, text("en", "ConnectedFrom"))));
  EXPECT_NO_THROW(asymmetricUnnamed.emplace(
    NodeDescription::try_reference_type(NodeId{2, uint32_t{32}}, name, false, false, std::nullopt)));
  EXPECT_NO_THROW(symmetricUnnamed.emplace(
    NodeDescription::try_reference_type(NodeId{2, uint32_t{33}}, name, false, true, std::nullopt)));
  ASSERT_TRUE(symmetricNamed.has_value() && asymmetricUnnamed.has_value() && symmetricUnnamed.has_value());

  for (const auto* refused : {&*symmetricNamed, &*asymmetricUnnamed})
  {
    ASSERT_TRUE(refused->is_bad());
    EXPECT_EQ(refused->status_code().as_status(), Status::BadInvalidArgument)
      << to_string(refused->status_code());
    EXPECT_EQ(named_attribute(refused->shared_detail()), to_string(AttributeId::InverseName));
  }
  ASSERT_TRUE(symmetricUnnamed->is_good()) << to_string(symmetricUnnamed->status_code());
  const NodeDescription& symmetric = symmetricUnnamed->value();
  EXPECT_EQ(symmetric.node_class(), NodeClass::ReferenceType);
  EXPECT_EQ(symmetric.symmetric(), std::optional<bool>{true});
  EXPECT_EQ(symmetric.inverse_name(), nullptr);
}

// OPC 10000-4 5.10.4.1: a written LocalizedText replaces the locale it names, an empty text removes its
// locale, and a null value removes every locale; the original description is unchanged.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-WITH-ATTRIBUTE-MERGES-LOCALIZED-TEXT, scope=function)
TEST(NodeDescriptionBody, TryWithAttributeMergesLocalizedTextPerLocale)
{
  const NodeDescription original =
    NodeDescription::object(NodeId{2, uint32_t{44}}, QualifiedName{2, "Pump"})
      .with_display_name(text("en", "Pump").with_translation(LocaleId{"de"}, String{"Pumpe"}));

  const auto renamed =
    original.try_with_attribute(AttributeId::DisplayName, Variant{text("en", "Main pump")});
  ASSERT_TRUE(renamed.is_good()) << to_string(renamed.status_code());
  const auto withoutGerman =
    renamed.value().try_with_attribute(AttributeId::DisplayName, Variant{text("de", "")});
  ASSERT_TRUE(withoutGerman.is_good()) << to_string(withoutGerman.status_code());
  const auto cleared = original.try_with_attribute(AttributeId::DisplayName, Variant{});
  ASSERT_TRUE(cleared.is_good()) << to_string(cleared.status_code());

  const auto locale = [](const NodeDescription& described, const char* id)
  {
    return described.display_name().text_for_locale(id);
  };
  EXPECT_EQ(locale(renamed.value(), "en"), std::optional<String>{String{"Main pump"}});
  EXPECT_EQ(locale(renamed.value(), "de"), std::optional<String>{String{"Pumpe"}});
  EXPECT_EQ(locale(withoutGerman.value(), "en"), std::optional<String>{String{"Main pump"}});
  EXPECT_EQ(locale(withoutGerman.value(), "de"), std::nullopt);
  EXPECT_EQ(withoutGerman.value().display_name().translation_count(), 1u);
  EXPECT_EQ(cleared.value().display_name().translation_count(), 0u);
  EXPECT_EQ(locale(original, "en"), std::optional<String>{String{"Pump"}});
  EXPECT_EQ(locale(original, "de"), std::optional<String>{String{"Pumpe"}});
}

// NR-21: a VariableType's default Value may be written null, which is held as a Value whose value is
// empty; a Variable's Value is not part of its description and is refused.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-WITH-ATTRIBUTE-NULL-VARIABLETYPE-VALUE, scope=function)
TEST(NodeDescriptionBody, TryWithAttributeAcceptsANullVariableTypeValue)
{
  const NodeDescription type = NodeDescription::variable_type(NodeId{2, uint32_t{45}},
    QualifiedName{2, "LevelType"},
    NodeId{DataTypeId::Int32},
    ValueRank{ValueRank::scalar})
                                 .with_value(DataValue{Variant{int32_t{5}}});
  const NodeDescription variable =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Int32});

  const auto nulled = type.try_with_attribute(AttributeId::Value, Variant{});
  ASSERT_TRUE(nulled.is_good()) << to_string(nulled.status_code());
  ASSERT_NE(nulled.value().value(), nullptr) << "a null Value was held as no Value";
  EXPECT_TRUE(nulled.value().value()->value().empty());
  ASSERT_NE(type.value(), nullptr);
  EXPECT_EQ(type.value()->value(), Variant{int32_t{5}});

  const auto refused = variable.try_with_attribute(AttributeId::Value, Variant{int32_t{7}});
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadAttributeIdInvalid)
    << to_string(refused.status_code());
  EXPECT_EQ(named_attribute(refused.shared_detail()), to_string(AttributeId::Value));
}

// NR-21: a value of the wrong type is refused, and so is a null on a mandatory Attribute; nothing changes. A
// null removes AccessRestrictions, AccessLevelEx and DataTypeDefinition, which the accessor's setters clear
// with one.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-WITH-ATTRIBUTE-REFUSES-WRONG-TYPE-AND-NULL, scope=function)
TEST(NodeDescriptionBody, TryWithAttributeRefusesAWrongTypeAndANull)
{
  const AccessRestrictionType signing{AccessRestrictionType::Bit::SigningRequired};
  const AccessLevelExType nonatomic{
    AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::NonatomicRead};
  const NodeDescription variable =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double})
      .with_access_restrictions(signing)
      .with_access_level_ex(nonatomic);
  const NodeDescription dataType =
    NodeDescription::data_type(NodeId{2, uint32_t{46}}, QualifiedName{2, "Reading"})
      .with_data_type_definition(std::make_shared<StructureDefinition>());

  struct Refused
  {
    const char* name;
    const NodeDescription* on;
    AttributeId attributeId;
    Variant given;
  };

  const Refused refused[] = {
    {"(a) Historizing as a String", &variable, AttributeId::Historizing, Variant{String{"yes"}}},
    {"(b) a null BrowseName", &variable, AttributeId::BrowseName, Variant{}},
  };
  for (const auto& each : refused)
  {
    SCOPED_TRACE(each.name);
    std::optional<NodeDescriptionResult> result;
    EXPECT_NO_THROW(result.emplace(each.on->try_with_attribute(each.attributeId, each.given)));
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->is_bad());
    EXPECT_EQ(result->status_code().as_status(), Status::BadTypeMismatch) << to_string(result->status_code());
    EXPECT_EQ(named_attribute(result->shared_detail()), to_string(each.attributeId));
  }

  EXPECT_EQ(variable.historizing(), std::optional<bool>{false});
  EXPECT_EQ(variable.browse_name(), (QualifiedName{2, "Level"}));

  const auto withoutRestrictions = variable.try_with_attribute(AttributeId::AccessRestrictions, Variant{});
  ASSERT_TRUE(withoutRestrictions.is_good()) << "(c) " << to_string(withoutRestrictions.status_code());
  EXPECT_FALSE(withoutRestrictions.value().access_restrictions().has_value())
    << "(c) a null AccessRestrictions";
  const auto withoutExtended = variable.try_with_attribute(AttributeId::AccessLevelEx, Variant{});
  ASSERT_TRUE(withoutExtended.is_good()) << "(d) " << to_string(withoutExtended.status_code());
  EXPECT_FALSE(withoutExtended.value().access_level_ex().has_value()) << "(d) a null AccessLevelEx";
  const auto withoutDefinition = dataType.try_with_attribute(AttributeId::DataTypeDefinition, Variant{});
  ASSERT_TRUE(withoutDefinition.is_good()) << "(e) " << to_string(withoutDefinition.status_code());
  EXPECT_EQ(withoutDefinition.value().data_type_definition(), nullptr) << "(e) a null DataTypeDefinition";

  EXPECT_EQ(variable.access_restrictions(), std::optional<AccessRestrictionType>{signing});
  EXPECT_EQ(variable.access_level_ex(), std::optional<AccessLevelExType>{nonatomic});
  EXPECT_NE(dataType.data_type_definition(), nullptr);
}

// NR-21 rule 4: a with_ or try_with_ form of an Attribute the NodeClass does not define is refused, the
// try_ form with a result naming the Attribute and the NodeClass, the other by throwing; the Variable, which
// defines Historizing, is the control.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-TRY-WITH-REFUSES-ATTRIBUTE-NOT-IN-NODECLASS, scope=function)
TEST(NodeDescriptionBody, AWithFormOfAnAttributeTheNodeClassLacksIsRefused)
{
  const NodeDescription object = NodeDescription::object(NodeId{2, uint32_t{47}}, QualifiedName{2, "Pump"});
  const NodeDescription variable =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double});

  std::optional<NodeDescriptionResult> refused;
  EXPECT_NO_THROW(refused.emplace(object.try_with_historizing(true)));
  ASSERT_TRUE(refused.has_value());
  ASSERT_TRUE(refused->is_bad());
  EXPECT_EQ(refused->status_code().as_status(), Status::BadInvalidArgument)
    << to_string(refused->status_code());
  EXPECT_EQ(named_attribute(refused->shared_detail()), to_string(AttributeId::Historizing));
  ASSERT_NE(refused->shared_detail(), nullptr);
  EXPECT_EQ(test_utils::error_context(refused->shared_detail().get(), ContextKeys::value.value()),
    to_string(NodeClass::Object));
  try
  {
    (void)object.with_historizing(true);
    ADD_FAILURE() << "with_historizing on an Object did not throw";
  }
  catch (const UaException& thrown)
  {
    EXPECT_EQ(thrown.status_code().as_status(), Status::BadInvalidArgument)
      << to_string(thrown.status_code());
  }
  EXPECT_FALSE(object.historizing().has_value());

  const auto tried = variable.try_with_historizing(true);
  ASSERT_TRUE(tried.is_good()) << to_string(tried.status_code());
  EXPECT_EQ(tried.value().historizing(), std::optional<bool>{true});
  EXPECT_EQ(variable.with_historizing(true).historizing(), std::optional<bool>{true});
  EXPECT_EQ(variable.historizing(), std::optional<bool>{false});
}

// The Write service's answer for a ValueRank below -3 written to a Variable whose WriteMask allows it,
// Bad_InvalidArgument as the criterion records it, is the answer of both description forms; -3 is accepted.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-01-VALUE-RANK-BELOW-MINUS-THREE-AS-THE-WRITE-SERVICE, scope=function)
TEST(NodeDescriptionBody, AValueRankBelowMinusThreeIsAnsweredAsTheWriteServiceAnswersIt)
{
  const NodeDescription variable =
    NodeDescription::variable(levelId, QualifiedName{2, "Level"}, NodeId{DataTypeId::Double});
  const InitialAttribute level{AttributeId::BrowseName, Variant{QualifiedName{2, "Level"}}};

  for (const int32_t rank : {int32_t{-4}, int32_t{-3}})
  {
    SCOPED_TRACE(rank);
    std::optional<NodeDescriptionResult> created;
    std::optional<NodeDescriptionResult> written;
    EXPECT_NO_THROW(created.emplace(NodeDescription::try_from_attributes(
      levelId, NodeClass::Variable, {level, {AttributeId::ValueRank, Variant{rank}}})));
    EXPECT_NO_THROW(written.emplace(variable.try_with_attribute(AttributeId::ValueRank, Variant{rank})));
    ASSERT_TRUE(created.has_value() && written.has_value());
    for (const auto* each : {&*created, &*written})
    {
      if (rank == -4)
      {
        ASSERT_TRUE(each->is_bad());
        EXPECT_EQ(each->status_code().as_status(), Status::BadInvalidArgument)
          << to_string(each->status_code());
        EXPECT_NE(each->shared_detail(), nullptr);
      }
      else
      {
        ASSERT_TRUE(each->is_good()) << to_string(each->status_code());
        ASSERT_TRUE(each->value().value_rank().has_value());
        EXPECT_EQ(each->value().value_rank()->as_int32(), -3);
      }
    }
  }
  ASSERT_TRUE(variable.value_rank().has_value());
  EXPECT_EQ(variable.value_rank()->as_int32(), ValueRank::scalar)
    << "the refused write changed the description";
}
