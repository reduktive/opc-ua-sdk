// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_description.h"

#include "ua_array.h"
#include "ua_attribute_wire.h"
#include "ua_data_type_definition.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_node.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace ua
{

namespace
{

constexpr const char* origin{"NodeDescription"};

bool is_node_class(NodeClass nodeClass) noexcept
{
  switch (nodeClass)
  {
  case NodeClass::Object:
  case NodeClass::Variable:
  case NodeClass::Method:
  case NodeClass::ObjectType:
  case NodeClass::VariableType:
  case NodeClass::ReferenceType:
  case NodeClass::DataType:
  case NodeClass::View:
    return true;
  case NodeClass::Unspecified:
    break;
  }
  return false;
}

// Whether a description of the NodeClass holds the Attribute (OPC 10000-3 Tables 7 to 16). The
// Session-derived Attributes and a Variable's Value are defined by the NodeClass but never held in a
// description, so they answer false here; callers that report them distinctly test for them first.
bool holds(NodeClass nodeClass, AttributeId attributeId) noexcept
{
  switch (attributeId)
  {
  case AttributeId::NodeId:
  case AttributeId::NodeClass:
  case AttributeId::BrowseName:
  case AttributeId::DisplayName:
  case AttributeId::Description:
  case AttributeId::WriteMask:
  case AttributeId::RolePermissions:
  case AttributeId::AccessRestrictions:
    return true;
  case AttributeId::EventNotifier:
    return nodeClass == NodeClass::Object || nodeClass == NodeClass::View;
  case AttributeId::IsAbstract:
    return nodeClass == NodeClass::ObjectType || nodeClass == NodeClass::VariableType ||
           nodeClass == NodeClass::ReferenceType || nodeClass == NodeClass::DataType;
  case AttributeId::Symmetric:
  case AttributeId::InverseName:
    return nodeClass == NodeClass::ReferenceType;
  case AttributeId::ContainsNoLoops:
    return nodeClass == NodeClass::View;
  case AttributeId::DataType:
  case AttributeId::ValueRank:
  case AttributeId::ArrayDimensions:
    return nodeClass == NodeClass::Variable || nodeClass == NodeClass::VariableType;
  case AttributeId::Value:
    return nodeClass == NodeClass::VariableType;
  case AttributeId::AccessLevel:
  case AttributeId::MinimumSamplingInterval:
  case AttributeId::Historizing:
  case AttributeId::AccessLevelEx:
    return nodeClass == NodeClass::Variable;
  case AttributeId::Executable:
    return nodeClass == NodeClass::Method;
  case AttributeId::DataTypeDefinition:
    return nodeClass == NodeClass::DataType;
  default:
    return false;
  }
}

bool is_variable_value(NodeClass nodeClass, AttributeId attributeId) noexcept
{
  return nodeClass == NodeClass::Variable && attributeId == AttributeId::Value;
}

std::string render(NodeClass nodeClass)
{
  return is_node_class(nodeClass) ? to_string(nodeClass) : std::to_string(static_cast<int32_t>(nodeClass));
}

// A refusal naming the Node, the Attribute and the NodeClass of the description it concerns.
UaException attribute_refused(Status status, const char* code, const char* summary, const NodeId& nodeId,
  NodeClass nodeClass, AttributeId attributeId)
{
  return UaException{StatusCode{status,
    ErrorDetail::build(code, summary, origin)
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::nodeAttribute, to_string(attributeId))
      .context(ContextKeys::value, render(nodeClass))}};
}

// Why an Attribute is not held in a description of the NodeClass, refused with @p status.
UaException not_held(Status status, const NodeId& nodeId, NodeClass nodeClass, AttributeId attributeId)
{
  if (is_session_derived_attribute(attributeId))
  {
    return attribute_refused(status,
      "SessionDerivedAttribute",
      "The Attribute is derived per Session from its source Attribute and is not part of a NodeDescription",
      nodeId,
      nodeClass,
      attributeId);
  }
  if (is_variable_value(nodeClass, attributeId))
  {
    return attribute_refused(status,
      "VariableValueNotDescribed",
      "A Variable's Value is not part of a NodeDescription; it is read and written through the namespace",
      nodeId,
      nodeClass,
      attributeId);
  }
  return attribute_refused(status,
    "AttributeNotInNodeClass",
    "The NodeClass does not define the Attribute",
    nodeId,
    nodeClass,
    attributeId);
}

UaException type_mismatch(const NodeId& nodeId, AttributeId attributeId, StatusCode cause)
{
  return UaException{StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("AttributeTypeMismatch", "The value is not of the Attribute's type", origin)
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::nodeAttribute, to_string(attributeId))
      .cause(std::move(cause))}};
}

UaException type_mismatch(const NodeId& nodeId, AttributeId attributeId)
{
  return type_mismatch(nodeId, attributeId, StatusCode{Status::BadTypeMismatch});
}

// The value of a built-in type, or Bad_TypeMismatch. Exact-type: no numeric conversion.
template<class T>
T decode(const NodeId& nodeId, AttributeId attributeId, const Variant& value)
{
  auto converted = value.to<T>();
  if (!converted.is_good())
  {
    throw type_mismatch(nodeId, attributeId, converted.status_code());
  }
  return std::move(converted).value();
}

// A LocalizedText Attribute as written: an empty Variant is the null LocalizedText, which deletes every
// locale when merged (OPC 10000-4 5.10.4.1).
LocalizedText decode_written_text(const NodeId& nodeId, AttributeId attributeId, const Variant& value)
{
  return value.empty() ? LocalizedText{} : decode<LocalizedText>(nodeId, attributeId, value);
}

// A ValueRank below the lowest defined one is refused as the Write service refuses it: its
// encode_writable_attribute builds a ValueRank, whose constructor answers Bad_InvalidArgument. That refusal
// is kept as the cause, under a detail naming the Node and the Attribute.
ValueRank decode_value_rank(const NodeId& nodeId, const Variant& value)
{
  const auto rank = decode<int32_t>(nodeId, AttributeId::ValueRank, value);
  try
  {
    return ValueRank{rank};
  }
  catch (...)
  {
    throw UaException{StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("ValueRankOutOfRange", "The ValueRank is below the lowest defined ValueRank", origin)
        .context(ContextKeys::nodeId, to_string(nodeId))
        .context(ContextKeys::nodeAttribute, to_string(AttributeId::ValueRank))
        .context(ContextKeys::value, std::to_string(rank))
        .context(ContextKeys::min, std::to_string(ValueRank::scalarOrOneDimension))
        .cause(exception_to_status_code(std::current_exception()))}};
  }
}

// Whether a write of a null Variant to the Attribute is a value it can hold. A LocalizedText Attribute
// merges it (OPC 10000-4 5.10.4.1); ArrayDimensions holds it as no dimensions and RolePermissions as no
// override of the namespace's DefaultRolePermissions (OPC 10000-6 5.1.9: a null array is an empty one;
// OPC 10000-3 5.2.9: an empty RolePermissions removes the override); a VariableType's Value holds a null.
// Any other Attribute is refused rather than removed by it.
bool accepts_written_null(AttributeId attributeId) noexcept
{
  switch (attributeId)
  {
  case AttributeId::DisplayName:
  case AttributeId::Description:
  case AttributeId::InverseName:
  case AttributeId::ArrayDimensions:
  case AttributeId::RolePermissions:
  case AttributeId::Value:
    return true;
  default:
    return false;
  }
}

// Whether a write of a null Variant removes the Attribute: the optional Attributes an accessor setter clears
// with a null (COMP-ADDRSP-ACCESSOR-ROUTE-05 item 2). The server clears a Node's AccessRestrictions this way
// when it publishes its namespace's metadata.
bool clears_with_null(AttributeId attributeId) noexcept
{
  switch (attributeId)
  {
  case AttributeId::AccessRestrictions:
  case AttributeId::MinimumSamplingInterval:
  case AttributeId::AccessLevelEx:
  case AttributeId::DataTypeDefinition:
    return true;
  default:
    return false;
  }
}

UaException written_null_refused(const NodeId& nodeId, AttributeId attributeId)
{
  return UaException{StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("NullAttributeValue",
      "A null value is not of the Attribute's type; a write does not remove the Attribute",
      origin)
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::nodeAttribute, to_string(attributeId))}};
}

// ArrayDimensions as written: null, or a one-dimensional array of UInt32. An empty array means the same as
// null (OPC 10000-6 5.1.9) and is held as null.
std::optional<std::vector<uint32_t>> decode_array_dimensions(const NodeId& nodeId, const Variant& value)
{
  if (value.empty())
  {
    return std::nullopt;
  }
  const auto& dimensions = value.is_array() ? value.get_array_base().dimensions() : std::nullopt;
  if (!value.is_array_of_uint32() || (dimensions.has_value() && dimensions->size() > 1))
  {
    throw type_mismatch(nodeId, AttributeId::ArrayDimensions);
  }
  const auto& entries = value.as<Array<uint32_t>>().payload();
  if (entries.empty())
  {
    return std::nullopt;
  }
  return std::vector<uint32_t>{entries.begin(), entries.end()};
}

// RolePermissions in wire form: an array of RolePermissionType structures. A null Variant and an empty
// array are the same (OPC 10000-6 5.1.9) and both mean no override of the namespace's
// DefaultRolePermissions (OPC 10000-3 5.2.9), so neither is held as an empty list, which would grant
// nothing.
std::optional<std::vector<RolePermissionType>> decode_role_permissions(
  const NodeId& nodeId, const Variant& value)
{
  if (value.empty())
  {
    return std::nullopt;
  }
  if (!value.is_array_of_structure())
  {
    throw type_mismatch(nodeId, AttributeId::RolePermissions);
  }
  const auto& entries = value.as<Array<RefStructure<Structure>>>();
  if (entries.size() == 0)
  {
    return std::nullopt;
  }
  std::vector<RolePermissionType> permissions;
  permissions.reserve(entries.size());
  for (size_t i = 0; i < entries.size(); ++i)
  {
    const auto* permission = dynamic_cast<const RolePermissionType*>(entries[i].get());
    if (permission == nullptr)
    {
      throw type_mismatch(nodeId, AttributeId::RolePermissions);
    }
    permissions.push_back(*permission);
  }
  return permissions;
}

// A DataTypeDefinition in wire form: a structure deriving from DataTypeDefinition, held as an owning clone;
// an empty Variant is none.
shared_ptr<const DataTypeDefinition> decode_data_type_definition(const NodeId& nodeId, const Variant& value)
{
  if (value.empty())
  {
    return {};
  }
  if (!value.is_structure())
  {
    throw type_mismatch(nodeId, AttributeId::DataTypeDefinition);
  }
  const auto* definition = dynamic_cast<const DataTypeDefinition*>(value.as<RefStructure<Structure>>().get());
  if (definition == nullptr)
  {
    throw type_mismatch(nodeId, AttributeId::DataTypeDefinition);
  }
  auto cloned = definition->clone();
  return shared_ptr<const DataTypeDefinition>{static_cast<DataTypeDefinition*>(cloned.release())};
}

// A VariableType's Value, given as the value's Variant or as a DataValue holding it.
DataValue decode_type_value(const Variant& value)
{
  if (value.is_data_value())
  {
    return value.as<DataValue>();
  }
  return DataValue{value};
}

LocalizedText default_display_name(const QualifiedName& browseName)
{
  return browseName.name().empty() ? LocalizedText{} : LocalizedText{browseName.name()};
}

// How a wire value is applied to a body: at creation an empty Variant is an Attribute not given and a
// LocalizedText replaces; on a write an empty Variant is a written null and a LocalizedText merges.
enum class Apply
{
  Create,
  Write,
};

// An optional Attribute held behind a pointer: engaged or empty like std::optional, but an empty one costs
// the pointer alone, and a description and the copy a with_ form makes of it share an Attribute neither
// changes. For the Attributes most Nodes do not carry, or whose value is large (NR-21 rule 9, measured in
// DL-112).
template<class T>
class SharedOptional
{
public:
  SharedOptional() = default;

  SharedOptional& operator=(T value)
  {
    mHeld = std::make_shared<const T>(std::move(value));
    return *this;
  }

  SharedOptional& operator=(std::optional<T> value)
  {
    mHeld = value ? std::make_shared<const T>(std::move(*value)) : nullptr;
    return *this;
  }

  explicit operator bool() const noexcept
  {
    return mHeld != nullptr;
  }

  const T& operator*() const noexcept
  {
    return *mHeld;
  }

  // The value, or null when the Attribute is not carried.
  const T* get() const noexcept
  {
    return mHeld.get();
  }

private:
  shared_ptr<const T> mHeld;
};

}  // namespace

struct NodeDescription::Body
{
  NodeId nodeId;
  NodeClass nodeClass{NodeClass::Unspecified};
  QualifiedName browseName;
  LocalizedText displayName;
  SharedOptional<LocalizedText> description;
  std::optional<AttributeWriteMask> writeMask;
  SharedOptional<std::vector<RolePermissionType>> rolePermissions;
  std::optional<AccessRestrictionType> accessRestrictions;

  // NodeClass-specific: a mandatory one is engaged exactly when the NodeClass defines it; an optional one
  // when, in addition, the Node carries it.
  std::optional<bool> isAbstract;
  std::optional<bool> symmetric;
  SharedOptional<LocalizedText> inverseName;
  std::optional<bool> containsNoLoops;
  std::optional<EventNotifierType> eventNotifier;
  SharedOptional<NodeId> dataType;
  std::optional<ValueRank> valueRank;
  SharedOptional<std::vector<uint32_t>> arrayDimensions;
  std::optional<AccessLevelType> accessLevel;
  std::optional<Duration> minimumSamplingInterval;
  std::optional<bool> historizing;
  std::optional<AccessLevelExType> accessLevelEx;
  std::optional<bool> executable;
  shared_ptr<const DataTypeDefinition> dataTypeDefinition;
  SharedOptional<DataValue> value;

  // A body of the NodeClass with every mandatory Attribute at its factory default.
  static shared_ptr<Body> make(NodeId nodeId, NodeClass nodeClass, QualifiedName browseName)
  {
    auto body = std::make_shared<Body>();
    body->nodeId = std::move(nodeId);
    body->nodeClass = nodeClass;
    body->displayName = default_display_name(browseName);
    body->browseName = std::move(browseName);
    switch (nodeClass)
    {
    case NodeClass::Object:
      body->eventNotifier = EventNotifierType{uint8_t{0}};
      break;
    case NodeClass::Variable:
      body->dataType = NodeId{DataTypeId::BaseDataType};
      body->valueRank = ValueRank{ValueRank::scalar};
      body->accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead};
      body->historizing = false;
      break;
    case NodeClass::Method:
      body->executable = true;
      break;
    case NodeClass::VariableType:
      body->dataType = NodeId{DataTypeId::BaseDataType};
      body->valueRank = ValueRank{ValueRank::scalar};
      body->isAbstract = false;
      break;
    case NodeClass::ReferenceType:
      body->isAbstract = false;
      body->symmetric = false;
      break;
    case NodeClass::ObjectType:
    case NodeClass::DataType:
      body->isAbstract = false;
      break;
    case NodeClass::View:
      body->containsNoLoops = false;
      body->eventNotifier = EventNotifierType{uint8_t{0}};
      break;
    case NodeClass::Unspecified:
      break;
    }
    return body;
  }

  static NodeDescription describe(shared_ptr<const Body> body) noexcept
  {
    return NodeDescription{std::move(body)};
  }

  template<class Change>
  static NodeDescription copy_with(const NodeDescription& from, Change&& change)
  {
    auto body = std::make_shared<Body>(*from.mBody);
    std::forward<Change>(change)(*body);
    return NodeDescription{std::move(body)};
  }

  // The copy for a NodeClass-specific with_ form: Bad_InvalidArgument when the NodeClass does not define
  // the Attribute.
  template<class Change>
  static NodeDescriptionResult try_copy_with(
    const NodeDescription& from, AttributeId attributeId, Change&& change) noexcept
  {
    try
    {
      const Body& body = *from.mBody;
      if (!holds(body.nodeClass, attributeId))
      {
        throw not_held(Status::BadInvalidArgument, body.nodeId, body.nodeClass, attributeId);
      }
      return copy_with(from, std::forward<Change>(change));
    }
    catch (...)
    {
      return exception_to_status_code(std::current_exception());
    }
  }

  // Sets one Attribute the NodeClass holds from its wire form; throws Bad_TypeMismatch for a value that
  // does not fit it, a written null included, and Bad_InvalidArgument for a ValueRank below the lowest.
  void apply(AttributeId attributeId, const Variant& wire, Apply mode)
  {
    if (wire.empty())
    {
      if (mode == Apply::Create)
      {
        return;
      }
      if (clears_with_null(attributeId))
      {
        clear(attributeId);
        return;
      }
      if (!accepts_written_null(attributeId))
      {
        throw written_null_refused(nodeId, attributeId);
      }
    }
    const auto text = [&](const LocalizedText* held)
    {
      if (mode == Apply::Create)
      {
        return decode<LocalizedText>(nodeId, attributeId, wire);
      }
      return (held != nullptr ? *held : LocalizedText{})
        .merged_with(decode_written_text(nodeId, attributeId, wire));
    };

    switch (attributeId)
    {
    case AttributeId::BrowseName:
      browseName = decode<QualifiedName>(nodeId, attributeId, wire);
      break;
    case AttributeId::DisplayName:
      displayName = text(&displayName);
      break;
    case AttributeId::Description:
      description = text(description.get());
      break;
    case AttributeId::WriteMask:
      writeMask = AttributeWriteMask{decode<uint32_t>(nodeId, attributeId, wire)};
      break;
    case AttributeId::RolePermissions:
      rolePermissions = decode_role_permissions(nodeId, wire);
      break;
    case AttributeId::AccessRestrictions:
      accessRestrictions = AccessRestrictionType{decode<uint16_t>(nodeId, attributeId, wire)};
      break;
    case AttributeId::IsAbstract:
      isAbstract = decode<bool>(nodeId, attributeId, wire);
      break;
    case AttributeId::Symmetric:
      symmetric = decode<bool>(nodeId, attributeId, wire);
      break;
    case AttributeId::InverseName:
      inverseName = text(inverseName.get());
      break;
    case AttributeId::ContainsNoLoops:
      containsNoLoops = decode<bool>(nodeId, attributeId, wire);
      break;
    case AttributeId::EventNotifier:
      eventNotifier = EventNotifierType{decode<uint8_t>(nodeId, attributeId, wire)};
      break;
    case AttributeId::DataType:
      dataType = decode<NodeId>(nodeId, attributeId, wire);
      break;
    case AttributeId::ValueRank:
      valueRank = decode_value_rank(nodeId, wire);
      break;
    case AttributeId::ArrayDimensions:
      arrayDimensions = decode_array_dimensions(nodeId, wire);
      break;
    case AttributeId::AccessLevel:
      accessLevel = AccessLevelType{decode<uint8_t>(nodeId, attributeId, wire)};
      break;
    case AttributeId::MinimumSamplingInterval:
      minimumSamplingInterval = decode<double>(nodeId, attributeId, wire);
      break;
    case AttributeId::Historizing:
      historizing = decode<bool>(nodeId, attributeId, wire);
      break;
    case AttributeId::AccessLevelEx:
      accessLevelEx = AccessLevelExType{decode<uint32_t>(nodeId, attributeId, wire)};
      break;
    case AttributeId::Executable:
      executable = decode<bool>(nodeId, attributeId, wire);
      break;
    case AttributeId::DataTypeDefinition:
      dataTypeDefinition = decode_data_type_definition(nodeId, wire);
      break;
    case AttributeId::Value:
      value = decode_type_value(wire);
      break;
    default:
      throw not_held(Status::BadInternalError, nodeId, nodeClass, attributeId);
    }
    couple_access_levels(attributeId);
  }

  // Removes an Attribute @ref clears_with_null names.
  void clear(AttributeId attributeId) noexcept
  {
    switch (attributeId)
    {
    case AttributeId::AccessRestrictions:
      accessRestrictions.reset();
      break;
    case AttributeId::MinimumSamplingInterval:
      minimumSamplingInterval.reset();
      break;
    case AttributeId::AccessLevelEx:
      accessLevelEx.reset();
      break;
    case AttributeId::DataTypeDefinition:
      dataTypeDefinition.reset();
      break;
    default:
      break;
    }
  }

  // AccessLevelEx contains AccessLevel as its first 8 bits (OPC 10000-3 5.6.2): the two are one value, and
  // setting either sets both. AccessLevelEx is held once AccessLevel is set; at creation the last of the two
  // given decides.
  void couple_access_levels(AttributeId set) noexcept
  {
    if (set == AttributeId::AccessLevel && accessLevel)
    {
      const uint32_t high = accessLevelEx ? (accessLevelEx->as_underlying_type() & 0xFFFFFF00u) : 0u;
      accessLevelEx = AccessLevelExType{high | uint32_t{accessLevel->as_underlying_type()}};
    }
    else if (set == AttributeId::AccessLevelEx && accessLevelEx)
    {
      accessLevel = AccessLevelType{static_cast<uint8_t>(accessLevelEx->as_underlying_type() & 0xFFu)};
    }
  }

  // The Attribute in wire form, or nullopt when the Node does not carry it. Only for an Attribute the
  // NodeClass holds; a VariableType's Value is answered by the caller.
  [[nodiscard]] std::optional<Variant> wire(AttributeId attributeId) const
  {
    const auto optionalWire = [](const auto& held, auto encode) -> std::optional<Variant>
    {
      if (!held)
      {
        return std::nullopt;
      }
      return encode(held);
    };

    switch (attributeId)
    {
    case AttributeId::NodeId:
      return Variant{nodeId};
    case AttributeId::NodeClass:
      return Variant{static_cast<int32_t>(nodeClass)};
    case AttributeId::BrowseName:
      return attribute_wire::browse_name(browseName);
    case AttributeId::DisplayName:
      // Not attribute_wire::display_name: its size limit guards writes, and a read answers what is held.
      return Variant{displayName};
    case AttributeId::Description:
      return optionalWire(description, [](const auto& held) { return attribute_wire::description(*held); });
    case AttributeId::WriteMask:
      return optionalWire(writeMask, [](const auto& held) { return attribute_wire::write_mask(held); });
    case AttributeId::RolePermissions:
      return optionalWire(
        rolePermissions, [](const auto& held) { return attribute_wire::role_permissions(*held); });
    case AttributeId::AccessRestrictions:
      return optionalWire(
        accessRestrictions, [](const auto& held) { return attribute_wire::access_restrictions(held); });
    case AttributeId::IsAbstract:
      return optionalWire(isAbstract, [](const auto& held) { return attribute_wire::is_abstract(*held); });
    case AttributeId::Symmetric:
      return optionalWire(symmetric, [](const auto& held) { return attribute_wire::symmetric(*held); });
    case AttributeId::InverseName:
      return optionalWire(inverseName, [](const auto& held) { return attribute_wire::inverse_name(*held); });
    case AttributeId::ContainsNoLoops:
      return optionalWire(
        containsNoLoops, [](const auto& held) { return attribute_wire::contains_no_loops(*held); });
    case AttributeId::EventNotifier:
      return optionalWire(
        eventNotifier, [](const auto& held) { return attribute_wire::event_notifier(*held); });
    case AttributeId::DataType:
      return optionalWire(dataType, [](const auto& held) { return attribute_wire::data_type(*held); });
    case AttributeId::ValueRank:
      return optionalWire(valueRank, [](const auto& held) { return attribute_wire::value_rank(*held); });
    case AttributeId::ArrayDimensions:
      return optionalWire(
        arrayDimensions, [](const auto& held) { return attribute_wire::array_dimensions(*held); });
    case AttributeId::AccessLevel:
      return optionalWire(accessLevel, [](const auto& held) { return attribute_wire::access_level(*held); });
    case AttributeId::MinimumSamplingInterval:
      return optionalWire(minimumSamplingInterval,
        [](const auto& held) { return attribute_wire::minimum_sampling_interval(held); });
    case AttributeId::Historizing:
      return optionalWire(historizing, [](const auto& held) { return attribute_wire::historizing(*held); });
    case AttributeId::AccessLevelEx:
      return optionalWire(
        accessLevelEx, [](const auto& held) { return attribute_wire::access_level_ex(held); });
    case AttributeId::Executable:
      return optionalWire(executable, [](const auto& held) { return attribute_wire::executable(*held); });
    case AttributeId::DataTypeDefinition:
      return optionalWire(
        dataTypeDefinition, [](const auto& held) { return attribute_wire::data_type_definition(held); });
    default:
      return std::nullopt;
    }
  }
};

NodeDescription::NodeDescription(shared_ptr<const Body> body) noexcept : mBody{std::move(body)}
{}

NodeDescription::NodeDescription(NodeDescription&& other) noexcept : mBody{other.mBody}
{}

NodeDescription& NodeDescription::operator=(NodeDescription&& other) noexcept
{
  mBody = other.mBody;
  return *this;
}

// --- Factories ---

NodeDescription NodeDescription::object(NodeId nodeId, QualifiedName browseName)
{
  return Body::describe(Body::make(std::move(nodeId), NodeClass::Object, std::move(browseName)));
}

NodeDescription NodeDescription::variable(
  NodeId nodeId, QualifiedName browseName, NodeId dataType, ValueRank valueRank)
{
  auto body = Body::make(std::move(nodeId), NodeClass::Variable, std::move(browseName));
  body->dataType = std::move(dataType);
  body->valueRank = valueRank;
  return Body::describe(std::move(body));
}

NodeDescription NodeDescription::method(NodeId nodeId, QualifiedName browseName)
{
  return Body::describe(Body::make(std::move(nodeId), NodeClass::Method, std::move(browseName)));
}

NodeDescription NodeDescription::object_type(NodeId nodeId, QualifiedName browseName, bool isAbstract)
{
  auto body = Body::make(std::move(nodeId), NodeClass::ObjectType, std::move(browseName));
  body->isAbstract = isAbstract;
  return Body::describe(std::move(body));
}

NodeDescription NodeDescription::variable_type(
  NodeId nodeId, QualifiedName browseName, NodeId dataType, ValueRank valueRank, bool isAbstract)
{
  auto body = Body::make(std::move(nodeId), NodeClass::VariableType, std::move(browseName));
  body->dataType = std::move(dataType);
  body->valueRank = valueRank;
  body->isAbstract = isAbstract;
  return Body::describe(std::move(body));
}

NodeDescription NodeDescription::data_type(NodeId nodeId, QualifiedName browseName, bool isAbstract)
{
  auto body = Body::make(std::move(nodeId), NodeClass::DataType, std::move(browseName));
  body->isAbstract = isAbstract;
  return Body::describe(std::move(body));
}

NodeDescriptionResult NodeDescription::try_reference_type(NodeId nodeId, QualifiedName browseName,
  bool isAbstract, bool symmetric, std::optional<LocalizedText> inverseName) noexcept
{
  try
  {
    if (symmetric && inverseName.has_value())
    {
      throw attribute_refused(Status::BadInvalidArgument,
        "SymmetricWithInverseName",
        "A symmetric ReferenceType has no InverseName",
        nodeId,
        NodeClass::ReferenceType,
        AttributeId::InverseName);
    }
    if (!symmetric && !inverseName.has_value())
    {
      throw attribute_refused(Status::BadInvalidArgument,
        "InverseNameMissing",
        "A non-symmetric ReferenceType has an InverseName",
        nodeId,
        NodeClass::ReferenceType,
        AttributeId::InverseName);
    }
    auto body = Body::make(std::move(nodeId), NodeClass::ReferenceType, std::move(browseName));
    body->isAbstract = isAbstract;
    body->symmetric = symmetric;
    body->inverseName = std::move(inverseName);
    return Body::describe(std::move(body));
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

NodeDescription NodeDescription::view(NodeId nodeId, QualifiedName browseName, bool containsNoLoops)
{
  auto body = Body::make(std::move(nodeId), NodeClass::View, std::move(browseName));
  body->containsNoLoops = containsNoLoops;
  return Body::describe(std::move(body));
}

NodeDescriptionResult NodeDescription::try_from_attributes(
  const NodeId& nodeId, NodeClass nodeClass, const InitialAttributes& attributes) noexcept
{
  try
  {
    if (!is_node_class(nodeClass))
    {
      throw UaException{StatusCode{Status::BadNodeClassInvalid,
        ErrorDetail::build("NodeClassInvalid", "The NodeClass is Unspecified or not a NodeClass", origin)
          .context(ContextKeys::nodeId, to_string(nodeId))
          .context(ContextKeys::value, render(nodeClass))}};
    }

    auto body = Body::make(nodeId, nodeClass, QualifiedName{});
    bool displayNameGiven{false};
    for (const auto& [attributeId, wire] : attributes)
    {
      if (attributeId == AttributeId::NodeId)
      {
        if (!wire.empty() && decode<NodeId>(nodeId, attributeId, wire) != nodeId)
        {
          throw UaException{StatusCode{Status::BadNodeAttributesInvalid,
            ErrorDetail::build(
              "NodeIdContradicted", "The NodeId Attribute differs from the Node's NodeId", origin)
              .context(ContextKeys::expected, to_string(nodeId))
              .context(ContextKeys::actual, to_string(wire.as<NodeId>()))}};
        }
        continue;
      }
      if (attributeId == AttributeId::NodeClass)
      {
        if (!wire.empty())
        {
          const auto given = static_cast<NodeClass>(decode<int32_t>(nodeId, attributeId, wire));
          if (given != nodeClass)
          {
            throw UaException{StatusCode{Status::BadNodeClassInvalid,
              ErrorDetail::build("NodeClassContradicted",
                "The NodeClass Attribute differs from the NodeClass requested",
                origin)
                .context(ContextKeys::nodeId, to_string(nodeId))
                .context(ContextKeys::expected, render(nodeClass))
                .context(ContextKeys::actual, render(given))}};
          }
        }
        continue;
      }
      if (wire.empty())
      {
        continue;  // not given, whichever Attribute it names
      }
      if (!holds(nodeClass, attributeId))
      {
        throw not_held(Status::BadNodeAttributesInvalid, nodeId, nodeClass, attributeId);
      }
      body->apply(attributeId, wire, Apply::Create);
      displayNameGiven = displayNameGiven || (attributeId == AttributeId::DisplayName && !wire.empty());
    }
    if (!displayNameGiven)
    {
      body->displayName = default_display_name(body->browseName);
    }
    return Body::describe(std::move(body));
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

// --- Modified copies: Attributes of every NodeClass ---

NodeDescription NodeDescription::with_browse_name(QualifiedName value) const
{
  return Body::copy_with(*this, [&value](Body& body) { body.browseName = std::move(value); });
}

NodeDescription NodeDescription::with_display_name(LocalizedText value) const
{
  return Body::copy_with(*this, [&value](Body& body) { body.displayName = std::move(value); });
}

NodeDescription NodeDescription::with_description(std::optional<LocalizedText> value) const
{
  return Body::copy_with(*this, [&value](Body& body) { body.description = std::move(value); });
}

NodeDescription NodeDescription::with_write_mask(std::optional<AttributeWriteMask> value) const
{
  return Body::copy_with(*this, [&value](Body& body) { body.writeMask = value; });
}

NodeDescription NodeDescription::with_role_permissions(
  std::optional<std::vector<RolePermissionType>> value) const
{
  // An empty RolePermissions removes the Node's own (OPC 10000-3 5.2.9), as the wire path reads it.
  if (value && value->empty())
  {
    value.reset();
  }
  return Body::copy_with(*this, [&value](Body& body) { body.rolePermissions = std::move(value); });
}

NodeDescription NodeDescription::with_access_restrictions(std::optional<AccessRestrictionType> value) const
{
  return Body::copy_with(*this, [&value](Body& body) { body.accessRestrictions = value; });
}

// --- Modified copies: NodeClass-specific Attributes ---

NodeDescription NodeDescription::with_is_abstract(bool value) const
{
  return try_with_is_abstract(value).value();
}

NodeDescriptionResult NodeDescription::try_with_is_abstract(bool value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::IsAbstract, [value](Body& body) { body.isAbstract = value; });
}

NodeDescription NodeDescription::with_symmetric(bool value) const
{
  return try_with_symmetric(value).value();
}

NodeDescriptionResult NodeDescription::try_with_symmetric(bool value) const noexcept
{
  return Body::try_copy_with(*this, AttributeId::Symmetric, [value](Body& body) { body.symmetric = value; });
}

NodeDescription NodeDescription::with_inverse_name(std::optional<LocalizedText> value) const
{
  return try_with_inverse_name(std::move(value)).value();
}

NodeDescriptionResult NodeDescription::try_with_inverse_name(
  std::optional<LocalizedText> value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::InverseName, [&value](Body& body) { body.inverseName = std::move(value); });
}

NodeDescription NodeDescription::with_contains_no_loops(bool value) const
{
  return try_with_contains_no_loops(value).value();
}

NodeDescriptionResult NodeDescription::try_with_contains_no_loops(bool value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::ContainsNoLoops, [value](Body& body) { body.containsNoLoops = value; });
}

NodeDescription NodeDescription::with_event_notifier(EventNotifierType value) const
{
  return try_with_event_notifier(value).value();
}

NodeDescriptionResult NodeDescription::try_with_event_notifier(EventNotifierType value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::EventNotifier, [value](Body& body) { body.eventNotifier = value; });
}

NodeDescription NodeDescription::with_data_type(NodeId value) const
{
  return try_with_data_type(std::move(value)).value();
}

NodeDescriptionResult NodeDescription::try_with_data_type(NodeId value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::DataType, [&value](Body& body) { body.dataType = std::move(value); });
}

NodeDescription NodeDescription::with_value_rank(ValueRank value) const
{
  return try_with_value_rank(value).value();
}

NodeDescriptionResult NodeDescription::try_with_value_rank(ValueRank value) const noexcept
{
  return Body::try_copy_with(*this, AttributeId::ValueRank, [value](Body& body) { body.valueRank = value; });
}

NodeDescription NodeDescription::with_array_dimensions(std::optional<std::vector<uint32_t>> value) const
{
  return try_with_array_dimensions(std::move(value)).value();
}

NodeDescriptionResult NodeDescription::try_with_array_dimensions(
  std::optional<std::vector<uint32_t>> value) const noexcept
{
  // An empty ArrayDimensions is no ArrayDimensions, as the wire path reads it.
  if (value && value->empty())
  {
    value.reset();
  }
  return Body::try_copy_with(
    *this, AttributeId::ArrayDimensions, [&value](Body& body) { body.arrayDimensions = std::move(value); });
}

NodeDescription NodeDescription::with_access_level(AccessLevelType value) const
{
  return try_with_access_level(value).value();
}

NodeDescriptionResult NodeDescription::try_with_access_level(AccessLevelType value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::AccessLevel, [value](Body& body) { body.accessLevel = value; });
}

NodeDescription NodeDescription::with_minimum_sampling_interval(std::optional<Duration> value) const
{
  return try_with_minimum_sampling_interval(value).value();
}

NodeDescriptionResult NodeDescription::try_with_minimum_sampling_interval(
  std::optional<Duration> value) const noexcept
{
  return Body::try_copy_with(*this,
    AttributeId::MinimumSamplingInterval,
    [value](Body& body) { body.minimumSamplingInterval = value; });
}

NodeDescription NodeDescription::with_historizing(bool value) const
{
  return try_with_historizing(value).value();
}

NodeDescriptionResult NodeDescription::try_with_historizing(bool value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::Historizing, [value](Body& body) { body.historizing = value; });
}

NodeDescription NodeDescription::with_access_level_ex(std::optional<AccessLevelExType> value) const
{
  return try_with_access_level_ex(value).value();
}

NodeDescriptionResult NodeDescription::try_with_access_level_ex(
  std::optional<AccessLevelExType> value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::AccessLevelEx, [value](Body& body) { body.accessLevelEx = value; });
}

NodeDescription NodeDescription::with_executable(bool value) const
{
  return try_with_executable(value).value();
}

NodeDescriptionResult NodeDescription::try_with_executable(bool value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::Executable, [value](Body& body) { body.executable = value; });
}

NodeDescription NodeDescription::with_data_type_definition(shared_ptr<const DataTypeDefinition> value) const
{
  return try_with_data_type_definition(std::move(value)).value();
}

NodeDescriptionResult NodeDescription::try_with_data_type_definition(
  shared_ptr<const DataTypeDefinition> value) const noexcept
{
  return Body::try_copy_with(*this,
    AttributeId::DataTypeDefinition,
    [&value](Body& body) { body.dataTypeDefinition = std::move(value); });
}

NodeDescription NodeDescription::with_value(std::optional<DataValue> value) const
{
  return try_with_value(std::move(value)).value();
}

NodeDescriptionResult NodeDescription::try_with_value(std::optional<DataValue> value) const noexcept
{
  return Body::try_copy_with(
    *this, AttributeId::Value, [&value](Body& body) { body.value = std::move(value); });
}

NodeDescriptionResult NodeDescription::try_with_attribute(
  AttributeId attributeId, const Variant& value) const noexcept
{
  try
  {
    const Body& body = *mBody;
    if (attributeId == AttributeId::NodeId || attributeId == AttributeId::NodeClass)
    {
      throw attribute_refused(Status::BadAttributeIdInvalid,
        "AttributeNotWritable",
        "The NodeId and the NodeClass of a Node are fixed when it is created",
        body.nodeId,
        body.nodeClass,
        attributeId);
    }
    if (!holds(body.nodeClass, attributeId))
    {
      throw not_held(Status::BadAttributeIdInvalid, body.nodeId, body.nodeClass, attributeId);
    }
    if (attributeId == AttributeId::InverseName && body.symmetric.value_or(false))
    {
      // OPC 10000-3 5.3.2: "If a ReferenceType is symmetric, the InverseName Attribute shall be omitted."
      // An empty Variant is not given; anything else is refused as try_reference_type refuses it.
      if (value.empty())
      {
        return *this;
      }
      throw attribute_refused(Status::BadInvalidArgument,
        "SymmetricWithInverseName",
        "A symmetric ReferenceType has no InverseName",
        body.nodeId,
        NodeClass::ReferenceType,
        AttributeId::InverseName);
    }
    return Body::copy_with(*this, [&](Body& copy) { copy.apply(attributeId, value, Apply::Write); });
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

// --- Readers ---

const NodeId& NodeDescription::node_id() const& noexcept
{
  return mBody->nodeId;
}

NodeClass NodeDescription::node_class() const noexcept
{
  return mBody->nodeClass;
}

const QualifiedName& NodeDescription::browse_name() const& noexcept
{
  return mBody->browseName;
}

const LocalizedText& NodeDescription::display_name() const& noexcept
{
  return mBody->displayName;
}

const LocalizedText* NodeDescription::description() const& noexcept
{
  return mBody->description.get();
}

std::optional<AttributeWriteMask> NodeDescription::write_mask() const noexcept
{
  return mBody->writeMask;
}

const std::vector<RolePermissionType>* NodeDescription::role_permissions() const& noexcept
{
  return mBody->rolePermissions.get();
}

std::optional<AccessRestrictionType> NodeDescription::access_restrictions() const noexcept
{
  return mBody->accessRestrictions;
}

std::optional<bool> NodeDescription::is_abstract() const noexcept
{
  return mBody->isAbstract;
}

std::optional<bool> NodeDescription::symmetric() const noexcept
{
  return mBody->symmetric;
}

const LocalizedText* NodeDescription::inverse_name() const& noexcept
{
  return mBody->inverseName.get();
}

std::optional<bool> NodeDescription::contains_no_loops() const noexcept
{
  return mBody->containsNoLoops;
}

std::optional<EventNotifierType> NodeDescription::event_notifier() const noexcept
{
  return mBody->eventNotifier;
}

const NodeId* NodeDescription::data_type() const& noexcept
{
  return mBody->dataType.get();
}

std::optional<ValueRank> NodeDescription::value_rank() const noexcept
{
  return mBody->valueRank;
}

const std::vector<uint32_t>* NodeDescription::array_dimensions() const& noexcept
{
  return mBody->arrayDimensions.get();
}

std::optional<AccessLevelType> NodeDescription::access_level() const noexcept
{
  return mBody->accessLevel;
}

std::optional<Duration> NodeDescription::minimum_sampling_interval() const noexcept
{
  return mBody->minimumSamplingInterval;
}

std::optional<bool> NodeDescription::historizing() const noexcept
{
  return mBody->historizing;
}

std::optional<AccessLevelExType> NodeDescription::access_level_ex() const noexcept
{
  return mBody->accessLevelEx;
}

std::optional<bool> NodeDescription::executable() const noexcept
{
  return mBody->executable;
}

const shared_ptr<const DataTypeDefinition>& NodeDescription::data_type_definition() const& noexcept
{
  return mBody->dataTypeDefinition;
}

const DataValue* NodeDescription::value() const& noexcept
{
  return mBody->value.get();
}

DataValueResult NodeDescription::attribute(AttributeId attributeId) const noexcept
{
  try
  {
    const Body& body = *mBody;
    if (!holds(body.nodeClass, attributeId))
    {
      throw not_held(Status::BadAttributeIdInvalid, body.nodeId, body.nodeClass, attributeId);
    }
    if (attributeId == AttributeId::Value)
    {
      if (body.value)
      {
        return *body.value;
      }
    }
    else if (auto wire = body.wire(attributeId))
    {
      return DataValue{std::move(*wire)};
    }
    throw attribute_refused(Status::BadAttributeIdInvalid,
      "AttributeNotCarried",
      "The Node does not carry this optional Attribute",
      body.nodeId,
      body.nodeClass,
      attributeId);
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

}  // namespace ua
