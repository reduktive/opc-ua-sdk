// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <optional>
#include <ranges>
#include <future>
#include "ua_callback_safety.h"
#include "ua_sync_wait.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_namespace_route.h"
#include "ua_reference_identity.h"
#include "ua_attribute_wire.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_to_string.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_access_level_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_reference.h"
#include "ua_call_method_result.h"
#include "ua_read_value_id.h"
#include "ua_write_value.h"

namespace ua
{

namespace
{

// One Reference held by the accessor's Node, added or removed through the owning namespace.
void change_one_reference(const NodeAccessor& accessor, NodeId type, ExpandedNodeId target, bool isForward,
  bool add, ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  try
  {
    std::vector<Reference> references;
    references.emplace_back(std::move(type), std::move(target), isForward);
    detail::NodeAccessorRoute::change_references(
      accessor, std::move(references), add, halves, std::move(callback));
  }
  catch (...)
  {
    detail::invoke_user_callback(
      callback, VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace

bool NodeAccessor::is_object() const
{
  return (get_node_class() == NodeClass::Object);
}

bool NodeAccessor::is_object_type() const
{
  return (get_node_class() == NodeClass::ObjectType);
}

bool NodeAccessor::is_data_type() const
{
  return (get_node_class() == NodeClass::DataType);
}

bool NodeAccessor::is_variable() const
{
  return (get_node_class() == NodeClass::Variable);
}

bool NodeAccessor::is_variable_type() const
{
  return (get_node_class() == NodeClass::VariableType);
}

bool NodeAccessor::is_reference_type() const
{
  return (get_node_class() == NodeClass::ReferenceType);
}

bool NodeAccessor::is_view() const
{
  return (get_node_class() == NodeClass::View);
}

bool NodeAccessor::is_method() const
{
  return (get_node_class() == NodeClass::Method);
}

bool NodeAccessor::is_type() const
{
  return (is_data_type() || is_object_type() || is_variable_type() || is_reference_type());
}

NodeDescription NodeAccessor::described() const
{
  // Every getter reads the Node's description, after checking that the Node is not deleted (NR-2 rule 2,
  // NR-44 rule 2): a deleted Node fails with Bad_NodeIdUnknown.
  auto nodeDescription = detail::NodeAccessorRoute::attributes(*this);
  if (!nodeDescription.is_good())
  {
    throw UaException{nodeDescription.status_code()};
  }
  return nodeDescription.value();
}

NodeId NodeAccessor::get_node_id() const
{
  const NodeDescription nodeDescription = described();
  return nodeDescription.node_id();
}

NodeClass NodeAccessor::get_node_class() const
{
  return described().node_class();
}

QualifiedName NodeAccessor::get_browse_name() const
{
  // The null name for a Node created without one: a description always holds a BrowseName.
  const NodeDescription nodeDescription = described();
  return nodeDescription.browse_name();
}

optional<AttributeWriteMask> NodeAccessor::get_write_mask() const
{
  return described().write_mask();
}

optional<std::vector<RolePermissionType>> NodeAccessor::get_role_permissions() const
{
  const NodeDescription nodeDescription = described();
  const auto* held = nodeDescription.role_permissions();
  if (held == nullptr)
  {
    return std::nullopt;
  }
  return *held;
}

optional<AccessRestrictionType> NodeAccessor::get_access_restrictions() const
{
  return described().access_restrictions();
}

Variant NodeAccessor::read_attribute(AttributeId attributeId) const
{
  // The boundary every accessor user crosses, so the refusal lives here as well as in the default
  // node: a Session-derived Attribute has no stored answer, and answering empty would read as "no
  // permissions" rather than "you asked the wrong question".
  if (is_session_derived_attribute(attributeId))
  {
    throw UaException{Status::BadAttributeIdInvalid,
      ErrorDetail::build("SessionDerivedAttributeNotStored",
        "This Attribute is derived per Session from its source Attribute and the authorization "
        "verdict; read the source Attribute and let access control project it",
        "NodeAccessor")
        .context(ContextKeys::nodeAttribute, to_string(attributeId))};
  }
  const NodeDescription nodeDescription = described();
  auto held = nodeDescription.attribute(attributeId);
  if (held.status_code().as_status() == Status::BadAttributeIdInvalid)
  {
    // An Attribute the Node does not carry, or its NodeClass does not define, reads as absent.
    return Variant{};
  }
  if (!held.is_good())
  {
    throw UaException{held.status_code()};
  }
  if (attributeId == AttributeId::Value)
  {
    // A VariableType's Value, as the DataValue it is held as.
    return Variant{held.value()};
  }
  return held.value().value();
}

void NodeAccessor::write_attribute_async(
  AttributeId attributeId, Variant attributeValue, std::function<void(VoidResult)> callback) noexcept
{
  try
  {
    WriteValue writeValue;
    writeValue.node_id() = get_node_id();
    writeValue.attribute_id() = utils::to_underlying(attributeId);
    // A VariableType's Value is stored as a DataValue, which the write carries as its own.
    if (attributeId == AttributeId::Value && attributeValue.is_data_value())
    {
      writeValue.value() = attributeValue.as<DataValue>();
    }
    else
    {
      writeValue.value().value() = std::move(attributeValue);
    }
    detail::NodeAccessorRoute::write(*this, writeValue, nullptr, std::move(callback));
  }
  catch (...)
  {
    detail::invoke_user_callback(
      callback, VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult NodeAccessor::try_write_attribute_sync(AttributeId attributeId, Variant attributeValue) noexcept
{
  // try_*_sync member of the attribute-write triad: waits for write_attribute_async and returns the outcome,
  // or Bad_WouldBlock on a thread of the address space's executor (NR-7). Never throws.
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      { write_attribute_async(attributeId, std::move(attributeValue), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::write_attribute_sync(AttributeId attributeId, Variant attributeValue)
{
  try_write_attribute_sync(attributeId, std::move(attributeValue)).value();  // throws if bad
}

void NodeAccessor::set_browse_name(QualifiedName browseName)
{
  write_attribute_sync(AttributeId::BrowseName, attribute_wire::browse_name(browseName));
}

void NodeAccessor::set_display_name(LocalizedText displayName)
{
  // The DisplayName size limit is enforced inside attribute_wire::display_name (single source for
  // every write path); it throws BadInvalidArgument when exceeded, preserving this setter's contract.
  write_attribute_sync(AttributeId::DisplayName, attribute_wire::display_name(displayName));
}

void NodeAccessor::set_description(LocalizedText description)
{
  write_attribute_sync(AttributeId::Description, attribute_wire::description(description));
}

void NodeAccessor::set_write_mask(optional<AttributeWriteMask> writeMask)
{
  write_attribute_sync(AttributeId::WriteMask, attribute_wire::write_mask(writeMask));
}

void NodeAccessor::set_role_permissions(optional<std::vector<RolePermissionType>> rolePermissions)
{
  write_attribute_sync(AttributeId::RolePermissions, attribute_wire::role_permissions(rolePermissions));
}

void NodeAccessor::set_access_restrictions(optional<AccessRestrictionType> accessRestrictions)
{
  write_attribute_sync(
    AttributeId::AccessRestrictions, attribute_wire::access_restrictions(accessRestrictions));
}

bool NodeAccessor::is_matching_class() const
{
  return true;
}

bool DataTypeAccessor::is_matching_class() const
{
  return is_data_type();
}

bool DataTypeAccessor::get_is_abstract() const
{
  return described().is_abstract().value_or(false);
}

void DataTypeAccessor::set_is_abstract(bool isAbstract)
{
  write_attribute_sync(AttributeId::IsAbstract, attribute_wire::is_abstract(isAbstract));
}

shared_ptr<const DataTypeDefinition> DataTypeAccessor::get_data_type_definition() const
{
  const NodeDescription nodeDescription = described();
  return nodeDescription.data_type_definition();
}

void DataTypeAccessor::set_data_type_definition(shared_ptr<const DataTypeDefinition> dataTypeDefinition)
{
  write_attribute_sync(
    AttributeId::DataTypeDefinition, attribute_wire::data_type_definition(dataTypeDefinition));
}

bool MethodAccessor::is_matching_class() const
{
  return is_method();
}

bool MethodAccessor::get_executable() const
{
  return described().executable().value_or(true);
}

void MethodAccessor::set_executable(bool executable)
{
  write_attribute_sync(AttributeId::Executable, attribute_wire::executable(executable));
}

void MethodAccessor::call_async(const CallMethodRequest& methodToCall,
  shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback) const noexcept
{
  detail::NodeAccessorRoute::call(*this, methodToCall, std::move(context), std::move(callback));
}

CallResult MethodAccessor::try_call_sync(const CallMethodRequest& methodToCall) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CallResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(CallResult)> complete)
      { call_async(methodToCall, nullptr, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

CallMethodResult MethodAccessor::call_sync(const CallMethodRequest& methodToCall) const
{
  return ua::detail::good_value(try_call_sync(methodToCall));
}

bool ObjectAccessor::is_matching_class() const
{
  return is_object();
}

EventNotifierType ObjectAccessor::get_event_notifier() const
{
  return described().event_notifier().value_or(EventNotifierType{uint8_t{0}});
}

void ObjectAccessor::set_event_notifier(const EventNotifierType& eventNotifier)
{
  write_attribute_sync(AttributeId::EventNotifier, attribute_wire::event_notifier(eventNotifier));
}

bool ReferenceTypeAccessor::is_matching_class() const
{
  return is_reference_type();
}

bool ReferenceTypeAccessor::get_is_abstract() const
{
  return described().is_abstract().value_or(false);
}

void ReferenceTypeAccessor::set_is_abstract(bool isAbstract)
{
  write_attribute_sync(AttributeId::IsAbstract, attribute_wire::is_abstract(isAbstract));
}

bool ReferenceTypeAccessor::get_symmetric() const
{
  return described().symmetric().value_or(false);
}

void ReferenceTypeAccessor::set_symmetric(bool symmetric)
{
  write_attribute_sync(AttributeId::Symmetric, attribute_wire::symmetric(symmetric));
}

void ReferenceTypeAccessor::set_inverse_name(LocalizedText inverseName)
{
  write_attribute_sync(AttributeId::InverseName, attribute_wire::inverse_name(inverseName));
}

bool VariableAccessor::is_matching_class() const
{
  return is_variable();
}

NodeId VariableAccessor::get_data_type() const
{
  const NodeDescription nodeDescription = described();
  const NodeId* dataType = nodeDescription.data_type();
  return dataType != nullptr ? *dataType : NodeId{};
}

ValueRank VariableAccessor::get_value_rank() const
{
  return described().value_rank().value_or(ValueRank{-1});
}

optional<std::vector<uint32_t>> VariableAccessor::get_array_dimensions() const
{
  const NodeDescription nodeDescription = described();
  const auto* held = nodeDescription.array_dimensions();
  if (held == nullptr)
  {
    return std::nullopt;
  }
  return *held;
}

void VariableAccessor::set_data_type(NodeId dataType)
{
  write_attribute_sync(AttributeId::DataType, attribute_wire::data_type(dataType));
}

void VariableAccessor::set_value_rank(ValueRank valueRank)
{
  write_attribute_sync(AttributeId::ValueRank, attribute_wire::value_rank(valueRank));
}

void VariableAccessor::set_array_dimensions(optional<std::vector<uint32_t>> arrayDimensions)
{
  write_attribute_sync(AttributeId::ArrayDimensions, attribute_wire::array_dimensions(arrayDimensions));
}

AccessLevelType VariableAccessor::get_access_level() const
{
  return described().access_level().value_or(AccessLevelType{uint8_t{0}});
}

bool VariableAccessor::get_historizing() const
{
  // Historizing is a mandatory Variable attribute that defaults to false (Part 3 5.6.2).
  return described().historizing().value_or(false);
}

optional<Duration> VariableAccessor::get_minimum_sampling_interval() const
{
  return described().minimum_sampling_interval();
}

optional<AccessLevelExType> VariableAccessor::get_access_level_ex() const
{
  return described().access_level_ex();
}

void VariableAccessor::set_access_level(const AccessLevelType& accessLevel)
{
  write_attribute_sync(AttributeId::AccessLevel, attribute_wire::access_level(accessLevel));
}

void VariableAccessor::set_historizing(bool historizing)
{
  write_attribute_sync(AttributeId::Historizing, attribute_wire::historizing(historizing));
}

void VariableAccessor::set_minimum_sampling_interval(optional<Duration> minimumSamplingInterval)
{
  write_attribute_sync(
    AttributeId::MinimumSamplingInterval, attribute_wire::minimum_sampling_interval(minimumSamplingInterval));
}

void VariableAccessor::set_access_level_ex(optional<AccessLevelExType> accessLevelEx)
{
  write_attribute_sync(AttributeId::AccessLevelEx, attribute_wire::access_level_ex(accessLevelEx));
}

void VariableAccessor::read_value_async(Duration maxAge, bool setSourceTimestamp,
  const ReadValueId& nodeToRead, const CallerInfo* caller,
  NodeAccessor::ReadValueCompleteCallback callback) const noexcept
{
  detail::NodeAccessorRoute::read_value(
    *this, maxAge, setSourceTimestamp, nodeToRead, caller, std::move(callback));
}

DataValueResult VariableAccessor::try_read_value_sync() const noexcept
{
  try
  {
    ReadValueId readValueId;
    readValueId.node_id() = get_node_id();
    readValueId.attribute_id() = utils::to_underlying(AttributeId::Value);

    // Blocking external convenience with no Session in scope.
    return ua::async::detail::blocking_call<DataValueResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(DataValueResult)> complete)
      { read_value_async({}, true, readValueId, nullptr, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

DataValue VariableAccessor::read_value_sync() const
{
  return ua::detail::good_data_value(try_read_value_sync());
}

// --- write_value: WriteValue family (service-facing, callback-canonical) ---

void VariableAccessor::write_value_async(const WriteValue& nodeToWrite, const CallerInfo* caller,
  NodeAccessor::WriteValueCompleteCallback callback) noexcept
{
  detail::NodeAccessorRoute::write(*this, nodeToWrite, caller, std::move(callback));
}

VoidResult VariableAccessor::try_write_value_sync(WriteValue writeValue) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      {
        // Blocking external convenience with no Session in scope.
        write_value_async(writeValue, nullptr, std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void VariableAccessor::write_value_sync(WriteValue writeValue)
{
  try_write_value_sync(std::move(writeValue)).value();
}

// --- write_value: DataValue convenience family ---

void VariableAccessor::write_value_async(
  DataValue value, NodeAccessor::WriteValueCompleteCallback callback) noexcept
{
  WriteValue writeValue;
  try
  {
    // The getter throws for a Node its namespace has deleted; the write is answered with that status.
    writeValue.node_id() = get_node_id();
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value() = std::move(value);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      std::move(callback), VoidResult{ua::exception_to_status_code(std::current_exception())});
    return;
  }
  write_value_async(writeValue, nullptr, std::move(callback));
}

VoidResult VariableAccessor::try_write_value_sync(DataValue value) noexcept
{
  try
  {
    WriteValue writeValue;
    writeValue.node_id() = get_node_id();
    writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeValue.value() = std::move(value);
    return try_write_value_sync(std::move(writeValue));
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void VariableAccessor::write_value_sync(DataValue value)
{
  try_write_value_sync(std::move(value)).value();
}

bool VariableTypeAccessor::is_matching_class() const
{
  return is_variable_type();
}

NodeId VariableTypeAccessor::get_data_type() const
{
  const NodeDescription nodeDescription = described();
  const NodeId* dataType = nodeDescription.data_type();
  return dataType != nullptr ? *dataType : NodeId{};
}

ValueRank VariableTypeAccessor::get_value_rank() const
{
  return described().value_rank().value_or(ValueRank{-1});
}

optional<std::vector<uint32_t>> VariableTypeAccessor::get_array_dimensions() const
{
  const NodeDescription nodeDescription = described();
  const auto* held = nodeDescription.array_dimensions();
  if (held == nullptr)
  {
    return std::nullopt;
  }
  return *held;
}

void VariableTypeAccessor::set_data_type(NodeId dataType)
{
  write_attribute_sync(AttributeId::DataType, attribute_wire::data_type(dataType));
}

void VariableTypeAccessor::set_value_rank(ValueRank valueRank)
{
  write_attribute_sync(AttributeId::ValueRank, attribute_wire::value_rank(valueRank));
}

void VariableTypeAccessor::set_array_dimensions(optional<std::vector<uint32_t>> arrayDimensions)
{
  write_attribute_sync(AttributeId::ArrayDimensions, attribute_wire::array_dimensions(arrayDimensions));
}

bool VariableTypeAccessor::get_is_abstract() const
{
  return described().is_abstract().value_or(false);
}

void VariableTypeAccessor::set_is_abstract(bool isAbstract)
{
  write_attribute_sync(AttributeId::IsAbstract, attribute_wire::is_abstract(isAbstract));
}

optional<DataValue> VariableTypeAccessor::get_value() const
{
  const NodeDescription nodeDescription = described();
  const DataValue* held = nodeDescription.value();
  if (held == nullptr)
  {
    return std::nullopt;
  }
  return *held;
}

void VariableTypeAccessor::set_value(optional<DataValue> value)
{
  write_attribute_sync(AttributeId::Value, attribute_wire::variable_type_value(value));
}

template<>
void VariableTypeAccessor::set_value<DataValue>(DataValue value, optional<DateTime> sourceTimestamp)
{
  UA_UNUSED(value);
  UA_UNUSED(sourceTimestamp);
  throw UaException{Status::BadNotSupported,
    make_error_detail("AttributeNotSupported",
      "set_value<DataValue> is not supported on VariableTypeAccessor",
      "NodeAccessor")};
}

template<>
void VariableTypeAccessor::set_value<Variant>(Variant value, optional<DateTime> sourceTimestamp)
{
  DataValue dataValue;
  dataValue.value() = std::move(value);
  if (sourceTimestamp)
  {
    dataValue.source_timestamp() = sourceTimestamp;
  }

  write_attribute_sync(AttributeId::Value, Variant{std::move(dataValue)});
}

bool ObjectTypeAccessor::is_matching_class() const
{
  return is_object_type();
}

bool ObjectTypeAccessor::get_is_abstract() const
{
  return described().is_abstract().value_or(false);
}

void ObjectTypeAccessor::set_is_abstract(bool isAbstract)
{
  write_attribute_sync(AttributeId::IsAbstract, attribute_wire::is_abstract(isAbstract));
}

bool ViewAccessor::is_matching_class() const
{
  return is_view();
}

EventNotifierType ViewAccessor::get_event_notifier() const
{
  return described().event_notifier().value_or(EventNotifierType{uint8_t{0}});
}

void ViewAccessor::set_event_notifier(const EventNotifierType& eventNotifier)
{
  write_attribute_sync(AttributeId::EventNotifier, attribute_wire::event_notifier(eventNotifier));
}

bool ViewAccessor::get_contains_no_loops() const
{
  return described().contains_no_loops().value_or(false);
}

void ViewAccessor::set_contains_no_loops(bool containsNoLoops)
{
  write_attribute_sync(AttributeId::ContainsNoLoops, attribute_wire::contains_no_loops(containsNoLoops));
}

// --- is_node_in_view ---

void ViewAccessor::is_node_in_view_async(
  NodeId nodeId, NodeAccessor::IsNodeInViewCallback callback) const noexcept
{
  detail::NodeAccessorRoute::view_contains(*this, std::move(nodeId), std::move(callback));
}

BoolResult ViewAccessor::try_is_node_in_view_sync(const NodeId& nodeId) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(BoolResult)> complete) { is_node_in_view_async(nodeId, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

bool ViewAccessor::is_node_in_view_sync(const NodeId& nodeId) const
{
  return ua::detail::good_value(try_is_node_in_view_sync(nodeId));
}

// --- add_node_to_view ---

void ViewAccessor::add_node_to_view_async(NodeId nodeId, NodeAccessor::ViewModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::add_to_view(*this, std::move(nodeId), std::move(callback));
}

VoidResult ViewAccessor::try_add_node_to_view_sync(const NodeId& nodeId) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete) { add_node_to_view_async(nodeId, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void ViewAccessor::add_node_to_view_sync(const NodeId& nodeId)
{
  try_add_node_to_view_sync(nodeId).value();
}

const Node& NodeAccessor::node() const
{
  return *mNode;
}

Node& NodeAccessor::node()
{
  return *mNode;
}

NodeAccessor::NodeAccessor(shared_ptr<Node> node, WeakAddressSpace addressSpace)
  : mNode(std::move(node)), mAddressSpace(std::move(addressSpace))
{
  check(mNode);
}

// --- get_references: get all ---

void NodeAccessor::get_references_async(NodeAccessor::GetReferencesCallback callback) const noexcept
{
  detail::NodeAccessorRoute::read_all_references(*this, std::move(callback));
}

Result<References> NodeAccessor::try_get_references_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeAccessor::ReferencesResult>(
      detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(NodeAccessor::ReferencesResult)> complete)
      { get_references_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

References NodeAccessor::get_references_sync() const
{
  return ua::detail::good_value(try_get_references_sync());
}

// --- get_references: paginated ---

void NodeAccessor::get_references_async(uint32_t maxReferences, ByteString continuationToken,
  NodeAccessor::GetReferencesPageCallback callback) const noexcept
{
  detail::NodeAccessorRoute::read_references(
    *this, maxReferences, std::move(continuationToken), std::move(callback));
}

NodeAccessor::ReferencesPageResult NodeAccessor::try_get_references_sync(
  uint32_t maxReferences, ByteString continuationToken) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeAccessor::ReferencesPageResult>(
      detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(NodeAccessor::ReferencesPageResult)> complete)
      {
        get_references_async(maxReferences,
          std::move(continuationToken),

          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

NodeAccessor::ReferencePage NodeAccessor::get_references_sync(
  uint32_t maxReferences, ByteString continuationToken) const
{
  return ua::detail::good_value(try_get_references_sync(maxReferences, std::move(continuationToken)));
}

// --- get_components ---

void NodeAccessor::get_components_async(NodeAccessor::GetReferencesCallback callback) const noexcept
{
  try
  {
    get_references_async(
      [callback](NodeAccessor::ReferencesResult result) mutable
      {
        // The answer carries the References read's code: a Good subcode, or an Uncertain code with the
        // References it holds.
        if (!result.has_value())
        {
          callback(Result<References>{result.status_code(), result.shared_detail()});
          return;
        }
        const auto& refs = result.value();
        std::vector<Reference> components;
        for (const auto& ref : refs)
        {
          if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasComponent})
          {
            components.push_back(ref);
          }
        }
        callback(Result<References>{References{std::move(components)}, result.status_code()});
      });
  }
  catch (...)
  {
    // The noexcept facade must never let a synchronously-thrown exception escape. Convert it to
    // a Bad Result (the StatusCode carries the ErrorDetail) and deliver it through the
    // still-intact callback (captured by copy above).
    callback(Result<References>{ua::exception_to_status_code(std::current_exception())});
  }
}

Result<References> NodeAccessor::try_get_components_sync() const noexcept
{
  try
  {
    auto result = try_get_references_sync();
    if (!result.has_value())
    {
      return result;
    }

    const auto& refs = result.value();
    std::vector<Reference> components;
    for (const auto& ref : refs)
    {
      if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasComponent})
      {
        components.push_back(ref);
      }
    }

    return Result<References>{References{std::move(components)}, result.status_code()};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

References NodeAccessor::get_components_sync() const
{
  return ua::detail::good_value(try_get_components_sync());
}

// --- get_properties ---

void NodeAccessor::get_properties_async(NodeAccessor::GetReferencesCallback callback) const noexcept
{
  try
  {
    get_references_async(
      [callback](NodeAccessor::ReferencesResult result) mutable
      {
        // The answer carries the References read's code: a Good subcode, or an Uncertain code with the
        // References it holds.
        if (!result.has_value())
        {
          callback(Result<References>{result.status_code(), result.shared_detail()});
          return;
        }
        const auto& refs = result.value();
        std::vector<Reference> properties;
        for (const auto& ref : refs)
        {
          if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasProperty})
          {
            properties.push_back(ref);
          }
        }
        callback(Result<References>{References{std::move(properties)}, result.status_code()});
      });
  }
  catch (...)
  {
    // The noexcept facade must never let a synchronously-thrown exception escape. Convert it to
    // a Bad Result (the StatusCode carries the ErrorDetail) and deliver it through the
    // still-intact callback (captured by copy above).
    callback(Result<References>{ua::exception_to_status_code(std::current_exception())});
  }
}

Result<References> NodeAccessor::try_get_properties_sync() const noexcept
{
  try
  {
    auto result = try_get_references_sync();
    if (!result.has_value())
    {
      return result;
    }

    const auto& refs = result.value();
    std::vector<Reference> properties;
    for (const auto& ref : refs)
    {
      if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasProperty})
      {
        properties.push_back(ref);
      }
    }

    return Result<References>{References{std::move(properties)}, result.status_code()};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

References NodeAccessor::get_properties_sync() const
{
  return ua::detail::good_value(try_get_properties_sync());
}

// --- add_reference ---

void NodeAccessor::add_reference_async(NodeId type, ExpandedNodeId target, bool isForward,
  ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  change_one_reference(
    *this, std::move(type), std::move(target), isForward, true, halves, std::move(callback));
}

VoidResult NodeAccessor::try_add_reference_sync(
  const NodeId& type, const ExpandedNodeId& target, bool isForward, ReferenceHalves halves) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      { add_reference_async(type, target, isForward, halves, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::add_reference_sync(
  const NodeId& type, const ExpandedNodeId& target, bool isForward, ReferenceHalves halves)
{
  try_add_reference_sync(type, target, isForward, halves).value();
}

VoidResult NodeAccessor::try_add_reference_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves) noexcept
{
  return try_add_reference_sync(type, ExpandedNodeId{target}, isForward, halves);
}

void NodeAccessor::add_reference_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves)
{
  try_add_reference_sync(type, target, isForward, halves).value();
}

void NodeAccessor::add_reference_async(
  const Reference& reference, ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::change_references(
    *this, std::vector<Reference>{reference}, true, halves, std::move(callback));
}

void NodeAccessor::add_reference_sync(const Reference& reference, ReferenceHalves halves)
{
  try_add_reference_sync(reference, halves).value();
}

VoidResult NodeAccessor::try_add_reference_sync(const Reference& reference, ReferenceHalves halves) noexcept
{
  return try_add_references_sync(std::vector<Reference>{reference}, halves);
}

// --- add_references (batch) ---

void NodeAccessor::add_references_async(std::vector<Reference> references, ReferenceHalves halves,
  NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::change_references(
    *this, std::move(references), true, halves, std::move(callback));
}

VoidResult NodeAccessor::try_add_references_sync(
  std::vector<Reference> references, ReferenceHalves halves) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      { add_references_async(std::move(references), halves, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::add_references_sync(std::vector<Reference> references, ReferenceHalves halves)
{
  try_add_references_sync(std::move(references), halves).value();
}

// --- add_reference_if_not_present ---

namespace
{

/// Per-flow heap-state struct for add_reference_if_not_present_async.
///
/// Continuation chain:
///   start
///     -> on_references_fetched   (node->get_references_async)
///       if (already present): -> complete_add_ref_if_not_present
///       else                : -> on_reference_added (node->add_reference)
///                              -> complete_add_ref_if_not_present | fail_add_ref_if_not_present
///
/// Single-flight, self-owning via shared_from_this() captured in each callback.
class AddRefIfNotPresentFlow : public std::enable_shared_from_this<AddRefIfNotPresentFlow>
{
public:
  enum class Step
  {
    NotStarted,
    FetchingReferences,
    AddingReference,
    Done,
  };

  AddRefIfNotPresentFlow(NodeAccessor node, NodeId type, NodeId target, bool isForward,
    ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback onComplete,
    std::optional<WeakAddressSpace> requiredAddressSpace)
    : mNode(std::move(node)), mType(std::move(type)), mTarget(std::move(target)), mIsForward(isForward),
      mHalves(halves), mOnComplete(std::move(onComplete)),
      mRequiredAddressSpace(std::move(requiredAddressSpace))
  {}

  void start()
  {
    try
    {
      mStep = Step::FetchingReferences;
      // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
      detail::NodeAccessorRoute::read_all_references(
        mNode,
        [self = shared_from_this()](NodeAccessor::ReferencesResult result) mutable
        { self->on_references_fetched(std::move(result)); },
        mRequiredAddressSpace);
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail_add_ref_if_not_present(bad.status_code(), bad.shared_detail());
    }
  }

private:
  void on_references_fetched(NodeAccessor::ReferencesResult result)
  {
    if (mStep != Step::FetchingReferences)
    {
      fail_add_ref_if_not_present(StatusCode{Status::BadInternalError}, nullptr);
      return;
    }
    try
    {
      // The read decides whether to add, so an Uncertain answer is not acted on.
      if (!result.is_good())
      {
        const StatusCode refused = detail::references_failure(result.status_code(), "NodeAccessor");
        fail_add_ref_if_not_present(refused, refused.shared_detail());
        return;
      }
      const auto& collection = result.value();
      const Reference wanted{mType, ExpandedNodeId{mTarget}, mIsForward};
      auto test = [&wanted](const Reference& reference) -> bool
      {
        return wanted.identifies_same_reference_as(reference);
      };
      if (const auto held = std::ranges::find_if(collection, test); held != collection.end())
      {
        // Present only as the type asked for or a subtype of it; another type is refused, not passed off
        // as the Reference asked for.
        if (reference_identity::held_as_requested(wanted, *held))
        {
          complete_add_ref_if_not_present(VoidResult{});
          return;
        }
        const StatusCode refused = reference_identity::conflicting_type_refusal(wanted, *held);
        fail_add_ref_if_not_present(refused, refused.shared_detail());
        return;
      }

      // Read again after a refusal and still not held: the refusal is the answer, and nothing is added twice.
      if (mRefusal)
      {
        fail_add_ref_if_not_present(mRefusal->status_code(), mRefusal->shared_detail());
        return;
      }
      // An absent Reference requires a new mutation, unlike a terminal present/refused answer.
      // Keep this local lock through initiation only, never in the callback or flow state.
      std::optional<AddressSpace> addressSpace;
      if (mRequiredAddressSpace)
      {
        addressSpace = mRequiredAddressSpace->lock();
        if (!addressSpace)
        {
          const StatusCode ownerGone = detail::address_space_gone("NodeAccessor");
          fail_add_ref_if_not_present(ownerGone, ownerGone.shared_detail());
          return;
        }
      }
      mStep = Step::AddingReference;
      // Copied: a refusal reads the References again and compares them with the type and target.
      mNode.add_reference_async(mType,
        ExpandedNodeId{mTarget},
        mIsForward,
        mHalves,

        // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
        [self = shared_from_this()](VoidResult r) mutable { self->on_reference_added(std::move(r)); });
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail_add_ref_if_not_present(bad.status_code(), bad.shared_detail());
    }
  }

  void on_reference_added(VoidResult result)
  {
    if (mStep != Step::AddingReference)
    {
      fail_add_ref_if_not_present(StatusCode{Status::BadInternalError}, nullptr);
      return;
    }
    // Refused as a duplicate: added by someone else since the read. Read once more to tell whether it is
    // the Reference asked for.
    if (result.status_code().as_status() == Status::BadDuplicateReferenceNotAllowed && !mReread)
    {
      mReread = true;
      mRefusal = result;
      mStep = Step::FetchingReferences;
      // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
      detail::NodeAccessorRoute::read_all_references(
        mNode,
        [self = shared_from_this()](NodeAccessor::ReferencesResult answer) mutable
        { self->on_references_fetched(std::move(answer)); },
        mRequiredAddressSpace);
      return;
    }
    // The add's own answer is the answer, its code whatever it is, as the sync form answers it.
    complete_add_ref_if_not_present(std::move(result));
  }

  void complete_add_ref_if_not_present(VoidResult answer)
  {
    mStep = Step::Done;
    if (auto callback = std::exchange(mOnComplete, nullptr))
      detail::invoke_user_callback(callback, std::move(answer));
  }

  void fail_add_ref_if_not_present(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    mStep = Step::Done;
    if (auto callback = std::exchange(mOnComplete, nullptr))
      detail::invoke_user_callback(callback, VoidResult{status, std::move(detail)});
  }

  // Inputs.
  NodeAccessor mNode;
  NodeId mType;
  NodeId mTarget;
  bool mIsForward;
  ReferenceHalves mHalves;
  NodeAccessor::ReferenceModifyCallback mOnComplete;
  std::optional<WeakAddressSpace> mRequiredAddressSpace;

  // Mutable flow state.
  Step mStep{Step::NotStarted};
  bool mReread{false};
  std::optional<VoidResult> mRefusal;  // the duplicate refusal that started the second read
};

}  // namespace

void NodeAccessor::add_reference_if_not_present_async(NodeId type, NodeId target, bool isForward,
  ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::add_reference_if_not_present(
    *this, std::move(type), std::move(target), isForward, std::move(callback), std::nullopt, halves);
}

void detail::NodeAccessorRoute::add_reference_if_not_present(const NodeAccessor& accessor, NodeId type,
  NodeId target, bool isForward, NodeAccessor::ReferenceModifyCallback callback,
  std::optional<WeakAddressSpace> requiredAddressSpace, ReferenceHalves halves) noexcept
{
  try
  {
    // Copy into fallible setup so the entry retains its exception answer path.
    auto flow = std::make_shared<AddRefIfNotPresentFlow>(accessor,
      std::move(type),
      std::move(target),
      isForward,
      halves,
      callback,
      std::move(requiredAddressSpace));
    flow->start();
  }
  catch (...)
  {
    detail::invoke_user_callback(
      callback, VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

namespace
{

/// Per-flow heap-state struct for add_references_if_not_present_async (batch).
///
/// Continuation chain:
///   start
///     -> on_references_fetched   (node->get_references_async)
///        filter the batch against existing refs + within-batch duplicates
///        if (nothing new): -> complete
///        else            : -> node->add_references -> on_references_added -> complete | fail
///
/// Reads existing references once and writes the de-duplicated batch once - the whole point is to
/// avoid the per-reference vector clone of repeated add_reference calls. Single-flight, self-owning.
class AddRefsIfNotPresentFlow : public std::enable_shared_from_this<AddRefsIfNotPresentFlow>
{
public:
  enum class Step
  {
    NotStarted,
    FetchingReferences,
    AddingReferences,
    Done,
  };

  AddRefsIfNotPresentFlow(NodeAccessor node, std::vector<Reference> references, ReferenceHalves halves,
    NodeAccessor::ReferenceModifyCallback onComplete)
    : mNode(std::move(node)), mReferences(std::move(references)), mHalves(halves),
      mOnComplete(std::move(onComplete))
  {}

  void start()
  {
    try
    {
      if (mReferences.empty())
      {
        complete();
        return;
      }
      mStep = Step::FetchingReferences;
      // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
      mNode.get_references_async([self = shared_from_this()](NodeAccessor::ReferencesResult r) mutable
        { self->on_references_fetched(std::move(r)); });
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

private:
  void on_references_fetched(NodeAccessor::ReferencesResult result)
  {
    if (mStep != Step::FetchingReferences)
    {
      fail(StatusCode{Status::BadInternalError}, nullptr);
      return;
    }
    try
    {
      // The read decides what to add, so an Uncertain answer is not acted on.
      if (!result.is_good())
      {
        const StatusCode refused = detail::references_failure(result.status_code(), "NodeAccessor");
        fail(refused, refused.shared_detail());
        return;
      }
      const auto& existing = result.value();

      // Keep only references the node does not hold, one per group the batch repeats, as Part 3 4.3.4
      // identifies References; a group that cannot be held as asked (a type neither a subtype nor a supertype
      // of another's) is refused, and nothing is added. The batch is read, not moved: a refusal filters it
      // again.
      auto decided = reference_identity::references_to_add(existing.span(), mReferences);
      if (!decided.is_good())
      {
        fail(decided.status_code(), decided.shared_detail());
        return;
      }
      std::vector<Reference> toAdd = std::move(decided).value();

      if (toAdd.empty())
      {
        complete();
        return;
      }
      // Filtered again after a refusal and nothing more is held: the refusal is not a concurrent add.
      if (mRefusal && toAdd.size() >= mLastAttemptSize)
      {
        fail(mRefusal->status_code(), mRefusal->shared_detail());
        return;
      }
      mLastAttemptSize = toAdd.size();

      mStep = Step::AddingReferences;
      mNode.add_references_async(std::move(toAdd),
        mHalves,
        // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
        [self = shared_from_this()](VoidResult r) mutable { self->on_references_added(std::move(r)); });
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void on_references_added(VoidResult result)
  {
    if (mStep != Step::AddingReferences)
    {
      fail(StatusCode{Status::BadInternalError}, nullptr);
      return;
    }
    // Some of them added by someone else since the read. Each Reference is answered alone, so the others may
    // be stored: the Node is read again and what it does not hold is offered again, for as long as each
    // refusal leaves less to add.
    if (result.status_code().as_status() == Status::BadDuplicateReferenceNotAllowed)
    {
      mRefusal = std::move(result);
      mStep = Step::FetchingReferences;
      // nosemgrep: lambda-captures-shared-from-this (self-owned one-shot flow)
      mNode.get_references_async([self = shared_from_this()](NodeAccessor::ReferencesResult r) mutable
        { self->on_references_fetched(std::move(r)); });
      return;
    }
    // The add's own answer is the answer, its code whatever it is.
    complete(std::move(result));
  }

  void complete(VoidResult answer = VoidResult{})
  {
    auto cb = std::move(mOnComplete);
    mStep = Step::Done;
    cb(std::move(answer));
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    auto cb = std::move(mOnComplete);
    mStep = Step::Done;
    cb(VoidResult{status, std::move(detail)});
  }

  // Inputs.
  NodeAccessor mNode;
  std::vector<Reference> mReferences;
  ReferenceHalves mHalves;
  NodeAccessor::ReferenceModifyCallback mOnComplete;

  // Mutable flow state.
  Step mStep{Step::NotStarted};
  std::optional<VoidResult> mRefusal;
  std::size_t mLastAttemptSize{0};
};

}  // namespace

void NodeAccessor::add_references_if_not_present_async(std::vector<Reference> references,
  ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  auto flow =
    std::make_shared<AddRefsIfNotPresentFlow>(*this, std::move(references), halves, std::move(callback));
  flow->start();
}

VoidResult NodeAccessor::try_add_reference_if_not_present_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves) noexcept
{
  try
  {
    auto collection = try_get_references_sync();
    // The read decides whether to add, so an Uncertain answer is not acted on.
    if (!collection.is_good())
    {
      return VoidResult{detail::references_failure(collection.status_code(), "NodeAccessor")};
    }

    const Reference wanted{type, ExpandedNodeId{target}, isForward};
    auto test = [&wanted](const Reference& reference) -> bool
    {
      return wanted.identifies_same_reference_as(reference);
    };

    const auto held = std::ranges::find_if(collection.value(), test);
    if (held == collection.value().end())
    {
      auto added = try_add_reference_sync(type, target, isForward, halves);
      // Refused as a duplicate: added by someone else since the read. Read once more to tell which.
      if (added.status_code().as_status() == Status::BadDuplicateReferenceNotAllowed)
      {
        auto again = try_get_references_sync();
        if (again.is_good())
        {
          const auto heldNow = std::ranges::find_if(again.value(), test);
          if (heldNow != again.value().end())
          {
            return reference_identity::held_as_requested(wanted, *heldNow)
                     ? VoidResult{}
                     : VoidResult{reference_identity::conflicting_type_refusal(wanted, *heldNow)};
          }
        }
      }
      return added;
    }
    // Present only as the type asked for or a subtype of it.
    if (reference_identity::held_as_requested(wanted, *held))
    {
      return VoidResult{};
    }
    return VoidResult{reference_identity::conflicting_type_refusal(wanted, *held)};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::add_reference_if_not_present_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves)
{
  try_add_reference_if_not_present_sync(type, target, isForward, halves).value();
}

// --- remove_reference ---

void NodeAccessor::remove_reference_async(NodeId type, ExpandedNodeId target, bool isForward,
  ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  change_one_reference(
    *this, std::move(type), std::move(target), isForward, false, halves, std::move(callback));
}

VoidResult NodeAccessor::try_remove_reference_sync(
  const NodeId& type, const ExpandedNodeId& target, bool isForward, ReferenceHalves halves) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      { remove_reference_async(type, target, isForward, halves, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::remove_reference_sync(
  const NodeId& type, const ExpandedNodeId& target, bool isForward, ReferenceHalves halves)
{
  try_remove_reference_sync(type, target, isForward, halves).value();
}

VoidResult NodeAccessor::try_remove_reference_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves) noexcept
{
  return try_remove_reference_sync(type, ExpandedNodeId{target}, isForward, halves);
}

void NodeAccessor::remove_reference_sync(
  const NodeId& type, const NodeId& target, bool isForward, ReferenceHalves halves)
{
  try_remove_reference_sync(type, target, isForward, halves).value();
}

void NodeAccessor::remove_reference_async(
  const Reference& reference, ReferenceHalves halves, NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::change_references(
    *this, std::vector<Reference>{reference}, false, halves, std::move(callback));
}

void NodeAccessor::remove_reference_sync(const Reference& reference, ReferenceHalves halves)
{
  try_remove_reference_sync(reference, halves).value();
}

VoidResult NodeAccessor::try_remove_reference_sync(
  const Reference& reference, ReferenceHalves halves) noexcept
{
  return try_remove_reference_sync(
    reference.type_id(), reference.target_id(), reference.is_forward(), halves);
}

// --- remove_references (batch) ---

void NodeAccessor::remove_references_async(std::vector<Reference> references, ReferenceHalves halves,
  NodeAccessor::ReferenceModifyCallback callback) noexcept
{
  detail::NodeAccessorRoute::change_references(
    *this, std::move(references), false, halves, std::move(callback));
}

VoidResult NodeAccessor::try_remove_references_sync(
  std::vector<Reference> references, ReferenceHalves halves) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(detail::NodeAccessorRoute::executor(*this),
      [&](std::function<void(VoidResult)> complete)
      { remove_references_async(std::move(references), halves, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void NodeAccessor::remove_references_sync(std::vector<Reference> references, ReferenceHalves halves)
{
  try_remove_references_sync(std::move(references), halves).value();
}

}  // namespace ua
