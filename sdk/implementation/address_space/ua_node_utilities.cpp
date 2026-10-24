// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_node_utilities.h"
#include "ua_namespace_batch_support.h"

#include "ua_attribute_wire.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_weak_address_space.h"

#include "ua_self_owning_operation.h"

#include <boost/asio/strand.hpp>
#include "ua_access_level_type.h"
#include "ua_data_value.h"
#include "ua_access_level_ex_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_event_notifier_type.h"
#include "ua_data_type_definition.h"
#include "ua_enum_definition.h"
#include "ua_error_detail.h"
#include "ua_reference.h"
#include "ua_on_strand.h"
#include "ua_address_space.h"
#include "ua_structure_definition.h"
#include "ua_application_configuration.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>

namespace ua
{

namespace node_utils
{

namespace
{
}  // namespace

DataValue read_node_sync_attribute(const NodeAccessor& node, AttributeId id, TimestampsToReturn timestamps,
  span<const LocaleId> locales, const LocaleId& defaultLocale)
{
  DataValue result;

  switch (id)
  {
  case AttributeId::NodeId:
    result.value() = node.get_node_id();
    break;

  case AttributeId::NodeClass:
    result.value() = utils::as_int32(node.get_node_class());
    break;

  case AttributeId::BrowseName:
  {
    // An absent BrowseName is a malformed node, not a readable empty value. Report it the way the
    // DisplayName case below already reports its own absence, so the two cannot drift apart.
    auto stored = node.read_attribute(AttributeId::BrowseName);
    if (!stored.empty() && stored.is_qualified_name())
    {
      result.value() = std::move(stored);
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
  }
  break;

  case AttributeId::DisplayName:
  {
    auto stored = node.read_attribute(AttributeId::DisplayName);
    if (!stored.empty() && stored.is_localized_text())
    {
      // The resolved value may be an empty scalar (e.g. after spec
      // 5.10.4 "delete all" upsert). That is still a valid readable
      // value - the attribute is set but empty. Writing it into the
      // variant ensures the read returns Good + empty LT rather than
      // BadAttributeIdInvalid.
      result.value() = stored.as<LocalizedText>().resolve(locales, defaultLocale);
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
  }
  break;

  case AttributeId::Description:
  {
    auto stored = node.read_attribute(AttributeId::Description);
    if (!stored.empty() && stored.is_localized_text())
    {
      result.value() = stored.as<LocalizedText>().resolve(locales, defaultLocale);
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
  }
  break;

  case AttributeId::WriteMask:
  {
    // WriteMask is a mandatory UInt32 attribute on every node (OPC 10000-3 5.2.7). When the node
    // carries no explicit write mask it defaults to 0 (no attribute is writable via node
    // management); returning BadAttributeIdInvalid would wrongly claim the attribute is absent.
    if (auto writeMask = node.get_write_mask())
    {
      result.value() = writeMask.value().as_underlying_type();
    }
    else
    {
      result.value() = uint32_t{0};
    }
  }
  break;

  case AttributeId::IsAbstract:
    if (auto type = node.as<NodeAccessor>())  // Any type is still NodeAccessor, but we need specialized check
    {
      if (auto dataType = node.as<DataTypeAccessor>())
      {
        result.value() = dataType->get_is_abstract();
      }
      else if (auto objectType = node.as<ObjectTypeAccessor>())
      {
        result.value() = objectType->get_is_abstract();
      }
      else if (auto variableType = node.as<VariableTypeAccessor>())
      {
        result.value() = variableType->get_is_abstract();
      }
      else if (auto referenceType = node.as<ReferenceTypeAccessor>())
      {
        result.value() = referenceType->get_is_abstract();
      }
      else
      {
        result.status() = Status::BadAttributeIdInvalid;
      }
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::Symmetric:
    if (auto referenceType = node.as<ReferenceTypeAccessor>())
    {
      result.value() = referenceType->get_symmetric();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::InverseName:
    if (node.as<ReferenceTypeAccessor>())
    {
      auto stored = node.read_attribute(AttributeId::InverseName);
      if (!stored.empty() && stored.is_localized_text())
      {
        result.value() = stored.as<LocalizedText>().resolve(locales, defaultLocale);
      }
      else
      {
        result.status() = Status::BadAttributeIdInvalid;
      }
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::ContainsNoLoops:
    if (auto view = node.as<ViewAccessor>())
    {
      result.value() = view->get_contains_no_loops();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::EventNotifier:
    if (auto view = node.as<ViewAccessor>())
    {
      result.value() = view->get_event_notifier().as_underlying_type();
    }
    else if (auto object = node.as<ObjectAccessor>())
    {
      result.value() = object->get_event_notifier().as_underlying_type();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  // Value is deliberately handled for VariableType ONLY. A VariableType holds a
  // *static default* Value as a stored attribute. A Variable's *live* value is
  // dynamic / possibly externally-sourced and is NOT a stored attribute -- it is
  // read through the namespace's read_values_async (DataValue), never through this sync attribute
  // path. Hence there is intentionally no VariableAccessor branch (unlike DataType /
  // ValueRank below); a Variable falls through to BadAttributeIdInvalid.
  case AttributeId::Value:
    if (auto variableType = node.as<VariableTypeAccessor>())
    {
      // A Value written as null is held as a null value and read as one; only a VariableType that holds
      // no Value at all lacks the Attribute.
      if (auto value = variableType->get_value())
      {
        result.value() = std::move(value->value());
        break;
      }
    }
    result.status() = Status::BadAttributeIdInvalid;
    break;

  case AttributeId::DataType:
    if (auto variableType = node.as<VariableTypeAccessor>())
    {
      result.value() = variableType->get_data_type();
    }
    else if (auto variable = node.as<VariableAccessor>())
    {
      result.value() = variable->get_data_type();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::ValueRank:
    if (auto variableType = node.as<VariableTypeAccessor>())
    {
      result.value() = variableType->get_value_rank().as_int32();
    }
    else if (auto variable = node.as<VariableAccessor>())
    {
      result.value() = variable->get_value_rank().as_int32();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::ArrayDimensions:
    if (auto variableType = node.as<VariableTypeAccessor>())
    {
      auto arrayDimensions = variableType->get_array_dimensions();
      if (arrayDimensions)
      {
        result.value() = Array<uint32_t>{Dimensions{}, arrayDimensions.value()};
      }
    }
    else if (auto variable = node.as<VariableAccessor>())
    {
      auto arrayDimensions = variable->get_array_dimensions();
      if (arrayDimensions)
      {
        result.value() = Array<uint32_t>{Dimensions{}, arrayDimensions.value()};
      }
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::AccessLevel:
    if (auto variable = node.as<VariableAccessor>())
    {
      result.value() = variable->get_access_level().as_underlying_type();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::MinimumSamplingInterval:
    if (auto variable = node.as<VariableAccessor>())
    {
      auto msi = variable->get_minimum_sampling_interval();
      if (msi)
      {
        result.value() = msi.value();
      }
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::Historizing:
    if (auto variable = node.as<VariableAccessor>())
    {
      result.value() = variable->get_historizing();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::Executable:
    if (auto method = node.as<MethodAccessor>())
    {
      result.value() = method->get_executable();
    }
    else
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::DataTypeDefinition:
    if (auto dataType = node.as<DataTypeAccessor>())
    {
      auto stored = dataType->get_data_type_definition();
      if (stored)
      {
        // Clone the stored definition (an immutable shared snapshot)
        // and resolve its LocalizedText fields against the session
        // locales. The generated `resolve` override walks nested
        // `StructureField` / `EnumField` entries so that each
        // aggregate collapses to the requested locale.
        auto cloned = stored->clone();
        // Build a combined locale list with the server default appended,
        // matching the fallback order of LocalizedText::resolve(locales, defaultLocale):
        // session locales first, then server default, then first-inserted.
        if (!defaultLocale.empty())
        {
          std::vector<LocaleId> combined(locales.begin(), locales.end());
          combined.push_back(defaultLocale);
          cloned->resolve(combined);
        }
        else
        {
          cloned->resolve(locales);
        }
        result.value() = std::move(cloned);
      }
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  case AttributeId::RolePermissions:
  {
    auto rolePermissions = node.get_role_permissions();
    if (rolePermissions)
    {
      result.value() = array_utils::copy_to_array_of_references(rolePermissions.value());
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
  }
  break;

  case AttributeId::AccessRestrictions:
  {
    auto accessRestrictions = node.get_access_restrictions();
    if (accessRestrictions)
    {
      result.value() = accessRestrictions.value().as_underlying_type();
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
  }
  break;

  case AttributeId::AccessLevelEx:
    if (auto variable = node.as<VariableAccessor>())
    {
      auto accessLevelEx = variable->get_access_level_ex();
      if (accessLevelEx)
      {
        result.value() = accessLevelEx.value().as_underlying_type();
      }
    }
    if (result.value().empty())
    {
      result.status() = Status::BadAttributeIdInvalid;
    }
    break;

  default:
    result.status() = Status::BadAttributeIdInvalid;
    break;
  }

  if (server_timestamp(timestamps))
  {
    result.server_timestamp() = DateTime::now();
  }

  return result;
}

namespace
{

StatusCode not_valid_for_node_class(const NodeId& nodeId, std::string_view attribute)
{
  return StatusCode{Status::BadAttributeIdInvalid,
    ErrorDetail::build(
      "InvalidAttributeId", std::string{attribute} + " is not valid for this node class", "NodeUtilities")
      .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))};
}

// ArrayDimensions as written: null, or a one-dimensional array of UInt32. An empty array means the same as
// null (Part 6 5.1.9) and is held as null.
Result<Variant> array_dimensions_value(const NodeId& nodeId, const Variant& value)
{
  if (value.empty())
  {
    return attribute_wire::array_dimensions(std::nullopt);
  }
  const auto& dimensions = value.is_array() ? value.get_array_base().dimensions() : std::nullopt;
  if (!value.is_array_of_uint32() || (dimensions.has_value() && dimensions->size() > 1))
  {
    return StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build(
        "TypeMismatch", "ArrayDimensions is written as a one-dimensional array of UInt32", "NodeUtilities")
        .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))};
  }
  const auto& entries = value.as<Array<uint32_t>>().payload();
  if (entries.empty())
  {
    return attribute_wire::array_dimensions(std::nullopt);
  }
  return attribute_wire::array_dimensions(std::vector<uint32_t>{entries.begin(), entries.end()});
}

// A LocalizedText Attribute value as written: an empty Variant is the null LocalizedText - null locale and
// null text - which Part 4 5.10.4.1 says deletes the entries for all locales. Any other type is
// Bad_TypeMismatch (5.10.4.2), thrown so the caller's handler refuses the write.
LocalizedText localized_text(const Variant& value)
{
  if (value.empty())
    return LocalizedText{};
  return value.to<LocalizedText>().value();
}

}  // namespace

Result<Variant> encode_writable_attribute_of_class(
  NodeClass nodeClass, const NodeId& nodeId, AttributeId id, const Variant& value) noexcept
{
  try
  {
    switch (id)
    {
    case AttributeId::BrowseName:
      return attribute_wire::browse_name(value.to<QualifiedName>().value());
    case AttributeId::DisplayName:
      return attribute_wire::display_name(localized_text(value));
    case AttributeId::Description:
      return attribute_wire::description(localized_text(value));
    case AttributeId::WriteMask:
      return attribute_wire::write_mask(AttributeWriteMask{value.to<uint32_t>().value()});
    case AttributeId::IsAbstract:
      if (nodeClass == NodeClass::DataType || nodeClass == NodeClass::ObjectType ||
          nodeClass == NodeClass::VariableType || nodeClass == NodeClass::ReferenceType)
      {
        return attribute_wire::is_abstract(value.to<bool>().value());
      }
      return not_valid_for_node_class(nodeId, "IsAbstract");
    case AttributeId::Symmetric:
      if (nodeClass == NodeClass::ReferenceType)
      {
        return attribute_wire::symmetric(value.to<bool>().value());
      }
      return not_valid_for_node_class(nodeId, "Symmetric");
    case AttributeId::InverseName:
      if (nodeClass == NodeClass::ReferenceType)
      {
        return attribute_wire::inverse_name(localized_text(value));
      }
      return not_valid_for_node_class(nodeId, "InverseName");
    case AttributeId::ContainsNoLoops:
      if (nodeClass == NodeClass::View)
      {
        return attribute_wire::contains_no_loops(value.to<bool>().value());
      }
      return not_valid_for_node_class(nodeId, "ContainsNoLoops");
    case AttributeId::EventNotifier:
      if (nodeClass == NodeClass::View || nodeClass == NodeClass::Object)
      {
        return attribute_wire::event_notifier(EventNotifierType{value.to<uint8_t>().value()});
      }
      return not_valid_for_node_class(nodeId, "EventNotifier");
    case AttributeId::DataType:
      if (nodeClass == NodeClass::VariableType || nodeClass == NodeClass::Variable)
      {
        return attribute_wire::data_type(value.to<NodeId>().value());
      }
      return not_valid_for_node_class(nodeId, "DataType");
    case AttributeId::ValueRank:
      if (nodeClass == NodeClass::VariableType || nodeClass == NodeClass::Variable)
      {
        return attribute_wire::value_rank(ValueRank{value.to<int32_t>().value()});
      }
      return not_valid_for_node_class(nodeId, "ValueRank");
    case AttributeId::AccessLevel:
      if (nodeClass == NodeClass::Variable)
      {
        return attribute_wire::access_level(AccessLevelType{value.to<uint8_t>().value()});
      }
      return not_valid_for_node_class(nodeId, "AccessLevel");
    case AttributeId::MinimumSamplingInterval:
      if (nodeClass == NodeClass::Variable)
      {
        return attribute_wire::minimum_sampling_interval(value.to<double>().value());
      }
      return not_valid_for_node_class(nodeId, "MinimumSamplingInterval");
    case AttributeId::Historizing:
      if (nodeClass == NodeClass::Variable)
      {
        return attribute_wire::historizing(value.to<bool>().value());
      }
      return not_valid_for_node_class(nodeId, "Historizing");
    case AttributeId::Executable:
      if (nodeClass == NodeClass::Method)
      {
        return attribute_wire::executable(value.to<bool>().value());
      }
      return not_valid_for_node_class(nodeId, "Executable");

    case AttributeId::ArrayDimensions:
      if (nodeClass == NodeClass::Variable || nodeClass == NodeClass::VariableType)
      {
        return array_dimensions_value(nodeId, value);
      }
      return not_valid_for_node_class(nodeId, "ArrayDimensions");

    // A VariableType's Value is part of the type's description and is written through this path. A
    // Variable's live value is not: it is written through Node::write_value, and reaching here with it is
    // a wiring mistake.
    case AttributeId::Value:
      if (nodeClass == NodeClass::VariableType)
      {
        // A null Value is held as a null value: the Attribute stays, and a Read returns the null.
        return attribute_wire::variable_type_value(DataValue{value});
      }
      return StatusCode{Status::BadAttributeIdInvalid,
        ErrorDetail::build("ValueNotWritableViaAttributePath",
          "A Variable's Value is not written through the attribute path; it is written through "
          "Node::write_value",
          "NodeUtilities")
          .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))};

    default:
      return StatusCode{Status::BadAttributeIdInvalid,
        ErrorDetail::build("InvalidAttributeId", "Attribute is not writable", "NodeUtilities")
          .context(ua::ContextKeys::nodeAttribute, std::to_string(utils::to_underlying(id)))};
    }
  }
  catch (...)
  {
    // A value of the wrong type for the attribute (Bad_TypeMismatch from Variant::to): refused, not thrown.
    return ua::exception_to_status_code(std::current_exception());
  }
}

Result<Variant> encode_writable_attribute(
  const NodeAccessor& node, AttributeId id, const Variant& value) noexcept
{
  try
  {
    const NodeDescription nodeDescription = node->attributes();
    return encode_writable_attribute_of_class(
      nodeDescription.node_class(), nodeDescription.node_id(), id, value);
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void write_node_sync_attribute(NodeAccessor& node, AttributeId id, const Variant& value)
{
  auto encoded = encode_writable_attribute(node, id, value);
  node.write_attribute_sync(id, std::move(encoded).value());  // throws the refusal if bad
}

void write_node_attribute_async(
  NodeAccessor node, AttributeId id, const Variant& value, std::function<void(VoidResult)> callback) noexcept
{
  auto encoded = encode_writable_attribute(node, id, value);
  if (!encoded.is_good())
  {
    callback(VoidResult{encoded.status_code(), encoded.shared_detail()});
    return;
  }
  node.write_attribute_async(id, std::move(encoded).value(), std::move(callback));
}

bool source_timestamp(TimestampsToReturn timestamps)
{
  return ((timestamps == TimestampsToReturn::Source) || (timestamps == TimestampsToReturn::Both));
}

bool server_timestamp(TimestampsToReturn timestamps)
{
  return ((timestamps == TimestampsToReturn::Server) || (timestamps == TimestampsToReturn::Both));
}

ExpandedNodeId get_type_definition_id(const NodeAccessor& node)
{
  auto references = node.get_references_sync();
  for (const auto& reference : references)
  {
    if ((reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition}) && reference.is_forward())
    {
      return reference.target_id();
    }
  }

  return ExpandedNodeId{};
}

ExpandedNodeId get_super_type_id(const NodeAccessor& node)
{
  if (!node.is_type())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidNodeClass", "Node is not a type node", "NodeUtilities")
        .context(ua::ContextKeys::nodeId, ua::to_string(node.get_node_id()))};
  }

  auto references = node.get_references_sync();
  for (const auto& reference : references)
  {
    if ((reference.type_id() == NodeId{ReferenceTypeId::HasSubtype}) && !reference.is_forward())
    {
      return reference.target_id();
    }
  }

  throw UaException{Status::BadNotFound,
    ErrorDetail::build(
      "ReferenceNotFound", "Node has no HasSubtype inverse reference (no super type)", "NodeUtilities")
      .context(ua::ContextKeys::nodeId, ua::to_string(node.get_node_id()))};
}

namespace
{

/// The first reference on @p references of @p referenceType in the given direction, or nullopt.
std::optional<ExpandedNodeId> first_reference_target(
  const References& references, const NodeId& referenceType, bool forward)
{
  for (const auto& reference : references)
  {
    if (reference.type_id() == referenceType && reference.is_forward() == forward)
    {
      return reference.target_id();
    }
  }
  return std::nullopt;
}

}  // namespace

void get_super_type_async(
  AddressSpace addressSpace, NodeAccessor type, std::function<void(OptionalNodeAccessorResult)> callback)
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    // A node that is not a type has no supertype: the walk ends without reading References.
    if (!type.is_type())
    {
      detail::invoke_user_callback(
        logger, callback, OptionalNodeAccessorResult{optional<NodeAccessor>{std::nullopt}});
      return;
    }

    const auto weakSpace = addressSpace.weak();
    // Copy the completion into fallible setup so the entry catch retains its answer path.
    detail::NodeAccessorRoute::read_all_references(
      type,
      [weakSpace, logger, callback](NodeAccessor::ReferencesResult references) mutable
      {
        try
        {
          // The answer carries the References read's code and the lookup's, combined as and_then combines two
          // steps: a Good subcode, or an Uncertain code with the data it held, reaches the caller.
          if (!references.has_value())
          {
            detail::invoke_user_callback(
              logger, callback, OptionalNodeAccessorResult{references.status_code()});
            return;
          }
          const StatusCode referencesCode = references.status_code();
          const auto superTypeId = first_reference_target(
            references.value(), NodeId{ReferenceTypeId::HasSubtype}, /*forward=*/false);
          if (!superTypeId)
          {
            detail::invoke_user_callback(logger,
              callback,
              OptionalNodeAccessorResult{optional<NodeAccessor>{std::nullopt}, referencesCode});
            return;
          }
          if (superTypeId->is_remote())
          {
            detail::invoke_user_callback(logger,
              callback,
              OptionalNodeAccessorResult{Status::BadInvalidArgument,
                ErrorDetail::build("InvalidNodeClass",
                  "Super type node is remote and cannot be resolved locally",
                  "NodeUtilities")
                  .context(ua::ContextKeys::nodeId, ua::to_string(*superTypeId))});
            return;
          }
          auto lockedSpace = weakSpace.lock();
          if (!lockedSpace)
          {
            detail::invoke_user_callback(
              logger, callback, OptionalNodeAccessorResult{detail::address_space_gone("NodeUtilities")});
            return;
          }
          lockedSpace->find_node_async(superTypeId->node_id(),
            [logger, callback, referencesCode](NodeAccessorResult result) mutable
            {
              auto answer = ua::detail::carried(std::move(result), referencesCode);
              if (answer.has_value())
              {
                const StatusCode answered = answer.status_code();
                detail::invoke_user_callback(logger,
                  callback,
                  OptionalNodeAccessorResult{optional<NodeAccessor>{std::move(answer).value()}, answered});
                return;
              }
              // A refused parent lookup is not a type without a supertype.
              detail::invoke_user_callback(
                logger, callback, OptionalNodeAccessorResult{answer.status_code()});
            });
        }
        catch (...)
        {
          detail::invoke_user_callback(logger,
            callback,
            OptionalNodeAccessorResult{ua::exception_to_status_code(std::current_exception())});
        }
      },
      weakSpace);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      logger, callback, OptionalNodeAccessorResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void get_type_definition_async(const NodeAccessor& node, std::function<void(ExpandedNodeIdResult)> callback)
{
  node.get_references_async(
    [callback = std::move(callback)](NodeAccessor::ReferencesResult references) mutable
    {
      // The answer carries the References read's code: a Good subcode, or an Uncertain code with the
      // References it held.
      if (!references.has_value())
      {
        callback(ExpandedNodeIdResult{references.status_code(), references.shared_detail()});
        return;
      }
      const auto typeDefinition = first_reference_target(
        references.value(), NodeId{ReferenceTypeId::HasTypeDefinition}, /*forward=*/true);
      callback(ExpandedNodeIdResult{typeDefinition.value_or(ExpandedNodeId{}), references.status_code()});
    });
}

namespace
{

/// The type-hierarchy walk behind `is_ref_of_type_async`, as one body.
///
/// A free function's operation has no component to hold its task, so it is owned by the work
/// outstanding on it - which is what the callback chain this replaces did too, through the strong
/// `shared_from_this()` its every step carried. @see ua::async::SelfOwningOperation
class IsRefOfTypeOperation final : public ua::async::SelfOwningOperation<IsRefOfTypeOperation>
{
public:
  IsRefOfTypeOperation(EncodingLimits limits, AddressSpace addressSpace, NodeId refTypeId, NodeId typeId,
    std::function<void(BoolResult)> onComplete)
    : ua::async::SelfOwningOperation<IsRefOfTypeOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mRefTypeId(std::move(refTypeId)), mTypeId(std::move(typeId)),
      mLoopLimit(limits.execution.loopLimit), mOnComplete(std::move(onComplete))
  {}

  static void start(EncodingLimits limits, AddressSpace addressSpace, NodeId refTypeId, NodeId typeId,
    std::function<void(BoolResult)> onComplete)
  {
    launch(std::make_shared<IsRefOfTypeOperation>(
      limits, std::move(addressSpace), std::move(refTypeId), std::move(typeId), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<IsRefOfTypeOperation>;

  ua::async::Task<> run()
  {
    // A ROOT task: nobody awaits it, so an exception that escaped would be stored in a promise
    // nobody reads and the caller would never be answered at all.
    try
    {
      auto found = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(mRefTypeId, std::move(completion));
          else
            completion(NodeAccessorResult{detail::address_space_gone("NodeUtilities")});
        });

      if (!found.is_good())
      {
        if (found.status_code() == StatusCode{Status::BadNodeIdUnknown})
        {
          // A genuinely absent initial ReferenceType is not a match, as for selective imports.
          complete(BoolResult{false});
        }
        else
        {
          complete(BoolResult{detail::lookup_failure(mRefTypeId, found.status_code(), "NodeUtilities")});
        }
        co_return;
      }

      // The walk is a LOOP now, where it was a handler calling itself back through the executor.
      // `await_step` posts each answer, so the bound the old `post_owning` gave - a fresh stack per
      // step, and the strand handed back between them - is the same (R18).
      NodeAccessor current = found.value();
      while (true)
      {
        // Throws when the configured iteration budget is exhausted; the catch below answers with it.
        mLoopLimit.consume_iteration();

        bool supertypeInitiated{false};
        auto superResult = co_await await_step<OptionalNodeAccessorResult>(
          [this, &current, &supertypeInitiated](auto completion)
          {
            if (!current.is_type())
            {
              completion(OptionalNodeAccessorResult{optional<NodeAccessor>{std::nullopt}});
              return;
            }
            if (auto addressSpace = mAddressSpace.lock())
            {
              supertypeInitiated = true;
              get_super_type_async(*addressSpace, current, std::move(completion));
            }
            else
            {
              completion(OptionalNodeAccessorResult{detail::address_space_gone("NodeUtilities")});
            }
          });

        if (!superResult.is_good())
        {
          if (!supertypeInitiated)
          {
            complete(BoolResult{superResult.status_code()});
            co_return;
          }
          // The walk decides a rule, so it does not act on a supertype the namespace is uncertain of.
          if (superResult.is_uncertain())
          {
            complete(BoolResult{
              detail::lookup_failure(current.get_node_id(), superResult.status_code(), "NodeUtilities")});
            co_return;
          }
          // A bad super-type resolution during the walk means an intermediate super-type node could
          // not be found - typically a HasSubtype inverse reference pointing at a node that was
          // deleted concurrently (deletion race / dangling reference). Preserve the truthful
          // per-operation status code (BadNodeIdUnknown) but wrap it with a named cause so the
          // wire-boundary log identifies the deletion race rather than only the bare status. The
          // original StatusCode (code + ErrorDetail) is chained.
          auto failure = superResult.status_code();
          try
          {
            failure = StatusCode{failure.value(),
              make_error_detail("DanglingHasSubtype",
                "Super-type node was not found while walking the type hierarchy "
                "(deleted mid-walk / dangling HasSubtype reference)",
                "NodeUtilities",
                superResult.status_code())};
          }
          catch (...)
          {
            // Extra wrapper metadata is optional when its construction fails; the received refusal
            // remains the answer, including its full numeric status and original shared detail.
            ua::detail::ignore_expected_exception();
          }
          complete(BoolResult{std::move(failure)});
          co_return;
        }

        auto& superType = superResult.value();
        if (!superType.has_value())
        {
          complete(BoolResult{false});
          co_return;
        }

        const auto nodeId = superType->get_node_id();
        if (nodeId == mTypeId)
        {
          complete(BoolResult{true});
          co_return;
        }
        if (nodeId == NodeId{ReferenceTypeId::References})
        {
          complete(BoolResult{false});
          co_return;
        }
        current = *superType;
      }
    }
    catch (const ua::async::Abandoned&)
    {
      // This operation carries no withdrawal token, so nothing can throw this - but a root task
      // says what it does with one rather than letting the catch-all below answer a caller who is
      // no longer there.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      complete(BoolResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  /// Answers when the body's frame could not be allocated. @see ua::async::SelfOwningOperation
  void fail_to_start(StatusCode status)
  {
    complete(BoolResult{status});
  }

  /// Answers the caller exactly once, independently of moved-from function state.
  void complete(BoolResult result)
  {
    if (auto onComplete = std::exchange(mOnComplete, nullptr))
    {
      ua::detail::invoke_user_callback(mLogger, onComplete, std::move(result));
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeId mRefTypeId;
  NodeId mTypeId;
  LoopLimit mLoopLimit;
  std::function<void(BoolResult)> mOnComplete;
};

}  // namespace

void is_ref_of_type_async(EncodingLimits limits, AddressSpace addressSpace, bool allowSubTypes,
  NodeId refTypeId, NodeId typeId, std::function<void(BoolResult)> callback)
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    if (refTypeId == typeId)
    {
      detail::invoke_user_callback(logger, callback, BoolResult{true});
      return;
    }
    if (!allowSubTypes)
    {
      detail::invoke_user_callback(logger, callback, BoolResult{false});
      return;
    }
    IsRefOfTypeOperation::start(
      limits, std::move(addressSpace), std::move(refTypeId), std::move(typeId), callback);
  }
  catch (...)
  {
    detail::invoke_user_callback(
      logger, callback, BoolResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void is_ref_of_type_cached_async(EncodingLimits limits, AddressSpace addressSpace, bool allowSubTypes,
  NodeId refId, NodeId typeId, std::shared_ptr<RefTypeCache> cache, std::function<void(BoolResult)> callback)
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    if (refId == typeId)
    {
      detail::invoke_user_callback(logger, callback, BoolResult{true});
      return;
    }
    if (!allowSubTypes)
    {
      detail::invoke_user_callback(logger, callback, BoolResult{false});
      return;
    }
    auto key = std::make_pair(refId, typeId);
    if (const auto cached = cache->lookup(key))
    {
      detail::invoke_user_callback(logger, callback, BoolResult{*cached});
      return;
    }
    is_ref_of_type_async(limits,
      std::move(addressSpace),
      allowSubTypes,
      std::move(refId),
      std::move(typeId),
      // The cache is synchronized and may outlive the component which started the walk.
      [cache, key, callback](BoolResult result) mutable
      {
        if (result.is_good())
        {
          cache->store(key, result.value());
        }
        callback(std::move(result));
      });
  }
  catch (...)
  {
    detail::invoke_user_callback(
      logger, callback, BoolResult{ua::exception_to_status_code(std::current_exception())});
  }
}

bool filter_reference_direction(BrowseDirection direction, const Reference& reference)
{
  const bool isForward = reference.is_forward();

  switch (direction)
  {
  case BrowseDirection::Both:
    return true;

  case BrowseDirection::Forward:
    return isForward;

  case BrowseDirection::Inverse:
    return !isForward;

  case BrowseDirection::Invalid:
  default:
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidBrowseDirection",
        "Browse direction 'Invalid' is not a valid filter direction",
        "NodeUtilities"));
  }
}

}  // namespace node_utils

}  // namespace ua
