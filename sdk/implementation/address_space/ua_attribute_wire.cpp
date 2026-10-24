// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_attribute_wire.h"
#include "ua_array.h"
#include "ua_callback_safety.h"
#include "ua_defines.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"

namespace ua::attribute_wire
{

Variant browse_name(const QualifiedName& value)
{
  return Variant{value};
}

Variant display_name(const LocalizedText& value)
{
  // Single-source DisplayName size enforcement (OPC 10000-3): the limit applies on every write path
  // - the NodeAccessor setter and the create-with-attributes builders all encode through here.
  if (value.text().size() > displayNameMaxTextSize)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidAttributeId", "DisplayName exceeds maximum size", "NodeAccessor")
        .context(ua::ContextKeys::sizeActual, std::to_string(value.text().size()))
        .context(ua::ContextKeys::sizeMax, std::to_string(displayNameMaxTextSize))};
  }
  return Variant{value};
}

Variant description(const LocalizedText& value)
{
  return Variant{value};
}

Variant write_mask(const optional<AttributeWriteMask>& value)
{
  if (value)
  {
    return Variant{numeric_cast<uint32_t>(value->as_underlying_type())};
  }
  return Variant{};
}

Variant role_permissions(const optional<std::vector<RolePermissionType>>& value)
{
  if (value)
  {
    return role_permissions(*value);
  }
  return Variant{};
}

Variant role_permissions(const std::vector<RolePermissionType>& value)
{
  return Variant{array_utils::copy_to_array_of_references(value)};
}

Result<std::vector<RolePermissionType>> decode_role_permissions(const Variant& value)
{
  std::vector<RolePermissionType> proposed;
  if (value.empty())
  {
    return proposed;
  }

  if (!value.is_array_of_structure())
  {
    return Result<std::vector<RolePermissionType>>{StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("TypeMismatch",
        "RolePermissions Write value is not an array of RolePermissionType",
        "AttributeServiceSet")}};
  }

  const auto& entries = value.as<Array<RefStructure<Structure>>>();
  proposed.reserve(entries.size());
  for (size_t i = 0; i < entries.size(); ++i)
  {
    const auto* rolePermission = dynamic_cast<const RolePermissionType*>(entries[i].get());
    if (rolePermission == nullptr)
    {
      return Result<std::vector<RolePermissionType>>{StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build("TypeMismatch",
          "RolePermissions contains a Structure that is not RolePermissionType",
          "AttributeServiceSet")
          .context(ua::ContextKeys::index, std::to_string(i))}};
    }
    proposed.push_back(*rolePermission);
  }
  return proposed;
}

Variant access_restrictions(const optional<AccessRestrictionType>& value)
{
  if (value)
  {
    return Variant{numeric_cast<uint16_t>(value->as_underlying_type())};
  }
  return Variant{};
}

Variant is_abstract(bool value)
{
  return Variant{value};
}

Variant symmetric(bool value)
{
  return Variant{value};
}

Variant inverse_name(const LocalizedText& value)
{
  return Variant{value};
}

Variant data_type_definition(const shared_ptr<const DataTypeDefinition>& value)
{
  if (!value)
  {
    return Variant{};
  }
  // Variant stores the value as an owning clone; repeated reads clone
  // again. Definitions are small - this is not on a hot path.
  auto cloned = value->clone();
  return Variant{std::move(cloned)};
}

Variant event_notifier(const EventNotifierType& value)
{
  return Variant{numeric_cast<uint8_t>(value.as_underlying_type())};
}

Variant variable_type_value(const optional<DataValue>& value)
{
  if (value)
  {
    return Variant{value.value()};
  }
  return Variant{};
}

Variant data_type(const NodeId& value)
{
  return Variant{value};
}

Variant value_rank(ValueRank value)
{
  return Variant{value.as_int32()};
}

Variant array_dimensions(const optional<std::vector<uint32_t>>& value)
{
  if (value)
  {
    return array_dimensions(*value);
  }
  return Variant{};
}

Variant array_dimensions(const std::vector<uint32_t>& value)
{
  Array<uint32_t> arr;
  arr.payload() = value;
  return Variant{std::move(arr)};
}

Variant contains_no_loops(bool value)
{
  return Variant{value};
}

Variant access_level(const AccessLevelType& value)
{
  return Variant{numeric_cast<uint8_t>(value.as_underlying_type())};
}

Variant access_level_ex(const optional<AccessLevelExType>& value)
{
  if (value)
  {
    return Variant{numeric_cast<uint32_t>(value->as_underlying_type())};
  }
  return Variant{};
}

Variant minimum_sampling_interval(const optional<Duration>& value)
{
  if (value)
  {
    return Variant{value.value()};
  }
  return Variant{};
}

Variant historizing(bool value)
{
  return Variant{value};
}

Variant executable(bool value)
{
  return Variant{value};
}

}  // namespace ua::attribute_wire
