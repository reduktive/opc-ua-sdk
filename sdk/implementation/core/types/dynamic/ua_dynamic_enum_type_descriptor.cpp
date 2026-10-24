// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_enum_type_descriptor.h"

namespace ua
{

DynamicEnumTypeDescriptor::DynamicEnumTypeDescriptor(
  String typeName, ExpandedNodeId typeId, bool isOptionSet, EnumDefinition definition)
  : mTypeName(std::move(typeName)), mTypeId(std::move(typeId)), mIsOptionSet(isOptionSet),
    mDefinition(std::move(definition))
{
  const auto& fields = mDefinition.fields();
  for (size_t i = 0; i < fields.size(); ++i)
  {
    const auto& field = fields[i];
    const int64_t val = field.value();
    const string_view name = field.name();
    mValueToName.emplace(val, name);
    mNameToValue.emplace(name, val);
  }
}

const String& DynamicEnumTypeDescriptor::type_name() const
{
  return mTypeName;
}

const ExpandedNodeId& DynamicEnumTypeDescriptor::type_id() const
{
  return mTypeId;
}

bool DynamicEnumTypeDescriptor::is_option_set() const
{
  return mIsOptionSet;
}

std::optional<string_view> DynamicEnumTypeDescriptor::name_for_value(int64_t value) const
{
  auto it = mValueToName.find(value);
  if (it == mValueToName.end())
  {
    return std::nullopt;
  }
  return it->second;
}

std::optional<int64_t> DynamicEnumTypeDescriptor::value_for_name(string_view name) const
{
  auto it = mNameToValue.find(name);
  if (it == mNameToValue.end())
  {
    return std::nullopt;
  }
  return it->second;
}

const EnumDefinition& DynamicEnumTypeDescriptor::definition() const
{
  return mDefinition;
}

}  // namespace ua
