// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_views.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "fmt/format.h"

namespace ua
{

DynamicEnumView::DynamicEnumView(int64_t value, const DynamicEnumTypeDescriptor& descriptor)
  : mValue(value), mDescriptor(descriptor)
{}

int64_t DynamicEnumView::value() const
{
  return mValue;
}

string_view DynamicEnumView::value_name() const
{
  auto name = mDescriptor.name_for_value(mValue);
  if (name.has_value())
  {
    return *name;
  }
  return {};
}

std::string DynamicEnumView::to_string() const
{
  auto name = mDescriptor.name_for_value(mValue);
  string_view typeName = mDescriptor.type_name();
  if (name.has_value())
  {
    return fmt::format("{}::{}", typeName, *name);
  }
  return fmt::format("{}({})", typeName, mValue);
}

const DynamicEnumTypeDescriptor& DynamicEnumView::descriptor() const
{
  return mDescriptor;
}

}  // namespace ua
