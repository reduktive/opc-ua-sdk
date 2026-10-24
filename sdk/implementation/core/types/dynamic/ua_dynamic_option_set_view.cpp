// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_views.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "fmt/format.h"

namespace ua
{

DynamicOptionSetView::DynamicOptionSetView(uint64_t value, const DynamicEnumTypeDescriptor& descriptor)
  : mValue(value), mDescriptor(descriptor)
{}

bool DynamicOptionSetView::is_set(string_view bitName) const
{
  const int64_t bitNumber = require_bit_number(bitName);
  return (mValue & (uint64_t{1} << bitNumber)) != 0;
}

void DynamicOptionSetView::set_bit(string_view bitName, bool value)
{
  const int64_t bitNumber = require_bit_number(bitName);
  if (value)
  {
    mValue |= (uint64_t{1} << bitNumber);
  }
  else
  {
    mValue &= ~(uint64_t{1} << bitNumber);
  }
}

uint64_t DynamicOptionSetView::underlying() const
{
  return mValue;
}

std::string DynamicOptionSetView::to_string() const
{
  const string_view typeName = mDescriptor.type_name();
  std::string result;
  result += typeName;
  result += '{';

  const auto& fields = mDescriptor.definition().fields();
  bool first = true;
  for (size_t i = 0; i < fields.size(); ++i)
  {
    const int64_t bitNumber = fields[i].value();
    if (bitNumber >= 0 && bitNumber < 64 && (mValue & (uint64_t{1} << bitNumber)) != 0)
    {
      if (!first)
      {
        result += ", ";
      }
      result += string_view(fields[i].name());
      first = false;
    }
  }

  result += '}';
  return result;
}

const DynamicEnumTypeDescriptor& DynamicOptionSetView::descriptor() const
{
  return mDescriptor;
}

int64_t DynamicOptionSetView::require_bit_number(string_view bitName) const
{
  auto val = mDescriptor.value_for_name(bitName);
  if (!val.has_value())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("UnknownBitName", "Bit name not found in option set type", "DynamicOptionSetView")
        .context(ua::ContextKeys::bitName, std::string(bitName))
        .context(ua::ContextKeys::typeName, std::string(mDescriptor.type_name())));
  }
  if (*val < 0 || *val >= 64)
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build(
        "BitNumberOutOfRange", "Bit number is outside the valid range", "DynamicOptionSetView")
        .context(ua::ContextKeys::bitIndex, std::to_string(*val))
        .context(ua::ContextKeys::bitName, std::string(bitName))
        .context(ua::ContextKeys::min, "0")
        .context(ua::ContextKeys::max, "63")
        .context(ua::ContextKeys::typeName, std::string(mDescriptor.type_name())));
  }
  return *val;
}

}  // namespace ua
