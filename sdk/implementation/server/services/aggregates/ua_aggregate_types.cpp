// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_types.h"

namespace ua::server::aggregates
{

std::optional<double> value_to_double(const Variant& variant)
{
  if (variant.is_boolean())
    return variant.as<bool>() ? 1.0 : 0.0;
  if (variant.is_int8())
    return static_cast<double>(variant.as<int8_t>());
  if (variant.is_uint8())
    return static_cast<double>(variant.as<uint8_t>());
  if (variant.is_int16())
    return static_cast<double>(variant.as<int16_t>());
  if (variant.is_uint16())
    return static_cast<double>(variant.as<uint16_t>());
  if (variant.is_int32())
    return static_cast<double>(variant.as<int32_t>());
  if (variant.is_uint32())
    return static_cast<double>(variant.as<uint32_t>());
  if (variant.is_int64())
    return static_cast<double>(variant.as<int64_t>());
  if (variant.is_uint64())
    return static_cast<double>(variant.as<uint64_t>());
  if (variant.is_float())
    return static_cast<double>(variant.as<float>());
  if (variant.is_double())
    return variant.as<double>();
  return std::nullopt;
}

}  // namespace ua::server::aggregates
