// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregator.h"

namespace ua::server::aggregates
{

Variant numeric_like(const Variant& templateValue, double numeric)
{
  const int64_t rounded = round_to_int64(numeric);
  if (templateValue.is_double())
    return Variant{numeric};
  if (templateValue.is_float())
    return Variant{static_cast<float>(numeric)};
  if (templateValue.is_int8())
    return Variant{static_cast<int8_t>(rounded)};
  if (templateValue.is_uint8())
    return Variant{static_cast<uint8_t>(rounded)};
  if (templateValue.is_int16())
    return Variant{static_cast<int16_t>(rounded)};
  if (templateValue.is_uint16())
    return Variant{static_cast<uint16_t>(rounded)};
  if (templateValue.is_int32())
    return Variant{static_cast<int32_t>(rounded)};
  if (templateValue.is_uint32())
    return Variant{static_cast<uint32_t>(rounded)};
  if (templateValue.is_int64())
    return Variant{static_cast<int64_t>(rounded)};
  if (templateValue.is_uint64())
    return Variant{static_cast<uint64_t>(rounded)};
  return Variant{numeric};  // fallback to Double
}

}  // namespace ua::server::aggregates
