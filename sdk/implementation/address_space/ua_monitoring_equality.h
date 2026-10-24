// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#pragma once

#include "ua_variant.h"

#include <cmath>

namespace ua
{

/// SVR-MI-GEN-052: NaN-aware value equality for monitored-item change detection.
///
/// For scalar floating-point values, two NaN values compare **equal** so
/// that the NaN state is reported once (on entry) and not on every
/// subsequent sample while the value stays NaN. Non-NaN scalar
/// floats fall back to wire-level `Variant::operator==`, as do all
/// other variant shapes.
///
/// This relaxation is strictly monitoring-layer (Part 4 section 7.10) and must
/// NOT be applied to general `Variant::operator==` (Part 6 section 5.2.2.3).
inline bool values_equal_for_monitoring(const Variant& a, const Variant& b)
{
  if (a.is_double() && b.is_double())
  {
    const double av = a.as<double>();
    const double bv = b.as<double>();
    if (std::isnan(av) && std::isnan(bv))
      return true;
  }
  if (a.is_float() && b.is_float())
  {
    const float av = a.as<float>();
    const float bv = b.as<float>();
    if (std::isnan(av) && std::isnan(bv))
      return true;
  }
  return a == b;
}

/// NaN-aware DataValue equality for sampling engine change detection.
///
/// Compares status, source timestamp, and server timestamp normally, but uses
/// `values_equal_for_monitoring` for the Variant value component.
inline bool data_values_equal_for_monitoring(const DataValue& a, const DataValue& b)
{
  if (a.status() != b.status())
    return false;
  if (a.source_timestamp() != b.source_timestamp())
    return false;
  if (a.server_timestamp() != b.server_timestamp())
    return false;
  return values_equal_for_monitoring(a.value(), b.value());
}

}  // namespace ua
