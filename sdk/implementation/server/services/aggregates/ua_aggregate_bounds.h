// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_BOUNDS_H
#define UA_AGGREGATE_BOUNDS_H

/// Bounding-value primitives for the aggregate calculator
/// (OPC 10000-13 3.1.7-3.1.9: Interpolated and Simple Bounding Values,
/// Sloped/Stepped interpolation and extrapolation).

#include "ua_aggregate_types.h"

namespace ua::server::aggregates
{

/// A boundary value computed at a specific timestamp.
struct BoundValue
{
  bool hasValue{false};  ///< false => Bad_NoData (no usable bound)
  double numeric{0.0};  ///< numeric projection of the bound
  Variant raw;  ///< the source Variant when the bound is an exact raw value
  StatusCode status;  ///< Good / UncertainDataSubNormal / BadNoData
  bool isRaw{false};  ///< an exact raw value existed at the timestamp (Raw bit)
};

/// `true` if the sample must be treated as Bad while searching for bounds,
/// honoring TreatUncertainAsBad.
bool treated_as_bad(const Sample& sample, const CalcConfig& cfg);

/// Interpolated Bounding Value at `t` (OPC 10000-13 3.1.8). Uses the first
/// non-Bad samples before/after `t`; sloped or stepped per cfg.stepped; sloped
/// reads extrapolate past the last sample per cfg.useSlopedExtrapolation.
/// `samples` must be sorted ascending by time.
BoundValue interpolated_bound(const std::vector<Sample>& samples, const DateTime& t, const CalcConfig& cfg);

/// Simple Bounding Value at `t` (OPC 10000-13 3.1.9). Uses the data points
/// immediately before/after `t` even if Bad. UseSlopedExtrapolation is ignored.
BoundValue simple_bound(const std::vector<Sample>& samples, const DateTime& t, const CalcConfig& cfg);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_BOUNDS_H
