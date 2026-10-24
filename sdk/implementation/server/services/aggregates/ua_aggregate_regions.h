// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_REGIONS_H
#define UA_AGGREGATE_REGIONS_H

/// Time-weighted region engine (OPC 10000-13 5.4.3.2). For time-weighted
/// aggregates each interval is divided into regions of Good / Uncertain / Bad
/// data, bounded by the interval start bound, each raw point strictly inside the
/// interval, and the interval end (or the effective end for an interval that
/// straddles the end of the data, 5.4.2.4).
///
/// The region quality follows the Sloped / Stepped rules illustrated by Figures
/// 2 and 3 (Stepped = False / Simple bounds, and Stepped = True / Interpolated
/// bounds respectively):
///   - Stepped: a region takes its left boundary's quality; the end point has no
///     effect on the region.
///   - Sloped: a region that ends in a Bad value is held (stepped) from its left
///     boundary (you cannot slope to a Bad value); a region that ends in an
///     Uncertain value is Uncertain; otherwise it takes its left boundary quality.
///   - TreatUncertainAsBad folds Uncertain into Bad before classification, so
///     there are no Uncertain regions when it is set.
///
/// This engine is shared by the duration / percent / state families (and, once
/// the trapezoid integration lands, the time-average / total families).

#include "ua_aggregator.h"

namespace ua::server::aggregates
{

enum class RegionQuality
{
  Good,
  Uncertain,
  Bad
};

/// One homogeneous slice of an interval.
struct Region
{
  DateTime start;
  DateTime end;
  RegionQuality quality{RegionQuality::Bad};  ///< the region's (left-boundary) quality
  RegionQuality rightQuality{RegionQuality::Bad};  ///< the right boundary's quality (trapezoid gate)
  double leftValue{0.0};  ///< value at the region start (held value / area left edge)
  bool hasLeftValue{false};
  double rightValue{0.0};  ///< value at the region end (area right edge for sloped integration)
  bool hasRightValue{false};

  /// Region width in milliseconds.
  double duration_ms() const
  {
    return seconds_between(start, end) * 1000.0;
  }
};

/// The regions of one interval plus the time used (the interval width that the
/// StatusCode ratios and PercentGood/Bad are computed against, 5.4.3.2.1).
struct RegionSet
{
  std::vector<Region> regions;
  double widthMs{0.0};  ///< Sum region durations: ProcessingInterval, or the partial-interval width

  double good_ms() const;
  double bad_ms() const;
  double uncertain_ms() const;
};

/// Build the regions for `slice` from its precomputed start/end bounds and the
/// raw points inside it.
RegionSet build_regions(const TimeSlice& slice, const CalcConfig& cfg);

/// PercentTime StatusCode severity from raw Good/Bad/Uncertain durations and the
/// interval width (5.4.3.2.1 + 4.2.1.2 / errata 6227): Good when there are no
/// Bad regions; Bad when the Bad ratio >= PercentDataBad; Good when the Good
/// ratio >= PercentDataGood; otherwise Uncertain_DataSubNormal. When
/// PercentDataGood == 100 - PercentDataBad the Good calculation governs the tie.
/// TreatUncertainAsBad groups the Uncertain duration with Bad (else with Good).
Status percent_time_status(
  double goodMs, double badMs, double uncertainMs, double widthMs, const CalcConfig& cfg);

/// PercentTime severity for a built RegionSet (delegates to percent_time_status).
Status percent_time_severity(const RegionSet& regions, const CalcConfig& cfg);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_REGIONS_H
