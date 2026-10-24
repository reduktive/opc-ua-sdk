// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_SUPPORT_H
#define UA_AGGREGATE_SUPPORT_H

/// Shared per-interval analysis for count-based aggregates: classify the
/// in-window samples by quality and derive the PercentValues result severity
/// (OPC 10000-13 5.4.3.2, count/value family).

#include "ua_aggregator.h"

namespace ua::server::aggregates
{

/// Quality breakdown of the samples that fall inside an interval AND within the
/// data window (the leading Bad_NoData "point created" placeholder is excluded).
struct IntervalStats
{
  int good{0};
  int uncertain{0};
  int bad{0};
  std::vector<double> goodValues;  ///< numeric of the Good samples, in time order
  std::vector<double> uncertainValues;  ///< numeric of the Uncertain samples, in time order
  const Sample* firstGood{nullptr};
  const Sample* lastGood{nullptr};
  const Sample* minGood{nullptr};  ///< earliest sample holding the minimum Good value
  const Sample* maxGood{nullptr};  ///< earliest sample holding the maximum Good value
  int minGoodCount{0};  ///< how many Good samples equal the minimum
  int maxGoodCount{0};  ///< how many Good samples equal the maximum

  int total() const
  {
    return good + uncertain + bad;
  }
};

/// Classify the countable samples of `slice` (those within [firstDataTime,
/// lastDataTime]). Good = Good status + numeric; Uncertain = Uncertain + numeric;
/// Bad = Bad status or no value.
IntervalStats classify(const TimeSlice& slice);

/// PercentValues result severity for a populated interval (OPC 10000-13).
/// Returns Bad / UncertainDataSubNormal / Good. `total()==0` should be handled
/// by the caller as Bad_NoData before calling this.
Status percent_values_severity(const IntervalStats& stats, const CalcConfig& cfg);

/// The samples that fall inside the interval AND within the data window, in time
/// order (the leading Bad_NoData placeholder is excluded). Used by raw-selecting
/// aggregates (Start/End) that consider values of any quality.
std::vector<const Sample*> window_samples(const TimeSlice& slice);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_SUPPORT_H
