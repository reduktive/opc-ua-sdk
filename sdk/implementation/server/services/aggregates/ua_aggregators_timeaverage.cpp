// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Time-weighted average / total aggregate family (OPC 10000-13 5.4.3.6-5.4.3.9,
/// Tables 17-20): TimeAverage, Total, TimeAverage2, Total2.
///
/// TimeAverage / Total use Interpolated Bounding Values; Bad values are bridged
/// (omitted from the line). The StatusCode is Custom: Uncertain if any Bad value
/// was bridged or any Uncertain value was used. Total = TimeAverage x
/// width(seconds), i.e. the integral itself. After the end of data the line is
/// extrapolated (Uncertain).
///   Interpolation asymmetry (errata 5210, which corrected Historian_3 in Total):
///   TimeAverage ALWAYS uses sloped interpolation regardless of the Stepped
///   property; Total follows the variable's Stepped property. For Stepped=false
///   variables the two coincide.
///
/// TimeAverage2 / Total2 use Simple Bounding Values and the PercentTime status,
/// with the interval reduced by the non-Good duration. They walk the "knots"
/// (start bound, raw samples inside, end bound) and, per segment, track BOTH a
/// value contribution (held / trapezoid over Good - and Uncertain when
/// TreatUncertainAsBad=false - data) AND a status quality (Figures 2/3 region
/// rules, where the end-of-interval bound downgrades the last segment). The two
/// genuinely diverge: a Good segment bounded by an Uncertain end bound is
/// value-Good (held) but status-Uncertain. Total2 = TimeAverage2 x
/// good-duration(seconds).

#include "ua_aggregate_regions.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <numeric>
#include <vector>

namespace ua::server::aggregates
{

namespace
{

AggregateResult no_value(Status severity)
{
  AggregateResult result;
  result.severity = severity;
  return result;
}

/// Raw quality of a knot value (no TreatUncertainAsBad fold - TUAB is applied
/// later in the value-usability test and the PercentTime grouping).
RegionQuality quality_of(const StatusCode& status, bool hasValue)
{
  if (!hasValue || status.is_bad())
    return RegionQuality::Bad;
  if (status.is_uncertain())
    return RegionQuality::Uncertain;
  return RegionQuality::Good;
}

// ---- TimeAverage (2343, Table 17) / Total (2344, Table 19) ----------------
class TimeAverageAggregator final : public Aggregator
{
public:
  TimeAverageAggregator(bool total, bool forceSloped) : mTotal(total), mForceSloped(forceSloped)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::None;  // the integrator computes its own bounds
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::Double;
    descriptor.calcMethod = CalcMethod::Custom;
    descriptor.partial = BitUsage::SetSometimes;
    descriptor.calculated = BitUsage::SetAlways;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data() || slice.samples == nullptr)
      return no_value(Status::BadNoData);
    const std::vector<Sample>& samples = *slice.samples;

    // TimeAverage always uses sloped interpolation (errata 5210); Total follows
    // the variable's Stepped property. The bound computation and the area both
    // honour the resulting `stepped` flag.
    CalcConfig cfg = ctx.cfg;
    if (mForceSloped)
      cfg.stepped = false;
    const bool stepped = cfg.stepped;

    const DateTime regionStart = slice.start;
    // Past the end of data the value is extrapolated over the whole interval
    // (Table 17 "After End of Data: Value extrapolated, Uncertain status"); the
    // interval is NOT reduced.
    const DateTime regionEnd = slice.end;

    const BoundValue startBound = interpolated_bound(samples, regionStart, cfg);
    const BoundValue endBound = interpolated_bound(samples, regionEnd, cfg);

    // Effective integration start: the interpolated start bound, or - when there
    // is no start bound (data begins after the interval start) - the first data
    // point inside, computed as a partial interval with an Uncertain status.
    DateTime effectiveStart = regionStart;
    double previousValue = 0.0;
    bool uncertain = false;
    if (startBound.hasValue)
    {
      previousValue = startBound.numeric;
      uncertain = !startBound.status.is_good();
    }
    else
    {
      const Sample* first = nullptr;
      for (const auto& sample : samples)
        if (regionStart < sample.time && sample.time < regionEnd && !treated_as_bad(sample, cfg))
        {
          first = &sample;
          break;
        }
      if (first == nullptr)
        return no_value(Status::BadNoData);
      effectiveStart = first->time;
      previousValue = first->numeric;
      uncertain = true;  // "No Start Bound: Calculate Partial Interval" => Uncertain
    }
    if (!endBound.status.is_good())
      uncertain = true;

    double area = 0.0;  // value x seconds
    DateTime cursor = effectiveStart;
    for (const auto& sample : samples)
    {
      if (!(effectiveStart < sample.time) || !(sample.time < regionEnd))
        continue;
      if (treated_as_bad(sample, cfg))
      {
        uncertain = true;  // a Bad (or Uncertain-as-Bad) value is bridged
        continue;
      }
      if (!sample.is_good())
        uncertain = true;  // an Uncertain value is used in the line
      // Stepped: hold the left value over the segment; sloped: average the ends.
      const double mean = stepped ? previousValue : std::midpoint(previousValue, sample.numeric);
      area += mean * seconds_between(cursor, sample.time);
      cursor = sample.time;
      previousValue = sample.numeric;
    }
    const double endValue = endBound.hasValue ? endBound.numeric : previousValue;
    const double finalMean = stepped ? previousValue : std::midpoint(previousValue, endValue);
    area += finalMean * seconds_between(cursor, regionEnd);

    const double widthSeconds = seconds_between(effectiveStart, regionEnd);
    if (widthSeconds <= 0.0)
      return no_value(Status::BadNoData);

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{mTotal ? area : area / widthSeconds};
    result.severity = uncertain ? Status::UncertainDataSubNormal : Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }

private:
  bool mTotal;
  bool mForceSloped;
};

// ---- TimeAverage2 (11285, Table 18) / Total2 (11304, Table 20) ------------
class TimeAverage2Aggregator final : public Aggregator
{
public:
  explicit TimeAverage2Aggregator(bool total) : mTotal(total)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::Simple;
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::Double;
    descriptor.calcMethod = CalcMethod::PercentTime;
    descriptor.partial = BitUsage::SetSometimes;
    descriptor.calculated = BitUsage::SetAlways;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data() || slice.samples == nullptr)
      return no_value(Status::BadNoData);
    const CalcConfig& cfg = ctx.cfg;
    const bool stepped = cfg.stepped;

    // Knots in time order: start bound, the raw samples strictly inside, end bound.
    struct Knot
    {
      DateTime time;
      double value;
      RegionQuality quality;
      bool hasValue;
    };

    std::vector<Knot> knots;
    knots.push_back({slice.start,
      slice.startBound.numeric,
      quality_of(slice.startBound.status, slice.startBound.hasValue),
      slice.startBound.hasValue});
    for (const auto& sample : *slice.samples)
      if (slice.start < sample.time && sample.time < slice.end)
        knots.push_back(
          {sample.time, sample.numeric, quality_of(sample.status, sample.hasNumeric), sample.hasNumeric});
    knots.push_back({slice.end,
      slice.endBound.numeric,
      quality_of(slice.endBound.status, slice.endBound.hasValue),
      slice.endBound.hasValue});

    // "Data" for the BadNoData decision is the start bound or a raw sample inside;
    // the end bound (the next interval's edge) does not make this interval have data.
    bool anyData = slice.startBound.hasValue;
    for (const auto& sample : *slice.samples)
      anyData = anyData || (slice.start < sample.time && sample.time < slice.end && sample.hasNumeric);

    // The interval lies past the end of the data when no raw value exists strictly
    // after its start. Combined with no end bound and sloped extrapolation, the
    // value cannot be extrapolated (Tables 18/20 + 5.4.2.4; errata 6187/6188).
    const bool afterEndOfData = !(slice.start < slice.lastDataTime);
    // 5.4.2.4: one data point in the interval that falls on the StartTime
    // contributes a single server time unit (not the whole interval) to the
    // duration. That is the "raw start bound, no inside points, no data after" case.
    const double unitMs = cfg.timeResolutionSeconds * 1000.0;
    const bool singlePointAtStart = afterEndOfData && slice.startBound.isRaw && knots.size() == 2;

    double goodMs = 0.0, badMs = 0.0, uncertainMs = 0.0;  // status durations
    double area = 0.0, usableMs = 0.0;  // value (value x ms)
    for (size_t i = 0; i + 1 < knots.size(); ++i)
    {
      const Knot& left = knots[i];
      const Knot& right = knots[i + 1];
      const bool lastSegment = (i + 2 == knots.size());
      const bool endBadNoData = lastSegment && !slice.endBound.hasValue;
      // A missing end bound past the end of data with sloped extrapolation cannot
      // be filled; otherwise the last good value is simply held to the interval end.
      const bool noForward = endBadNoData && afterEndOfData && cfg.useSlopedExtrapolation;

      double durationMs = seconds_between(left.time, right.time) * 1000.0;
      if (singlePointAtStart && !noForward)
        durationMs = unitMs;  // 5.4.2.4 single-point-at-StartTime duration
      if (durationMs <= 0.0)
        continue;

      // Status quality of the segment (Figures 2/3 region rules). Default to holding the left
      // value: both the "no end bound / stepped / Bad end point" case and the sloped good case
      // resolve to the left quality. Only an all-Bad/no-forward segment or a sloped segment that
      // ends Uncertain override it.
      RegionQuality segment = left.quality;
      if (left.quality == RegionQuality::Bad || noForward)
        segment = RegionQuality::Bad;
      else if (!endBadNoData && !stepped && right.quality == RegionQuality::Uncertain)
        segment = RegionQuality::Uncertain;  // sloped, ends in an Uncertain value/bound

      if (segment == RegionQuality::Good)
        goodMs += durationMs;
      else if (segment == RegionQuality::Bad)
        badMs += durationMs;
      else
        uncertainMs += durationMs;

      // Value contribution: a segment is usable when its left knot holds Good (or
      // Uncertain, when TreatUncertainAsBad=false) data that can be carried forward.
      const bool leftUsable = left.hasValue && !noForward &&
                              (left.quality == RegionQuality::Good ||
                                (left.quality == RegionQuality::Uncertain && !cfg.treatUncertainAsBad));
      if (leftUsable)
      {
        const bool rightUsable = right.hasValue && right.quality != RegionQuality::Bad;
        const double increment =
          stepped ? left.value : (rightUsable ? std::midpoint(left.value, right.value) : left.value);
        area += increment * durationMs;
        usableMs += durationMs;
      }
    }

    const double widthMs = seconds_between(slice.start, slice.end) * 1000.0;
    AggregateResult result;
    result.dataLocation = DataLocation::Calculated;
    result.severity = percent_time_status(goodMs, badMs, uncertainMs, widthMs, cfg);
    if (usableMs > 0.0)
    {
      result.hasValue = true;
      // TimeAverage2 = area / usableMs; Total2 = TimeAverage2 x usableSeconds = area/1000.
      result.value = Variant{mTotal ? area / 1000.0 : area / usableMs};
    }
    else if (!anyData)
    {
      result.severity = Status::BadNoData;  // no data anywhere in the interval
    }
    return result;
  }

private:
  bool mTotal;
};

}  // namespace

void register_time_average_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_TimeAverage),
    std::make_unique<TimeAverageAggregator>(/*total=*/false, /*forceSloped=*/true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Total),
    std::make_unique<TimeAverageAggregator>(/*total=*/true, /*forceSloped=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_TimeAverage2),
    std::make_unique<TimeAverage2Aggregator>(/*total=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Total2),
    std::make_unique<TimeAverage2Aggregator>(/*total=*/true));
}

}  // namespace ua::server::aggregates
