// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Simple-bound extreme family (OPC 10000-13 5.4.3.15-5.4.3.19, Tables 26-30):
/// Minimum2, Maximum2, MinimumActualTime2, MaximumActualTime2, Range2.
///
/// These behave like the no-bounds Minimum/Maximum/Range except that the Simple
/// Bounding Values (3.1.9) are added to the candidate set, and the StatusCode is
/// the time-based PercentTime calculation (5.3) rather than a value-count one.
/// The candidate set for an interval is:
///   - the Simple start bound, when it has a value;
///   - each raw value strictly inside the interval that is Good (or Uncertain,
///     when TreatUncertainAsBad is false) - Bad values are always ignored;
///   - the Simple end bound, but ONLY for sloped interpolation. 5.4.3.15: "If
///     sloped interpolation is used and the End bound is the minimum value then
///     End bound is used ... The End bound is ignored in all other cases."
/// The extreme value over that set is the result. The result's data-location
/// (Raw / Calculated / Interpolated) reflects how the reported (value, timestamp)
/// pair relates to the source data; MultiValue is set when more than one
/// candidate ties at the extreme. Range2 = Maximum2 - Minimum2 with a status that
/// combines the two (Table 30).

#include "ua_aggregate_regions.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

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

/// One value eligible to be the interval extreme.
struct Candidate
{
  enum class Source
  {
    StartBound,
    Inside,
    EndBound
  };

  double value{0.0};
  DateTime time;  ///< the candidate's own time (StartTime / sample time / EndTime)
  Source source{Source::Inside};
  bool isRaw{false};  ///< an exact raw value (vs an interpolated Simple bound)
  Variant raw;  ///< the original Variant when isRaw (for Same-as-Source typing)
};

/// Collect the extreme candidates for one interval, in time order (the start
/// bound, then each usable inside raw value ascending, then the end bound). The
/// end bound is included only for sloped interpolation (5.4.3.15-18).
std::vector<Candidate> collect_candidates(const TimeSlice& slice, const CalcConfig& cfg)
{
  std::vector<Candidate> candidates;
  if (slice.startBound.hasValue)
    candidates.push_back({slice.startBound.numeric,
      slice.start,
      Candidate::Source::StartBound,
      slice.startBound.isRaw,
      slice.startBound.raw});
  if (slice.samples != nullptr)
  {
    for (const auto& sample : *slice.samples)
    {
      if (!(slice.start < sample.time) || !(sample.time < slice.end))
        continue;
      // Bad values are always ignored; Uncertain values are ignored only when
      // TreatUncertainAsBad is set (treated_as_bad folds both, 3.1.7).
      if (treated_as_bad(sample, cfg))
        continue;
      candidates.push_back({sample.numeric, sample.time, Candidate::Source::Inside, true, sample.raw});
    }
  }
  if (!cfg.stepped && slice.endBound.hasValue)
    candidates.push_back({slice.endBound.numeric,
      slice.end,
      Candidate::Source::EndBound,
      slice.endBound.isRaw,
      slice.endBound.raw});
  return candidates;
}

/// The extreme candidate (minimum or maximum). Because candidates are in time
/// order and ties keep the first (earliest), the returned candidate is the
/// earliest occurrence of the extreme - which determines the data-location bit
/// and the ActualTime timestamp. `tieCount` reports how many candidates tie at
/// the extreme value (drives the MultiValue bit).
const Candidate* select_extreme(const std::vector<Candidate>& candidates, bool wantMax, int& tieCount)
{
  const Candidate* extreme = nullptr;
  for (const auto& candidate : candidates)
  {
    if (extreme == nullptr || (wantMax ? candidate.value > extreme->value : candidate.value < extreme->value))
      extreme = &candidate;
  }
  tieCount = 0;
  if (extreme != nullptr)
    for (const auto& candidate : candidates)
      if (candidate.value == extreme->value)
        ++tieCount;
  return extreme;
}

// ---- Minimum2 (11286) / Maximum2 (11287) and the ActualTime2 variants -------
class SimpleBoundMinMax final : public Aggregator
{
public:
  SimpleBoundMinMax(bool wantMax, bool actualTime) : mWantMax(wantMax), mActualTime(actualTime)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::Simple;
    descriptor.timestamp = mActualTime ? TimestampRule::ValueTime : TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::SameAsSource;
    descriptor.calcMethod = CalcMethod::PercentTime;
    descriptor.partial = BitUsage::SetSometimes;
    descriptor.multiValue = BitUsage::SetSometimes;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);  // before / after the data (Tables 26-29)
    const std::vector<Candidate> candidates = collect_candidates(slice, ctx.cfg);
    if (candidates.empty())
      return no_value(Status::BadNoData);

    int tieCount = 0;
    const Candidate* extreme = select_extreme(candidates, mWantMax, tieCount);

    AggregateResult result;
    result.hasValue = true;
    result.value = extreme->isRaw ? extreme->raw : Variant{extreme->value};
    result.severity = percent_time_severity(build_regions(slice, ctx.cfg), ctx.cfg);
    result.multipleValues = tieCount > 1;
    result.dataLocation = location_for(*extreme);
    if (mActualTime)
      result.timestampOverride = report_time(*extreme, slice);
    return result;
  }

private:
  /// Data-location of the reported value. The result is stamped at StartTime
  /// (Min2/Max2) or at the value's own time (ActualTime2): a raw value reported
  /// at its own time is Raw, an interpolated bound is Interpolated, and an exact
  /// raw value reported at a different time is Calculated. The ActualTime2 tables
  /// set Calculated "Not Set", so for them an end bound (reported at the
  /// EffectiveEndTime, not the raw's own time) is reported as Interpolated.
  DataLocation location_for(const Candidate& candidate) const
  {
    switch (candidate.source)
    {
    case Candidate::Source::StartBound:
      return candidate.isRaw ? DataLocation::Raw : DataLocation::Interpolated;
    case Candidate::Source::Inside:
      return mActualTime ? DataLocation::Raw : DataLocation::Calculated;
    case Candidate::Source::EndBound:
      if (mActualTime)
        return DataLocation::Interpolated;
      return candidate.isRaw ? DataLocation::Calculated : DataLocation::Interpolated;
    }
    return DataLocation::Calculated;
  }

  /// Timestamp for the ActualTime2 variants: the start bound stamps at StartTime,
  /// an inside raw value at its own time, the end bound at the EffectiveEndTime
  /// (5.4.3.17-18: "the timestamp set to the EffectiveEndTime of the interval").
  static DateTime report_time(const Candidate& candidate, const TimeSlice& slice)
  {
    switch (candidate.source)
    {
    case Candidate::Source::StartBound:
      return slice.start;
    case Candidate::Source::Inside:
      return candidate.time;
    case Candidate::Source::EndBound:
      return slice.effectiveEnd;
    }
    return slice.start;
  }

  bool mWantMax;
  bool mActualTime;
};

// ---- Range2 (11288) -------------------------------------------------------
class Range2Aggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::Simple;
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::SameAsSource;
    descriptor.calcMethod = CalcMethod::Custom;
    descriptor.partial = BitUsage::SetSometimes;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const std::vector<Candidate> candidates = collect_candidates(slice, ctx.cfg);
    if (candidates.empty())
      return no_value(Status::BadNoData);

    int tieCount = 0;
    const Candidate* low = select_extreme(candidates, /*wantMax=*/false, tieCount);
    const Candidate* high = select_extreme(candidates, /*wantMax=*/true, tieCount);

    // Table 30 (Custom): Minimum2 and Maximum2 share the PercentTime severity
    // over the same regions, so it is computed once. Bad => Bad_NoData; Uncertain
    // => Uncertain_DataSubNormal; Good otherwise.
    const Status severity = percent_time_severity(build_regions(slice, ctx.cfg), ctx.cfg);

    AggregateResult result;
    result.severity = (severity == Status::Bad) ? Status::BadNoData : severity;
    result.dataLocation = DataLocation::Calculated;
    if (result.severity != Status::BadNoData)
    {
      result.hasValue = true;
      result.value = Variant{high->value - low->value};  // always zero or positive
    }
    return result;
  }
};

}  // namespace

void register_simple_bound_minmax_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_Minimum2),
    std::make_unique<SimpleBoundMinMax>(/*wantMax=*/false, /*actualTime=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Maximum2),
    std::make_unique<SimpleBoundMinMax>(/*wantMax=*/true, /*actualTime=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_MinimumActualTime2),
    std::make_unique<SimpleBoundMinMax>(/*wantMax=*/false, /*actualTime=*/true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_MaximumActualTime2),
    std::make_unique<SimpleBoundMinMax>(/*wantMax=*/true, /*actualTime=*/true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Range2), std::make_unique<Range2Aggregator>());
}

}  // namespace ua::server::aggregates
