// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Data-variation + start/end aggregate family (OPC 10000-13 5.4.3.10-5.4.3.27,
/// Tables 21-25, 36-38): Minimum/Maximum(+ActualTime), Range, Start/End, Delta.
/// All use no bounds and operate on the raw samples inside the interval.

#include "ua_aggregate_support.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

namespace ua::server::aggregates
{

namespace
{

AggregateResult no_value(Status severity)
{
  AggregateResult result;
  result.hasValue = false;
  result.severity = severity;
  return result;
}

// Common descriptor for the no-bounds, Same-as-Source, Custom-status family.
AggregateDescriptor variation_descriptor(TimestampRule timestamp, BitUsage multiValue)
{
  AggregateDescriptor d;
  d.useBounds = BoundsKind::None;
  d.timestamp = timestamp;
  d.resultType = ResultType::SameAsSource;
  d.calcMethod = CalcMethod::Custom;
  d.partial = BitUsage::SetSometimes;  // "If an interval is not a complete interval"
  d.multiValue = multiValue;
  return d;
}

// ---- Minimum (2346, Table 21) / Maximum (2347, Table 22) -----------------
// `wantMax` selects maximum; `actualTime` stamps the value's own time.
class MinMaxAggregator final : public Aggregator
{
public:
  MinMaxAggregator(bool wantMax, bool actualTime) : mWantMax(wantMax), mActualTime(actualTime)
  {}

  AggregateDescriptor descriptor() const override
  {
    return variation_descriptor(
      mActualTime ? TimestampRule::ValueTime : TimestampRule::IntervalStart, BitUsage::SetSometimes);
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const IntervalStats stats = classify(slice);
    if (stats.good == 0)
      return no_value(Status::BadNoData);

    const Sample* extreme = mWantMax ? stats.maxGood : stats.minGood;
    const int extremeCount = mWantMax ? stats.maxGoodCount : stats.minGoodCount;

    // The result is a selected Good raw value. Per OPC 10000-13 5.3 (Table 9),
    // Uncertain_DataSubNormal means a value derived with fewer than the required
    // number of Good values, i.e. non-Good values were skipped. Per 3.1.7
    // TreatUncertainAsBad decides whether an Uncertain value counts as non-Good:
    // when false it is treated as non-Bad and does not downgrade the result.
    const bool uncertain = stats.bad > 0 || (ctx.cfg.treatUncertainAsBad && stats.uncertain > 0);

    AggregateResult result;
    result.hasValue = true;
    result.value = extreme->raw;
    result.severity = uncertain ? Status::UncertainDataSubNormal : Status::Good;
    result.multipleValues = extremeCount > 1;
    if (mActualTime)
    {
      // A Good extreme raw value is always returned (Raw bit), at its own time.
      result.timestampOverride = extreme->time;
      result.dataLocation = DataLocation::Raw;
    }
    else
    {
      // Raw only when the extreme sits exactly on the interval start and is Good.
      const bool onStart = extreme->time == slice.start;
      result.dataLocation = (onStart && !uncertain) ? DataLocation::Raw : DataLocation::Calculated;
    }
    return result;
  }

private:
  bool mWantMax;
  bool mActualTime;
};

// ---- Range (2350, Table 25) ----------------------------------------------
class RangeAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    return variation_descriptor(TimestampRule::IntervalStart, BitUsage::NotSet);
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const IntervalStats stats = classify(slice);
    if (stats.good == 0)
      return no_value(Status::BadNoData);

    const double minValue = stats.minGood->numeric;
    const double maxValue = stats.maxGood->numeric;

    // As Minimum/Maximum: Uncertain_DataSubNormal when non-Good values were
    // skipped (OPC 10000-13 5.3); 3.1.7 TreatUncertainAsBad governs whether an
    // Uncertain value counts as non-Good.
    const bool uncertain = stats.bad > 0 || (ctx.cfg.treatUncertainAsBad && stats.uncertain > 0);

    AggregateResult result;
    result.hasValue = true;
    result.value = numeric_like(ctx.sourceTemplate, maxValue - minValue);
    result.severity = uncertain ? Status::UncertainDataSubNormal : Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

// ---- Start (2357, Table 36) / End (2358, Table 37) -----------------------
// Earliest/latest raw value in the interval (any quality), with its own status
// and timestamp. Raw bit always set.
class StartEndAggregator final : public Aggregator
{
public:
  explicit StartEndAggregator(bool wantEnd) : mWantEnd(wantEnd)
  {}

  AggregateDescriptor descriptor() const override
  {
    return variation_descriptor(TimestampRule::ValueTime, BitUsage::NotSet);
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const std::vector<const Sample*> samples = window_samples(slice);
    if (samples.empty())
      return no_value(Status::BadNoData);

    const Sample* chosen = mWantEnd ? samples.back() : samples.front();
    AggregateResult result;
    result.hasValue = true;
    result.value = chosen->raw;
    result.severity = chosen->status.as_status();
    result.dataLocation = DataLocation::Raw;
    result.timestampOverride = chosen->time;
    return result;
  }

private:
  bool mWantEnd;
};

// ---- Delta (2359, Table 38) ----------------------------------------------
// Difference between the last and first Good values in the interval.
class DeltaAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    return variation_descriptor(TimestampRule::IntervalStart, BitUsage::NotSet);
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const IntervalStats stats = classify(slice);
    if (stats.good == 0)
      return no_value(Status::BadNoData);

    const double delta = stats.lastGood->numeric - stats.firstGood->numeric;

    // Uncertain if non-Good values were skipped while locating the first/last
    // Good value (i.e. the interval's earliest or latest sample is non-Good).
    const std::vector<const Sample*> samples = window_samples(slice);
    const bool uncertain = !samples.empty() && (!samples.front()->is_good() || !samples.back()->is_good());

    AggregateResult result;
    result.hasValue = true;
    result.value = numeric_like(ctx.sourceTemplate, delta);
    result.severity = uncertain ? Status::UncertainDataSubNormal : Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

}  // namespace

void register_variation_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_Minimum),
    std::make_unique<MinMaxAggregator>(/*wantMax=*/false, /*actualTime=*/false));
  map.emplace(
    utils::to_underlying(Id::AggregateFunction_Maximum), std::make_unique<MinMaxAggregator>(true, false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_MinimumActualTime),
    std::make_unique<MinMaxAggregator>(false, true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_MaximumActualTime),
    std::make_unique<MinMaxAggregator>(true, true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Range), std::make_unique<RangeAggregator>());
  map.emplace(utils::to_underlying(Id::AggregateFunction_Start),
    std::make_unique<StartEndAggregator>(/*wantEnd=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_End), std::make_unique<StartEndAggregator>(true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_Delta), std::make_unique<DeltaAggregator>());
}

}  // namespace ua::server::aggregates
