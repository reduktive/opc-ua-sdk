// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Time-weighted duration / percent / state aggregate family (OPC 10000-13
/// 5.4.3.22-5.4.3.23 and 5.4.3.31-5.4.3.34, Tables 33-34 and 42-45):
/// DurationGood, DurationBad, PercentGood, PercentBad, DurationInStateZero,
/// DurationInStateNonZero. All split the interval into Good/Uncertain/Bad regions
/// using Simple Bounding Values (the shared region engine) and sum region
/// durations; the only difference is which regions are summed and how the
/// StatusCode is derived.

#include "ua_aggregate_regions.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <cmath>

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

// Common descriptor: Simple bounds, stamped at the interval start, Calculated.
AggregateDescriptor duration_descriptor(CalcMethod calcMethod)
{
  AggregateDescriptor descriptor;
  descriptor.useBounds = BoundsKind::Simple;
  descriptor.timestamp = TimestampRule::IntervalStart;
  descriptor.resultType = ResultType::Duration;
  descriptor.calcMethod = calcMethod;
  descriptor.partial = BitUsage::SetSometimes;
  return descriptor;
}

// ---- DurationGood (2360, Table 42) / DurationBad (2361, Table 43) ---------
// Sum of the durations of the Good (resp. Bad) regions, in milliseconds. The
// StatusCode is always Good, Calculated.
class DurationGoodBadAggregator final : public Aggregator
{
public:
  explicit DurationGoodBadAggregator(bool wantBad) : mWantBad(wantBad)
  {}

  AggregateDescriptor descriptor() const override
  {
    return duration_descriptor(CalcMethod::Custom);  // always Good
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const RegionSet regions = build_regions(slice, ctx.cfg);

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{mWantBad ? regions.bad_ms() : regions.good_ms()};
    result.severity = Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }

private:
  bool mWantBad;
};

// ---- PercentGood (2362, Table 44) / PercentBad (2363, Table 45) -----------
// DurationGood / DurationBad expressed as a percentage of the interval width.
class PercentGoodBadAggregator final : public Aggregator
{
public:
  explicit PercentGoodBadAggregator(bool wantBad) : mWantBad(wantBad)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor = duration_descriptor(CalcMethod::Custom);  // always Good
    descriptor.resultType = ResultType::Double;  // percentage 0..100
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const RegionSet regions = build_regions(slice, ctx.cfg);
    const double duration = mWantBad ? regions.bad_ms() : regions.good_ms();
    const double percent = regions.widthMs > 0.0 ? duration / regions.widthMs * 100.0 : 0.0;

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{percent};
    result.severity = Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }

private:
  bool mWantBad;
};

// ---- DurationInStateZero (11307, Table 33) / NonZero (11308, Table 34) ----
// Time the (stepped-held) value was in the zero / non-zero state, summed over
// the Good regions only. The StatusCode uses the time-weighted calculation.
class DurationInStateAggregator final : public Aggregator
{
public:
  explicit DurationInStateAggregator(bool wantNonZero) : mWantNonZero(wantNonZero)
  {}

  AggregateDescriptor descriptor() const override
  {
    return duration_descriptor(CalcMethod::PercentTime);
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const RegionSet regions = build_regions(slice, ctx.cfg);

    double total = 0.0;
    for (const auto& region : regions.regions)
    {
      if (region.quality != RegionQuality::Good || !region.hasLeftValue)
        continue;  // non-Good data is not included in the Duration
      const bool isZero = std::fabs(region.leftValue) < 1e-12;
      if (mWantNonZero ? !isZero : isZero)
        total += region.duration_ms();
    }

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{total};
    result.severity = percent_time_severity(regions, ctx.cfg);
    result.dataLocation = DataLocation::Calculated;
    return result;
  }

private:
  bool mWantNonZero;
};

}  // namespace

void register_duration_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_DurationGood),
    std::make_unique<DurationGoodBadAggregator>(/*wantBad=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_DurationBad),
    std::make_unique<DurationGoodBadAggregator>(true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_PercentGood),
    std::make_unique<PercentGoodBadAggregator>(/*wantBad=*/false));
  map.emplace(
    utils::to_underlying(Id::AggregateFunction_PercentBad), std::make_unique<PercentGoodBadAggregator>(true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_DurationInStateZero),
    std::make_unique<DurationInStateAggregator>(/*wantNonZero=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_DurationInStateNonZero),
    std::make_unique<DurationInStateAggregator>(true));
}

}  // namespace ua::server::aggregates
