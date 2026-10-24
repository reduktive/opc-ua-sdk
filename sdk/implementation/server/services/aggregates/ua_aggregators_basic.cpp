// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// The no-region "value/count" aggregate family (OPC 10000-13 5.4.3): they read
/// the samples inside an interval (and, for Interpolative, the interval's start
/// bound) without time-weighted region analysis. Each aggregator supplies only
/// its value + severity + data-location + condition flags; the engine assembles
/// the StatusCode historian bits from the descriptor (the spec summary table).

#include "ua_aggregate_support.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <numeric>

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

// ---- Interpolative (2341), Table 15 --------------------------------------
// Returns the Interpolated Bounding Value at the interval start. Custom severity
// (from the bound); Raw if an exact value exists, else Interpolated.
class InterpolativeAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor d;
    d.useBounds = BoundsKind::Interpolated;
    d.timestamp = TimestampRule::IntervalStart;
    d.resultType = ResultType::SameAsSource;
    d.calcMethod = CalcMethod::Custom;
    return d;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    const BoundValue& bound = slice.startBound;
    if (!bound.hasValue)
      return no_value(bound.status.as_status());

    AggregateResult result;
    result.hasValue = true;
    // An exact raw value keeps its source type; an interpolated value is a real
    // number reported with full precision (a fraction cannot fit an integer source).
    result.value = bound.isRaw ? bound.raw : Variant{bound.numeric};
    result.severity = bound.status.as_status();
    result.dataLocation = bound.isRaw ? DataLocation::Raw : DataLocation::Interpolated;
    return result;
  }
};

// ---- Average (2342), Table 16 --------------------------------------------
class AverageAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor d;
    d.resultType = ResultType::Double;
    d.calcMethod = CalcMethod::PercentValues;
    return d;  // Partial Not Set; Calculated always (via DataLocation::Calculated)
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const IntervalStats stats = classify(slice);
    if (stats.good == 0)
      return no_value(Status::BadNoData);

    const double sum = std::accumulate(stats.goodValues.begin(), stats.goodValues.end(), 0.0);
    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{sum / static_cast<double>(stats.good)};
    result.severity = percent_values_severity(stats, ctx.cfg);
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

// ---- Count (2352), Table 32 ----------------------------------------------
class CountAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor d;
    d.resultType = ResultType::Integer;
    d.calcMethod = CalcMethod::PercentValues;
    d.partial = BitUsage::SetSometimes;
    return d;  // Calculated always (via DataLocation::Calculated)
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);
    const IntervalStats stats = classify(slice);
    if (stats.total() == 0)
      return no_value(Status::BadNoData);

    const Status severity = percent_values_severity(stats, ctx.cfg);
    if (severity == Status::Bad)
      return no_value(Status::Bad);

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{static_cast<int32_t>(stats.good)};
    result.severity = severity;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

}  // namespace

void register_basic_aggregators(AggregatorMap& map)
{
  map.emplace(utils::to_underlying(ObjectId::AggregateFunction_Interpolative),
    std::make_unique<InterpolativeAggregator>());
  map.emplace(
    utils::to_underlying(ObjectId::AggregateFunction_Average), std::make_unique<AverageAggregator>());
  map.emplace(utils::to_underlying(ObjectId::AggregateFunction_Count), std::make_unique<CountAggregator>());
}

}  // namespace ua::server::aggregates
