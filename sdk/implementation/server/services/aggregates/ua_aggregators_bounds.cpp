// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Bound aggregate family (OPC 10000-13 5.4.3.28-5.4.3.30, Tables 39-41):
/// StartBound, EndBound, DeltaBounds. All use Simple Bounding Values at the
/// interval edges (prepared by the engine) and are stamped at the interval start.

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
  result.severity = severity;
  return result;
}

AggregateDescriptor bound_descriptor()
{
  AggregateDescriptor d;
  d.useBounds = BoundsKind::Simple;
  d.timestamp = TimestampRule::IntervalStart;
  d.resultType = ResultType::SameAsSource;
  d.calcMethod = CalcMethod::Custom;
  d.partial = BitUsage::SetSometimes;
  return d;
}

// A raw bound keeps its source type; an interpolated bound is reported as a real.
Variant bound_value(const BoundValue& bound)
{
  return bound.isRaw ? bound.raw : Variant{bound.numeric};
}

// ---- StartBound (11505, Table 39) ----------------------------------------
// The Simple Bounding Value at the interval start, with its own status.
// Raw if a value exists exactly at the start, else Interpolated.
class StartBoundAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    return bound_descriptor();
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    if (slice.outside_data() || !slice.startBound.hasValue)
      return no_value(Status::BadNoData);

    AggregateResult result;
    result.hasValue = true;
    result.value = bound_value(slice.startBound);
    result.severity = slice.startBound.status.as_status();
    result.dataLocation = slice.startBound.isRaw ? DataLocation::Raw : DataLocation::Interpolated;
    return result;
  }
};

// ---- EndBound (11506, Table 40) ------------------------------------------
// The Simple Bounding Value at the interval end, with its status, but stamped at
// the interval start and always marked Calculated.
class EndBoundAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    return bound_descriptor();
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    if (slice.outside_data() || !slice.endBound.hasValue)
      return no_value(Status::BadNoData);

    AggregateResult result;
    result.hasValue = true;
    result.value = bound_value(slice.endBound);
    result.severity = slice.endBound.status.as_status();
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

// ---- DeltaBounds (11507, Table 41) ---------------------------------------
// EndBound value - StartBound value; both bounds must be Good for a Good result.
class DeltaBoundsAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    return bound_descriptor();
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    const BoundValue& startBound = slice.startBound;
    const BoundValue& endBound = slice.endBound;
    if (slice.outside_data() || !startBound.hasValue || !endBound.hasValue)
      return no_value(Status::BadNoData);
    if (startBound.status.is_bad() || endBound.status.is_bad())
      return no_value(Status::BadNoData);

    AggregateResult result;
    result.hasValue = true;
    // The bounds may be interpolated (fractional); report the difference with
    // full precision rather than coercing to the integer source type.
    result.value = Variant{endBound.numeric - startBound.numeric};
    result.severity = (startBound.status.is_uncertain() || endBound.status.is_uncertain())
                        ? Status::UncertainDataSubNormal
                        : Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

}  // namespace

void register_bound_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(
    utils::to_underlying(Id::AggregateFunction_StartBound), std::make_unique<StartBoundAggregator>());
  map.emplace(utils::to_underlying(Id::AggregateFunction_EndBound), std::make_unique<EndBoundAggregator>());
  map.emplace(
    utils::to_underlying(Id::AggregateFunction_DeltaBounds), std::make_unique<DeltaBoundsAggregator>());
}

}  // namespace ua::server::aggregates
