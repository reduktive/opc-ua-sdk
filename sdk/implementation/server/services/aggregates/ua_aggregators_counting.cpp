// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Counting aggregate family (OPC 10000-13 5.4.3.20, 5.4.3.24):
/// AnnotationCount and NumberOfTransitions.
///
/// NumberOfTransitions counts the value changes within an interval. Bad values
/// are excluded from the count; the earliest in-interval value is compared
/// against the last non-Bad value BEFORE the interval (the "Custom" bound, Table
/// 35). A change to a different value - or the first value when no prior non-Bad
/// value exists - is a transition; equal consecutive values are not. The
/// StatusCode is the non-time-based PercentValues calculation (5.3) over the
/// in-interval samples, and a Bad status yields a null value.
///
/// AnnotationCount (Table 31) counts all entries in the interval (any quality),
/// status Good unless the interval is outside the data. The aggregate is generic
/// over its input series: run over a variable's Annotations-property history it
/// counts annotations (its spec purpose); run over the value series it counts
/// raw values (as the OPC worked examples do). The turnkey HistoryRead path
/// feeds the value series today; feeding the Annotations-property history is a
/// follow-up in the read service.

#include "ua_aggregate_support.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <optional>

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

// ---- NumberOfTransitions (2355, Table 35) --------------------------------
class NumberOfTransitionsAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::None;  // the prior non-Bad value is located directly
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::Integer;  // Int32, never negative
    descriptor.calcMethod = CalcMethod::PercentValues;
    descriptor.partial = BitUsage::SetSometimes;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data() || slice.samples == nullptr)
      return no_value(Status::BadNoData);  // before / after the data (Table 35)

    const IntervalStats stats = classify(slice);
    const Status severity = percent_values_severity(stats, ctx.cfg);

    AggregateResult result;
    result.severity = severity;
    result.dataLocation = DataLocation::Calculated;
    // A Bad interval (one or more required values Bad) produces no count.
    if (severity == Status::Bad || severity == Status::BadNoData)
      return result;  // hasValue stays false (null value)

    // The previous non-Bad value before the interval (the Custom bound): the
    // latest such value, found by scanning the ascending series up to the start.
    std::optional<double> previous;
    for (const auto& sample : *slice.samples)
    {
      if (!(sample.time < slice.start))
        break;  // reached the interval; samples are ascending
      if (!treated_as_bad(sample, ctx.cfg))
        previous = sample.numeric;
    }

    // Walk the in-interval non-Bad values [start, end), counting changes. The
    // first value is a transition when it differs from the prior non-Bad value
    // (or when no prior value exists); equal consecutive values are not.
    int transitions = 0;
    for (const auto& sample : *slice.samples)
    {
      if (sample.time < slice.start || !(sample.time < slice.end))
        continue;
      if (treated_as_bad(sample, ctx.cfg))
        continue;
      if (!previous.has_value() || sample.numeric != *previous)
        ++transitions;
      previous = sample.numeric;
    }

    result.hasValue = true;
    result.value = Variant{static_cast<int32_t>(transitions)};
    return result;
  }
};

// ---- AnnotationCount (2351, Table 31) ------------------------------------
class AnnotationCountAggregator final : public Aggregator
{
public:
  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::None;
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::Integer;  // Int32, never negative
    descriptor.calcMethod = CalcMethod::Custom;  // Good unless outside the data
    descriptor.partial = BitUsage::SetSometimes;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);  // before / after the data (Table 31)

    AggregateResult result;
    result.hasValue = true;
    // Count every entry in the interval's data window, regardless of quality.
    result.value = Variant{static_cast<int32_t>(window_samples(slice).size())};
    result.severity = Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }
};

}  // namespace

void register_counting_aggregators(AggregatorMap& map)
{
  map.emplace(utils::to_underlying(ObjectId::AggregateFunction_NumberOfTransitions),
    std::make_unique<NumberOfTransitionsAggregator>());
  map.emplace(utils::to_underlying(ObjectId::AggregateFunction_AnnotationCount),
    std::make_unique<AnnotationCountAggregator>());
}

}  // namespace ua::server::aggregates
