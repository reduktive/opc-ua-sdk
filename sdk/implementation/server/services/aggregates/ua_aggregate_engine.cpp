// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_engine.h"

#include <algorithm>
#include <cmath>

namespace ua::server::aggregates
{

std::vector<Sample> samples_from_data_values(const std::vector<DataValue>& raw)
{
  std::vector<Sample> samples;
  samples.reserve(raw.size());
  for (const auto& dataValue : raw)
  {
    Sample sample;
    const auto& sourceTimestamp = dataValue.source_timestamp();
    if (sourceTimestamp.has_value())
      sample.time = sourceTimestamp.value();
    sample.raw = dataValue.value();
    const auto& status = dataValue.status();
    if (status.has_value())
      sample.status = status.value();
    if (auto numeric = value_to_double(sample.raw))
    {
      sample.numeric = *numeric;
      sample.hasNumeric = true;
    }
    samples.push_back(std::move(sample));
  }
  std::stable_sort(
    samples.begin(), samples.end(), [](const Sample& a, const Sample& b) { return a.time < b.time; });
  return samples;
}

Variant source_template(const std::vector<Sample>& samples)
{
  for (const auto& sample : samples)
    if (sample.hasNumeric)
      return sample.raw;
  return Variant{};
}

namespace
{

std::vector<Sample> slice_inside(
  const std::vector<Sample>& samples, const DateTime& start, const DateTime& end)
{
  std::vector<Sample> inside;
  for (const auto& sample : samples)
    if (!(sample.time < start) && sample.time < end)  // start <= time < end
      inside.push_back(sample);
  return inside;
}

}  // namespace

std::vector<DataValue> run_aggregator(const Aggregator& aggregator, const std::vector<Sample>& samples,
  const IntervalSet& intervals, const AggregateContext& ctx)
{
  std::vector<DataValue> results;
  results.reserve(intervals.intervals.size());

  const AggregateDescriptor desc = aggregator.descriptor();
  const int64_t resolutionTicks = seconds_to_ticks(ctx.cfg.timeResolutionSeconds);

  // Data window: first/last samples carrying an actual value (a leading
  // Bad_NoData "point created" placeholder does not count as data).
  bool hasData = false;
  DateTime firstDataTime;
  DateTime lastDataTime;
  for (const auto& sample : samples)
  {
    if (!sample.hasNumeric)
      continue;
    if (!hasData)
    {
      firstDataTime = sample.time;
      hasData = true;
    }
    lastDataTime = sample.time;  // samples are sorted ascending
  }

  for (const auto& interval : intervals.intervals)
  {
    TimeSlice slice;
    slice.start = interval.start;
    slice.end = interval.end;
    slice.effectiveEnd = DateTime{interval.end.value() - datetime::OneHundredNanoSeconds{resolutionTicks}};
    slice.partial = interval.partial;
    slice.reverse = intervals.reverse;
    slice.inside = slice_inside(samples, interval.start, interval.end);
    slice.samples = &samples;

    slice.hasData = hasData;
    slice.firstDataTime = firstDataTime;
    slice.lastDataTime = lastDataTime;
    if (hasData)
    {
      slice.entirelyBeforeData = !(firstDataTime < interval.end);  // end <= firstDataTime
      slice.entirelyAfterData = lastDataTime < interval.start;  // start > lastDataTime
      slice.straddlesStartOfData = interval.start < firstDataTime && firstDataTime < interval.end;
      slice.straddlesEndOfData = !slice.entirelyBeforeData && !(lastDataTime < interval.start) &&
                                 lastDataTime < interval.end;  // reaches the last datum and extends past it
    }

    if (desc.useBounds == BoundsKind::Interpolated)
    {
      slice.startBound = interpolated_bound(samples, interval.start, ctx.cfg);
      slice.endBound = interpolated_bound(samples, interval.end, ctx.cfg);
    }
    else if (desc.useBounds == BoundsKind::Simple)
    {
      slice.startBound = simple_bound(samples, interval.start, ctx.cfg);
      slice.endBound = simple_bound(samples, interval.end, ctx.cfg);
    }

    const AggregateResult result = aggregator.compute(slice, ctx);

    // Assemble the historian info bits uniformly from the descriptor table
    // (OPC 10000-4 Table 181 / OPC 10000-13 Table 14). Bits qualify a value, so
    // they are only applied when the aggregate produced one.
    uint32_t bits = 0;
    // The Partial bit qualifies an incomplete interval and applies even when the
    // interval has no value (OPC 10000-13 5.3.3.2).
    if (desc.partial == BitUsage::SetSometimes && slice.incomplete())
      bits |= HistorianBit::Partial;
    if (result.hasValue)
    {
      switch (result.dataLocation)
      {
      case DataLocation::Raw:
        break;  // bits 00
      case DataLocation::Calculated:
        bits |= HistorianBit::Calculated;
        break;
      case DataLocation::Interpolated:
        bits |= HistorianBit::Interpolated;
        break;
      }
      if (desc.multiValue == BitUsage::SetSometimes && result.multipleValues)
        bits |= HistorianBit::MultipleValues;
    }
    else if (desc.calculated == BitUsage::SetAlways && result.severity != Status::BadNoData)
    {
      // Time-weighted aggregates set the Calculated bit even on a null result for
      // an interval that has data (e.g. an all-Bad interval => "Bad, Calculated").
      bits |= HistorianBit::Calculated;
    }
    const StatusCode status{utils::to_underlying(result.severity) | bits};

    DateTime timestamp = intervals.reverse ? interval.end : interval.start;
    if (desc.timestamp == TimestampRule::ValueTime && result.timestampOverride)
      timestamp = *result.timestampOverride;
    else if (desc.timestamp == TimestampRule::EffectiveEnd)
      timestamp = slice.effectiveEnd;

    results.push_back(DataValue{result.hasValue ? result.value : Variant{}, status, timestamp});
  }
  return results;
}

}  // namespace ua::server::aggregates
