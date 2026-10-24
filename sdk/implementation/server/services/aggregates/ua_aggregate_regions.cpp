// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_regions.h"

namespace ua::server::aggregates
{

namespace
{

/// Effective quality of a raw sample (TreatUncertainAsBad folds Uncertain->Bad).
RegionQuality effective_quality(const Sample& sample, const CalcConfig& cfg)
{
  if (sample.is_bad() || !sample.hasNumeric)
    return RegionQuality::Bad;
  if (sample.is_uncertain())
    return cfg.treatUncertainAsBad ? RegionQuality::Bad : RegionQuality::Uncertain;
  return RegionQuality::Good;
}

/// Effective quality of a (simple/interpolated) bounding value.
RegionQuality bound_quality(const BoundValue& bound, const CalcConfig& cfg)
{
  if (!bound.hasValue)
    return RegionQuality::Bad;
  if (bound.status.is_bad())
    return RegionQuality::Bad;
  if (bound.status.is_uncertain())
    return cfg.treatUncertainAsBad ? RegionQuality::Bad : RegionQuality::Uncertain;
  return RegionQuality::Good;
}

/// Quality of the FIRST region of an interval (from the interval start to the
/// first data point inside it). Validated against Figures 2/3 + the worked
/// examples; the prose's "ends in a Bad/Uncertain value" only applies to this
/// bound-anchored region, not to interior regions.
///   - Stepped: the value is held from the predecessor, with its own status; an
///     Uncertain predecessor yields an Uncertain region (it is NOT folded to Bad
///     by TreatUncertainAsBad - only the StatusCode roll-up groups it).
///   - Sloped: a line is drawn from the predecessor to the first inside point.
///     A predecessor that is Bad (or Uncertain when TreatUncertainAsBad) gives a
///     Bad region (you cannot slope from it); otherwise sloping toward a non-Good
///     first inside point downgrades the region to Uncertain.
RegionQuality first_region_quality(
  const Sample& predecessor, const Sample* firstInside, const CalcConfig& cfg)
{
  if (cfg.stepped)
  {
    if (predecessor.is_bad() || !predecessor.hasNumeric)
      return RegionQuality::Bad;
    if (predecessor.is_uncertain())
      return RegionQuality::Uncertain;  // held value is Uncertain; not folded here
    return RegionQuality::Good;
  }
  // Sloped interpolation.
  if (treated_as_bad(predecessor, cfg))
    return RegionQuality::Bad;  // cannot slope from a Bad / Uncertain-as-Bad value
  const RegionQuality predecessorQuality =
    predecessor.is_uncertain() ? RegionQuality::Uncertain : RegionQuality::Good;
  if (firstInside != nullptr && (treated_as_bad(*firstInside, cfg) || firstInside->is_uncertain()))
    return predecessorQuality == RegionQuality::Bad ? RegionQuality::Bad : RegionQuality::Uncertain;
  return predecessorQuality;
}

}  // namespace

double RegionSet::good_ms() const
{
  double total = 0.0;
  for (const auto& region : regions)
    if (region.quality == RegionQuality::Good)
      total += region.duration_ms();
  return total;
}

double RegionSet::bad_ms() const
{
  double total = 0.0;
  for (const auto& region : regions)
    if (region.quality == RegionQuality::Bad)
      total += region.duration_ms();
  return total;
}

double RegionSet::uncertain_ms() const
{
  double total = 0.0;
  for (const auto& region : regions)
    if (region.quality == RegionQuality::Uncertain)
      total += region.duration_ms();
  return total;
}

RegionSet build_regions(const TimeSlice& slice, const CalcConfig& cfg)
{
  RegionSet result;
  if (slice.samples == nullptr)
    return result;
  const std::vector<Sample>& samples = *slice.samples;

  const int64_t unitTicks = seconds_to_ticks(cfg.timeResolutionSeconds);

  const DateTime regionStart = slice.start;
  // When the interval extends past the end of the data, calculations use the
  // time immediately after the last data point (5.4.2.4); the region span is
  // therefore reduced to lastDataTime + one server time unit.
  DateTime regionEnd = slice.end;
  if (slice.straddlesEndOfData)
    regionEnd = DateTime{slice.lastDataTime.value() + datetime::OneHundredNanoSeconds{unitTicks}};

  // Locate the sample exactly at the start, the predecessor (latest before the
  // start), and the first sample strictly inside the (effective) interval.
  const Sample* exact = nullptr;
  const Sample* predecessor = nullptr;
  const Sample* firstInside = nullptr;
  for (const auto& sample : samples)
  {
    if (sample.time == regionStart)
      exact = &sample;
    else if (sample.time < regionStart)
      predecessor = &sample;  // samples are ascending, so the last match is the closest
    else if (sample.time < regionEnd && firstInside == nullptr)
      // The == and < branches above already established sample.time > regionStart.
      firstInside = &sample;
  }

  // The first region's left boundary quality comes from the exact value at the
  // start, else the predecessor (held/sloped); its VALUE comes from the simple
  // bound (interpolated for sloped, held for stepped) so the area integration is
  // correct, falling back to the raw exact/predecessor value.
  RegionQuality leftQuality = RegionQuality::Bad;
  double leftValue = 0.0;
  bool leftHasValue = false;
  if (exact != nullptr)
    leftQuality = effective_quality(*exact, cfg);
  else if (predecessor != nullptr)
    leftQuality = first_region_quality(*predecessor, firstInside, cfg);
  if (slice.startBound.hasValue)
  {
    leftValue = slice.startBound.numeric;
    leftHasValue = true;
  }
  else if (exact != nullptr && exact->hasNumeric)
  {
    leftValue = exact->numeric;
    leftHasValue = true;
  }
  else if (predecessor != nullptr && predecessor->hasNumeric)
  {
    leftValue = predecessor->numeric;
    leftHasValue = true;
  }

  DateTime cursor = regionStart;
  auto emit = [&](
                const DateTime& segmentEnd, RegionQuality rightQuality, double rightValue, bool rightHasValue)
  {
    Region region;
    region.start = cursor;
    region.end = segmentEnd;
    region.quality = leftQuality;  // a region takes its left boundary's quality
    region.rightQuality = rightQuality;
    region.leftValue = leftValue;
    region.hasLeftValue = leftHasValue;
    region.rightValue = rightValue;
    region.hasRightValue = rightHasValue;
    result.regions.push_back(region);
    cursor = segmentEnd;
  };

  for (const auto& sample : samples)
  {
    // Interior boundaries are the raw samples strictly inside [regionStart, regionEnd).
    if (!(regionStart < sample.time) || !(sample.time < regionEnd))
      continue;
    emit(sample.time, effective_quality(sample, cfg), sample.numeric, sample.hasNumeric);
    leftQuality = effective_quality(sample, cfg);
    leftValue = sample.numeric;
    leftHasValue = sample.hasNumeric;
  }
  // The final region runs to the (effective) interval end; its right boundary is
  // the end bound (value + quality), used by the trapezoid integration.
  emit(regionEnd, bound_quality(slice.endBound, cfg), slice.endBound.numeric, slice.endBound.hasValue);

  result.widthMs = seconds_between(regionStart, regionEnd) * 1000.0;
  return result;
}

Status percent_time_status(
  double goodMs, double badMs, double uncertainMs, double widthMs, const CalcConfig& cfg)
{
  // Group the Uncertain duration with Bad or Good (5.4.3.2.1).
  if (cfg.treatUncertainAsBad)
    badMs += uncertainMs;
  else
    goodMs += uncertainMs;

  if (badMs <= 0.0)
    return Status::Good;  // no Bad regions in the interval
  if (widthMs <= 0.0)
    return Status::Good;

  const double badRatio = badMs / widthMs * 100.0;
  const double goodRatio = goodMs / widthMs * 100.0;
  const int percentGood = static_cast<int>(cfg.percentDataGood);
  const int percentBad = static_cast<int>(cfg.percentDataBad);

  // OPC 10000-13 4.2.1.2 (errata 6227): PercentDataGood >= 100 - PercentDataBad,
  // and "if they are equal the result of the PercentDataGood calculation is used".
  // At the equal-thresholds boundary the Good test governs, so a Good shortfall
  // yields Uncertain rather than Bad (e.g. 40% Good / 60% Bad with 50/50 thresholds).
  if (percentGood == 100 - percentBad)
    return goodRatio >= percentGood ? Status::Good : Status::UncertainDataSubNormal;

  if (badRatio >= percentBad)
    return Status::Bad;
  if (goodRatio >= percentGood)
    return Status::Good;
  return Status::UncertainDataSubNormal;
}

Status percent_time_severity(const RegionSet& regions, const CalcConfig& cfg)
{
  return percent_time_status(
    regions.good_ms(), regions.bad_ms(), regions.uncertain_ms(), regions.widthMs, cfg);
}

}  // namespace ua::server::aggregates
