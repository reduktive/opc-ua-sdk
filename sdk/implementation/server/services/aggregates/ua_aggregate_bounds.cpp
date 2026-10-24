// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_bounds.h"

#include <cmath>
#include <optional>

namespace ua::server::aggregates
{

namespace
{

double line_fit(
  const DateTime& tBefore, double vBefore, const DateTime& tAfter, double vAfter, const DateTime& t)
{
  const double span = seconds_between(tBefore, tAfter);
  if (span == 0.0)
    return vBefore;
  // std::lerp is errno-free and monotonic, and handles extrapolation (the
  // interpolation fraction may fall outside [0,1] past the data).
  return std::lerp(vBefore, vAfter, seconds_between(tBefore, t) / span);
}

// Index of an exact-time sample, or nullopt.
std::optional<size_t> index_at(const std::vector<Sample>& s, const DateTime& t)
{
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i].time == t)
      return i;
  return std::nullopt;
}

}  // namespace

bool treated_as_bad(const Sample& sample, const CalcConfig& cfg)
{
  if (sample.is_bad() || !sample.hasNumeric)
    return true;
  if (cfg.treatUncertainAsBad && sample.is_uncertain())
    return true;
  return false;
}

BoundValue interpolated_bound(const std::vector<Sample>& s, const DateTime& t, const CalcConfig& cfg)
{
  BoundValue result;

  // 1. A non-Bad value exactly at t wins, returned as a raw value.
  if (auto exact = index_at(s, t); exact && !treated_as_bad(s[*exact], cfg))
  {
    const Sample& sample = s[*exact];
    result.hasValue = true;
    result.numeric = sample.numeric;
    result.raw = sample.raw;
    result.isRaw = true;
    // A raw value at the boundary is returned with its OWN status (Raw bit).
    result.status = StatusCode{sample.status.value() | static_cast<uint32_t>(HistorianBit::Raw)};
    return result;
  }

  // 2. First non-Bad before / after, plus the second non-Bad before (for sloped
  //    extrapolation). Track whether any Bad sample was skipped between anchors.
  std::optional<size_t> before, secondBefore, after;
  for (size_t i = 0; i < s.size(); ++i)
  {
    if (treated_as_bad(s[i], cfg))
      continue;
    if (s[i].time < t)
    {
      secondBefore = before;
      before = i;
    }
    else if (s[i].time > t && !after)
    {
      after = i;
    }
  }

  if (!before)
  {
    result.status = aggregate_status(Status::BadNoData);
    return result;  // hasValue stays false
  }

  // Any effective-Bad sample skipped between the before anchor and t/after?
  auto badBetween = [&](const DateTime& lo, const DateTime& hi)
  {
    for (const auto& sample : s)
      if (lo < sample.time && sample.time < hi && treated_as_bad(sample, cfg))
        return true;
    return false;
  };

  const Sample& b = s[*before];
  bool uncertain = b.is_uncertain();

  if (cfg.stepped)
  {
    // Stepped interpolation: hold the value of the first non-Bad before t.
    result.numeric = b.numeric;
    result.raw = b.raw;
    if (badBetween(b.time, t))
      uncertain = true;
    // Past the end of data => extrapolation, always Uncertain.
    if (!after && !s.empty() && s.back().time < t)
      uncertain = true;
    result.hasValue = true;
    result.status =
      aggregate_status(uncertain ? Status::UncertainDataSubNormal : Status::Good, HistorianBit::Interpolated);
    return result;
  }

  // Sloped interpolation.
  if (after)
  {
    const Sample& a = s[*after];
    result.numeric = line_fit(b.time, b.numeric, a.time, a.numeric, t);
    if (a.is_uncertain())
      uncertain = true;
    if (badBetween(b.time, a.time))
      uncertain = true;
    result.hasValue = true;
    result.status =
      aggregate_status(uncertain ? Status::UncertainDataSubNormal : Status::Good, HistorianBit::Interpolated);
    return result;
  }

  // No non-Bad value after t => extrapolate; always Uncertain (3.1.8).
  if (cfg.useSlopedExtrapolation && secondBefore)
  {
    const Sample& sb = s[*secondBefore];
    result.numeric = line_fit(sb.time, sb.numeric, b.time, b.numeric, t);
  }
  else
  {
    result.numeric = b.numeric;  // stepped extrapolation: hold last non-Bad value
  }
  result.hasValue = true;
  result.status = aggregate_status(Status::UncertainDataSubNormal, HistorianBit::Interpolated);
  return result;
}

BoundValue simple_bound(const std::vector<Sample>& s, const DateTime& t, const CalcConfig& cfg)
{
  // TreatUncertainAsBad governs whether an Uncertain sample counts as Bad in the
  // bound search (3.1.7); UseSlopedExtrapolation does not apply to Simple bounds.
  BoundValue result;

  // Any raw value exactly at t wins (Bad - incl. Uncertain when TUAB - => Bad_NoData).
  if (auto exact = index_at(s, t))
  {
    const Sample& sample = s[*exact];
    if (treated_as_bad(sample, cfg))
    {
      result.status = aggregate_status(Status::BadNoData);
      return result;
    }
    result.hasValue = true;
    result.numeric = sample.numeric;
    result.raw = sample.raw;
    result.isRaw = true;
    result.status = StatusCode{sample.status.value() | static_cast<uint32_t>(HistorianBit::Raw)};
    return result;
  }

  // Immediate predecessor / successor (regardless of quality).
  std::optional<size_t> before, after;
  for (size_t i = 0; i < s.size(); ++i)
  {
    if (s[i].time < t)
      before = i;
    else if (s[i].time > t && !after)
    {
      after = i;
      break;
    }
  }

  if (!before)
  {
    result.status = aggregate_status(Status::BadNoData);
    return result;
  }
  const Sample& b = s[*before];
  if (treated_as_bad(b, cfg))
  {
    result.status = aggregate_status(Status::BadNoData);
    return result;
  }
  if (!after)
  {
    // Beyond the last data point there is no Simple bound (3.1.9: the Server
    // may extrapolate or report no bound; we report no bound, matching the
    // "No Bound => Bad_NoData" disposition of the bound aggregates).
    result.status = aggregate_status(Status::BadNoData);
    return result;
  }

  bool uncertain = b.is_uncertain();
  if (cfg.stepped)
  {
    // Stepped: hold the before value.
    result.numeric = b.numeric;
  }
  else
  {
    const Sample& a = s[*after];
    if (treated_as_bad(a, cfg))
    {
      result.numeric = b.numeric;  // successor Bad => use the before value
      uncertain = true;
    }
    else
    {
      result.numeric = line_fit(b.time, b.numeric, a.time, a.numeric, t);
      if (a.is_uncertain())
        uncertain = true;
    }
  }
  result.hasValue = true;
  result.status =
    aggregate_status(uncertain ? Status::UncertainDataSubNormal : Status::Good, HistorianBit::Interpolated);
  return result;
}

}  // namespace ua::server::aggregates
