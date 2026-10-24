// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_support.h"

namespace ua::server::aggregates
{

IntervalStats classify(const TimeSlice& slice)
{
  IntervalStats stats;
  if (!slice.hasData)
    return stats;

  for (const auto& sample : slice.inside)
  {
    // Only samples within the data window count; the leading Bad_NoData
    // placeholder (before firstDataTime) is "no data", not "bad data".
    if (sample.time < slice.firstDataTime || slice.lastDataTime < sample.time)
      continue;

    if (sample.is_bad() || !sample.hasNumeric)
    {
      ++stats.bad;
    }
    else if (sample.is_uncertain())
    {
      ++stats.uncertain;
      stats.uncertainValues.push_back(sample.numeric);
    }
    else
    {
      ++stats.good;
      stats.goodValues.push_back(sample.numeric);
      if (!stats.firstGood)
        stats.firstGood = &sample;
      stats.lastGood = &sample;
      if (!stats.minGood || sample.numeric < stats.minGood->numeric)
      {
        stats.minGood = &sample;
        stats.minGoodCount = 1;
      }
      else if (sample.numeric == stats.minGood->numeric)
      {
        ++stats.minGoodCount;
      }
      if (!stats.maxGood || sample.numeric > stats.maxGood->numeric)
      {
        stats.maxGood = &sample;
        stats.maxGoodCount = 1;
      }
      else if (sample.numeric == stats.maxGood->numeric)
      {
        ++stats.maxGoodCount;
      }
    }
  }
  return stats;
}

Status percent_values_severity(const IntervalStats& stats, const CalcConfig& cfg)
{
  const int total = stats.total();
  if (total == 0)
    return Status::BadNoData;

  // Uncertain is grouped with Bad only when TreatUncertainAsBad; otherwise it is
  // neutral (counts toward neither Good nor Bad ratios), leaving the result
  // Uncertain unless enough actual-Good values are present.
  const int badEff = stats.bad + (cfg.treatUncertainAsBad ? stats.uncertain : 0);

  // Good is evaluated first: the spec requires PercentDataGood >= 100 -
  // PercentDataBad, so the two thresholds can only both be met at the equality
  // boundary, where the PercentDataGood (Good) result is the one to use.
  if (100 * stats.good >= static_cast<int>(cfg.percentDataGood) * total)
    return Status::Good;
  if (100 * badEff >= static_cast<int>(cfg.percentDataBad) * total)
    return Status::Bad;
  return Status::UncertainDataSubNormal;
}

std::vector<const Sample*> window_samples(const TimeSlice& slice)
{
  std::vector<const Sample*> result;
  if (!slice.hasData)
    return result;
  for (const auto& sample : slice.inside)
    if (!(sample.time < slice.firstDataTime) && !(slice.lastDataTime < sample.time))
      result.push_back(&sample);
  return result;
}

}  // namespace ua::server::aggregates
