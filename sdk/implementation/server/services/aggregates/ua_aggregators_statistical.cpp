// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Statistical aggregate family (OPC 10000-13 5.4.3.37-5.4.3.40, Tables 48-51):
/// StandardDeviation/Variance, Sample and Population. Computed over the Good raw
/// values in the interval; no bounds. Good when every in-window sample was Good,
/// Uncertain_DataSubNormal if any Bad/Uncertain sample was skipped (5.3 Table 9),
/// Bad_NoData when the interval has no Good data.

#include "ua_aggregate_support.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <cmath>
#include <numeric>

namespace ua::server::aggregates
{

namespace
{

class StatisticalAggregator final : public Aggregator
{
public:
  StatisticalAggregator(bool population, bool standardDeviation)
    : mPopulation(population), mStandardDeviation(standardDeviation)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor d;
    d.resultType = ResultType::Double;
    d.calcMethod = CalcMethod::Custom;  // aggregator supplies its own severity; engine does not roll it up
    d.partial = BitUsage::SetSometimes;
    return d;  // Calculated always (via DataLocation::Calculated)
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext&) const override
  {
    if (slice.outside_data())
      return failure();
    const IntervalStats stats = classify(slice);
    if (stats.good == 0)
      return failure();

    const double n = static_cast<double>(stats.good);
    const double sum = std::accumulate(stats.goodValues.begin(), stats.goodValues.end(), 0.0);
    const double mean = sum / n;
    double sumSquares = 0.0;
    for (const double value : stats.goodValues)
      sumSquares += (value - mean) * (value - mean);

    const double divisor = mPopulation ? n : (n - 1.0);
    const double variance = divisor > 0.0 ? sumSquares / divisor : 0.0;  // n==1 sample => 0

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{mStandardDeviation ? std::sqrt(variance) : variance};
    // Computed over the Good values only. Per OPC 10000-13 5.3 (Table 9) a value
    // derived with fewer than the required number of Good values is
    // Uncertain_DataSubNormal, so any skipped non-Good value (Bad or Uncertain)
    // downgrades the result; Good otherwise.
    result.severity = (stats.bad > 0 || stats.uncertain > 0) ? Status::UncertainDataSubNormal : Status::Good;
    result.dataLocation = DataLocation::Calculated;
    return result;
  }

private:
  static AggregateResult failure()
  {
    AggregateResult result;
    result.severity = Status::BadNoData;
    return result;
  }

  bool mPopulation;
  bool mStandardDeviation;
};

}  // namespace

void register_statistical_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_StandardDeviationSample),
    std::make_unique<StatisticalAggregator>(/*population=*/false, /*standardDeviation=*/true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_StandardDeviationPopulation),
    std::make_unique<StatisticalAggregator>(true, true));
  map.emplace(utils::to_underlying(Id::AggregateFunction_VarianceSample),
    std::make_unique<StatisticalAggregator>(false, false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_VariancePopulation),
    std::make_unique<StatisticalAggregator>(true, false));
}

}  // namespace ua::server::aggregates
