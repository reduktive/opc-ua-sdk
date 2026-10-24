// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Worst-quality aggregate family (OPC 10000-13 5.4.3.35-5.4.3.36, Tables
/// 46-47): WorstQuality and WorstQuality2.
///
/// Both return the worst StatusCode of the values in the interval AS THE VALUE,
/// ranking Bad worse than Uncertain worse than Good; TreatUncertainAsBad is
/// ignored for the ranking (an Uncertain value ranks Uncertain, not Bad). When
/// several values share the worst quality the MultipleValues bit is set and the
/// StatusCode of the first (earliest) such value is returned. The aggregate's own
/// StatusCode is always Good, Calculated (with Partial for an incomplete
/// interval); before/after the data it is Bad_NoData with no value.
///
/// WorstQuality uses the raw values only. WorstQuality2 additionally includes the
/// Simple Bounding Values at both edges of the interval (3.1.9). The 3.1.9
/// bound status is computed ignoring TreatUncertainAsBad, matching the WorstQuality
/// "ignore TreatUncertainAsBad" rule and errata 6160 (which corrected Historian3).

#include "ua_aggregate_support.h"
#include "ua_aggregator_factories.h"

#include "ua_object_id.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <algorithm>
#include <vector>

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

/// Quality rank used to find the worst StatusCode: Bad (incl. Bad_NoData) worst,
/// then Uncertain, then Good. TreatUncertainAsBad is deliberately ignored.
int quality_rank(const StatusCode& status)
{
  if (status.is_bad())
    return 2;
  if (status.is_uncertain())
    return 1;
  return 0;
}

// ---- WorstQuality (2364, Table 46) / WorstQuality2 (11292, Table 47) -------
class WorstQualityAggregator final : public Aggregator
{
public:
  explicit WorstQualityAggregator(bool includeBounds) : mIncludeBounds(includeBounds)
  {}

  AggregateDescriptor descriptor() const override
  {
    AggregateDescriptor descriptor;
    descriptor.useBounds = BoundsKind::None;  // WorstQuality2 computes its own 3.1.9 bounds
    descriptor.timestamp = TimestampRule::IntervalStart;
    descriptor.resultType = ResultType::StatusCodeValue;
    descriptor.calcMethod = CalcMethod::Custom;  // the aggregate status is always Good
    descriptor.partial = BitUsage::SetSometimes;
    descriptor.multiValue = BitUsage::SetSometimes;
    return descriptor;
  }

  AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const override
  {
    if (slice.outside_data())
      return no_value(Status::BadNoData);  // before / after the data (Tables 46-47)

    // Candidates in time order: the start bound (WorstQuality2), each raw value
    // in the interval, then the end bound (WorstQuality2). Each contributes its
    // StatusCode; the first at the worst rank wins on a tie.
    struct Candidate
    {
      uint32_t code;
    };

    std::vector<Candidate> candidates;

    // The 3.1.9 Simple Bounding Values ignore TreatUncertainAsBad here.
    CalcConfig boundCfg = ctx.cfg;
    boundCfg.treatUncertainAsBad = false;
    if (mIncludeBounds && slice.samples != nullptr)
      candidates.push_back({simple_bound(*slice.samples, slice.start, boundCfg).status.value()});
    for (const Sample* sample : window_samples(slice))
      candidates.push_back({sample->status.value()});
    if (mIncludeBounds && slice.samples != nullptr)
      candidates.push_back({simple_bound(*slice.samples, slice.end, boundCfg).status.value()});

    if (candidates.empty())
      return no_value(Status::BadNoData);

    int worstRank = 0;
    for (const Candidate& candidate : candidates)
      worstRank = std::max(worstRank, quality_rank(StatusCode{candidate.code}));

    uint32_t worstCode = 0;
    int worstCount = 0;
    bool found = false;
    for (const Candidate& candidate : candidates)
    {
      if (quality_rank(StatusCode{candidate.code}) != worstRank)
        continue;
      if (!found)
      {
        worstCode = candidate.code;  // the first (earliest) value at the worst rank
        found = true;
      }
      ++worstCount;
    }

    AggregateResult result;
    result.hasValue = true;
    result.value = Variant{StatusCode{worstCode}};
    result.severity = Status::Good;  // the aggregate status is always Good
    result.dataLocation = DataLocation::Calculated;
    // A non-Good worst quality shared by several values sets the MultipleValues
    // bit (the worked examples never flag multiple Good values).
    result.multipleValues = worstRank != 0 && worstCount > 1;
    return result;
  }

private:
  bool mIncludeBounds;
};

}  // namespace

void register_quality_aggregators(AggregatorMap& map)
{
  using Id = ObjectId;
  map.emplace(utils::to_underlying(Id::AggregateFunction_WorstQuality),
    std::make_unique<WorstQualityAggregator>(/*includeBounds=*/false));
  map.emplace(utils::to_underlying(Id::AggregateFunction_WorstQuality2),
    std::make_unique<WorstQualityAggregator>(/*includeBounds=*/true));
}

}  // namespace ua::server::aggregates
