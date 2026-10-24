// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATOR_FACTORIES_H
#define UA_AGGREGATOR_FACTORIES_H

/// Per-family registration hooks. Each family's translation unit defines one of
/// these; the registry constructor calls them all. Adding a family = add a file
/// + a hook here, no edit to the registry logic.

#include "ua_aggregator.h"

#include <memory>
#include <unordered_map>

namespace ua::server::aggregates
{

using AggregatorMap = std::unordered_map<uint32_t, std::unique_ptr<Aggregator>>;

/// Interpolative, Average, Count - bound/count aggregates.
void register_basic_aggregators(AggregatorMap& map);

/// Minimum/Maximum(+ActualTime), Range, Start/End, Delta - the no-region
/// data-variation and start/end family (no bounds).
void register_variation_aggregators(AggregatorMap& map);

/// StandardDeviation/Variance, Sample and Population.
void register_statistical_aggregators(AggregatorMap& map);

/// StartBound, EndBound, DeltaBounds - Simple-bounding-value aggregates.
void register_bound_aggregators(AggregatorMap& map);

/// DurationGood/Bad, PercentGood/Bad, DurationInStateZero/NonZero - the
/// time-weighted region-duration family (shared region engine).
void register_duration_aggregators(AggregatorMap& map);

/// TimeAverage/Total (interpolated bounds) and TimeAverage2/Total2 (simple
/// bounds) - the time-weighted average / total family.
void register_time_average_aggregators(AggregatorMap& map);

/// Minimum2/Maximum2(+ActualTime), Range2 - the simple-bound extreme family
/// (Simple bounds in the candidate set, PercentTime status).
void register_simple_bound_minmax_aggregators(AggregatorMap& map);

/// NumberOfTransitions - the counting family (value-change count, PercentValues).
void register_counting_aggregators(AggregatorMap& map);

/// WorstQuality/WorstQuality2 - the worst-quality family (StatusCode-valued).
void register_quality_aggregators(AggregatorMap& map);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATOR_FACTORIES_H
