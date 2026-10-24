// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_ENGINE_H
#define UA_AGGREGATE_ENGINE_H

/// The shared driver that turns raw history into aggregated results: it builds
/// the per-interval TimeSlice (in-interval samples + bounds) and invokes an
/// Aggregator, then stamps each result's timestamp.

#include "ua_aggregate_intervals.h"
#include "ua_aggregator.h"
#include "ua_data_value.h"

namespace ua::server::aggregates
{

/// Reduce raw history DataValues to engine Samples (sorted ascending by source
/// timestamp; numeric projected; non-numeric/null flagged).
std::vector<Sample> samples_from_data_values(const std::vector<DataValue>& raw);

/// A representative non-null source Variant for "same as source" typing, or a
/// null Variant if none exists.
Variant source_template(const std::vector<Sample>& samples);

/// Run one aggregator across all intervals, returning one DataValue per interval
/// in result order.
std::vector<DataValue> run_aggregator(const Aggregator& aggregator, const std::vector<Sample>& samples,
  const IntervalSet& intervals, const AggregateContext& ctx);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_ENGINE_H
