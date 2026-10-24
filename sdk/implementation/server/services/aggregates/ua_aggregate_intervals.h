// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_INTERVALS_H
#define UA_AGGREGATE_INTERVALS_H

/// Processing-interval generation for the aggregate calculator
/// (OPC 10000-13 5.4.2.2, Table 12).

#include "ua_aggregate_types.h"

namespace ua::server::aggregates
{

/// The ordered set of processing intervals for one aggregate request.
struct IntervalSet
{
  std::vector<Interval> intervals;  ///< in result order (late-first when reverse)
  bool reverse{false};  ///< request had startTime > endTime
  bool invalid{false};  ///< startTime == endTime, or a non-finite / negative interval => Bad_InvalidArgument
  bool tooMany{false};  ///< the interval count exceeds `maxIntervals` => Bad_TooManyOperations
};

/// Upper bound on the intervals (one aggregate value each) a single ReadProcessed node may produce
/// when no per-node value cap is configured. Three peer-supplied values (start, end, interval)
/// otherwise drive an allocation of up to 1e18 entries.
inline constexpr size_t defaultMaxIntervals{1'000'000};

/// Divide [startTime, endTime] into processing intervals.
///
/// `processingIntervalMs` is the OPC Duration (milliseconds); 0 (or a value
/// >= the whole range) yields a single interval spanning the request. Intervals
/// are half-open: each includes its earliest edge and excludes its latest edge.
/// When the range is not an exact multiple of the interval a final short "rest"
/// interval holds the remainder. `startTime == endTime` sets `invalid`.
/// `maxIntervals` bounds the number of intervals (and so the values and the memory one node may
/// produce); a request that would exceed it sets `tooMany` and produces no intervals.
IntervalSet generate_intervals(const DateTime& startTime, const DateTime& endTime,
  Duration processingIntervalMs, size_t maxIntervals = defaultMaxIntervals);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_INTERVALS_H
