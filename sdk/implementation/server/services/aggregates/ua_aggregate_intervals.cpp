// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_intervals.h"

#include <chrono>
#include <cmath>

namespace ua::server::aggregates
{

namespace
{

using Ticks = datetime::OneHundredNanoSeconds;  // 100ns resolution

// OPC Duration is milliseconds; convert to 100ns ticks with std::chrono::round
// (type-safe, errno-free) rather than an llround on a scaled double.
int64_t ms_to_ticks(Duration milliseconds)
{
  return std::chrono::round<Ticks>(std::chrono::duration<double, std::milli>{milliseconds}).count();
}

DateTime at(const DateTime& origin, int64_t ticks)
{
  return DateTime{origin.value() + Ticks{ticks}};
}

}  // namespace

IntervalSet generate_intervals(
  const DateTime& startTime, const DateTime& endTime, Duration processingIntervalMs, size_t maxIntervals)
{
  IntervalSet result;

  if (startTime == endTime)
  {
    result.invalid = true;
    return result;
  }

  const bool reverse = endTime < startTime;
  result.reverse = reverse;

  const DateTime lo = reverse ? endTime : startTime;
  const DateTime hi = reverse ? startTime : endTime;

  // The interval is peer-supplied: a NaN, an infinity or a negative value has no meaning, and
  // the rule is enforced here, whichever service path reaches the primitive.
  if (!std::isfinite(processingIntervalMs) || processingIntervalMs < 0.0)
  {
    result.invalid = true;
    return result;
  }

  const int64_t rangeTicks = (hi.value() - lo.value()).count();

  // ProcessingInterval == 0 or >= whole range => a single interval spanning the
  // request (Table 12, rows for Int=0 and Int>=Range). Decided in the double domain BEFORE the
  // conversion to ticks: a finite interval past the int64 tick range (about 9.2e14 ms) would
  // otherwise be an undefined double-to-integer conversion.
  constexpr double ticksPerMs = 10'000.0;  // 100 ns ticks
  if (processingIntervalMs == 0.0 || processingIntervalMs * ticksPerMs >= static_cast<double>(rangeTicks))
  {
    result.intervals.push_back(Interval{lo, hi, /*partial=*/false});
    return result;  // single interval; order is unaffected by direction
  }
  const int64_t intervalTicks = ms_to_ticks(processingIntervalMs);
  if (intervalTicks <= 0 || intervalTicks >= rangeTicks)
  {
    result.intervals.push_back(Interval{lo, hi, /*partial=*/false});
    return result;
  }

  const int64_t fullCount = rangeTicks / intervalTicks;
  const int64_t remainder = rangeTicks % intervalTicks;

  // Bound before allocating: the count is driven by three peer-supplied values and can reach 1e18.
  if (fullCount < 0 || static_cast<uint64_t>(fullCount) + (remainder > 0 ? 1u : 0u) > maxIntervals)
  {
    result.tooMany = true;
    return result;
  }

  std::vector<Interval> forward;
  forward.reserve(static_cast<size_t>(fullCount) + 1);
  for (int64_t k = 0; k < fullCount; ++k)
  {
    forward.push_back(Interval{at(lo, k * intervalTicks), at(lo, (k + 1) * intervalTicks), false});
  }
  if (remainder > 0)
  {
    // Uneven trailing "rest" interval (Table 12, footnote): shorter than the
    // others; the engine flags it Partial when data exists beyond the end.
    forward.push_back(Interval{at(lo, fullCount * intervalTicks), hi, /*partial=*/true});
  }

  if (!reverse)
  {
    result.intervals = std::move(forward);
  }
  else
  {
    // Reverse read: results are returned late-first.
    result.intervals.assign(forward.rbegin(), forward.rend());
  }
  return result;
}

}  // namespace ua::server::aggregates
