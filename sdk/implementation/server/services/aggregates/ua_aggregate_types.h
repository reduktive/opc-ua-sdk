// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_TYPES_H
#define UA_AGGREGATE_TYPES_H

/// Internal data model + shared helpers for the Part-13 aggregate calculator.
///
/// The public facade is `ua_aggregate_calculator.h`. Everything here is an
/// implementation detail of the engine and the per-aggregate `Aggregator`
/// implementations. See OPC 10000-13 clause 5.4 for the normative model.

#include "ua_date_time.h"
#include "ua_duration.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace ua::server::aggregates
{

/// Historian info bits (OPC 10000-4 Table 181, HistorianBits, bits 0:4). The
/// low two bits are a mutually-exclusive data-location field; the upper three
/// are independent flags. These follow the reference-stack convention of living
/// in the low five bits of the StatusCode with no separate InfoType marker
/// (mirrors how this SDK already encodes the overflow bit).
enum HistorianBit : uint32_t
{
  Raw = 0x00,  ///< a raw data value (data-location = 00)
  Calculated = 0x01,  ///< a calculated value (data-location = 01)
  Interpolated = 0x02,  ///< an interpolated value (data-location = 10)
  Partial = 0x04,  ///< calculated over an incomplete interval
  ExtraData = 0x08,  ///< a raw value that hides other data at the same time
  MultipleValues = 0x10,  ///< multiple values matched the aggregate criteria
};

/// Build a result StatusCode from a base symbolic status + historian bits.
inline StatusCode aggregate_status(Status base, uint32_t historianBits = HistorianBit::Raw)
{
  return StatusCode{utils::to_underlying(base) | historianBits};
}

/// Project a numeric/boolean Variant onto a double. Returns nullopt for null,
/// non-scalar, or non-numeric values. Booleans map true->1.0, false->0.0.
std::optional<double> value_to_double(const Variant& variant);

/// A raw historical sample reduced for the engine. `raw` keeps the original
/// Variant so "Same as source" aggregates (Minimum/Start/End/...) can return it.
struct Sample
{
  DateTime time;
  Variant raw;
  StatusCode status;
  double numeric{0.0};  ///< numeric projection of `raw` (valid iff hasNumeric)
  bool hasNumeric{false};  ///< false when raw is null/non-numeric

  bool is_good() const
  {
    return status.is_good();
  }

  bool is_bad() const
  {
    return status.is_bad();
  }

  bool is_uncertain() const
  {
    return status.is_uncertain();
  }
};

/// How an aggregate sources its interval-boundary values (OPC 10000-13 3.1.7).
enum class BoundsKind
{
  None,  ///< only raw values strictly inside the interval are used
  Simple,  ///< Simple Bounding Values (immediate before/after, 3.1.9)
  Interpolated  ///< Interpolated Bounding Values (first non-Bad before/after, 3.1.8)
};

/// The timestamp an aggregate stamps onto its result (Table 14).
enum class TimestampRule
{
  IntervalStart,  ///< the (forward) start of the interval (default)
  ValueTime,  ///< the timestamp of the chosen raw value (ActualTime/Start/End)
  EffectiveEnd  ///< the effective end of the interval
};

/// Result value data type family (Table 13) - drives null/default handling.
enum class ResultType
{
  SameAsSource,  ///< Interpolative/Min/Max/Range/Start/End/Delta/*Bound
  Double,  ///< Average/TimeAverage*/Total*/Percent*/StdDev*/Variance*
  Integer,  ///< Count/NumberOfTransitions/AnnotationCount
  Duration,  ///< Duration* (milliseconds)
  StatusCodeValue  ///< WorstQuality*
};

/// Resolved per-call configuration (after applying server-capability defaults).
struct CalcConfig
{
  bool stepped{false};  ///< HistoricalConfiguration.Stepped
  bool treatUncertainAsBad{true};  ///< group Uncertain with Bad in the calc
  uint8_t percentDataBad{100};  ///< Bad-ratio threshold for a Bad result
  uint8_t percentDataGood{100};  ///< Good-ratio threshold for a Good result
  bool useSlopedExtrapolation{false};  ///< sloped (true) vs stepped (false) extrapolation
  /// Server time resolution used for EffectiveEndTime (5.4.2.4). Default 1ms.
  Duration timeResolutionSeconds{0.001};
};

/// One processing interval. `start`/`end` are ordered earliest..latest even for
/// reverse reads; `reverse` records the original request direction so result
/// timestamps and inclusion rules can be applied correctly.
struct Interval
{
  DateTime start;  ///< inclusive (earliest edge)
  DateTime end;  ///< exclusive (latest edge)
  bool partial{false};  ///< incomplete interval (Partial-bit candidate)
};

/// Whole-of-request boundary metadata derived from the available raw data.
struct DataWindow
{
  bool hasData{false};
  DateTime firstDataTime;  ///< timestamp of the earliest raw sample
  DateTime lastDataTime;  ///< timestamp of the latest raw sample
};

/// Seconds between two DateTimes (b - a), as a double.
inline double seconds_between(const DateTime& earlier, const DateTime& later)
{
  return std::chrono::duration<double>(later.value() - earlier.value()).count();
}

/// Convert a Duration in seconds to 100 ns ticks, rounded to the nearest tick.
/// Uses std::chrono::round (type-safe, errno-free, constexpr) rather than the
/// <cmath> rounding functions (llround/lround/rint), which interact with errno
/// and the floating-point environment.
inline int64_t seconds_to_ticks(double seconds)
{
  return std::chrono::round<datetime::OneHundredNanoSeconds>(std::chrono::duration<double>{seconds}).count();
}

/// Round a (possibly negative) value to the nearest integer, half away from
/// zero. A plain arithmetic cast - no errno / floating-point-environment side
/// effects (unlike std::llround), so the optimiser can fold it freely.
inline int64_t round_to_int64(double value)
{
  return static_cast<int64_t>(value + (value >= 0.0 ? 0.5 : -0.5));
}

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_TYPES_H
