// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATOR_H
#define UA_AGGREGATOR_H

/// The `Aggregator` interface (one implementation per OPC 10000-13 aggregate)
/// plus the per-interval inputs/outputs the shared engine feeds them.

#include "ua_aggregate_bounds.h"
#include "ua_aggregate_types.h"

#include <optional>

namespace ua::server::aggregates
{

/// How the StatusCode severity is determined (OPC 10000-13 Table 14).
enum class CalcMethod
{
  PercentValues,  ///< severity from a percentage of value counts (5.3)
  PercentTime,  ///< severity from a percentage of the time interval (5.3)
  Custom  ///< aggregate-specific (the aggregator supplies the severity)
};

/// Per-bit usage from each aggregate's summary table (OPC 10000-13 Table 14),
/// for the two independent flag bits (Partial, MultiValue).
enum class BitUsage
{
  NotSet,  ///< the bit is never set
  SetSometimes,  ///< set under a condition the aggregator/engine evaluates
  SetAlways  ///< the bit is always set when a value is produced
};

/// The mutually-exclusive data-location of a result value (OPC 10000-4 Table 181
/// HistorianBits low two bits). Each aggregate chooses this per result, per the
/// conditions in its summary table (e.g. Minimum: Raw if on StartTime else Calculated).
enum class DataLocation
{
  Raw,  ///< an exact raw value (bits 00)
  Calculated,  ///< a computed value (bits 01)
  Interpolated  ///< an interpolated value (bits 10)
};

/// The spec's per-aggregate "summary table" (OPC 10000-13 Table 14), captured
/// declaratively. The engine reads this to prepare bounds, choose the timestamp,
/// and assemble the historian info bits uniformly - so no aggregate hand-rolls
/// its StatusCode bit layout.
struct AggregateDescriptor
{
  BoundsKind useBounds{BoundsKind::None};
  TimestampRule timestamp{TimestampRule::IntervalStart};
  ResultType resultType{ResultType::Double};
  CalcMethod calcMethod{CalcMethod::Custom};  ///< documents how severity is derived
  BitUsage partial{BitUsage::NotSet};  ///< Partial bit usage
  BitUsage multiValue{BitUsage::NotSet};  ///< MultiValue bit usage
  /// Calculated-bit usage when the aggregate produces NO value (time-weighted
  /// aggregates set "Calculated" even on a null Bad result for an in-data
  /// interval). When a value IS produced the bit comes from `dataLocation`.
  BitUsage calculated{BitUsage::NotSet};
};

/// One processing interval's worth of prepared inputs.
struct TimeSlice
{
  DateTime start;  ///< earliest edge (inclusive)
  DateTime end;  ///< latest edge (exclusive)
  DateTime effectiveEnd;  ///< end minus one server time unit (5.4.2.4)
  bool partial{false};  ///< uneven trailing interval (Partial-bit candidate)
  bool reverse{false};  ///< request direction was reverse
  std::vector<Sample> inside;  ///< samples with start <= time < end, ascending
  BoundValue startBound;  ///< valid when descriptor.useBounds != None
  BoundValue endBound;  ///< valid when descriptor.useBounds != None
  const std::vector<Sample>* samples{nullptr};  ///< the whole series (for the region engine)

  // Data-window context (OPC 10000-13 5.3.3.2). "Data" = samples with an actual
  // value (Good/Uncertain); the leading Bad_NoData placeholder does not count.
  bool hasData{false};  ///< any valued sample exists in the series
  DateTime firstDataTime;  ///< timestamp of the first valued sample
  DateTime lastDataTime;  ///< timestamp of the last valued sample
  bool entirelyBeforeData{false};  ///< interval ends at/before the first valued sample
  bool entirelyAfterData{false};  ///< interval starts at/after the last valued sample
  bool straddlesStartOfData{false};  ///< interval spans the first valued sample (=> Partial)
  bool straddlesEndOfData{false};  ///< interval extends past the last valued sample (=> Partial)

  /// Convenience: this interval lies wholly outside the available data.
  bool outside_data() const
  {
    return !hasData || entirelyBeforeData || entirelyAfterData;
  }

  /// Convenience: this interval is not a complete, full-length interval covered
  /// by data (straddles the start/end of data, or is the uneven trailing piece).
  bool incomplete() const
  {
    return partial || straddlesStartOfData || straddlesEndOfData;
  }
};

/// Per-request context shared by every interval of one aggregate run.
struct AggregateContext
{
  CalcConfig cfg;
  Variant sourceTemplate;  ///< a representative source Variant (for "same as source" typing)
};

/// An aggregate's output for one interval. The aggregator supplies the value and
/// the result severity (sub-code) plus a few condition flags; the engine assembles
/// the final StatusCode (severity + historian bits) from the descriptor table.
struct AggregateResult
{
  Variant value;  ///< the result value; ignored when !hasValue
  bool hasValue{false};  ///< false => no value (engine emits a null DataValue)
  Status severity{Status::Good};  ///< the result sub-code (Good/UncertainDataSubNormal/Bad/BadNoData/...)
  DataLocation dataLocation{DataLocation::Calculated};  ///< the value's data-location bits
  bool multipleValues{false};  ///< drives the MultiValue bit when multiValue == SetSometimes
  std::optional<DateTime> timestampOverride;  ///< used when descriptor.timestamp == ValueTime
};

/// Base class for every aggregate implementation.
class Aggregator
{
public:
  virtual ~Aggregator() = default;
  Aggregator(const Aggregator&) = delete;
  Aggregator& operator=(const Aggregator&) = delete;
  Aggregator(Aggregator&&) = delete;
  Aggregator& operator=(Aggregator&&) = delete;
  virtual AggregateDescriptor descriptor() const = 0;
  virtual AggregateResult compute(const TimeSlice& slice, const AggregateContext& ctx) const = 0;

protected:
  Aggregator() = default;
};

/// Build a Variant holding `numeric`, typed like `templateValue` (integers are
/// rounded). Falls back to Double when the template is null/non-numeric.
Variant numeric_like(const Variant& templateValue, double numeric);

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATOR_H
