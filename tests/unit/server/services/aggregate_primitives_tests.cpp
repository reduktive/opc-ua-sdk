// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the aggregate-calculator primitives: processing-interval
/// generation (OPC 10000-13 section 5.4.2.2) and Interpolated Bounding Values
/// (section 3.1.8). The bounding-value cases are validated against the canonical
/// AggregateExamples.csv "Interpolative / Historian1" worked example.

#include "ua_aggregate_bounds.h"
#include "ua_aggregate_engine.h"
#include "ua_aggregate_intervals.h"
#include "ua_aggregate_registry.h"
#include "ua_aggregate_types.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <gtest/gtest.h>
#include <limits>

using namespace ua;
using namespace ua::server::aggregates;

namespace
{

constexpr int64_t ticksPerSecond = 10'000'000;  // 100ns ticks

// Deterministic DateTime at `seconds` past the 100ns epoch.
DateTime at_second(int64_t seconds)
{
  return DateTime{std::chrono::sys_time<datetime::OneHundredNanoSeconds>{
    datetime::OneHundredNanoSeconds{seconds * ticksPerSecond}}};
}

Sample good(int64_t sec, double value)
{
  return Sample{at_second(sec), Variant{static_cast<int32_t>(value)}, StatusCode{Status::Good}, value, true};
}

Sample uncertain(int64_t sec, double value)
{
  return Sample{
    at_second(sec), Variant{static_cast<int32_t>(value)}, StatusCode{Status::Uncertain}, value, true};
}

Sample bad(int64_t sec, Status status)
{
  return Sample{at_second(sec), Variant{}, StatusCode{status}, 0.0, false};
}

// Historian1 from AggregateExamples.csv (Stepped=false, TreatUncertainAsBad=false,
// UseSlopedExtrapolation=false).
std::vector<Sample> historian1()
{
  return {bad(0, Status::BadNoData),
    good(10, 10),
    good(20, 20),
    good(30, 30),
    bad(40, Status::Bad),
    good(50, 50),
    good(60, 60),
    uncertain(70, 70),
    good(80, 80),
    good(90, 90)};
}

CalcConfig historian1_config()
{
  CalcConfig cfg;
  cfg.stepped = false;
  cfg.treatUncertainAsBad = false;
  cfg.useSlopedExtrapolation = false;
  return cfg;
}

}  // namespace

// ---- Interval generation -------------------------------------------------

TEST(AggregateIntervals, EvenDivisionProducesExactCount)
{
  auto set = generate_intervals(at_second(0), at_second(100), 5000.0);  // 5s interval
  EXPECT_FALSE(set.invalid);
  EXPECT_FALSE(set.reverse);
  ASSERT_EQ(set.intervals.size(), 20u);
  EXPECT_EQ(set.intervals.front().start, at_second(0));
  EXPECT_EQ(set.intervals.front().end, at_second(5));
  EXPECT_EQ(set.intervals.back().end, at_second(100));
  for (const auto& interval : set.intervals)
    EXPECT_FALSE(interval.partial);
}

// The interval count is driven by three peer-supplied values; it is bounded before any allocation.
// @relation(AC-SVR-HIST-AGG-025-PROCESSED-INTERVAL-COUNT-IS-BOUNDED, scope=function)
TEST(AggregateIntervals, MoreIntervalsThanTheCapAreRefusedBeforeAllocation)
{
  auto refused = generate_intervals(at_second(0), at_second(100), 5000.0, /*maxIntervals=*/10);
  EXPECT_TRUE(refused.tooMany);
  EXPECT_FALSE(refused.invalid);
  EXPECT_TRUE(refused.intervals.empty()) << "a refused request produces no intervals";

  auto within = generate_intervals(at_second(0), at_second(100), 5000.0, /*maxIntervals=*/20);
  EXPECT_FALSE(within.tooMany);
  ASSERT_EQ(within.intervals.size(), 20u) << "control: exactly the cap is admitted";

  auto remainderCounts = generate_intervals(at_second(0), at_second(101), 5000.0, /*maxIntervals=*/20);
  EXPECT_TRUE(remainderCounts.tooMany) << "the partial rest interval counts against the cap";
}

// The interval is peer-supplied: a NaN, an infinity or a negative value has no meaning and the
// primitive refuses it whichever service path reaches it; a finite value past the int64 tick range
// is one whole-range interval, decided before any double-to-integer conversion.
// @relation(AC-SVR-HIST-AGG-025-PROCESSED-INTERVAL-COUNT-IS-BOUNDED, scope=function)
TEST(AggregateIntervals, ANonFiniteOrNegativeIntervalIsInvalidAndAHugeFiniteOneIsOneInterval)
{
  for (const double interval : {std::numeric_limits<double>::quiet_NaN(),
         std::numeric_limits<double>::infinity(),
         -std::numeric_limits<double>::infinity(),
         -1.0})
  {
    auto set = generate_intervals(at_second(0), at_second(100), interval);
    EXPECT_TRUE(set.invalid) << interval;
    EXPECT_FALSE(set.tooMany) << interval;
    EXPECT_TRUE(set.intervals.empty()) << interval;
  }

  for (const double interval : {1e20, 1e300, std::numeric_limits<double>::max()})
  {
    auto set = generate_intervals(at_second(0), at_second(100), interval);
    EXPECT_FALSE(set.invalid) << interval;
    EXPECT_FALSE(set.tooMany) << interval;
    ASSERT_EQ(set.intervals.size(), 1u) << interval;
    EXPECT_EQ(set.intervals.front().start, at_second(0));
    EXPECT_EQ(set.intervals.front().end, at_second(100));
  }
}

// @relation(AC-SVR-HIST-AGG-026-CONSISTENCY, scope=function)

TEST(AggregateIntervals, UnevenRangeAddsPartialRemainder)
{
  auto set = generate_intervals(at_second(0), at_second(12), 5000.0);  // 5s into 12s
  ASSERT_EQ(set.intervals.size(), 3u);  // [0,5) [5,10) [10,12)
  EXPECT_FALSE(set.intervals[0].partial);
  EXPECT_FALSE(set.intervals[1].partial);
  EXPECT_TRUE(set.intervals[2].partial);
  EXPECT_EQ(set.intervals[2].start, at_second(10));
  EXPECT_EQ(set.intervals[2].end, at_second(12));
}

// @relation(AC-SVR-HIST-AGG-026-CONSISTENCY, scope=function)

TEST(AggregateIntervals, ZeroIntervalIsSingleSpan)
{
  auto set = generate_intervals(at_second(0), at_second(100), 0.0);
  ASSERT_EQ(set.intervals.size(), 1u);
  EXPECT_EQ(set.intervals[0].start, at_second(0));
  EXPECT_EQ(set.intervals[0].end, at_second(100));
}

// @relation(AC-SVR-HIST-AGG-026-CONSISTENCY, scope=function)

TEST(AggregateIntervals, IntervalLargerThanRangeIsSingleSpan)
{
  auto set = generate_intervals(at_second(0), at_second(100), 9'999'000.0);
  ASSERT_EQ(set.intervals.size(), 1u);
}

TEST(AggregateIntervals, EqualStartEndIsInvalid)
{
  auto set = generate_intervals(at_second(50), at_second(50), 5000.0);
  EXPECT_TRUE(set.invalid);
  EXPECT_TRUE(set.intervals.empty());
}

TEST(AggregateIntervals, ReverseReadReturnsLateFirst)
{
  auto set = generate_intervals(at_second(100), at_second(0), 5000.0);
  EXPECT_TRUE(set.reverse);
  ASSERT_EQ(set.intervals.size(), 20u);
  // late-first ordering: first emitted interval is the latest one
  EXPECT_EQ(set.intervals.front().start, at_second(95));
  EXPECT_EQ(set.intervals.front().end, at_second(100));
}

// ---- Interpolated bounding values vs the Historian1/Interpolative oracle --

namespace
{
struct ExpectedBound
{
  int64_t sec;
  bool hasValue;
  double value;
  uint32_t status;  // full StatusCode incl. historian bits
};

constexpr uint32_t goodRaw = 0x00000000U;
constexpr uint32_t goodInterp = 0x00000002U;
constexpr uint32_t uncertainRaw = 0x40000000U;  // generic Uncertain, raw
constexpr uint32_t uncertainSubInterp = 0x40A40002U;  // UncertainDataSubNormal + Interpolated
constexpr uint32_t badNoData = 0x809B0000U;
}  // namespace

TEST(AggregateInterpolatedBound, Historian1InterpolativeOracle)
{
  const auto samples = historian1();
  const auto cfg = historian1_config();

  const std::vector<ExpectedBound> expected = {
    {0, false, 0, badNoData},
    {5, false, 0, badNoData},
    {10, true, 10, goodRaw},
    {15, true, 15, goodInterp},
    {20, true, 20, goodRaw},
    {25, true, 25, goodInterp},
    {30, true, 30, goodRaw},
    {35, true, 35, uncertainSubInterp},  // 00:40 Bad skipped
    {40, true, 40, uncertainSubInterp},  // Bad exactly here, interpolated
    {45, true, 45, uncertainSubInterp},
    {50, true, 50, goodRaw},
    {55, true, 55, goodInterp},
    {60, true, 60, goodRaw},
    {65, true, 65, uncertainSubInterp},  // after anchor (70) is Uncertain
    {70, true, 70, uncertainRaw},  // exact raw Uncertain returned as-is
    {75, true, 75, uncertainSubInterp},  // before anchor (70) is Uncertain
    {80, true, 80, goodRaw},
    {85, true, 85, goodInterp},
    {90, true, 90, goodRaw},
    {95, true, 90, uncertainSubInterp},  // stepped extrapolation past end
  };

  for (const auto& exp : expected)
  {
    const BoundValue bound = interpolated_bound(samples, at_second(exp.sec), cfg);
    SCOPED_TRACE("interval second = " + std::to_string(exp.sec));
    EXPECT_EQ(bound.hasValue, exp.hasValue);
    if (exp.hasValue)
      EXPECT_DOUBLE_EQ(bound.numeric, exp.value);
    EXPECT_EQ(bound.status.value(), exp.status)
      << "got 0x" << std::hex << bound.status.value() << " want 0x" << exp.status;
  }
}

// ---- Result StatusCode quality roll-up -----------------------------------

namespace
{

// NS0 numeric identifiers of the aggregate functions exercised below.
constexpr uint32_t averageId = 2342;
constexpr uint32_t timeAverage2Id = 11285;
constexpr uint32_t worstQualityId = 2364;
constexpr uint32_t worstQuality2Id = 11292;

constexpr uint32_t severityMask = ~uint32_t{0x1F};  // drop the historian info bits
constexpr uint32_t uncertainSubNormal = 0x40A40000U;
constexpr uint32_t badSeverity = 0x80000000U;

uint32_t status_of(const DataValue& value)
{
  return value.status().has_value() ? value.status().value().value() : 0;
}

// Run the registered aggregator for `aggregateId` over the single processing
// interval [fromSec, toSec) of `samples`, through the real engine (bounds, data
// window and StatusCode assembly all come from production code).
std::vector<DataValue> run_single_interval(uint32_t aggregateId, const std::vector<Sample>& samples,
  int64_t fromSec, int64_t toSec, const CalcConfig& cfg)
{
  const Aggregator* aggregator = AggregatorRegistry::instance().find(NodeId{aggregateId});
  if (aggregator == nullptr)
    return {};
  const Duration intervalMs = static_cast<double>(toSec - fromSec) * 1000.0;
  const IntervalSet intervals = generate_intervals(at_second(fromSec), at_second(toSec), intervalMs);
  AggregateContext ctx;
  ctx.cfg = cfg;
  ctx.sourceTemplate = source_template(samples);
  return run_aggregator(*aggregator, samples, intervals, ctx);
}

// A series whose Bad data covers a large share of the interval TIME but only a
// small share of the sample COUNT: over [00:00, 01:40) the Bad region runs from
// 00:30 to 01:40 (70 s of 100 s = 70%), yet only one of the four samples in the
// interval is Bad (25%). Time-weighted and count-weighted status calculations
// therefore land on different severities for the same data.
std::vector<Sample> bad_region_series()
{
  return {good(0, 10), good(10, 10), good(20, 10), bad(30, Status::Bad), good(100, 10)};
}

// Thresholds chosen so the two calculations disagree: 70% Bad time crosses
// PercentDataBad (50) => Bad, while 75% Good count misses PercentDataGood (80)
// and 25% Bad count misses PercentDataBad => Uncertain.
CalcConfig bad_region_config()
{
  CalcConfig cfg;
  cfg.stepped = false;
  cfg.treatUncertainAsBad = false;
  cfg.useSlopedExtrapolation = false;
  cfg.percentDataBad = 50;
  cfg.percentDataGood = 80;
  return cfg;
}

}  // namespace

// @relation(AC-SVR-HIST-AGG-003-UNCERTAIN-POLICY, scope=function)
TEST(AggregateRestored, TreatUncertainAsBadChangesQualityClassification)
{
  const std::vector<Sample> samples = {good(0, 10), uncertain(10, 20), good(20, 30)};
  CalcConfig separate = historian1_config();
  separate.percentDataGood = 75;
  separate.percentDataBad = 50;
  separate.treatUncertainAsBad = false;
  CalcConfig folded = separate;
  folded.treatUncertainAsBad = true;

  const auto separateResult = run_single_interval(averageId, samples, 0, 20, separate);
  const auto foldedResult = run_single_interval(averageId, samples, 0, 20, folded);
  ASSERT_EQ(separateResult.size(), 1u);
  ASSERT_EQ(foldedResult.size(), 1u);
  EXPECT_EQ(status_of(separateResult.front()) & severityMask, uncertainSubNormal);
  EXPECT_EQ(status_of(foldedResult.front()) & severityMask, badSeverity);
}

// @relation(AC-SVR-HIST-AGG-004-INTERVAL-MATRIX, scope=function)
// @relation(AC-SVR-HIST-AGG-005-ZERO-INTERVAL, scope=function)
// @relation(AC-SVR-HIST-AGG-006-TIMESTAMP-RULE, scope=function)
TEST(AggregateRestored, IntervalGenerationAndTimestampsFollowPart13)
{
  const auto exact = generate_intervals(at_second(0), at_second(20), 5000.0);
  ASSERT_EQ(exact.intervals.size(), 4u);
  EXPECT_EQ(exact.intervals.front().start, at_second(0));
  EXPECT_EQ(exact.intervals.back().end, at_second(20));

  const auto uneven = generate_intervals(at_second(0), at_second(12), 5000.0);
  ASSERT_EQ(uneven.intervals.size(), 3u);
  EXPECT_FALSE(uneven.intervals[1].partial);
  EXPECT_TRUE(uneven.intervals[2].partial);
  EXPECT_EQ(uneven.intervals[2].start, at_second(10));
  EXPECT_EQ(uneven.intervals[2].end, at_second(12));

  const auto zero = generate_intervals(at_second(0), at_second(20), 0.0);
  ASSERT_EQ(zero.intervals.size(), 1u);
  EXPECT_EQ(zero.intervals[0].start, at_second(0));
  EXPECT_EQ(zero.intervals[0].end, at_second(20));

  const auto larger = generate_intervals(at_second(0), at_second(20), 25000.0);
  ASSERT_EQ(larger.intervals.size(), 1u);
  const auto reverse = generate_intervals(at_second(20), at_second(0), 5000.0);
  ASSERT_TRUE(reverse.reverse);
  ASSERT_EQ(reverse.intervals.size(), 4u);
  EXPECT_EQ(reverse.intervals.front().start, at_second(15));
  EXPECT_EQ(reverse.intervals.front().end, at_second(20));

  const std::vector<Sample> samples = {good(2, 20), good(10, 10), good(20, 30)};
  const auto average = run_single_interval(averageId, samples, 0, 20, historian1_config());
  const auto minimumActualTime = run_single_interval(2348, samples, 0, 20, historian1_config());
  ASSERT_EQ(average.size(), 1u);
  ASSERT_EQ(minimumActualTime.size(), 1u);
  ASSERT_TRUE(average.front().source_timestamp().has_value());
  ASSERT_TRUE(minimumActualTime.front().source_timestamp().has_value());
  EXPECT_EQ(*average.front().source_timestamp(), at_second(0));
  EXPECT_EQ(*minimumActualTime.front().source_timestamp(), at_second(10));
}

// @relation(AC-SVR-HIST-AGG-009-DATA-TYPES, scope=function)
// @relation(AC-SVR-HIST-AGG-010-LOCATION-BITS, scope=function)
// @relation(AC-SVR-HIST-AGG-011-PARTIAL, scope=function)
// @relation(AC-SVR-HIST-AGG-012-NO-DATA, scope=function)
// @relation(AC-SVR-HIST-AGG-013-SUBNORMAL, scope=function)
TEST(AggregateRestored, DataTypesAndHistorianBitsFollowDescriptors)
{
  const std::vector<Sample> numeric = {good(10, 10), good(20, 20), good(30, 30)};
  const auto average = run_single_interval(averageId, numeric, 10, 20, historian1_config());
  const auto count = run_single_interval(2352, numeric, 10, 20, historian1_config());
  const auto start = run_single_interval(2357, numeric, 10, 20, historian1_config());
  const auto duration = run_single_interval(11307, numeric, 10, 20, historian1_config());
  const auto worst = run_single_interval(worstQualityId, numeric, 10, 20, historian1_config());
  ASSERT_EQ(average.size(), 1u);
  ASSERT_EQ(count.size(), 1u);
  ASSERT_EQ(start.size(), 1u);
  ASSERT_EQ(duration.size(), 1u);
  ASSERT_EQ(worst.size(), 1u);
  EXPECT_TRUE(average.front().value().is_double());
  EXPECT_NE(count.front().value().try_as<int32_t>(), nullptr);
  EXPECT_NE(start.front().value().try_as<int32_t>(), nullptr);
  EXPECT_TRUE(duration.front().value().is_double());
  EXPECT_NE(worst.front().value().try_as<StatusCode>(), nullptr);

  const auto exactRaw = run_single_interval(2341, numeric, 10, 20, historian1_config());
  const auto interpolated = run_single_interval(2341, numeric, 15, 20, historian1_config());
  ASSERT_EQ(exactRaw.size(), 1u);
  ASSERT_EQ(interpolated.size(), 1u);
  EXPECT_EQ(status_of(exactRaw.front()) & 0x3u, HistorianBit::Raw);
  EXPECT_EQ(status_of(interpolated.front()) & 0x3u, HistorianBit::Interpolated);
  EXPECT_EQ(status_of(average.front()) & 0x3u, HistorianBit::Calculated);

  const std::vector<Sample> partialSamples = {good(0, 1), good(5, 2), good(7, 3)};
  const auto partialIntervals = generate_intervals(at_second(0), at_second(7), 5000.0);
  const Aggregator* countAggregator = AggregatorRegistry::instance().find(NodeId{2352u});
  ASSERT_NE(countAggregator, nullptr);
  AggregateContext context;
  context.cfg = historian1_config();
  context.sourceTemplate = source_template(partialSamples);
  const auto partialResults = run_aggregator(*countAggregator, partialSamples, partialIntervals, context);
  ASSERT_EQ(partialResults.size(), 2u);
  EXPECT_EQ(status_of(partialResults[0]) & HistorianBit::Partial, 0u);
  EXPECT_NE(status_of(partialResults[1]) & HistorianBit::Partial, 0u);

  const auto noData = run_single_interval(averageId, numeric, 0, 5, historian1_config());
  ASSERT_EQ(noData.size(), 1u);
  EXPECT_TRUE(noData.front().value().empty());
  EXPECT_EQ(status_of(noData.front()) & severityMask, StatusCode{Status::BadNoData}.value());

  const std::vector<Sample> mixed = {good(0, 10), bad(10, Status::Bad), good(20, 30)};
  CalcConfig thresholds = historian1_config();
  thresholds.percentDataGood = 80;
  thresholds.percentDataBad = 80;
  const auto subnormal = run_single_interval(averageId, mixed, 0, 20, thresholds);
  ASSERT_EQ(subnormal.size(), 1u);
  EXPECT_EQ(status_of(subnormal.front()) & severityMask, uncertainSubNormal);
}

// Part 13 5.4.3.2.1: an aggregate's StatusCode shall take into account the values
// used to calculate it, and a time-weighted aggregate shall weight that StatusCode
// by TIME, dividing the interval into Good/Bad regions. The arithmetic succeeds
// whatever the inputs' quality, so the plausible wrong implementation stamps Good
// on a result computed from partly-Bad data; the subtler one rolls the quality up
// by counting samples, which is right for Average and wrong for TimeAverage2.
// @verifies AC-SVR-HIST-AGG-029-STATUS-REFLECTS-INPUTS
TEST(AggregateResultStatus, StatusReflectsInputQualityAndIsTimeWeightedWhenTheAggregateIs)
{
  // (1) Count-based aggregate over an interval holding one Good and one Bad value.
  const std::vector<Sample> samples = historian1();
  const std::vector<DataValue> average = run_single_interval(averageId, samples, 30, 50, historian1_config());
  ASSERT_EQ(average.size(), 1u);
  const uint32_t averageStatus = status_of(average.front());
  EXPECT_FALSE(StatusCode{averageStatus}.is_good())
    << "Average over Good+Bad input reported Good: 0x" << std::hex << averageStatus;
  EXPECT_EQ(averageStatus & severityMask, uncertainSubNormal) << "got 0x" << std::hex << averageStatus;

  // (2) Time-weighted aggregate over an interval whose Bad region covers 70% of
  //     the elapsed time but only 25% of the samples.
  const std::vector<Sample> regionSamples = bad_region_series();
  const CalcConfig cfg = bad_region_config();
  const std::vector<DataValue> timeAverage2 = run_single_interval(timeAverage2Id, regionSamples, 0, 100, cfg);
  ASSERT_EQ(timeAverage2.size(), 1u);
  const uint32_t timeWeighted = status_of(timeAverage2.front());
  EXPECT_FALSE(StatusCode{timeWeighted}.is_good())
    << "TimeAverage2 over a 70%-Bad interval reported Good: 0x" << std::hex << timeWeighted;
  EXPECT_EQ(timeWeighted & severityMask, badSeverity)
    << "time-weighted status must follow the 70% Bad duration; got 0x" << std::hex << timeWeighted;
  EXPECT_FALSE(StatusCode{timeWeighted}.is_uncertain())
    << "Uncertain here is the sample-count answer, not the time-weighted one";

  // The control that makes (2) falsifiable: the same data and thresholds, scored
  // by sample count, give a different severity - so the Bad above can only have
  // come from weighting the interval by time.
  const std::vector<DataValue> countWeighted = run_single_interval(averageId, regionSamples, 0, 100, cfg);
  ASSERT_EQ(countWeighted.size(), 1u);
  EXPECT_EQ(status_of(countWeighted.front()) & severityMask, uncertainSubNormal)
    << "got 0x" << std::hex << status_of(countWeighted.front());
}

// Part 13 5.4.3.35 / 5.4.3.36: "The server shall ignore the TreatUncertainAsBad
// for this aggregate." An implementation that folds Uncertain into Bad in a shared
// preprocessing step is correct for every other aggregate and wrong here - it
// would report the worst quality as Bad when the data was merely Uncertain,
// defeating the entire point of the aggregate.
// @verifies AC-SVR-HIST-AGG-030-WORSTQUALITY-IGNORES-FLAG
TEST(AggregateWorstQuality, WorstQualityReportsUncertainWhicheverWayTreatUncertainAsBadIsSet)
{
  const std::vector<Sample> samples = historian1();

  // [01:00, 01:20) holds a Good value at 01:00 and an Uncertain value at 01:10;
  // the worst quality present is Uncertain.
  const std::vector<uint32_t> aggregates = {worstQualityId, worstQuality2Id};
  ASSERT_FALSE(aggregates.empty());

  for (const uint32_t aggregateId : aggregates)
  {
    SCOPED_TRACE("aggregate NS0 id = " + std::to_string(aggregateId));

    CalcConfig honest = historian1_config();
    honest.treatUncertainAsBad = false;
    CalcConfig folding = historian1_config();
    folding.treatUncertainAsBad = true;

    const std::vector<DataValue> flagClear = run_single_interval(aggregateId, samples, 60, 80, honest);
    const std::vector<DataValue> flagSet = run_single_interval(aggregateId, samples, 60, 80, folding);
    ASSERT_EQ(flagClear.size(), 1u);
    ASSERT_EQ(flagSet.size(), 1u);

    // The reported worst quality is Uncertain, not Bad, in both configurations.
    const StatusCode* clearWorst = flagClear.front().value().try_as<StatusCode>();
    const StatusCode* setWorst = flagSet.front().value().try_as<StatusCode>();
    ASSERT_NE(clearWorst, nullptr) << "WorstQuality* must return a StatusCode-typed value";
    ASSERT_NE(setWorst, nullptr) << "WorstQuality* must return a StatusCode-typed value";
    EXPECT_TRUE(clearWorst->is_uncertain()) << "got 0x" << std::hex << clearWorst->value();
    EXPECT_FALSE(clearWorst->is_bad()) << "got 0x" << std::hex << clearWorst->value();
    EXPECT_TRUE(setWorst->is_uncertain())
      << "TreatUncertainAsBad folded Uncertain into Bad: 0x" << std::hex << setWorst->value();
    EXPECT_FALSE(setWorst->is_bad()) << "got 0x" << std::hex << setWorst->value();
    EXPECT_EQ(clearWorst->value(), uncertainRaw) << "got 0x" << std::hex << clearWorst->value();
    EXPECT_EQ(setWorst->value(), uncertainRaw) << "got 0x" << std::hex << setWorst->value();

    // ... and the whole result - value and StatusCode alike - is identical either way.
    EXPECT_EQ(setWorst->value(), clearWorst->value());
    EXPECT_EQ(status_of(flagSet.front()), status_of(flagClear.front()))
      << "aggregate status differed: 0x" << std::hex << status_of(flagSet.front()) << " vs 0x"
      << status_of(flagClear.front());
  }
}
