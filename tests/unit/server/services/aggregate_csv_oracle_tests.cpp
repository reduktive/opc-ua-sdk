// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Data-driven validation of the aggregate calculator against the OPC Foundation
/// canonical worked examples (AggregateExamples.csv): each implemented aggregate
/// is run over the Historian raw series and every interval's value + StatusCode
/// is asserted against the CSV. Aggregates not yet implemented are skipped, so
/// this test grows coverage automatically as families are added.

#include "ua_aggregate_engine.h"
#include "ua_aggregate_intervals.h"
#include "ua_aggregate_registry.h"
#include "ua_aggregate_types.h"

#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace ua;
using namespace ua::server::aggregates;

namespace
{

// ---- CSV + value/status parsing -----------------------------------------

std::vector<std::string> split_csv(const std::string& line)
{
  std::vector<std::string> fields;
  std::string field;
  bool inQuotes = false;
  for (char ch : line)
  {
    if (ch == '"')
      inQuotes = !inQuotes;
    else if (ch == ',' && !inQuotes)
    {
      fields.push_back(field);
      field.clear();
    }
    else
      field.push_back(ch);
  }
  fields.push_back(field);
  return fields;
}

std::string trim(std::string s)
{
  const auto notSpace = [](unsigned char c)
  {
    return !std::isspace(c);
  };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
  s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
  return s;
}

DateTime time_of_day(const std::string& text)
{
  int hh = 0, mm = 0, ss = 0, ms = 0;
  char dot = 0;
  std::istringstream in(text);
  in >> hh;
  in.ignore(1);  // ':'
  in >> mm;
  in.ignore(1);  // ':'
  in >> ss;
  if (in >> dot && dot == '.')
    in >> ms;
  const int64_t ticks =
    (static_cast<int64_t>(hh) * 3600 + mm * 60 + ss) * 10'000'000 + static_cast<int64_t>(ms) * 10'000;
  return DateTime{
    std::chrono::sys_time<datetime::OneHundredNanoSeconds>{datetime::OneHundredNanoSeconds{ticks}}};
}

// Parse a CSV value cell into a (Variant, numeric?) pair. Empty / "undefined" => null.
struct ParsedValue
{
  Variant variant;
  std::optional<double> numeric;
};

ParsedValue parse_value(const std::string& cell)
{
  const std::string text = trim(cell);
  if (text.empty() || text == "undefined")
    return {Variant{}, std::nullopt};
  if (text == "true")
    return {Variant{true}, 1.0};
  if (text == "false")
    return {Variant{false}, 0.0};
  try
  {
    size_t consumed = 0;
    const double numeric = std::stod(text, &consumed);
    if (consumed != text.size())
      return {Variant{}, std::nullopt};  // trailing junk => treat as non-numeric
    if (text.find('.') != std::string::npos)
      return {Variant{numeric}, numeric};
    return {Variant{static_cast<int32_t>(numeric)}, numeric};
  }
  catch (const std::exception&)
  {
    // Non-numeric value cell (e.g. WorstQuality's StatusCode-typed value).
    return {Variant{}, std::nullopt};
  }
}

uint32_t parse_status(const std::string& cell)
{
  uint32_t base = 0;
  uint32_t bits = 0;
  std::istringstream in(cell);
  std::string token;
  while (std::getline(in, token, ','))
  {
    const std::string t = trim(token);
    if (t == "Good")
      base = 0x00000000U;
    else if (t == "Uncertain")
      base = 0x40000000U;
    else if (t == "UncertainDataSubNormal")
      base = 0x40A40000U;
    else if (t == "Bad")
      base = 0x80000000U;
    else if (t == "BadNoData" || t == "Bad_NoData")
      base = 0x809B0000U;
    else if (t == "Calculated")
      bits |= 0x01U;
    else if (t == "Interpolated")
      bits |= 0x02U;
    else if (t == "Partial")
      bits |= 0x04U;
    else if (t == "ExtraData")
      bits |= 0x08U;
    else if (t == "MultipleValues")
      bits |= 0x10U;
    // "Raw" contributes 0; "No Data" handled by callers.
  }
  return base | bits;
}

// A value cell that names a StatusCode (WorstQuality* return a StatusCode as the
// value). Returns the base StatusCode, or nullopt when the cell is not a status
// symbol (numbers, booleans, empty cells fall through to the numeric/null paths).
std::optional<uint32_t> parse_status_value(const std::string& cell)
{
  const std::string text = trim(cell);
  if (text == "Good" || text == "Bad" || text == "Uncertain" || text == "BadNoData" || text == "Bad_NoData" ||
      text == "UncertainDataSubNormal")
    return parse_status(text);
  return std::nullopt;
}

// ---- CSV model -----------------------------------------------------------

struct RawSeries
{
  std::vector<Sample> samples;
};

struct ExpectedRow
{
  DateTime time;
  bool valueNull{true};
  double value{0.0};
  std::optional<uint32_t> statusValue;  ///< StatusCode-typed value (WorstQuality*)
  uint32_t status{0};
};

struct ProcessedBlock
{
  std::string aggregate;
  std::string historian;
  CalcConfig cfg;
  Duration intervalMs{0.0};
  std::vector<ExpectedRow> rows;
};

bool apply_config(const std::vector<std::string>& fields, CalcConfig& cfg, Duration& intervalMs)
{
  if (fields.size() < 2)
    return false;
  const std::string key = trim(fields[0]);
  const std::string value = trim(fields[1]);
  const bool boolVal = (value == "true");
  if (key == "Stepped")
    cfg.stepped = boolVal;
  else if (key == "Treat Uncertain as Bad")
    cfg.treatUncertainAsBad = boolVal;
  else if (key == "Percent Bad")
    cfg.percentDataBad = static_cast<uint8_t>(std::stoi(value));
  else if (key == "Percent Good")
    cfg.percentDataGood = static_cast<uint8_t>(std::stoi(value));
  else if (key == "Use Sloped Extrapolation")
    cfg.useSlopedExtrapolation = boolVal;
  else if (key == "Processing Interval")
    intervalMs = std::stod(value);
  else
    return false;
  return true;
}

struct CsvModel
{
  std::map<std::string, RawSeries> rawByName;
  std::vector<ProcessedBlock> processed;
};

CsvModel parse_csv(std::istream& in)
{
  CsvModel model;
  std::string line;
  enum class Section
  {
    None,
    Raw,
    Processed
  } section = Section::None;

  // Raw-series accumulation.
  std::string rawName;
  RawSeries rawSeries;
  CalcConfig rawCfg;
  Duration rawInterval = 0;
  bool inRawRows = false;

  // Processed-block accumulation.
  ProcessedBlock block;
  bool inProcRows = false;

  auto flushRaw = [&]()
  {
    if (!rawName.empty())
      model.rawByName[rawName] = rawSeries;
    rawName.clear();
    rawSeries = RawSeries{};
    inRawRows = false;
  };
  auto flushBlock = [&]()
  {
    if (!block.aggregate.empty() && !block.historian.empty() && !block.rows.empty())
      model.processed.push_back(block);
    block.rows.clear();
    block.historian.clear();
    inProcRows = false;
  };

  while (std::getline(in, line))
  {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const std::string trimmed = trim(line);

    if (trimmed == "Start of Raw Data Tables")
    {
      section = Section::Raw;
      continue;
    }
    if (trimmed == "End of Raw Data Tables")
    {
      flushRaw();
      section = Section::None;
      continue;
    }
    if (trimmed == "Start of Processed Data Tables")
    {
      section = Section::Processed;
      continue;
    }
    if (trimmed == "End of Processed Data Tables")
    {
      flushBlock();
      section = Section::None;
      continue;
    }
    if (trimmed.empty())
      continue;

    const auto fields = split_csv(line);

    if (section == Section::Raw)
    {
      if (trimmed.rfind("Historian", 0) == 0 && fields.size() == 1)
      {
        flushRaw();
        rawName = trimmed;
        continue;
      }
      if (trimmed.rfind("Timestamp,", 0) == 0)
      {
        inRawRows = true;
        continue;
      }
      CalcConfig ignoreCfg;
      Duration ignoreInterval = 0;
      if (apply_config(fields, ignoreCfg, ignoreInterval))
        continue;
      if (inRawRows)
      {
        const std::string ts = trim(fields[0]);
        if (ts.empty())  // trailing "No Data" row
          continue;
        ParsedValue parsed = parse_value(fields.size() > 1 ? fields[1] : "");
        const uint32_t status = parse_status(fields.size() > 2 ? fields[2] : "");
        Sample sample;
        sample.time = time_of_day(ts);
        sample.raw = parsed.variant;
        sample.status = StatusCode{status};
        if (parsed.numeric)
        {
          sample.numeric = *parsed.numeric;
          sample.hasNumeric = true;
        }
        rawSeries.samples.push_back(std::move(sample));
      }
      continue;
    }

    if (section == Section::Processed)
    {
      if (fields.size() >= 2 && trim(fields[0]) == "Aggregate")
      {
        flushBlock();
        block = ProcessedBlock{};
        block.aggregate = trim(fields[1]);
        continue;
      }
      if (trimmed.rfind("Historian", 0) == 0 && fields.size() == 1)
      {
        flushBlock();
        block.historian = trimmed;
        continue;
      }
      if (trimmed.rfind("Timestamp,", 0) == 0)
      {
        inProcRows = true;
        continue;
      }
      if (apply_config(fields, block.cfg, block.intervalMs))
        continue;
      if (inProcRows)
      {
        const std::string ts = trim(fields[0]);
        if (ts.empty())
          continue;
        ExpectedRow row;
        row.time = time_of_day(ts);
        const std::string valueCell = fields.size() > 1 ? fields[1] : "";
        ParsedValue parsed = parse_value(valueCell);
        if (parsed.numeric)
        {
          row.valueNull = false;
          row.value = *parsed.numeric;
        }
        else if (auto statusValue = parse_status_value(valueCell))
        {
          row.valueNull = false;
          row.statusValue = statusValue;
        }
        row.status = parse_status(fields.size() > 2 ? fields[2] : "");
        block.rows.push_back(row);
      }
      continue;
    }
  }
  flushBlock();
  return model;
}

}  // namespace

class AggregateCsvOracle : public ::testing::Test
{
protected:
  static CsvModel& model()
  {
    static CsvModel parsed = []
    {
      std::ifstream file("AggregateExamples.csv");
      EXPECT_TRUE(file.is_open()) << "AggregateExamples.csv must be copied next to the test binary";
      return parse_csv(file);
    }();
    return parsed;
  }
};

TEST_F(AggregateCsvOracle, CsvParsedAndRawSeriesPresent)
{
  ASSERT_GE(model().rawByName.size(), 3u);
  EXPECT_TRUE(model().rawByName.count("Historian1"));
  EXPECT_GT(model().processed.size(), 30u);
}

// @relation(AC-SVR-HIST-AGG-026-CONSISTENCY, scope=function)

// Covers SVR-HIST-AGG-001..023 (coverage-audit retag).
TEST_F(AggregateCsvOracle, ImplementedAggregatesMatchOracle)
{
  const auto& registry = AggregatorRegistry::instance();
  int blocksChecked = 0;
  std::map<std::string, int> coveredAggregates;

  for (const auto& block : model().processed)
  {
    // Map the CSV aggregate name to its NS0 NodeId via name; only run if implemented.
    static const std::map<std::string, uint32_t> nameToId = {{"Interpolative", 2341},
      {"Average", 2342},
      {"TimeAverage", 2343},
      {"Total", 2344},
      {"Minimum", 2346},
      {"Maximum", 2347},
      {"MinimumActualTime", 2348},
      {"MaximumActualTime", 2349},
      {"Range", 2350},
      {"AnnotationCount", 2351},
      {"Count", 2352},
      {"NumberOfTransitions", 2355},
      {"Start", 2357},
      {"End", 2358},
      {"Delta", 2359},
      {"DurationGood", 2360},
      {"DurationBad", 2361},
      {"PercentGood", 2362},
      {"PercentBad", 2363},
      {"WorstQuality", 2364},
      {"TimeAverage2", 11285},
      {"Minimum2", 11286},
      {"Maximum2", 11287},
      {"Range2", 11288},
      {"WorstQuality2", 11292},
      {"Total2", 11304},
      {"MinimumActualTime2", 11305},
      {"MaximumActualTime2", 11306},
      {"DurationInStateZero", 11307},
      {"DurationInStateNonZero", 11308},
      {"StandardDeviationSample", 11426},
      {"StandardDeviationPopulation", 11427},
      {"VarianceSample", 11428},
      {"VariancePopulation", 11429},
      {"StartBound", 11505},
      {"EndBound", 11506},
      {"DeltaBounds", 11507}};

    const auto idIt = nameToId.find(block.aggregate);
    if (idIt == nameToId.end())
      continue;
    const NodeId aggregateType{idIt->second};
    const Aggregator* aggregator = registry.find(aggregateType);
    if (!aggregator)
      continue;  // not yet implemented

    const auto rawIt = model().rawByName.find(block.historian);
    ASSERT_NE(rawIt, model().rawByName.end()) << block.historian;

    const auto& samples = rawIt->second.samples;
    // All worked examples use StartTime = 12:00:00. The per-row timestamp is the
    // interval start only for startTime-stamped aggregates; ValueTime aggregates
    // (ActualTime/Start/End) stamp the value's own time, so derive the request
    // start from the fixed StartTime, not the first row.
    const DateTime start = time_of_day("12:00:00.000");
    const DateTime end =
      DateTime{start.value() + datetime::OneHundredNanoSeconds{
                                 static_cast<int64_t>(block.rows.size()) *
                                 static_cast<int64_t>(std::llround(block.intervalMs * 10'000.0))}};

    const IntervalSet intervals = generate_intervals(start, end, block.intervalMs);
    ASSERT_EQ(intervals.intervals.size(), block.rows.size()) << block.aggregate << "/" << block.historian;

    AggregateContext ctx;
    ctx.cfg = block.cfg;
    ctx.sourceTemplate = source_template(samples);
    const std::vector<DataValue> results = run_aggregator(*aggregator, samples, intervals, ctx);
    ASSERT_EQ(results.size(), block.rows.size());

    for (size_t i = 0; i < block.rows.size(); ++i)
    {
      ExpectedRow expected = block.rows[i];
      const DataValue& actual = results[i];
      SCOPED_TRACE(block.aggregate + "/" + block.historian + " interval[" + std::to_string(i) + "]");

      // OPC 10000-13 errata 6160 corrected only Historian3 for WorstQuality2. The
      // Historian2 worked-example cells for intervals 4-5 retain the pre-errata
      // TreatUncertainAsBad folding of the Simple Bounding Value, which contradicts
      // section 3.1.9 (a before-Uncertain Simple Bound is Uncertain_DataSubNormal, not
      // Bad_NoData). The SDK follows section 3.1.9 / the errata rule (matching the
      // corrected Historian3 + Historian4), so assert the spec-faithful result for
      // these two known-defective worked-example cells rather than the CSV value.
      if (block.aggregate == "WorstQuality2" && block.historian == "Historian2")
      {
        if (i == 4)  // end Simple Bound is Uncertain (before=Uncertain t=01:10), shared with the raw
        {
          expected.statusValue = 0x40000000U;  // Uncertain (the raw value's StatusCode)
          expected.status = 0x00000011U;  // Good, Calculated, MultipleValues
        }
        else if (i == 5)  // end Simple Bound is Bad_NoData (no value after the interval)
        {
          expected.statusValue = 0x809B0000U;  // Bad_NoData (the end Simple Bound)
          expected.status = 0x00000005U;  // Good, Calculated, Partial
        }
      }

      const uint32_t actualStatus = actual.status().has_value() ? actual.status().value().value() : 0;
      EXPECT_EQ(actualStatus, expected.status)
        << "status got 0x" << std::hex << actualStatus << " want 0x" << expected.status;

      if (expected.statusValue.has_value())
      {
        // StatusCode-typed value (WorstQuality*); compare the severity + sub-code,
        // ignoring the low historian info bits the CSV value column omits.
        const StatusCode* code = actual.value().try_as<StatusCode>();
        ASSERT_NE(code, nullptr) << "expected a StatusCode-typed value";
        const uint32_t masked = code->value() & ~uint32_t{0x1F};
        EXPECT_EQ(masked, *expected.statusValue)
          << "status-value got 0x" << std::hex << masked << " want 0x" << *expected.statusValue;
      }
      else
      {
        const std::optional<double> actualValue = value_to_double(actual.value());
        if (expected.valueNull)
        {
          EXPECT_FALSE(actualValue.has_value()) << "expected null value";
        }
        else
        {
          ASSERT_TRUE(actualValue.has_value()) << "expected " << expected.value;
          // The CSV prints values rounded to ~4 decimal places.
          const double tolerance = std::max(1e-3, std::abs(expected.value) * 1e-4);
          EXPECT_NEAR(*actualValue, expected.value, tolerance);
        }
      }
    }
    ++blocksChecked;
    ++coveredAggregates[block.aggregate];
  }

  EXPECT_GT(blocksChecked, 0) << "no implemented aggregates were validated";
  std::string covered;
  for (const auto& [name, count] : coveredAggregates)
    covered += name + "(" + std::to_string(count) + ") ";
  RecordProperty("covered_aggregates", covered);
  std::cout << "[ aggregates ] validated: " << covered << "\n";
}

// @relation(AC-SVR-HIST-AGG-014-AVERAGES, scope=function)
// @relation(AC-SVR-HIST-AGG-015-TOTALS, scope=function)
// @relation(AC-SVR-HIST-AGG-016-MINMAX, scope=function)
// @relation(AC-SVR-HIST-AGG-017-RANGES, scope=function)
// @relation(AC-SVR-HIST-AGG-018-COUNTS, scope=function)
// @relation(AC-SVR-HIST-AGG-019-STATE, scope=function)
// @relation(AC-SVR-HIST-AGG-020-START-END-DELTA, scope=function)
// @relation(AC-SVR-HIST-AGG-021-QUALITY, scope=function)
// @relation(AC-SVR-HIST-AGG-022-STATISTICS, scope=function)
// @relation(AC-SVR-HIST-AGG-023-INTERPOLATIVE, scope=function)
TEST_F(AggregateCsvOracle, AllStandardAggregateFamiliesMatchOracle)
{
  const std::map<std::string, uint32_t> required = {{"Interpolative", 2341},
    {"Average", 2342},
    {"TimeAverage", 2343},
    {"Total", 2344},
    {"Minimum", 2346},
    {"Maximum", 2347},
    {"MinimumActualTime", 2348},
    {"MaximumActualTime", 2349},
    {"Range", 2350},
    {"AnnotationCount", 2351},
    {"Count", 2352},
    {"NumberOfTransitions", 2355},
    {"Start", 2357},
    {"End", 2358},
    {"Delta", 2359},
    {"DurationGood", 2360},
    {"DurationBad", 2361},
    {"PercentGood", 2362},
    {"PercentBad", 2363},
    {"WorstQuality", 2364},
    {"TimeAverage2", 11285},
    {"Minimum2", 11286},
    {"Maximum2", 11287},
    {"Range2", 11288},
    {"WorstQuality2", 11292},
    {"Total2", 11304},
    {"MinimumActualTime2", 11305},
    {"MaximumActualTime2", 11306},
    {"DurationInStateZero", 11307},
    {"DurationInStateNonZero", 11308},
    {"StandardDeviationSample", 11426},
    {"StandardDeviationPopulation", 11427},
    {"VarianceSample", 11428},
    {"VariancePopulation", 11429},
    {"StartBound", 11505},
    {"EndBound", 11506},
    {"DeltaBounds", 11507}};

  const auto& registry = AggregatorRegistry::instance();
  for (const auto& [name, numericId] : required)
  {
    SCOPED_TRACE(name);
    const Aggregator* aggregator = registry.find(NodeId{numericId});
    ASSERT_NE(aggregator, nullptr) << "required standard Aggregate is absent from the registry";

    const ProcessedBlock* selected = nullptr;
    for (const auto& block : model().processed)
    {
      if (block.aggregate == name)
      {
        selected = &block;
        break;
      }
    }
    ASSERT_NE(selected, nullptr) << "required standard Aggregate has no checked-in Part 13 oracle block";

    const auto rawIt = model().rawByName.find(selected->historian);
    ASSERT_NE(rawIt, model().rawByName.end());
    const auto& samples = rawIt->second.samples;
    const DateTime start = time_of_day("12:00:00.000");
    const DateTime end =
      DateTime{start.value() + datetime::OneHundredNanoSeconds{
                                 static_cast<int64_t>(selected->rows.size()) *
                                 static_cast<int64_t>(std::llround(selected->intervalMs * 10000.0))}};
    const IntervalSet intervals = generate_intervals(start, end, selected->intervalMs);
    ASSERT_EQ(intervals.intervals.size(), selected->rows.size());

    AggregateContext context;
    context.cfg = selected->cfg;
    context.sourceTemplate = source_template(samples);
    const std::vector<DataValue> results = run_aggregator(*aggregator, samples, intervals, context);
    ASSERT_EQ(results.size(), selected->rows.size());

    for (size_t index = 0; index < selected->rows.size(); ++index)
    {
      ExpectedRow expected = selected->rows[index];
      const DataValue& actual = results[index];
      SCOPED_TRACE("interval " + std::to_string(index));

      if (selected->aggregate == "WorstQuality2" && selected->historian == "Historian2")
      {
        if (index == 4)
        {
          expected.statusValue = 0x40000000U;
          expected.status = 0x00000011U;
        }
        else if (index == 5)
        {
          expected.statusValue = 0x809B0000U;
          expected.status = 0x00000005U;
        }
      }

      const uint32_t actualStatus = actual.status().has_value() ? actual.status()->value() : 0;
      EXPECT_EQ(actualStatus, expected.status);
      if (expected.statusValue.has_value())
      {
        const StatusCode* statusValue = actual.value().try_as<StatusCode>();
        ASSERT_NE(statusValue, nullptr);
        EXPECT_EQ(statusValue->value() & ~uint32_t{0x1F}, *expected.statusValue);
      }
      else
      {
        const std::optional<double> actualValue = value_to_double(actual.value());
        if (expected.valueNull)
        {
          EXPECT_FALSE(actualValue.has_value());
        }
        else
        {
          ASSERT_TRUE(actualValue.has_value());
          const double tolerance = std::max(1e-3, std::abs(expected.value) * 1e-4);
          EXPECT_NEAR(*actualValue, expected.value, tolerance);
        }
      }
    }
  }
}
