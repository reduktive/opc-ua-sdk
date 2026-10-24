// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the storage-agnostic Historical Access engine.
// The engine implements OPC 10000-11 section 6.4 read + section 6.8 update semantics over a HistoryStore;
// these tests drive it against the real SqliteHistoryStore backed by an in-memory SQLite database, so there
// is a single store implementation under test.

#include "ua_history_engine.h"
#include "history_test_support.h"
#include "ua_history_annotations_property.h"
#include "ua_history_engine_delegate.h"
#include "ua_history_sqlite_store.h"

// The Part-13 aggregate calculator is a server-implementation component (sdk/implementation/server/
// services/aggregates); the interval arithmetic below is exercised against the production primitives
// rather than a restatement of them.
#include "ua_aggregate_engine.h"
#include "ua_aggregate_descriptions.h"
#include "ua_aggregate_intervals.h"
#include "ua_aggregate_registry.h"
#include "ua_aggregate_types.h"
#include "ua_aggregator.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_annotation.h"
#include "ua_attribute_id.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_history_annotation_update_event_payload.h"
#include "ua_audit_history_at_time_delete_event_payload.h"
#include "ua_audit_history_delete_event_payload.h"
#include "ua_audit_history_event_delete_event_payload.h"
#include "ua_audit_history_event_update_event_payload.h"
#include "ua_audit_history_raw_modify_delete_event_payload.h"
#include "ua_audit_history_update_event_payload.h"
#include "ua_audit_history_value_update_event_payload.h"
#include "ua_base_data_variable.h"
#include "ua_base_event.h"
#include "ua_byte_string.h"
#include "ua_content_filter_element.h"
#include "ua_continuation_points.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_default_namespace.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_event_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_event_bus.h"
#include "ua_event_filter.h"
#include "ua_event_notifier_type.h"
#include "ua_filter_operator.h"
#include "ua_history_data.h"
#include "ua_history_event.h"
#include "ua_history_event_field_list.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_history_update_service.h"
#include "ua_instantiation_options.h"
#include "ua_literal_operand.h"
#include "ua_locale_id.h"
#include "ua_localized_text.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_node_utilities.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_read_event_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_raw_modified_details.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include "ua_simple_attribute_operand.h"
#include "ua_sinks.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_test_server.h"
#include "ua_timestamps_to_return.h"
#include "ua_update_data_details.h"
#include "ua_update_event_details.h"
#include "ua_update_structure_data_details.h"
#include "ua_value_rank.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include "stubs.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "test_components.h"
using ua::DataValue;
using ua::DateTime;
using ua::NodeId;
using ua::StatusCode;
using ua::Variant;
using ua::history::HistoryEngine;
using ua::history::SqliteHistoryStore;
using ua::history::test::make_codec;
using ReadRawItem = ua::NamespaceHistoryDelegate::ReadRawItem;

namespace
{

const NodeId testNode{uint16_t{2}, 1000};
const DateTime base = DateTime::now();

DateTime at(int seconds)
{
  return DateTime{base.value() + std::chrono::seconds{seconds}};
}

DataValue sample(int seconds, double value)
{
  DataValue dv;
  dv.value() = Variant{value};
  dv.source_timestamp() = at(seconds);
  dv.status() = StatusCode{ua::Status::Good};
  return dv;
}

// Seed the store with samples at t = 0,10,20,...,(count-1)*10 seconds; value == second-offset.
void seed(SqliteHistoryStore& store, int count)
{
  for (int i = 0; i < count; ++i)
    store.insert_value(testNode, sample(i * 10, static_cast<double>(i * 10))).value();
}

ReadRawItem raw_item(DateTime start, DateTime end, uint32_t cap = 0, bool bounds = false)
{
  ReadRawItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.startTime = start;
  item.endTime = end;
  item.maxValuesPerNode = cap;
  item.returnBounds = bounds;
  return item;
}

int64_t ticks(const DataValue& dv)
{
  return dv.source_timestamp().value_or(DateTime{}).value().time_since_epoch().count();
}

}  // namespace

TEST(HistoryEngineReadRaw, ForwardRangeIsHalfOpenAscending)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40

  auto item = raw_item(at(10), at(30));  // [10, 30) -> expects 10, 20 (30 excluded)
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 2u);
  EXPECT_EQ(ticks(values[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[1]), at(20).value().time_since_epoch().count());
  EXPECT_FALSE(result.value().cursor.has_value());
}

TEST(HistoryEngineReadRaw, ReverseRangeIsDescending)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40

  auto item = raw_item(at(30), at(10));  // end < start -> reverse (10, 30] = 20, 30 newest-first
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 2u);
  EXPECT_EQ(ticks(values[0]), at(30).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[1]), at(20).value().time_since_epoch().count());
}

TEST(HistoryEngineReadRaw, ReturnBoundsPrependsStartAndAppendsEnd)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40

  auto item = raw_item(at(15), at(35), 0, /*bounds*/ true);  // window 20,30; start bound 10; end bound 40
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 4u);
  EXPECT_EQ(ticks(values[0]), at(10).value().time_since_epoch().count());  // start bound
  EXPECT_EQ(ticks(values[1]), at(20).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[2]), at(30).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[3]), at(40).value().time_since_epoch().count());  // end bound
}

TEST(HistoryEngineReadRaw, MissingBoundIsBadBoundNotFoundPlaceholder)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);  // t = 0,10,20 - nothing before 0

  auto item = raw_item(at(-5), at(5), 0, /*bounds*/ true);  // no start bound; end bound = 10
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  const auto& values = result.value().values;
  ASSERT_GE(values.size(), 1u);
  EXPECT_EQ(values.front().status().value_or(StatusCode{}).as_uint32(),
    StatusCode{ua::Status::BadBoundNotFound}.as_uint32());
}

TEST(HistoryEngineReadRaw, SingleInstantReturnsExactValue)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);

  auto item = raw_item(at(20), at(20));  // start == end -> just the value at 20
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 1u);
  EXPECT_EQ(ticks(result.value().values[0]), at(20).value().time_since_epoch().count());
  EXPECT_FALSE(result.value().cursor.has_value());
}

TEST(HistoryEngineReadRaw, SingleInstantNoValueNoBoundsIsEmpty)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);

  auto item = raw_item(at(25), at(25));  // no value at 25
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().values.empty());
}

TEST(HistoryEngineReadRaw, NumValuesCapEmitsContinuationAndResumeYieldsRest)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 6);  // t = 0..50

  auto item = raw_item(at(0), at(60), /*cap*/ 2);  // 6 values, cap 2
  auto first = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().values.size(), 2u);
  ASSERT_TRUE(first.value().cursor.has_value());

  // Resume.
  ReadRawItem resume = raw_item(at(0), at(60), 2);
  resume.cursor = first.value().cursor;
  auto second = HistoryEngine::read_raw(store, resume);
  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().values.size(), 2u);
  ASSERT_TRUE(second.value().cursor.has_value());

  ReadRawItem resume2 = raw_item(at(0), at(60), 2);
  resume2.cursor = second.value().cursor;
  auto third = HistoryEngine::read_raw(store, resume2);
  ASSERT_TRUE(third.is_good());
  EXPECT_EQ(third.value().values.size(), 2u);
  EXPECT_FALSE(third.value().cursor.has_value());
}

TEST(HistoryEngineReadRaw, IndexRangeOnScalarIsBadIndexRangeNoData)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);

  auto item = raw_item(at(0), at(30));
  item.indexRange = ua::String{"0:1"};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadIndexRangeNoData}.as_uint32());
}

namespace
{
/// A Double[@p length] sample at @p seconds whose element e is seconds + e / 10.
DataValue array_sample(int seconds, size_t length)
{
  ua::Array<double> elements{ua::Size{length}};
  for (size_t e = 0; e < length; ++e)
    elements[e] = seconds + static_cast<double>(e) / 10.0;
  DataValue dv;
  dv.value() = Variant{std::move(elements)};
  dv.source_timestamp() = at(seconds);
  dv.server_timestamp() = at(seconds);
  return dv;
}

std::vector<double> doubles(const DataValue& dv)
{
  const auto* array = dv.value().try_as<ua::Array<double>>();
  return array ? std::vector<double>(array->begin(), array->end()) : std::vector<double>{};
}
}  // namespace

// Part 11 6.4: an IndexRange selects the same elements of every historical array value.
TEST(HistoryEngineReadRaw, AnIndexRangeSlicesEveryArrayValue)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 3; ++i)
    store.insert_value(testNode, array_sample(i * 10, 5)).value();

  auto item = raw_item(at(0), at(30));
  item.indexRange = ua::String{"1:3"};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 3u);
  for (size_t i = 0; i < values.size(); ++i)
  {
    const double t = static_cast<double>(i * 10);
    EXPECT_EQ(doubles(values[i]), (std::vector<double>{t + 0.1, t + 0.2, t + 0.3})) << i;
  }
}

// A two-dimensional value is sliced in both dimensions.
TEST(HistoryEngineReadRaw, AnIndexRangeSlicesAMatrixInBothDimensions)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  std::vector<double> payload(25);
  for (size_t e = 0; e < payload.size(); ++e)
    payload[e] = static_cast<double>(e);
  DataValue matrix;
  matrix.value() = Variant{ua::Array<double>{ua::Dimensions{5, 5}, std::move(payload)}};
  matrix.source_timestamp() = at(0);
  matrix.server_timestamp() = at(0);
  store.insert_value(testNode, matrix).value();

  auto item = raw_item(at(0), at(10));
  item.indexRange = ua::String{"1:2,3:4"};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  ASSERT_EQ(result.value().values.size(), 1u);
  // Rows 1-2, columns 3-4 of a row-major 5x5 whose element (r, c) is 5r + c.
  EXPECT_EQ(doubles(result.value().values[0]), (std::vector<double>{8, 9, 13, 14}));
}

// A malformed IndexRange is the operation's Bad_IndexRangeInvalid (Part 4 7.27): the CTT's Historical Access
// Read Raw Err-010 sends eleven of them.
TEST(HistoryEngineReadRaw, AMalformedIndexRangeIsBadIndexRangeInvalid)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, array_sample(0, 5)).value();
  for (const auto* range : {"3:1", "3:3", "1:A", "1-3"})
  {
    auto item = raw_item(at(0), at(10));
    item.indexRange = ua::String{range};
    auto result = HistoryEngine::read_raw(store, item);
    EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadIndexRangeInvalid}.as_uint32())
      << range;
  }
}

// A value with nothing in the range is returned with Bad_IndexRangeNoData in its place; the others are
// sliced.
TEST(HistoryEngineReadRaw, AValueWithNothingInTheRangeCarriesBadIndexRangeNoData)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, array_sample(0, 5)).value();
  store.insert_value(testNode, array_sample(10, 2)).value();

  auto item = raw_item(at(0), at(20));
  item.indexRange = ua::String{"3"};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 2u);
  EXPECT_EQ(doubles(values[0]), (std::vector<double>{0.3}));
  ASSERT_TRUE(values[1].status().has_value());
  EXPECT_EQ(values[1].status()->as_uint32(), StatusCode{ua::Status::BadIndexRangeNoData}.as_uint32());
}

TEST(HistoryEngineReadRaw, ModifiedReadWithBoundsIsBadInvalidArgument)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);

  auto item = raw_item(at(0), at(30), 0, /*bounds*/ true);
  item.isReadModified = true;
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadInvalidArgument}.as_uint32());
}

TEST(HistoryEngineReadRaw, BadCursorTypeIsBadContinuationPointInvalid)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);

  auto item = raw_item(at(0), at(30));
  item.cursor = ua::NamespaceHistoryDelegate::Cursor{std::string{"not a real cursor"}};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(
    result.status_code().as_uint32(), StatusCode{ua::Status::BadContinuationPointInvalid}.as_uint32());
}

namespace
{
using UpdateDataItem = ua::NamespaceHistoryDelegate::UpdateDataItem;
using DeleteRawItem = ua::NamespaceHistoryDelegate::DeleteRawItem;
using DeleteAtTimeItem = ua::NamespaceHistoryDelegate::DeleteAtTimeItem;

UpdateDataItem update_item(ua::PerformUpdateType type, std::vector<DataValue> values)
{
  UpdateDataItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.performInsertReplace = type;
  item.values = std::move(values);
  return item;
}

uint32_t code(StatusCode s)
{
  return s.as_uint32();
}
}  // namespace

TEST(HistoryEngineUpdateData, InsertNewReturnsGoodEntryInserted)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Insert, {sample(10, 1.0)}));
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 1u);
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));
  EXPECT_TRUE(store.read_value_at(testNode, at(10)).value().has_value());
}

TEST(HistoryEngineUpdateData, InsertDuplicateReturnsBadEntryExistsAndNoOverwrite)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();
  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Insert, {sample(10, 999.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}));
}

TEST(HistoryEngineUpdateData, ReplaceExistingReturnsGoodEntryReplacedAndRecordsModification)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();
  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));
  EXPECT_TRUE(store.has_modification_at(testNode, at(10)).value());
}

TEST(HistoryEngineUpdateData, ReplaceMissingReturnsBadNoEntryExists)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));
}

// @relation(AC-SVR-HIST-UPD-016-UPDATEDATA-OUTCOMES, scope=function)

TEST(HistoryEngineUpdateData, UpdateUpsertsInsertThenReplace)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto inserted =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Update, {sample(10, 1.0)}));
  EXPECT_EQ(code(inserted.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));
  auto replaced =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Update, {sample(10, 2.0)}));
  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));
}

TEST(HistoryEngineUpdateData, NullTimestampReturnsBadInvalidArgument)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  DataValue noTs;
  noTs.value() = Variant{1.0};  // no source timestamp
  auto result = HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Insert, {noTs}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadInvalidArgument}));
}

TEST(HistoryEngineDelete, DeleteRawRemovesRangeAndRecordsModifications)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40
  DeleteRawItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.startTime = at(10);
  item.endTime = at(30);  // inclusive [10,30] -> removes 10,20,30
  auto result = HistoryEngine::delete_raw(store, item);
  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(store.read_value_at(testNode, at(20)).value().has_value());
  EXPECT_TRUE(store.read_value_at(testNode, at(0)).value().has_value());
  EXPECT_TRUE(store.read_value_at(testNode, at(40)).value().has_value());
  EXPECT_TRUE(store.has_modification_at(testNode, at(20)).value());
}

TEST(HistoryEngineDelete, DeleteAtTimeGoodWhenExistsBadWhenMissing)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);  // t = 0,10,20
  DeleteAtTimeItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.timestamps = {at(10), at(15)};  // 10 exists, 15 does not
  auto result = HistoryEngine::delete_at_time(store, item);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 2u);
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::BadNoEntryExists}));
  EXPECT_FALSE(store.read_value_at(testNode, at(10)).value().has_value());
}

namespace
{
using ReadAtTimeItem = ua::NamespaceHistoryDelegate::ReadAtTimeItem;

ReadAtTimeItem at_time_item(std::vector<DateTime> times, bool simpleBounds = false)
{
  ReadAtTimeItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.timestamps = std::move(times);
  item.useSimpleBounds = simpleBounds;
  return item;
}
}  // namespace

TEST(HistoryEngineReadAtTime, ExactValuesInRequestOrder)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40 ; value == seconds

  auto result = HistoryEngine::read_at_time(store, at_time_item({at(20), at(0), at(10)}));
  ASSERT_TRUE(result.is_good());
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 3u);
  EXPECT_EQ(ticks(values[0]), at(20).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[1]), at(0).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[2]), at(10).value().time_since_epoch().count());
}

// The at-time path applies the IndexRange to each returned value as the raw path does (Part 11 6.4).
TEST(HistoryEngineReadAtTime, AnIndexRangeSlicesTheValueAtEachTime)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, array_sample(0, 5)).value();
  store.insert_value(testNode, array_sample(10, 5)).value();

  auto item = at_time_item({at(0), at(10)}, /*simpleBounds*/ true);
  item.indexRange = ua::String{"4"};
  auto result = HistoryEngine::read_at_time(store, item);

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  ASSERT_EQ(result.value().values.size(), 2u);
  EXPECT_EQ(doubles(result.value().values[0]), (std::vector<double>{0.4}));
  EXPECT_EQ(doubles(result.value().values[1]), (std::vector<double>{10.4}));

  item.indexRange = ua::String{"1:A"};
  EXPECT_EQ(HistoryEngine::read_at_time(store, item).status_code().as_uint32(),
    StatusCode{ua::Status::BadIndexRangeInvalid}.as_uint32());
}

TEST(HistoryEngineReadAtTime, InterpolatesBetweenBoundingValues)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(0, 0.0)).value();
  store.insert_value(testNode, sample(10, 10.0)).value();  // value == seconds

  auto result = HistoryEngine::read_at_time(store, at_time_item({at(5)}));  // midpoint -> 5.0
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 1u);
  ASSERT_TRUE(result.value().values[0].value().try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*result.value().values[0].value().try_as<double>(), 5.0);
  EXPECT_EQ(ticks(result.value().values[0]), at(5).value().time_since_epoch().count());
}

TEST(HistoryEngineReadAtTime, SimpleBoundsHoldsValueAtOrBefore)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(0, 0.0)).value();
  store.insert_value(testNode, sample(10, 10.0)).value();

  auto result = HistoryEngine::read_at_time(store, at_time_item({at(7)}, /*simpleBounds*/ true));
  ASSERT_TRUE(result.is_good());
  EXPECT_DOUBLE_EQ(*result.value().values[0].value().try_as<double>(), 0.0);  // held from t=0
}

TEST(HistoryEngineReadAtTime, BeforeAllDataIsBadNoData)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 3);  // 0,10,20

  auto result = HistoryEngine::read_at_time(store, at_time_item({at(-5)}));
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 1u);
  EXPECT_EQ(result.value().values[0].status().value_or(StatusCode{}).as_uint32(),
    StatusCode{ua::Status::BadNoData}.as_uint32());
}

TEST(HistoryEngineReadModified, ReturnsModificationRecordsWithInfos)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  ua::ModificationInfo info;
  info.update_type() = ua::HistoryUpdateType::Replace;
  info.user_name() = ua::String{"tester"};
  store.insert_modification(testNode, sample(10, 1.0), info).value();
  store.insert_modification(testNode, sample(20, 2.0), info).value();

  auto item = raw_item(at(0), at(60));
  item.isReadModified = true;
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 2u);
  ASSERT_EQ(result.value().modificationInfos.size(), 2u);
  EXPECT_EQ(result.value().modificationInfos[0].user_name(), ua::String{"tester"});
}

namespace
{
using ReadEventsItem = ua::NamespaceHistoryDelegate::ReadEventsItem;

ua::history::StoredEvent make_event(int seconds, std::vector<uint8_t> id, double severity)
{
  ua::history::StoredEvent event;
  event.time = at(seconds);
  event.eventId = ua::ByteString{std::move(id)};
  event.fields["Severity"] = Variant{severity};
  return event;
}

ua::EventFilter filter_selecting(const std::vector<std::string>& fieldNames)
{
  ua::EventFilter filter;
  for (const auto& name : fieldNames)
  {
    ua::SimpleAttributeOperand operand;
    operand.browse_path().push_back(ua::QualifiedName{uint16_t{0}, name});
    filter.select_clauses().push_back(operand);
  }
  return filter;
}

ReadEventsItem events_item(DateTime start, DateTime end, ua::EventFilter filter, uint32_t cap = 0)
{
  ReadEventsItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.startTime = start;
  item.endTime = end;
  item.maxValuesPerNode = cap;
  item.filter = std::move(filter);
  return item;
}
}  // namespace

TEST(HistoryEngineReadEvents, ProjectsSelectClausesPerEventInTimeOrder)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();
  store.insert_event(testNode, make_event(20, {2}, 200.0)).value();

  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto result = HistoryEngine::read_events(store, item);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().events.size(), 2u);
  ASSERT_EQ(result.value().events[0].event_fields().size(), 1u);
  ASSERT_TRUE(result.value().events[0].event_fields()[0].try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*result.value().events[0].event_fields()[0].try_as<double>(), 100.0);
  EXPECT_DOUBLE_EQ(*result.value().events[1].event_fields()[0].try_as<double>(), 200.0);
}

// A selected field not established as part of the Event remains null; Bad_NoData is reserved for a
// declared field that the historian cannot return.
// @relation(AC-SVR-HIST-READ-004-EVENT-NODATA, scope=function)
TEST(HistoryEngineReadEvents, MissingFieldProjectsToNullVariant)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();  // has Severity, not Message

  auto item = events_item(at(0), at(60), filter_selecting({"Message"}));
  item.selectClauseModelStatuses.push_back(StatusCode{Status::BadBrowseNameInvalid});
  auto result = HistoryEngine::read_events(store, item);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().events.size(), 1u);
  ASSERT_EQ(result.value().events[0].event_fields().size(), 1u);
  EXPECT_EQ(result.value().events[0].event_fields()[0].try_as<double>(), nullptr);
}

TEST(HistoryEngineReadEvents, NumValuesCapEmitsContinuationAndResume)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();
  store.insert_event(testNode, make_event(20, {2}, 200.0)).value();
  store.insert_event(testNode, make_event(30, {3}, 300.0)).value();

  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  auto first = HistoryEngine::read_events(store, item);
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().events.size(), 2u);
  ASSERT_TRUE(first.value().cursor.has_value());

  ReadEventsItem resume = events_item(at(0), at(60), filter_selecting({"Severity"}), 2);
  resume.cursor = first.value().cursor;
  auto second = HistoryEngine::read_events(store, resume);
  ASSERT_TRUE(second.is_good());
  EXPECT_EQ(second.value().events.size(), 1u);
  EXPECT_FALSE(second.value().cursor.has_value());
}

// The server authorizes the fields of the request in hand, so a continuation may not project the
// remaining events through other select clauses than the ones its continuation point was issued for.
// @relation(AC-SVR-AUTHZ-001-HISTORICAL-FIELD-READ-AUTHORIZATION, scope=function)
TEST(HistoryEngineReadEvents, AContinuationWithOtherSelectClausesIsRefused)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();
  store.insert_event(testNode, make_event(20, {2}, 200.0)).value();
  store.insert_event(testNode, make_event(30, {3}, 300.0)).value();

  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  auto first = HistoryEngine::read_events(store, item);
  ASSERT_TRUE(first.is_good());
  ASSERT_TRUE(first.value().cursor.has_value());

  for (const auto& clauses : {std::vector<std::string>{"Time"}, std::vector<std::string>{"Severity", "Time"}})
  {
    ReadEventsItem changed = events_item(at(0), at(60), filter_selecting(clauses), 2);
    changed.cursor = first.value().cursor;
    auto refused = HistoryEngine::read_events(store, changed);
    EXPECT_EQ(refused.status_code().as_status(), ua::Status::BadContinuationPointInvalid);
    EXPECT_FALSE(refused.has_value());
  }

  // Control: the cursor is not spent by a refusal; the original clauses still resume it.
  ReadEventsItem resume = events_item(at(0), at(60), filter_selecting({"Severity"}), 2);
  resume.cursor = first.value().cursor;
  auto second = HistoryEngine::read_events(store, resume);
  ASSERT_TRUE(second.is_good());
  EXPECT_EQ(second.value().events.size(), 1u);
}

namespace
{
using UpdateEventsItem = ua::NamespaceHistoryDelegate::UpdateEventsItem;
using DeleteEventsItem = ua::NamespaceHistoryDelegate::DeleteEventsItem;

// An event record whose fields are ordered to match event_write_filter(): EventId, Time, Severity.
// A null id leaves the EventId field empty so the engine generates one.
ua::HistoryEventFieldList event_record(std::optional<std::vector<uint8_t>> id, int seconds, double severity)
{
  ua::HistoryEventFieldList record;
  record.event_fields().push_back(id ? Variant{ua::ByteString{*id}} : Variant{});
  record.event_fields().push_back(Variant{at(seconds)});
  record.event_fields().push_back(Variant{severity});
  return record;
}

UpdateEventsItem update_events_item(
  ua::PerformUpdateType perform, std::vector<ua::HistoryEventFieldList> events)
{
  UpdateEventsItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.performInsertReplace = perform;
  item.filter = filter_selecting({"EventId", "Time", "Severity"});
  item.events = std::move(events);
  return item;
}
}  // namespace

TEST(HistoryEngineUpdateEvents, InsertStoresEventReadableViaReadEvents)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto result = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::Good}));

  auto read = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto readResult = HistoryEngine::read_events(store, read);
  ASSERT_TRUE(readResult.is_good());
  ASSERT_EQ(readResult.value().events.size(), 1u);
  EXPECT_DOUBLE_EQ(*readResult.value().events[0].event_fields()[0].try_as<double>(), 100.0);
}

TEST(HistoryEngineUpdateEvents, InsertDuplicateEventIdReturnsBadEntryExists)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));
  auto dup = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 20, 200.0)}));
  ASSERT_TRUE(dup.is_good());
  EXPECT_EQ(code(dup.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}));
}

TEST(HistoryEngineUpdateEvents, ReplaceMissingReturnsBadNoEntryExists)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto result = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Replace, {event_record({{9}}, 10, 1.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));
}

TEST(HistoryEngineUpdateEvents, ReplaceExistingUpdatesFields)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));
  auto replaced = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Replace, {event_record({{1}}, 10, 200.0)}));
  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::Good}));

  auto readItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto read = HistoryEngine::read_events(store, readItem);
  ASSERT_EQ(read.value().events.size(), 1u);  // replaced, not duplicated
  EXPECT_DOUBLE_EQ(*read.value().events[0].event_fields()[0].try_as<double>(), 200.0);
}

TEST(HistoryEngineUpdateEvents, UpdateUpsertsEvent)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto inserted = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Update, {event_record({{1}}, 10, 100.0)}));
  EXPECT_EQ(code(inserted.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));
  auto replaced = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Update, {event_record({{1}}, 10, 200.0)}));
  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));
  auto readItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto read = HistoryEngine::read_events(store, readItem);
  EXPECT_EQ(read.value().events.size(), 1u);
}

TEST(HistoryEngineUpdateEvents, ServerGeneratesUniqueGuidEventIdWhenAbsent)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  // Two events at the SAME Time, neither carrying an EventId: the server must assign distinct
  // identifiers (the time-derived scheme this replaced would have collided here).
  auto result = HistoryEngine::update_events(store,
    update_events_item(ua::PerformUpdateType::Insert,
      {event_record(std::nullopt, 10, 1.0), event_record(std::nullopt, 10, 2.0)}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::Good}));

  auto readItem = events_item(at(0), at(60), filter_selecting({"EventId"}));
  auto read = HistoryEngine::read_events(store, readItem);
  ASSERT_EQ(read.value().events.size(), 2u);
  const auto* eventId0 = read.value().events[0].event_fields()[0].try_as<ua::ByteString>();
  const auto* eventId1 = read.value().events[1].event_fields()[0].try_as<ua::ByteString>();
  ASSERT_NE(eventId0, nullptr);
  ASSERT_NE(eventId1, nullptr);
  EXPECT_EQ(eventId0->size(), 16u);  // a v4 GUID
  EXPECT_EQ(eventId1->size(), 16u);
  EXPECT_NE(*eventId0, *eventId1);  // collision-free
}

// OPC 10000-11 section 6.8.4.2: "The EventId is a Server generated opaque value and a Client cannot
// assume that it knows how to create valid EventIds. A Server shall be able to generate an appropriate
// default value for the EventId field. If a Client does specify the EventId in the selectClause and it
// matches an existing Event then the statusCode shall indicate Bad_EntryExists." Storing whatever the
// Client sent is the shorter path and it breaks both halves at once: an insert that supplies nothing
// leaves the Event with no handle for a later replace to find, and one that supplies a value already in
// use is filed beside the Event it collides with rather than refused.
// @verifies AC-SVR-HIST-UPD-010-SERVER-GENERATED-EVENTID
TEST(HistoryEngineUpdateEvents, AnInsertedEventGetsAServerGeneratedEventIdAndASuppliedOneIsMatched)
{
  SqliteHistoryStore store{":memory:", make_codec()};

  // No EventId supplied: the Server must generate one, and a HistoryRead must be able to discover it.
  auto generated = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record(std::nullopt, 10, 100.0)}));
  ASSERT_TRUE(generated.is_good());
  ASSERT_EQ(generated.value().operationResults.size(), 1u);
  EXPECT_EQ(code(generated.value().operationResults[0]), code(StatusCode{ua::Status::Good}));

  auto discoverItem = events_item(at(0), at(60), filter_selecting({"EventId"}));
  auto discover = HistoryEngine::read_events(store, discoverItem);
  ASSERT_TRUE(discover.is_good());
  ASSERT_EQ(discover.value().events.size(), 1u) << "the Event inserted without an EventId was not stored";
  ASSERT_EQ(discover.value().events[0].event_fields().size(), 1u);
  const auto* assigned = discover.value().events[0].event_fields()[0].try_as<ua::ByteString>();
  ASSERT_NE(assigned, nullptr) << "the Server stored no EventId for an Event that supplied none";
  EXPECT_FALSE(assigned->empty()) << "the generated EventId is empty, so nothing can address the Event";

  // The same value supplied by a Client is matched against what the Server already holds, not stored.
  ua::HistoryEventFieldList collision;
  collision.event_fields().push_back(Variant{*assigned});
  collision.event_fields().push_back(Variant{at(20)});
  collision.event_fields().push_back(Variant{200.0});
  auto refused = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {std::move(collision)}));
  ASSERT_TRUE(refused.is_good());
  ASSERT_EQ(refused.value().operationResults.size(), 1u);
  EXPECT_EQ(code(refused.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}))
    << "a Client-supplied EventId matching an existing Event was accepted rather than refused";

  auto afterItem = events_item(at(0), at(60), filter_selecting({"EventId"}));
  auto after = HistoryEngine::read_events(store, afterItem);
  ASSERT_TRUE(after.is_good());
  EXPECT_EQ(after.value().events.size(), 1u)
    << "the refused insert stored a second Event under an EventId that was already taken";
}

// OPC 10000-11 section 6.8.4.3: "The SelectClause parameter of the EventFilter shall specify the EventId
// Property and the eventData shall contain the EventId which will be used to find the Event to be
// replaced. If no entry exists matching the specified EventId then no replace operation will be
// performed; instead the operationResults entry for the eventData entry shall indicate
// Bad_NoEntryExists." The plausible convenience is an upsert - one store primitive serving both modes -
// and it silently adds the Event the caller believed they were correcting, leaving the original in place
// under the EventId they mistyped.
// @verifies AC-SVR-HIST-UPD-013-EVENT-REPLACE-EVENTID
TEST(HistoryEngineUpdateEvents, AnEventReplaceIsLocatedByEventIdAndAMissInsertsNothing)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));

  // The EventId carried by the eventData selects the Event that is replaced.
  auto replaced = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Replace, {event_record({{1}}, 10, 200.0)}));
  ASSERT_TRUE(replaced.is_good());
  ASSERT_EQ(replaced.value().operationResults.size(), 1u);
  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::Good}));

  auto afterReplaceItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto afterReplace = HistoryEngine::read_events(store, afterReplaceItem);
  ASSERT_TRUE(afterReplace.is_good());
  ASSERT_EQ(afterReplace.value().events.size(), 1u) << "the replace did not act on the stored Event";
  ASSERT_EQ(afterReplace.value().events[0].event_fields().size(), 1u);
  const auto* severity = afterReplace.value().events[0].event_fields()[0].try_as<double>();
  ASSERT_NE(severity, nullptr);
  EXPECT_DOUBLE_EQ(*severity, 200.0) << "the Event named by the EventId was not the one replaced";

  // An EventId matching no stored Event: refused, and no Event created in its place.
  auto missed = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Replace, {event_record({{9}}, 30, 300.0)}));
  ASSERT_TRUE(missed.is_good());
  ASSERT_EQ(missed.value().operationResults.size(), 1u);
  EXPECT_EQ(code(missed.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));

  auto afterMissItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto afterMiss = HistoryEngine::read_events(store, afterMissItem);
  ASSERT_TRUE(afterMiss.is_good());
  EXPECT_EQ(afterMiss.value().events.size(), 1u)
    << "a replace matching no EventId inserted a new Event instead of refusing the operation";
}

TEST(HistoryEngineDeleteEvents, GoodWhenExistsBadWhenMissing)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));

  DeleteEventsItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.eventIds = {ua::ByteString{std::vector<uint8_t>{1}}, ua::ByteString{std::vector<uint8_t>{2}}};
  auto result = HistoryEngine::delete_events(store, item);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 2u);
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::BadNoEntryExists}));

  auto readItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto read = HistoryEngine::read_events(store, readItem);
  EXPECT_EQ(read.value().events.size(), 0u);
}

namespace
{
using ReadAnnotationItem = ua::NamespaceHistoryDelegate::ReadAnnotationItem;
using UpdateStructureDataItem = ua::NamespaceHistoryDelegate::UpdateStructureDataItem;

DataValue make_annotation(int seconds, const std::string& message, const std::string& userName = "tester")
{
  ua::Annotation annotation;
  annotation.message() = ua::String{message};
  annotation.user_name() = ua::String{userName};
  annotation.annotation_time() = at(seconds + 1000);
  DataValue dv{Variant{std::move(annotation)}};
  dv.source_timestamp() = at(seconds);
  return dv;
}

UpdateStructureDataItem struct_item(ua::PerformUpdateType perform, std::vector<DataValue> values)
{
  UpdateStructureDataItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.performInsertReplace = perform;
  item.values = std::move(values);
  return item;
}

ReadAnnotationItem annotation_item(std::vector<DateTime> reqTimes)
{
  ReadAnnotationItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.reqTimes = std::move(reqTimes);
  return item;
}

std::string annotation_message(const DataValue& dv)
{
  const auto* annotation = dv.value().try_as<ua::Annotation>();
  return annotation ? std::string{annotation->message()} : std::string{};
}
}  // namespace

TEST(HistoryEngineAnnotations, InsertThenReadReturnsAnnotationsInRequestOrder)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto inserted = HistoryEngine::update_structure_data(store,
    struct_item(
      ua::PerformUpdateType::Insert, {make_annotation(10, "first"), make_annotation(20, "second")}));
  ASSERT_TRUE(inserted.is_good());
  EXPECT_EQ(code(inserted.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));

  auto read = HistoryEngine::read_annotations(store, annotation_item({at(20), at(10)}));
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().values.size(), 2u);
  EXPECT_EQ(annotation_message(read.value().values[0]), "second");
  EXPECT_EQ(annotation_message(read.value().values[1]), "first");
}

// @relation(AC-SVR-HIST-ANN-002-STRUCTURE, AC-SVR-HIST-ANN-003-REQUEST-ORDER, scope=function)
TEST(HistoryEngineAnnotations, ReadPreservesStandardStructureAndRequestedTimestampOrder)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto first = make_annotation(10, "first", "alice");
  auto second = make_annotation(20, "second", "bob");
  ASSERT_TRUE(
    HistoryEngine::update_structure_data(store, struct_item(ua::PerformUpdateType::Insert, {first, second}))
      .is_good());

  auto read = HistoryEngine::read_annotations(store, annotation_item({at(20), at(10)}));
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().values.size(), 2u);

  const auto* latest = read.value().values[0].value().try_as<ua::Annotation>();
  const auto* earliest = read.value().values[1].value().try_as<ua::Annotation>();
  ASSERT_NE(latest, nullptr);
  ASSERT_NE(earliest, nullptr);
  ASSERT_TRUE(read.value().values[0].source_timestamp().has_value());
  ASSERT_TRUE(read.value().values[1].source_timestamp().has_value());
  EXPECT_EQ(*read.value().values[0].source_timestamp(), at(20));
  EXPECT_EQ(*read.value().values[1].source_timestamp(), at(10));
  EXPECT_EQ(latest->message(), ua::String{"second"});
  EXPECT_EQ(latest->user_name(), ua::String{"bob"});
  EXPECT_EQ(latest->annotation_time(), at(1020));
  EXPECT_EQ(earliest->message(), ua::String{"first"});
  EXPECT_EQ(earliest->user_name(), ua::String{"alice"});
  EXPECT_EQ(earliest->annotation_time(), at(1010));
}

TEST(HistoryEngineAnnotations, ReadMissingTimestampIsBadNoData)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "x")}));

  auto read = HistoryEngine::read_annotations(store, annotation_item({at(99)}));
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().values.size(), 1u);
  EXPECT_EQ(read.value().values[0].status().value_or(StatusCode{}).as_uint32(),
    StatusCode{ua::Status::BadNoData}.as_uint32());
}

TEST(HistoryEngineAnnotations, InsertDuplicateIsBadEntryExists)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "a")}));
  auto dup = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "b")}));
  EXPECT_EQ(code(dup.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}));
}

TEST(HistoryEngineAnnotations, ReplaceMissingIsBadNoEntryExists)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto result = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Replace, {make_annotation(10, "a")}));
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));
}

TEST(HistoryEngineAnnotations, ReplaceExistingUpdatesMessage)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "old")}));
  auto replaced = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Replace, {make_annotation(10, "new")}));
  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));

  auto read = HistoryEngine::read_annotations(store, annotation_item({at(10)}));
  ASSERT_EQ(read.value().values.size(), 1u);
  EXPECT_EQ(annotation_message(read.value().values[0]), "new");
}

TEST(HistoryEngineAnnotations, RemoveDeletesAnnotation)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "a")}));
  auto removed = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Remove, {make_annotation(10, "a")}));
  EXPECT_EQ(code(removed.value().operationResults[0]), code(StatusCode{ua::Status::Good}));

  auto read = HistoryEngine::read_annotations(store, annotation_item({at(10)}));
  EXPECT_EQ(read.value().values[0].status().value_or(StatusCode{}).as_uint32(),
    StatusCode{ua::Status::BadNoData}.as_uint32());
}

// @relation(AC-SVR-HIST-ANN-005-INSERT, scope=function)
// @relation(AC-SVR-HIST-ANN-006-REPLACE, scope=function)
// @relation(AC-SVR-HIST-ANN-007-UPDATE, scope=function)
// @relation(AC-SVR-HIST-ANN-008-REMOVE, scope=function)
TEST(HistoryEngineAnnotations, StructuredUpdateModesReturnExactStatusesAndIsolateState)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  auto insert = HistoryEngine::update_structure_data(store,
    struct_item(
      ua::PerformUpdateType::Insert, {make_annotation(10, "original"), make_annotation(50, "unrelated")}));
  ASSERT_TRUE(insert.is_good());
  ASSERT_EQ(insert.value().operationResults.size(), 2u);
  EXPECT_EQ(code(insert.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));
  EXPECT_EQ(code(insert.value().operationResults[1]), code(StatusCode{ua::Status::GoodEntryInserted}));

  auto duplicate = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Insert, {make_annotation(10, "duplicate")}));
  ASSERT_TRUE(duplicate.is_good());
  EXPECT_EQ(code(duplicate.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}));
  auto original = HistoryEngine::read_annotations(store, annotation_item({at(10)}));
  ASSERT_TRUE(original.is_good());
  ASSERT_EQ(original.value().values.size(), 1u);
  EXPECT_EQ(annotation_message(original.value().values[0]), "original");

  auto replaceMissing = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Replace, {make_annotation(20, "missing")}));
  ASSERT_TRUE(replaceMissing.is_good());
  EXPECT_EQ(code(replaceMissing.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));

  auto replaceExisting = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Replace, {make_annotation(10, "replaced")}));
  ASSERT_TRUE(replaceExisting.is_good());
  EXPECT_EQ(
    code(replaceExisting.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));

  auto updateExisting = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Update, {make_annotation(10, "updated")}));
  auto updateMissing = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Update, {make_annotation(30, "inserted")}));
  ASSERT_TRUE(updateExisting.is_good());
  ASSERT_TRUE(updateMissing.is_good());
  EXPECT_EQ(
    code(updateExisting.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));
  EXPECT_EQ(code(updateMissing.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}));

  auto removed = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Remove, {make_annotation(30, "ignored")}));
  ASSERT_TRUE(removed.is_good());
  EXPECT_TRUE(removed.value().operationResults[0].is_good());
  auto removedAgain = HistoryEngine::update_structure_data(
    store, struct_item(ua::PerformUpdateType::Remove, {make_annotation(30, "ignored")}));
  ASSERT_TRUE(removedAgain.is_good());
  EXPECT_EQ(code(removedAgain.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));

  auto finalRead = HistoryEngine::read_annotations(store, annotation_item({at(10), at(20), at(30), at(50)}));
  ASSERT_TRUE(finalRead.is_good());
  ASSERT_EQ(finalRead.value().values.size(), 4u);
  EXPECT_EQ(annotation_message(finalRead.value().values[0]), "updated");
  EXPECT_EQ(finalRead.value().values[1].status().value_or(StatusCode{}), StatusCode{ua::Status::BadNoData});
  EXPECT_EQ(finalRead.value().values[2].status().value_or(StatusCode{}), StatusCode{ua::Status::BadNoData});
  EXPECT_EQ(annotation_message(finalRead.value().values[3]), "unrelated");
}

// @relation(AC-SVR-HIST-READ-009-DUPLICATE-TIMESTAMPS, scope=function)

// Gap 2 - raw-read ExtraData bit (OPC 10000-11 section 3.1 / section 6.4.3.2): a returned value that hides a
// modification record carries the ExtraData StatusCode info bit.
// @verifies AC-SVR-HIST-READ-014-EXTRADATA
TEST(HistoryEngineReadRaw, ValueHidingModificationRecordGetsExtraDataBit)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();
  // Replace creates a modification record at t=10.
  HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}));

  auto item = raw_item(at(0), at(60));
  auto result = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 1u);
  EXPECT_TRUE(result.value().values[0].status().value_or(StatusCode{}).extra_data());
}

// @relation(AC-SVR-HIST-READ-009-DUPLICATE-TIMESTAMPS, scope=function)

// @verifies AC-SVR-HIST-READ-014-EXTRADATA
TEST(HistoryEngineReadRaw, ValueWithoutModificationHasNoExtraDataBit)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();

  auto item = raw_item(at(0), at(60));
  auto result = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 1u);
  EXPECT_FALSE(result.value().values[0].status().value_or(StatusCode{}).extra_data());
}

// Gap 3 - ModificationInfo records the session user + modification time (OPC 10000-11 section 6.5.3).
TEST(HistoryEngineUpdateData, ReplaceRecordsModificationWithUserNameAndTime)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();
  HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}), "alice");

  auto mods =
    store
      .read_modifications(testNode, std::nullopt, true, std::nullopt, true, 0, ua::history::Direction::After)
      .value();
  ASSERT_EQ(mods.size(), 1u);
  EXPECT_EQ(mods[0].info.user_name(), ua::String{"alice"});
  EXPECT_EQ(mods[0].info.update_type(), ua::HistoryUpdateType::Replace);
  EXPECT_FALSE(mods[0].info.modification_time().is_null());
}

// OPC 10000-11 section 6.4.3.2: "It is specifically not allowed for the Server to return a
// Bad_InvalidArgument StatusCode if the requested time domain is outside of the Server's range. Such a
// case shall be treated as an interval in which no data exists." Range-checking the requested window
// against the historian's extents is the natural way to answer "is this a valid window?", and an
// implementation that does so reports an argument error - telling the client it asked wrongly, when the
// correct answer is that the question was well formed and there is nothing there.
// @verifies AC-SVR-HIST-READ-007-OUT-OF-RANGE-IS-NODATA
TEST(HistoryEngineReadRaw, TimeDomainOutsideStoredRangeIsNoDataNotBadInvalidArgument)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // the entire stored range is t = 0,10,20,30,40

  // Entirely before the earliest stored value.
  auto beforeItem = raw_item(at(-200), at(-100));
  auto before = HistoryEngine::read_raw(store, beforeItem);
  EXPECT_NE(code(before.status_code()), code(StatusCode{ua::Status::BadInvalidArgument}));
  ASSERT_TRUE(before.is_good());
  EXPECT_TRUE(before.value().values.empty());
  EXPECT_FALSE(before.value().cursor.has_value());

  // Entirely after the latest stored value.
  auto afterItem = raw_item(at(100), at(200));
  auto after = HistoryEngine::read_raw(store, afterItem);
  EXPECT_NE(code(after.status_code()), code(StatusCode{ua::Status::BadInvalidArgument}));
  ASSERT_TRUE(after.is_good());
  EXPECT_TRUE(after.value().values.empty());
  EXPECT_FALSE(after.value().cursor.has_value());
}

// OPC 10000-11 section 6.4.3.2: one and the same empty interval has two correct answers, chosen by
// returnBounds. Emptiness of the window is the obvious thing to branch on, so an implementation that
// settles the outcome before consulting returnBounds answers "no data" both times - discarding the
// values either side, which are exactly what the client asked for when it set the flag.
// @verifies AC-SVR-HIST-READ-008-EMPTY-INTERVAL-STATUS
TEST(HistoryEngineReadRaw, EmptyIntervalReturnsNothingWithoutBoundsAndTheBoundingValuesWithThem)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 5);  // t = 0,10,20,30,40 - the interval (12, 18) holds nothing

  // Bounds not requested: the interval is empty and nothing is returned.
  auto withoutBoundsItem = raw_item(at(12), at(18));
  auto withoutBounds = HistoryEngine::read_raw(store, withoutBoundsItem);
  ASSERT_TRUE(withoutBounds.is_good());
  EXPECT_TRUE(withoutBounds.value().values.empty());
  EXPECT_FALSE(withoutBounds.value().cursor.has_value());

  // Same interval, bounds requested: the values either side are returned instead of nothing.
  auto withBoundsItem = raw_item(at(12), at(18), 0, /*bounds*/ true);
  auto withBounds = HistoryEngine::read_raw(store, withBoundsItem);
  ASSERT_TRUE(withBounds.is_good());
  const auto& bounding = withBounds.value().values;
  ASSERT_EQ(bounding.size(), 2u);
  EXPECT_EQ(ticks(bounding[0]), at(10).value().time_since_epoch().count());  // value before the interval
  EXPECT_EQ(ticks(bounding[1]), at(20).value().time_since_epoch().count());  // value after the interval
  // Each bound carries its own stored status, not a no-data or Bad_BoundNotFound placeholder.
  EXPECT_EQ(code(bounding[0].status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(code(bounding[1].status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}));
}

// OPC 10000-11 section 6.5.2.2: "a StatusCode value will be returned for any Event
// field that cannot be returned. The value of the StatusCode shall be Bad_NoData." Leaving the slot of a
// field the historian never collected empty is the natural projection - the lookup simply missed - but it
// is indistinguishable from an Event whose field genuinely held a null value, and it collapses the
// per-field answer into the same "nothing here" the empty-range case reports for the whole operation.
// @verifies AC-SVR-HIST-READ-004-EVENT-NODATA
TEST(HistoryEngineReadEvents, EmptyRangeYieldsNoEventsWhileAnUnavailableFieldIsBadNoDataInItsOwnSlot)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();  // carries Severity, never Message

  // A range containing no Events at all: the operation succeeds and yields no rows.
  auto emptyRangeItem = events_item(at(100), at(160), filter_selecting({"Severity"}));
  auto emptyRange = HistoryEngine::read_events(store, emptyRangeItem);
  ASSERT_TRUE(emptyRange.is_good());
  EXPECT_TRUE(emptyRange.value().events.empty());
  EXPECT_FALSE(emptyRange.value().cursor.has_value());

  // A range whose Event lacks a selected field: the Event is still returned, and the field it cannot
  // supply carries Bad_NoData in that field's position.
  auto missingFieldItem = events_item(at(0), at(60), filter_selecting({"Severity", "Message"}));
  missingFieldItem.selectClauseModelStatuses.assign(2, StatusCode{Status::Good});
  auto missingField = HistoryEngine::read_events(store, missingFieldItem);
  ASSERT_TRUE(missingField.is_good());
  ASSERT_EQ(missingField.value().events.size(), 1u);
  const auto& fields = missingField.value().events[0].event_fields();
  ASSERT_EQ(fields.size(), 2u);
  ASSERT_TRUE(fields[0].try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*fields[0].try_as<double>(), 100.0);  // the field the historian did collect
  const auto* unavailable = fields[1].try_as<StatusCode>();
  ASSERT_NE(unavailable, nullptr);
  EXPECT_EQ(code(*unavailable), code(StatusCode{ua::Status::BadNoData}));
}

// OPC 10000-11 section 6.8.2 (Insert data functionality): "If an entry exists at the specified
// timestamp, then the new entry shall not be inserted; instead the StatusCode shall indicate
// Bad_EntryExists." Reporting the code is the visible half of that sentence; not writing is the half
// an implementation loses, because the natural store primitive for "put this value at this time" is an
// upsert (SQL INSERT OR REPLACE, map::operator[]) that overwrites first and lets the status be decided
// from the pre-read afterwards - the caller is told its insert was refused while the value it never
// asked to touch has already been replaced by the one that was rejected.
// @verifies AC-SVR-HIST-UPD-001-INSERT-ENTRYEXISTS
TEST(HistoryEngineUpdateData, InsertAtAnOccupiedTimestampIsRefusedAndLeavesTheStoredValueIntact)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();  // the entry the insert must not disturb

  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Insert, {sample(10, 999.0)}));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 1u);
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadEntryExists}));

  // The occupied timestamp still holds the original value, not the rejected one.
  auto stored = store.read_value_at(testNode, at(10)).value();
  ASSERT_TRUE(stored.has_value());
  ASSERT_TRUE(stored->value().try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*stored->value().try_as<double>(), 1.0);

  // Nor was the rejected value appended beside it: a raw read over the whole range still reports one
  // entry, at the original timestamp and carrying the original value.
  auto item = raw_item(at(0), at(60));
  auto read = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().values.size(), 1u);
  EXPECT_EQ(ticks(read.value().values[0]), at(10).value().time_since_epoch().count());
  ASSERT_TRUE(read.value().values[0].value().try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*read.value().values[0].value().try_as<double>(), 1.0);
}

// OPC 10000-11 section 6.8.2.3 (Replace data functionality): where no entry exists at the specified
// timestamp the new entry shall not be inserted and the StatusCode shall indicate Bad_NoEntryExists.
// This is the mirror of the insert-collision rule above and it fails the same way: the store primitive
// that serves Replace is the one that serves Insert, so a Replace aimed at an empty timestamp writes the
// value and then reports whatever the pre-read found - the caller is told the entry did not exist while
// the history has silently gained the entry it was told was not there.
// @verifies AC-SVR-HIST-UPD-003-REPLACE-NOENTRY
TEST(HistoryEngineUpdateData, AReplaceAtAnUnoccupiedTimestampIsRefusedAndInsertsNothing)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(0, 0.0)).value();  // a neighbour, so the history is not merely empty

  auto result =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 5.0)}));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 1u);
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::BadNoEntryExists}));

  // Nothing was inserted at the timestamp the replace named ...
  EXPECT_FALSE(store.read_value_at(testNode, at(10)).value().has_value())
    << "the refused replace inserted an entry at the unoccupied timestamp anyway";

  // ... and the history still holds only the entry that was there before.
  auto item = raw_item(at(0), at(60));
  auto read = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().values.size(), 1u) << "the refused replace changed how many values the history "
                                               "holds; only the pre-existing value at t=0 should remain";
  EXPECT_EQ(ticks(read.value().values[0]), at(0).value().time_since_epoch().count());
}

namespace
{
using ua::AddressSpace;
using ua::InstantiationOptions;
using ua::QualifiedName;
using ua::ReferenceTypeId;

// Instantiation options whose first allocated node takes `rootId` and subsequent nodes get unique ids.
InstantiationOptions options_rooted_at(const ua::server::Server& server, const NodeId& rootId)
{
  InstantiationOptions options{.parentReferenceType = NodeId{ReferenceTypeId::Organizes},
    .nodeIdAllocator = {},
    .optionalChildFilter = {},
    .targetNamespaceIndex = std::nullopt};
  options.nodeIdAllocator = [rootId, first = true](uint16_t ns, const QualifiedName&) mutable -> NodeId
  {
    if (first)
    {
      first = false;
      return rootId;
    }
    static std::atomic<uint32_t> counter{78000};
    return NodeId{ns, counter.fetch_add(1)};
  };
  return options;
}

// A historised Double DataVariable under the Objects folder - a HistoricalDataNode in Part 11 terms.
NodeId make_historised_variable(AddressSpace addressSpace, const ua::server::Server& server,
  const NodeId& nodeId, std::string_view browseName)
{
  const ua::VariableInstantiationAttributes attrs{.dataType = NodeId{ua::DataTypeId::Double},
    .valueRank = ua::ValueRank::scalar,
    .accessLevel = ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead,
      ua::AccessLevelType::Bit::HistoryRead,
      ua::AccessLevelType::Bit::HistoryWrite}};
  auto variable = ua::BaseDataVariable::try_create_sync(addressSpace,
    NodeId{ua::ObjectId::ObjectsFolder},
    QualifiedName{nodeId.namespace_index(), std::string{browseName}},
    options_rooted_at(server, nodeId),
    attrs)
                    .value();
  variable.release();
  return variable.node_id();
}

// A history delegate whose collection supports nothing at all - in particular, no Annotations.
class NoAnnotationsDelegate : public ua::NamespaceHistoryDelegate
{
public:
  Capabilities capabilities() const noexcept override
  {
    return Capabilities{};
  }
};

// Whether `parent` carries a forward HasProperty reference to a local node browse-named "Annotations".
bool node_advertises_annotations(AddressSpace addressSpace, const NodeId& parent)
{
  auto parentNode = addressSpace.find_node_sync(parent);
  for (const auto& ref : parentNode.get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
      continue;
    if (ref.type_id() != NodeId{ReferenceTypeId::HasProperty})
      continue;
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    auto child = addressSpace.try_find_node_sync(target.node_id());
    if (child.is_good() && child.value().get_browse_name().name() == "Annotations")
      return true;
  }
  return false;
}
}  // namespace

// OPC 10000-11 section 5.1: "A Server shall add the Annotations Property to a HistoricalDataNode only if it
// will also support Annotations on that HistoricalDataNode." Modelling the Property uniformly across every
// historised Variable is the tidier build - one instantiation path, no per-node branch - and it is exactly
// what the clause forbids: the Property's presence is the client's only signal that annotation is
// available, so an empty one on a node whose collection cannot hold annotations invites a write that is
// accepted nowhere. The two halves must be observed on one server, since the defect is the *uniformity*.
// @verifies AC-SVR-HIST-ANN-009-ANNOTATIONS-ONLY-IF-SUPPORTED
TEST(HistoryEngineAnnotationsProperty, PropertyPresentOnlyOnNodesWhoseHistoryCollectionSupportsAnnotations)
{
  ua::test_helpers::TestServer server;
  server.create();
  auto addressSpace = server.server().address_space();

  const NodeId supportedId{1, "Engine.Historised.Supported"};
  make_historised_variable(addressSpace, server.server(), supportedId, "EngineHistorisedSupported");
  const NodeId unsupportedId{1, "Engine.Historised.Unsupported"};
  make_historised_variable(addressSpace, server.server(), unsupportedId, "EngineHistorisedUnsupported");

  // One historian backs annotations (the real SqliteHistoryStore-backed delegate), the other does not.
  auto backingStore = std::make_unique<SqliteHistoryStore>(":memory:", make_codec());
  ua::history::HistoryEngineDelegate annotating{std::move(backingStore)};
  ASSERT_TRUE(annotating.capabilities().readAnnotations || annotating.capabilities().insertAnnotation);
  NoAnnotationsDelegate notAnnotating;
  ASSERT_FALSE(notAnnotating.capabilities().readAnnotations || notAnnotating.capabilities().insertAnnotation);

  auto added = ua::history::add_annotations_property(addressSpace,
    supportedId,
    annotating,
    options_rooted_at(server.server(), NodeId{1, "Engine.Supported.Annotations"}));
  ASSERT_TRUE(added.is_good()) << "status=" << added.status_code().as_uint32();

  auto refused = ua::history::add_annotations_property(addressSpace,
    unsupportedId,
    notAnnotating,
    options_rooted_at(server.server(), NodeId{1, "Engine.Unsupported.Annotations"}));
  EXPECT_TRUE(refused.is_bad());
  EXPECT_EQ(code(refused.status_code()), code(StatusCode{ua::Status::BadNotSupported}));

  // Present where the collection supports Annotations ...
  EXPECT_TRUE(node_advertises_annotations(addressSpace, supportedId))
    << "the supporting HistoricalDataNode must advertise the Annotations Property";
  // ... and absent - not an empty placeholder - where it does not.
  EXPECT_FALSE(node_advertises_annotations(addressSpace, unsupportedId))
    << "a node whose collection cannot hold Annotations must carry no Annotations Property at all";
}

namespace
{

// ---------------------------------------------------------------------------
// HistoryUpdate audit-trail harness (OPC 10000-11 section 5.6).
//
// The audit Events are raised by the SDK's HistoryUpdateService, not by the engine, so these tests
// drive a real HistoryUpdateRequest through a real server whose namespace is served by the reference
// `ua::history::HistoryEngineDelegate` over the same in-memory SqliteHistoryStore the rest of this file
// uses. Nothing here fabricates an audit Event: the capturing EventBus below only records the
// objects the service itself emitted, and the update outcomes come from the real engine.
// ---------------------------------------------------------------------------

const char* const auditNamespaceUri = "uri://history-engine-audit-ns";

// A namespace whose Historical Access is served by the reference delegate.
class AuditHistoryNamespace : public ua::default_ns::Namespace,
                              public std::enable_shared_from_this<AuditHistoryNamespace>
{
public:
  AuditHistoryNamespace(std::string_view uri, boost::asio::any_io_executor executor)
    : ua::default_ns::Namespace(uri, std::move(executor))
  {}

  void set_history_delegate(std::shared_ptr<ua::NamespaceHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  std::shared_ptr<ua::NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  std::shared_ptr<ua::NamespaceHistoryDelegate> mDelegate;
};

// What one emitted audit Event carried. The payload hierarchy mirrors the NS0 EventType hierarchy
// one-for-one, so a successful dynamic_cast is exactly the spec's "that type or a sub-type of it"
// test, taken from the object the service really emitted rather than from a name the test supplies.
struct CapturedHistoryAudit
{
  ua::NodeId eventType;
  ua::NodeId sourceNode;
  bool status{false};

  bool isHistoryUpdateFamily{false};
  bool isValueUpdateFamily{false};
  bool isEventUpdateFamily{false};
  bool isDeleteFamily{false};
  bool isRawModifyDeleteFamily{false};
  bool isAtTimeDeleteFamily{false};
  bool isEventDeleteFamily{false};

  std::optional<ua::NodeId> updatedNode;
  std::optional<int32_t> performInsertReplace;
  bool newValuesPresent{false};

  std::optional<bool> isDeleteModified;
  bool startTimePresent{false};
  bool endTimePresent{false};

  ua::Variant reqTimes;
  ua::Array<ua::ByteString> eventIds;
};

class CapturingAuditEventBus : public ua::server::EventBus
{
public:
  explicit CapturingAuditEventBus(ua::AddressSpace addressSpace)
    : ua::server::EventBus(std::move(addressSpace))
  {}

  void emit(ua::BaseEvent& event) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    CapturedHistoryAudit captured;
    captured.eventType = event.eventType;
    captured.sourceNode = event.sourceNode;

    if (auto* audit = dynamic_cast<ua::AuditEventPayload*>(&event))
      captured.status = audit->status;

    captured.isHistoryUpdateFamily = dynamic_cast<ua::AuditHistoryUpdateEventPayload*>(&event) != nullptr;
    captured.isValueUpdateFamily = dynamic_cast<ua::AuditHistoryValueUpdateEventPayload*>(&event) != nullptr;
    captured.isEventUpdateFamily = dynamic_cast<ua::AuditHistoryEventUpdateEventPayload*>(&event) != nullptr;
    captured.isDeleteFamily = dynamic_cast<ua::AuditHistoryDeleteEventPayload*>(&event) != nullptr;
    captured.isRawModifyDeleteFamily =
      dynamic_cast<ua::AuditHistoryRawModifyDeleteEventPayload*>(&event) != nullptr;
    captured.isAtTimeDeleteFamily =
      dynamic_cast<ua::AuditHistoryAtTimeDeleteEventPayload*>(&event) != nullptr;
    captured.isEventDeleteFamily = dynamic_cast<ua::AuditHistoryEventDeleteEventPayload*>(&event) != nullptr;

    if (auto* valueUpdate = dynamic_cast<ua::AuditHistoryValueUpdateEventPayload*>(&event))
    {
      captured.updatedNode = valueUpdate->updatedNode;
      if (!valueUpdate->performInsertReplace.empty())
        captured.performInsertReplace = valueUpdate->performInsertReplace.as<int32_t>();
      captured.newValuesPresent = !valueUpdate->newValues.empty();
    }
    if (auto* eventUpdate = dynamic_cast<ua::AuditHistoryEventUpdateEventPayload*>(&event))
    {
      captured.updatedNode = eventUpdate->updatedNode;
      if (!eventUpdate->performInsertReplace.empty())
        captured.performInsertReplace = eventUpdate->performInsertReplace.as<int32_t>();
      captured.newValuesPresent = !eventUpdate->newValues.empty();
    }
    if (auto* rawDelete = dynamic_cast<ua::AuditHistoryRawModifyDeleteEventPayload*>(&event))
    {
      captured.updatedNode = rawDelete->updatedNode;
      captured.isDeleteModified = rawDelete->isDeleteModified;
      captured.startTimePresent = !rawDelete->startTime.empty();
      captured.endTimePresent = !rawDelete->endTime.empty();
    }
    else if (auto* atTimeDelete = dynamic_cast<ua::AuditHistoryAtTimeDeleteEventPayload*>(&event))
    {
      captured.updatedNode = atTimeDelete->updatedNode;
      captured.reqTimes = atTimeDelete->reqTimes;
    }
    else if (auto* eventDelete = dynamic_cast<ua::AuditHistoryEventDeleteEventPayload*>(&event))
    {
      captured.updatedNode = eventDelete->updatedNode;
      captured.eventIds = eventDelete->eventIds;
    }
    else if (auto* anyDelete = dynamic_cast<ua::AuditHistoryDeleteEventPayload*>(&event))
    {
      captured.updatedNode = anyDelete->updatedNode;
    }

    mEvents.push_back(std::move(captured));
  }

  std::vector<CapturedHistoryAudit> events()
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mEvents;
  }

private:
  std::mutex mMutex;
  std::vector<CapturedHistoryAudit> mEvents;
};

struct HistoryAuditHarness
{
  ~HistoryAuditHarness()
  {
    sessionInfo.reset();
    ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  std::shared_ptr<AuditHistoryNamespace> historyNamespace;
  std::shared_ptr<SessionInfoStub> sessionInfo;
  uint16_t nsIndex{0};

  // A server with auditing enabled and one history-serving namespace behind the reference delegate.
  void setup()
  {
    ua::server::ServerConfig serverConfig;
    serverConfig.auditingEnabled = true;
    ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::test_utils::create_test_config(),
      .server = std::move(serverConfig)};

    std::optional<ua::server::Server> server;
    server.emplace(ua::server::Server::create(threadPool.get_executor(),
      std::move(config),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

    historyNamespace = std::make_shared<AuditHistoryNamespace>(auditNamespaceUri, threadPool.get_executor());
    historyNamespace->set_history_delegate(std::make_shared<ua::history::HistoryEngineDelegate>(
      std::make_unique<SqliteHistoryStore>(":memory:", make_codec())));
    server->address_space().add_namespace_sync(historyNamespace);
    nsIndex = server->address_space().namespace_array().get_namespace_index(auditNamespaceUri);

    sessionInfo = std::make_shared<SessionInfoStub>(std::move(*server), threadPool.get_executor());
    server.reset();
  }

  ua::NodeId historised_variable(uint32_t numericId)
  {
    ua::NodeId nodeId{nsIndex, numericId};
    auto addressSpace = sessionInfo->address_space();
    auto varResult = addressSpace.try_create_sync<ua::VariableAccessor>(nodeId, ua::NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "failed to create the historised Variable";
    if (varResult.is_good())
    {
      ua::AccessLevelType accessLevel;
      accessLevel.set(ua::AccessLevelType::Bit::CurrentRead);
      accessLevel.set(ua::AccessLevelType::Bit::HistoryRead);
      accessLevel.set(ua::AccessLevelType::Bit::HistoryWrite);
      varResult.value().set_access_level(accessLevel);
    }
    return nodeId;
  }

  ua::NodeId event_source_object(uint32_t numericId)
  {
    ua::NodeId nodeId{nsIndex, numericId};
    auto addressSpace = sessionInfo->address_space();
    auto objResult = addressSpace.try_create_sync<ua::ObjectAccessor>(nodeId, ua::NodeClass::Object);
    EXPECT_TRUE(objResult.is_good()) << "failed to create the event-source Object";
    if (objResult.is_good())
    {
      ua::EventNotifierType notifier;
      notifier.set(ua::EventNotifierType::Bit::HistoryWrite);
      objResult.value().set_event_notifier(notifier);
    }
    return nodeId;
  }

  ua::Response run(ua::HistoryUpdateRequest request)
  {
    auto resultPromise = std::make_shared<std::promise<ua::Response>>();
    auto resultFuture = resultPromise->get_future();
    auto service = ua::server::HistoryUpdateService::create(sessionInfo,
      0,
      std::move(request),
      threadPool.get_executor(),
      [resultPromise](ua::Response response) { resultPromise->set_value(std::move(response)); });
    if (resultFuture.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the HistoryUpdate service did not complete";
      return {};
    }
    return resultFuture.get();
  }
};

ua::HistoryUpdateResponse* update_response(const ua::Response& response)
{
  return dynamic_cast<ua::HistoryUpdateResponse*>(std::get<std::shared_ptr<ua::Structure>>(response).get());
}

std::unique_ptr<ua::UpdateDataDetails> data_details(
  const ua::NodeId& nodeId, ua::PerformUpdateType mode, const DataValue& value)
{
  auto details = std::make_unique<ua::UpdateDataDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = mode;
  details->update_values().push_back(value);
  return details;
}

std::unique_ptr<ua::UpdateEventDetails> event_details(
  const ua::NodeId& nodeId, ua::PerformUpdateType mode, ua::HistoryEventFieldList record)
{
  // `record` carries the three fields a caller varies - EventId, Time and Severity - and the rest
  // of BaseEventType's Mandatory set is filled in around them. The padding is not decoration: a
  // Server that enforces OPC 10000-11 6.8.4.2 refuses an insert whose selectClause omits a field
  // the EventType makes Mandatory, so a partial row would exercise the refusal rather than the
  // behaviour these callers are about. Anything that varies stays in `record`; anything held
  // constant is written here once.
  auto details = std::make_unique<ua::UpdateEventDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = mode;
  for (const auto* name :
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"})
  {
    ua::SimpleAttributeOperand clause;
    clause.type_definition_id() = ua::NodeId{ua::ObjectTypeId::BaseEventType};
    clause.browse_path().push_back(ua::QualifiedName{uint16_t{0}, name});
    clause.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    details->filter().select_clauses().push_back(clause);
  }

  const auto& supplied = record.event_fields();
  const auto time =
    supplied.size() > 1 && supplied[1].try_as<DateTime>() ? supplied[1].as<DateTime>() : at(0);
  // Severity is a UInt16 on BaseEventType; callers spell it as a double for brevity.
  const auto severity = supplied.size() > 2 && supplied[2].try_as<double>()
                          ? static_cast<uint16_t>(supplied[2].as<double>())
                          : uint16_t{1};

  ua::HistoryEventFieldList row;
  row.event_fields().push_back(supplied.empty() ? Variant{} : supplied[0]);
  row.event_fields().push_back(Variant{ua::NodeId{ua::ObjectTypeId::BaseEventType}});
  row.event_fields().push_back(Variant{nodeId});
  row.event_fields().push_back(Variant{ua::String{"history engine tests"}});
  row.event_fields().push_back(Variant{time});
  row.event_fields().push_back(Variant{time});
  row.event_fields().push_back(Variant{ua::LocalizedText{"", "history engine tests"}});
  row.event_fields().push_back(Variant{severity});
  details->event_data().push_back(std::move(row));
  return details;
}

std::unique_ptr<ua::UpdateStructureDataDetails> annotation_details(
  const ua::NodeId& nodeId, ua::PerformUpdateType mode, const DataValue& annotation)
{
  auto details = std::make_unique<ua::UpdateStructureDataDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = mode;
  details->update_values().push_back(annotation);
  return details;
}

std::unique_ptr<ua::DeleteRawModifiedDetails> raw_delete_details(
  const ua::NodeId& nodeId, bool deleteModified, DateTime start, DateTime end)
{
  auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
  details->node_id() = nodeId;
  details->is_delete_modified() = deleteModified;
  details->start_time() = start;
  details->end_time() = end;
  return details;
}

std::unique_ptr<ua::DeleteAtTimeDetails> at_time_delete_details(
  const ua::NodeId& nodeId, const std::vector<DateTime>& times)
{
  auto details = std::make_unique<ua::DeleteAtTimeDetails>();
  details->node_id() = nodeId;
  for (const auto& time : times)
    details->req_times().push_back(time);
  return details;
}

std::unique_ptr<ua::DeleteEventDetails> event_delete_details(
  const ua::NodeId& nodeId, const std::vector<ua::ByteString>& eventIds)
{
  auto details = std::make_unique<ua::DeleteEventDetails>();
  details->node_id() = nodeId;
  for (const auto& eventId : eventIds)
    details->event_ids().push_back(eventId);
  return details;
}

// The one audit Event whose SourceNode is `nodeId`, or nullptr when the service raised none.
const CapturedHistoryAudit* audit_for(
  const std::vector<CapturedHistoryAudit>& events, const ua::NodeId& nodeId)
{
  const CapturedHistoryAudit* match = nullptr;
  for (const auto& event : events)
  {
    if (event.sourceNode == nodeId)
      match = &event;
  }
  return match;
}

// True when at least one per-operation status in `result` is bad - i.e. the update really failed.
bool any_operation_failed(const ua::HistoryUpdateResult& result)
{
  for (size_t i = 0; i < result.operation_results().size(); ++i)
  {
    if (result.operation_results()[i].is_bad())
      return true;
  }
  return false;
}

}  // namespace

// OPC 10000-11 section 5.6: "Servers shall generate Events of the AuditHistoryUpdateEventType or a
// sub-type of this type for all invocations of the HistoryUpdate Service on any HistoricalNode" -
// every update mode, and regardless of whether the update succeeded. An implementation naturally
// wires the audit emitter into the one success path it first writes (value updates, or the branch
// taken when every operation returned Good), leaving the remaining modes - and every refused
// update - with no audit record at all, which is precisely the case an auditor is looking for.
// @verifies AC-SVR-HIST-AUDIT-001-UPDATE-AUDITED
TEST(HistoryUpdateAuditTrail, EveryUpdateModeRaisesAnAuditHistoryUpdateEventOnSuccessAndOnFailure)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto dataNode = harness.historised_variable(900);
  const auto eventNode = harness.historised_variable(901);
  const auto annotationNode = harness.historised_variable(902);
  const auto rawDeleteNode = harness.historised_variable(903);
  const auto atTimeDeleteNode = harness.historised_variable(904);
  const auto eventDeleteNode = harness.event_source_object(905);

  // Seed the historian so the delete modes have something real to remove. No sink is attached yet,
  // so the audit Events counted below belong only to the requests under test.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(5);
    seedRequest.history_update_details()[0] =
      data_details(rawDeleteNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(atTimeDeleteNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[2] =
      event_details(eventDeleteNode, ua::PerformUpdateType::Insert, event_record({{2}}, 10, 1.0));
    seedRequest.history_update_details()[3] =
      data_details(dataNode, ua::PerformUpdateType::Insert, sample(0, 0.0));
    seedRequest.history_update_details()[4] =
      annotation_details(annotationNode, ua::PerformUpdateType::Insert, make_annotation(0, "seed"));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 5u);
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  // Round 1 - every update mode, each succeeding.
  ua::HistoryUpdateRequest succeeding;
  succeeding.request_header().request_handle() = 2;
  succeeding.history_update_details().resize(6);
  succeeding.history_update_details()[0] =
    data_details(dataNode, ua::PerformUpdateType::Insert, sample(20, 2.0));
  succeeding.history_update_details()[1] =
    event_details(eventNode, ua::PerformUpdateType::Insert, event_record({{1}}, 10, 1.0));
  succeeding.history_update_details()[2] =
    annotation_details(annotationNode, ua::PerformUpdateType::Insert, make_annotation(20, "note"));
  succeeding.history_update_details()[3] = raw_delete_details(rawDeleteNode, false, at(0), at(60));
  succeeding.history_update_details()[4] = at_time_delete_details(atTimeDeleteNode, {at(10)});
  succeeding.history_update_details()[5] =
    event_delete_details(eventDeleteNode, {ua::ByteString{std::vector<uint8_t>{2}}});

  auto succeeded = harness.run(std::move(succeeding));
  auto* succeededResponse = update_response(succeeded);
  ASSERT_NE(succeededResponse, nullptr);
  ASSERT_EQ(succeededResponse->results().size(), 6u);
  for (size_t i = 0; i < 6u; ++i)
    EXPECT_TRUE(succeededResponse->results()[i].status_code().is_good()) << "detail " << i << " was refused";

  auto afterSuccess = eventBus.events();
  ASSERT_EQ(afterSuccess.size(), 6u) << "each update mode must raise exactly one audit Event";
  for (const auto& nodeId :
    {dataNode, eventNode, annotationNode, rawDeleteNode, atTimeDeleteNode, eventDeleteNode})
  {
    const auto* match = audit_for(afterSuccess, nodeId);
    ASSERT_NE(match, nullptr) << "an update mode raised no audit Event at all";
    EXPECT_TRUE(match->isHistoryUpdateFamily)
      << "the Event must be AuditHistoryUpdateEventType or a sub-type of it";
    EXPECT_TRUE(match->status) << "a successful update must be audited as successful";
  }

  // Round 2 - the same modes, now failing: each collides with what round 1 left behind, or names
  // an entry that does not exist. Delete-raw is omitted: deleting an empty range is not an error.
  ua::HistoryUpdateRequest failing;
  failing.request_header().request_handle() = 3;
  failing.history_update_details().resize(5);
  failing.history_update_details()[0] =
    data_details(dataNode, ua::PerformUpdateType::Insert, sample(20, 9.0));
  failing.history_update_details()[1] =
    event_details(eventNode, ua::PerformUpdateType::Insert, event_record({{1}}, 10, 9.0));
  failing.history_update_details()[2] =
    annotation_details(annotationNode, ua::PerformUpdateType::Insert, make_annotation(20, "again"));
  failing.history_update_details()[3] = at_time_delete_details(atTimeDeleteNode, {at(999)});
  failing.history_update_details()[4] =
    event_delete_details(eventDeleteNode, {ua::ByteString{std::vector<uint8_t>{99}}});

  auto failed = harness.run(std::move(failing));
  auto* failedResponse = update_response(failed);
  ASSERT_NE(failedResponse, nullptr);
  ASSERT_EQ(failedResponse->results().size(), 5u);
  for (size_t i = 0; i < 5u; ++i)
    EXPECT_TRUE(any_operation_failed(failedResponse->results()[i])) << "detail " << i << " did not fail";

  auto afterFailure = eventBus.events();
  ASSERT_EQ(afterFailure.size(), 11u) << "a refused update must still be audited";
  const std::vector<CapturedHistoryAudit> failureEvents{afterFailure.begin() + 6, afterFailure.end()};
  ASSERT_EQ(failureEvents.size(), 5u);
  for (const auto& nodeId : {dataNode, eventNode, annotationNode, atTimeDeleteNode, eventDeleteNode})
  {
    const auto* match = audit_for(failureEvents, nodeId);
    ASSERT_NE(match, nullptr) << "a failing update mode raised no audit Event at all";
    EXPECT_TRUE(match->isHistoryUpdateFamily)
      << "a refused update must still be AuditHistoryUpdateEventType or a sub-type of it";
  }
}

// OPC 10000-11 section 5.6.1 (lines 1188-1190): inserting historical Events shall raise
// AuditHistoryEventUpdateEventType. A HistoryUpdate request carries every update flavour in one
// details array, so routing them all through a single emitter - or reusing the value-update emitter
// that the far commoner data path already needed - is the natural build. It raises a type that an
// audit query filtering on Event-history changes will never select, and the record of who altered
// the Event history is silently filed as a value change.
// @verifies AC-SVR-HIST-AUDIT-002-EVENT-INSERT-SUBTYPE
TEST(HistoryUpdateAuditTrail, InsertingHistoricalEventsRaisesTheEventUpdateSubTypeNotTheGenericParent)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto eventNode = harness.historised_variable(910);

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(1);
  request.history_update_details()[0] =
    event_details(eventNode, ua::PerformUpdateType::Insert, event_record({{7}}, 10, 500.0));

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "inserting historical Events must raise an audit Event";

  const ua::AuditHistoryEventUpdateEventPayload eventUpdateType;
  const ua::AuditHistoryUpdateEventPayload genericUpdateType;
  const ua::AuditHistoryValueUpdateEventPayload valueUpdateType;

  EXPECT_TRUE(events[0].isEventUpdateFamily)
    << "the emitted payload must be AuditHistoryEventUpdateEventType or a sub-type";
  EXPECT_EQ(events[0].eventType, eventUpdateType.eventType);
  EXPECT_NE(events[0].eventType, genericUpdateType.eventType)
    << "the generic AuditHistoryUpdateEventType is not sufficient for an Event insert";
  EXPECT_NE(events[0].eventType, valueUpdateType.eventType)
    << "an Event insert must not be recorded as a value update";
  EXPECT_EQ(events[0].sourceNode, eventNode);
}

// OPC 10000-11 section 5.6.1 (lines 1191-1193): "In the case where the HistoryUpdate Service is
// invoked to delete records, the AuditHistoryDeleteEventType or one of its sub-types shall be
// generated." Deletion is the one history operation that leaves no recoverable trace, so an
// implementation that falls back to the generic update audit for any one of the three delete
// flavours leaves an auditor unable to tell a correction from an erasure. All three are asserted on
// one server because the defect is a missing branch, visible only where the branches are compared.
// @verifies AC-SVR-HIST-AUDIT-003-DELETE-SUBTYPE
TEST(HistoryUpdateAuditTrail, EveryDeleteFlavourRaisesAnAuditHistoryDeleteEventOrASubType)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto rawDeleteNode = harness.historised_variable(920);
  const auto atTimeDeleteNode = harness.historised_variable(921);
  const auto eventDeleteNode = harness.event_source_object(922);

  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(3);
    seedRequest.history_update_details()[0] =
      data_details(rawDeleteNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(atTimeDeleteNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[2] =
      event_details(eventDeleteNode, ua::PerformUpdateType::Insert, event_record({{3}}, 10, 1.0));
    auto seedResult = harness.run(std::move(seedRequest));
    ASSERT_NE(update_response(seedResult), nullptr);
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 2;
  request.history_update_details().resize(3);
  request.history_update_details()[0] = raw_delete_details(rawDeleteNode, false, at(0), at(60));
  request.history_update_details()[1] = at_time_delete_details(atTimeDeleteNode, {at(10)});
  request.history_update_details()[2] =
    event_delete_details(eventDeleteNode, {ua::ByteString{std::vector<uint8_t>{3}}});

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (size_t i = 0; i < 3u; ++i)
    EXPECT_TRUE(response->results()[i].status_code().is_good()) << "delete detail " << i << " was refused";

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 3u) << "every delete flavour must raise its own audit Event";

  const ua::AuditHistoryUpdateEventPayload genericUpdateType;
  for (const auto& nodeId : {rawDeleteNode, atTimeDeleteNode, eventDeleteNode})
  {
    const auto* match = audit_for(events, nodeId);
    ASSERT_NE(match, nullptr) << "a delete raised no audit Event at all";
    EXPECT_TRUE(match->isDeleteFamily)
      << "a delete must raise AuditHistoryDeleteEventType or a sub-type of it";
    EXPECT_NE(match->eventType, genericUpdateType.eventType)
      << "the generic AuditHistoryUpdateEventType does not record that history was erased";
    ASSERT_TRUE(match->updatedNode.has_value()) << "UpdatedNode must name the node whose history was erased";
    EXPECT_EQ(*match->updatedNode, nodeId);
  }
}

// OPC 10000-11 section 5.6.1 (lines 1195-1196): "using the Delete raw or Delete modified
// functionality shall generate an AuditHistoryRawModifyDeleteEventType Event or a sub-type of it."
// Both forms arrive as the same DeleteRawModifiedDetails distinguished only by IsDeleteModified, so
// an implementation that branches on that flag - or that copies the flag from a default rather than
// from the request - records the erasure of raw values and the erasure of the modification history
// as the same act, or leaves the modified form under the generic parent with the range unstated.
// @verifies AC-SVR-HIST-AUDIT-004-DELETE-SUBTYPE
TEST(HistoryUpdateAuditTrail, DeletingRawAndDeletingModifiedBothRaiseTheRawModifyDeleteSubType)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto rawNode = harness.historised_variable(930);
  const auto modifiedNode = harness.historised_variable(931);

  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      data_details(rawNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(modifiedNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    auto seedResult = harness.run(std::move(seedRequest));
    ASSERT_NE(update_response(seedResult), nullptr);
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 2;
  request.history_update_details().resize(2);
  request.history_update_details()[0] = raw_delete_details(rawNode, false, at(0), at(60));
  request.history_update_details()[1] = raw_delete_details(modifiedNode, true, at(0), at(60));

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_TRUE(response->results()[1].status_code().is_good());

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 2u) << "delete-raw and delete-modified must each raise an audit Event";

  const ua::AuditHistoryRawModifyDeleteEventPayload rawModifyDeleteType;
  const ua::AuditHistoryUpdateEventPayload genericUpdateType;

  const auto* rawEvent = audit_for(events, rawNode);
  ASSERT_NE(rawEvent, nullptr) << "delete-raw raised no audit Event";
  EXPECT_TRUE(rawEvent->isRawModifyDeleteFamily)
    << "delete-raw must raise AuditHistoryRawModifyDeleteEventType or a sub-type";
  EXPECT_EQ(rawEvent->eventType, rawModifyDeleteType.eventType);
  EXPECT_NE(rawEvent->eventType, genericUpdateType.eventType);
  ASSERT_TRUE(rawEvent->isDeleteModified.has_value());
  EXPECT_FALSE(*rawEvent->isDeleteModified);
  EXPECT_TRUE(rawEvent->startTimePresent);
  EXPECT_TRUE(rawEvent->endTimePresent);

  const auto* modifiedEvent = audit_for(events, modifiedNode);
  ASSERT_NE(modifiedEvent, nullptr) << "delete-modified raised no audit Event";
  EXPECT_TRUE(modifiedEvent->isRawModifyDeleteFamily)
    << "delete-modified must raise AuditHistoryRawModifyDeleteEventType or a sub-type";
  EXPECT_EQ(modifiedEvent->eventType, rawModifyDeleteType.eventType);
  EXPECT_NE(modifiedEvent->eventType, genericUpdateType.eventType);
  ASSERT_TRUE(modifiedEvent->isDeleteModified.has_value());
  EXPECT_TRUE(*modifiedEvent->isDeleteModified)
    << "the audit Event must carry the IsDeleteModified the request actually used";
  EXPECT_TRUE(modifiedEvent->startTimePresent);
  EXPECT_TRUE(modifiedEvent->endTimePresent);
}

// OPC 10000-11 section 5.6.1 (lines 1196-1197): "Using the Delete at time functionality shall
// generate an AuditHistoryAtTimeDeleteEventType Event or a sub-type of it." The deleted values are
// gone, so the ReqTimes the Event carries are the only surviving record of what was removed;
// raising the right sub-type with an empty ReqTimes satisfies a type check and records nothing.
// Copying the node identity is the obvious half of populating the payload and is all the audit
// needs to be routable, so the timestamps - the part that costs an extra field copy - are the half
// an implementation drops.
// @verifies AC-SVR-HIST-AUDIT-005-ATTIME-DELETE-SUBTYPE
TEST(HistoryUpdateAuditTrail, DeleteAtTimeRaisesTheAtTimeDeleteSubTypeCarryingTheTimestampsDeleted)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto atTimeNode = harness.historised_variable(940);

  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      data_details(atTimeNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(atTimeNode, ua::PerformUpdateType::Insert, sample(20, 2.0));
    auto seedResult = harness.run(std::move(seedRequest));
    ASSERT_NE(update_response(seedResult), nullptr);
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 2;
  request.history_update_details().resize(1);
  request.history_update_details()[0] = at_time_delete_details(atTimeNode, {at(10), at(20)});

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  ASSERT_EQ(response->results()[0].operation_results().size(), 2u);
  EXPECT_TRUE(response->results()[0].operation_results()[0].is_good()) << "the value at t=10 was not deleted";
  EXPECT_TRUE(response->results()[0].operation_results()[1].is_good()) << "the value at t=20 was not deleted";

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "delete-at-time must raise an audit Event";

  const ua::AuditHistoryAtTimeDeleteEventPayload atTimeDeleteType;
  EXPECT_TRUE(events[0].isAtTimeDeleteFamily)
    << "delete-at-time must raise AuditHistoryAtTimeDeleteEventType or a sub-type";
  EXPECT_EQ(events[0].eventType, atTimeDeleteType.eventType);
  EXPECT_EQ(events[0].sourceNode, atTimeNode);

  // ... and it must carry the timestamps that were erased, which nothing else now records.
  ASSERT_FALSE(events[0].reqTimes.empty())
    << "ReqTimes is empty: the audit records nothing about what was erased";
  auto reqTimes = events[0].reqTimes.to_vector<DateTime>();
  ASSERT_TRUE(reqTimes.is_good()) << "ReqTimes must hold the requested timestamps";
  ASSERT_EQ(reqTimes.value().size(), 2u);
  EXPECT_EQ(
    reqTimes.value()[0].value().time_since_epoch().count(), at(10).value().time_since_epoch().count());
  EXPECT_EQ(
    reqTimes.value()[1].value().time_since_epoch().count(), at(20).value().time_since_epoch().count());
}

// OPC 10000-11 section 5.6.1 (lines 1198-1199): "Using the Delete Event functionality shall generate
// an AuditHistoryEventDeleteEventType Event or a sub-type of it." The EventId is the only handle on
// a stored historical Event, so once the Event is deleted the EventIds field of the audit record is
// the only remaining evidence of which Events were erased. UpdatedNode alone says a node's Event
// history was touched - an implementation that populates the identity fields and stops there leaves
// the audit trail unable to distinguish one erased Event from every Event on that node.
// @verifies AC-SVR-HIST-AUDIT-006-EVENT-DELETE-SUBTYPE
TEST(HistoryUpdateAuditTrail, DeleteEventRaisesTheEventDeleteSubTypeCarryingTheEventIdsDeleted)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto eventNode = harness.event_source_object(950);
  const ua::ByteString firstDeletedEventId{std::vector<uint8_t>{5}};
  const ua::ByteString secondDeletedEventId{std::vector<uint8_t>{6}};

  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      event_details(eventNode, ua::PerformUpdateType::Insert, event_record({{5}}, 10, 1.0));
    seedRequest.history_update_details()[1] =
      event_details(eventNode, ua::PerformUpdateType::Insert, event_record({{6}}, 20, 2.0));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 2u);
    EXPECT_TRUE(seedResponse->results()[0].status_code().is_good());
    EXPECT_TRUE(seedResponse->results()[1].status_code().is_good());
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 2;
  request.history_update_details().resize(1);
  request.history_update_details()[0] =
    event_delete_details(eventNode, {firstDeletedEventId, secondDeletedEventId});

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  ASSERT_EQ(response->results()[0].operation_results().size(), 2u);
  EXPECT_TRUE(response->results()[0].operation_results()[0].is_good()) << "the Event was not deleted";
  EXPECT_TRUE(response->results()[0].operation_results()[1].is_good()) << "the Event was not deleted";

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 1u) << "delete-event must raise an audit Event";

  const ua::AuditHistoryEventDeleteEventPayload eventDeleteType;
  EXPECT_TRUE(events[0].isEventDeleteFamily)
    << "delete-event must raise AuditHistoryEventDeleteEventType or a sub-type";
  EXPECT_EQ(events[0].eventType, eventDeleteType.eventType);
  EXPECT_EQ(events[0].sourceNode, eventNode);

  // ... and it must carry the EventIds erased, which nothing else now records.
  EXPECT_FALSE(events[0].eventIds.empty())
    << "EventIds is empty: the audit does not say which Event was erased";
  ASSERT_EQ(events[0].eventIds.size(), 2u);
  EXPECT_EQ(events[0].eventIds[0], firstDeletedEventId);
  EXPECT_EQ(events[0].eventIds[1], secondDeletedEventId);
}

// OPC 10000-11 section 5.6.1 (lines 1199-1200): "All other updates shall follow the guidelines
// provided in the AuditHistoryUpdateEventType model" - the Event names the node affected, the
// PerformInsertReplace mode used and the values written. Raising the right type with the payload
// left at its defaults satisfies every type check while recording nothing about the change, and the
// values are the field most easily dropped: unlike the node and the mode, they are not needed to
// route or classify the Event, only to say what the history now holds that it did not before.
// @verifies AC-SVR-HIST-AUDIT-007-OTHER-UPDATES
TEST(HistoryUpdateAuditTrail, InsertReplaceAndUpdateAuditEventsCarryTheNodeTheModeAndTheValues)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto insertNode = harness.historised_variable(960);
  const auto replaceNode = harness.historised_variable(961);
  const auto updateNode = harness.historised_variable(962);

  // Replace and Update act on existing entries, so seed the two nodes they target.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      data_details(replaceNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(updateNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    auto seedResult = harness.run(std::move(seedRequest));
    ASSERT_NE(update_response(seedResult), nullptr);
  }

  auto addressSpace = harness.sessionInfo->address_space();
  CapturingAuditEventBus eventBus{addressSpace};
  eventBus.set_event_listener([](const ua::BaseEvent&) {});
  harness.sessionInfo->eventSink = &eventBus;

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 2;
  request.history_update_details().resize(3);
  request.history_update_details()[0] =
    data_details(insertNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
  request.history_update_details()[1] =
    data_details(replaceNode, ua::PerformUpdateType::Replace, sample(10, 2.0));
  request.history_update_details()[2] =
    data_details(updateNode, ua::PerformUpdateType::Update, sample(10, 3.0));

  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (size_t i = 0; i < 3u; ++i)
  {
    EXPECT_TRUE(response->results()[i].status_code().is_good()) << "update detail " << i << " was refused";
    EXPECT_FALSE(any_operation_failed(response->results()[i])) << "update detail " << i << " did not apply";
  }

  auto events = eventBus.events();
  ASSERT_EQ(events.size(), 3u) << "insert, replace and update must each raise an audit Event";

  const std::vector<std::pair<ua::NodeId, ua::PerformUpdateType>> expected{
    {insertNode, ua::PerformUpdateType::Insert},
    {replaceNode, ua::PerformUpdateType::Replace},
    {updateNode, ua::PerformUpdateType::Update}};

  for (const auto& [nodeId, mode] : expected)
  {
    const auto* match = audit_for(events, nodeId);
    ASSERT_NE(match, nullptr) << "an update raised no audit Event at all";
    EXPECT_TRUE(match->isHistoryUpdateFamily)
      << "the Event must follow the AuditHistoryUpdateEventType model";
    // The affected node.
    ASSERT_TRUE(match->updatedNode.has_value()) << "UpdatedNode must name the affected node";
    EXPECT_EQ(*match->updatedNode, nodeId);
    // The mode.
    ASSERT_TRUE(match->performInsertReplace.has_value()) << "PerformInsertReplace must be populated";
    EXPECT_EQ(*match->performInsertReplace, static_cast<int32_t>(mode));
    // The values involved.
    EXPECT_TRUE(match->newValuesPresent)
      << "NewValues must carry the values written; an empty field records nothing";
  }
}

namespace
{

// ---------------------------------------------------------------------------
// Historical Access capability advertisement (OPC 10000-11 section 5.4.2).
//
// The HistoryServerCapabilities properties are written by the server itself, during start(), by
// aggregating the capabilities of every registered namespace history delegate. So the delegate has to
// be registered before the server is started, and nothing here writes a capability value: the tests
// register the real reference `ua::history::HistoryEngineDelegate` (or none at all) and read back what the
// server chose to advertise.
// ---------------------------------------------------------------------------
struct StartedHistoryServer
{
  boost::asio::thread_pool threadPool;
  std::optional<ua::server::Server> server;

  ~StartedHistoryServer()
  {
    if (server)
    {
      (void)server->try_shutdown_sync();
      server.reset();
    }
    ua::test_utils::drain_with_timeout(threadPool);
  }

  // `delegate` may be null, which is a server offering no Historical Access at all.
  void prepare(std::shared_ptr<ua::NamespaceHistoryDelegate> delegate, std::string_view uri,
    ua::server::ServerConfig serverConfig)
  {
    ua::server::CreateConfig config{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    server.emplace(ua::server::Server::create(threadPool.get_executor(),
      std::move(config),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
    if (delegate)
    {
      auto historyNamespace = std::make_shared<AuditHistoryNamespace>(uri, threadPool.get_executor());
      historyNamespace->set_history_delegate(std::move(delegate));
      server->address_space().add_namespace_sync(historyNamespace);
    }
  }

  void launch()
  {
    server->start_sync();
  }

  void start(std::shared_ptr<ua::NamespaceHistoryDelegate> delegate, std::string_view uri,
    ua::server::ServerConfig serverConfig)
  {
    prepare(std::move(delegate), uri, std::move(serverConfig));
    launch();
  }

  ua::AddressSpace address_space()
  {
    return server->address_space();
  }
};

// What a HistoryServerCapabilities Boolean property currently advertises, and whether it was there to
// read at all: an NS0 Variable that was imported but never given a value reads back as an empty
// Variant, which is "absent", not "false".
struct CapabilityFlag
{
  bool present{false};
  bool value{false};
};

CapabilityFlag capability_flag(ua::AddressSpace addressSpace, ua::VariableId variableId)
{
  CapabilityFlag flag;
  auto node = addressSpace.find_node_sync(ua::NodeId{variableId});
  auto variable = node.as<ua::VariableAccessor>();
  if (!variable)
    return flag;
  auto dataValue = variable->read_value_sync();
  if (dataValue.value().empty() || !dataValue.value().is_boolean())
    return flag;
  flag.present = true;
  flag.value = dataValue.value().as<bool>();
  return flag;
}

// Insert one historical Event through `delegate` itself, so the read paired with the capability flag
// below has something real to find.
ua::BatchResult<ua::NamespaceHistoryDelegate::UpdateEventsItemResult> insert_event_through(
  ua::NamespaceHistoryDelegate& delegate, const ua::NodeId& nodeId)
{
  ua::NamespaceHistoryDelegate::UpdateContext context;
  context.cancelled = std::make_shared<std::atomic_bool>(false);
  auto item = update_events_item(ua::PerformUpdateType::Insert, {event_record({{6}}, 10, 600.0)});
  item.nodeId = nodeId;
  std::vector<UpdateEventsItem> items;
  items.push_back(std::move(item));

  auto promise =
    std::make_shared<std::promise<ua::BatchResult<ua::NamespaceHistoryDelegate::UpdateEventsItemResult>>>();
  auto future = promise->get_future();
  delegate.update_events_async(context,
    std::move(items),
    [promise](ua::BatchResult<ua::NamespaceHistoryDelegate::UpdateEventsItemResult> batch)
    { promise->set_value(std::move(batch)); });
  if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
  {
    ADD_FAILURE() << "the historical Event insert did not complete";
    ua::BatchResult<ua::NamespaceHistoryDelegate::UpdateEventsItemResult> unfinished;
    return unfinished;
  }
  return future.get();
}

// Attempt one historical Event read through `delegate` itself. The outcome is the delegate's own, so
// the capability flag is checked against the operation it claims to describe.
ua::BatchResult<ua::NamespaceHistoryDelegate::ReadEventsItemResult> read_events_through(
  ua::NamespaceHistoryDelegate& delegate, const ua::NodeId& nodeId)
{
  ua::NamespaceHistoryDelegate::ReadContext context;
  context.cancelled = std::make_shared<std::atomic_bool>(false);
  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}));
  item.nodeId = nodeId;
  std::vector<ReadEventsItem> items;
  items.push_back(std::move(item));

  auto promise =
    std::make_shared<std::promise<ua::BatchResult<ua::NamespaceHistoryDelegate::ReadEventsItemResult>>>();
  auto future = promise->get_future();
  delegate.read_events_async(context,
    std::move(items),
    [promise](ua::BatchResult<ua::NamespaceHistoryDelegate::ReadEventsItemResult> batch)
    { promise->set_value(std::move(batch)); });
  if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
  {
    ADD_FAILURE() << "the historical Event read did not complete";
    ua::BatchResult<ua::NamespaceHistoryDelegate::ReadEventsItemResult> unfinished;
    return unfinished;
  }
  return future.get();
}

const char* const servingCapabilityNamespaceUri = "uri://history-engine-serving-caps-ns";

}  // namespace

// OPC 10000-11 section 5.4.2: AccessHistoryDataCapability and AccessHistoryEventsCapability are the
// only route a client has to discover that a Server offers Historical Access at all, and both default
// to false. Advertising is a step separate from serving, so an implementation that wires the history
// delegate into the read and update services and stops there is fully functional to anyone who tries
// a HistoryRead and completely invisible to every client that asks first - the pair still reads false,
// which is a positive claim that the Server historises nothing.
// @verifies AC-SVR-HIST-CAP-002-ACCESS-CAPABILITIES
TEST(HistoryServerCapabilitiesAdvertisement, AnAccessCapabilityIsDeclaredExactlyWhenHistoryIsOffered)
{
  // A server whose namespace really is served by the reference historian.
  {
    StartedHistoryServer serving;
    serving.start(std::make_shared<ua::history::HistoryEngineDelegate>(
                    std::make_unique<SqliteHistoryStore>(":memory:", make_codec())),
      servingCapabilityNamespaceUri,
      ua::server::ServerConfig{});

    auto addressSpace = serving.address_space();
    const auto data =
      capability_flag(addressSpace, ua::VariableId::HistoryServerCapabilities_AccessHistoryDataCapability);
    const auto events =
      capability_flag(addressSpace, ua::VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability);

    EXPECT_TRUE(data.present) << "AccessHistoryDataCapability must be a readable Boolean, not absent";
    EXPECT_TRUE(events.present) << "AccessHistoryEventsCapability must be a readable Boolean, not absent";
    EXPECT_TRUE(data.value || events.value)
      << "a server offering Historical Access declares neither access capability, so no conforming "
         "client can discover it";
  }

  // ... and a server offering no Historical Access at all: both are present, and both are false.
  {
    StartedHistoryServer bare;
    bare.start(nullptr, "uri://history-engine-bare-caps-ns", ua::server::ServerConfig{});

    auto addressSpace = bare.address_space();
    const auto data =
      capability_flag(addressSpace, ua::VariableId::HistoryServerCapabilities_AccessHistoryDataCapability);
    const auto events =
      capability_flag(addressSpace, ua::VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability);

    EXPECT_TRUE(data.present) << "AccessHistoryDataCapability must default to false, not be absent";
    EXPECT_FALSE(data.value);
    EXPECT_TRUE(events.present) << "AccessHistoryEventsCapability must default to false, not be absent";
    EXPECT_FALSE(events.value);
  }
}

// OPC 10000-11 section 5.4.2: AccessHistoryEventsCapability must predict the outcome of a historical
// Event read; a flag that does not is worse than none, because the client trusts it instead of trying.
// Event history and value history are collected by different machinery but advertised from one
// capability object, so the natural implementation derives the events flag from whatever it already
// computed for data - "there is a historian, so there is Event history" - and the flag then reads true
// on a delegate whose Event read reports Bad_HistoryOperationUnsupported. Both halves are observed on
// one delegate each, since the defect is the flag and the operation disagreeing.
// @verifies AC-SVR-HIST-CAP-003-EVENTS-CAPABILITY
TEST(HistoryServerCapabilitiesAdvertisement, TheEventsCapabilityIsTrueExactlyWhereAnEventReadSucceeds)
{
  // A historian that really does serve Event history.
  {
    auto serving = std::make_shared<ua::history::HistoryEngineDelegate>(
      std::make_unique<SqliteHistoryStore>(":memory:", make_codec()));
    StartedHistoryServer harness;
    harness.start(serving, "uri://history-engine-events-caps-ns", ua::server::ServerConfig{});

    const auto events = capability_flag(
      harness.address_space(), ua::VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability);
    EXPECT_TRUE(events.present) << "AccessHistoryEventsCapability must be a readable Boolean, not absent";
    EXPECT_TRUE(events.value) << "the flag denies Event history the delegate actually serves";

    auto inserted = insert_event_through(*serving, testNode);
    ASSERT_TRUE(inserted.batchStatus.is_good());
    ASSERT_EQ(inserted.items.size(), 1u);
    ASSERT_TRUE(inserted.items[0].is_good()) << "the historical Event could not be stored";

    auto read = read_events_through(*serving, testNode);
    EXPECT_TRUE(read.batchStatus.is_good());
    ASSERT_EQ(read.items.size(), 1u);
    ASSERT_TRUE(read.items[0].is_good()) << "the flag is true but the Event read was refused";
    EXPECT_EQ(read.items[0].value().events.size(), 1u) << "the stored Event did not come back";
  }

  // A historian whose collection supports nothing: the flag must say so, and the read must fail.
  {
    auto notServing = std::make_shared<NoAnnotationsDelegate>();
    StartedHistoryServer harness;
    harness.start(notServing, "uri://history-engine-no-events-caps-ns", ua::server::ServerConfig{});

    const auto events = capability_flag(
      harness.address_space(), ua::VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability);
    EXPECT_TRUE(events.present) << "AccessHistoryEventsCapability must default to false, not be absent";
    EXPECT_FALSE(events.value) << "the flag claims Event history this delegate cannot serve";

    auto read = read_events_through(*notServing, testNode);
    ASSERT_EQ(read.items.size(), 1u);
    EXPECT_TRUE(read.items[0].is_bad()) << "the flag is false but the Event read succeeded";
    EXPECT_EQ(
      code(read.items[0].status_code()), code(StatusCode{ua::Status::BadHistoryOperationUnsupported}));
  }
}

namespace
{

// The nodes a folder Organizes, in the address space's own reference order.
std::vector<ua::NodeId> organized_targets(ua::AddressSpace addressSpace, const ua::NodeId& folder)
{
  std::vector<ua::NodeId> targets;
  auto folderNode = addressSpace.find_node_sync(folder);
  for (const auto& ref : folderNode.get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
      continue;
    if (ref.type_id() != ua::NodeId{ua::ReferenceTypeId::Organizes})
      continue;
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    targets.push_back(target.node_id());
  }
  return targets;
}

// Read a node's Description exactly as a session with `sessionLocales` would see it: through the
// server's own attribute-read path, which resolves the stored LocalizedText against those locales and
// falls back to the server default when none matches.
ua::DataValue description_under(
  ua::AddressSpace addressSpace, const ua::NodeId& nodeId, const std::vector<ua::LocaleId>& sessionLocales)
{
  auto node = addressSpace.find_node_sync(nodeId);
  return ua::node_utils::read_node_sync_attribute(node,
    ua::AttributeId::Description,
    ua::TimestampsToReturn::Neither,
    sessionLocales,
    ua::LocaleId{ua::String{"en"}});
}

}  // namespace

// OPC 10000-11 Table 5 gives every standard AggregateFunction Object a Description, and a server that
// advertises a non-English LocaleId in LocaleIdArray has undertaken to answer in it. Translations are
// data, not code, so they are the part that never gets written: the aggregate Objects arrive from the
// standard NodeSet with their English text and the implementation reads them straight back whatever
// locale the session asked for, which looks correct in an English test and silently makes the locale
// advertisement a false claim. The unmatched-locale read is asserted alongside it because the fix that
// returns nothing rather than untranslated text is the other way to get this wrong.
// @verifies AC-SVR-HIST-CAP-018-AGGREGATE-DESCRIPTIONS
TEST(HistoryServerCapabilitiesAdvertisement, AggregateObjectsCarryALocalisedDescriptionPerSessionLocale)
{
  ua::server::ServerConfig serverConfig;
  serverConfig.server_capabilities().localeIds = {"en", "de-DE"};

  StartedHistoryServer harness;
  harness.start(std::make_shared<ua::history::HistoryEngineDelegate>(
                  std::make_unique<SqliteHistoryStore>(":memory:", make_codec())),
    "uri://history-engine-aggregate-locale-ns",
    std::move(serverConfig));

  auto addressSpace = harness.address_space();
  const auto aggregates =
    organized_targets(addressSpace, ua::NodeId{ua::ObjectId::HistoryServerCapabilities_AggregateFunctions});
  ASSERT_FALSE(aggregates.empty()) << "the server published no standard Aggregate Objects at all";

  const ua::LocaleId advertised{ua::String{"de-DE"}};
  const ua::LocaleId unadvertised{ua::String{"fr"}};

  for (size_t i = 0; i < aggregates.size(); ++i)
  {
    const auto& aggregate = aggregates[i];

    // The advertised locale: the Description must be there, and it must be the translation.
    auto translated = description_under(addressSpace, aggregate, {advertised});
    ASSERT_EQ(code(translated.status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}))
      << "no Description at all on published aggregate " << i;
    const auto* translatedText = translated.value().try_as<ua::LocalizedText>();
    ASSERT_NE(translatedText, nullptr)
      << "the Description of published aggregate " << i << " is not a LocalizedText";
    EXPECT_FALSE(std::string{translatedText->text()}.empty())
      << "an empty Table 5 Description on published aggregate " << i;
    // Exact-or-language match, because Part 4's locale resolution accepts a language-level translation for a
    // region-qualified request: a shipped `de` discharges Part 13 for a `de-DE` session just as `de-DE` does.
    // Demanding the exact tag would fail a conforming server, which is a different fault from the one here -
    // the observed locale is the empty tag, so no translation of any granularity exists.
    const std::string servedLocale{translatedText->locale()};
    const std::string requestedLanguage{std::string{advertised}.substr(0, 2)};
    EXPECT_TRUE(servedLocale == std::string{advertised} || servedLocale == requestedLanguage)
      << "the server advertises de-DE but answers published aggregate " << i << " with locale '"
      << servedLocale << "' - untranslated text, not a de translation";

    auto english = description_under(addressSpace, aggregate, {ua::LocaleId{ua::String{"en"}}});
    ASSERT_EQ(code(english.status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}));
    const auto* englishText = english.value().try_as<ua::LocalizedText>();
    ASSERT_NE(englishText, nullptr);
    EXPECT_NE(std::string{translatedText->text()}, std::string{englishText->text()})
      << "the advertised German Description is only the English text relabelled as German on aggregate " << i;

    // A locale the server never advertised: the Table 5 text must still come back, not nothing.
    auto fallback = description_under(addressSpace, aggregate, {unadvertised});
    ASSERT_EQ(code(fallback.status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}))
      << "an unmatched locale removed the Description of published aggregate " << i;
    const auto* fallbackText = fallback.value().try_as<ua::LocalizedText>();
    ASSERT_NE(fallbackText, nullptr);
    EXPECT_FALSE(std::string{fallbackText->text()}.empty())
      << "an unmatched locale returned an empty Description for published aggregate " << i;
  }
}

// Every implemented standard Aggregate is advertised from the registry, so the checked-in translation
// resource must cover exactly that set. This catches both adding a new Aggregate without its mandatory
// localized Description and stale translation entries for functions the SDK cannot compute.
// @verifies AC-SVR-HIST-CAP-018-AGGREGATE-DESCRIPTIONS
TEST(StandardAggregateDescriptionTranslations, GermanResourceCoversEveryImplementedAggregate)
{
  const auto translations = ua::server::aggregates::standard_aggregate_descriptions("de");
  const auto supported = ua::server::aggregates::AggregatorRegistry::instance().supported();

  ASSERT_EQ(translations.size(), supported.size());
  for (const auto& aggregateId : supported)
  {
    const auto translation = std::ranges::find_if(translations,
      [&aggregateId](const ua::server::aggregates::StandardAggregateDescription& candidate)
      { return ua::NodeId{candidate.objectId} == aggregateId; });
    ASSERT_NE(translation, translations.end()) << "an implemented Aggregate has no German Description";
    EXPECT_FALSE(translation->text.empty()) << "an implemented Aggregate has an empty German Description";
  }

  EXPECT_TRUE(ua::server::aggregates::standard_aggregate_descriptions("fr").empty());
}

// Advertising a locale is a claim that the mandatory Aggregate Descriptions can be served in it. If
// neither the SDK nor the application supplies the translations, startup must reject that inconsistent
// configuration and retain the actionable explanation on the StatusCode carried by UaException.
// @verifies AC-SVR-HIST-CAP-018-AGGREGATE-DESCRIPTIONS
TEST(HistoryServerCapabilitiesAdvertisement, RefusesAggregateAdvertisementWithoutConfiguredTranslations)
{
  ua::server::ServerConfig serverConfig;
  serverConfig.server_capabilities().localeIds = {"en", "fr"};

  StartedHistoryServer harness;
  try
  {
    harness.start(std::make_shared<ua::history::HistoryEngineDelegate>(
                    std::make_unique<SqliteHistoryStore>(":memory:", make_codec())),
      "uri://history-engine-missing-aggregate-locale-ns",
      std::move(serverConfig));
    FAIL() << "the server advertised French Aggregate Descriptions without any French translations";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status_code(), StatusCode{ua::Status::BadConfigurationError});
    ASSERT_NE(exception.status_code().shared_detail(), nullptr);
    EXPECT_EQ(exception.status_code().shared_detail()->code, "AggregateDescriptionTranslationMissing");
  }
}

// A deployment may provide a locale the SDK does not ship. Preserve and accept those application-owned
// translations instead of constraining servers to the built-in resource languages.
// @verifies AC-SVR-HIST-CAP-018-AGGREGATE-DESCRIPTIONS
TEST(HistoryServerCapabilitiesAdvertisement, AcceptsApplicationSuppliedAggregateTranslations)
{
  ua::server::ServerConfig serverConfig;
  serverConfig.server_capabilities().localeIds = {"en", "fr-FR"};

  StartedHistoryServer harness;
  harness.prepare(std::make_shared<ua::history::HistoryEngineDelegate>(
                    std::make_unique<SqliteHistoryStore>(":memory:", make_codec())),
    "uri://history-engine-application-aggregate-locale-ns",
    std::move(serverConfig));

  auto addressSpace = harness.address_space();
  for (const auto& aggregateId : ua::server::aggregates::AggregatorRegistry::instance().supported())
  {
    auto aggregate = addressSpace.find_node_sync(aggregateId);
    const auto storedValue = aggregate.read_attribute(ua::AttributeId::Description);
    const auto* storedDescription = storedValue.try_as<ua::LocalizedText>();
    ASSERT_NE(storedDescription, nullptr);
    aggregate.set_description(
      storedDescription->merged_with(ua::LocalizedText{"fr", "Description fran\u00e7aise"}));
  }

  ASSERT_NO_THROW(harness.launch());
  for (const auto& aggregateId : ua::server::aggregates::AggregatorRegistry::instance().supported())
  {
    auto translated = description_under(addressSpace, aggregateId, {ua::LocaleId{ua::String{"fr-FR"}}});
    ASSERT_EQ(code(translated.status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}));
    const auto* translatedText = translated.value().try_as<ua::LocalizedText>();
    ASSERT_NE(translatedText, nullptr);
    EXPECT_EQ(std::string{translatedText->locale()}, "fr");
    EXPECT_EQ(std::string{translatedText->text()}, "Description fran\u00e7aise");
  }
}

// OPC 10000-11 section 5.2.4 / OPC 10000-3 section 5.6.2: Historizing is how a client tells "this Node
// has history" from "this Node is collecting history right now" - a Node switched off still answers
// HistoryRead, so without the Attribute a gap in the data is indistinguishable from an outage. The
// Attribute is optional in the underlying storage, so a Node that was never explicitly marked has no
// value in its attribute slot at all, and the read path that copies stored slots verbatim then reports
// the mandatory Attribute as absent (Bad_AttributeIdInvalid) rather than as the false it defaults to.
// Both Nodes are historised; only one is collecting, which is what makes the value - not merely its
// presence - observable.
// @verifies AC-SVR-HIST-CAP-017-HISTORIZING-ATTRIBUTE
TEST(HistoricalDataNodeAttributes, EveryHistorisedNodeExposesHistorizingReflectingWhetherItIsCollecting)
{
  ua::test_helpers::TestServer server;
  server.create();
  auto addressSpace = server.server().address_space();

  const NodeId collectingId{1, "Engine.Historizing.Collecting"};
  make_historised_variable(addressSpace, server.server(), collectingId, "EngineHistorizingCollecting");
  const NodeId dormantId{1, "Engine.Historizing.Dormant"};
  make_historised_variable(addressSpace, server.server(), dormantId, "EngineHistorizingDormant");

  // Collection is running on the first HistoricalDataNode and is not on the second. Both are
  // historised: both carry HistoryRead in their AccessLevel.
  auto collectingNode = addressSpace.find_node_sync(collectingId);
  auto collectingVariable = collectingNode.as<ua::VariableAccessor>();
  ASSERT_TRUE(collectingVariable.has_value());
  collectingVariable->set_historizing(true);

  const std::vector<ua::LocaleId> noLocales;
  const ua::LocaleId defaultLocale{ua::String{"en"}};

  const std::vector<NodeId> nodeIds{collectingId, dormantId};
  const std::vector<bool> collecting{true, false};

  for (size_t i = 0; i < nodeIds.size(); ++i)
  {
    auto node = addressSpace.find_node_sync(nodeIds[i]);
    auto historizing = ua::node_utils::read_node_sync_attribute(
      node, ua::AttributeId::Historizing, ua::TimestampsToReturn::Neither, noLocales, defaultLocale);

    // Present on each - a historised Node that answers Bad_AttributeIdInvalid here has hidden the
    // only Attribute that says whether its history is still being added to.
    EXPECT_EQ(code(historizing.status().value_or(StatusCode{})), code(StatusCode{ua::Status::Good}))
      << "the Historizing Attribute is absent on historised node " << i;
    ASSERT_TRUE(historizing.value().is_boolean())
      << "the Historizing Attribute of historised node " << i << " is not a Boolean";
    // ... and reflecting whether collection is currently active.
    const bool expected = collecting[i];
    EXPECT_EQ(historizing.value().as<bool>(), expected)
      << "Historizing on historised node " << i << " does not reflect whether it is collecting";
  }
}

namespace
{

ua::HistoryReadResponse* history_read_response(const ua::Response& response)
{
  return dynamic_cast<ua::HistoryReadResponse*>(std::get<std::shared_ptr<ua::Structure>>(response).get());
}

// The service-level outcome, whether it arrived as a HistoryReadResponse header or as a ServiceFault.
bool history_read_service_result_is(const ua::Response& response, StatusCode expected)
{
  auto* structure = std::get<std::shared_ptr<ua::Structure>>(response).get();
  if (auto* histResponse = dynamic_cast<ua::HistoryReadResponse*>(structure))
    return histResponse->response_header().service_result() == expected;
  auto* fault = dynamic_cast<ua::ServiceFault*>(structure);
  return fault != nullptr && fault->response_header().service_result() == expected;
}

ua::HistoryReadRequest raw_read_request(
  const ua::NodeId& nodeId, bool readModified, ua::TimestampsToReturn timestamps)
{
  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = timestamps;
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->is_read_modified() = readModified;
  details->start_time() = at(0);
  details->end_time() = at(60);
  details->num_values_per_node() = 100;
  details->return_bounds() = false;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

// Drive one real HistoryRead through the server the audit harness already stands up: its namespace is
// served by the reference `ua::history::HistoryEngineDelegate` over an in-memory SqliteHistoryStore, so the
// values the read sees are the ones the historian really stored.
ua::server::HistoryReadService::HistoryReadServiceResponse run_history_read(
  HistoryAuditHarness& harness, ua::HistoryReadRequest request)
{
  ua::server::HistoryContinuationPoints sessionContinuationPoints;
  auto resultPromise =
    std::make_shared<std::promise<ua::server::HistoryReadService::HistoryReadServiceResponse>>();
  auto resultFuture = resultPromise->get_future();
  auto service = ua::server::HistoryReadService::create(harness.sessionInfo,
    {},
    0,
    std::move(request),
    sessionContinuationPoints,
    harness.threadPool.get_executor(),
    [resultPromise](ua::server::HistoryReadService::HistoryReadServiceResponse response)
    { resultPromise->set_value(std::move(response)); });
  if (resultFuture.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
  {
    ADD_FAILURE() << "the HistoryRead service did not complete";
    ua::server::HistoryReadService::HistoryReadServiceResponse unfinished;
    return unfinished;
  }
  return resultFuture.get();
}

// An Object that may have its Event history both read and written.
ua::NodeId event_history_object(HistoryAuditHarness& harness, uint32_t numericId)
{
  ua::NodeId nodeId{harness.nsIndex, numericId};
  auto addressSpace = harness.sessionInfo->address_space();
  auto objResult = addressSpace.try_create_sync<ua::ObjectAccessor>(nodeId, ua::NodeClass::Object);
  EXPECT_TRUE(objResult.is_good()) << "failed to create the Event-history Object";
  if (objResult.is_good())
  {
    ua::EventNotifierType notifier;
    notifier.set(ua::EventNotifierType::Bit::HistoryRead);
    notifier.set(ua::EventNotifierType::Bit::HistoryWrite);
    objResult.value().set_event_notifier(notifier);
  }
  return nodeId;
}

}  // namespace

// OPC 10000-11 section 6.4: a HistoryRead that asks for both timestamps from a historian that only
// ever collected the source one is a request the Server cannot honour, and it must say so with
// Bad_TimestampsToReturnInvalid. Answering with the timestamp it does have is the accommodating
// behaviour and it is the trap: the Client receives values whose ServerTimestamp is simply missing,
// which it reads as "these particular values had none" rather than "this historian never collects it",
// and no error anywhere tells it otherwise. The refusal is a property of the request against the
// Server's collection, so it belongs at the service level, before any node is dispatched.
// @verifies AC-SVR-HIST-READ-001-BOTH-TIMESTAMPS
TEST(HistoryReadTimestamps, RequestingBothTimestampsFromASourceOnlyHistorianIsRefusedRatherThanAnswered)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto node = harness.historised_variable(970);

  // Seed the historian with values that carry a source timestamp and nothing else - `sample()` sets
  // only source_timestamp, so this collection genuinely holds no ServerTimestamp for any entry.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      data_details(node, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(node, ua::PerformUpdateType::Insert, sample(20, 2.0));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 2u);
    EXPECT_TRUE(seedResponse->results()[0].status_code().is_good());
    EXPECT_TRUE(seedResponse->results()[1].status_code().is_good());
  }

  auto result =
    run_history_read(harness, raw_read_request(node, /*readModified*/ false, ua::TimestampsToReturn::Both));

  const StatusCode notSupported{ua::Status::BadTimestampNotSupported};
  const bool refusedAtService = history_read_service_result_is(result.response, notSupported);
  auto* response = history_read_response(result.response);
  const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                  code(response->results()[0].status_code()) == code(notSupported);
  EXPECT_TRUE(refusedAtService || refusedAtOperation)
    << "the request asked for both timestamps of a source-only collection and was not refused with "
       "Bad_TimestampNotSupported at either level";

  // ... and it must not instead have answered with the one timestamp the historian does keep.
  if (response != nullptr && response->results().size() == 1u)
  {
    auto* histData = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
    EXPECT_TRUE(histData == nullptr || histData->data_values().size() == 0u)
      << "the available timestamp was returned alone instead of the request being refused";
  }
}

// OPC 10000-11 sections 6.4.2.2, 6.4.3.2 and 6.4.3.3 all carry the same sentence: "If the requested
// TimestampsToReturn is not supported for a Node, the operation shall return the
// Bad_TimestampNotSupported StatusCode." It is per operation, not per request, so it lives in each
// read mode's result handler - and an implementation writes that handler once, for the raw path that
// every historian needs, then builds the modified and Event replies from their own success payloads
// without repeating the check. The Client asking a HistoricalEventNode for a timestamp the collection
// never had is then told the operation was Good. All three modes are asserted together because the
// defect is a missing branch, visible only where the modes are compared.
// @verifies AC-SVR-HIST-READ-002-TIMESTAMP-NOT-SUPPORTED
// The retained GoogleTest identity says "EveryReadMode" because it is present in checked-in execution
// evidence. Part 11 section 6.5.2.2 excludes ordinary Event fields; the corrected body covers every
// applicable data-history mode (Raw and Modified) without invalidating that historical identity.
TEST(HistoryReadTimestamps, ANodeThatCannotSupplyTheRequestedTimestampIsRefusedInEveryReadMode)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto valueNode = harness.historised_variable(980);

  // Value history that carries the source timestamp only, plus one replacement so the modified-history
  // read has a modification record to return.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      data_details(valueNode, ua::PerformUpdateType::Insert, sample(10, 1.0));
    seedRequest.history_update_details()[1] =
      data_details(valueNode, ua::PerformUpdateType::Insert, sample(20, 2.0));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 2u);
    for (size_t i = 0; i < 2u; ++i)
      EXPECT_TRUE(seedResponse->results()[i].status_code().is_good()) << "seed detail " << i << " failed";
  }
  {
    ua::HistoryUpdateRequest replaceRequest;
    replaceRequest.request_header().request_handle() = 2;
    replaceRequest.history_update_details().resize(1);
    replaceRequest.history_update_details()[0] =
      data_details(valueNode, ua::PerformUpdateType::Replace, sample(10, 3.0));
    auto replaceResult = harness.run(std::move(replaceRequest));
    auto* replaceResponse = update_response(replaceResult);
    ASSERT_NE(replaceResponse, nullptr);
    ASSERT_EQ(replaceResponse->results().size(), 1u);
    EXPECT_TRUE(replaceResponse->results()[0].status_code().is_good());
  }

  const StatusCode notSupported{ua::Status::BadTimestampNotSupported};

  // Raw.
  {
    auto raw = run_history_read(
      harness, raw_read_request(valueNode, /*readModified*/ false, ua::TimestampsToReturn::Both));
    auto* response = history_read_response(raw.response);
    ASSERT_NE(response, nullptr) << "the raw read produced no HistoryReadResponse";
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_EQ(code(response->results()[0].status_code()), code(notSupported))
      << "a raw read of a source-only Node was not refused per operation";
  }

  // Modified.
  {
    auto modified = run_history_read(
      harness, raw_read_request(valueNode, /*readModified*/ true, ua::TimestampsToReturn::Both));
    auto* response = history_read_response(modified.response);
    ASSERT_NE(response, nullptr) << "the modified read produced no HistoryReadResponse";
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_EQ(code(response->results()[0].status_code()), code(notSupported))
      << "a modified read of a source-only Node was not refused per operation";
  }
}

namespace
{

// ---------------------------------------------------------------------------
// HistoryRead / HistoryUpdate parameter contracts (OPC 10000-11 sections 6.4 and 6.8).
//
// These drive real HistoryRead and HistoryUpdate requests through the server the audit harness stands
// up, because the obligations below are about what a Client is told: the operationResults and
// StatusCodes the Services return. Nothing here inspects the historian directly - "was it stored?" is
// answered by a second real read.
// ---------------------------------------------------------------------------

// A raw HistoryRead carrying only the bounding parameters it is given. An absent startTime or endTime
// stays null and an absent cap stays zero, which is how Part 11 section 6.4.3.2 says "not specified".
ua::HistoryReadRequest bounded_raw_read_request(const ua::NodeId& nodeId, std::optional<DateTime> start,
  std::optional<DateTime> end, uint32_t numValuesPerNode)
{
  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = ua::TimestampsToReturn::Source;
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->is_read_modified() = false;
  if (start.has_value())
    details->start_time() = *start;
  if (end.has_value())
    details->end_time() = *end;
  details->num_values_per_node() = numValuesPerNode;
  details->return_bounds() = false;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

// The Event-history counterpart of bounded_raw_read_request(), selecting Time and Severity.
ua::HistoryReadRequest bounded_event_read_request(const ua::NodeId& nodeId, std::optional<DateTime> start,
  std::optional<DateTime> end, uint32_t numValuesPerNode)
{
  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = ua::TimestampsToReturn::Source;
  auto details = std::make_unique<ua::ReadEventDetails>();
  if (start.has_value())
    details->start_time() = *start;
  if (end.has_value())
    details->end_time() = *end;
  details->num_values_per_node() = numValuesPerNode;
  details->filter() = filter_selecting({"Time", "Severity"});
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

// run_history_read() keeps its continuation-point store private to the one call, so a paginated read
// cannot be resumed through it. This variant takes the session's store, which is where the SDK files
// the continuation point a capped read hands back.
ua::server::HistoryReadService::HistoryReadServiceResponse run_history_read_with(HistoryAuditHarness& harness,
  ua::HistoryReadRequest request, ua::server::HistoryContinuationPoints& sessionContinuationPoints)
{
  auto resultPromise =
    std::make_shared<std::promise<ua::server::HistoryReadService::HistoryReadServiceResponse>>();
  auto resultFuture = resultPromise->get_future();
  auto service = ua::server::HistoryReadService::create(harness.sessionInfo,
    {},
    0,
    std::move(request),
    sessionContinuationPoints,
    harness.threadPool.get_executor(),
    [resultPromise](ua::server::HistoryReadService::HistoryReadServiceResponse response)
    { resultPromise->set_value(std::move(response)); });
  if (resultFuture.wait_for(std::chrono::seconds{3}) != std::future_status::ready)
  {
    ADD_FAILURE() << "the HistoryRead service did not complete";
    ua::server::HistoryReadService::HistoryReadServiceResponse unfinished;
    return unfinished;
  }
  return resultFuture.get();
}

// How many historical Events a real ReadEventDetails now finds on `nodeId`.
size_t stored_event_count(HistoryAuditHarness& harness, const ua::NodeId& nodeId)
{
  auto result = run_history_read(harness, bounded_event_read_request(nodeId, at(-600), at(600), 100));
  auto* response = history_read_response(result.response);
  if (response == nullptr || response->results().size() != 1u)
  {
    ADD_FAILURE() << "the Event-history read that checks what was stored did not answer";
    return 0;
  }
  auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
  return events == nullptr ? size_t{0} : events->events().size();
}

struct StoredEventSnapshot
{
  DateTime time;
  uint16_t severity;
};

std::vector<StoredEventSnapshot> stored_event_snapshots(
  HistoryAuditHarness& harness, const ua::NodeId& nodeId)
{
  auto result = run_history_read(harness, bounded_event_read_request(nodeId, at(-600), at(600), 100));
  auto* response = history_read_response(result.response);
  if (response == nullptr || response->results().size() != 1u)
  {
    ADD_FAILURE() << "the Event-history read that checks stored fields did not answer";
    return {};
  }
  auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
  if (events == nullptr)
    return {};

  std::vector<StoredEventSnapshot> snapshots;
  snapshots.reserve(events->events().size());
  for (const auto& event : events->events())
  {
    if (event.event_fields().size() != 2u)
    {
      ADD_FAILURE() << "the Event read did not return the requested Time and Severity fields";
      continue;
    }
    const auto* time = event.event_fields()[0].try_as<DateTime>();
    const auto* severity = event.event_fields()[1].try_as<uint16_t>();
    if (time == nullptr || severity == nullptr)
    {
      ADD_FAILURE() << "the Event read returned Time or Severity with the wrong type";
      continue;
    }
    snapshots.push_back(StoredEventSnapshot{*time, *severity});
  }
  return snapshots;
}

// The one StatusCode a single-detail HistoryUpdate amounts to: the service result where the whole
// request was refused with a ServiceFault, the one per-operation StatusCode where that says anything
// beyond plain Good, and otherwise the detail's own StatusCode. Section 6.9.4.2 states some of its rules
// against "the statusCode" and others against "the related operationResults entry", so a Server may
// carry any one of these obligations at either level; the most specific answer present is taken rather
// than a level being picked in advance.
StatusCode update_outcome(const ua::Response& response)
{
  auto* structure = std::get<std::shared_ptr<ua::Structure>>(response).get();
  if (auto* fault = dynamic_cast<ua::ServiceFault*>(structure))
    return fault->response_header().service_result();
  auto* updateResponse = dynamic_cast<ua::HistoryUpdateResponse*>(structure);
  if (updateResponse == nullptr || updateResponse->results().size() != 1u)
  {
    ADD_FAILURE() << "the HistoryUpdate answered with neither a ServiceFault nor one detail result";
    return StatusCode{ua::Status::BadUnexpectedError};
  }
  const auto& result = updateResponse->results()[0];
  if (result.operation_results().size() == 1u &&
      result.operation_results()[0].as_uint32() != StatusCode{ua::Status::Good}.as_uint32())
    return result.operation_results()[0];
  return result.status_code();
}

// The fields OPC 10000-5 makes Mandatory on BaseEventType, in the order base_event_values() fills them.
const std::vector<std::string> baseEventFields{
  "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"};

// One well-formed eventData row for baseEventFields. The EventId is left null, which Part 11 section
// 6.8.4.2 defines as asking the Server for its own generated value.
std::vector<Variant> base_event_values(const ua::NodeId& sourceNode, DateTime time, uint16_t severity)
{
  std::vector<Variant> values;
  values.push_back(Variant{});
  values.push_back(Variant{ua::NodeId{ua::ObjectTypeId::BaseEventType}});
  values.push_back(Variant{sourceNode});
  values.push_back(Variant{ua::String{"history engine obligations"}});
  values.push_back(Variant{time});
  values.push_back(Variant{time});
  values.push_back(Variant{ua::LocalizedText{"", "history engine obligations"}});
  values.push_back(Variant{severity});
  return values;
}

// An UpdateEventDetails whose selectClause names `fieldNames` and whose one eventData row holds
// `values` in the same order.
std::unique_ptr<ua::UpdateEventDetails> event_insert_details(const ua::NodeId& nodeId,
  ua::PerformUpdateType mode, const std::vector<std::string>& fieldNames, std::vector<Variant> values)
{
  auto details = std::make_unique<ua::UpdateEventDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = mode;
  for (const auto& name : fieldNames)
  {
    ua::SimpleAttributeOperand operand;
    operand.type_definition_id() = ua::NodeId{ua::ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(ua::QualifiedName{uint16_t{0}, name});
    operand.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    details->filter().select_clauses().push_back(operand);
  }
  ua::HistoryEventFieldList record;
  for (auto& value : values)
    record.event_fields().push_back(std::move(value));
  details->event_data().push_back(std::move(record));
  return details;
}

// One HistoryUpdate request carrying `details` alone, with diagnostics asked for.
ua::HistoryUpdateRequest single_update_request(
  std::unique_ptr<ua::UpdateEventDetails> details, uint32_t requestHandle)
{
  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = requestHandle;
  request.request_header().return_diagnostics() = 0xFFFF;
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(details);
  return request;
}

}  // namespace

// OPC 10000-11 section 6.4.3.1 line 1711 and section 6.4.3.2 lines 1748-1755: "The time domain of the
// request is defined by startTime, endTime, and numValuesPerNode; at least two of these shall be
// specified", and "If a startTime, endTime and numValuesPerNode are all provided and if more than
// numValuesPerNode values exist within that time range for a given Node then only numValuesPerNode
// values per Node shall be returned along with a continuationPoint". Two-of-three is an unusual shape
// and a validator naturally checks each parameter for presence one at a time, which admits a request
// bounded by startTime alone: the Server then either returns the whole history or imposes a limit the
// Client did not ask for and cannot detect - and the same missing arithmetic drops or repeats values
// across the pages once all three bounds make the cap a paginating one.
//
// The continuationPoint obligation is conditioned on all three being provided; the same clause says of
// the open-ended pair that "the provided time is used as a starting point and the requested number of
// values is returned", so a start+numValuesPerNode read that hands back no continuationPoint is
// conforming and is asserted as such below.
// @verifies AC-SVR-HIST-READ-006-RAW-BOUNDS
TEST(HistoryReadBoundingParameters, ARawReadNeedsTwoOfItsThreeBoundsAndPaginatesOnTheCap)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto node = harness.historised_variable(1010);

  // Six values at t = 0,10,20,30,40,50.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(6);
    for (size_t i = 0; i < 6u; ++i)
    {
      seedRequest.history_update_details()[i] = data_details(
        node, ua::PerformUpdateType::Insert, sample(static_cast<int>(i) * 10, static_cast<double>(i)));
    }
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 6u);
    for (size_t i = 0; i < 6u; ++i)
      ASSERT_TRUE(seedResponse->results()[i].status_code().is_good()) << "seed value " << i << " refused";
  }

  // One bound of three: the request is unbounded, and must be refused rather than answered.
  {
    auto result = run_history_read(harness, bounded_raw_read_request(node, at(0), std::nullopt, 0));
    auto* response = history_read_response(result.response);
    const bool refusedAtService =
      history_read_service_result_is(result.response, StatusCode{ua::Status::BadHistoryOperationInvalid});
    const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                    response->results()[0].status_code().is_bad();
    EXPECT_TRUE(refusedAtService || refusedAtOperation)
      << "a raw read specifying only startTime was served; operation status = "
      << (response != nullptr && response->results().size() == 1u ? code(response->results()[0].status_code())
                                                                  : 0u);
    if (response != nullptr && response->results().size() == 1u)
    {
      auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
      EXPECT_TRUE(data == nullptr || data->data_values().empty())
        << "an unbounded raw read returned " << (data == nullptr ? size_t{0} : data->data_values().size())
        << " values against a range the Client never closed";
    }
  }

  // startTime with endTime: two of three, so the range is served in full.
  {
    auto result = run_history_read(harness, bounded_raw_read_request(node, at(0), at(60), 0));
    auto* response = history_read_response(result.response);
    ASSERT_NE(response, nullptr) << "a raw read bounded by startTime and endTime produced no response";
    ASSERT_EQ(response->results().size(), 1u);
    ASSERT_TRUE(response->results()[0].status_code().is_good())
      << "a raw read bounded by startTime and endTime was refused, status = "
      << code(response->results()[0].status_code());
    auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
    ASSERT_NE(data, nullptr) << "the bounded raw read returned no HistoryData at all";
    EXPECT_EQ(data->data_values().size(), 6u) << "the bounded range holds all six seeded values";
  }

  // startTime with numValuesPerNode: two of three, so it is served, and the provided time is the
  // starting point for exactly the requested number of values.
  {
    auto result = run_history_read(harness, bounded_raw_read_request(node, at(0), std::nullopt, 2));
    auto* response = history_read_response(result.response);
    ASSERT_NE(response, nullptr) << "a raw read bounded by startTime and numValuesPerNode was not served";
    ASSERT_EQ(response->results().size(), 1u);
    ASSERT_TRUE(response->results()[0].status_code().is_good())
      << "a raw read bounded by startTime and numValuesPerNode was refused, status = "
      << code(response->results()[0].status_code());
    auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
    ASSERT_NE(data, nullptr) << "the open-ended capped raw read returned no HistoryData at all";
    ASSERT_EQ(data->data_values().size(), 2u) << "the read did not return the requested number of values";
    EXPECT_EQ(ticks(data->data_values()[0]), at(0).value().time_since_epoch().count())
      << "the read did not start from the startTime the Client provided";
    EXPECT_EQ(ticks(data->data_values()[1]), at(10).value().time_since_epoch().count())
      << "the read did not go forward in time from startTime";
  }

  // All three bounds with the cap below the available data: capped at two, with a continuationPoint
  // that yields the remainder without repeating or dropping a value.
  {
    ua::server::HistoryContinuationPoints sessionContinuationPoints;
    std::vector<int64_t> paged;

    auto first = run_history_read_with(
      harness, bounded_raw_read_request(node, at(0), at(60), 2), sessionContinuationPoints);
    auto* response = history_read_response(first.response);
    ASSERT_NE(response, nullptr) << "a raw read bounded by all three parameters was not served";
    ASSERT_EQ(response->results().size(), 1u);
    ASSERT_TRUE(response->results()[0].status_code().is_good())
      << "a raw read bounded by all three parameters was refused, status = "
      << code(response->results()[0].status_code());
    auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
    ASSERT_NE(data, nullptr) << "the capped raw read returned no HistoryData at all";
    EXPECT_EQ(data->data_values().size(), 2u) << "the read returned more rows than numValuesPerNode";
    for (size_t i = 0; i < data->data_values().size(); ++i)
      paged.push_back(ticks(data->data_values()[i]));
    ASSERT_FALSE(response->results()[0].continuation_point().empty())
      << "six values in the range were capped at two and no continuationPoint came back, so the "
         "remaining four are unreachable";

    auto continuationPoint = response->results()[0].continuation_point();
    for (auto& point : first.continuationPoints)
    {
      auto identifier = point.identifier();
      sessionContinuationPoints.emplace(identifier, std::move(point));
    }

    for (int page = 0; page < 5 && !continuationPoint.empty(); ++page)
    {
      // Section 6.3: a continuation call repeats the original HistoryReadDetails and
      // TimestampsToReturn unchanged, so only the continuationPoint distinguishes it.
      auto request = bounded_raw_read_request(node, at(0), at(60), 2);
      request.nodes_to_read()[0].continuation_point() = continuationPoint;
      auto next = run_history_read_with(harness, std::move(request), sessionContinuationPoints);
      auto* nextResponse = history_read_response(next.response);
      ASSERT_NE(nextResponse, nullptr) << "continuing the capped raw read produced no response";
      ASSERT_EQ(nextResponse->results().size(), 1u);
      ASSERT_TRUE(nextResponse->results()[0].status_code().is_good())
        << "continuing the capped raw read was refused, status = "
        << code(nextResponse->results()[0].status_code());
      auto* nextData = dynamic_cast<ua::HistoryData*>(nextResponse->results()[0].history_data().get());
      if (nextData != nullptr)
      {
        for (size_t i = 0; i < nextData->data_values().size(); ++i)
          paged.push_back(ticks(nextData->data_values()[i]));
      }
      continuationPoint = nextResponse->results()[0].continuation_point();
      for (auto& point : next.continuationPoints)
      {
        auto identifier = point.identifier();
        sessionContinuationPoints.emplace(identifier, std::move(point));
      }
    }

    // Every seeded value once, in time order: the pages neither repeated nor dropped one.
    ASSERT_EQ(paged.size(), 6u) << "pagination yielded " << paged.size() << " values for six seeded ones";
    for (size_t i = 0; i < 6u; ++i)
    {
      EXPECT_EQ(paged[i], at(static_cast<int>(i) * 10).value().time_since_epoch().count())
        << "page position " << i << " does not hold the value that belongs there";
    }
  }
}

// OPC 10000-11 section 6.4.2.1 line 1638: "Two of the three parameters, numValuesPerNode, startTime,
// and endTime shall be specified." This is the Event-side twin of the raw rule above and is authored
// separately because the two details structures are validated at separate call sites - an
// implementation routinely guards the raw path, which every historian needs, and builds the Event reply
// from its own success payload without repeating the check.
// @verifies AC-SVR-HIST-READ-003-EVENT-BOUNDS
TEST(HistoryReadBoundingParameters, AnEventHistoryReadNeedsTwoOfItsThreeBounds)
{
  HistoryAuditHarness harness;
  harness.setup();

  const auto node = event_history_object(harness, 1020);

  // Three historical Events at t = 10,20,30.
  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(3);
    seedRequest.history_update_details()[0] =
      event_details(node, ua::PerformUpdateType::Insert, event_record({{1}}, 10, 100.0));
    seedRequest.history_update_details()[1] =
      event_details(node, ua::PerformUpdateType::Insert, event_record({{2}}, 20, 200.0));
    seedRequest.history_update_details()[2] =
      event_details(node, ua::PerformUpdateType::Insert, event_record({{3}}, 30, 300.0));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 3u);
    for (size_t i = 0; i < 3u; ++i)
      ASSERT_TRUE(seedResponse->results()[i].status_code().is_good()) << "seed Event " << i << " refused";
  }

  // One bound of three: refused.
  {
    auto result = run_history_read(harness, bounded_event_read_request(node, at(0), std::nullopt, 0));
    auto* response = history_read_response(result.response);
    const bool refusedAtService =
      history_read_service_result_is(result.response, StatusCode{ua::Status::BadHistoryOperationInvalid});
    const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                    response->results()[0].status_code().is_bad();
    EXPECT_TRUE(refusedAtService || refusedAtOperation)
      << "an Event history read specifying only startTime was served; operation status = "
      << (response != nullptr && response->results().size() == 1u ? code(response->results()[0].status_code())
                                                                  : 0u);
    if (response != nullptr && response->results().size() == 1u)
    {
      auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
      EXPECT_TRUE(events == nullptr || events->events().empty())
        << "an unbounded Event history read returned "
        << (events == nullptr ? size_t{0} : events->events().size())
        << " Events against a range the Client never closed";
    }
  }

  // startTime with numValuesPerNode: two of three, so it is served.
  {
    auto result = run_history_read(harness, bounded_event_read_request(node, at(0), std::nullopt, 2));
    auto* response = history_read_response(result.response);
    ASSERT_NE(response, nullptr) << "an Event history read bounded by two parameters produced no response";
    ASSERT_EQ(response->results().size(), 1u);
    ASSERT_TRUE(response->results()[0].status_code().is_good())
      << "an Event history read bounded by startTime and numValuesPerNode was refused, status = "
      << code(response->results()[0].status_code());
    auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(events, nullptr) << "the served Event history read returned no HistoryEvent at all";
    EXPECT_LE(events->events().size(), 2u)
      << "the read returned more Events than the numValuesPerNode it was bounded by";
    // Section 6.3 lets a Server return fewer results than the cap, but only with a ContinuationPoint,
    // so the Events it withheld stay reachable. Fewer and no point means Events were silently dropped.
    EXPECT_TRUE(events->events().size() == 2u || !response->results()[0].continuation_point().empty())
      << "the read returned " << events->events().size()
      << " of three stored Events with no continuationPoint, so the rest are unreachable";
  }
}

// OPC 10000-11 section 6.8.4.2 lines 2370-2372: "The whereClause parameter of the EventFilter shall be
// empty. The SelectClause shall as a minimum provide the following Event fields: EventType and Time."
// One EventFilter type serves the read path and the insert path, so the insert reuses the read's filter
// handling and simply ignores the half that has no meaning here - the Client is told its insert
// succeeded while the whereClause it believed was doing something did nothing, and an Event that names
// neither its type nor its time is filed where no query can find it.
// @verifies AC-SVR-HIST-UPD-005-EVENT-INSERT-FILTER
TEST(HistoryUpdateEventParameters, AnEventInsertIsRefusedForAWhereClauseAndForAnIncompleteSelectClause)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1030);

  // A control insert, so that "nothing was stored" below is distinguishable from "the read finds
  // nothing on this node whatever happens".
  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  // An insert is not a filtered query, so a whereClause on one has nothing to select against.
  {
    auto details = event_insert_details(
      node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(20), 200));
    ua::ContentFilterElement element;
    element.filter_operator() = ua::FilterOperator::OfType;
    ua::LiteralOperand operand;
    operand.value() = Variant{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
    ua::RefStructure<ua::Structure> operandRef;
    operandRef = std::unique_ptr<ua::Structure>(std::make_unique<ua::LiteralOperand>(std::move(operand)));
    element.filter_operands().push_back(std::move(operandRef));
    details->filter().where_clause().elements().push_back(std::move(element));

    auto result = harness.run(single_update_request(std::move(details), 2));
    EXPECT_TRUE(update_outcome(result).is_bad())
      << "an Event insert carrying a whereClause was accepted with status " << code(update_outcome(result))
      << ", so a parameter the Client supplied was silently ignored";
  }
  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "the Event insert carrying a whereClause stored its Event anyway";

  // A selectClause naming neither EventType nor Time is below the minimum an insert may carry.
  {
    const std::vector<std::string> belowMinimum{"EventId", "Severity"};
    std::vector<Variant> values;
    values.push_back(Variant{});
    values.push_back(Variant{uint16_t{300}});
    auto result = harness.run(single_update_request(
      event_insert_details(node, ua::PerformUpdateType::Insert, belowMinimum, std::move(values)), 3));
    EXPECT_TRUE(update_outcome(result).is_bad())
      << "an Event insert whose selectClause names neither EventType nor Time was accepted with status "
      << code(update_outcome(result));
  }
  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event carrying neither its EventType nor its Time was stored";
}

// OPC 10000-11 section 6.8.4.2 lines 2382-2384: "If the selectClause does not include fields which are
// mandatory for the EventType then the statusCode shall indicate Bad_ArgumentsMissing." Checking the
// two fields the clause itself names - EventType and Time - is the check an implementation writes,
// because it needs no knowledge of the type being inserted; consulting the EventType's own definition
// for the rest is a second lookup, and without it an Event missing the Severity and Message every
// consumer of BaseEventType expects is archived as though it were complete.
// @verifies AC-SVR-HIST-UPD-006-INSERT-ARGUMENTSMISSING
TEST(HistoryUpdateEventParameters, AnEventInsertOmittingAMandatoryEventTypeFieldIsRefused)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1040);

  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  // EventType and Time are present, but BaseEventType also makes SourceNode, SourceName, ReceiveTime,
  // Message and Severity Mandatory, and this insert provides none of them.
  const std::vector<std::string> minimumOnly{"EventId", "EventType", "Time"};
  std::vector<Variant> values;
  values.push_back(Variant{});
  values.push_back(Variant{ua::NodeId{ua::ObjectTypeId::BaseEventType}});
  values.push_back(Variant{at(20)});

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, minimumOnly, std::move(values)), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadArgumentsMissing}))
    << "an Event insert omitting fields BaseEventType makes Mandatory was not refused with "
       "Bad_ArgumentsMissing";

  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event missing fields its EventType makes Mandatory was stored anyway";
}

// OPC 10000-11 section 6.8.4.2 lines 2375-2376: "If the historian does not support archiving the
// specified EventType then the statusCode shall indicate Bad_TypeDefinitionInvalid." The historian's
// archived types are a subset of the address space's, so the EventType field is naturally treated as
// opaque payload and stored with the rest of the row - the Event is then archived under a type the
// historian cannot serve, and only a later read discovers it. The stimulus names a Node that exists so
// that Bad_NodeIdUnknown is not a defensible answer: the only thing wrong with it is that it is not an
// Event type.
// @verifies AC-SVR-HIST-UPD-007-UNSUPPORTED-EVENTTYPE
TEST(HistoryUpdateEventParameters, AnEventInsertOfATypeTheHistorianCannotArchiveIsRefused)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1050);

  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  // FolderType: a Node that exists in this Server, so the refusal cannot be a Bad_NodeIdUnknown about
  // an unresolvable NodeId - it is not an Event type, so no historian can archive Events of it.
  auto values = base_event_values(node, at(20), 200);
  values[1] = Variant{ua::NodeId{ua::ObjectTypeId::FolderType}};

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, baseEventFields, std::move(values)), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadTypeDefinitionInvalid}))
    << "an Event of a type the historian cannot archive was not refused with Bad_TypeDefinitionInvalid";

  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event of an unarchivable EventType was archived anyway";
}

// OPC 10000-11 section 6.8.4.2 lines 2376-2381: "If the SourceNode is not a valid source for Events
// then the related operationResults entry shall indicate Bad_SourceNodeIdInvalid." SourceNode arrives
// as one more Variant in the eventData row, so validating it means resolving that NodeId against the
// address space - work the insert does not otherwise need. Skipping it records a Node as having emitted
// an Event when no such Node exists, and the history then contradicts the address space.
// @verifies AC-SVR-HIST-UPD-008-INVALID-SOURCENODE
TEST(HistoryUpdateEventParameters, AnEventInsertNamingASourceNodeThatCannotEmitEventsIsRefused)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1060);

  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  // Bad_SourceNodeIdInvalid is glossed in OPC 10000-4 Table 183 as "the source node id does not refer to
  // a valid node" - an unresolvable NodeId, not a NodeClass judgement. OPC 10000-5 archives the
  // NodeClass point by example: AuditWriteUpdateEventType's SourceNode "identifies the Node that was
  // written", which is a Variable. A Variable is therefore a conforming SourceNode and the stimulus has
  // to be a NodeId that resolves to nothing at all.
  const ua::NodeId notAnEventSource{harness.nsIndex, 1099u};  // never created: no such Node exists
  auto values = base_event_values(notAnEventSource, at(20), 200);

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, baseEventFields, std::move(values)), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadSourceNodeIdInvalid}))
    << "an Event whose SourceNode resolves to no Node was not refused with Bad_SourceNodeIdInvalid";

  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event attributed to a Node that does not exist was stored anyway";
}

// OPC 10000-11 section 6.8.4.2 lines 2397-2399: "If any errors occur while processing individual fields
// then the related operationResults entry shall indicate Bad_InvalidArgument and the invalid fields
// shall be indicated in the DiagnosticInformation." The read path reports per-field problems per field,
// so the insert path is naturally written the same way - store what parsed, note what did not - and a
// partially stored Event is then indistinguishable on read from one the Server generated. The error is
// fatal to the whole entry, not to the field.
// @verifies AC-SVR-HIST-UPD-011-FIELD-ERROR-FATAL
TEST(HistoryUpdateEventParameters, AnEventInsertWithAFieldThatCannotBeProcessedStoresNoPartialEvent)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1070);

  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  // Severity is a UInt16 on BaseEventType; a String cannot be processed into that field.
  auto values = base_event_values(node, at(20), 200);
  values[7] = Variant{ua::String{"not a severity"}};

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, baseEventFields, std::move(values)), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadInvalidArgument}))
    << "an Event whose Severity field could not be processed was not refused with Bad_InvalidArgument";

  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event with an unprocessable field was stored in part rather than refused whole";
}

// OPC 10000-11 section 6.8.4.2 lines 2401-2402: "The IndexRange parameter of the SimpleAttributeOperand
// is not valid for insert operations and the StatusCode shall specify Bad_IndexRangeInvalid if one is
// specified." The operand type is shared with the read path, where an IndexRange is meaningful, so the
// insert path inherits a field it must reject rather than apply: left unchecked, the Client is told the
// whole value was archived while the Server stored whatever its read-path slicing made of it.
// @verifies AC-SVR-HIST-UPD-012-INSERT-FIELD-VALIDATION
TEST(HistoryUpdateEventParameters, AnEventInsertWhoseSelectClauseCarriesAnIndexRangeIsRefused)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1080);

  {
    auto control = single_update_request(
      event_insert_details(
        node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(10), 100)),
      1);
    auto result = harness.run(std::move(control));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "the well-formed control Event insert was refused, status = " << code(update_outcome(result));
  }
  ASSERT_EQ(stored_event_count(harness, node), 1u) << "the control Event was not stored";

  auto details = event_insert_details(
    node, ua::PerformUpdateType::Insert, baseEventFields, base_event_values(node, at(20), 200));
  ASSERT_EQ(details->filter().select_clauses().size(), baseEventFields.size());
  details->filter().select_clauses()[7].index_range() = ua::String{"0:1"};

  auto result = harness.run(single_update_request(std::move(details), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadIndexRangeInvalid}))
    << "an Event insert whose selectClause carries an IndexRange was not refused with "
       "Bad_IndexRangeInvalid";

  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "an Event inserted through a selectClause carrying an IndexRange was stored anyway";
}

// OPC 10000-11 section 6.8.4.2 lines 2384-2389: "If the selectClause specifies fields which are not
// valid for the EventType or cannot be saved by the historian then the related operationResults entry
// shall indicate Good_DataIgnored. Additional information about the ignored fields shall be provided
// through DiagnosticInformation related to the operationResults." Good_DataIgnored is a success code
// for work not done, and that is the whole point of it: the two plausible answers - plain Good, or a
// Bad that fails an otherwise valid insert - each lose one half of the truth, and a Client reading
// Good-severity as "everything I sent was stored" records fields the history does not hold.
// @verifies AC-SVR-HIST-UPD-009-INSERT-OUTCOMES
TEST(HistoryUpdateEventParameters, AnEventInsertReportsAFieldItCouldNotSaveAsIgnoredAndSaysWhichOne)
{
  HistoryAuditHarness harness;
  harness.setup();
  // The DiagnosticInformation this test is about is suppressed outright on an unsecured channel
  // and for a caller the diagnostic policy grants nothing to, so asking for it in the stub's
  // default state would observe the suppression rather than the Server's answer.
  harness.sessionInfo->enable_operation_diagnostics();
  const auto node = event_history_object(harness, 1090);

  const std::string ignoredField{"NotAFieldOfBaseEventType"};
  auto fieldNames = baseEventFields;
  fieldNames.push_back(ignoredField);
  auto values = base_event_values(node, at(10), 100);
  values.push_back(Variant{42.0});

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, fieldNames, std::move(values)), 1));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::GoodDataIgnored}))
    << "an Event insert naming a field BaseEventType does not define was not reported as "
       "Good_DataIgnored";

  auto* response = update_response(result);
  ASSERT_NE(response, nullptr) << "the Event insert answered with a ServiceFault, so no per-operation "
                                  "DiagnosticInformation exists to carry the ignored field";
  ASSERT_EQ(response->results().size(), 1u);

  // The Event itself is stored: Good_DataIgnored is a success, and only the field was dropped.
  EXPECT_EQ(stored_event_count(harness, node), 1u)
    << "the insert was not applied even though the ignored field is not a fatal error";

  // ... and the DiagnosticInformation says which field the historian dropped.
  ASSERT_FALSE(response->results()[0].diagnostic_infos().empty())
    << "no DiagnosticInformation accompanies the ignored field, so the Client cannot learn what was "
       "dropped";
  const auto& diagnostic = response->results()[0].diagnostic_infos()[0];
  EXPECT_TRUE(diagnostic.symbolic_id().has_value() || diagnostic.localized_text().has_value())
    << "the DiagnosticInformation names no string-table entry at all";
  ASSERT_TRUE(diagnostic.additional_info().has_value())
    << "the DiagnosticInformation has no structured context naming the ignored field";
  EXPECT_NE(diagnostic.additional_info()->find(ignoredField), std::string::npos)
    << "the DiagnosticInformation context does not name the ignored field " << ignoredField;
}

// @relation(AC-SVR-HIST-UPD-014-REPLACE-IGNORED-FIELD, scope=function)
TEST(HistoryUpdateEventReplace, IgnoredFieldReturnsGoodDataIgnoredNamesFieldAndAppliesValidFields)
{
  HistoryAuditHarness harness;
  harness.setup();
  harness.sessionInfo->enable_operation_diagnostics();
  const auto node = event_history_object(harness, 1100);
  const ua::ByteString eventId{std::vector<uint8_t>{0x14, 0x01}};

  auto seedValues = base_event_values(node, at(10), 100);
  seedValues[0] = Variant{eventId};
  auto seed = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, baseEventFields, std::move(seedValues)), 1));
  ASSERT_TRUE(update_outcome(seed).is_good());

  const std::string ignoredField{"NotAFieldOfBaseEventType"};
  auto fieldNames = baseEventFields;
  fieldNames.push_back(ignoredField);
  auto replacementValues = base_event_values(node, at(20), 200);
  replacementValues[0] = Variant{eventId};
  replacementValues.push_back(Variant{42.0});

  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Replace, fieldNames, std::move(replacementValues)), 2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::GoodDataIgnored}));

  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_EQ(response->results()[0].diagnostic_infos().size(), 1u);
  ASSERT_TRUE(response->results()[0].diagnostic_infos()[0].additional_info().has_value());
  EXPECT_NE(
    response->results()[0].diagnostic_infos()[0].additional_info()->find(ignoredField), std::string::npos);

  const auto stored = stored_event_snapshots(harness, node);
  ASSERT_EQ(stored.size(), 1u) << "Replace duplicated or removed the existing Event";
  EXPECT_EQ(stored[0].time, at(20));
  EXPECT_EQ(stored[0].severity, 200u);
}

// @relation(AC-SVR-HIST-UPD-014-REPLACE-FATAL-FIELD, scope=function)
TEST(HistoryUpdateEventReplace, FatalFieldReturnsBadInvalidArgumentNamesFieldAndPreservesEvent)
{
  HistoryAuditHarness harness;
  harness.setup();
  harness.sessionInfo->enable_operation_diagnostics();
  const auto node = event_history_object(harness, 1110);
  const ua::ByteString eventId{std::vector<uint8_t>{0x14, 0x02}};

  auto seedValues = base_event_values(node, at(10), 100);
  seedValues[0] = Variant{eventId};
  auto seed = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Insert, baseEventFields, std::move(seedValues)), 1));
  ASSERT_TRUE(update_outcome(seed).is_good());

  auto replacementValues = base_event_values(node, at(20), 200);
  replacementValues[0] = Variant{eventId};
  replacementValues[7] = Variant{ua::String{"not a severity"}};
  auto result = harness.run(single_update_request(
    event_insert_details(node, ua::PerformUpdateType::Replace, baseEventFields, std::move(replacementValues)),
    2));
  EXPECT_EQ(code(update_outcome(result)), code(StatusCode{ua::Status::BadInvalidArgument}));

  auto* response = update_response(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_EQ(response->results()[0].diagnostic_infos().size(), 1u)
    << "the fatal row has no DiagnosticInformation naming its invalid field";
  ASSERT_TRUE(response->results()[0].diagnostic_infos()[0].additional_info().has_value());
  EXPECT_NE(
    response->results()[0].diagnostic_infos()[0].additional_info()->find("Severity"), std::string::npos);

  const auto stored = stored_event_snapshots(harness, node);
  ASSERT_EQ(stored.size(), 1u) << "the fatal Replace duplicated or removed the existing Event";
  EXPECT_EQ(stored[0].time, at(10)) << "the fatal row partially changed the Event timestamp";
  EXPECT_EQ(stored[0].severity, 100u) << "the fatal row partially changed the Event Severity";
}

namespace
{

// The historian info bits of a StatusCode: OPC 10000-4 Table 181 puts them in the low five bits, of
// which the low pair is a mutually-exclusive data-location field (00 Raw, 01 Calculated, 10
// Interpolated). A read that reports "Good" and nothing else leaves the pair at 00, i.e. it makes the
// positive claim that the value it returned was stored.
constexpr uint32_t historianBitsMask = 0x1Fu;
constexpr uint32_t historianBitsRaw = 0x00u;
constexpr uint32_t historianBitsInterpolated = 0x02u;

uint32_t historian_bits(const DataValue& value)
{
  return value.status().value_or(StatusCode{}).as_uint32() & historianBitsMask;
}

}  // namespace

// OPC 10000-11 section 6.4.3.3 (Read modified functionality). Some historians store several values at
// one timestamp, and the modified read is the only way a Client sees them - a raw read returns one
// value per timestamp by construction. So an implementation that serves ReadModified by reusing the
// raw path and filtering it for entries that carry a modification record answers with the newest
// replacement alone, and every earlier correction of that timestamp is lost with no error anywhere.
// The same structure explains the second half: bounding values are defined for a window of raw values
// and have no meaning over a set of modification records, so returnBounds together with isReadModified
// is Bad_InvalidArgument rather than a flag the read may quietly ignore.
// @verifies AC-SVR-HIST-READ-010-MODIFIED
TEST(HistoryEngineReadModified, BothReplacementsAtOneTimestampComeBackAndReturnBoundsIsRefused)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();

  // Two Replaces at the SAME timestamp: the historian now holds two superseded values at t = 10
  // (1.0, superseded by 2.0; then 2.0, superseded by 3.0). No arm of this file drives that before.
  auto firstReplace =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}));
  ASSERT_TRUE(firstReplace.is_good());
  ASSERT_EQ(firstReplace.value().operationResults.size(), 1u);
  ASSERT_EQ(code(firstReplace.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}))
    << "the first replacement was refused, so the stimulus never happened";
  auto secondReplace =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 3.0)}));
  ASSERT_TRUE(secondReplace.is_good());
  ASSERT_EQ(code(secondReplace.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}))
    << "the second replacement was refused, so only one modification record exists to find";

  // returnBounds FALSE: both superseded values come back, not only the latest.
  auto item = raw_item(at(0), at(60));
  item.isReadModified = true;
  auto modified = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(modified.is_good()) << "the modified read failed, status = "
                                  << modified.status_code().as_uint32();
  ASSERT_EQ(modified.value().values.size(), 2u)
    << "two values were replaced at t = 10 and the modified read returned " << modified.value().values.size()
    << " of them";
  ASSERT_EQ(modified.value().modificationInfos.size(), 2u)
    << "the values and their ModificationInfos are parallel arrays and did not come back that way";

  std::vector<double> superseded;
  for (size_t i = 0; i < modified.value().values.size(); ++i)
  {
    EXPECT_EQ(ticks(modified.value().values[i]), at(10).value().time_since_epoch().count())
      << "modification record " << i << " is not at the timestamp that was replaced twice";
    const double* held = modified.value().values[i].value().try_as<double>();
    ASSERT_NE(held, nullptr) << "modification record " << i << " carries no value at all";
    superseded.push_back(*held);
  }
  EXPECT_NE(std::find(superseded.begin(), superseded.end(), 1.0), superseded.end())
    << "the first value replaced at t = 10 is missing, so the modified read kept only the newer entry";
  EXPECT_NE(std::find(superseded.begin(), superseded.end(), 2.0), superseded.end())
    << "the second value replaced at t = 10 is missing";

  // returnBounds TRUE: refused, the parameter having no meaning for a modification-record read.
  auto bounded = raw_item(at(0), at(60), 0, /*bounds*/ true);
  bounded.isReadModified = true;
  auto refused = HistoryEngine::read_raw(store, bounded);
  ASSERT_TRUE(refused.is_bad()) << "a modified read asking for bounding values was served";
  EXPECT_EQ(refused.status_code().as_uint32(), StatusCode{ua::Status::BadInvalidArgument}.as_uint32());
}

// @relation(AC-SVR-HIST-READ-012-SAME-TIMESTAMP-CONTINUATION, scope=function)
TEST(HistoryEngineReadModified, PageBoundaryInsideOneTimestampContinuesWithTheRemainingModification)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();
  ASSERT_TRUE(
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 2.0)}))
      .is_good());
  ASSERT_TRUE(
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 3.0)}))
      .is_good());

  auto firstItem = raw_item(at(0), at(60), 1);
  firstItem.isReadModified = true;
  auto first = HistoryEngine::read_raw(store, firstItem);
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().values.size(), 1u);
  ASSERT_EQ(first.value().modificationInfos.size(), 1u);
  ASSERT_TRUE(first.value().cursor.has_value());

  auto secondItem = raw_item(at(0), at(60), 1);
  secondItem.isReadModified = true;
  secondItem.cursor = first.value().cursor;
  auto second = HistoryEngine::read_raw(store, secondItem);
  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().values.size(), 1u);
  ASSERT_EQ(second.value().modificationInfos.size(), 1u);
  EXPECT_FALSE(second.value().cursor.has_value());

  EXPECT_EQ(ticks(first.value().values[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(ticks(second.value().values[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(first.value().modificationInfos[0].update_type(), ua::HistoryUpdateType::Replace);
  EXPECT_EQ(second.value().modificationInfos[0].update_type(), ua::HistoryUpdateType::Replace);

  std::vector<double> replacedValues;
  for (const auto* value :
    {first.value().values[0].value().try_as<double>(), second.value().values[0].value().try_as<double>()})
  {
    ASSERT_NE(value, nullptr);
    replacedValues.push_back(*value);
  }
  std::sort(replacedValues.begin(), replacedValues.end());
  EXPECT_EQ(replacedValues, (std::vector<double>{1.0, 2.0}));
}

namespace
{
namespace aggregates = ua::server::aggregates;

// One Good numeric sample for the aggregate engine, in the engine's own reduced form.
aggregates::Sample aggregate_sample(DateTime when, double value)
{
  return aggregates::Sample{when, Variant{value}, StatusCode{ua::Status::Good}, value, true};
}
}  // namespace

// OPC 10000-13 section 5.4.1 / 5.4.2.2: processing intervals are half-open - each includes its
// earliest edge and excludes its latest - which is the only convention under which adjacent intervals
// partition the data. Both alternative errors are silent: inclusive-both counts a value sitting on the
// shared boundary in each of the two intervals, exclusive-both counts it in neither, and neither
// mistake changes the shape of the result, only its numbers. A value placed exactly on the boundary is
// the sole stimulus that separates the three, so the two counts are asserted together: the first rules
// out inclusive-both and the second rules out exclusive-both.
// @verifies AC-SVR-HIST-AGG-024-INTERVAL-BOUNDS
TEST(AggregateProcessingIntervals, AValueOnASharedBoundaryContributesToTheLaterIntervalOnly)
{
  const aggregates::Aggregator* counter = aggregates::AggregatorRegistry::instance().find(
    NodeId{static_cast<uint32_t>(ua::ObjectId::AggregateFunction_Count)});
  ASSERT_NE(counter, nullptr)
    << "AggregateFunction_Count is not registered, so no aggregate counts the samples in an interval";

  // t = 5 lies inside the first interval, t = 10 sits exactly on the boundary the two share, and t = 15
  // lies inside the second. The trailing sample matters: without it the later interval starts at the
  // last data point and the calculator reports the whole interval as outside the data.
  const std::vector<aggregates::Sample> samples{
    aggregate_sample(at(5), 5.0), aggregate_sample(at(10), 10.0), aggregate_sample(at(15), 15.0)};

  const aggregates::IntervalSet intervals =
    aggregates::generate_intervals(at(0), at(20), /*processingIntervalMs*/ 10000.0);
  ASSERT_FALSE(intervals.invalid) << "a 20 s range at a 10 s interval was rejected as malformed";
  ASSERT_EQ(intervals.intervals.size(), 2u)
    << "the stimulus needs exactly two adjacent intervals sharing the boundary at t = 10";

  aggregates::AggregateContext context;
  context.cfg = aggregates::CalcConfig{};
  context.sourceTemplate = aggregates::source_template(samples);

  const std::vector<DataValue> counts = aggregates::run_aggregator(*counter, samples, intervals, context);
  ASSERT_EQ(counts.size(), 2u) << "one aggregate value per interval was expected";

  const std::optional<double> earlier = aggregates::value_to_double(counts[0].value());
  const std::optional<double> later = aggregates::value_to_double(counts[1].value());
  ASSERT_TRUE(earlier.has_value()) << "the earlier interval produced no countable value";
  ASSERT_TRUE(later.has_value()) << "the later interval produced no countable value";

  // Half-open: {5} then {10, 15}. Inclusive-both would give {5, 10} then {10, 15}; exclusive-both
  // would give {5} then {15}.
  EXPECT_DOUBLE_EQ(*earlier, 1.0)
    << "the earlier interval counted " << *earlier
    << " values, so the value on the shared boundary was counted in it as well as in the later one";
  EXPECT_DOUBLE_EQ(*later, 2.0)
    << "the later interval counted " << *later
    << " values, so the value on the shared boundary was excluded from the interval it starts";
}

// OPC 10000-11 section 6.8.4.4 (Update event functionality): "If an existing Event entry was replaced
// successfully then the related operationResults entry shall be Good_EntryReplaced. If a new Event
// entry was created then the related operationResults entry shall be Good_EntryInserted." The clause
// admits plain Good only where the Server "cannot determine whether it replaced or inserted" - which is
// not this Server: the engine looks the EventId up and deletes the match before writing, so it has the
// answer in hand and discards it. Both codes are Good-severity, so a Client checking severity alone
// cannot tell an Event it corrected from one it silently created under a mistyped EventId.
// @verifies AC-SVR-HIST-UPD-015-UPDATE-OUTCOMES
TEST(HistoryEngineUpdateEvents, UpdateSaysEntryReplacedForAKnownEventIdAndEntryInsertedForANewOne)
{
  SqliteHistoryStore store{":memory:", make_codec()};

  // The EventId {1} exists after this insert; {2} never will until the second UPDATE below.
  auto seeded = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));
  ASSERT_TRUE(seeded.is_good());
  ASSERT_EQ(seeded.value().operationResults.size(), 1u);
  ASSERT_TRUE(seeded.value().operationResults[0].is_good()) << "the seed Event was not stored";

  auto replaced = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Update, {event_record({{1}}, 10, 200.0)}));
  ASSERT_TRUE(replaced.is_good());
  ASSERT_EQ(replaced.value().operationResults.size(), 1u);

  auto inserted = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Update, {event_record({{2}}, 20, 300.0)}));
  ASSERT_TRUE(inserted.is_good());
  ASSERT_EQ(inserted.value().operationResults.size(), 1u);

  // Both really happened: one Event was corrected in place and one was added.
  auto readItem = events_item(at(0), at(60), filter_selecting({"Severity"}));
  auto read = HistoryEngine::read_events(store, readItem);
  ASSERT_TRUE(read.is_good());
  ASSERT_EQ(read.value().events.size(), 2u)
    << "the two UPDATEs did not leave one replaced and one inserted Event behind";

  EXPECT_EQ(code(replaced.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}))
    << "an UPDATE whose EventId matched an existing Event did not report Good_EntryReplaced";
  EXPECT_EQ(code(inserted.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}))
    << "an UPDATE whose EventId matched nothing did not report Good_EntryInserted";
  EXPECT_NE(code(replaced.value().operationResults[0]), code(inserted.value().operationResults[0]))
    << "the two outcomes report the same code, so the Client cannot tell them apart";
}

namespace
{

// Every NodeId owned by any namespace of `server`, gathered through the address space's own
// enumeration rather than a browse walk (a walk reaches only what is referenced from the Root).
std::vector<NodeId> all_nodes_of(ua::test_helpers::TestServer& server)
{
  std::vector<NodeId> nodes;
  auto addressSpace = server.server().address_space();
  const auto uris = addressSpace.namespace_array().get_namespace_array();
  for (size_t index = 0; index < uris.size(); ++index)
  {
    auto promise = std::make_shared<std::promise<ua::Result<std::vector<NodeId>>>>();
    auto future = promise->get_future();
    addressSpace.enumerate_nodes_async(static_cast<uint16_t>(index),
      [promise](ua::Result<std::vector<NodeId>> outcome) { promise->set_value(std::move(outcome)); });
    if (future.wait_for(std::chrono::seconds{10}) != std::future_status::ready)
    {
      ADD_FAILURE() << "enumerating namespace " << index << " did not complete";
      continue;
    }
    auto outcome = future.get();
    if (outcome.is_bad())
      continue;  // a namespace that declines to enumerate contributes no subjects
    for (const auto& nodeId : outcome.value())
      nodes.push_back(nodeId);
  }
  return nodes;
}

// A NodeId in the usual `ns=...;i=...` shorthand, so a failure names the node it is about.
std::string describe_node(const NodeId& nodeId)
{
  std::string text = "ns=" + std::to_string(nodeId.namespace_index()) + ";";
  if (nodeId.is_numeric())
    text += "i=" + std::to_string(nodeId.identifier().get_numeric());
  else if (nodeId.is_string())
    text += "s=" + std::string{nodeId.identifier().get_string()};
  else
    text += "<guid or opaque identifier>";
  return text;
}

// The local targets of `node`'s forward HasHistoricalConfiguration references - i.e. the historical
// configuration Objects that Node declares.
std::vector<NodeId> historical_configurations_of(ua::AddressSpace addressSpace, const NodeId& node)
{
  std::vector<NodeId> targets;
  auto found = addressSpace.try_find_node_sync(node);
  if (found.is_bad())
    return targets;
  for (const auto& reference : found.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.is_remote())
      continue;
    if (reference.type_id() != NodeId{ua::ReferenceTypeId::HasHistoricalConfiguration})
      continue;
    const auto target = reference.target_id();
    if (!target.is_local())
      continue;
    targets.push_back(target.node_id());
  }
  return targets;
}

}  // namespace

// OPC 10000-11 section 5.2: "If a HistoricalDataNode has configuration defined then one instance shall
// have a BrowseName of 'HA Configuration'. Additional configurations can be defined with different
// BrowseNames." 'HA Configuration' is the well-known name a Client browses for, so the well-known
// entry point fails in both directions: several configurations sharing the name make the lookup
// ambiguous, and none carrying it leaves the configuration undiscoverable even though it is modelled
// and reachable. Naming every configuration alike is the natural mistake when the name is copied from
// the type rather than assigned to the one canonical instance.
// @verifies AC-SVR-HIST-CAP-016-HA-CONFIGURATION
TEST(HistoricalDataNodeConfiguration, EachConfiguredNodeNamesExactlyOneConfigurationHaConfiguration)
{
  ua::test_helpers::TestServer server;
  server.create();
  auto addressSpace = server.server().address_space();

  const std::vector<NodeId> nodes = all_nodes_of(server);
  ASSERT_FALSE(nodes.empty()) << "the address-space scan found no nodes at all, so it proves nothing";

  // Collect the population first: the assertions below must not run over an empty set silently.
  std::vector<std::pair<NodeId, std::vector<NodeId>>> configured;
  for (const auto& nodeId : nodes)
  {
    auto targets = historical_configurations_of(addressSpace, nodeId);
    if (!targets.empty())
      configured.emplace_back(nodeId, std::move(targets));
  }

  GTEST_LOG_(INFO) << "scanned " << nodes.size() << " nodes; " << configured.size()
                   << " carry a HasHistoricalConfiguration reference";

  // The scan finds none: this SDK models no HistoricalDataConfigurationType instance of its own, and
  // Part 11's clause is conditional in its own words -- "If a HistoricalDataNode has configuration
  // defined". That used to be a skip. `qa_process.md` section 6.3 retired "the population is empty, so there
  // is nothing to test" and gives an absent subject four answers; the answer here is the second, the
  // test can build the subject, because the clause governs a shape an APPLICATION supplies and the
  // address space accepts it through its public API.
  //
  // Two configurations are built, which is the only arrangement that can fail in both directions the
  // obligation names: a single one named 'HA Configuration' would pass a server that named every
  // configuration alike, and the ambiguity that breaks a Client's lookup only appears with a second.
  // The second is given a different BrowseName, which is what Part 11 permits -- "Additional
  // configurations can be defined with different BrowseNames" -- so a conforming pair is exactly one
  // well-known name among several.
  // Built in a namespace of this test's own, not namespace 0: a test may not allocate nodes in the
  // standard model, and the obligation is about an application's historised Node in any case.
  boost::asio::thread_pool subjectPool{1};
  auto subjectNamespace =
    default_ns::Namespace::create("urn:test:historical-configuration", subjectPool.get_executor());
  const auto applicationNs = addressSpace.add_namespace_sync(subjectNamespace);
  ASSERT_GT(applicationNs, 0u) << "the subject namespace was registered as namespace 0";
  const NodeId historised{applicationNs, uint32_t{9800}};
  const NodeId canonicalConfig{applicationNs, uint32_t{9801}};
  const NodeId secondaryConfig{applicationNs, uint32_t{9802}};
  {
    auto variable = addressSpace.create_node_sync(historised, ua::NodeClass::Variable);
    variable.set_browse_name(ua::QualifiedName{applicationNs, "HistorisedSignal"});
    variable.set_display_name(ua::LocalizedText{"", ua::String{"HistorisedSignal"}});

    const std::pair<NodeId, const char*> configurations[]{
      {canonicalConfig, "HA Configuration"}, {secondaryConfig, "1 Second Collection"}};
    for (const auto& [id, name] : configurations)
    {
      auto configuration = addressSpace.create_node_sync(id, ua::NodeClass::Object);
      configuration.set_browse_name(ua::QualifiedName{applicationNs, name});
      configuration.set_display_name(ua::LocalizedText{"", ua::String{name}});
      configuration.add_reference_sync(NodeId{ua::ReferenceTypeId::HasTypeDefinition},
        NodeId{ua::ObjectTypeId::HistoricalDataConfigurationType});
      variable.add_reference_sync(NodeId{ua::ReferenceTypeId::HasHistoricalConfiguration}, id);
    }

    auto targets = historical_configurations_of(addressSpace, historised);
    ASSERT_EQ(targets.size(), 2u)
      << "the address space did not materialise both HasHistoricalConfiguration references, so the "
         "subject this test builds does not exist and the assertions below would prove nothing";
    configured.emplace_back(historised, std::move(targets));
  }

  for (const auto& [nodeId, targets] : configured)
  {
    size_t wellKnown = 0;
    for (const auto& target : targets)
    {
      auto configuration = addressSpace.try_find_node_sync(target);
      if (configuration.is_bad())
      {
        ADD_FAILURE() << "node " << describe_node(nodeId)
                      << " references a historical configuration that does not resolve";
        continue;
      }
      if (configuration.value().get_browse_name().name() == "HA Configuration")
        ++wellKnown;
    }
    EXPECT_EQ(wellKnown, 1u) << "node " << describe_node(nodeId) << " declares " << targets.size()
                             << " historical configuration(s) of which " << wellKnown
                             << " are BrowseNamed 'HA Configuration'; exactly one must be";
  }
}

namespace
{

// A ReadProcessedDetails HistoryRead over a bounded window, asking one aggregate of one Node. The
// window is deliberately non-degenerate so the equal-times rule (checked before the timestamp rule)
// cannot be what refuses a request aimed at the timestamp rule, and vice versa.
ua::HistoryReadRequest processed_read_request(
  const ua::NodeId& nodeId, DateTime start, DateTime end, ua::TimestampsToReturn timestamps)
{
  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = timestamps;
  auto details = std::make_unique<ua::ReadProcessedDetails>();
  details->start_time() = start;
  details->end_time() = end;
  details->processing_interval() = 10000.0;
  details->aggregate_type().resize(1);
  details->aggregate_type()[0] = ua::NodeId{static_cast<uint32_t>(ua::ObjectId::AggregateFunction_Count)};
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

// Seed `node` with values at t = 0,10,...,(count-1)*10 through the real HistoryUpdate service.
void seed_values(HistoryAuditHarness& harness, const ua::NodeId& node, int count)
{
  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i)
  {
    request.history_update_details()[static_cast<size_t>(i)] =
      data_details(node, ua::PerformUpdateType::Insert, sample(i * 10, static_cast<double>(i)));
  }
  auto result = harness.run(std::move(request));
  auto* response = update_response(result);
  ASSERT_NE(response, nullptr) << "the seeding HistoryUpdate produced no HistoryUpdateResponse";
  ASSERT_EQ(response->results().size(), static_cast<size_t>(count));
  for (int i = 0; i < count; ++i)
  {
    ASSERT_TRUE(response->results()[static_cast<size_t>(i)].status_code().is_good())
      << "seed value " << i << " was refused";
  }
}

}  // namespace

// OPC 10000-13 section 5.2 / 5.4.3.1: "If a requested timestamp is set to anything but the source
// timestamp the operation shall return the Bad_TimestampToReturnInvalid StatusCode." (The registered
// identifier in OPC 10000-4 Table 183 is the plural Bad_TimestampsToReturnInvalid; that is the code
// asserted.) An aggregate value was computed, not received, so it has no ServerTimestamp to return at
// all - the parameter is meaningless here rather than merely unsupported. A Server that defaults a
// non-Source request to Source answers a different question than the Client asked and says nothing
// about it. Both non-Source values are driven, because a validator written against the one value a
// test happened to use passes on that value and admits the other.
// @verifies AC-SVR-HIST-AGG-027-SOURCE-TIMESTAMP-ONLY
TEST(HistoryReadProcessedParameters, AProcessedReadIsRefusedForServerAndForBothTimestamps)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = harness.historised_variable(1110);
  seed_values(harness, node, 4);

  const StatusCode invalid{ua::Status::BadTimestampsToReturnInvalid};

  // Control: Source is the one accepted value, so a refusal below cannot be about the window or Node.
  {
    auto result =
      run_history_read(harness, processed_read_request(node, at(0), at(40), ua::TimestampsToReturn::Source));
    EXPECT_FALSE(history_read_service_result_is(result.response, invalid))
      << "a processed read asking for the source timestamp was refused as an invalid timestamp request";
  }

  const std::vector<std::pair<ua::TimestampsToReturn, const char*>> rejected{
    {ua::TimestampsToReturn::Server, "Server"}, {ua::TimestampsToReturn::Both, "Both"}};
  ASSERT_EQ(rejected.size(), 2u);

  for (const auto& [timestamps, name] : rejected)
  {
    SCOPED_TRACE(name);
    auto result = run_history_read(harness, processed_read_request(node, at(0), at(40), timestamps));
    auto* response = history_read_response(result.response);
    const bool refusedAtService = history_read_service_result_is(result.response, invalid);
    const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                    code(response->results()[0].status_code()) == code(invalid);
    EXPECT_TRUE(refusedAtService || refusedAtOperation)
      << "a processed read asking for " << name
      << " timestamps was not refused with Bad_TimestampsToReturnInvalid at either level";
    if (response != nullptr && response->results().size() == 1u)
    {
      auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
      EXPECT_TRUE(data == nullptr || data->data_values().size() == 0u)
        << "aggregate values were returned for a timestamp the aggregate cannot carry";
    }
  }
}

// OPC 10000-13 section 5.2: a zero-width range has "no meaningful way to interpret" it, so a
// ReadProcessedDetails whose startTime equals its endTime is Bad_InvalidArgument. This is deliberately
// the opposite disposition from AC-SVR-HIST-READ-007-OUT-OF-RANGE-IS-NODATA, where an argument error
// is forbidden: an empty *result* is a valid answer to a well-formed question, while an empty
// *interval* is a malformed question. The two sit adjacent, so the plausible implementation applies one
// rule to both and either rejects a legitimate empty window or serves an aggregate over no interval at
// all - a single value covering nothing, indistinguishable from a real one.
// @verifies AC-SVR-HIST-AGG-025-EQUAL-TIMES-INVALID
TEST(HistoryReadProcessedParameters, AProcessedReadWithEqualStartAndEndTimesIsBadInvalidArgument)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = harness.historised_variable(1120);
  seed_values(harness, node, 4);

  const StatusCode invalidArgument{ua::Status::BadInvalidArgument};

  // Control: the same request over a non-degenerate window is not refused with Bad_InvalidArgument, so
  // the refusal below is about the width of the interval and nothing else.
  {
    auto result =
      run_history_read(harness, processed_read_request(node, at(0), at(40), ua::TimestampsToReturn::Source));
    auto* response = history_read_response(result.response);
    const bool serviceRefused = history_read_service_result_is(result.response, invalidArgument);
    const bool operationRefused = response != nullptr && response->results().size() == 1u &&
                                  code(response->results()[0].status_code()) == code(invalidArgument);
    EXPECT_FALSE(serviceRefused || operationRefused)
      << "a processed read over a 40 s window was refused as an invalid argument";
  }

  auto result =
    run_history_read(harness, processed_read_request(node, at(20), at(20), ua::TimestampsToReturn::Source));
  auto* response = history_read_response(result.response);
  const bool refusedAtService = history_read_service_result_is(result.response, invalidArgument);
  const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                  code(response->results()[0].status_code()) == code(invalidArgument);
  EXPECT_TRUE(refusedAtService || refusedAtOperation)
    << "a processed read whose startTime equals its endTime was not refused with Bad_InvalidArgument";

  if (response != nullptr && response->results().size() == 1u)
  {
    auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
    EXPECT_TRUE(data == nullptr || data->data_values().size() == 0u)
      << "an aggregate was computed over a zero-width interval and returned as a value";
  }
}

// OPC 10000-11 section 6.4.4 (Read at time functionality): "The order of the values and qualities
// returned shall match the order of the timestamps supplied in the request", and "If a value is found
// for the specified timestamp then the Server will set the StatusCode InfoBits to be Raw. If the value
// is Interpolated from the surrounding values, then the Server will set the StatusCode InfoBits to be
// Interpolated." Sorting the requested timestamps is the natural optimisation and it breaks the
// correspondence the reply depends on - the response carries no request key, so the Client pairs
// results with requests by position. The InfoBits are the other half of the same answer: a value the
// Server derived, returned as plain Good, makes the positive claim that the historian stored it.
// @verifies AC-SVR-HIST-READ-011-ATTIME-ORDER
TEST(HistoryEngineReadAtTime, RequestOrderIsKeptAndDerivedValuesCarryTheInterpolatedInfoBits)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  seed(store, 4);  // t = 0,10,20,30 ; value == seconds

  // Deliberately out of chronological order, with two timestamps falling between stored values.
  auto result = HistoryEngine::read_at_time(store, at_time_item({at(25), at(0), at(15), at(30)}));
  ASSERT_TRUE(result.is_good()) << "the at-time read failed, status = " << result.status_code().as_uint32();
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 4u) << "one value per requested timestamp was expected";

  // Request order, not chronological order: a sorted reply would read 0, 15, 25, 30.
  EXPECT_EQ(ticks(values[0]), at(25).value().time_since_epoch().count()) << "position 0 is not t = 25";
  EXPECT_EQ(ticks(values[1]), at(0).value().time_since_epoch().count()) << "position 1 is not t = 0";
  EXPECT_EQ(ticks(values[2]), at(15).value().time_since_epoch().count()) << "position 2 is not t = 15";
  EXPECT_EQ(ticks(values[3]), at(30).value().time_since_epoch().count()) << "position 3 is not t = 30";

  // The two derived values are the midpoints of the pairs bounding them.
  const double* interpolated25 = values[0].value().try_as<double>();
  const double* interpolated15 = values[2].value().try_as<double>();
  ASSERT_NE(interpolated25, nullptr) << "the value at t = 25 carries nothing";
  ASSERT_NE(interpolated15, nullptr) << "the value at t = 15 carries nothing";
  EXPECT_DOUBLE_EQ(*interpolated25, 25.0);
  EXPECT_DOUBLE_EQ(*interpolated15, 15.0);

  // ... and they say so, while the two exact hits say the opposite.
  EXPECT_EQ(historian_bits(values[0]), historianBitsInterpolated)
    << "the value derived for t = 25 is not marked Interpolated; its InfoBits are 0x" << std::hex
    << historian_bits(values[0]);
  EXPECT_EQ(historian_bits(values[2]), historianBitsInterpolated)
    << "the value derived for t = 15 is not marked Interpolated; its InfoBits are 0x" << std::hex
    << historian_bits(values[2]);
  EXPECT_TRUE(values[0].status().value_or(StatusCode{}).info_type_data_value())
    << "the Interpolated bits for t = 25 are meaningless unless InfoType selects DataValue";
  EXPECT_TRUE(values[2].status().value_or(StatusCode{}).info_type_data_value())
    << "the Interpolated bits for t = 15 are meaningless unless InfoType selects DataValue";
  EXPECT_EQ(historian_bits(values[1]), historianBitsRaw)
    << "the stored value at t = 0 was reported as something other than Raw";
  EXPECT_EQ(historian_bits(values[3]), historianBitsRaw)
    << "the stored value at t = 30 was reported as something other than Raw";

  auto held = HistoryEngine::read_at_time(store, at_time_item({at(25)}, /*simpleBounds=*/true));
  ASSERT_TRUE(held.is_good());
  ASSERT_EQ(held.value().values.size(), 1u);
  EXPECT_EQ(historian_bits(held.value().values[0]), historianBitsInterpolated)
    << "a simple-bounds held value is derived too and must be marked Interpolated";
  EXPECT_TRUE(held.value().values[0].status().value_or(StatusCode{}).info_type_data_value());
}

// OPC 10000-11 section 6.5.3 (ModificationInfo): ModificationTime and UserName record who changed an
// entry and when. Neither is always known - an entry corrected before the historian tracked users, or
// imported from an archive that carried no such column, has no answer to give - and a null is the only
// honest one. Substituting a default is worse than saying nothing: an epoch ModificationTime reads as a
// known time and places the change in 1601, and an empty UserName reads as a user whose name is blank,
// so an auditor cannot tell an unrecorded fact from a recorded one. The paired record with both fields
// populated is the control: it proves the read carries ModificationInfo at all, so the nulls above are
// the record's own content and not a read that lost the whole structure.
// @verifies AC-SVR-HIST-READ-013-MODIFICATIONINFO-NULLS
TEST(HistoryEngineReadModified, AnUnknownModificationTimeAndUserComeBackNullRatherThanDefaulted)
{
  SqliteHistoryStore store{":memory:", make_codec()};

  // t = 10: a modification that predates user tracking - the update type is all that is known.
  ua::ModificationInfo unknown;
  unknown.update_type() = ua::HistoryUpdateType::Replace;
  ASSERT_TRUE(unknown.modification_time().is_null());
  ASSERT_TRUE(unknown.user_name().is_null());
  store.insert_modification(testNode, sample(10, 1.0), unknown).value();

  // t = 20: the control - both fields known.
  ua::ModificationInfo known;
  known.update_type() = ua::HistoryUpdateType::Replace;
  known.user_name() = ua::String{"tester"};
  known.modification_time() = at(21);
  store.insert_modification(testNode, sample(20, 2.0), known).value();

  auto item = raw_item(at(0), at(60));
  item.isReadModified = true;
  auto result = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(result.is_good()) << "the modified read failed, status = " << result.status_code().as_uint32();
  ASSERT_EQ(result.value().modificationInfos.size(), 2u)
    << "the two modification records did not both come back";

  const auto& first = result.value().modificationInfos[0];
  const auto& second = result.value().modificationInfos[1];

  EXPECT_TRUE(first.modification_time().is_null())
    << "an unknown ModificationTime came back as a value, placing the change at a time nobody asserted";
  EXPECT_TRUE(first.user_name().is_null())
    << "an unknown UserName came back as a string, naming a user nobody recorded";

  // The control record proves the read did not simply drop every optional field it was given.
  EXPECT_FALSE(second.modification_time().is_null()) << "the known ModificationTime was lost on read";
  EXPECT_EQ(
    second.modification_time().value().time_since_epoch().count(), at(21).value().time_since_epoch().count());
  EXPECT_EQ(second.user_name(), ua::String{"tester"}) << "the known UserName was lost on read";
}

// OPC 10000-11 section 6.8.2.4 (Update data functionality): "If the Server can determine whether the
// new entry replaces an entry that was already there, then it should use Good_EntryInserted or
// Good_EntryReplaced to return that information." Both are Good-severity, so a Client checking severity
// alone cannot tell an entry it corrected from one it created - and a bulk correction that silently
// added rows looks identical to one that fixed them.
//
// The criterion also names Good_DataIgnored as a third outcome of a data update. Part 11 defines that
// code only for the Event paths (sections 6.8.4.2 and 6.8.4.3, for selectClause fields the historian
// cannot save); the UpdateDataDetails clause has no notion of a value the Server declines to store, and
// this historian stores every well-formed value it is given. There is therefore no stimulus for it
// here, and asserting it would fail a conforming Server, so the test is written to the specification:
// the two outcomes the clause defines, asserted to be distinct from each other and from plain Good.
TEST(HistoryEngineUpdateData, AnUpdateSaysWhichEntryItReplacedAndWhichItCreated)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(testNode, sample(10, 1.0)).value();  // t = 10 occupied, t = 20 empty

  auto result = HistoryEngine::update_data(
    store, update_item(ua::PerformUpdateType::Update, {sample(10, 2.0), sample(20, 3.0)}));
  ASSERT_TRUE(result.is_good()) << "the update failed as a whole, status = "
                                << result.status_code().as_uint32();
  ASSERT_EQ(result.value().operationResults.size(), 2u) << "one status per submitted value was expected";

  // Both writes really happened, so the codes below describe work that was done.
  auto replacedValue = store.read_value_at(testNode, at(10)).value();
  auto insertedValue = store.read_value_at(testNode, at(20)).value();
  ASSERT_TRUE(replacedValue.has_value()) << "the value at the occupied timestamp is gone";
  ASSERT_TRUE(insertedValue.has_value()) << "the value at the empty timestamp was not created";
  ASSERT_NE(replacedValue->value().try_as<double>(), nullptr);
  ASSERT_NE(insertedValue->value().try_as<double>(), nullptr);
  EXPECT_DOUBLE_EQ(*replacedValue->value().try_as<double>(), 2.0);
  EXPECT_DOUBLE_EQ(*insertedValue->value().try_as<double>(), 3.0);

  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}))
    << "an update over an occupied timestamp did not report Good_EntryReplaced";
  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::GoodEntryInserted}))
    << "an update over an empty timestamp did not report Good_EntryInserted";
  EXPECT_NE(code(result.value().operationResults[0]), code(result.value().operationResults[1]))
    << "the replace and the insert report the same code, so the two outcomes are indistinguishable";
  EXPECT_NE(code(result.value().operationResults[0]), code(StatusCode{ua::Status::Good}))
    << "the replace collapsed to plain Good, which this Server may use only when it cannot tell";
  EXPECT_NE(code(result.value().operationResults[1]), code(StatusCode{ua::Status::Good}))
    << "the insert collapsed to plain Good, which this Server may use only when it cannot tell";
}

namespace
{

// The SourceTimestamps a real raw HistoryRead now finds on `nodeId`, in time order.
std::vector<int64_t> stored_value_times(HistoryAuditHarness& harness, const ua::NodeId& nodeId)
{
  std::vector<int64_t> times;
  auto result = run_history_read(harness, bounded_raw_read_request(nodeId, at(-600), at(600), 0));
  auto* response = history_read_response(result.response);
  if (response == nullptr || response->results().size() != 1u)
  {
    ADD_FAILURE() << "the raw read that checks what survived a delete did not answer";
    return times;
  }
  auto* data = dynamic_cast<ua::HistoryData*>(response->results()[0].history_data().get());
  if (data == nullptr)
    return times;
  for (size_t i = 0; i < data->data_values().size(); ++i)
    times.push_back(ticks(data->data_values()[i]));
  return times;
}

// One HistoryUpdate request carrying a single DeleteRawModifiedDetails.
ua::HistoryUpdateRequest single_delete_request(
  std::unique_ptr<ua::DeleteRawModifiedDetails> details, uint32_t requestHandle)
{
  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = requestHandle;
  request.request_header().return_diagnostics() = 0xFFFF;
  request.history_update_details().resize(1);
  request.history_update_details()[0] = std::move(details);
  return request;
}

}  // namespace

// OPC 10000-11 section 6.8.5 (DeleteRawModifiedDetails): "Both startTime and endTime shall be defined.
// The startTime shall be less than the endTime, and values up to but not including the endTime are
// deleted." The half-open boundary is the same convention the aggregate intervals use, and here it
// destroys data when it is wrong: an inclusive endTime removes one value more than the caller asked
// for, and the evidence of the mistake is exactly what was removed. The two malformed ranges fail the
// same way - a delete written as "erase whatever the query matches" treats a missing endTime as
// unbounded and a reversed pair as an empty match, so the Client is told Good while the historian has
// either lost everything after startTime or done nothing at all.
// @verifies AC-SVR-HIST-UPD-017-DELETE-RANGE
TEST(HistoryUpdateDeleteRange, DeleteRawModifiedNeedsAnOrderedRangeAndSpecificallyExcludesTheEndTime)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = harness.historised_variable(1130);
  seed_values(harness, node, 4);  // t = 0,10,20,30

  ASSERT_EQ(stored_value_times(harness, node).size(), 4u) << "the four seeded values are not all there";

  // (1) Only a startTime: the range is not defined, so the request is refused - and nothing is deleted.
  {
    auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
    details->node_id() = node;
    details->is_delete_modified() = false;
    details->start_time() = at(10);  // endTime deliberately left null
    auto result = harness.run(single_delete_request(std::move(details), 2));
    EXPECT_EQ(update_outcome(result), StatusCode{ua::Status::BadInvalidArgument})
      << "a DeleteRawModified carrying only a startTime was accepted with status "
      << code(update_outcome(result));
    EXPECT_EQ(stored_value_times(harness, node).size(), 4u)
      << "a delete over a range the Client never closed removed values anyway";
  }

  // (2) startTime after endTime: an inverted range is malformed, not an empty one.
  {
    auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
    details->node_id() = node;
    details->is_delete_modified() = false;
    details->start_time() = at(30);
    details->end_time() = at(10);
    auto result = harness.run(single_delete_request(std::move(details), 3));
    EXPECT_EQ(update_outcome(result), StatusCode{ua::Status::BadInvalidArgument})
      << "a DeleteRawModified whose startTime follows its endTime was accepted with status "
      << code(update_outcome(result));
    EXPECT_EQ(stored_value_times(harness, node).size(), 4u)
      << "a delete over an inverted range removed values anyway";
  }

  // (3) A well-formed [10, 30) with a value stored exactly at endTime: 10 and 20 go, 30 stays.
  {
    auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
    details->node_id() = node;
    details->is_delete_modified() = false;
    details->start_time() = at(10);
    details->end_time() = at(30);
    auto result = harness.run(single_delete_request(std::move(details), 4));
    EXPECT_TRUE(update_outcome(result).is_good())
      << "a well-formed DeleteRawModified was refused with status " << code(update_outcome(result));

    const std::vector<int64_t> survivors = stored_value_times(harness, node);
    EXPECT_NE(std::find(survivors.begin(), survivors.end(), at(30).value().time_since_epoch().count()),
      survivors.end())
      << "the value stored exactly at endTime was deleted; deletion runs up to but not including it";
    EXPECT_EQ(std::find(survivors.begin(), survivors.end(), at(10).value().time_since_epoch().count()),
      survivors.end())
      << "the value at startTime survived, so the range was not deleted at all";
    EXPECT_EQ(std::find(survivors.begin(), survivors.end(), at(20).value().time_since_epoch().count()),
      survivors.end())
      << "the value inside the range survived, so the range was not deleted at all";
    EXPECT_EQ(survivors.size(), 2u)
      << "after deleting [10, 30) of {0,10,20,30} exactly the values at 0 and 30 must remain; "
      << survivors.size() << " did";
  }

  // (4) Equal non-null bounds are the explicit point-delete exception: only t=10 is removed.
  {
    const auto pointNode = harness.historised_variable(1131);
    seed_values(harness, pointNode, 3);  // t = 0,10,20
    auto details = std::make_unique<ua::DeleteRawModifiedDetails>();
    details->node_id() = pointNode;
    details->is_delete_modified() = false;
    details->start_time() = at(10);
    details->end_time() = at(10);
    auto result = harness.run(single_delete_request(std::move(details), 5));
    ASSERT_TRUE(update_outcome(result).is_good())
      << "equal non-null bounds are a point delete, not an invalid range";

    const std::vector<int64_t> survivors = stored_value_times(harness, pointNode);
    EXPECT_EQ(survivors.size(), 2u);
    EXPECT_NE(std::find(survivors.begin(), survivors.end(), at(0).value().time_since_epoch().count()),
      survivors.end());
    EXPECT_EQ(std::find(survivors.begin(), survivors.end(), at(10).value().time_since_epoch().count()),
      survivors.end());
    EXPECT_NE(std::find(survivors.begin(), survivors.end(), at(20).value().time_since_epoch().count()),
      survivors.end());
  }
}

// OPC 10000-11 section 6.4.2, Table 29 (ReadEventDetails, filter): "This parameter shall be specified
// and at least one EventField is required." Without a selected field there is nothing for the read to
// return, so the request cannot be answered - and the failure is quiet, because the natural
// implementation projects each stored Event onto the (empty) list of select clauses and hands back a
// row of no fields per Event. The Client then receives a Good result carrying the right number of
// empty Events and concludes the historian holds nothing about them. The whereClause-only arm is
// separate from the no-filter arm because a validator that tests "is a filter present?" accepts it.
// @verifies AC-SVR-HIST-READ-005-EVENT-FILTER-REQUIRED
TEST(HistoryReadEventFilter, AnEventHistoryReadWithNoFilterAndOneSelectingNoFieldsAreBothRefused)
{
  HistoryAuditHarness harness;
  harness.setup();
  const auto node = event_history_object(harness, 1140);

  {
    ua::HistoryUpdateRequest seedRequest;
    seedRequest.request_header().request_handle() = 1;
    seedRequest.history_update_details().resize(2);
    seedRequest.history_update_details()[0] =
      event_details(node, ua::PerformUpdateType::Insert, event_record({{1}}, 10, 100.0));
    seedRequest.history_update_details()[1] =
      event_details(node, ua::PerformUpdateType::Insert, event_record({{2}}, 20, 200.0));
    auto seedResult = harness.run(std::move(seedRequest));
    auto* seedResponse = update_response(seedResult);
    ASSERT_NE(seedResponse, nullptr);
    ASSERT_EQ(seedResponse->results().size(), 2u);
    for (size_t i = 0; i < 2u; ++i)
      ASSERT_TRUE(seedResponse->results()[i].status_code().is_good()) << "seed Event " << i << " refused";
  }

  // A request identical in every respect except its filter, so the refusals below are about the filter.
  auto requestWith = [&node](ua::EventFilter filter)
  {
    ua::HistoryReadRequest request;
    request.request_header().request_handle() = 1;
    request.timestamps_to_return() = ua::TimestampsToReturn::Source;
    auto details = std::make_unique<ua::ReadEventDetails>();
    details->start_time() = at(0);
    details->end_time() = at(60);
    details->num_values_per_node() = 100;
    details->filter() = std::move(filter);
    request.history_read_details() = std::move(details);
    request.nodes_to_read().resize(1);
    request.nodes_to_read()[0].node_id() = node;
    return request;
  };

  // Control: one selected field is enough, and the two stored Events come back.
  {
    auto result = run_history_read(harness, requestWith(filter_selecting({"Severity"})));
    auto* response = history_read_response(result.response);
    ASSERT_NE(response, nullptr) << "the control Event history read produced no response";
    ASSERT_EQ(response->results().size(), 1u);
    ASSERT_TRUE(response->results()[0].status_code().is_good())
      << "an Event history read selecting one field was refused, status = "
      << code(response->results()[0].status_code());
    auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(events, nullptr);
    ASSERT_EQ(events->events().size(), 2u) << "the control read did not find the two seeded Events";
  }

  // (1) No filter supplied at all: the details' EventFilter is left at its default.
  {
    auto result = run_history_read(harness, requestWith(ua::EventFilter{}));
    auto* response = history_read_response(result.response);
    const bool refusedAtService =
      history_read_service_result_is(result.response, StatusCode{ua::Status::BadHistoryOperationInvalid});
    const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                    response->results()[0].status_code().is_bad();
    EXPECT_TRUE(refusedAtService || refusedAtOperation)
      << "an Event history read carrying no filter was served; operation status = "
      << (response != nullptr && response->results().size() == 1u ? code(response->results()[0].status_code())
                                                                  : 0u);
    if (response != nullptr && response->results().size() == 1u)
    {
      auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
      EXPECT_TRUE(events == nullptr || events->events().empty())
        << "a filterless read returned " << (events == nullptr ? size_t{0} : events->events().size())
        << " Events, each of which can carry no field the Client asked for";
    }
  }

  // (2) A filter that is present and selects nothing: it restricts which Events match but names no
  //     field to return, which is the case a presence check admits.
  {
    ua::EventFilter selectsNothing;
    ua::ContentFilterElement element;
    element.filter_operator() = ua::FilterOperator::OfType;
    ua::LiteralOperand operand;
    operand.value() = Variant{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
    ua::RefStructure<ua::Structure> operandRef;
    operandRef = std::unique_ptr<ua::Structure>(std::make_unique<ua::LiteralOperand>(std::move(operand)));
    element.filter_operands().push_back(std::move(operandRef));
    selectsNothing.where_clause().elements().push_back(std::move(element));
    ASSERT_TRUE(selectsNothing.select_clauses().empty());

    auto result = run_history_read(harness, requestWith(std::move(selectsNothing)));
    auto* response = history_read_response(result.response);
    const bool refusedAtService =
      history_read_service_result_is(result.response, StatusCode{ua::Status::BadHistoryOperationInvalid});
    const bool refusedAtOperation = response != nullptr && response->results().size() == 1u &&
                                    response->results()[0].status_code().is_bad();
    EXPECT_TRUE(refusedAtService || refusedAtOperation)
      << "an Event history read whose filter selects no field was served; operation status = "
      << (response != nullptr && response->results().size() == 1u ? code(response->results()[0].status_code())
                                                                  : 0u);
    if (response != nullptr && response->results().size() == 1u)
    {
      auto* events = dynamic_cast<ua::HistoryEvent*>(response->results()[0].history_data().get());
      EXPECT_TRUE(events == nullptr || events->events().empty())
        << "a read selecting no field returned " << (events == nullptr ? size_t{0} : events->events().size())
        << " Events with nothing in them";
    }
  }
}

namespace
{

// A HistoryStore whose archive covers a bounded stretch of time, which is what Part 11 means by "the
// range that can be stored": a historian keeps a finite window (a retention horizon, a partitioned
// archive, a fixed-width time column), and a write outside it cannot be accepted. Every other
// operation is the real SqliteHistoryStore, so nothing about the engine's semantics is stubbed - only
// the storable range, which the reference store does not otherwise model, is expressed through the
// documented interface.
class StorableRangeStore final : public ua::history::HistoryStore
{
public:
  StorableRangeStore(DateTime earliest, DateTime latest)
    : mEarliest(earliest), mLatest(latest), mInner(":memory:", make_codec())
  {}

  bool storable(DateTime when) const
  {
    return !(when < mEarliest) && !(mLatest < when);
  }

  ua::Result<std::vector<DataValue>> read_values(const NodeId& node, std::optional<DateTime> lower,
    bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive, uint32_t limit,
    ua::history::Direction order) override
  {
    return mInner.read_values(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<std::optional<DataValue>> read_nearest_value(
    const NodeId& node, DateTime reference, ua::history::Direction direction, bool inclusive) override
  {
    return mInner.read_nearest_value(node, reference, direction, inclusive);
  }

  ua::Result<std::optional<DataValue>> read_value_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.read_value_at(node, timestamp);
  }

  ua::VoidResult insert_value(const NodeId& node, const DataValue& value) override
  {
    const DateTime when = value.source_timestamp().value_or(DateTime{});
    if (!storable(when))
      return ua::VoidResult{StatusCode{ua::Status::BadOutOfRange}};
    return mInner.insert_value(node, value);
  }

  ua::VoidResult delete_value_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.delete_value_at(node, timestamp);
  }

  ua::Result<std::size_t> delete_values(const NodeId& node, DateTime start, DateTime end) override
  {
    return mInner.delete_values(node, start, end);
  }

  ua::VoidResult insert_modification(
    const NodeId& node, const DataValue& value, const ua::ModificationInfo& info) override
  {
    return mInner.insert_modification(node, value, info);
  }

  ua::Result<std::vector<ua::history::ModifiedValue>> read_modifications(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    return mInner.read_modifications(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<bool> has_modification_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.has_modification_at(node, timestamp);
  }

  ua::VoidResult insert_event(const NodeId& node, const ua::history::StoredEvent& event) override
  {
    return mInner.insert_event(node, event);
  }

  ua::Result<std::vector<ua::history::StoredEvent>> read_events(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    return mInner.read_events(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<std::optional<ua::history::StoredEvent>> read_event(
    const NodeId& node, const ua::ByteString& eventId) override
  {
    return mInner.read_event(node, eventId);
  }

  ua::Result<bool> delete_event(const NodeId& node, const ua::ByteString& eventId) override
  {
    return mInner.delete_event(node, eventId);
  }

  ua::VoidResult insert_annotation(const NodeId& node, const DataValue& annotation) override
  {
    return mInner.insert_annotation(node, annotation);
  }

  ua::Result<std::optional<DataValue>> read_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.read_annotation_at(node, timestamp);
  }

  ua::VoidResult delete_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.delete_annotation_at(node, timestamp);
  }

private:
  DateTime mEarliest;
  DateTime mLatest;
  SqliteHistoryStore mInner;
};

}  // namespace

// OPC 10000-11 section 6.8.2.2 (Insert data functionality): "If the Time does not fall within range
// that can be stored then the related operationResults entry shall indicate Bad_OutOfRange." The
// obligation is per entry, and that is the whole of it: a bulk upload spanning the edge of the archive
// stores what it can and reports what it cannot, entry by entry. The plausible implementation lets the
// storage layer's refusal propagate as it stands - one write fails, the operation fails - and the
// Client is then told nothing about which value was the problem, while the values either side of it,
// which the historian would have accepted, are lost with it.
// @verifies AC-SVR-HIST-UPD-002-INSERT-OUTOFRANGE
TEST(HistoryEngineUpdateData, AnInsertOutsideTheStorableRangeFailsThatEntryAloneWithBadOutOfRange)
{
  StorableRangeStore store{at(0), at(100)};
  ASSERT_TRUE(store.storable(at(10)));
  ASSERT_TRUE(store.storable(at(20)));
  ASSERT_FALSE(store.storable(at(1000))) << "the stimulus needs a timestamp the archive cannot hold";

  // One request, three entries: the middle one falls beyond the end of the archive.
  auto result = HistoryEngine::update_data(
    store, update_item(ua::PerformUpdateType::Insert, {sample(10, 1.0), sample(1000, 2.0), sample(20, 3.0)}));
  ASSERT_TRUE(result.is_good()) << "one unstorable value failed the whole operation (status "
                                << result.status_code().as_uint32()
                                << "), so the entries either side of it were never attempted";
  ASSERT_EQ(result.value().operationResults.size(), 3u) << "one status per submitted value was expected";

  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::BadOutOfRange}))
    << "an insert at a Time the historian cannot store was not reported as Bad_OutOfRange";
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryInserted}))
    << "the storable entry before the out-of-range one was not applied";
  EXPECT_EQ(code(result.value().operationResults[2]), code(StatusCode{ua::Status::GoodEntryInserted}))
    << "the storable entry after the out-of-range one was not applied";

  EXPECT_TRUE(store.read_value_at(testNode, at(10)).value().has_value())
    << "the first storable value is not in the archive";
  EXPECT_TRUE(store.read_value_at(testNode, at(20)).value().has_value())
    << "the second storable value is not in the archive";
  EXPECT_FALSE(store.read_value_at(testNode, at(1000)).value().has_value())
    << "the out-of-range value was stored despite being refused";
}

// OPC 10000-11 section 6.8.2.4 (Update data functionality) repeats the sentence verbatim: "If the Time
// does not fall within range that can be stored then the related operationResults entry shall indicate
// Bad_OutOfRange." It is authored separately from the insert rule because UPDATE reaches the archive by
// a different branch - it may insert or replace - and a range check written into the insert branch
// alone leaves the upsert path unguarded, which is where a backfill correction lands.
// @verifies AC-SVR-HIST-UPD-004-UPDATE-OUTOFRANGE
TEST(HistoryEngineUpdateData, AnUpdateOutsideTheStorableRangeReportsBadOutOfRangeForThatEntry)
{
  StorableRangeStore store{at(0), at(100)};
  ASSERT_FALSE(store.storable(at(-1000))) << "the stimulus needs a timestamp the archive cannot hold";
  store.insert_value(testNode, sample(10, 1.0)).value();  // an entry UPDATE will replace

  // UPDATE over an occupied in-range timestamp, an unstorable one, and an empty in-range one.
  auto result = HistoryEngine::update_data(store,
    update_item(ua::PerformUpdateType::Update, {sample(10, 2.0), sample(-1000, 3.0), sample(20, 4.0)}));
  ASSERT_TRUE(result.is_good()) << "one unstorable value failed the whole update (status "
                                << result.status_code().as_uint32() << ")";
  ASSERT_EQ(result.value().operationResults.size(), 3u) << "one status per submitted value was expected";

  EXPECT_EQ(code(result.value().operationResults[1]), code(StatusCode{ua::Status::BadOutOfRange}))
    << "an update at a Time the historian cannot store was not reported as Bad_OutOfRange";
  EXPECT_EQ(code(result.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}))
    << "the in-range replacement was not applied";
  EXPECT_EQ(code(result.value().operationResults[2]), code(StatusCode{ua::Status::GoodEntryInserted}))
    << "the in-range insertion was not applied";

  EXPECT_FALSE(store.read_value_at(testNode, at(-1000)).value().has_value())
    << "the out-of-range value was stored despite being refused";
}

// SVC-17: the engine reports where each archived event came from, from the SourceNode/EventType fields
// it recorded, so the server can authorize archived events as it authorizes live ones; the origins
// stay aligned with the events across a continuation cursor, and an event recorded without them
// reports a null origin.
// @verifies AC-SVR-AUTHZ-016-ARCHIVED-EVENTS-ARE-FILTERED-BY-RECEIVEEVENTS
TEST(HistoryEngineReadEvents, ReportsEachEventsOriginAlignedAcrossTheCursor)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  const NodeId sourceA{uint16_t{2}, 7001};
  const NodeId sourceB{uint16_t{2}, 7002};
  const NodeId typeA{uint16_t{0}, 2041};
  auto first = make_event(10, {1}, 100.0);
  first.fields["SourceNode"] = Variant{sourceA};
  first.fields["EventType"] = Variant{typeA};
  auto second = make_event(20, {2}, 200.0);
  second.fields["SourceNode"] = Variant{sourceB};
  second.fields["EventType"] = Variant{typeA};
  auto third = make_event(30, {3}, 300.0);  // recorded without an origin
  store.insert_event(testNode, first).value();
  store.insert_event(testNode, second).value();
  store.insert_event(testNode, third).value();

  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  auto page1 = HistoryEngine::read_events(store, item);
  ASSERT_TRUE(page1.is_good());
  ASSERT_EQ(page1.value().events.size(), 2u);
  ASSERT_EQ(page1.value().origins.size(), 2u);
  EXPECT_EQ(page1.value().origins[0].sourceNode, sourceA);
  EXPECT_EQ(page1.value().origins[0].eventType, typeA);
  EXPECT_EQ(page1.value().origins[1].sourceNode, sourceB);
  ASSERT_TRUE(page1.value().cursor.has_value());

  auto resume = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  resume.cursor = page1.value().cursor;
  auto page2 = HistoryEngine::read_events(store, resume);
  ASSERT_TRUE(page2.is_good());
  ASSERT_EQ(page2.value().events.size(), 1u);
  ASSERT_EQ(page2.value().origins.size(), 1u) << "the cursor carries the origins with the events";
  EXPECT_TRUE(page2.value().origins[0].sourceNode.is_null()) << "no SourceNode recorded: null origin";
  EXPECT_TRUE(page2.value().origins[0].eventType.is_null());
  EXPECT_DOUBLE_EQ(*page2.value().events[0].event_fields()[0].try_as<double>(), 300.0);
}

namespace
{

// A HistoryStore that answers with a code together with its data, the way a historian qualifies what it
// holds: Good_LocalOverride for a value an operator overrode, Uncertain_DataSubNormal for one derived
// from too few samples. `readCode` is answered by the reads (read_values, read_value_at, read_events,
// read_event, read_annotation_at), with their data unless `readKeepsData` is false, and `writeCode` by the
// writes, each only where the SqliteHistoryStore underneath answers Good. The data, and every other call, are
// the real store's.
class ScriptedCodeStore final : public ua::history::HistoryStore
{
public:
  std::optional<StatusCode> readCode;  // answered by the reads
  bool readKeepsData{true};  // whether a read answered readCode holds its data
  std::optional<StatusCode> writeCode;  // answered by a write the store accepts

  ua::Result<std::vector<DataValue>> read_values(const NodeId& node, std::optional<DateTime> lower,
    bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive, uint32_t limit,
    ua::history::Direction order) override
  {
    return read(mInner.read_values(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
  }

  ua::Result<std::optional<DataValue>> read_nearest_value(
    const NodeId& node, DateTime reference, ua::history::Direction direction, bool inclusive) override
  {
    return mInner.read_nearest_value(node, reference, direction, inclusive);
  }

  ua::Result<std::optional<DataValue>> read_value_at(const NodeId& node, DateTime timestamp) override
  {
    return read(mInner.read_value_at(node, timestamp));
  }

  ua::VoidResult insert_value(const NodeId& node, const DataValue& value) override
  {
    return write(mInner.insert_value(node, value));
  }

  ua::VoidResult delete_value_at(const NodeId& node, DateTime timestamp) override
  {
    return write(mInner.delete_value_at(node, timestamp));
  }

  ua::Result<std::size_t> delete_values(const NodeId& node, DateTime start, DateTime end) override
  {
    return mInner.delete_values(node, start, end);
  }

  ua::VoidResult insert_modification(
    const NodeId& node, const DataValue& value, const ua::ModificationInfo& info) override
  {
    return write(mInner.insert_modification(node, value, info));
  }

  ua::Result<std::vector<ua::history::ModifiedValue>> read_modifications(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    return mInner.read_modifications(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<bool> has_modification_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.has_modification_at(node, timestamp);
  }

  ua::VoidResult insert_event(const NodeId& node, const ua::history::StoredEvent& event) override
  {
    return write(mInner.insert_event(node, event));
  }

  ua::Result<std::vector<ua::history::StoredEvent>> read_events(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    return read(mInner.read_events(node, lower, lowerInclusive, upper, upperInclusive, limit, order));
  }

  ua::Result<std::optional<ua::history::StoredEvent>> read_event(
    const NodeId& node, const ua::ByteString& eventId) override
  {
    return read(mInner.read_event(node, eventId));
  }

  ua::Result<bool> delete_event(const NodeId& node, const ua::ByteString& eventId) override
  {
    return mInner.delete_event(node, eventId);
  }

  ua::VoidResult insert_annotation(const NodeId& node, const DataValue& annotation) override
  {
    return write(mInner.insert_annotation(node, annotation));
  }

  ua::Result<std::optional<DataValue>> read_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return read(mInner.read_annotation_at(node, timestamp));
  }

  ua::VoidResult delete_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return write(mInner.delete_annotation_at(node, timestamp));
  }

private:
  template<class T>
  ua::Result<T> read(ua::Result<T> answer) const
  {
    if (!readCode || !answer.is_good())
      return answer;
    if (!readKeepsData)
      return ua::Result<T>{*readCode};
    return ua::Result<T>{std::move(answer).value(), *readCode};
  }

  ua::VoidResult write(ua::VoidResult answer) const
  {
    if (!writeCode || !answer.is_good())
      return answer;
    return ua::VoidResult{*writeCode};
  }

  SqliteHistoryStore mInner{":memory:", make_codec()};
};

// Samples at t = 0,10,...,(count-1)*10 seconds whose value is the second-offset.
void seed_store(ua::history::HistoryStore& store, int count)
{
  for (int i = 0; i < count; ++i)
    store.insert_value(testNode, sample(i * 10, static_cast<double>(i * 10))).value();
}

// Whether @p status is the engine's refusal of a store read answered Uncertain_DataSubNormal:
// Bad_InternalError with the ErrorDetail ReadAnswerUncertain whose cause is the store's code.
::testing::AssertionResult is_store_read_refusal(const StatusCode& status)
{
  if (status.as_status() != ua::Status::BadInternalError)
    return ::testing::AssertionFailure() << "answered " << ua::to_string(status);
  const auto& detail = status.shared_detail();
  if (!detail)
    return ::testing::AssertionFailure() << "Bad_InternalError without an ErrorDetail";
  if (detail->code != "ReadAnswerUncertain")
    return ::testing::AssertionFailure() << "ErrorDetail " << detail->code;
  if (detail->innerStatus != StatusCode{ua::Status::UncertainDataSubNormal}.value())
    return ::testing::AssertionFailure() << "the cause is " << ua::to_string(StatusCode{detail->innerStatus});
  return ::testing::AssertionSuccess();
}

}  // namespace

// A store's Uncertain answer with values is the read's answer: the values with the Uncertain code (OPC
// 10000-4 7.39.1: they "might not be suitable for some purposes"), not the values under a plain Good the
// store did not give, and not the values dropped.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, ARawReadAnsweredUncertainReturnsItsValuesWithTheUncertainCode)
{
  ScriptedCodeStore store;
  seed_store(store, 5);  // t = 0,10,20,30,40
  store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};

  auto item = raw_item(at(10), at(30));  // [10, 30) -> 10, 20
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_uncertain()) << ua::to_string(result.status_code());
  EXPECT_EQ(code(result.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 2u) << "the values the store answered with its Uncertain code were not returned";
  EXPECT_EQ(ticks(values[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(ticks(values[1]), at(20).value().time_since_epoch().count());
}

// A Good subcode the store answers stays on the read's result; the engine does not replace it with a
// plain Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, ARawReadAnsweredWithAGoodSubcodeKeepsTheSubcode)
{
  ScriptedCodeStore store;
  seed_store(store, 5);
  store.readCode = StatusCode{ua::Status::GoodLocalOverride};

  auto item = raw_item(at(10), at(30));
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  EXPECT_EQ(code(result.status_code()), code(StatusCode{ua::Status::GoodLocalOverride}))
    << "the store's Good_LocalOverride was answered as " << ua::to_string(result.status_code());
  EXPECT_EQ(result.value().values.size(), 2u);
}

// An IndexRange selects its elements from the values of an Uncertain answer as from a Good one, and the
// sliced values keep the answer's code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, AnIndexRangeSlicesTheValuesOfAnUncertainAnswer)
{
  ScriptedCodeStore store;
  for (int i = 0; i < 3; ++i)
    store.insert_value(testNode, array_sample(i * 10, 5)).value();
  store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};

  auto item = raw_item(at(0), at(30));
  item.indexRange = ua::String{"1:3"};
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_uncertain()) << ua::to_string(result.status_code());
  EXPECT_EQ(code(result.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 3u);
  for (size_t i = 0; i < values.size(); ++i)
  {
    const double t = static_cast<double>(i * 10);
    EXPECT_EQ(doubles(values[i]), (std::vector<double>{t + 0.1, t + 0.2, t + 0.3}))
      << "value " << i << " of the Uncertain answer was not sliced";
  }
}

// ReadAtTime passes a store's Uncertain answer on with the value it answered.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, AnAtTimeReadAnsweredUncertainReturnsTheValueWithTheUncertainCode)
{
  ScriptedCodeStore store;
  seed_store(store, 5);
  store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};

  auto result = HistoryEngine::read_at_time(store, at_time_item({at(20)}));  // an exact raw value

  ASSERT_TRUE(result.is_uncertain()) << ua::to_string(result.status_code());
  EXPECT_EQ(code(result.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  const auto& values = result.value().values;
  ASSERT_EQ(values.size(), 1u);
  EXPECT_EQ(ticks(values[0]), at(20).value().time_since_epoch().count());
  ASSERT_NE(values[0].value().try_as<double>(), nullptr);
  EXPECT_DOUBLE_EQ(*values[0].value().try_as<double>(), 20.0);
}

// The control: a store that answers plain Good leaves the read plain Good, with no code of the engine's.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, PlainGoodAnswersLeaveTheReadPlainGood)
{
  ScriptedCodeStore store;
  seed_store(store, 5);

  auto item = raw_item(at(10), at(30));
  auto raw = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(raw.is_good());
  EXPECT_EQ(code(raw.status_code()), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(raw.value().values.size(), 2u);

  auto atTime = HistoryEngine::read_at_time(store, at_time_item({at(20), at(25)}));
  ASSERT_TRUE(atTime.is_good());
  EXPECT_EQ(code(atTime.status_code()), code(StatusCode{ua::Status::Good}));
  EXPECT_EQ(atTime.value().values.size(), 2u);
}

// An UpdateData entry the store answers with a Good subcode or an Uncertain code is answered with that
// code; Good_EntryInserted and Good_EntryReplaced are the engine's answer only over a plain Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, AnUpdateDataEntryIsAnsweredWithTheCodeTheStoreAnsweredForIt)
{
  ScriptedCodeStore store;
  store.insert_value(testNode, sample(10, 1.0)).value();  // an entry Update replaces

  store.writeCode = StatusCode{ua::Status::UncertainDataSubNormal};
  auto uncertain = HistoryEngine::update_data(
    store, update_item(ua::PerformUpdateType::Update, {sample(10, 2.0), sample(20, 3.0)}));
  ASSERT_TRUE(uncertain.is_good()) << ua::to_string(uncertain.status_code());
  ASSERT_EQ(uncertain.value().operationResults.size(), 2u);
  EXPECT_EQ(code(uncertain.value().operationResults[0]), code(StatusCode{ua::Status::UncertainDataSubNormal}))
    << "the replaced entry was answered " << ua::to_string(uncertain.value().operationResults[0]);
  EXPECT_EQ(code(uncertain.value().operationResults[1]), code(StatusCode{ua::Status::UncertainDataSubNormal}))
    << "the inserted entry was answered " << ua::to_string(uncertain.value().operationResults[1]);

  store.writeCode = StatusCode{ua::Status::GoodLocalOverride};
  auto overridden =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 4.0)}));
  ASSERT_TRUE(overridden.is_good());
  ASSERT_EQ(overridden.value().operationResults.size(), 1u);
  EXPECT_EQ(code(overridden.value().operationResults[0]), code(StatusCode{ua::Status::GoodLocalOverride}))
    << "the store's Good_LocalOverride was replaced by "
    << ua::to_string(overridden.value().operationResults[0]);

  store.writeCode.reset();
  auto plain =
    HistoryEngine::update_data(store, update_item(ua::PerformUpdateType::Replace, {sample(10, 5.0)}));
  ASSERT_TRUE(plain.is_good());
  ASSERT_EQ(plain.value().operationResults.size(), 1u);
  EXPECT_EQ(code(plain.value().operationResults[0]), code(StatusCode{ua::Status::GoodEntryReplaced}));
}

// An Event insert the store answers Uncertain is that entry's answer, not a failure of the whole
// operation; a DeleteAtTime entry the store answers with a Good subcode keeps the subcode.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, AnEventInsertAndADeleteAtTimeAnswerTheStoresCodeForTheEntry)
{
  ScriptedCodeStore store;
  seed_store(store, 3);  // t = 0,10,20

  store.writeCode = StatusCode{ua::Status::UncertainDataSubNormal};
  auto inserted = HistoryEngine::update_events(
    store, update_events_item(ua::PerformUpdateType::Insert, {event_record({{1}}, 10, 100.0)}));
  ASSERT_TRUE(inserted.is_good()) << "an Uncertain write failed the whole operation: "
                                  << ua::to_string(inserted.status_code());
  ASSERT_EQ(inserted.value().operationResults.size(), 1u);
  EXPECT_EQ(code(inserted.value().operationResults[0]), code(StatusCode{ua::Status::UncertainDataSubNormal}));

  store.writeCode = StatusCode{ua::Status::GoodLocalOverride};
  DeleteAtTimeItem item;
  item.index = 0;
  item.nodeId = testNode;
  item.timestamps = {at(10), at(15)};  // 10 exists, 15 does not
  auto deleted = HistoryEngine::delete_at_time(store, item);
  ASSERT_TRUE(deleted.is_good());
  ASSERT_EQ(deleted.value().operationResults.size(), 2u);
  EXPECT_EQ(code(deleted.value().operationResults[0]), code(StatusCode{ua::Status::GoodLocalOverride}));
  EXPECT_EQ(code(deleted.value().operationResults[1]), code(StatusCode{ua::Status::BadNoEntryExists}));
}

// Every page of an Uncertain answer is answered Uncertain: the values the continuation cursor holds were
// answered with the code as much as the first page's were.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, EveryPageOfAnUncertainRawAnswerIsAnsweredUncertain)
{
  ScriptedCodeStore store;
  seed_store(store, 5);  // t = 0,10,20,30,40
  store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};

  auto item = raw_item(at(0), at(50), /*cap*/ 2);  // 5 values, 2 per page
  auto first = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(first.is_uncertain()) << ua::to_string(first.status_code());
  EXPECT_EQ(code(first.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  ASSERT_EQ(first.value().values.size(), 2u);
  ASSERT_TRUE(first.value().cursor.has_value());

  store.readCode.reset();  // the code the first page was answered with stays on the later pages
  ReadRawItem resume = raw_item(at(0), at(50), 2);
  resume.cursor = first.value().cursor;
  auto second = HistoryEngine::read_raw(store, resume);
  ASSERT_TRUE(second.is_uncertain()) << "the page resumed from the cursor was answered "
                                     << ua::to_string(second.status_code());
  EXPECT_EQ(code(second.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  ASSERT_EQ(second.value().values.size(), 2u);
  EXPECT_EQ(ticks(second.value().values[0]), at(20).value().time_since_epoch().count());
  ASSERT_TRUE(second.value().cursor.has_value());

  ReadRawItem last = raw_item(at(0), at(50), 2);
  last.cursor = second.value().cursor;
  auto third = HistoryEngine::read_raw(store, last);
  ASSERT_TRUE(third.is_uncertain()) << "the last page was answered " << ua::to_string(third.status_code());
  EXPECT_EQ(code(third.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  ASSERT_EQ(third.value().values.size(), 1u);
  EXPECT_FALSE(third.value().cursor.has_value());
}

// The same holds for the pages of an Event read.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-THE-HISTORY-ENGINE-PASSES-ITS-STORES-CODE, scope=function)
TEST(HistoryEngineStoreCodes, EveryPageOfAnUncertainEventAnswerIsAnsweredUncertain)
{
  ScriptedCodeStore store;
  store.insert_event(testNode, make_event(10, {1}, 100.0)).value();
  store.insert_event(testNode, make_event(20, {2}, 200.0)).value();
  store.insert_event(testNode, make_event(30, {3}, 300.0)).value();
  store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};

  auto item = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  auto first = HistoryEngine::read_events(store, item);
  ASSERT_TRUE(first.is_uncertain()) << ua::to_string(first.status_code());
  EXPECT_EQ(code(first.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  ASSERT_EQ(first.value().events.size(), 2u);
  ASSERT_TRUE(first.value().cursor.has_value());

  store.readCode.reset();
  auto resume = events_item(at(0), at(60), filter_selecting({"Severity"}), /*cap*/ 2);
  resume.cursor = first.value().cursor;
  auto second = HistoryEngine::read_events(store, resume);
  ASSERT_TRUE(second.is_uncertain()) << "the page resumed from the cursor was answered "
                                     << ua::to_string(second.status_code());
  EXPECT_EQ(code(second.status_code()), code(StatusCode{ua::Status::UncertainDataSubNormal}));
  ASSERT_EQ(second.value().events.size(), 1u);
  EXPECT_DOUBLE_EQ(*second.value().events[0].event_fields()[0].try_as<double>(), 300.0);
}

// The engine decides whether an UpdateData value, an Event or an Annotation exists from the store's read, so
// an Uncertain answer to that read, with or without data, refuses the entry before anything is written:
// Bad_InternalError (ReadAnswerUncertain) whose cause is the store's code. The store is left as it was.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(HistoryEngineStoreCodes, AnUncertainExistenceReadRefusesTheEntryAndChangesNothing)
{
  for (const bool keepsData : {true, false})
  {
    SCOPED_TRACE(keepsData ? "the Uncertain read holds its data" : "the Uncertain read holds no data");
    ScriptedCodeStore store;
    store.insert_value(testNode, sample(10, 1.0)).value();
    store.insert_event(testNode, make_event(10, {1}, 100.0)).value();
    store.insert_annotation(testNode, make_annotation(10, "kept")).value();
    store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};
    store.readKeepsData = keepsData;

    auto values = HistoryEngine::update_data(
      store, update_item(ua::PerformUpdateType::Update, {sample(10, 2.0), sample(20, 3.0)}));
    ASSERT_TRUE(values.is_good()) << ua::to_string(values.status_code());
    ASSERT_EQ(values.value().operationResults.size(), 2u);
    EXPECT_TRUE(is_store_read_refusal(values.value().operationResults[0])) << "the value that exists";
    EXPECT_TRUE(is_store_read_refusal(values.value().operationResults[1])) << "the value that does not";

    auto events = HistoryEngine::update_events(
      store, update_events_item(ua::PerformUpdateType::Replace, {event_record({{1}}, 10, 200.0)}));
    ASSERT_TRUE(events.is_good()) << ua::to_string(events.status_code());
    ASSERT_EQ(events.value().operationResults.size(), 1u);
    EXPECT_TRUE(is_store_read_refusal(events.value().operationResults[0]));

    auto annotations = HistoryEngine::update_structure_data(
      store, struct_item(ua::PerformUpdateType::Replace, {make_annotation(10, "replaced")}));
    ASSERT_TRUE(annotations.is_good()) << ua::to_string(annotations.status_code());
    ASSERT_EQ(annotations.value().operationResults.size(), 1u);
    EXPECT_TRUE(is_store_read_refusal(annotations.value().operationResults[0]));

    store.readCode.reset();
    const auto value = store.read_value_at(testNode, at(10));
    ASSERT_TRUE(value.is_good() && value.value().has_value());
    EXPECT_DOUBLE_EQ(*value.value()->value().try_as<double>(), 1.0) << "the value was replaced";
    EXPECT_FALSE(store.has_modification_at(testNode, at(10)).value()) << "a modification was recorded";
    EXPECT_FALSE(store.read_value_at(testNode, at(20)).value().has_value()) << "a value was inserted";
    auto read = events_item(at(0), at(60), filter_selecting({"Severity"}));
    const auto stored = HistoryEngine::read_events(store, read);
    ASSERT_TRUE(stored.is_good());
    ASSERT_EQ(stored.value().events.size(), 1u);
    EXPECT_DOUBLE_EQ(*stored.value().events[0].event_fields()[0].try_as<double>(), 100.0)
      << "the Event was replaced";
    const auto annotation = store.read_annotation_at(testNode, at(10));
    ASSERT_TRUE(annotation.is_good() && annotation.value().has_value());
    EXPECT_EQ(annotation_message(*annotation.value()), "kept") << "the Annotation was replaced";
  }
}

// The engine deletes the values its read of the interval or the timestamp answers, so an Uncertain answer to
// that read, with or without data, refuses the delete before anything is deleted: DeleteRaw fails with
// Bad_InternalError (ReadAnswerUncertain) whose cause is the store's code, and a DeleteAtTime timestamp is
// answered with it.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(HistoryEngineStoreCodes, AnUncertainReadOfWhatToDeleteRefusesTheDeleteAndDeletesNothing)
{
  for (const bool keepsData : {true, false})
  {
    SCOPED_TRACE(keepsData ? "the Uncertain read holds its data" : "the Uncertain read holds no data");
    ScriptedCodeStore store;
    seed_store(store, 3);  // t = 0,10,20
    store.readCode = StatusCode{ua::Status::UncertainDataSubNormal};
    store.readKeepsData = keepsData;

    DeleteRawItem range;
    range.index = 0;
    range.nodeId = testNode;
    range.startTime = at(0);
    range.endTime = at(20);
    const auto rangeResult = HistoryEngine::delete_raw(store, range);
    EXPECT_TRUE(is_store_read_refusal(rangeResult.status_code())) << "the interval";

    DeleteRawItem exact = range;
    exact.startTime = at(10);
    exact.endTime = at(10);
    const auto exactResult = HistoryEngine::delete_raw(store, exact);
    EXPECT_TRUE(is_store_read_refusal(exactResult.status_code())) << "the single instant";

    DeleteAtTimeItem atTime;
    atTime.index = 0;
    atTime.nodeId = testNode;
    atTime.timestamps = {at(10)};
    const auto atTimeResult = HistoryEngine::delete_at_time(store, atTime);
    ASSERT_TRUE(atTimeResult.is_good()) << ua::to_string(atTimeResult.status_code());
    ASSERT_EQ(atTimeResult.value().operationResults.size(), 1u);
    EXPECT_TRUE(is_store_read_refusal(atTimeResult.value().operationResults[0])) << "the timestamp";

    store.readCode.reset();
    for (const int seconds : {0, 10, 20})
    {
      EXPECT_TRUE(store.read_value_at(testNode, at(seconds)).value().has_value())
        << "the value at " << seconds << " s was deleted";
      EXPECT_FALSE(store.has_modification_at(testNode, at(seconds)).value())
        << "a Delete modification was recorded at " << seconds << " s";
    }
  }
}

namespace
{

// The real SqliteHistoryStore, recording the limit of every window read the engine asks it for and how
// many ExtraData lookups it makes.
class WindowReadRecordingStore final : public ua::history::HistoryStore
{
public:
  std::vector<uint32_t> windowLimits;
  size_t modificationLookups{0};

  ua::Result<std::vector<DataValue>> read_values(const NodeId& node, std::optional<DateTime> lower,
    bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive, uint32_t limit,
    ua::history::Direction order) override
  {
    windowLimits.push_back(limit);
    return mInner.read_values(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<std::optional<DataValue>> read_nearest_value(
    const NodeId& node, DateTime reference, ua::history::Direction direction, bool inclusive) override
  {
    return mInner.read_nearest_value(node, reference, direction, inclusive);
  }

  ua::Result<std::optional<DataValue>> read_value_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.read_value_at(node, timestamp);
  }

  ua::VoidResult insert_value(const NodeId& node, const DataValue& value) override
  {
    return mInner.insert_value(node, value);
  }

  ua::VoidResult delete_value_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.delete_value_at(node, timestamp);
  }

  ua::Result<std::size_t> delete_values(const NodeId& node, DateTime start, DateTime end) override
  {
    return mInner.delete_values(node, start, end);
  }

  ua::VoidResult insert_modification(
    const NodeId& node, const DataValue& value, const ua::ModificationInfo& info) override
  {
    return mInner.insert_modification(node, value, info);
  }

  ua::Result<std::vector<ua::history::ModifiedValue>> read_modifications(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    windowLimits.push_back(limit);
    return mInner.read_modifications(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<bool> has_modification_at(const NodeId& node, DateTime timestamp) override
  {
    ++modificationLookups;
    return mInner.has_modification_at(node, timestamp);
  }

  ua::VoidResult insert_event(const NodeId& node, const ua::history::StoredEvent& event) override
  {
    return mInner.insert_event(node, event);
  }

  ua::Result<std::vector<ua::history::StoredEvent>> read_events(const NodeId& node,
    std::optional<DateTime> lower, bool lowerInclusive, std::optional<DateTime> upper, bool upperInclusive,
    uint32_t limit, ua::history::Direction order) override
  {
    windowLimits.push_back(limit);
    return mInner.read_events(node, lower, lowerInclusive, upper, upperInclusive, limit, order);
  }

  ua::Result<std::optional<ua::history::StoredEvent>> read_event(
    const NodeId& node, const ua::ByteString& eventId) override
  {
    return mInner.read_event(node, eventId);
  }

  ua::Result<bool> delete_event(const NodeId& node, const ua::ByteString& eventId) override
  {
    return mInner.delete_event(node, eventId);
  }

  ua::VoidResult insert_annotation(const NodeId& node, const DataValue& annotation) override
  {
    return mInner.insert_annotation(node, annotation);
  }

  ua::Result<std::optional<DataValue>> read_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.read_annotation_at(node, timestamp);
  }

  ua::VoidResult delete_annotation_at(const NodeId& node, DateTime timestamp) override
  {
    return mInner.delete_annotation_at(node, timestamp);
  }

private:
  SqliteHistoryStore mInner{":memory:", make_codec()};
};

// Every page of a capped raw read, from the first to the one without a cursor. Each page's store reads are
// checked to have asked for one page (and the row that says whether more follow), never the window.
std::vector<DataValue> read_raw_in_pages(WindowReadRecordingStore& store, ReadRawItem item)
{
  const uint32_t cap = item.maxValuesPerNode;
  std::vector<DataValue> all;
  for (int pages = 0; pages < 1000; ++pages)
  {
    store.windowLimits.clear();
    store.modificationLookups = 0;
    auto page = HistoryEngine::read_raw(store, item);
    EXPECT_TRUE(page.is_good()) << ua::to_string(page.status_code());
    if (!page.has_value())
      break;
    EXPECT_LE(page.value().values.size(), cap);
    for (const uint32_t limit : store.windowLimits)
    {
      EXPECT_NE(limit, 0u) << "a capped page asked the store for the whole window";
      EXPECT_LE(limit, cap + 1) << "a capped page asked the store for more than one page";
    }
    EXPECT_LE(store.modificationLookups, cap)
      << "ExtraData was looked up for values the page does not return";
    all.insert(all.end(), page.value().values.begin(), page.value().values.end());
    if (!page.value().cursor.has_value())
      break;
    item.cursor = page.value().cursor;
  }
  return all;
}

std::vector<int64_t> seconds_of(const std::vector<DataValue>& values)
{
  std::vector<int64_t> seconds;
  for (const auto& value : values)
    seconds.push_back(std::chrono::duration_cast<std::chrono::seconds>(
      value.source_timestamp().value_or(DateTime{}).value() - base.value())
                        .count());
  return seconds;
}

}  // namespace

// A capped raw read pages through the store: each page asks the store for one page and the row after it,
// and looks ExtraData up for the values it returns, so a read of a large archive holds one page in memory
// rather than the whole time window. The pages, joined, are the window with its bounds in time order,
// forward and reverse, with ExtraData on the value that hides a modification.
// @relation(AC-SVR-HIST-READ-006-A-CAPPED-READ-HOLDS-ONE-PAGE, scope=function)
TEST(HistoryEngineReadRaw, ACappedReadAsksTheStoreForOnePageAtATime)
{
  WindowReadRecordingStore store;
  for (int i = 0; i < 200; ++i)
    store.insert_value(testNode, sample(i * 10, static_cast<double>(i))).value();
  ua::ModificationInfo info;
  info.update_type() = ua::HistoryUpdateType::Replace;
  store.insert_modification(testNode, sample(500, -1.0), info).value();

  std::vector<int64_t> ascending;
  for (int i = 0; i < 200; ++i)
    ascending.push_back(i * 10);
  const std::vector<int64_t> descending(ascending.rbegin(), ascending.rend());

  // Forward [5, 1985) with bounds: the bound at 0, the values 10..1980, the bound at 1990.
  const auto forward = read_raw_in_pages(store, raw_item(at(5), at(1985), /*cap*/ 7, /*bounds*/ true));
  EXPECT_EQ(seconds_of(forward), ascending);
  // Reverse (5, 1985] with bounds: the bound at 1990, the values 1980..10, the bound at 0.
  const auto reverse = read_raw_in_pages(store, raw_item(at(1985), at(5), /*cap*/ 7, /*bounds*/ true));
  EXPECT_EQ(seconds_of(reverse), descending);

  for (const auto* values : {&forward, &reverse})
    for (const auto& value : *values)
      EXPECT_EQ(value.status().value_or(StatusCode{}).extra_data(), seconds_of({value}).front() == 500)
        << "ExtraData at " << seconds_of({value}).front() << " s";
}

// Modification records and events can share a time, so a page can end part-way through the rows at one
// time. The next page resumes at that time and returns the rest of its rows, in order, forward and reverse,
// still asking the store for one page (with the rows at that time already returned) at a time.
// @relation(AC-SVR-HIST-READ-006-A-CAPPED-READ-HOLDS-ONE-PAGE, scope=function)
TEST(HistoryEngineReadEvents, PagesThroughEventsThatShareATimeInBothDirections)
{
  WindowReadRecordingStore store;
  // Five events at 10 s, three at 20 s, one at 30 s; the severity numbers them in insertion order.
  std::vector<int> times{10, 10, 10, 10, 10, 20, 20, 20, 30};
  for (size_t i = 0; i < times.size(); ++i)
    store
      .insert_event(testNode, make_event(times[i], {static_cast<uint8_t>(i + 1)}, static_cast<double>(i + 1)))
      .value();
  constexpr uint32_t cap = 2;
  constexpr uint32_t mostAtOneTime = 5;

  const auto read_in_pages = [&](DateTime start, DateTime end)
  {
    std::vector<double> severities;
    auto item = events_item(start, end, filter_selecting({"Severity"}), cap);
    for (int pages = 0; pages < 100; ++pages)
    {
      store.windowLimits.clear();
      auto page = HistoryEngine::read_events(store, item);
      EXPECT_TRUE(page.is_good()) << ua::to_string(page.status_code());
      if (!page.has_value())
        break;
      EXPECT_LE(page.value().events.size(), cap);
      EXPECT_EQ(page.value().origins.size(), page.value().events.size());
      for (const uint32_t limit : store.windowLimits)
      {
        EXPECT_NE(limit, 0u) << "a capped page asked the store for the whole window";
        EXPECT_LE(limit, cap + 1 + mostAtOneTime) << "a capped page asked the store for more than one page";
      }
      for (const auto& event : page.value().events)
        severities.push_back(*event.event_fields()[0].try_as<double>());
      if (!page.value().cursor.has_value())
        break;
      item.cursor = page.value().cursor;
    }
    return severities;
  };

  EXPECT_EQ(read_in_pages(at(0), at(60)), (std::vector<double>{1, 2, 3, 4, 5, 6, 7, 8, 9}));
  EXPECT_EQ(read_in_pages(at(60), at(0)), (std::vector<double>{9, 8, 7, 6, 5, 4, 3, 2, 1}));
}

// The same holds for the modification records of a ReadModified.
// @relation(AC-SVR-HIST-READ-006-A-CAPPED-READ-HOLDS-ONE-PAGE, scope=function)
TEST(HistoryEngineReadModified, PagesThroughRecordsThatShareATimeInBothDirections)
{
  WindowReadRecordingStore store;
  // Four records at 10 s and two at 20 s; the value numbers them in insertion order.
  std::vector<int> times{10, 10, 10, 10, 20, 20};
  ua::ModificationInfo info;
  info.update_type() = ua::HistoryUpdateType::Replace;
  for (size_t i = 0; i < times.size(); ++i)
    store.insert_modification(testNode, sample(times[i], static_cast<double>(i + 1)), info).value();
  constexpr uint32_t cap = 3;
  constexpr uint32_t mostAtOneTime = 4;

  const auto read_in_pages = [&](DateTime start, DateTime end)
  {
    std::vector<double> numbers;
    auto item = raw_item(start, end, cap);
    item.isReadModified = true;
    for (int pages = 0; pages < 100; ++pages)
    {
      store.windowLimits.clear();
      auto page = HistoryEngine::read_raw(store, item);
      EXPECT_TRUE(page.is_good()) << ua::to_string(page.status_code());
      if (!page.has_value())
        break;
      EXPECT_LE(page.value().values.size(), cap);
      EXPECT_EQ(page.value().modificationInfos.size(), page.value().values.size());
      for (const uint32_t limit : store.windowLimits)
      {
        EXPECT_NE(limit, 0u) << "a capped page asked the store for the whole window";
        EXPECT_LE(limit, cap + 1 + mostAtOneTime) << "a capped page asked the store for more than one page";
      }
      for (const auto& value : page.value().values)
        numbers.push_back(*value.value().try_as<double>());
      if (!page.value().cursor.has_value())
        break;
      item.cursor = page.value().cursor;
    }
    return numbers;
  };

  EXPECT_EQ(read_in_pages(at(0), at(60)), (std::vector<double>{1, 2, 3, 4, 5, 6}));
  EXPECT_EQ(read_in_pages(at(60), at(0)), (std::vector<double>{6, 5, 4, 3, 2, 1}));
}

// A continuation point resumes the read of the Node it was issued for: presented with another Node it is
// Bad_ContinuationPointInvalid, and no other Node's history is read through it.
// @relation(AC-SVR-HIST-READ-006-A-CAPPED-READ-HOLDS-ONE-PAGE, scope=function)
TEST(HistoryEngineReadRaw, AContinuationPointPresentedForAnotherNodeIsInvalid)
{
  WindowReadRecordingStore store;
  for (int i = 0; i < 5; ++i)
    store.insert_value(testNode, sample(i * 10, static_cast<double>(i))).value();

  auto item = raw_item(at(0), at(60), /*cap*/ 2);
  auto first = HistoryEngine::read_raw(store, item);
  ASSERT_TRUE(first.is_good());
  ASSERT_TRUE(first.value().cursor.has_value());

  auto other = raw_item(at(0), at(60), 2);
  other.nodeId = NodeId{uint16_t{2}, 1001};
  other.cursor = first.value().cursor;
  store.windowLimits.clear();
  auto resumed = HistoryEngine::read_raw(store, other);
  EXPECT_EQ(
    resumed.status_code().as_uint32(), StatusCode{ua::Status::BadContinuationPointInvalid}.as_uint32());
  EXPECT_TRUE(store.windowLimits.empty())
    << "the store was read through a continuation point for another Node";
}
