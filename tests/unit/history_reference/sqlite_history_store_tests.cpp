// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the SQLite-backed HistoryStore. These target the SQL
// mapping the engine relies on - bound inclusivity (exclusive bounds mapped to +/-1 tick), ordering,
// limits, round-trip via the UA-Binary codec, and modification records - using an in-memory SQLite
// database and a minimal codec. The engine semantics themselves are covered in history_engine_tests.
//
// Every store method returns a ua::Result (the HistoryStore failure contract); these tests unwrap with
// .value(), which asserts success (it throws on an error Result) before inspecting the payload.

#include "ua_history_engine.h"
#include "ua_history_sqlite_store.h"

#include "ua_binary_data_value_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_encoding_limits.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <memory>

using ua::DataValue;
using ua::DateTime;
using ua::NodeId;
using ua::StatusCode;
using ua::Variant;
using ua::history::Direction;
using ua::history::HistoryEngine;
using ua::history::SqliteHistoryStore;

namespace
{

const NodeId node{uint16_t{2}, 5000};
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

// A scalar-only codec: no structured DataTypes are exercised, so the resolver returns nullptr.
std::shared_ptr<const ua::UaBinaryDataValueCodec> make_codec()
{
  return ua::UaBinaryDataValueCodec::create([](const NodeId&) -> std::unique_ptr<ua::Structure>
    { return nullptr; },
    ua::CodecNamespaceContext{},
    ua::EncodingLimits{});
}

int64_t ticks(const DataValue& dv)
{
  return dv.source_timestamp().value_or(DateTime{}).value().time_since_epoch().count();
}

}  // namespace

TEST(SqliteHistoryStore, InsertAndReadValueRoundTripsValue)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(node, sample(10, 42.5)).value();

  auto fetched = store.read_value_at(node, at(10)).value();
  ASSERT_TRUE(fetched.has_value());
  ASSERT_TRUE(fetched->value().try_as<double>() != nullptr);
  EXPECT_DOUBLE_EQ(*fetched->value().try_as<double>(), 42.5);
  EXPECT_EQ(ticks(*fetched), at(10).value().time_since_epoch().count());
}

TEST(SqliteHistoryStore, InsertValueOverwritesAtSameTimestamp)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  store.insert_value(node, sample(10, 1.0)).value();
  store.insert_value(node, sample(10, 2.0)).value();  // INSERT OR REPLACE -> one row

  auto window = store.read_values(node, std::nullopt, true, std::nullopt, true, 0, Direction::After).value();
  ASSERT_EQ(window.size(), 1u);
  EXPECT_DOUBLE_EQ(*window[0].value().try_as<double>(), 2.0);
}

TEST(SqliteHistoryStore, ReadValuesHonoursExclusiveUpperBound)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 4; ++i)
    store.insert_value(node, sample(i * 10, i)).value();  // 0,10,20,30

  // [10, 30): lower inclusive, upper exclusive -> 10, 20.
  auto window = store
                  .read_values(node,
                    std::optional<DateTime>{at(10)},
                    true,
                    std::optional<DateTime>{at(30)},
                    false,
                    0,
                    Direction::After)
                  .value();
  ASSERT_EQ(window.size(), 2u);
  EXPECT_EQ(ticks(window[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(ticks(window[1]), at(20).value().time_since_epoch().count());
}

TEST(SqliteHistoryStore, ReadValuesAscendingWithLimit)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 5; ++i)
    store.insert_value(node, sample(i * 10, i)).value();

  auto window = store.read_values(node, std::nullopt, true, std::nullopt, true, 3, Direction::After).value();
  ASSERT_EQ(window.size(), 3u);
  EXPECT_EQ(ticks(window[0]), at(0).value().time_since_epoch().count());
  EXPECT_EQ(ticks(window[2]), at(20).value().time_since_epoch().count());
}

TEST(SqliteHistoryStore, ReadNearestRespectsDirectionAndInclusivity)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 4; ++i)
    store.insert_value(node, sample(i * 10, i)).value();  // 0,10,20,30

  auto beforeIncl = store.read_nearest_value(node, at(20), Direction::Before, true).value();
  ASSERT_TRUE(beforeIncl.has_value());
  EXPECT_EQ(ticks(*beforeIncl), at(20).value().time_since_epoch().count());

  auto beforeExcl = store.read_nearest_value(node, at(20), Direction::Before, false).value();
  ASSERT_TRUE(beforeExcl.has_value());
  EXPECT_EQ(ticks(*beforeExcl), at(10).value().time_since_epoch().count());

  auto afterExcl = store.read_nearest_value(node, at(20), Direction::After, false).value();
  ASSERT_TRUE(afterExcl.has_value());
  EXPECT_EQ(ticks(*afterExcl), at(30).value().time_since_epoch().count());

  EXPECT_FALSE(store.read_nearest_value(node, at(100), Direction::After, true).value().has_value());
}

TEST(SqliteHistoryStore, DeleteValuesRemovesInclusiveBoundsAndReportsCount)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 5; ++i)
    store.insert_value(node, sample(i * 10, i)).value();  // 0,10,20,30,40

  auto removed = store.delete_values(node, at(10), at(30)).value();  // [10,30] inclusive -> 10,20,30
  EXPECT_EQ(removed, 3u);
  EXPECT_TRUE(store.read_value_at(node, at(0)).value().has_value());
  EXPECT_FALSE(store.read_value_at(node, at(20)).value().has_value());
  EXPECT_TRUE(store.read_value_at(node, at(40)).value().has_value());
}

TEST(SqliteHistoryStore, ModificationRecordsRoundTrip)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  ua::ModificationInfo info;
  info.update_type() = ua::HistoryUpdateType::Replace;
  info.user_name() = ua::String{"alice"};
  store.insert_modification(node, sample(10, 7.0), info).value();

  EXPECT_TRUE(store.has_modification_at(node, at(10)).value());
  auto mods =
    store.read_modifications(node, std::nullopt, true, std::nullopt, true, 0, Direction::After).value();
  ASSERT_EQ(mods.size(), 1u);
  EXPECT_EQ(mods[0].info.update_type(), ua::HistoryUpdateType::Replace);
  EXPECT_EQ(mods[0].info.user_name(), ua::String{"alice"});
  EXPECT_DOUBLE_EQ(*mods[0].value.value().try_as<double>(), 7.0);
}

// Parity check: the engine produces the same result over the SQLite store as over the in-memory
// store (covered in history_engine_tests). Exercises engine + SQLite end-to-end.
TEST(SqliteHistoryStore, EngineReadRawForwardRangeOverSqlite)
{
  SqliteHistoryStore store{":memory:", make_codec()};
  for (int i = 0; i < 5; ++i)
    store.insert_value(node, sample(i * 10, i)).value();  // 0,10,20,30,40

  HistoryEngine::ReadRawItem item;
  item.index = 0;
  item.nodeId = node;
  item.startTime = at(10);
  item.endTime = at(30);  // [10,30) -> 10,20
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().values.size(), 2u);
  EXPECT_EQ(ticks(result.value().values[0]), at(10).value().time_since_epoch().count());
  EXPECT_EQ(ticks(result.value().values[1]), at(20).value().time_since_epoch().count());
}

TEST(SqliteHistoryStore, EngineUpdateAndReadBackOverSqlite)
{
  SqliteHistoryStore store{":memory:", make_codec()};

  HistoryEngine::UpdateDataItem insert;
  insert.nodeId = node;
  insert.performInsertReplace = ua::PerformUpdateType::Insert;
  insert.values = {sample(10, 1.0), sample(20, 2.0)};
  auto inserted = HistoryEngine::update_data(store, insert);
  ASSERT_TRUE(inserted.is_good());
  EXPECT_EQ(
    inserted.value().operationResults[0].as_uint32(), StatusCode{ua::Status::GoodEntryInserted}.as_uint32());

  // Duplicate insert is rejected.
  auto dup = HistoryEngine::update_data(store, insert);
  EXPECT_EQ(dup.value().operationResults[0].as_uint32(), StatusCode{ua::Status::BadEntryExists}.as_uint32());

  HistoryEngine::ReadRawItem read;
  read.nodeId = node;
  read.startTime = at(0);
  read.endTime = at(60);
  auto result = HistoryEngine::read_raw(store, read);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().values.size(), 2u);
}
