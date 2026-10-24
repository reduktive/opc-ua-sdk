// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Failure-contract tests for the HistoryStore interface.
//
// The interface's contract (history_store.h) is: every method returns a ua::Result and never throws; a
// storage failure is an error Result carrying a StatusCode + ErrorDetail, which the engine forwards
// into the per-item history result, and which the delegate surfaces without ever letting an exception
// escape its `noexcept` async methods. These tests inject failures two ways - a store that returns
// error Results, and a (contract-violating) store that throws - and assert both surface as an error
// item Result with the detail intact, and that the delegate's worker never terminates.

#include "ua_history_engine_delegate.h"
#include "ua_history_engine.h"
#include "ua_history_store.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <memory>

using ua::DataValue;
using ua::DateTime;
using ua::NodeId;
using ua::Result;
using ua::StatusCode;
using ua::VoidResult;
using ua::history::Direction;
using ua::history::HistoryEngine;
using ua::history::HistoryStore;
using ua::history::ModifiedValue;
using ua::history::StoredEvent;

namespace
{

const NodeId node{uint16_t{2}, 7000};

// The distinctive failure every faulting store reports - a recognisable code + ErrorDetail so a test
// can prove the engine/delegate forwarded *this* error, lossless.
StatusCode injected_fault()
{
  return StatusCode{ua::Status::BadOutOfMemory,
    ua::make_error_detail("InjectedStoreFault", "simulated backend failure", "FaultyStore")};
}

// A store whose every operation fails with injected_fault() - the contract-honouring failure path
// (returns an error Result, does not throw).
class FaultyStore : public HistoryStore
{
public:
  Result<std::vector<DataValue>> read_values(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    return injected_fault();
  }

  Result<std::optional<DataValue>> read_nearest_value(const NodeId&, DateTime, Direction, bool) override
  {
    return injected_fault();
  }

  Result<std::optional<DataValue>> read_value_at(const NodeId&, DateTime) override
  {
    return injected_fault();
  }

  VoidResult insert_value(const NodeId&, const DataValue&) override
  {
    return injected_fault();
  }

  VoidResult delete_value_at(const NodeId&, DateTime) override
  {
    return injected_fault();
  }

  Result<std::size_t> delete_values(const NodeId&, DateTime, DateTime) override
  {
    return injected_fault();
  }

  VoidResult insert_modification(const NodeId&, const DataValue&, const ua::ModificationInfo&) override
  {
    return injected_fault();
  }

  Result<std::vector<ModifiedValue>> read_modifications(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    return injected_fault();
  }

  Result<bool> has_modification_at(const NodeId&, DateTime) override
  {
    return injected_fault();
  }

  VoidResult insert_event(const NodeId&, const StoredEvent&) override
  {
    return injected_fault();
  }

  Result<std::vector<StoredEvent>> read_events(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    return injected_fault();
  }

  Result<std::optional<StoredEvent>> read_event(const NodeId&, const ua::ByteString&) override
  {
    return injected_fault();
  }

  Result<bool> delete_event(const NodeId&, const ua::ByteString&) override
  {
    return injected_fault();
  }

  VoidResult insert_annotation(const NodeId&, const DataValue&) override
  {
    return injected_fault();
  }

  Result<std::optional<DataValue>> read_annotation_at(const NodeId&, DateTime) override
  {
    return injected_fault();
  }

  VoidResult delete_annotation_at(const NodeId&, DateTime) override
  {
    return injected_fault();
  }
};

// A store that VIOLATES the contract by throwing instead of returning an error Result. Used to prove
// the engine's to_result boundary and the delegate's noexcept backstop both contain the throw.
class ThrowingStore : public HistoryStore
{
  [[noreturn]] static void boom()
  {
    throw ua::UaException{
      ua::Status::BadOutOfMemory, ua::make_error_detail("ThrownStoreFault", "store threw", "ThrowingStore")};
  }

public:
  Result<std::vector<DataValue>> read_values(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    boom();
  }

  Result<std::optional<DataValue>> read_nearest_value(const NodeId&, DateTime, Direction, bool) override
  {
    boom();
  }

  Result<std::optional<DataValue>> read_value_at(const NodeId&, DateTime) override
  {
    boom();
  }

  VoidResult insert_value(const NodeId&, const DataValue&) override
  {
    boom();
  }

  VoidResult delete_value_at(const NodeId&, DateTime) override
  {
    boom();
  }

  Result<std::size_t> delete_values(const NodeId&, DateTime, DateTime) override
  {
    boom();
  }

  VoidResult insert_modification(const NodeId&, const DataValue&, const ua::ModificationInfo&) override
  {
    boom();
  }

  Result<std::vector<ModifiedValue>> read_modifications(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    boom();
  }

  Result<bool> has_modification_at(const NodeId&, DateTime) override
  {
    boom();
  }

  VoidResult insert_event(const NodeId&, const StoredEvent&) override
  {
    boom();
  }

  Result<std::vector<StoredEvent>> read_events(
    const NodeId&, std::optional<DateTime>, bool, std::optional<DateTime>, bool, uint32_t, Direction) override
  {
    boom();
  }

  Result<std::optional<StoredEvent>> read_event(const NodeId&, const ua::ByteString&) override
  {
    boom();
  }

  Result<bool> delete_event(const NodeId&, const ua::ByteString&) override
  {
    boom();
  }

  VoidResult insert_annotation(const NodeId&, const DataValue&) override
  {
    boom();
  }

  Result<std::optional<DataValue>> read_annotation_at(const NodeId&, DateTime) override
  {
    boom();
  }

  VoidResult delete_annotation_at(const NodeId&, DateTime) override
  {
    boom();
  }
};

HistoryEngine::ReadRawItem raw_item()
{
  HistoryEngine::ReadRawItem item;
  item.index = 0;
  item.nodeId = node;
  item.startTime = DateTime::now();
  item.endTime = DateTime{item.startTime.value() + std::chrono::seconds{60}};
  return item;
}

}  // namespace

TEST(HistoryFailureContract, EngineForwardsStoreErrorResultWithDetailOnRead)
{
  FaultyStore store;
  auto item = raw_item();
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadOutOfMemory}.as_uint32());
  ASSERT_NE(result.error_detail(), nullptr);  // detail preserved through the engine
}

TEST(HistoryFailureContract, EngineForwardsStoreErrorResultOnUpdate)
{
  FaultyStore store;
  HistoryEngine::UpdateDataItem item;
  item.index = 0;
  item.nodeId = node;
  item.performInsertReplace = ua::PerformUpdateType::Insert;
  DataValue dv;
  dv.source_timestamp() = DateTime::now();
  item.values = {dv};

  auto result = HistoryEngine::update_data(store, item);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadOutOfMemory}.as_uint32());
  ASSERT_NE(result.error_detail(), nullptr);
}

TEST(HistoryFailureContract, EngineContainsAThrowingStore)
{
  // A store that violates the no-throw contract must still not propagate the throw out of the engine:
  // the to_result boundary converts it to an error Result (lossless for a UaException).
  ThrowingStore store;
  auto item = raw_item();
  auto result = HistoryEngine::read_raw(store, item);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_uint32(), StatusCode{ua::Status::BadOutOfMemory}.as_uint32());
  ASSERT_NE(result.error_detail(), nullptr);
}

TEST(HistoryFailureContract, DelegateSurfacesStoreErrorWithoutTerminating)
{
  // The delegate's *_async methods are noexcept. Drive one with a throwing store and confirm the
  // batch callback receives an error item result rather than the process terminating.
  ua::history::HistoryEngineDelegate delegate{std::make_unique<ThrowingStore>()};

  ua::history::HistoryEngineDelegate::ReadContext context;
  context.cancelled = std::make_shared<std::atomic_bool>(false);

  std::vector<ua::history::HistoryEngineDelegate::ReadRawItem> items{raw_item()};

  std::promise<ua::BatchResult<ua::history::HistoryEngineDelegate::ReadRawItemResult>> promise;
  auto future = promise.get_future();
  delegate.read_raw_async(context,
    std::move(items),
    [&promise](ua::BatchResult<ua::history::HistoryEngineDelegate::ReadRawItemResult> batch)
    { promise.set_value(std::move(batch)); });

  // Blocking on the test (main) thread, never on the delegate's worker - see the no-blocking rule.
  auto batch = future.get();
  ASSERT_EQ(batch.items.size(), 1u);
  EXPECT_TRUE(batch.items[0].is_bad());
  EXPECT_EQ(batch.items[0].status_code().as_uint32(), StatusCode{ua::Status::BadOutOfMemory}.as_uint32());
}
