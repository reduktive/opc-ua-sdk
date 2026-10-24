// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5e - strand-dispatch contract.
//
//
// The 4.5e flip restructures both services from a coroutine that
// `co_await delegate->read_raw_coro(...)` into a callback chain. The runbook
// stipulates that the post-flip code must dispatch the next step back to the
// service strand whenever the delegate completes off-strand - otherwise the
// continuation runs on the delegate's own worker thread, breaking strand
// discipline.
//
// At pin-authoring time the production body is still a coroutine. We observe
// the contract indirectly:
//   * SD-A - inline-completing fake. The user CompleteCallback fires on the
//     same family of threads as a strand-pool worker (not the test thread).
//   * SD-B / SD-C - deferred-completing fake whose worker is a dedicated
//     thread. The pin asserts the user CompleteCallback does NOT observe the
//     fake-worker thread id, i.e. production code returned to the strand
//     after the off-strand completion.
//
// Per the runbook section 4.3 "SD-A observability decision" the per-step thread
// observation is out of scope for pin authoring (it would require a
// production-code hook). The pins here lock the externally-observable
// terminal-callback affinity.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_continuation_points.h"
#include "ua_history_data.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_history_update_details.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_service.h"
#include "ua_node_accessor.h"
#include "ua_perform_update_type.h"
#include "ua_read_raw_modified_details.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_update_data_details.h"

#include "fake_history_delegate.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"

namespace ua::test::behaviour_pins::phase_4_5e
{
namespace
{

class HistoryReadUpdateStrandDispatchPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mTestThreadId = std::this_thread::get_id();
  }

  void TearDown() override
  {
    mSessionInfo.reset();
    mPool.join();
  }

  void build(FakeHistoryDelegate::Mode mode)
  {
    ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = {}};
    auto server = ua::server::Server::create(mPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

    mNamespace = std::make_shared<HistoryPinNamespace>("uri://history-strand-pin", mPool.get_executor());
    mDelegate = std::make_shared<FakeHistoryDelegate>(mode);
    mNamespace->set_delegate(mDelegate);
    server.address_space().add_namespace_sync(mNamespace);
    mNsIndex = server.address_space().namespace_array().get_namespace_index("uri://history-strand-pin");

    mSessionInfo = std::make_shared<SessionInfoStub>(std::move(server), mPool.get_executor());
  }

  ua::NodeId variable_with_history_read(uint32_t numericId)
  {
    ua::NodeId nodeId{mNsIndex, numericId};
    auto as = mSessionInfo->address_space();
    auto v = as.try_create_sync<ua::VariableAccessor>(nodeId, ua::NodeClass::Variable);
    EXPECT_TRUE(v.is_good());
    if (v.is_good())
    {
      ua::AccessLevelType al;
      al.set(ua::AccessLevelType::Bit::CurrentRead);
      al.set(ua::AccessLevelType::Bit::HistoryRead);
      v.value().set_access_level(al);
    }
    return nodeId;
  }

  ua::NodeId variable_with_history_write(uint32_t numericId)
  {
    ua::NodeId nodeId{mNsIndex, numericId};
    auto as = mSessionInfo->address_space();
    auto v = as.try_create_sync<ua::VariableAccessor>(nodeId, ua::NodeClass::Variable);
    EXPECT_TRUE(v.is_good());
    if (v.is_good())
    {
      ua::AccessLevelType al;
      al.set(ua::AccessLevelType::Bit::CurrentRead);
      al.set(ua::AccessLevelType::Bit::HistoryWrite);
      v.value().set_access_level(al);
    }
    return nodeId;
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<HistoryPinNamespace> mNamespace;
  std::shared_ptr<FakeHistoryDelegate> mDelegate;
  std::shared_ptr<SessionInfoStub> mSessionInfo;
  uint16_t mNsIndex{0};

  std::thread::id mTestThreadId{};
};

}  // namespace

// ---------------------------------------------------------------------------
// SD-A - Inline-completing delegate: the user CompleteCallback fires on a
// thread that is neither the test thread nor a fake-owned worker. The fake
// in inline mode has no worker thread; affinity is asserted as
// "callback ran somewhere on the pool, not the test thread."
// ---------------------------------------------------------------------------
TEST_F(HistoryReadUpdateStrandDispatchPin, HistoryReadInlineFastPathDeliversCallbackOffTestThread)
{
  build(FakeHistoryDelegate::Mode::Inline);
  mDelegate->stage_read_raw_per_item_success();

  auto a = variable_with_history_read(100);

  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->start_time() = ua::DateTime{ua::DateTime::min()};
  details->end_time() = ua::DateTime::now();
  details->num_values_per_node() = 100;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = a;

  std::promise<std::thread::id> threadPromise;
  std::promise<ua::server::HistoryReadService::HistoryReadServiceResponse> donePromise;

  ua::server::HistoryContinuationPoints cps;
  auto service = ua::server::HistoryReadService::create(mSessionInfo,
    {},
    0,
    std::move(request),
    cps,
    mPool.get_executor(),
    [&threadPromise, &donePromise](ua::server::HistoryReadService::HistoryReadServiceResponse response)
    {
      threadPromise.set_value(std::this_thread::get_id());
      donePromise.set_value(std::move(response));
    });

  auto threadFut = threadPromise.get_future();
  auto doneFut = donePromise.get_future();
  (void)doneFut.get();
  auto cbThread = threadFut.get();

  EXPECT_NE(cbThread, mTestThreadId)
    << "inline-mode delegate: user CompleteCallback must run on a strand-pool thread, "
       "not the main test thread";
}

// ---------------------------------------------------------------------------
// SD-B - Deferred-completing delegate: the fake parks the read_raw callback
// and fires it from its dedicated worker. The user CompleteCallback must NOT
// observe the worker thread id - production code is required to dispatch
// the continuation back to the service strand.
// ---------------------------------------------------------------------------
TEST_F(HistoryReadUpdateStrandDispatchPin, HistoryReadDeferredDelegateUserCallbackDoesNotRunOnDelegateWorker)
{
  build(FakeHistoryDelegate::Mode::Deferred);
  mDelegate->stage_read_raw_per_item_success();

  auto a = variable_with_history_read(100);

  ua::HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->start_time() = ua::DateTime{ua::DateTime::min()};
  details->end_time() = ua::DateTime::now();
  details->num_values_per_node() = 100;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = a;

  std::promise<std::thread::id> threadPromise;
  std::promise<ua::server::HistoryReadService::HistoryReadServiceResponse> donePromise;

  ua::server::HistoryContinuationPoints cps;
  auto service = ua::server::HistoryReadService::create(mSessionInfo,
    {},
    0,
    std::move(request),
    cps,
    mPool.get_executor(),
    [&threadPromise, &donePromise](ua::server::HistoryReadService::HistoryReadServiceResponse response)
    {
      threadPromise.set_value(std::this_thread::get_id());
      donePromise.set_value(std::move(response));
    });

  // Wait until the delegate has PARKED the read_raw completion before driving it. when_parked() gates
  // on the parked-queue size that drive_next_pending() consumes (not read_raw_call_count(), which
  // read_raw_async bumps BEFORE parking - that race flaked on 32-bit). It returns a future the main
  // thread blocks on: NOT a busy-spin poll or a latency deadline. This test asserts ordering and
  // affinity; the enclosing CI job timeout is the liveness guard for a genuine deadlock.
  mDelegate->when_parked().get();

  // Drive the parked completion from the fake's worker thread.
  ASSERT_TRUE(mDelegate->drive_next_pending());

  auto threadFut = threadPromise.get_future();
  auto doneFut = donePromise.get_future();
  (void)doneFut.get();
  auto cbThread = threadFut.get();

  EXPECT_NE(cbThread, mDelegate->worker_thread_id())
    << "user CompleteCallback ran on the delegate's worker thread - production code "
       "did not dispatch the continuation back to the service strand";
  EXPECT_NE(cbThread, mTestThreadId)
    << "user CompleteCallback ran on the test thread - strand affinity is broken";
}

// ---------------------------------------------------------------------------
// SD-C - Same shape as SD-B for HistoryUpdate (UpdateData group iteration).
// ---------------------------------------------------------------------------
// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
TEST_F(
  HistoryReadUpdateStrandDispatchPin, HistoryUpdateDeferredDelegateUserCallbackDoesNotRunOnDelegateWorker)
// clang-format on
{
  build(FakeHistoryDelegate::Mode::Deferred);
  mDelegate->stage_update_data_per_item_success();

  variable_with_history_write(100);

  ua::HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(1);
  auto details = std::make_unique<ua::UpdateDataDetails>();
  details->node_id() = ua::NodeId{mNsIndex, 100u};
  details->perform_insert_replace() = ua::PerformUpdateType::Insert;
  details->update_values().resize(1);
  details->update_values()[0].value() = static_cast<int32_t>(0);
  request.history_update_details()[0] = std::move(details);

  std::promise<std::thread::id> threadPromise;
  std::promise<ua::Response> donePromise;

  auto service = ua::server::HistoryUpdateService::create(mSessionInfo,
    0,
    std::move(request),
    mPool.get_executor(),
    [&threadPromise, &donePromise](ua::Response response)
    {
      threadPromise.set_value(std::this_thread::get_id());
      donePromise.set_value(std::move(response));
    });

  // Same park-vs-count race as SD-B (update_data_async bumps the call count before parking): gate on
  // the parked queue via a blocking future wait (load-robust), not the call count or a busy-spin poll.
  mDelegate->when_parked().get();

  ASSERT_TRUE(mDelegate->drive_next_pending());

  auto threadFut = threadPromise.get_future();
  auto doneFut = donePromise.get_future();
  (void)doneFut.get();
  auto cbThread = threadFut.get();

  EXPECT_NE(cbThread, mDelegate->worker_thread_id())
    << "HistoryUpdate: user CompleteCallback ran on the delegate's worker thread";
  EXPECT_NE(cbThread, mTestThreadId) << "HistoryUpdate: user CompleteCallback ran on the test thread";
}

}  // namespace ua::test::behaviour_pins::phase_4_5e
