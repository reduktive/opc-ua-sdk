// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <thread>
#include <future>
#include <map>
#include <mutex>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_event_notifier_type.h"
#include "ua_continuation_points.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_event.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_history_read_validation.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_aggregate_filter.h"
#include "ua_range.h"
#include "ua_read_annotation_data_details.h"
#include "ua_read_at_time_details.h"
#include "ua_read_event_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_raw_modified_details.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_node_accessor.h"

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Fake history delegate with configurable read_raw callback
// ---------------------------------------------------------------------------
class FakeNamespaceHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  using ReadRawHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadRawItem>, ReadRawCallback)>;

  void set_on_read_raw(ReadRawHandler handler)
  {
    mOnReadRaw = std::move(handler);
  }

  void read_raw_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    if (mOnReadRaw)
    {
      mOnReadRaw(context, items, std::move(callback));
      return;
    }
    // Default: call base class (returns BadHistoryOperationUnsupported per item)
    NamespaceHistoryDelegate::read_raw_async(context, items, std::move(callback));
  }

  using ReadAnnotationHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadAnnotationItem>, ReadAnnotationCallback)>;

  void set_on_read_annotations(ReadAnnotationHandler handler)
  {
    mOnReadAnnotations = std::move(handler);
  }

  void read_annotations_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadAnnotationItem> items,
    ReadAnnotationCallback callback) noexcept override
  {
    if (mOnReadAnnotations)
    {
      mOnReadAnnotations(context, std::move(items), std::move(callback));
      return;
    }
    // Default: BadHistoryOperationUnsupported per item.
    NamespaceHistoryDelegate::read_annotations_async(context, std::move(items), std::move(callback));
  }

  using ReadAtTimeHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>, ReadAtTimeCallback)>;

  void set_on_read_at_time(ReadAtTimeHandler handler)
  {
    mOnReadAtTime = std::move(handler);
  }

  void read_at_time_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadAtTimeItem> items,
    ReadAtTimeCallback callback) noexcept override
  {
    if (mOnReadAtTime)
    {
      mOnReadAtTime(context, std::move(items), std::move(callback));
      return;
    }
    // Default: BadHistoryOperationUnsupported per item.
    NamespaceHistoryDelegate::read_at_time_async(context, std::move(items), std::move(callback));
  }

  using ReadEventsHandler = std::function<void(const NamespaceHistoryDelegate::ReadContext&,
    std::vector<NamespaceHistoryDelegate::ReadEventsItem>, ReadEventsCallback)>;

  void set_on_read_events(ReadEventsHandler handler)
  {
    mOnReadEvents = std::move(handler);
  }

  void read_events_async(const NamespaceHistoryDelegate::ReadContext& context,
    std::vector<NamespaceHistoryDelegate::ReadEventsItem> items,
    ReadEventsCallback callback) noexcept override
  {
    if (mOnReadEvents)
    {
      mOnReadEvents(context, std::move(items), std::move(callback));
      return;
    }
    // Default: BadHistoryOperationUnsupported per item.
    NamespaceHistoryDelegate::read_events_async(context, std::move(items), std::move(callback));
  }

  void release_cursor(NamespaceHistoryDelegate::Cursor cursor) noexcept override
  {
    std::lock_guard lock(mMutex);
    mReleasedCursors.push_back(std::move(cursor));
  }

  std::vector<NamespaceHistoryDelegate::Cursor> released_cursors()
  {
    std::lock_guard lock(mMutex);
    return mReleasedCursors;
  }

private:
  ReadRawHandler mOnReadRaw;
  ReadAnnotationHandler mOnReadAnnotations;
  ReadAtTimeHandler mOnReadAtTime;
  ReadEventsHandler mOnReadEvents;
  std::mutex mMutex;
  std::vector<NamespaceHistoryDelegate::Cursor> mReleasedCursors;
};

// ---------------------------------------------------------------------------
// Test namespace that provides a history delegate
// ---------------------------------------------------------------------------
class HistoryTestNamespace : public default_ns::Namespace,
                             public std::enable_shared_from_this<HistoryTestNamespace>
{
public:
  HistoryTestNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void set_delegate(shared_ptr<FakeNamespaceHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<FakeNamespaceHistoryDelegate> mDelegate;
};

// ---------------------------------------------------------------------------
// Helper: create a standard test harness (thread pool, server, namespace)
// ---------------------------------------------------------------------------
struct TestHarness
{
  ~TestHarness()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  optional<Server> server;
  shared_ptr<HistoryTestNamespace> ns;
  shared_ptr<FakeNamespaceHistoryDelegate> delegate;
  shared_ptr<SessionInfoStub> sessionInfo;
  uint16_t nsIndex{0};

  void setup(
    bool withDelegate = true, ServerConfig serverConfig = ServerConfig{}, bool noAccessIdentity = false)
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};

    server.emplace(Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

    ns = make_shared<HistoryTestNamespace>("uri://history-test-ns", threadPool.get_executor());
    if (withDelegate)
    {
      delegate = make_shared<FakeNamespaceHistoryDelegate>();
      ns->set_delegate(delegate);
    }
    server->address_space().add_namespace_sync(ns);
    nsIndex = server->address_space().namespace_array().get_namespace_index("uri://history-test-ns");

    if (noAccessIdentity)
    {
      sessionInfo =
        make_shared<SessionInfoStub>(std::move(*server), threadPool.get_executor(), nullptr, true);
    }
    else
    {
      sessionInfo = make_shared<SessionInfoStub>(std::move(*server), threadPool.get_executor());
    }
    server.reset();
  }

  NodeId create_variable_with_history(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      al.set(AccessLevelType::Bit::HistoryRead);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  NodeId create_variable_without_history(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(varResult.is_good()) << "Failed to create variable node";
    if (varResult.is_good())
    {
      AccessLevelType al;
      al.set(AccessLevelType::Bit::CurrentRead);
      varResult.value().set_access_level(al);
    }
    return nodeId;
  }

  NodeId create_object_with_history_read(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(objResult.is_good()) << "Failed to create object node";
    if (objResult.is_good())
    {
      EventNotifierType en;
      en.set(EventNotifierType::Bit::HistoryRead);
      objResult.value().set_event_notifier(en);
    }
    return nodeId;
  }

  NodeId create_object_without_history_read(uint32_t numericId)
  {
    NodeId nodeId{nsIndex, numericId};
    auto as = sessionInfo->address_space();
    auto objResult = as.try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    EXPECT_TRUE(objResult.is_good()) << "Failed to create object node";
    // EventNotifier defaults to 0 (no history)
    return nodeId;
  }

  HistoryReadService::HistoryReadServiceResponse run_service(
    HistoryReadRequest request, std::chrono::milliseconds wait = 3s)
  {
    HistoryContinuationPoints sessionCPs;
    return run_service(std::move(request), sessionCPs, wait);
  }

  HistoryReadService::HistoryReadServiceResponse run_service(
    HistoryReadRequest request, HistoryContinuationPoints& sessionCPs, std::chrono::milliseconds wait = 3s)
  {
    // Hand the result back via a promise/future pair rather than a hand-rolled
    // mutex+condition_variable: the shared state is heap-allocated and
    // reference-counted (owned by the callback via the shared_ptr and by the
    // future here), so there is no stack-local condition_variable for the waiter
    // to destroy while a pool thread is still inside notify_* (the
    // pthread_cond_destroy data race TSan flagged). set_value->get is a defined
    // synchronizes-with handoff. The promise lives in a shared_ptr because the
    // callback is stored in a copyable std::function and std::promise is move-only.
    auto resultPromise = std::make_shared<std::promise<HistoryReadService::HistoryReadServiceResponse>>();
    auto resultFuture = resultPromise->get_future();

    auto service = HistoryReadService::create(sessionInfo,
      {},
      0,
      std::move(request),
      sessionCPs,
      threadPool.get_executor(),
      [resultPromise](HistoryReadService::HistoryReadServiceResponse response)
      { resultPromise->set_value(std::move(response)); });

    if (resultFuture.wait_for(wait) != std::future_status::ready)
    {
      ADD_FAILURE() << "Service did not complete within timeout";
      return {};
    }
    return resultFuture.get();
  }

  shared_ptr<HistoryReadService> create_service_no_wait(HistoryReadRequest request,
    HistoryContinuationPoints& sessionCPs, HistoryReadService::CompleteCallback callback)
  {
    return HistoryReadService::create(
      sessionInfo, {}, 0, std::move(request), sessionCPs, threadPool.get_executor(), std::move(callback));
  }
};

HistoryReadRequest make_read_raw_request(std::initializer_list<NodeId> nodeIds)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto details = std::make_unique<ReadRawModifiedDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 100;
  details->return_bounds() = true;
  request.history_read_details() = std::move(details);

  request.nodes_to_read().resize(nodeIds.size());
  size_t i = 0;
  for (const auto& nid : nodeIds)
  {
    request.nodes_to_read()[i].node_id() = nid;
    ++i;
  }

  return request;
}

// Builds a ReadProcessedDetails request for one node and one aggregate function.
HistoryReadRequest make_read_processed_request(NodeId nodeId, uint32_t aggregateFunctionId, DateTime start,
  DateTime end, double processingIntervalMs, size_t aggregateCount = 1)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  // ReadProcessed requires Source timestamps (Part 13 section 5.4.3.1 / SVR-HIST-AGG-027).
  request.timestamps_to_return() = TimestampsToReturn::Source;

  auto details = std::make_unique<ReadProcessedDetails>();
  details->start_time() = start;
  details->end_time() = end;
  details->processing_interval() = processingIntervalMs;
  details->aggregate_type().resize(aggregateCount);
  for (size_t i = 0; i < aggregateCount; ++i)
    details->aggregate_type()[i] = NodeId{aggregateFunctionId};
  details->aggregate_configuration().use_server_capabilities_defaults() = true;
  request.history_read_details() = std::move(details);

  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

// Builds a ReadAnnotationDataDetails request for one node and a list of requested timestamps.
HistoryReadRequest make_read_annotation_request(NodeId nodeId, const std::vector<DateTime>& reqTimes)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto details = std::make_unique<ReadAnnotationDataDetails>();
  details->req_times().resize(reqTimes.size());
  for (size_t i = 0; i < reqTimes.size(); ++i)
    details->req_times()[i] = reqTimes[i];
  request.history_read_details() = std::move(details);

  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  return request;
}

bool is_service_fault(const Response& response, StatusCode expected)
{
  auto* fault = dynamic_cast<ServiceFault*>(std::get<shared_ptr<Structure>>(response).get());
  return fault && fault->response_header().service_result() == expected;
}

bool has_service_result(const Response& response, StatusCode expected)
{
  auto* structure = std::get<shared_ptr<Structure>>(response).get();
  // Check typed response first (HistoryReadResponse with bad service_result)
  auto* histResp = dynamic_cast<HistoryReadResponse*>(structure);
  if (histResp)
    return histResp->response_header().service_result() == expected;
  // Fall back to ServiceFault (e.g., for cancel/timeout)
  auto* fault = dynamic_cast<ServiceFault*>(structure);
  return fault && fault->response_header().service_result() == expected;
}

HistoryReadResponse* get_history_response(const Response& response)
{
  return dynamic_cast<HistoryReadResponse*>(std::get<shared_ptr<Structure>>(response).get());
}

}  // namespace

// ---------------------------------------------------------------------------
// Test 1: Empty request returns BadNothingToDo
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-015, scope=function)
TEST(HistoryReadServiceTests, EmptyRequestReturnsBadNothingToDo)
{
  TestHarness h;
  h.setup();

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  // nodes_to_read is empty

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadNothingToDo));
}

// ---------------------------------------------------------------------------
// Test 2: Missing details returns BadHistoryOperationInvalid
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-018, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, MissingDetailsReturnsBadHistoryOperationInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  // history_read_details is not set (nullptr)
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadHistoryOperationInvalid));
}

// ---------------------------------------------------------------------------
// Test 3: ReadAtTimeDetails with no requested timestamps is a whole-request error
// (BadHistoryOperationInvalid ServiceFault). AtTime is now a dispatched detail type, so this
// exercises the service-level validation rather than the old "unsupported details type" path.
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, AtTimeDetailsWithNoTimestampsReturnsServiceFault)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadAtTimeDetails>();  // empty req_times
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadHistoryOperationInvalid));
}

// ---------------------------------------------------------------------------
// Test 3c: a details extension object that is not a HistoryReadDetails subtype at all (here an
// AggregateFilter, exactly as UACTT Aggregate Err-001 sends) is invalid for the operation, so the
// whole request fails with BadHistoryOperationInvalid - not BadHistoryOperationUnsupported (which is
// reserved for a valid details type the delegate cannot service). Mirrors the HistoryUpdate path's
// HU-D treatment of a wrong-subtype details.
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, NonHistoryReadDetailsSubtypeReturnsBadHistoryOperationInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<AggregateFilter>();  // not a HistoryReadDetails
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadHistoryOperationInvalid));
}

// ---------------------------------------------------------------------------
// Test 4: ReadRaw dispatches to delegate and returns correct values
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, ReadRawDispatchesToDelegate)
{
  TestHarness h;
  h.setup();

  auto nodeId1 = h.create_variable_with_history(100);
  auto nodeId2 = h.create_variable_with_history(101);

  // Capture the items the delegate receives so we can assert on them from the main thread.
  struct CapturedItem
  {
    NodeId nodeId;
    DateTime startTime;
    DateTime endTime;
    uint32_t maxValuesPerNode;
    bool returnBounds;
    bool isReadModified;
    bool hasCursor;
    size_t index;
  };

  std::mutex captureMtx;
  std::vector<CapturedItem> capturedItems;

  h.delegate->set_on_read_raw(
    [&captureMtx, &capturedItems](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        for (const auto& item : items)
        {
          CapturedItem ci;
          ci.nodeId = item.nodeId;
          ci.startTime = item.startTime;
          ci.endTime = item.endTime;
          ci.maxValuesPerNode = item.maxValuesPerNode;
          ci.returnBounds = item.returnBounds;
          ci.isReadModified = item.isReadModified;
          ci.hasCursor = item.cursor.has_value();
          ci.index = item.index;
          capturedItems.push_back(std::move(ci));
        }
      }

      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(item.index);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId1, nodeId2});
  // Capture the details values before the request is moved.
  auto* detailsPtr = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(detailsPtr, nullptr);
  DateTime expectedStartTime = detailsPtr->start_time();
  DateTime expectedEndTime = detailsPtr->end_time();
  uint32_t expectedMaxValues = detailsPtr->num_values_per_node();
  bool expectedReturnBounds = detailsPtr->return_bounds();
  bool expectedIsReadModified = detailsPtr->is_read_modified();

  auto result = h.run_service(std::move(request));

  // Verify delegate received correct parameters.
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(capturedItems.size(), 2u);

    EXPECT_EQ(capturedItems[0].nodeId, nodeId1);
    EXPECT_EQ(capturedItems[1].nodeId, nodeId2);

    for (size_t i = 0; i < 2; ++i)
    {
      EXPECT_EQ(capturedItems[i].startTime, expectedStartTime) << "Item " << i;
      EXPECT_EQ(capturedItems[i].endTime, expectedEndTime) << "Item " << i;
      EXPECT_EQ(capturedItems[i].maxValuesPerNode, expectedMaxValues) << "Item " << i;
      EXPECT_EQ(capturedItems[i].returnBounds, expectedReturnBounds) << "Item " << i;
      EXPECT_EQ(capturedItems[i].isReadModified, expectedIsReadModified) << "Item " << i;
      EXPECT_FALSE(capturedItems[i].hasCursor) << "Item " << i << " should have no cursor (fresh read)";
    }
  }

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);

  for (size_t i = 0; i < 2; ++i)
  {
    EXPECT_TRUE(response->results()[i].status_code().is_good()) << "Item " << i << " had bad status";

    auto* histData = dynamic_cast<HistoryData*>(response->results()[i].history_data().get());
    ASSERT_NE(histData, nullptr) << "Item " << i << " has no HistoryData";
    ASSERT_EQ(histData->data_values().size(), 1u);

    // Verify the DataValue content matches what the delegate wrote (item.index).
    auto& dv = histData->data_values()[0];
    EXPECT_EQ(dv.value().as<int32_t>(), static_cast<int32_t>(i)) << "Item " << i << " value mismatch";
  }
}

// ---------------------------------------------------------------------------
// Test 5: Delegate returns unsupported (default behavior)
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, DelegateReturnsUnsupported)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);
  // Don't set on_read_raw - default returns BadHistoryOperationUnsupported

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// ---------------------------------------------------------------------------
// Test 6: No history delegate returns unsupported
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, NoHistoryDelegateReturnsUnsupported)
{
  TestHarness h;
  h.setup(false);  // no delegate

  auto nodeId = h.create_variable_with_history(100);

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// Phase 5 end-to-end guarantee: a history delegate that drops its ReadRawCallback
// without invoking it must cause the HistoryRead service to deliver a bad per-item
// status (BadInternalError from std::function<void(T)>'s RAII default) to every routed item.
// The atomic flag proves the delegate path was entered.
// ---------------------------------------------------------------------------
// Test 7: Variable without HistoryRead access level returns BadHistoryOperationUnsupported
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-011, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, AccessLevelWithoutHistoryReadReturnsBadHistoryOperationUnsupported)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_without_history(100);

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// ---------------------------------------------------------------------------
// Test 8: Continuation point created from cursor
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, ContinuationPointCreatedFromCursor)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = 42;
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        // Return a cursor to indicate more data available
        success.cursor = std::string("page2");
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_FALSE(response->results()[0].continuation_point().empty())
    << "Continuation point should be non-empty when cursor is returned";

  // Verify that the service response contains HistoryContinuationPoint objects.
  ASSERT_EQ(result.continuationPoints.size(), 1u);

  auto& cp = result.continuationPoints[0];

  // Verify the cursor value is preserved through the continuation point.
  ASSERT_TRUE(cp.cursor().has_value()) << "Cursor should have a value";
  auto* cursorStr = std::any_cast<std::string>(&cp.cursor());
  ASSERT_NE(cursorStr, nullptr) << "Cursor should be a std::string";
  EXPECT_EQ(*cursorStr, "page2");

  // Verify detail_kind: not is_read_modified, so should be Raw.
  EXPECT_EQ(cp.detail_kind(), NamespaceHistoryDelegate::DetailKind::Raw);

  // Verify namespace_index matches the test namespace.
  EXPECT_EQ(cp.namespace_index(), h.nsIndex);
}

// ---------------------------------------------------------------------------
// Test 8b: Continuation point resumption passes cursor to delegate
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-007, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, ContinuationPointResumption)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  // Track which call this is (first read vs continuation read).
  std::atomic<int> callCount{0};

  // Capture cursor from the continuation (second) call.
  std::mutex captureMtx;
  bool resumptionHadCursor = false;
  std::string resumptionCursorValue;

  h.delegate->set_on_read_raw(
    [&callCount, &captureMtx, &resumptionHadCursor, &resumptionCursorValue](
      const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      int call = callCount.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(call);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));

        if (call == 0)
        {
          // First call: return a cursor to indicate more data.
          success.cursor = std::string("page2");
        }
        else
        {
          // Continuation call: capture what cursor was received.
          std::lock_guard lock(captureMtx);
          resumptionHadCursor = item.cursor.has_value();
          if (item.cursor.has_value())
          {
            auto* str = std::any_cast<std::string>(&*item.cursor);
            if (str)
              resumptionCursorValue = *str;
          }
          // No cursor returned = no more data.
        }

        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // Step 1: First read returns a continuation point.
  HistoryContinuationPoints sessionCPs;
  auto request1 = make_read_raw_request({nodeId});
  auto result1 = h.run_service(std::move(request1), sessionCPs);

  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 1u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty())
    << "First read should return a continuation point";
  ASSERT_EQ(result1.continuationPoints.size(), 1u);

  // Step 2: Move the CPs into the session map (as the session would do).
  auto cpBytes = response1->results()[0].continuation_point();
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs.emplace(id, std::move(cp));
  }

  // Step 3: Create a continuation request using the CP bytes.
  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = nodeId;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), sessionCPs);

  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  ASSERT_EQ(response2->results().size(), 1u);
  EXPECT_TRUE(response2->results()[0].status_code().is_good());

  // No more data: continuation point should be empty.
  EXPECT_TRUE(response2->results()[0].continuation_point().empty())
    << "Second read should have no continuation point (no more data)";
  EXPECT_TRUE(result2.continuationPoints.empty());

  // Verify the delegate received the cursor on the continuation call.
  {
    std::lock_guard lock(captureMtx);
    EXPECT_TRUE(resumptionHadCursor) << "Delegate should have received a cursor on continuation read";
    EXPECT_EQ(resumptionCursorValue, "page2") << "Delegate should have received the expected cursor value";
  }
}

// ---------------------------------------------------------------------------
// Test 9: Cancel returns BadRequestCancelledByClient
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, CancelReturnsServiceFault)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  // Hold the delegate callback so the read stays suspended. The delegate fires on
  // a pool thread; hand its "reached" signal back through a heap-allocated,
  // reference-counted promise rather than a stack condition_variable the waiter
  // could destroy the instant the wait returns while the pool thread is still
  // inside notify_* (the pthread_cond_destroy data race). The set_value->wait
  // handoff also publishes heldCallback to us, so no separate mutex is needed.
  NamespaceHistoryDelegate::ReadRawCallback heldCallback;
  auto delegateReachedPromise = std::make_shared<std::promise<void>>();
  auto delegateReachedFuture = delegateReachedPromise->get_future();
  auto delegateReachedOnce = std::make_shared<std::once_flag>();

  h.delegate->set_on_read_raw(
    [&heldCallback, delegateReachedPromise, delegateReachedOnce](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>,
      auto callback)
    {
      heldCallback = std::move(callback);
      std::call_once(*delegateReachedOnce, [&] { delegateReachedPromise->set_value(); });
      // Do not call it yet -- simulates a long operation.
    });

  auto request = make_read_raw_request({nodeId});

  HistoryContinuationPoints sessionCPs;
  // Same promise-based handoff for the service result. A once_flag guards set_value
  // because the late heldCallback delivery below could drive a second completion -
  // which the original bool flag silently tolerated; call_once preserves that.
  auto resultPromise = std::make_shared<std::promise<HistoryReadService::HistoryReadServiceResponse>>();
  auto resultFuture = resultPromise->get_future();
  auto resultOnce = std::make_shared<std::once_flag>();

  auto service = h.create_service_no_wait(std::move(request),
    sessionCPs,
    [resultPromise, resultOnce](HistoryReadService::HistoryReadServiceResponse response)
    { std::call_once(*resultOnce, [&] { resultPromise->set_value(std::move(response)); }); });

  // Wait for the read to reach the delegate.
  ASSERT_EQ(delegateReachedFuture.wait_for(3s), std::future_status::ready)
    << "Delegate was not reached within timeout";

  service->cancel();

  ASSERT_EQ(resultFuture.wait_for(3s), std::future_status::ready) << "Cancel did not complete within timeout";
  auto serviceResult = resultFuture.get();
  EXPECT_TRUE(is_service_fault(serviceResult.response, Status::BadRequestCancelledByClient));

  // Complete the held callback late to avoid dangling coroutine state. By now the
  // delegate has published heldCallback (delegateReachedFuture is ready) and the
  // service has completed (resultFuture is ready), so this thread is its sole
  // accessor.
  if (heldCallback)
  {
    heldCallback({});
    heldCallback = nullptr;
  }
}

// ---------------------------------------------------------------------------
// Test 10: TimestampsToReturn::Neither is invalid for HistoryRead.
// (Spec-correct mapping + ServiceFault delivery are asserted by
// TimestampsToReturnNeitherReturnsBadTimestampsToReturnInvalidServiceFault below.)

// ---------------------------------------------------------------------------
// Test 11: Operation limits - too many nodes returns BadTooManyOperations
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-016, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, TooManyNodesReturnsBadTooManyOperations)
{
  ServerConfig serverConfig;
  serverConfig.server_capabilities().operationLimits.maxNodesPerHistoryReadData = 2;

  TestHarness h;
  h.setup(true, std::move(serverConfig));

  auto nodeId1 = h.create_variable_with_history(100);
  auto nodeId2 = h.create_variable_with_history(101);
  auto nodeId3 = h.create_variable_with_history(102);

  auto request = make_read_raw_request({nodeId1, nodeId2, nodeId3});
  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadTooManyOperations));
}

// ---------------------------------------------------------------------------
// Test 12: Operation limits - exactly at limit succeeds
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-016, scope=function)
TEST(HistoryReadServiceTests, ExactlyAtLimitSucceeds)
{
  ServerConfig serverConfig;
  serverConfig.server_capabilities().operationLimits.maxNodesPerHistoryReadData = 2;

  TestHarness h;
  h.setup(true, std::move(serverConfig));

  auto nodeId1 = h.create_variable_with_history(100);
  auto nodeId2 = h.create_variable_with_history(101);

  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId1, nodeId2});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
}

// ---------------------------------------------------------------------------
// Test 13: ReadRawModifiedDetails with fewer than 2 parameters specified
// ---------------------------------------------------------------------------
// Covers SVR-HIST-READ-006 (coverage-audit retag).
// @relation(SVR-ATTR-HREAD-018, scope=function)
TEST(HistoryReadServiceTests, ReadRawWithInsufficientParametersReturnsBadHistoryOperationInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  // Only specify numValuesPerNode (1 of 3)
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadRawModifiedDetails>();
  details->num_values_per_node() = 100;
  // start_time and end_time left as null
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadHistoryOperationInvalid));
}

// ---------------------------------------------------------------------------
// Test 14: ReadRawModifiedDetails with zero parameters specified
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-018, scope=function)
TEST(HistoryReadServiceTests, ReadRawWithNoParametersReturnsBadHistoryOperationInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadHistoryOperationInvalid));
}

// ---------------------------------------------------------------------------
// Test 15: Object node without HistoryRead EventNotifier returns BadHistoryOperationUnsupported
// ---------------------------------------------------------------------------
// Covers SVR-EVT-HIST-002 (coverage-audit retag).
// @relation(SVR-ATTR-HREAD-011, scope=function)
TEST(HistoryReadServiceTests, ObjectWithoutHistoryReadEventNotifierReturnsBadHistoryOperationUnsupported)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_object_without_history_read(200);

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// ---------------------------------------------------------------------------
// Test 16: Object node with HistoryRead EventNotifier accepts event history
// ---------------------------------------------------------------------------
// @relation(AC-SVR-EVT-ATTR-010-BIT-TWO-HISTORYREAD, scope=function)
TEST(HistoryReadServiceTests, ObjectWithHistoryReadEventNotifierAcceptsEventHistoryRead)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_object_with_history_read(201);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_events(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadEventsSuccess{});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand select;
  select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  select.browse_path().push_back(QualifiedName{0, "Message"});
  select.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(select));
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(delegateCalls.load(), 1);
}

// ---------------------------------------------------------------------------
// Test 17: Session locales are passed to delegate context
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, SessionLocalesPassedToDelegate)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  std::mutex captureMtx;
  std::vector<LocaleId> capturedLocales;

  h.delegate->set_on_read_raw(
    [&captureMtx, &capturedLocales](const NamespaceHistoryDelegate::ReadContext& context,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(captureMtx);
        capturedLocales.assign(context.sessionLocales.begin(), context.sessionLocales.end());
      }

      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});

  // Create service with specific locales.
  HistoryContinuationPoints sessionCPs;
  // Signal completion through a heap-allocated, reference-counted promise rather
  // than a stack-local condition_variable: the service completes on a pool thread,
  // and a stack condition_variable would be destroyed by this thread the moment
  // the wait returns while the pool thread is still inside notify_* (the
  // pthread_cond_destroy data race). The test only inspects capturedLocales, so a
  // bare completion signal suffices.
  auto donePromise = std::make_shared<std::promise<void>>();
  auto doneFuture = donePromise->get_future();

  std::vector<LocaleId> locales;
  locales.push_back(LocaleId{"en"});
  locales.push_back(LocaleId{"de"});

  auto service = HistoryReadService::create(h.sessionInfo,
    locales,
    0,
    std::move(request),
    sessionCPs,
    h.threadPool.get_executor(),
    [donePromise](HistoryReadService::HistoryReadServiceResponse) { donePromise->set_value(); });

  ASSERT_EQ(doneFuture.wait_for(3s), std::future_status::ready) << "Service did not complete within timeout";

  // Verify locales were passed to the context.
  {
    std::lock_guard capLock(captureMtx);
    ASSERT_EQ(capturedLocales.size(), 2u);
    EXPECT_EQ(std::string(capturedLocales[0]), "en");
    EXPECT_EQ(std::string(capturedLocales[1]), "de");
  }
}

// ---------------------------------------------------------------------------
// Test 18: Null NodeId returns BadNodeIdInvalid
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-020, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, BadNodeIdInvalid)
{
  TestHarness h;
  h.setup();

  auto request = make_read_raw_request({NodeId{}});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadNodeIdInvalid});
}

// ---------------------------------------------------------------------------
// Test 19: Non-existent NodeId returns BadNodeIdUnknown
// ---------------------------------------------------------------------------
// @relation(AC-SVR-ATTR-HREAD-021-NODEIDUNKNOWN, scope=function)
TEST(HistoryReadServiceTests, BadNodeIdUnknown)
{
  TestHarness h;
  h.setup();

  // Use a NodeId in the test namespace that was never created.
  auto request = make_read_raw_request({NodeId{h.nsIndex, uint32_t{99999}}});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadNodeIdUnknown});
}

// ---------------------------------------------------------------------------
// Test 20: Fabricated continuation point bytes return BadContinuationPointInvalid
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-025, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, BadContinuationPointInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  // Set garbage continuation point bytes.
  request.nodes_to_read()[0].continuation_point() = ByteString{0xDE, 0xAD, 0xBE, 0xEF};

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
}

// ---------------------------------------------------------------------------
// Test 21: Out-of-range TimestampsToReturn returns BadTimestampsToReturnInvalid
// ---------------------------------------------------------------------------
// clang-format off
// A traceability marker is parsed as one comment line; wrapping it splits the relation list and
// check_strictdoc.sh fails on the fragment.
// @relation(AC-SVR-ATTR-HREAD-017-TIMESTAMPSTORETURN-INVALID, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
// clang-format on
TEST(HistoryReadServiceTests, BadTimestampsToReturnInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  auto request = make_read_raw_request({nodeId});
  request.timestamps_to_return() = static_cast<TimestampsToReturn>(99);

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadTimestampsToReturnInvalid));
}

// ---------------------------------------------------------------------------
// Test 22: ReleaseContinuationPoints frees the CP so reuse gets BadContinuationPointInvalid
// ---------------------------------------------------------------------------
// @relation(SVR-ATTR-HREAD-006, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST(HistoryReadServiceTests, ReleaseContinuationPoints)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  // Delegate returns a cursor on the first call to produce a continuation point.
  std::atomic<int> callCount{0};
  h.delegate->set_on_read_raw(
    [&callCount](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      int call = callCount.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        if (call == 0)
          success.cursor = std::string("more-data");
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // Step 1: Initial read - gets a continuation point.
  HistoryContinuationPoints sessionCPs;
  auto request1 = make_read_raw_request({nodeId});
  auto result1 = h.run_service(std::move(request1), sessionCPs);

  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 1u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty());
  auto cpBytes = response1->results()[0].continuation_point();

  // Move CPs into session map (as the session would do).
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs.emplace(id, std::move(cp));
  }

  // Step 2: Release the continuation point.
  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.release_continuation_points() = true;
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = nodeId;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), sessionCPs);
  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  EXPECT_TRUE(response2->response_header().service_result().is_good());

  // Step 3: Try to reuse the same CP bytes - should be invalid now.
  HistoryReadRequest request3;
  request3.request_header().request_handle() = 3;
  request3.timestamps_to_return() = TimestampsToReturn::Both;
  request3.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request3.release_continuation_points() = false;
  request3.nodes_to_read().resize(1);
  request3.nodes_to_read()[0].node_id() = nodeId;
  request3.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result3 = h.run_service(std::move(request3), sessionCPs);
  auto* response3 = get_history_response(result3.response);
  ASSERT_NE(response3, nullptr);
  ASSERT_EQ(response3->results().size(), 1u);
  EXPECT_EQ(response3->results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
}

// ---------------------------------------------------------------------------
// Test 22b: releaseContinuationPoints on a FRESH read (no continuation point) returns
// Bad_ContinuationPointInvalid per item - NOT a blanket Good. OPC 10000-11 section 6.3: an operation
// whose continuation point is missing or invalid shall return Bad_ContinuationPointInvalid. This
// is exactly the UACTT DetectUAServices HistoryRead probe (fresh ReadRaw + release=true), which
// a blanket-Good fast-path wrongly passed (F70). No delegate call should be made.
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, ReleaseContinuationPointsOnFreshReadReturnsBadContinuationPointInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  request.release_continuation_points() = true;  // fresh read (no CP) + release

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
  EXPECT_TRUE(response->results()[0].continuation_point().empty());
  EXPECT_EQ(delegateCalls.load(), 0) << "release path must not call the history delegate";
}

// ---------------------------------------------------------------------------
// Test 22c: releaseContinuationPoints with an unknown/garbage continuation point returns
// Bad_ContinuationPointInvalid (the "invalid" arm of OPC 10000-11 section 6.3), again with no
// delegate call and no blanket Good.
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, ReleaseContinuationPointsWithUnknownCpReturnsBadContinuationPointInvalid)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      callback(BatchResult<NamespaceHistoryDelegate::ReadRawItemResult>{});
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request.release_continuation_points() = true;
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  request.nodes_to_read()[0].continuation_point() = ByteString{0xDE, 0xAD, 0xBE, 0xEF};

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
  EXPECT_EQ(delegateCalls.load(), 0) << "release path must not call the history delegate";
}

// ---------------------------------------------------------------------------
// Test 23: Mixed namespace dispatch - delegate namespace succeeds, ns0 gets unsupported
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, MixedNamespaceDispatch)
{
  TestHarness h;
  h.setup();

  auto nodeIdWithDelegate = h.create_variable_with_history(100);

  // Namespace 0 node: ServerStatus_State (ns=0, i=2259) - a well-known variable with no history delegate.
  NodeId ns0Node{uint16_t{0}, uint32_t{2259}};

  // Set delegate to return Good for the test namespace item.
  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = 42;
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeIdWithDelegate, ns0Node});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good())
    << "Service-level result should be Good";
  ASSERT_EQ(response->results().size(), 2u);

  // The test namespace item should succeed.
  EXPECT_TRUE(response->results()[0].status_code().is_good()) << "Item in delegate namespace should succeed";

  // The ns0 item should get BadHistoryOperationUnsupported (no history delegate for ns0).
  EXPECT_EQ(response->results()[1].status_code(), StatusCode{Status::BadHistoryOperationUnsupported})
    << "Item in namespace 0 (no delegate) should get BadHistoryOperationUnsupported";
}

// ---------------------------------------------------------------------------
// ReadProcessedDetails: turnkey calculator path (delegate supplies raw, the
// service runs the built-in Part-13 AggregateCalculator).
// ---------------------------------------------------------------------------

namespace
{
// Stages a fixed Good raw series at `base + {2,5,12,15,18} s` with values
// {10,20,30,40,50} for every requested item, the store answering each read with @p code.
void stage_processed_raw_series(
  FakeNamespaceHistoryDelegate& delegate, DateTime base, StatusCode code = StatusCode{Status::Good})
{
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };
  delegate.set_on_read_raw(
    [at, code](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      // batchStatus defaults to Good (a VoidResult constructed with a Good
      // StatusCode throws - leave it default).
      for (size_t i = 0; i < items.size(); ++i)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        const int64_t times[] = {2, 5, 12, 15, 18};
        const int32_t vals[] = {10, 20, 30, 40, 50};
        for (size_t k = 0; k < 5; ++k)
          success.values.push_back(DataValue{Variant{vals[k]}, StatusCode{Status::Good}, at(times[k])});
        batch.items.push_back(NamespaceHistoryDelegate::ReadRawItemResult{std::move(success), code});
      }
      callback(std::move(batch));
    });
}
}  // namespace

TEST(HistoryReadServiceTests, ReadProcessedTurnkeyCountAcrossIntervals)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(200);

  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);

  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  // Two 10s intervals: [0,10) has 2 values, [10,20) has 3.
  auto request = make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Count), at(0), at(20), 10000.0);
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());

  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  auto& values = histData->data_values().payload();
  ASSERT_EQ(values.size(), 2u);
  const int32_t* count0 = values[0].value().try_as<int32_t>();
  const int32_t* count1 = values[1].value().try_as<int32_t>();
  ASSERT_NE(count0, nullptr);
  ASSERT_NE(count1, nullptr);
  EXPECT_EQ(*count0, 2);
  EXPECT_EQ(*count1, 3);
}

// The per-node interval cap bounds one node; a request naming many nodes shares one budget of the same
// size, so it cannot have the server compute that many aggregate values for each of them.
// @relation(AC-SVR-HIST-READ-006-B-PROCESSED-VALUES-BOUNDED-PER-REQUEST, scope=function)
TEST(HistoryReadServiceTests, ReadProcessedNodesShareOneAggregateValueBudget)
{
  TestHarness h;
  h.setup();
  const auto first = h.create_variable_with_history(210);
  const auto second = h.create_variable_with_history(211);

  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);

  // 600 s at 1 ms: 600,000 intervals per node. One node fits the budget; the second would exceed it.
  auto request = make_read_processed_request(first,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count),
    base,
    DateTime{base.value() + std::chrono::seconds{600}},
    1.0,
    /*aggregateCount*/ 2);
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[1].node_id() = second;
  auto result = h.run_service(std::move(request), 30s);  // 600,000 values are computed

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  EXPECT_EQ(histData->data_values().size(), 600000u);
  EXPECT_EQ(response->results()[1].status_code().as_status(), Status::BadTooManyOperations);
  ASSERT_NE(response->results()[1].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[1].status_code().shared_detail()->code, "ProcessedValueBudgetExhausted")
    << "the request's budget, not the per-Node limit, refused the second Node";
  EXPECT_EQ(response->results()[1].history_data().get(), nullptr);
}

TEST(HistoryReadServiceTests, ReadProcessedTurnkeyAverageSingleInterval)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(201);

  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);

  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  // One interval over the whole window: Average of {10,20,30,40,50} = 30.
  auto request = make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Average), at(0), at(20), 0.0);
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  auto& values = histData->data_values().payload();
  ASSERT_EQ(values.size(), 1u);
  const double* avg = values[0].value().try_as<double>();
  ASSERT_NE(avg, nullptr);
  EXPECT_NEAR(*avg, 30.0, 1e-6);
}

// Covers SVR-HIST-AGG-008 (coverage-audit retag).
TEST(HistoryReadServiceTests, ReadProcessedUnsupportedAggregateReturnsBadAggregateNotSupported)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(202);

  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);

  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  // 99999 is not a registered aggregate function.
  auto request = make_read_processed_request(nodeId, 99999u, at(0), at(20), 10000.0);
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadAggregateNotSupported});
}

// Covers SVR-HIST-AGG-007 (coverage-audit retag).
TEST(HistoryReadServiceTests, ReadProcessedAggregateListMismatchIsServiceError)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(203);
  DateTime base = DateTime::now();

  // aggregateCount = 2 but only one node-to-read => BadAggregateListMismatch.
  auto request = make_read_processed_request(nodeId,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count),
    DateTime{base.value()},
    DateTime{base.value() + std::chrono::seconds{20}},
    10000.0,
    /*aggregateCount=*/2);
  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(has_service_result(result.response, Status::BadAggregateListMismatch));
}

// @relation(AC-SVR-HIST-AGG-002-CONFIG-INVARIANT, scope=function)
TEST(HistoryReadServiceTests, InvalidAggregateConfigurationReturnsRichBadAggregateInvalidInputs)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(1202);
  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);

  auto run = [&](uint8_t percentGood, uint8_t percentBad)
  {
    auto request = make_read_processed_request(nodeId,
      static_cast<uint32_t>(ObjectId::AggregateFunction_Average),
      base,
      DateTime{base.value() + std::chrono::seconds{20}},
      0.0);
    auto& details = dynamic_cast<ReadProcessedDetails&>(*request.history_read_details());
    details.aggregate_configuration().use_server_capabilities_defaults() = false;
    details.aggregate_configuration().percent_data_good() = percentGood;
    details.aggregate_configuration().percent_data_bad() = percentBad;
    return h.run_service(std::move(request));
  };

  for (const auto [percentGood, percentBad] :
    {std::pair<uint8_t, uint8_t>{0, 80}, std::pair<uint8_t, uint8_t>{101, 100}})
  {
    auto result = run(percentGood, percentBad);
    auto* response = get_history_response(result.response);
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    const auto& operation = response->results()[0];
    EXPECT_EQ(operation.status_code(), StatusCode{Status::BadAggregateInvalidInputs});
    ASSERT_NE(operation.status_code().shared_detail(), nullptr);
    EXPECT_EQ(operation.status_code().shared_detail()->code, "AggregateConfigurationInvalid");
    EXPECT_EQ(operation.history_data().get(), nullptr);
  }

  auto valid = run(20, 80);
  auto* validResponse = get_history_response(valid.response);
  ASSERT_NE(validResponse, nullptr);
  ASSERT_EQ(validResponse->results().size(), 1u);
  EXPECT_TRUE(validResponse->results()[0].status_code().is_good());
  EXPECT_NE(dynamic_cast<HistoryData*>(validResponse->results()[0].history_data().get()), nullptr);
}

// @relation(AC-SVR-HIST-AGG-007-LIST-MISMATCH, scope=function)
// @relation(AC-SVR-HIST-AGG-008-UNSUPPORTED, scope=function)
TEST(HistoryReadServiceTests, RestoredAggregateServiceErrorsAreExact)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(1203);
  DateTime base = DateTime::now();
  stage_processed_raw_series(*h.delegate, base);
  const DateTime end{base.value() + std::chrono::seconds{20}};

  auto mismatch = make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Count), base, end, 10000.0, 2);
  auto mismatchResult = h.run_service(std::move(mismatch));
  EXPECT_TRUE(has_service_result(mismatchResult.response, Status::BadAggregateListMismatch));

  auto unknown = make_read_processed_request(nodeId, 99999u, base, end, 10000.0);
  auto unknownResult = h.run_service(std::move(unknown));
  auto* unknownResponse = get_history_response(unknownResult.response);
  ASSERT_NE(unknownResponse, nullptr);
  ASSERT_EQ(unknownResponse->results().size(), 1u);
  EXPECT_EQ(unknownResponse->results()[0].status_code(), StatusCode{Status::BadAggregateNotSupported});
  EXPECT_EQ(unknownResponse->results()[0].history_data().get(), nullptr);

  auto supported = make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Count), base, end, 10000.0);
  auto supportedResult = h.run_service(std::move(supported));
  auto* supportedResponse = get_history_response(supportedResult.response);
  ASSERT_NE(supportedResponse, nullptr);
  ASSERT_EQ(supportedResponse->results().size(), 1u);
  EXPECT_TRUE(supportedResponse->results()[0].status_code().is_good());
  EXPECT_NE(dynamic_cast<HistoryData*>(supportedResponse->results()[0].history_data().get()), nullptr);
}

TEST(HistoryReadServiceTests, ReadProcessedNoDelegateReturnsUnsupported)
{
  TestHarness h;
  h.setup(/*withDelegate=*/false);
  auto nodeId = h.create_variable_with_history(204);
  DateTime base = DateTime::now();

  auto request = make_read_processed_request(nodeId,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count),
    DateTime{base.value()},
    DateTime{base.value() + std::chrono::seconds{20}},
    10000.0);
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// Covers SVR-HIST-AGG-025: ReadProcessed with startTime == endTime is a service-level Bad_InvalidArgument.
TEST(HistoryReadServiceTests, ReadProcessedStartEqualsEndReturnsBadInvalidArgument)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(205);
  DateTime base = DateTime::now();

  auto request = make_read_processed_request(nodeId,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count),
    DateTime{base.value()},
    DateTime{base.value()},  // start == end
    10000.0);
  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadInvalidArgument));
}

// Covers SVR-HIST-AGG-027: ReadProcessed requires Source timestamps; Server/Both are rejected.
TEST(HistoryReadServiceTests, ReadProcessedNonSourceTimestampsReturnsBadTimestampsToReturnInvalid)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(206);
  DateTime base = DateTime::now();

  auto request = make_read_processed_request(nodeId,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count),
    DateTime{base.value()},
    DateTime{base.value() + std::chrono::seconds{20}},
    10000.0);
  request.timestamps_to_return() = TimestampsToReturn::Server;
  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadTimestampsToReturnInvalid));
}

// ---------------------------------------------------------------------------
// ReadAnnotationDataDetails: annotations are read from the delegate at the
// requested timestamps (order-preserving); unsupported nodes => unsupported.
// ---------------------------------------------------------------------------

// Covers SVR-HIST-ANN-002, SVR-HIST-ANN-003 (coverage-audit retag).
TEST(HistoryReadServiceTests, ReadAnnotationDataReturnsAnnotationsInOrder)
{
  TestHarness h;
  h.setup();
  auto nodeId = h.create_variable_with_history(300);

  DateTime base = DateTime::now();
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };
  const std::vector<DateTime> reqTimes = {at(2), at(5), at(9)};

  // The delegate returns one Annotation-typed DataValue per requested timestamp, in order; here the
  // payload value encodes the request index so the test can assert order preservation.
  h.delegate->set_on_read_annotations(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAnnotationItem>
        items,
      NamespaceHistoryDelegate::ReadAnnotationCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadAnnotationItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAnnotationSuccess success;
        for (size_t i = 0; i < item.reqTimes.size(); ++i)
          success.values.push_back(
            DataValue{Variant{static_cast<int32_t>(100 + i)}, StatusCode{Status::Good}, item.reqTimes[i]});
        batch.items.push_back(NamespaceHistoryDelegate::ReadAnnotationItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_read_annotation_request(nodeId, reqTimes));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  auto& values = histData->data_values().payload();
  ASSERT_EQ(values.size(), reqTimes.size());
  for (size_t i = 0; i < values.size(); ++i)
  {
    const int32_t* marker = values[i].value().try_as<int32_t>();
    ASSERT_NE(marker, nullptr);
    EXPECT_EQ(*marker, static_cast<int32_t>(100 + i)) << "annotation order must match req_times";
  }
}

// Covers SVR-HIST-ANN-004 (coverage-audit retag).
TEST(HistoryReadServiceTests, ReadAnnotationDataUnsupportedDelegateReturnsUnsupported)
{
  TestHarness h;
  h.setup();  // delegate present but without an annotation handler => default unsupported
  auto nodeId = h.create_variable_with_history(301);
  DateTime base = DateTime::now();

  auto result =
    h.run_service(make_read_annotation_request(nodeId, {DateTime{base.value() + std::chrono::seconds{2}}}));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

TEST(HistoryReadServiceTests, ReadAnnotationDataNoDelegateReturnsUnsupported)
{
  TestHarness h;
  h.setup(/*withDelegate=*/false);
  auto nodeId = h.create_variable_with_history(302);
  DateTime base = DateTime::now();

  auto result =
    h.run_service(make_read_annotation_request(nodeId, {DateTime{base.value() + std::chrono::seconds{2}}}));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
}

// @relation(AC-SVR-HIST-ANN-004-UNSUPPORTED, scope=function)
TEST(HistoryReadServiceTests, UnsupportedAnnotationReadIsNeverReportedAsGoodEmptyHistory)
{
  for (const bool withDelegate : {true, false})
  {
    TestHarness h;
    h.setup(withDelegate);
    auto nodeId = h.create_variable_with_history(withDelegate ? 303 : 304);
    const DateTime requested = DateTime::now();

    auto result = h.run_service(make_read_annotation_request(nodeId, {requested}));
    auto* response = get_history_response(result.response);
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadHistoryOperationUnsupported});
    EXPECT_EQ(response->results()[0].history_data().get(), nullptr);
  }
}

// ---------------------------------------------------------------------------
// Whole-request validation failures must be delivered as a ServiceFault, not as a
// HistoryReadResponse carrying the bad code (Part 4 section 7.34; CTT Read Raw Err-001/003/026/027).
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, EmptyRequestReturnsServiceFault)
{
  TestHarness h;
  h.setup();

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  // nodes_to_read is empty.

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadNothingToDo));
  EXPECT_EQ(get_history_response(result.response), nullptr) << "expected a ServiceFault, not a response";
}

// TimestampsToReturn=Neither is a valid enumerator that value HistoryRead forbids. OPC 10000-11 4.5 rejects
// it with Bad_TimestampsToReturnInvalid as a ServiceFault (SVR-ATTR-HREAD-004).
// @relation(AC-SVR-ATTR-HREAD-004-NEITHER-INVALID, scope=function)
TEST(HistoryReadServiceTests, TimestampsToReturnNeitherReturnsBadTimestampsToReturnInvalidServiceFault)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);
  auto request = make_read_raw_request({nodeId});
  request.timestamps_to_return() = TimestampsToReturn::Neither;

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadTimestampsToReturnInvalid));
}

// An out-of-range TimestampsToReturn value is likewise rejected as a ServiceFault (CTT Err-003).
TEST(HistoryReadServiceTests, TimestampsToReturnOutOfRangeReturnsServiceFault)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);
  auto request = make_read_raw_request({nodeId});
  request.timestamps_to_return() = static_cast<TimestampsToReturn>(0x123);

  auto result = h.run_service(std::move(request));
  EXPECT_TRUE(is_service_fault(result.response, Status::BadTimestampsToReturnInvalid));
}

// TimestampsToReturn=Source must strip the ServerTimestamp the delegate populated (CTT Read Raw 001).
TEST(HistoryReadServiceTests, SourceTimestampsOnlyStripsServerTimestamp)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(7);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  request.timestamps_to_return() = TimestampsToReturn::Source;

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  ASSERT_EQ(histData->data_values().size(), 1u);
  auto& dv = histData->data_values()[0];
  EXPECT_TRUE(dv.source_timestamp().has_value()) << "Source requested -> SourceTimestamp kept";
  EXPECT_FALSE(dv.server_timestamp().has_value()) << "Source requested -> ServerTimestamp stripped";
}

// An empty raw interval with no bounds requested yields Good_NoData (Part 11 section 6.4.3.2; CTT Read Raw
// 006).
TEST(HistoryReadServiceTests, EmptyRawRangeReturnsGoodNoData)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      // Return success with no values and no cursor (the empty-interval case).
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  auto* details = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(details, nullptr);
  details->return_bounds() = false;

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::GoodNoData});
}

// Part 11 section 6.5.2.2 distinguishes an empty event range (operation-level Good_NoData) from a returned
// Event whose historian lacks one declared field (per-field Bad_NoData). This is the empty-range
// control at the public service boundary and also proves the EventType membership lookup runs before
// the delegate even when the delegate returns no rows.
// @relation(AC-SVR-HIST-READ-004-EVENT-NODATA, scope=function)
TEST(HistoryReadServiceTests, EmptyEventRangeReturnsGoodNoData)
{
  TestHarness h;
  h.setup();

  const auto nodeId = h.create_object_with_history_read(101);
  std::atomic<bool> declaredFieldStatusReceived{false};
  h.delegate->set_on_read_events(
    [&declaredFieldStatusReceived](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      if (items.size() == 1 && items[0].selectClauseModelStatuses.size() == 1 &&
          items[0].selectClauseModelStatuses[0].is_good())
      {
        declaredFieldStatusReceived.store(true);
      }
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadEventsSuccess{});
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand select;
  select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  select.browse_path().push_back(QualifiedName{0, "Message"});
  select.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(select));
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::GoodNoData});
  EXPECT_TRUE(declaredFieldStatusReceived.load());
  const auto* eventHistory = dynamic_cast<const HistoryEvent*>(response->results()[0].history_data().get());
  ASSERT_NE(eventHistory, nullptr);
  EXPECT_TRUE(eventHistory->events().empty());
}

namespace
{
// How a store answers a read of one Node that found no data: with @ref code, holding an empty result unless
// @ref holdsResult is false.
struct EmptyAnswer
{
  StatusCode code;
  bool holdsResult{true};
};

// The store's answer @p answer to a read that found no data.
template<typename Success>
Result<Success> empty_answer(const EmptyAnswer& answer)
{
  if (!answer.holdsResult)
  {
    return Result<Success>{answer.code};
  }
  return Result<Success>{Success{}, answer.code};
}

// The four answers to a read that found no data the tests below give, each with the code a client is answered
// for it.
struct NoDataCase
{
  const char* name;
  EmptyAnswer answer;
  StatusCode answered;
};

std::vector<NoDataCase> no_data_cases()
{
  return {{"plain Good", {StatusCode{Status::Good}}, StatusCode{Status::GoodNoData}},
    {"a Good subcode", {StatusCode{Status::GoodLocalOverride}}, StatusCode{Status::GoodLocalOverride}},
    {"Uncertain with an empty result",
      {StatusCode{Status::UncertainNoCommunicationLastUsableValue}},
      StatusCode{Status::UncertainNoCommunicationLastUsableValue}},
    {"Uncertain holding no result",
      {StatusCode{Status::UncertainNoCommunicationLastUsableValue}, false},
      StatusCode{Status::UncertainNoCommunicationLastUsableValue}}};
}

// A ReadEventDetails request for @p nodeIds selecting BaseEventType's Message.
HistoryReadRequest make_read_events_request(const std::vector<NodeId>& nodeIds)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand select;
  select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  select.browse_path().push_back(QualifiedName{0, "Message"});
  select.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(select));
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(nodeIds.size());
  for (std::size_t i = 0; i < nodeIds.size(); ++i)
  {
    request.nodes_to_read()[i].node_id() = nodeIds[i];
  }
  return request;
}

// Expects the operation results of @p response to be the codes @p cases answer, in order.
void expect_no_data_codes(const HistoryReadResponse& response, const std::vector<NoDataCase>& cases)
{
  ASSERT_EQ(response.results().size(), cases.size());
  for (std::size_t i = 0; i < cases.size(); ++i)
  {
    const auto& status = response.results()[i].status_code();
    EXPECT_EQ(status.value(), cases[i].answered.value())
      << "the store answered " << cases[i].name << ": " << to_string(status);
  }
}
}  // namespace

// OPC 10000-11 6.5.3.2 asks the Server for Good_NoData when a raw read finds no data; the SDK writes it only
// over the store's plain Good, so a Good code of the store's own and an Uncertain code are answered as given.
// @relation(AC-COMP-SVR-STATUS-ROUTING-03-GOOD-NO-DATA-ONLY-OVER-PLAIN-GOOD, scope=function)
TEST(HistoryReadServiceTests, AnEmptyRawReadIsAnsweredGoodNoDataOnlyOverTheStoresPlainGood)
{
  TestHarness h;
  h.setup();
  const auto cases = no_data_cases();
  std::vector<NodeId> nodeIds;
  std::map<NodeId, EmptyAnswer> answers;
  for (std::size_t i = 0; i < cases.size(); ++i)
  {
    nodeIds.push_back(h.create_variable_with_history(static_cast<uint32_t>(110 + i)));
    answers.emplace(nodeIds.back(), cases[i].answer);
  }
  h.delegate->set_on_read_raw(
    [answers](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        batch.items.push_back(
          empty_answer<NamespaceHistoryDelegate::HistoryReadRawSuccess>(answers.at(item.nodeId)));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeIds[0], nodeIds[1], nodeIds[2], nodeIds[3]});
  auto* details = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(details, nullptr);
  details->return_bounds() = false;
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  expect_no_data_codes(*response, cases);
}

// The same rule for an Event read that finds no Events (OPC 10000-11 6.5.2.2).
// @relation(AC-COMP-SVR-STATUS-ROUTING-03-GOOD-NO-DATA-ONLY-OVER-PLAIN-GOOD, scope=function)
TEST(HistoryReadServiceTests, AnEmptyEventReadIsAnsweredGoodNoDataOnlyOverTheStoresPlainGood)
{
  TestHarness h;
  h.setup();
  const auto cases = no_data_cases();
  std::vector<NodeId> nodeIds;
  std::map<NodeId, EmptyAnswer> answers;
  for (std::size_t i = 0; i < cases.size(); ++i)
  {
    nodeIds.push_back(h.create_object_with_history_read(static_cast<uint32_t>(120 + i)));
    answers.emplace(nodeIds.back(), cases[i].answer);
  }
  h.delegate->set_on_read_events(
    [answers](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      for (const auto& item : items)
      {
        batch.items.push_back(
          empty_answer<NamespaceHistoryDelegate::HistoryReadEventsSuccess>(answers.at(item.nodeId)));
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_read_events_request(nodeIds));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  expect_no_data_codes(*response, cases);
}

// A store's Uncertain answer to a raw read that holds data reaches the client with that data and its code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-HISTORY-READ-PASSES-AN-UNCERTAIN-ANSWER-WITH-ITS-DATA, scope=function)
TEST(HistoryReadServiceTests, AnUncertainRawAnswerIsAnsweredWithItsData)
{
  TestHarness h;
  h.setup();
  const auto nodeId = h.create_variable_with_history(130);
  const StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue};
  h.delegate->set_on_read_raw(
    [uncertain](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (std::size_t i = 0; i < items.size(); ++i)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue value{Variant{int32_t{17}}, StatusCode{Status::Good}, DateTime::now()};
        value.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(value));
        batch.items.push_back(NamespaceHistoryDelegate::ReadRawItemResult{std::move(success), uncertain});
      }
      callback(std::move(batch));
    });

  auto result = h.run_service(make_read_raw_request({nodeId}));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& status = response->results()[0].status_code();
  EXPECT_EQ(status.value(), uncertain.value()) << to_string(status);
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "the Uncertain answer's data was dropped";
  ASSERT_EQ(histData->data_values().size(), 1u);
  const int32_t* value = histData->data_values().payload()[0].value().try_as<int32_t>();
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(*value, 17);

  const StatusCode dataSubnormal{Status::UncertainDataSubNormal};
  h.delegate->set_on_read_raw(
    [dataSubnormal](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (std::size_t index = 0; index < items.size(); ++index)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        for (const auto supplied : {int32_t{17}, int32_t{23}})
        {
          DataValue data{Variant{supplied}, StatusCode{Status::Good}, DateTime::now()};
          data.server_timestamp() = DateTime::now();
          success.values.push_back(std::move(data));
        }
        batch.items.emplace_back(std::move(success), dataSubnormal);
      }
      callback(std::move(batch));
    });

  auto declared = h.run_service(make_read_raw_request({nodeId}));
  auto* declaredResponse = get_history_response(declared.response);
  ASSERT_NE(declaredResponse, nullptr);
  ASSERT_EQ(declaredResponse->results().size(), 1U);
  EXPECT_EQ(declaredResponse->results()[0].status_code().value(), dataSubnormal.value());
  auto* declaredData = dynamic_cast<HistoryData*>(declaredResponse->results()[0].history_data().get());
  ASSERT_NE(declaredData, nullptr);
  ASSERT_EQ(declaredData->data_values().size(), 2U);
  EXPECT_EQ(declaredData->data_values()[0].value(), Variant{int32_t{17}});
  EXPECT_EQ(declaredData->data_values()[1].value(), Variant{int32_t{23}});
}

// The SDK computes a processed read's values from the store's raw read, so the operation is answered with
// that read's code: a Good subcode stands rather than becoming plain Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-03-A-PROCESSED-READ-KEEPS-THE-STORES-CODE, scope=function)
TEST(HistoryReadServiceTests, AProcessedReadIsAnsweredWithTheCodeOfTheStoresRawRead)
{
  TestHarness h;
  h.setup();
  const auto nodeId = h.create_variable_with_history(203);
  const DateTime base = DateTime::now();
  const StatusCode overridden{Status::GoodLocalOverride};
  stage_processed_raw_series(*h.delegate, base, overridden);
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  auto result = h.run_service(make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Average), at(0), at(20), 0.0));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& status = response->results()[0].status_code();
  EXPECT_EQ(status.value(), overridden.value()) << to_string(status);
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  ASSERT_EQ(histData->data_values().size(), 1u);
  const double* average = histData->data_values().payload()[0].value().try_as<double>();
  ASSERT_NE(average, nullptr);
  EXPECT_NEAR(*average, 30.0, 1e-6);
}

// A store's Uncertain raw read under a processed read: the aggregates are computed from its data and the
// operation is answered with its code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-HISTORY-READ-PASSES-AN-UNCERTAIN-ANSWER-WITH-ITS-DATA, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-03-A-PROCESSED-READ-KEEPS-THE-STORES-CODE, scope=function)
TEST(HistoryReadServiceTests, AnUncertainRawReadUnderAProcessedReadIsAnsweredWithTheAggregates)
{
  TestHarness h;
  h.setup();
  const auto nodeId = h.create_variable_with_history(204);
  const DateTime base = DateTime::now();
  const StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue};
  stage_processed_raw_series(*h.delegate, base, uncertain);
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  auto result = h.run_service(make_read_processed_request(
    nodeId, static_cast<uint32_t>(ObjectId::AggregateFunction_Average), at(0), at(20), 0.0));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& status = response->results()[0].status_code();
  EXPECT_EQ(status.value(), uncertain.value()) << to_string(status);
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "the aggregates of the Uncertain answer's data were dropped";
  ASSERT_EQ(histData->data_values().size(), 1u);
  const double* average = histData->data_values()[0].value().try_as<double>();
  ASSERT_NE(average, nullptr);
  EXPECT_NEAR(*average, 30.0, 1e-6);

  const StatusCode dataSubnormal{Status::UncertainDataSubNormal};
  stage_processed_raw_series(*h.delegate, base, dataSubnormal);
  auto declared = h.run_service(make_read_processed_request(
    nodeId, utils::to_underlying(ObjectId::AggregateFunction_Average), at(0), at(20), 0.0));
  auto* declaredResponse = get_history_response(declared.response);
  ASSERT_NE(declaredResponse, nullptr);
  ASSERT_EQ(declaredResponse->results().size(), 1U);
  EXPECT_EQ(declaredResponse->results()[0].status_code().value(), dataSubnormal.value());
  auto* declaredData = dynamic_cast<HistoryData*>(declaredResponse->results()[0].history_data().get());
  ASSERT_NE(declaredData, nullptr);
  ASSERT_EQ(declaredData->data_values().size(), 1U);
  const double* declaredAverage = declaredData->data_values()[0].value().try_as<double>();
  ASSERT_NE(declaredAverage, nullptr);
  EXPECT_NEAR(*declaredAverage, 30.0, 1e-6);
}

// ---------------------------------------------------------------------------
// Authorization: per-node HistoryRead authz gate (Part 4 section 6.2.1).
//
// The static AccessLevel.HistoryRead bit advertises capability; effective RolePermissions
// are the enforcement gate. When ReadHistory is absent for the node, the item must come back
// BadUserAccessDenied AND the history
// delegate must never be read (the gate runs before dispatch).
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, HistoryReadDeniedByRolePermissionNotDispatched)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);
  auto node = h.sessionInfo->address_space().find_node_sync(nodeId);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::ReadHistory);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  // Track whether the delegate is ever read; it must not be when the gate denies.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "denied HistoryRead must not reach the history delegate";
}

// ---------------------------------------------------------------------------
// Stage-2 F1: a continuation-point RESUME must be re-authorized against the CURRENT identity.
// A stored continuation point carries no identity binding. Before the fix, the resume path pushed
// CP items straight past the per-node HistoryRead authz gate (which only ran for fresh reads), so a
// session re-activated as a lower-privilege identity could inherit a cursor created under a
// higher-privilege one and read history it can no longer access. The fix routes CP resumes through
// the same gate. Here HistoryRead is ALLOWED for the first read (which produces a CP) and then DENIED
// (simulating an ActivateSession identity downgrade) before the resume - the resume must come back
// BadUserAccessDenied and must NOT reach the history delegate.
// ---------------------------------------------------------------------------
TEST(HistoryReadServiceTests, ContinuationPointResumeIsReauthorizedAgainstCurrentIdentity)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  std::atomic<int> callCount{0};
  h.delegate->set_on_read_raw(
    [&callCount](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      const int call = callCount.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(call);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        if (call == 0)
          success.cursor = std::string("page2");  // first read: signal more data -> continuation point
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // Read 1 (authorized): produces a continuation point.
  HistoryContinuationPoints sessionCPs;
  auto result1 = h.run_service(make_read_raw_request({nodeId}), sessionCPs);
  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 1u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty());
  ASSERT_EQ(result1.continuationPoints.size(), 1u);
  ASSERT_EQ(callCount.load(), 1) << "first read must reach the delegate";

  // Move the CP into the session map (as the session would).
  auto cpBytes = response1->results()[0].continuation_point();
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs.emplace(id, std::move(cp));
  }

  // Simulate an ActivateSession identity downgrade: the same channel now has an identity carrying
  // no granted Roles, so the effective ReadHistory permission is absent.
  h.sessionInfo->set_access_identity_for_test(std::make_shared<AccessIdentity>(AccessIdentityKey{2},
    std::vector<NodeId>{},
    h.sessionInfo->user_identity(),
    h.sessionInfo->endpoint_security(),
    String{"urn:test:downgraded-client"}));

  // Read 2 (resume the CP under the downgraded identity): must be re-authorized and DENIED.
  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = nodeId;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), sessionCPs);
  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  ASSERT_EQ(response2->results().size(), 1u);
  EXPECT_EQ(response2->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied})
    << "a continuation-point resume must be re-authorized against the current identity, not bypassed";
  EXPECT_EQ(callCount.load(), 1) << "denied resume must NOT reach the history delegate a second time";
}

// Positive control: the default namespace RolePermissions grant ReadHistory, so a node that
// advertises HistoryRead still returns data. Proves the denial above is the access-control gate.
TEST(HistoryReadServiceTests, HistoryReadAllowedByDefaultRolePermissionsReturnsData)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(100);

  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(item.index);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  ASSERT_EQ(histData->data_values().size(), 1u);
  EXPECT_EQ(histData->data_values()[0].value().as<int32_t>(), 0);
}

// Fail-closed: a HistoryRead from a session with no committed AccessIdentity must
// deny every item (Bad_UserAccessDenied) and never read the history delegate (Part 4 section 6.2.1,
// invariant I4 - without a context the SDK cannot authorize, so it must not fall open). This
// exercises the fail-closed branch that a broadly permitted identity otherwise hides.
TEST(HistoryReadServiceTests, NoAuthorizerFailsClosed)
{
  TestHarness h;
  h.setup(/*withDelegate=*/true, ServerConfig{}, /*noAccessIdentity=*/true);

  auto nodeId = h.create_variable_with_history(100);

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_EQ(delegateCalls.load(), 0) << "identity-less session must not read the history delegate";
}

// ---------------------------------------------------------------------------
// The server publishes MaxReturnDataValues / MaxReturnEventValues on the Part-11 Mandatory
// HistoryServerCapabilities nodes, so a HistoryRead must honour them or the advertised capability is
// untrue.
//
// The cap is PER NODE PER REQUEST (OPC 10000-11 5.2: "the maximum number of values that can be
// returned by the Server for each HistoricalNode accessed during a request"), which is why these
// tests read several nodes in one request: an implementation that treated the limit as a per-request
// budget would divide it across the nodes, and a single-node fixture could not tell the two apart.
// ---------------------------------------------------------------------------

namespace
{
// Captures the maxValuesPerNode the service hands the delegate for each item of one request.
std::vector<uint32_t> capture_raw_caps(TestHarness& h, HistoryReadRequest request)
{
  std::mutex mtx;
  std::vector<uint32_t> caps;
  h.delegate->set_on_read_raw(
    [&mtx, &caps](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      {
        std::lock_guard lock(mtx);
        for (const auto& item : items)
        {
          caps.push_back(item.maxValuesPerNode);
        }
      }
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        batch.items.emplace_back(NamespaceHistoryDelegate::HistoryReadRawSuccess{});
      }
      callback(std::move(batch));
    });
  (void)h.run_service(std::move(request));
  std::lock_guard lock(mtx);
  return caps;
}

ServerConfig config_with_history_limits(uint32_t maxDataValues, uint32_t maxEventValues = 0)
{
  ServerConfig config;
  config.historyConfiguration.maxReturnDataValues = maxDataValues;
  config.historyConfiguration.maxReturnEventValues = maxEventValues;
  return config;
}
}  // namespace

// A configured MaxReturnDataValues bounds a client that asked for MORE, and does so on EVERY node of
// the request - not one node's worth shared between them.
TEST(HistoryReadServiceTests, MaxReturnDataValuesBoundsEachNodeOfTheRequest)
{
  TestHarness h;
  h.setup(/*withDelegate=*/true, config_with_history_limits(/*maxDataValues=*/10));

  auto nodeId1 = h.create_variable_with_history(100);
  auto nodeId2 = h.create_variable_with_history(101);
  auto nodeId3 = h.create_variable_with_history(102);

  // make_read_raw_request asks for 100 values per node; the server advertises 10.
  const auto caps = capture_raw_caps(h, make_read_raw_request({nodeId1, nodeId2, nodeId3}));

  ASSERT_EQ(caps.size(), 3u);
  for (size_t i = 0; i < caps.size(); ++i)
  {
    EXPECT_EQ(caps[i], 10u) << "node " << i
                            << ": the advertised per-node maximum must bound the client's request";
  }
}

// The client asking for FEWER than the server's maximum keeps its own number: the capability is a
// ceiling, not a quota to fill.
TEST(HistoryReadServiceTests, MaxReturnDataValuesLeavesASmallerClientRequestAlone)
{
  TestHarness h;
  h.setup(/*withDelegate=*/true, config_with_history_limits(/*maxDataValues=*/1000));

  auto nodeId = h.create_variable_with_history(100);
  const auto caps = capture_raw_caps(h, make_read_raw_request({nodeId}));  // asks for 100

  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0], 100u) << "a client request below the advertised maximum is not raised to it";
}

// numValuesPerNode = 0 means "all of them" (OPC 10000-11 6.4.3). With a server maximum configured,
// "all of them" becomes "up to the maximum, with a continuation point" - which the standard
// explicitly permits even where the client asked for everything.
TEST(HistoryReadServiceTests, MaxReturnDataValuesBoundsAnUnlimitedClientRequest)
{
  TestHarness h;
  h.setup(/*withDelegate=*/true, config_with_history_limits(/*maxDataValues=*/25));

  auto nodeId = h.create_variable_with_history(100);
  auto request = make_read_raw_request({nodeId});
  auto* details = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(details, nullptr);
  // ReadRawModifiedDetails needs 2 of {startTime, endTime, numValuesPerNode} specified; with the count
  // given up to "unlimited", BOTH times must be non-null (a null DateTime does not count as specified).
  details->num_values_per_node() = 0;  // "no limit"
  details->start_time() = DateTime::now();
  details->end_time() = DateTime::now();

  const auto caps = capture_raw_caps(h, std::move(request));

  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0], 25u) << "an unlimited client request is bounded by the advertised maximum";
}

// RATIFIED EXPECTATION CHANGE (DEF-6): the default MaxReturnDataValues is 10000, not 0, so an
// unconfigured server now caps an unlimited request at 10000. The 0-means-pass-through obligation
// keeps its own row below, with an explicit 0.
// @verifies AC-SVR-HIST-CAP-004-DEFAULT-RETURN-LIMITS-ARE-FINITE
TEST(HistoryReadServiceTests, DefaultMaxReturnDataValuesCapsAnUnlimitedRequestAtTenThousand)
{
  TestHarness h;
  h.setup();  // default ServerConfig: maxReturnDataValues == 10000

  auto nodeId = h.create_variable_with_history(100);
  auto request = make_read_raw_request({nodeId});
  auto* details = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(details, nullptr);
  details->num_values_per_node() = 0;
  details->start_time() = DateTime::now();  // both times non-null: 2 of 3 specified
  details->end_time() = DateTime::now();

  const auto caps = capture_raw_caps(h, std::move(request));

  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0], 10000u) << "the finite default bounds what one request can materialise";
}

// An explicit 0 remains a true pass-through: a server configured for "unlimited" keeps forwarding
// exactly what the client asked for, including "unlimited".
// @verifies AC-SVR-HIST-CAP-004-DEFAULT-RETURN-LIMITS-ARE-FINITE
TEST(HistoryReadServiceTests, ExplicitZeroMaxReturnDataValuesForwardsTheClientRequestUnchanged)
{
  TestHarness h;
  h.setup(/*withDelegate=*/true, config_with_history_limits(/*maxDataValues=*/0));

  auto nodeId = h.create_variable_with_history(100);
  auto request = make_read_raw_request({nodeId});
  auto* details = dynamic_cast<ReadRawModifiedDetails*>(request.history_read_details().get());
  ASSERT_NE(details, nullptr);
  details->num_values_per_node() = 0;
  details->start_time() = DateTime::now();
  details->end_time() = DateTime::now();

  const auto caps = capture_raw_caps(h, std::move(request));

  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0], 0u) << "an explicit 0 must leave an unlimited request unlimited";
}

// The clamp rule itself, stated once. 0 means "unbounded" on BOTH sides, which is why this is not a
// plain std::min: min(0, 10) would answer 0 and silently turn a configured maximum into no maximum.
TEST(HistoryReadServiceTests, EffectiveMaxValuesPerNodeTreatsZeroAsUnboundedOnEitherSide)
{
  using ua::server::history_read_validation::effective_max_values_per_node;

  EXPECT_EQ(effective_max_values_per_node(/*requested=*/0, /*serverLimit=*/0), 0u)
    << "neither side bounded -> unbounded";
  EXPECT_EQ(effective_max_values_per_node(/*requested=*/0, /*serverLimit=*/10), 10u)
    << "an unlimited client request takes the server's cap";
  EXPECT_EQ(effective_max_values_per_node(/*requested=*/10, /*serverLimit=*/0), 10u)
    << "no server cap leaves the client's request alone";
  EXPECT_EQ(effective_max_values_per_node(/*requested=*/5, /*serverLimit=*/10), 5u) << "the stricter wins";
  EXPECT_EQ(effective_max_values_per_node(/*requested=*/50, /*serverLimit=*/10), 10u) << "the stricter wins";
  EXPECT_EQ(effective_max_values_per_node(/*requested=*/10, /*serverLimit=*/10), 10u) << "equal is equal";
}

// ---------------------------------------------------------------------------
// Continuation-point pressure must never reach a client that is only continuing.
// ---------------------------------------------------------------------------

// OPC 10000-4 7.6: continuing a halted operation reuses the point the server already issued, so it
// allocates nothing and can never be refused for want of continuation points. A plausible
// implementation counts every operation that consumes a continuation-point slot rather than only
// fresh allocations, and then refuses the continuation exactly when the session is holding its
// advertised maximum - which is when a long paginated read is most likely to be in flight. The
// session store is loaded to the advertised MaxHistoryContinuationPoints before the continuation is
// issued, and the resumed cursor is asserted so the Good status cannot come from a short circuit
// that skipped the delegate.
// @verifies AC-SVR-ATTR-CP-006-NEVER-NOCONTINUATIONPOINTS
TEST(HistoryReadServiceTests, ContinuingAHaltedReadAtTheContinuationPointLimitStillSucceeds)
{
  ServerConfig serverConfig;
  serverConfig.server_capabilities().maxHistoryContinuationPoints = 2;

  TestHarness h;
  h.setup(true, std::move(serverConfig));

  auto nodeId1 = h.create_variable_with_history(100);
  auto nodeId2 = h.create_variable_with_history(101);

  std::mutex captureMtx;
  std::vector<std::string> resumedCursors;

  h.delegate->set_on_read_raw(
    [&captureMtx, &resumedCursors](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(item.index);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        if (item.cursor.has_value())
        {
          std::lock_guard lock(captureMtx);
          const auto* str = std::any_cast<std::string>(&*item.cursor);
          resumedCursors.push_back(str ? *str : std::string{});
        }
        else
        {
          success.cursor = std::string("page2");  // more data remains -> a continuation point
        }
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // Fill the session's continuation-point store to the advertised maximum.
  HistoryContinuationPoints sessionCPs;
  auto result1 = h.run_service(make_read_raw_request({nodeId1, nodeId2}), sessionCPs);

  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 2u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty());
  ASSERT_EQ(result1.continuationPoints.size(), 2u);

  auto cpBytes = response1->results()[0].continuation_point();
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs.emplace(id, std::move(cp));
  }
  const auto& capabilities = h.sessionInfo->server_configuration().server_capabilities();
  ASSERT_EQ(sessionCPs.size(), static_cast<size_t>(capabilities.maxHistoryContinuationPoints))
    << "the store must be at its advertised limit for this test to mean anything";

  // Continue the first read while the store is full.
  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = nodeId1;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), sessionCPs);

  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  EXPECT_TRUE(response2->response_header().service_result().is_good());
  ASSERT_EQ(response2->results().size(), 1u);
  EXPECT_NE(response2->results()[0].status_code(), StatusCode{Status::BadNoContinuationPoints})
    << "continuation-point pressure must never be the answer to a continuation";
  EXPECT_TRUE(response2->results()[0].status_code().is_good()) << "the continuation must succeed";

  auto* histData = dynamic_cast<HistoryData*>(response2->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "a successful continuation must carry the next page";
  EXPECT_EQ(histData->data_values().size(), 1u);

  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(resumedCursors.size(), 1u) << "the continuation must have reached the delegate";
    EXPECT_EQ(resumedCursors[0], "page2") << "the stored cursor must be replayed, not a fresh read";
  }
}

// OPC 10000-4 5.10.3, HistoryRead-specific: a continuation that itself still has more data hands the
// client a point back. An implementation that treats that as a fresh allocation and checks it against
// the advertised maximum makes a long history read unfinishable while the session is holding its
// maximum - the exact case the rule exists for. Here the store is at a maximum of one when the
// continuation arrives, and the continuation still has a page left, so the naive accounting refuses.
// @verifies AC-SVR-ATTR-HREAD-030-NEVER-NOCONTINUATIONPOINTS-ON-CONTINUE
TEST(HistoryReadServiceTests, ContinuingAHistoryReadWithMoreDataAtTheLimitIsNeverRefusedForWantOfPoints)
{
  ServerConfig serverConfig;
  serverConfig.server_capabilities().maxHistoryContinuationPoints = 1;

  TestHarness h;
  h.setup(true, std::move(serverConfig));

  auto nodeId = h.create_variable_with_history(100);

  std::mutex captureMtx;
  std::vector<std::string> resumedCursors;

  h.delegate->set_on_read_raw(
    [&captureMtx, &resumedCursors](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(item.index);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        if (!item.cursor.has_value())
        {
          success.cursor = std::string("page2");
        }
        else
        {
          std::string received;
          if (const auto* str = std::any_cast<std::string>(&*item.cursor))
            received = *str;
          {
            std::lock_guard lock(captureMtx);
            resumedCursors.push_back(received);
          }
          if (received == "page2")
            success.cursor = std::string("page3");  // the continuation still has a page left
        }
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  HistoryContinuationPoints sessionCPs;
  auto result1 = h.run_service(make_read_raw_request({nodeId}), sessionCPs);

  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 1u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty());
  ASSERT_EQ(result1.continuationPoints.size(), 1u);

  auto cpBytes = response1->results()[0].continuation_point();
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs.emplace(id, std::move(cp));
  }
  const auto& capabilities = h.sessionInfo->server_configuration().server_capabilities();
  ASSERT_EQ(sessionCPs.size(), static_cast<size_t>(capabilities.maxHistoryContinuationPoints))
    << "the store must be at its advertised limit for this test to mean anything";

  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = nodeId;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), sessionCPs);

  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  ASSERT_EQ(response2->results().size(), 1u);
  EXPECT_NE(response2->results()[0].status_code(), StatusCode{Status::BadNoContinuationPoints})
    << "Bad_NoContinuationPoints is never the answer to a continuation";
  EXPECT_TRUE(response2->results()[0].status_code().is_good()) << "the continuation must succeed";
  EXPECT_FALSE(response2->results()[0].continuation_point().empty())
    << "the remainder must still be reachable: a point is handed back";
  EXPECT_EQ(result2.continuationPoints.size(), 1u);

  auto* histData = dynamic_cast<HistoryData*>(response2->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  EXPECT_EQ(histData->data_values().size(), 1u);

  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(resumedCursors.size(), 1u) << "the continuation must have reached the delegate";
    EXPECT_EQ(resumedCursors[0], "page2") << "the stored cursor must be replayed";
  }
}

// OPC 10000-11 6.4: a history continuation point ends on exactly two things - being passed back, or
// the Session closing. There is no idle timeout and no invalidation by other Session activity, so a
// client that does work between pages must still find its point usable; and when the Session does go
// away the delegate cursor the point pinned must be handed back, or a paginating client leaks server
// state on every disconnect. A plausible implementation reclaims points opportunistically on
// unrelated requests, or drops the store without releasing the cursors it owns. Both halves are
// asserted: the point survives intervening reads on another node and still resumes with its stored
// cursor, and destroying the Session's store (what Session closure does to it) releases the cursor -
// checked to be still held immediately beforehand, so the release is observably caused by the close.
// @verifies AC-SVR-ATTR-HREAD-013-POINT-LIFETIME
TEST(HistoryReadServiceTests, ContinuationPointSurvivesOtherActivityAndIsReleasedWhenTheSessionCloses)
{
  TestHarness h;
  h.setup();

  auto pagedNode = h.create_variable_with_history(100);
  auto otherNode = h.create_variable_with_history(101);

  std::mutex captureMtx;
  std::vector<std::string> resumedCursors;

  h.delegate->set_on_read_raw(
    [pagedNode, &captureMtx, &resumedCursors](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(item.index);
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        if (item.nodeId == pagedNode)
        {
          if (item.cursor.has_value())
          {
            std::lock_guard lock(captureMtx);
            const auto* str = std::any_cast<std::string>(&*item.cursor);
            resumedCursors.push_back(str ? *str : std::string{});
            // Still more to come, so a live point outlives the resume and can be observed at close.
            success.cursor = std::string("page3");
          }
          else
          {
            success.cursor = std::string("page2");
          }
        }
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // The Session's continuation-point store; destroying it is what Session closure does to it.
  optional<HistoryContinuationPoints> sessionCPs;
  sessionCPs.emplace();

  auto result1 = h.run_service(make_read_raw_request({pagedNode}), *sessionCPs);
  auto* response1 = get_history_response(result1.response);
  ASSERT_NE(response1, nullptr);
  ASSERT_EQ(response1->results().size(), 1u);
  EXPECT_TRUE(response1->results()[0].status_code().is_good());
  ASSERT_FALSE(response1->results()[0].continuation_point().empty());
  ASSERT_EQ(result1.continuationPoints.size(), 1u);

  auto cpBytes = response1->results()[0].continuation_point();
  for (auto& cp : result1.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs->emplace(id, std::move(cp));
  }
  ASSERT_EQ(sessionCPs->size(), 1u);

  // Unrelated Session activity plus elapsed time between pages: neither may end the point.
  for (int i = 0; i < 3; ++i)
  {
    auto other = h.run_service(make_read_raw_request({otherNode}), *sessionCPs);
    auto* otherResponse = get_history_response(other.response);
    ASSERT_NE(otherResponse, nullptr);
    ASSERT_EQ(otherResponse->results().size(), 1u);
    EXPECT_TRUE(otherResponse->results()[0].status_code().is_good());
  }
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(sessionCPs->size(), 1u) << "other Session activity must not invalidate the point";

  // First half: the point is still usable.
  HistoryReadRequest request2;
  request2.request_header().request_handle() = 2;
  request2.timestamps_to_return() = TimestampsToReturn::Both;
  request2.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  request2.nodes_to_read().resize(1);
  request2.nodes_to_read()[0].node_id() = pagedNode;
  request2.nodes_to_read()[0].continuation_point() = cpBytes;

  auto result2 = h.run_service(std::move(request2), *sessionCPs);
  auto* response2 = get_history_response(result2.response);
  ASSERT_NE(response2, nullptr);
  ASSERT_EQ(response2->results().size(), 1u);
  EXPECT_TRUE(response2->results()[0].status_code().is_good())
    << "a point is not ended by the wait or by unrelated activity";
  auto* histData = dynamic_cast<HistoryData*>(response2->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  EXPECT_EQ(histData->data_values().size(), 1u);
  {
    std::lock_guard lock(captureMtx);
    ASSERT_EQ(resumedCursors.size(), 1u) << "the resume must have reached the delegate";
    EXPECT_EQ(resumedCursors[0], "page2") << "the stored cursor must survive the wait intact";
  }

  ASSERT_EQ(result2.continuationPoints.size(), 1u);
  for (auto& cp : result2.continuationPoints)
  {
    auto id = cp.identifier();
    sessionCPs->emplace(id, std::move(cp));
  }
  ASSERT_EQ(sessionCPs->size(), 1u);

  auto cursorReleased = [&h](std::string_view wanted)
  {
    auto released = h.delegate->released_cursors();
    for (auto& cursor : released)
    {
      const auto* str = std::any_cast<std::string>(&cursor);
      if (str && *str == wanted)
        return true;
    }
    return false;
  };

  // Second half: still held now, released by the close - and not the other way round.
  ASSERT_FALSE(cursorReleased("page3")) << "a point held by a live Session must keep its cursor";
  sessionCPs.reset();  // Session closes
  EXPECT_TRUE(cursorReleased("page3")) << "closing the Session must release the point's cursor";
}

// The other Part 11 exception. OPC 10000-4 5.10.3.2 (Table 56) says a TimestampsToReturn of NEITHER is
// not valid and then immediately says OPC 10000-11 defines exceptions where the parameter shall be
// ignored; OPC 10000-11 4.5 gives one - for HistoricalEventNodes the parameter does not apply, because
// what comes back is dictated by the EventFilter, and NEITHER is only excluded "for any HistoryRead
// accessing HistoricalDataNodes". A plausible implementation validates timestampsToReturn once, up
// front, before it knows which HistoryReadDetails it is holding, and so refuses the whole request -
// throwing away an event read whose returned fields, including the Time that keys each record, never
// depended on the parameter at all.
// @verifies AC-SVR-ATTR-HREAD-005-PART11-TIMESTAMP-EXCEPTIONS
TEST(HistoryReadServiceTests, EventHistoryReadIgnoresTimestampsToReturnAndStillReturnsItsPart11Fields)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_object_with_history_read(500);
  const DateTime eventTime = DateTime::now();

  std::atomic<int> delegateCalls{0};
  std::atomic<bool> modelMembershipReceived{false};
  h.delegate->set_on_read_events(
    [eventTime, &delegateCalls, &modelMembershipReceived](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      delegateCalls.fetch_add(1);
      if (items.size() == 1 && items[0].selectClauseModelStatuses.size() == 2 &&
          items[0].selectClauseModelStatuses[0].is_good() && items[0].selectClauseModelStatuses[1].is_good())
      {
        modelMembershipReceived.store(true);
      }
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        // Field 0 is the Event's Time - the Part 11 timestamp that places the record.
        fields.event_fields().push_back(Variant{eventTime});
        fields.event_fields().push_back(Variant{uint16_t{7}});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  // Neither is what would otherwise drop both timestamps of a value history read
  // (TimestampsToReturnNeitherReturnsBadTimestampsToReturnInvalidServiceFault is the mirror of that rule
  // on the Raw path).
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  for (const std::string_view fieldName : {std::string_view{"Time"}, std::string_view{"Severity"}})
  {
    SimpleAttributeOperand select;
    select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    select.browse_path().push_back(QualifiedName{0, std::string{fieldName}});
    select.attribute_id() = utils::to_underlying(AttributeId::Value);
    details->filter().select_clauses().push_back(std::move(select));
  }
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));

  EXPECT_FALSE(is_service_fault(result.response, Status::BadTimestampsToReturnInvalid))
    << "ReadEventDetails is a Part 11 exception: timestampsToReturn must not be validated against it";
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an event history read must not be refused for timestampsToReturn";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(delegateCalls.load(), 1) << "the event read must actually have been performed";
  EXPECT_TRUE(modelMembershipReceived.load())
    << "HistoryRead must carry live EventType declaration status for each select clause";

  auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr) << "a successful event history read carries HistoryEvent";
  ASSERT_EQ(histEvent->events().size(), 1u);
  auto& fields = histEvent->events()[0].event_fields();
  ASSERT_EQ(fields.size(), 2u) << "the fields the EventFilter selected are what determines the reply";
  const DateTime* time = fields[0].try_as<DateTime>();
  ASSERT_NE(time, nullptr) << "the Event's Time field must survive: timestampsToReturn does not apply here";
  EXPECT_EQ(*time, eventTime);
  const uint16_t* marker = fields[1].try_as<uint16_t>();
  ASSERT_NE(marker, nullptr);
  EXPECT_EQ(*marker, 7);
}

// OPC 10000-4 5.10.3.4 (Table 58) lists Bad_DataEncodingUnsupported among the HistoryRead OPERATION
// level result codes, and 5.10.3.2 (Table 56) gives dataEncoding the same meaning it has on Read: it
// applies only where the Variable's DataType is a subtype of Structure, and naming an encoding the
// Server does not provide for that DataType is an error. A plausible implementation carries
// dataEncoding on HistoryReadValueId only because the wire format has the field and then never reads
// it, silently returning history in whatever encoding it happens to hold - so a Client that asked for
// XML is handed binary with a Good status and no way to tell.
// @verifies AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED
TEST(HistoryReadServiceTests, AnEncodingTheServerDoesNotProvideRefusesThatHistoryReadOperation)
{
  TestHarness h;
  h.setup();

  // A Variable whose DataType is Range (ns=0;i=884), a subtype of Structure, so a dataEncoding does
  // apply to it and the refusal can only be "unsupported", never "invalid".
  NodeId structuredNode{h.nsIndex, 600u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(structuredNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{884}});
  }
  auto plainNode = h.create_variable_with_history(601);

  h.delegate->set_on_read_raw(
    [structuredNode](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        if (item.nodeId == structuredNode)
        {
          Range range;
          range.low() = 0.0;
          range.high() = 100.0;
          dv.value() = Variant{range};  // Structure-typed history
        }
        else
        {
          dv.value() = static_cast<int32_t>(5);
        }
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({structuredNode, plainNode});
  // "Default XML" is a real OPC UA encoding; this Server provides only Default Binary.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadDataEncodingUnsupported})
    << "an encoding this Server does not provide for that DataType must be refused, not ignored";
  ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoryDataEncodingUnsupported");
  EXPECT_TRUE(response->results()[1].status_code().is_good())
    << "the operation that named no encoding is unaffected";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the unaffected operation must still return its history";
  EXPECT_EQ(histData->data_values().size(), 1u);
}

// OPC 10000-11 4.5: where a Client asks for both timestamps and the Server only collects the
// SourceTimestamp for that HistoricalNode, the Server shall return Bad_TimestampNotSupported, and the
// clause explicitly allows that answer at the operation level - which is what SVR-ATTR-HREAD-031
// requires, because a Historian aggregating several underlying stores can have one Node that carries
// ServerTimestamps next to one that does not. A plausible implementation only checks
// timestampsToReturn once, against the whole service, and so either fails every operation in the
// request or, having found the enum well-formed, hands back rows silently missing the timestamp the
// Client asked for.
// @verifies AC-SVR-ATTR-HREAD-031-PER-NODE-TIMESTAMPS-INVALID
TEST(HistoryReadServiceTests, ANodeThatCannotSupplyTheRequestedTimestampsFailsOnlyItsOwnOperation)
{
  TestHarness h;
  h.setup();

  auto sourceOnlyNode = h.create_variable_with_history(700);
  auto bothTimestampsNode = h.create_variable_with_history(701);

  // The delegate supplies DATA, not verdicts: one Node's history simply carries no ServerTimestamp,
  // which is the Part 11 4.5 "only collecting the SourceTimestamp" case. Deciding what that means for
  // a request that asked for Both is the service's job.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [sourceOnlyNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(3);
        dv.source_timestamp() = DateTime::now();
        if (item.nodeId != sourceOnlyNode)
          dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // make_read_raw_request asks for TimestampsToReturn::Both.
  auto request = make_read_raw_request({sourceOnlyNode, bothTimestampsNode});
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "a per-Node timestamp refusal is per operation, not a service fault";
  EXPECT_TRUE(response->response_header().service_result().is_good())
    << "one Node's timestamp capability must not fail the service";
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadTimestampNotSupported})
    << "the Node that cannot supply the requested timestamps must say so";

  EXPECT_TRUE(response->results()[1].status_code().is_good()) << "the other operations still succeed";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the succeeding operation must still return its history";
  ASSERT_EQ(histData->data_values().size(), 1u);
  EXPECT_TRUE(histData->data_values()[0].source_timestamp().has_value());
  EXPECT_TRUE(histData->data_values()[0].server_timestamp().has_value())
    << "the Node that does carry both timestamps returns both";
}

// An at-time arm was retired here on 2026-08-10. It claimed ReadAtTime among Part 11's
// TimestampsToReturn exceptions; Part 11 section 6.5.2.2 names only HistoricalEventNodes, and
// SPEC-SVR-ATTR-HREAD-031 in the same corpus obliges the opposite for Raw/Modified/AtTime. The
// exception the criterion does state is verified by its Event arm, which passes.

// OPC 10000-4 5.10.3.4 (Table 58) lists Bad_DataEncodingUnsupported among the HistoryRead OPERATION
// level result codes, and 5.10.3.2 (Table 56) puts dataEncoding on HistoryReadValueId - the per-node
// structure that every historyReadDetails shares - not on the details. So the refusal is a property of
// the operation and not of the read flavour: a Structure-valued Variable read with ReadAtTimeDetails
// and an encoding this Server does not provide must be refused exactly as the raw read is. A plausible
// implementation puts the encoding check in whichever result handler it wrote first (the raw one) and
// leaves the other Part 11 handlers to return Structure history in whatever encoding they hold, with a
// Good status and no way for the Client to tell it did not get what it named.
// Coverage verifies-marker WITHHELD while the test is DISABLED_: it names
// AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED. A live marker on a test that never runs claims
// verification nothing performs. Restore it with the leading marker syntax in the same change that
// re-enables the test.
// DISABLED: this test is correct and the behaviour is unimplemented. The dataEncoding capability check
// exists only in the raw result handler (ua_history_read_service.cpp:773-783); the at-time handler
// HistoryReadService::on_namespace_at_time_complete (ua_history_read_service.cpp:1282-1337) never reads
// nodes_to_read()[i].data_encoding() at all, so an at-time operation naming "Default XML" is answered
// Good with binary-encoded Structure history. SVR-ATTR-HREAD-023 states the refusal per operation, and
// dataEncoding lives on HistoryReadValueId, shared by every historyReadDetails. Re-enable with the fix
// -- do not weaken the assertions.
TEST(HistoryReadServiceTests, AnEncodingTheServerDoesNotProvideRefusesTheOperationWhicheverReadItIs)
{
  TestHarness h;
  h.setup();

  // A Variable whose DataType is Range (ns=0;i=884), a subtype of Structure, so a dataEncoding does
  // apply to it and the refusal can only be "unsupported", never "invalid".
  NodeId structuredNode{h.nsIndex, 810u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(structuredNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{884}});
  }
  auto plainNode = h.create_variable_with_history(811);
  const DateTime reqTime = DateTime::now();

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_at_time(
    [structuredNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>
        items,
      NamespaceHistoryDelegate::ReadAtTimeCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
        for (const auto& timestamp : item.timestamps)
        {
          DataValue dv;
          if (item.nodeId == structuredNode)
          {
            Range range;
            range.low() = 0.0;
            range.high() = 100.0;
            dv.value() = Variant{range};  // Structure-typed history
          }
          else
          {
            dv.value() = static_cast<int32_t>(5);
          }
          dv.source_timestamp() = timestamp;
          dv.server_timestamp() = DateTime::now();
          success.values.push_back(std::move(dv));
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadAtTimeItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadAtTimeDetails>();
  details->req_times().resize(1);
  details->req_times()[0] = reqTime;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[0].node_id() = structuredNode;
  request.nodes_to_read()[1].node_id() = plainNode;
  // "Default XML" is a real OPC UA encoding; this Server provides only Default Binary.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadDataEncodingUnsupported})
    << "an encoding this Server does not provide must be refused on the at-time read too, not ignored";
  ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoryDataEncodingUnsupported");
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "a refused operation must not also hand back the history it refused to encode";

  EXPECT_TRUE(response->results()[1].status_code().is_good())
    << "the operation that named no encoding is unaffected";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the unaffected operation must still return its history";
  EXPECT_EQ(histData->data_values().size(), 1u);
}

// OPC 10000-11 4.5 states the per-Node refusal without naming a direction: where the Client asks for a
// timestamp combination the HistoricalNode does not collect, that operation is Bad_TimestampNotSupported
// while the rest of the request stands. SVR-ATTR-HREAD-031 illustrates it with the Source-only Node
// asked for Both, and an implementation written from that illustration alone tests only whether the
// ServerTimestamp is missing - so a Node that collects only the ServerTimestamp, asked for Source,
// silently returns rows with no SourceTimestamp at all under a Good status, which is the same
// unplaceable history the code exists to refuse.
// @verifies AC-SVR-ATTR-HREAD-031-PER-NODE-TIMESTAMPS-INVALID
TEST(HistoryReadServiceTests, ANodeThatCollectsOnlyTheServerTimestampFailsOnlyItsOwnOperation)
{
  TestHarness h;
  h.setup();

  auto serverOnlyNode = h.create_variable_with_history(820);
  auto sourceBearingNode = h.create_variable_with_history(821);

  // The delegate supplies DATA, not verdicts: one Node's history simply carries no SourceTimestamp.
  // Deciding what that means for a request that asked for Source is the service's job.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [serverOnlyNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = static_cast<int32_t>(9);
        dv.server_timestamp() = DateTime::now();
        if (item.nodeId != serverOnlyNode)
          dv.source_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({serverOnlyNode, sourceBearingNode});
  request.timestamps_to_return() = TimestampsToReturn::Source;
  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "a per-Node timestamp refusal is per operation, not a service fault";
  EXPECT_TRUE(response->response_header().service_result().is_good())
    << "one Node's timestamp capability must not fail the service";
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadTimestampNotSupported})
    << "a Node that never collects the requested SourceTimestamp must say so, not return rows without it";
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "the refused operation must not also hand back the history that lacks the timestamp";

  EXPECT_TRUE(response->results()[1].status_code().is_good()) << "the other operations still succeed";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the succeeding operation must still return its history";
  ASSERT_EQ(histData->data_values().size(), 1u);
  EXPECT_TRUE(histData->data_values()[0].source_timestamp().has_value())
    << "the Node that does collect the SourceTimestamp returns it";
}

// OPC 10000-11 6.5.5.2 applies TimestampsToReturn to ReadAtTime and returns
// Bad_TimestampNotSupported when a HistoricalDataNode cannot supply the requested combination. Only
// HistoricalEventNodes ignore this parameter (Part 11 4.5). Server-only must therefore remove the
// SourceTimestamp from each otherwise successful at-time value while preserving order and the requested
// ServerTimestamp. This is the supported-combination control for the per-Node refusal criterion.
// @verifies AC-SVR-ATTR-HREAD-031-PER-NODE-TIMESTAMPS-INVALID
TEST(HistoryReadServiceTests, AtTimeHistoryReadHonoursServerTimestampSelection)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_variable_with_history(830);

  DateTime base = DateTime::now();
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };
  const std::vector<DateTime> reqTimes = {at(2), at(5), at(9)};

  // The delegate supplies both timestamps and a marker payload so selection and ordering are independent.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_at_time(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAtTimeItem>
        items,
      NamespaceHistoryDelegate::ReadAtTimeCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
        for (size_t i = 0; i < item.timestamps.size(); ++i)
        {
          DataValue dv;
          dv.value() = static_cast<int32_t>(400 + i);
          dv.source_timestamp() = item.timestamps[i];
          dv.server_timestamp() = DateTime::now();
          success.values.push_back(std::move(dv));
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadAtTimeItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  // Server-only is what strips the SourceTimestamp from an ordinary raw read
  // (SourceTimestampsOnlyStripsServerTimestamp is the mirror of that rule on the Raw path).
  request.timestamps_to_return() = TimestampsToReturn::Server;
  auto details = std::make_unique<ReadAtTimeDetails>();
  details->req_times().resize(reqTimes.size());
  for (size_t i = 0; i < reqTimes.size(); ++i)
    details->req_times()[i] = reqTimes[i];
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "a supported at-time timestamp selection is not refused";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(delegateCalls.load(), 1) << "the at-time read must actually have been performed";

  auto* histData = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "a successful at-time read carries HistoryData";
  auto& values = histData->data_values().payload();
  ASSERT_EQ(values.size(), reqTimes.size()) << "one value per requested timestamp";

  for (size_t i = 0; i < values.size(); ++i)
  {
    const int32_t* marker = values[i].value().try_as<int32_t>();
    ASSERT_NE(marker, nullptr);
    EXPECT_EQ(*marker, static_cast<int32_t>(400 + i)) << "at-time order must match req_times";
    EXPECT_FALSE(values[i].source_timestamp().has_value())
      << "Server-only applies to ReadAtTime and must remove SourceTimestamp from value " << i;
    EXPECT_TRUE(values[i].server_timestamp().has_value())
      << "the ServerTimestamp the Client did ask for is still returned";
  }
}

// OPC 10000-4 5.10.3.2 (Table 56) puts dataEncoding on HistoryReadValueId - the per-node structure
// every historyReadDetails shares - and says it "only applies if the DataType of the Variable is a
// subtype of Structure", excusing only one read flavour from it: "the parameter is ignored when
// reading history of Events". An annotation read is not an Event read; its nodesToRead entry names a
// Variable, and OPC 10000-11 6.5.6 returns Annotation Structures from that Variable's Annotations
// Property, so a Client that names an encoding this Server does not provide must be refused per
// operation with Bad_DataEncodingUnsupported (OPC 10000-4 5.10.3.4, Table 58). A plausible
// implementation puts the encoding check in whichever result handler it wrote first - the raw one -
// and leaves the other Part 11 handlers to return Structure history in whatever encoding they happen
// to hold, under a Good status that gives the Client no way to tell it did not get what it named.
// @verifies AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED
TEST(HistoryReadServiceTests, AnEncodingTheServerDoesNotProvideRefusesTheAnnotationHistoryReadOperation)
{
  TestHarness h;
  h.setup();

  // A Variable whose DataType is Range (ns=0;i=884), a subtype of Structure, so a dataEncoding does
  // apply to it and the refusal can only be "unsupported", never "invalid".
  NodeId structuredNode{h.nsIndex, 840u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(structuredNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{884}});
  }
  auto plainNode = h.create_variable_with_history(841);

  DateTime base = DateTime::now();
  const DateTime reqTime{base.value() + std::chrono::seconds{2}};

  // The delegate supplies the annotations and nothing else; deciding whether the Client may have them
  // in the encoding it named is the service's job.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_annotations(
    [&delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadAnnotationItem>
        items,
      NamespaceHistoryDelegate::ReadAnnotationCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadAnnotationItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadAnnotationSuccess success;
        for (size_t i = 0; i < item.reqTimes.size(); ++i)
          success.values.push_back(
            DataValue{Variant{static_cast<int32_t>(500 + i)}, StatusCode{Status::Good}, item.reqTimes[i]});
        batch.items.push_back(NamespaceHistoryDelegate::ReadAnnotationItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadAnnotationDataDetails>();
  details->req_times().resize(1);
  details->req_times()[0] = reqTime;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[0].node_id() = structuredNode;
  request.nodes_to_read()[1].node_id() = plainNode;
  // "Default XML" is a real OPC UA encoding; this Server provides only Default Binary.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadDataEncodingUnsupported})
    << "an encoding this Server does not provide must be refused on the annotation read too, not ignored";
  ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoryDataEncodingUnsupported");
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "a refused operation must not also hand back the annotations it refused to encode";

  EXPECT_TRUE(response->results()[1].status_code().is_good())
    << "the operation that named no encoding is unaffected";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the unaffected operation must still return its annotations";
  ASSERT_EQ(histData->data_values().payload().size(), 1u);
  const int32_t* marker = histData->data_values().payload()[0].value().try_as<int32_t>();
  ASSERT_NE(marker, nullptr);
  EXPECT_EQ(*marker, 500);
}

// OPC 10000-4 5.10.3.2 (Table 56) says of timestampsToReturn that "OPC 10000-11 defines exceptions
// where this parameter shall be ignored", and OPC 10000-11 4.5 states that exception without
// qualifying it by value: "For HistoricalEventNodes this parameter does not apply. This parameter is
// ignored since the entries returned are dictated by the Event Filter." The
// Bad_TimestampsToReturnInvalid rejection that opens 4.5 governs the settings the clause then
// tabulates - SOURCE, SERVER, BOTH, NEITHER - every one of which chooses a timestamp for a
// HistoricalDataNode. An event read therefore cannot be refused for a value outside the enumeration
// any more than it can be refused for NEITHER: there is nothing for the value to be invalid for, and
// the fields that come back, including the Time that keys each record, never depended on it. A
// plausible implementation range-checks the enum once, up front, before it has looked at which
// HistoryReadDetails it is holding; or it exempts events from the NEITHER rule alone and leaves the
// range check in front of it to fire - and either way it discards a whole event read over a parameter
// that does not apply to that read.
// @verifies AC-SVR-ATTR-HREAD-005-PART11-TIMESTAMP-EXCEPTIONS
// @verifies AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED
TEST(HistoryReadServiceTests, EventHistoryReadIgnoresAnOutOfRangeTimestampsToReturnAndStillReturnsItsFields)
{
  TestHarness h;
  h.setup();

  auto nodeId = h.create_object_with_history_read(900);
  const DateTime eventTime = DateTime::now();

  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_events(
    [eventTime, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        // Field 0 is the Event's Time - the Part 11 timestamp that places the record.
        fields.event_fields().push_back(Variant{eventTime});
        fields.event_fields().push_back(Variant{static_cast<int32_t>(21)});
        success.events.push_back(std::move(fields));
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  // The value TimestampsToReturnOutOfRangeReturnsServiceFault sends on the raw path, where refusing
  // the whole request is right because there the parameter selects which timestamp is returned.
  request.timestamps_to_return() = static_cast<TimestampsToReturn>(0x123);
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand timeSelect;
  timeSelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  timeSelect.browse_path().push_back(QualifiedName{0, "Time"});
  timeSelect.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(timeSelect));
  // The delegate answers a second field; it is selected, as a field no clause selects is withheld.
  SimpleAttributeOperand severitySelect;
  severitySelect.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  severitySelect.browse_path().push_back(QualifiedName{0, "Severity"});
  severitySelect.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(severitySelect));
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = nodeId;
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  EXPECT_FALSE(is_service_fault(result.response, Status::BadTimestampsToReturnInvalid))
    << "timestampsToReturn does not apply to a HistoricalEventNode, so no value of it can refuse the read";
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an event history read must not be refused for timestampsToReturn";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(delegateCalls.load(), 1) << "the event read must actually have been performed";

  auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr) << "a successful event history read carries HistoryEvent";
  ASSERT_EQ(histEvent->events().size(), 1u);
  auto& fields = histEvent->events()[0].event_fields();
  ASSERT_EQ(fields.size(), 2u) << "the fields the EventFilter selected are what determines the reply";
  const DateTime* time = fields[0].try_as<DateTime>();
  ASSERT_NE(time, nullptr) << "the Event's Time field must survive: timestampsToReturn does not apply here";
  EXPECT_EQ(*time, eventTime);
  const int32_t* marker = fields[1].try_as<int32_t>();
  ASSERT_NE(marker, nullptr);
  EXPECT_EQ(*marker, 21);
}

// OPC 10000-4 5.10.3.2 (Table 56) puts dataEncoding on HistoryReadValueId - the per-node structure
// shared by every historyReadDetails - and excuses exactly one read flavour from it: "the parameter is
// ignored when reading history of Events". A processed read is not an event read; its nodesToRead
// entry names a Variable, and where that Variable's DataType is a subtype of Structure the encoding
// the Client named is part of what it asked for, so naming one this Server does not provide must be
// refused per operation with Bad_DataEncodingUnsupported (OPC 10000-4 5.10.3.4, Table 58). A plausible
// implementation puts the encoding check inside whichever result handler it wrote first - the raw one -
// and the aggregate paths, which build their own results from the calculator or from a native
// delegate, never look at dataEncoding at all, so the operation comes back Good and the Client has no
// way to tell it did not get the encoding it named.
// @verifies AC-SVR-ATTR-HREAD-023-DATAENCODINGUNSUPPORTED
TEST(HistoryReadServiceTests, AnEncodingTheServerDoesNotProvideRefusesTheProcessedHistoryReadOperation)
{
  TestHarness h;
  h.setup();

  // A Variable whose DataType is Range (ns=0;i=884), a subtype of Structure, so a dataEncoding does
  // apply to it and the refusal can only be "unsupported", never "invalid".
  NodeId structuredNode{h.nsIndex, 910u};
  {
    auto as = h.sessionInfo->address_space();
    auto varResult = as.try_create_sync<VariableAccessor>(structuredNode, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good()) << "Failed to create variable node";
    AccessLevelType al;
    al.set(AccessLevelType::Bit::CurrentRead);
    al.set(AccessLevelType::Bit::HistoryRead);
    varResult.value().set_access_level(al);
    varResult.value().set_data_type(NodeId{uint16_t{0}, uint32_t{884}});
  }
  auto plainNode = h.create_variable_with_history(911);

  DateTime base = DateTime::now();
  auto at = [base](int64_t secs)
  {
    return DateTime{base.value() + std::chrono::seconds{secs}};
  };

  // The delegate supplies the raw series the turnkey Part-13 calculator aggregates - five Good values
  // in the window for each node, Structure-valued for the Node whose DataType is a Structure subtype.
  // Whether the Client may have the answer in the encoding it named is the service's decision, not the
  // delegate's.
  std::atomic<int> delegateCalls{0};
  h.delegate->set_on_read_raw(
    [at, structuredNode, &delegateCalls](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      NamespaceHistoryDelegate::ReadRawCallback callback)
    {
      delegateCalls.fetch_add(1);
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        const int64_t times[] = {2, 5, 12, 15, 18};
        const int32_t vals[] = {10, 20, 30, 40, 50};
        for (size_t k = 0; k < 5; ++k)
        {
          if (item.nodeId == structuredNode)
          {
            Range range;
            range.low() = 0.0;
            range.high() = 100.0;
            success.values.push_back(
              DataValue{Variant{range}, StatusCode{Status::Good}, at(times[k])});  // Structure history
          }
          else
          {
            success.values.push_back(DataValue{Variant{vals[k]}, StatusCode{Status::Good}, at(times[k])});
          }
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadRawItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  // ReadProcessed requires Source timestamps (Part 13 5.4.3.1 / SVR-HIST-AGG-027).
  request.timestamps_to_return() = TimestampsToReturn::Source;
  auto details = std::make_unique<ReadProcessedDetails>();
  details->start_time() = at(0);
  details->end_time() = at(20);
  details->processing_interval() = 0.0;  // one interval over the whole window
  details->aggregate_type().resize(2);
  details->aggregate_type()[0] = NodeId{static_cast<uint32_t>(ObjectId::AggregateFunction_Count)};
  details->aggregate_type()[1] = NodeId{static_cast<uint32_t>(ObjectId::AggregateFunction_Count)};
  details->aggregate_configuration().use_server_capabilities_defaults() = true;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(2);
  request.nodes_to_read()[0].node_id() = structuredNode;
  request.nodes_to_read()[1].node_id() = plainNode;
  // "Default XML" is a real OPC UA encoding; this Server provides only Default Binary.
  request.nodes_to_read()[0].data_encoding() = QualifiedName{0, "Default XML"};

  auto result = h.run_service(std::move(request));

  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr) << "an encoding fault is per operation and must not fail the request";
  EXPECT_TRUE(response->response_header().service_result().is_good());
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_GT(delegateCalls.load(), 0) << "the read must have been performed for the verdict to be real";

  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::BadDataEncodingUnsupported})
    << "an encoding this Server does not provide must be refused on the processed read too, not ignored";
  ASSERT_NE(response->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[0].status_code().shared_detail()->code, "HistoryDataEncodingUnsupported");
  EXPECT_EQ(dynamic_cast<HistoryData*>(response->results()[0].history_data().get()), nullptr)
    << "a refused operation must not also hand back the history it refused to encode";

  EXPECT_TRUE(response->results()[1].status_code().is_good())
    << "the operation that named no encoding is unaffected";
  auto* histData = dynamic_cast<HistoryData*>(response->results()[1].history_data().get());
  ASSERT_NE(histData, nullptr) << "the unaffected operation must still return its aggregate";
  ASSERT_EQ(histData->data_values().payload().size(), 1u);
  const int32_t* count = histData->data_values().payload()[0].value().try_as<int32_t>();
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(*count, 5) << "the five Good raw values in the window";
}

// An archived field is withheld as live delivery withholds it: Bad_UserAccessDenied in its position when
// the session may not Read the field's InstanceDeclaration, whatever the archive holds there. The archive
// answers values whatever Attribute a clause names, so a DisplayName clause needs Read too. EventId,
// EventType and ReceiveTime are never withheld.
// @relation(AC-SVR-AUTHZ-001-HISTORICAL-FIELD-READ-AUTHORIZATION, scope=function)
TEST(HistoryReadServiceTests, HistoricalFieldsRespectDeclarationReadPermission)
{
  TestHarness harness;
  harness.setup();
  const auto notifier = harness.create_object_with_history_read(690);
  auto addressSpace = harness.sessionInfo->address_space();
  auto messageDeclaration = addressSpace.find_node_sync(NodeId{VariableId::BaseEventType_Message});
  auto notifierNode = addressSpace.find_node_sync(notifier);
  auto eventTypeNode = addressSpace.find_node_sync(NodeId{ObjectTypeId::BaseEventType});
  const DateTime archivedTime = DateTime::now();
  const ByteString archivedEventId{0xA1, 0xB2};
  const auto includeOrigins = std::make_shared<std::atomic_bool>(true);
  const auto returnCursor = std::make_shared<std::atomic_bool>(false);
  const auto resumedCursorCount = std::make_shared<std::atomic_size_t>(0);
  const StatusCode originalBad{Status::BadNoData,
    make_error_detail("OriginalArchivedFieldFailure", "archived field was unavailable", "test.history")};
  harness.delegate->set_on_read_events(
    [notifier, archivedTime, archivedEventId, includeOrigins, returnCursor, resumedCursorCount, originalBad](
      const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      for (const auto& item : items)
      {
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList fields;
        fields.event_fields().push_back(Variant{LocalizedText{"en", "protected archive sentinel"}});
        fields.event_fields().push_back(Variant{archivedTime});
        fields.event_fields().push_back(Variant{originalBad});
        fields.event_fields().push_back(Variant{});
        fields.event_fields().push_back(Variant{archivedEventId});
        fields.event_fields().push_back(Variant{NodeId{ObjectTypeId::BaseEventType}});
        fields.event_fields().push_back(Variant{archivedTime});
        success.events.push_back(std::move(fields));
        if (includeOrigins->load())
          success.origins.push_back({notifier, NodeId{ObjectTypeId::BaseEventType}});
        if (item.cursor.has_value())
        {
          const auto* cursor = std::any_cast<std::string>(&*item.cursor);
          EXPECT_NE(cursor, nullptr);
          if (cursor != nullptr)
            EXPECT_EQ(*cursor, "historical-field-second-page");
          resumedCursorCount->fetch_add(1);
        }
        else if (returnCursor->load())
          success.cursor = std::string{"historical-field-second-page"};
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  // The event's identity and receipt time remain available even when their Value declarations deny Read.
  for (const auto declaration : {VariableId::BaseEventType_EventId,
         VariableId::BaseEventType_EventType,
         VariableId::BaseEventType_ReceiveTime})
  {
    auto node = addressSpace.find_node_sync(NodeId{declaration});
    auto permissions = ua::test_helpers::all_permissions();
    permissions.reset(PermissionType::Bit::Read);
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

  const auto makeRequest = [notifier](AttributeId selectedAttribute)
  {
    auto request = make_read_events_request({notifier});
    auto* details = static_cast<ReadEventDetails*>(request.history_read_details().get());
    details->filter().select_clauses().clear();
    for (const auto& [name, attribute] : {std::pair{"Message", selectedAttribute},
           std::pair{"Time", AttributeId::Value},
           std::pair{"Message", selectedAttribute},
           std::pair{"Message", selectedAttribute},
           std::pair{"EventId", AttributeId::Value},
           std::pair{"EventType", AttributeId::Value},
           std::pair{"ReceiveTime", AttributeId::Value}})
    {
      SimpleAttributeOperand select;
      select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
      select.browse_path().push_back(QualifiedName{0, name});
      select.attribute_id() = utils::to_underlying(attribute);
      details->filter().select_clauses().push_back(std::move(select));
    }
    return request;
  };

  for (const auto attribute : {AttributeId::Value, AttributeId::DisplayName})
  {
    HistoryContinuationPoints sessionPoints;
    ByteString nextPage;
    for (size_t stage = 0; stage < 4; ++stage)
    {
      SCOPED_TRACE(static_cast<uint32_t>(attribute));
      SCOPED_TRACE(stage);
      // The archive returns the stored value for either Attribute, so both need Read; Browse is unrelated.
      auto permissions = ua::test_helpers::all_permissions();
      permissions.reset(stage == 1 ? PermissionType::Bit::Browse : PermissionType::Bit::Read);
      ua::test_helpers::set_test_node_permissions(messageDeclaration, permissions);
      includeOrigins->store(stage != 3);
      returnCursor->store(stage == 1);

      auto request = makeRequest(attribute);
      if (stage == 2)
      {
        ASSERT_FALSE(nextPage.empty());
        request.nodes_to_read()[0].continuation_point() = nextPage;
      }
      auto outcome = harness.run_service(std::move(request), sessionPoints);
      auto* response = get_history_response(outcome.response);
      ASSERT_NE(response, nullptr);
      ASSERT_EQ(response->results().size(), 1u);
      EXPECT_TRUE(response->results()[0].status_code().is_good());
      auto* history = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
      ASSERT_NE(history, nullptr);
      ASSERT_EQ(history->events().size(), 1u);
      const auto& fields = history->events()[0].event_fields();
      ASSERT_EQ(fields.size(), 7u);
      if (stage == 1)
      {
        EXPECT_EQ(std::string{fields[0].as<LocalizedText>().text()}, "protected archive sentinel");
        nextPage = response->results()[0].continuation_point();
        ASSERT_FALSE(nextPage.empty());
        ASSERT_EQ(outcome.continuationPoints.size(), 1u);
        for (auto& point : outcome.continuationPoints)
        {
          auto identifier = point.identifier();
          sessionPoints.emplace(identifier, std::move(point));
        }
      }
      else
      {
        const auto* denial = fields[0].try_as<StatusCode>();
        ASSERT_NE(denial, nullptr) << "a protected archived value was returned instead of a denial";
        EXPECT_EQ(*denial, StatusCode{Status::BadUserAccessDenied});
      }
      EXPECT_EQ(fields[1], Variant{archivedTime});
      const auto* bad = fields[2].try_as<StatusCode>();
      ASSERT_NE(bad, nullptr);
      if (stage == 1)
      {
        EXPECT_EQ(*bad, originalBad);
        EXPECT_EQ(bad->shared_detail(), originalBad.shared_detail());
        EXPECT_EQ(fields[3], Variant{});
      }
      else
      {
        // As live delivery: a denied declaration withholds the archive's Bad and null answers too.
        EXPECT_EQ(*bad, StatusCode{Status::BadUserAccessDenied});
        const auto* withheldNull = fields[3].try_as<StatusCode>();
        ASSERT_NE(withheldNull, nullptr);
        EXPECT_EQ(*withheldNull, StatusCode{Status::BadUserAccessDenied});
      }
      EXPECT_EQ(fields[4], Variant{archivedEventId});
      EXPECT_EQ(fields[5], Variant{NodeId{ObjectTypeId::BaseEventType}});
      EXPECT_EQ(fields[6], Variant{archivedTime});
      if (stage == 2)
        EXPECT_TRUE(response->results()[0].continuation_point().empty());
    }
  }
  EXPECT_EQ(resumedCursorCount->load(), 2u)
    << "both Attribute operations must resume an actual delegate page";

  ua::test_helpers::set_test_node_permissions(messageDeclaration, ua::test_helpers::all_permissions());
  returnCursor->store(false);
  for (auto* originNode : {&notifierNode, &eventTypeNode})
  {
    auto permissions = ua::test_helpers::all_permissions();
    permissions.reset(PermissionType::Bit::ReceiveEvents);
    ua::test_helpers::set_test_node_permissions(*originNode, permissions);
    includeOrigins->store(true);
    auto denied = harness.run_service(makeRequest(AttributeId::Value));
    auto* response = get_history_response(denied.response);
    ASSERT_NE(response, nullptr);
    auto* history = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
    ASSERT_NE(history, nullptr);
    EXPECT_TRUE(history->events().empty()) << "each recorded origin independently requires ReceiveEvents";
    ua::test_helpers::set_test_node_permissions(*originNode, ua::test_helpers::all_permissions());
  }
}

// SVC-17: an event a session may not receive live (no ReceiveEvents on its SourceNode) is not handed
// to it from the archive either. The delegate reports each event's origin; the service authorizes
// the distinct origins once and drops the denied events. A delegate that reports no origins keeps the
// legacy behaviour, gated by ReadHistory on the notifier alone.
// @verifies AC-SVR-AUTHZ-016-ARCHIVED-EVENTS-ARE-FILTERED-BY-RECEIVEEVENTS
TEST(HistoryReadServiceTests, ArchivedEventDeniedLiveIsDeniedInHistory)
{
  TestHarness h;
  h.setup();

  const auto notifierId = h.create_object_with_history_read(700);
  const auto deniedSource = h.create_object_without_history_read(701);
  const auto allowedSource = h.create_object_without_history_read(702);
  {
    auto node = h.sessionInfo->address_space().find_node_sync(deniedSource);
    auto permissions = ua::test_helpers::all_permissions();
    permissions.reset(PermissionType::Bit::ReceiveEvents);
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

  std::atomic<bool> reportOrigins{true};
  h.delegate->set_on_read_events(
    [&](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        for (const auto& [source, label] :
          {std::pair{deniedSource, "from-denied-source"}, std::pair{allowedSource, "from-allowed-source"}})
        {
          HistoryEventFieldList fields;
          fields.event_fields().push_back(Variant{String{label}});
          success.events.push_back(std::move(fields));
          if (reportOrigins.load())
            success.origins.push_back({source, NodeId{ObjectTypeId::BaseEventType}});
        }
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  const auto makeRequest = [&]
  {
    HistoryReadRequest request;
    request.request_header().request_handle() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    auto details = std::make_unique<ReadEventDetails>();
    details->start_time() = DateTime{DateTime::min()};
    details->end_time() = DateTime::now();
    details->num_values_per_node() = 10;
    SimpleAttributeOperand select;
    select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    select.browse_path().push_back(QualifiedName{0, std::string{"Message"}});
    select.attribute_id() = utils::to_underlying(AttributeId::Value);
    details->filter().select_clauses().push_back(std::move(select));
    request.history_read_details() = std::move(details);
    request.nodes_to_read().resize(1);
    request.nodes_to_read()[0].node_id() = notifierId;
    return request;
  };
  const auto delivered = [&](HistoryReadService::HistoryReadServiceResponse result)
  {
    std::vector<std::string> labels;
    auto* response = get_history_response(result.response);
    if (response == nullptr || response->results().size() != 1u ||
        !response->results()[0].status_code().is_good())
      return labels;
    auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
    if (histEvent == nullptr)
      return labels;
    for (const auto& event : histEvent->events())
      labels.emplace_back(event.event_fields()[0].template as<String>());
    return labels;
  };

  EXPECT_EQ(delivered(h.run_service(makeRequest())), (std::vector<std::string>{"from-allowed-source"}))
    << "the event whose SourceNode the session may not ReceiveEvents from is withheld";

  reportOrigins = false;
  EXPECT_EQ(delivered(h.run_service(makeRequest())),
    (std::vector<std::string>{"from-denied-source", "from-allowed-source"}))
    << "a delegate that reports no origins is gated by ReadHistory on the notifier alone";
}

// SVC-17: an origin the address space cannot resolve is not permitted (fail closed), while an event
// whose origin was not recorded (null) is left to the ReadHistory gate.
// @verifies AC-SVR-AUTHZ-016-ARCHIVED-EVENTS-ARE-FILTERED-BY-RECEIVEEVENTS
TEST(HistoryReadServiceTests, ArchivedEventWithAnUnresolvableOriginIsWithheldAndANullOriginIsKept)
{
  TestHarness h;
  h.setup();
  const auto notifierId = h.create_object_with_history_read(710);
  const NodeId ghostSource{notifierId.namespace_index(), 799999u};  // no such node

  h.delegate->set_on_read_events(
    [&](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadEventsItem>
        items,
      NamespaceHistoryDelegate::ReadEventsCallback callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
      for (const auto& item : items)
      {
        (void)item;
        NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
        HistoryEventFieldList ghost;
        ghost.event_fields().push_back(Variant{String{"from-ghost-source"}});
        success.events.push_back(std::move(ghost));
        success.origins.push_back({ghostSource, NodeId{ObjectTypeId::BaseEventType}});
        HistoryEventFieldList unrecorded;
        unrecorded.event_fields().push_back(Variant{String{"origin-not-recorded"}});
        success.events.push_back(std::move(unrecorded));
        success.origins.push_back({NodeId{}, NodeId{}});
        batch.items.push_back(NamespaceHistoryDelegate::ReadEventsItemResult{std::move(success)});
      }
      callback(std::move(batch));
    });

  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 10;
  SimpleAttributeOperand select;
  select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  select.browse_path().push_back(QualifiedName{0, std::string{"Message"}});
  select.attribute_id() = utils::to_underlying(AttributeId::Value);
  details->filter().select_clauses().push_back(std::move(select));
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(1);
  request.nodes_to_read()[0].node_id() = notifierId;

  auto result = h.run_service(std::move(request));
  auto* response = get_history_response(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_TRUE(response->results()[0].status_code().is_good());
  auto* histEvent = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr);
  ASSERT_EQ(histEvent->events().size(), 1u) << "the unresolvable origin is withheld, the null one kept";
  EXPECT_EQ(histEvent->events()[0].event_fields()[0].template as<String>(), String{"origin-not-recorded"});
}

// ---------------------------------------------------------------------------
// Partial results at the deadline (item 10, API-10.2 to API-10.5): OPC 10000-4 section 5.10.3.1 lets
// HistoryRead "return zero results with a continuation point for the affected nodes before the timeout
// expires", and OPC 10000-11 section 6.3 lets the continuation point own the running read.
// ---------------------------------------------------------------------------

namespace
{

/// Holds every raw read the delegate receives until the test releases it.
struct HeldRawReads
{
  std::mutex mutex;
  std::condition_variable arrived;
  std::vector<NamespaceHistoryDelegate::ReadContext> contexts;
  std::vector<std::vector<NamespaceHistoryDelegate::ReadRawItem>> items;
  std::vector<NamespaceHistoryDelegate::ReadRawCallback> callbacks;

  void install(FakeNamespaceHistoryDelegate& delegate)
  {
    delegate.set_on_read_raw(
      [this](const NamespaceHistoryDelegate::ReadContext& context,
        std::vector<NamespaceHistoryDelegate::ReadRawItem>
          held,
        NamespaceHistoryDelegate::ReadRawCallback callback)
      {
        const std::lock_guard<std::mutex> lock(mutex);
        contexts.push_back(context);
        items.push_back(std::move(held));
        callbacks.push_back(std::move(callback));
        arrived.notify_all();
      });
  }

  bool wait_for(size_t count)
  {
    std::unique_lock<std::mutex> lock(mutex);
    return arrived.wait_for(lock, 2s, [&] { return callbacks.size() >= count; });
  }

  NamespaceHistoryDelegate::ReadContext context(size_t index)
  {
    const std::lock_guard<std::mutex> lock(mutex);
    return contexts.at(index);
  }

  /// Answers read @p index with one value per item, carrying @p value.
  void release(size_t index, int32_t value)
  {
    NamespaceHistoryDelegate::ReadRawCallback callback;
    size_t count = 0;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      callback = std::move(callbacks.at(index));
      count = items.at(index).size();
    }
    BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
    for (size_t i = 0; i < count; ++i)
    {
      NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      DataValue dv;
      dv.value() = value;
      dv.source_timestamp() = DateTime::now();
      dv.server_timestamp() = DateTime::now();
      success.values.push_back(std::move(dv));
      batch.items.emplace_back(std::move(success));
    }
    callback(std::move(batch));
  }
};

ServerConfig partial_result_configuration(double fraction, uint16_t maxHistoryContinuationPoints = 10)
{
  ServerConfig configuration;
  configuration.partialResultDeadlineFraction = fraction;
  configuration.server_capabilities().maxHistoryContinuationPoints = maxHistoryContinuationPoints;
  return configuration;
}

HistoryContinuationPoints store_of(HistoryReadService::HistoryReadServiceResponse& response)
{
  HistoryContinuationPoints store;
  for (auto& continuationPoint : response.continuationPoints)
  {
    auto identifier = continuationPoint.identifier();
    store.emplace(identifier, std::move(continuationPoint));
  }
  response.continuationPoints.clear();
  return store;
}

HistoryReadResponse* as_history(HistoryReadService::HistoryReadServiceResponse& response)
{
  return dynamic_cast<HistoryReadResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
}

}  // namespace

// Disabled: re-authorizing a paused result when a later call consumes it is a known limitation the owner
// deferred for the release (security_review_summary_and_status_2026_10_18.md, A2 decision, 2026-10-19).
// Fields are authorized once per request; this test asserts the deferred re-check and is kept for it.
TEST(HistoryReadServiceTests,
  DISABLED_PartialEventResultContinuationRechecksFieldPermissionAfterProviderCompletion)
{
  for (const auto attribute : {AttributeId::Value, AttributeId::DisplayName})
  {
    for (const bool outcomeReadyBeforeRevocation : {false, true})
    {
      for (int revokedSubject = 0; revokedSubject < 3; ++revokedSubject)
      {
        SCOPED_TRACE(::testing::Message{} << "attribute=" << static_cast<uint32_t>(attribute) << " ready="
                                          << outcomeReadyBeforeRevocation << " subject=" << revokedSubject);
        TestHarness harness;
        harness.setup(true, partial_result_configuration(0.01));
        const auto notifier = harness.create_object_with_history_read(691);
        auto addressSpace = harness.sessionInfo->address_space();
        auto messageDeclaration = addressSpace.find_node_sync(NodeId{VariableId::BaseEventType_Message});
        auto notifierNode = addressSpace.find_node_sync(notifier);
        auto eventTypeNode = addressSpace.find_node_sync(NodeId{ObjectTypeId::BaseEventType});
        const DateTime archivedTime = DateTime::now();
        const StatusCode originalBad{Status::BadNoData,
          make_error_detail("PausedArchivedFieldFailure", "archived field was unavailable", "test.history")};

        using HeldEventRead = std::pair<std::vector<NamespaceHistoryDelegate::ReadEventsItem>,
          NamespaceHistoryDelegate::ReadEventsCallback>;
        auto arrived = std::make_shared<std::promise<HeldEventRead>>();
        auto held = arrived->get_future();
        auto providerCalls = std::make_shared<std::atomic_size_t>(0);
        harness.delegate->set_on_read_events(
          [arrived, providerCalls](const NamespaceHistoryDelegate::ReadContext&,
            std::vector<NamespaceHistoryDelegate::ReadEventsItem>
              items,
            NamespaceHistoryDelegate::ReadEventsCallback callback)
          {
            if (providerCalls->fetch_add(1) != 0)
            {
              ADD_FAILURE() << "a paused continuation must consume the original provider result";
              callback(BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>{});
              return;
            }
            arrived->set_value(HeldEventRead{std::move(items), std::move(callback)});
          });
        const auto makeRequest = [notifier, attribute]
        {
          auto request = make_read_events_request({notifier});
          auto* details = static_cast<ReadEventDetails*>(request.history_read_details().get());
          details->filter().select_clauses().clear();
          for (const auto& [name, selectedAttribute] : {std::pair{"Message", attribute},
                 std::pair{"Time", AttributeId::Value},
                 std::pair{"Message", attribute},
                 std::pair{"Message", attribute}})
          {
            SimpleAttributeOperand select;
            select.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
            select.browse_path().push_back(QualifiedName{0, name});
            select.attribute_id() = utils::to_underlying(selectedAttribute);
            details->filter().select_clauses().push_back(std::move(select));
          }
          return request;
        };

        auto initialRequest = makeRequest();
        initialRequest.request_header().timeout_hint() = 1000;
        auto first = harness.run_service(std::move(initialRequest));
        auto* firstResponse = as_history(first);
        ASSERT_NE(firstResponse, nullptr);
        ASSERT_EQ(firstResponse->results().size(), 1u);
        ASSERT_TRUE(firstResponse->results()[0].status_code().is_good());
        ASSERT_FALSE(firstResponse->results()[0].continuation_point().empty());
        auto* emptyEvents = dynamic_cast<HistoryEvent*>(firstResponse->results()[0].history_data().get());
        ASSERT_NE(emptyEvents, nullptr);
        ASSERT_TRUE(emptyEvents->events().empty());
        ASSERT_EQ(first.continuationPoints.size(), 1u);
        ASSERT_EQ(held.wait_for(2s), std::future_status::ready);
        auto providerRead = held.get();
        ASSERT_EQ(providerRead.first.size(), 1u);
        EXPECT_FALSE(providerRead.first[0].cursor.has_value());

        // Transfer the existing paused operation into an equivalent point so its public completion
        // callback can provide deterministic synchronization without reading private service state.
        auto& returnedPoint = first.continuationPoints[0];
        auto paused = returnedPoint.take_paused();
        ASSERT_NE(paused, nullptr);
        returnedPoint = HistoryContinuationPoint{returnedPoint.namespace_index(),
          returnedPoint.timestamps_to_return(),
          returnedPoint.detail_kind(),
          paused};
        const auto pointBytes = returnedPoint.identifier().as_ua_binary();
        const ByteString point{span<const byte>{pointBytes}};
        auto ready = std::make_shared<std::promise<void>>();
        auto providerFinished = ready->get_future();
        paused->when_done([ready] { ready->set_value(); });
        auto store = store_of(first);

        const auto releaseProvider = [notifier, archivedTime, originalBad, &providerRead]
        {
          BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
          NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
          HistoryEventFieldList fields;
          fields.event_fields().push_back(Variant{LocalizedText{"en", "paused protected archive sentinel"}});
          fields.event_fields().push_back(Variant{archivedTime});
          fields.event_fields().push_back(Variant{originalBad});
          fields.event_fields().push_back(Variant{});
          success.events.push_back(std::move(fields));
          success.origins.push_back({notifier, NodeId{ObjectTypeId::BaseEventType}});
          batch.items.emplace_back(std::move(success));
          auto callback = std::move(providerRead.second);
          callback(std::move(batch));
        };
        const auto revoke = [attribute, revokedSubject, &messageDeclaration, &notifierNode, &eventTypeNode]
        {
          auto permissions = ua::test_helpers::all_permissions();
          if (revokedSubject == 0)
          {
            permissions.reset(
              attribute == AttributeId::Value ? PermissionType::Bit::Read : PermissionType::Bit::Browse);
            ua::test_helpers::set_test_node_permissions(messageDeclaration, permissions);
          }
          else
          {
            permissions.reset(PermissionType::Bit::ReceiveEvents);
            ua::test_helpers::set_test_node_permissions(
              revokedSubject == 1 ? notifierNode : eventTypeNode, permissions);
          }
        };

        if (outcomeReadyBeforeRevocation)
        {
          releaseProvider();
          ASSERT_EQ(providerFinished.wait_for(2s), std::future_status::ready);
          ASSERT_TRUE(paused->done());
          revoke();
        }

        auto resultPromise = std::make_shared<std::promise<HistoryReadService::HistoryReadServiceResponse>>();
        auto completed = resultPromise->get_future();
        auto continuationRequest = makeRequest();
        continuationRequest.nodes_to_read()[0].continuation_point() = point;
        auto continuing = harness.create_service_no_wait(std::move(continuationRequest),
          store,
          [resultPromise](HistoryReadService::HistoryReadServiceResponse response)
          { resultPromise->set_value(std::move(response)); });
        if (!outcomeReadyBeforeRevocation)
        {
          EXPECT_FALSE(paused->done());
          EXPECT_EQ(completed.wait_for(0ms), std::future_status::timeout);
          revoke();
          releaseProvider();
        }

        ASSERT_EQ(completed.wait_for(3s), std::future_status::ready);
        auto second = completed.get();
        auto* response = as_history(second);
        ASSERT_NE(response, nullptr);
        ASSERT_EQ(response->results().size(), 1u);
        EXPECT_TRUE(response->results()[0].status_code().is_good());
        EXPECT_TRUE(response->results()[0].continuation_point().empty());
        auto* events = dynamic_cast<HistoryEvent*>(response->results()[0].history_data().get());
        ASSERT_NE(events, nullptr);
        if (revokedSubject != 0)
        {
          EXPECT_TRUE(events->events().empty())
            << "the current origin ReceiveEvents denial must remove the event";
        }
        else
        {
          ASSERT_EQ(events->events().size(), 1u);
          const auto& fields = events->events()[0].event_fields();
          ASSERT_EQ(fields.size(), 4u);
          const auto* denial = fields[0].try_as<StatusCode>();
          ASSERT_NE(denial, nullptr)
            << "the partial-result continuation disclosed an earlier protected value";
          EXPECT_EQ(*denial, StatusCode{Status::BadUserAccessDenied});
          EXPECT_EQ(fields[1], Variant{archivedTime});
          const auto* bad = fields[2].try_as<StatusCode>();
          ASSERT_NE(bad, nullptr);
          EXPECT_EQ(*bad, originalBad);
          EXPECT_EQ(bad->shared_detail(), originalBad.shared_detail());
          EXPECT_EQ(fields[3], Variant{});
        }
        EXPECT_EQ(providerCalls->load(), 1u);
        continuing.reset();
        paused.reset();
      }
    }
  }
}

// A read still running at the deadline is answered Good with zero values and a continuation point; the
// read goes on, and the HistoryRead that continues the point returns its values.
// @relation(AC-SVR-PARTIAL-RESULTS-002-PAUSE-AND-RESUME, scope=function)
TEST(
  HistoryReadServiceTests, PartialResults_UnfinishedReadIsAnsweredWithAContinuationPointThatReturnsItsValues)
{
  TestHarness h;
  h.setup(true, partial_result_configuration(0.1));
  auto nodeId = h.create_variable_with_history(900);
  HeldRawReads held;
  held.install(*h.delegate);

  auto request = make_read_raw_request({nodeId});
  request.request_header().timeout_hint() = 1000;
  auto first = h.run_service(std::move(request));
  auto* response = as_history(first);
  ASSERT_NE(response, nullptr) << "answered at the deadline, not failed";
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::Good});
  const auto point = response->results()[0].continuation_point();
  ASSERT_FALSE(point.empty());
  auto* zeroValues = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(zeroValues, nullptr);
  EXPECT_EQ(zeroValues->data_values().size(), 0u);
  ASSERT_EQ(first.continuationPoints.size(), 1u);

  ASSERT_TRUE(held.wait_for(1));
  held.release(0, 42);

  auto store = store_of(first);
  auto next = make_read_raw_request({nodeId});
  next.request_header().timeout_hint() = 1000;
  next.nodes_to_read()[0].continuation_point() = point;
  auto second = h.run_service(std::move(next), store);
  auto* secondResponse = as_history(second);
  ASSERT_NE(secondResponse, nullptr);
  EXPECT_EQ(secondResponse->results()[0].status_code(), StatusCode{Status::Good});
  auto* values = dynamic_cast<HistoryData*>(secondResponse->results()[0].history_data().get());
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->data_values().size(), 1u);
  EXPECT_EQ(values->data_values()[0].value().as<int32_t>(), 42);
  EXPECT_TRUE(secondResponse->results()[0].continuation_point().empty());
}

// A continuing HistoryRead whose own deadline comes first returns zero values and a new point; releasing a
// point that owns a running read sets that read's cancellation flag.
// @relation(AC-SVR-PARTIAL-RESULTS-002-WAIT-AGAIN-AND-RELEASE, scope=function)
TEST(HistoryReadServiceTests, PartialResults_ContinuingBeforeTheReadEndsGivesANewPointAndReleaseStopsTheRead)
{
  TestHarness h;
  h.setup(true, partial_result_configuration(0.1));
  auto nodeId = h.create_variable_with_history(901);
  HeldRawReads held;
  held.install(*h.delegate);

  auto request = make_read_raw_request({nodeId});
  request.request_header().timeout_hint() = 1000;
  auto first = h.run_service(std::move(request));
  ASSERT_NE(as_history(first), nullptr);
  const auto firstPoint = as_history(first)->results()[0].continuation_point();
  ASSERT_FALSE(firstPoint.empty());
  ASSERT_TRUE(held.wait_for(1));
  const auto flag = held.context(0).cancelled;
  ASSERT_NE(flag, nullptr);

  auto store = store_of(first);
  auto again = make_read_raw_request({nodeId});
  again.request_header().timeout_hint() = 1000;
  again.nodes_to_read()[0].continuation_point() = firstPoint;
  auto second = h.run_service(std::move(again), store);
  auto* secondResponse = as_history(second);
  ASSERT_NE(secondResponse, nullptr);
  EXPECT_EQ(secondResponse->results()[0].status_code(), StatusCode{Status::Good});
  const auto secondPoint = secondResponse->results()[0].continuation_point();
  ASSERT_FALSE(secondPoint.empty());
  EXPECT_NE(secondPoint, firstPoint);
  EXPECT_FALSE(flag->load()) << "continuing must not stop the read";

  auto secondStore = store_of(second);
  auto release = make_read_raw_request({nodeId});
  release.release_continuation_points() = true;
  release.nodes_to_read()[0].continuation_point() = secondPoint;
  auto released = h.run_service(std::move(release), secondStore);
  ASSERT_NE(as_history(released), nullptr);
  EXPECT_EQ(as_history(released)->results()[0].status_code(), StatusCode{Status::Good});
  secondStore.clear();
  const auto until = std::chrono::steady_clock::now() + 1000ms;
  while (!flag->load() && std::chrono::steady_clock::now() < until)
  {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_TRUE(flag->load()) << "releasing the point must tell the running read to stop";
  held.release(0, 1);  // the late answer has nowhere to go
}

// Control for the tests above: a read finishing before the deadline returns its values and no point.
// @relation(AC-SVR-PARTIAL-RESULTS-002-PAUSE-AND-RESUME, scope=function)
TEST(HistoryReadServiceTests, PartialResults_AReadFinishedBeforeTheDeadlineGetsNoContinuationPoint)
{
  TestHarness h;
  h.setup(true, partial_result_configuration(0.1));
  auto nodeId = h.create_variable_with_history(902);
  h.delegate->set_on_read_raw(
    [](const NamespaceHistoryDelegate::ReadContext&,
      std::vector<NamespaceHistoryDelegate::ReadRawItem>
        items,
      auto callback)
    {
      BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
      for (size_t i = 0; i < items.size(); ++i)
      {
        NamespaceHistoryDelegate::HistoryReadRawSuccess success;
        DataValue dv;
        dv.value() = int32_t{7};
        dv.source_timestamp() = DateTime::now();
        dv.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(dv));
        batch.items.emplace_back(std::move(success));
      }
      callback(std::move(batch));
    });

  auto request = make_read_raw_request({nodeId});
  request.request_header().timeout_hint() = 1000;
  auto first = h.run_service(std::move(request));
  auto* response = as_history(first);
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->results()[0].continuation_point().empty());
  auto* values = dynamic_cast<HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(values, nullptr);
  EXPECT_EQ(values->data_values().size(), 1u);
  EXPECT_TRUE(first.continuationPoints.empty());
}

// With no continuation point left, a new read still running is awaited until the timeoutHint and then
// answered Bad_NoContinuationPoints on its own (OPC 10000-4 section 7.9); the delegate is told the deadline.
// @relation(AC-SVR-PARTIAL-RESULTS-002-NO-CONTINUATION-POINT, scope=function)
TEST(HistoryReadServiceTests, PartialResults_AReadWithNoPointLeftIsAnsweredBadNoContinuationPointsAtTheHint)
{
  TestHarness h;
  h.setup(true, partial_result_configuration(0.25, /*maxHistoryContinuationPoints=*/1));
  auto first = h.create_variable_with_history(903);
  auto second = h.create_variable_with_history(904);
  HeldRawReads held;
  held.install(*h.delegate);

  auto request = make_read_raw_request({first, second});
  request.request_header().timeout_hint() = 400;
  const auto started = std::chrono::steady_clock::now();
  auto answered = h.run_service(std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  auto* response = as_history(answered);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_EQ(response->results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_FALSE(response->results()[0].continuation_point().empty());
  EXPECT_EQ(response->results()[1].status_code(), StatusCode{Status::BadNoContinuationPoints});
  EXPECT_GE(elapsed, 400ms);

  ASSERT_TRUE(held.wait_for(1));
  const auto deadline = held.context(0).deadline;
  ASSERT_TRUE(deadline.has_value()) << "the delegate is told the partial-result deadline (API-10.2)";
  EXPECT_GE(*deadline, started + 100ms);
  EXPECT_LE(*deadline, started + 150ms);
  held.release(0, 3);
}

// A continuing HistoryRead of a paused read is authorized again first, as every continuation is: under a
// downgraded identity it is answered Bad_UserAccessDenied with no values, and the refused read is told to
// stop.
// @relation(AC-SVR-PARTIAL-RESULTS-002-WAIT-REAUTHORIZED, scope=function)
TEST(HistoryReadServiceTests, PartialResults_AContinuationOfAPausedReadIsAuthorizedAgain)
{
  TestHarness h;
  h.setup(true, partial_result_configuration(0.1));
  auto nodeId = h.create_variable_with_history(904);
  HeldRawReads held;
  held.install(*h.delegate);

  auto request = make_read_raw_request({nodeId});
  request.request_header().timeout_hint() = 1000;
  auto first = h.run_service(std::move(request));
  ASSERT_NE(as_history(first), nullptr);
  const auto point = as_history(first)->results()[0].continuation_point();
  ASSERT_FALSE(point.empty());
  ASSERT_TRUE(held.wait_for(1));
  const auto flag = held.context(0).cancelled;
  ASSERT_NE(flag, nullptr);

  h.sessionInfo->set_access_identity_for_test(std::make_shared<AccessIdentity>(AccessIdentityKey{2},
    std::vector<NodeId>{},
    h.sessionInfo->user_identity(),
    h.sessionInfo->endpoint_security(),
    String{"urn:test:downgraded-client"}));

  auto store = store_of(first);
  auto again = make_read_raw_request({nodeId});
  again.request_header().timeout_hint() = 1000;
  again.nodes_to_read()[0].continuation_point() = point;
  auto second = h.run_service(std::move(again), store);
  auto* secondResponse = as_history(second);
  ASSERT_NE(secondResponse, nullptr);
  ASSERT_EQ(secondResponse->results().size(), 1u);
  EXPECT_EQ(secondResponse->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(secondResponse->results()[0].continuation_point().empty());
  EXPECT_TRUE(flag->load()) << "a refused continuation must tell the read it was waiting for to stop";
  held.release(0, 1);  // the late answer has nowhere to go
}
