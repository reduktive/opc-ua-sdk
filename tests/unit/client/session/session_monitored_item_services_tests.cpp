// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Absent-session guard unit tests for SessionMonitoredItemServices (MonitoredItem Service Set
// forwarder).
//
// Each async method locks its weak_ptr<SessionImpl>; when the owning session has been destroyed the
// guard fast-fails with Bad_SessionIdInvalid instead of dereferencing a dangling pointer. A missing
// guard would crash on the null lock or drop the callback; a still-live (Closed) impl would return
// Bad_SessionClosed. Only a genuinely dead session plus a working guard yields Bad_SessionIdInvalid.

#include <gtest/gtest.h>

#include "client_session_capture_harness.h"
#include "session_service_guard_fixture.h"

#include "ua_error_detail.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_session_monitored_item_services.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

using namespace ua;
using namespace ua::client;
using ua::client::guard_test::DeadSessionHarness;

TEST(SessionMonitoredItemServicesGuard, CreateMonitoredItemsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto items = harness.live().monitored_items();
  ASSERT_TRUE(harness.kill()) << "SessionImpl must be destroyed so the service weak_ptr is expired";

  bool called = false;
  StatusCode status;
  items.create_monitored_items_async(CreateMonitoredItemsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called) << "guard must invoke the callback synchronously, not drop it";
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionMonitoredItemServicesGuard, ModifyMonitoredItemsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto items = harness.live().monitored_items();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  items.modify_monitored_items_async(ModifyMonitoredItemsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionMonitoredItemServicesGuard, SetMonitoringModeOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto items = harness.live().monitored_items();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  items.set_monitoring_mode_async(SetMonitoringModeRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionMonitoredItemServicesGuard, SetTriggeringOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto items = harness.live().monitored_items();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  items.set_triggering_async(SetTriggeringRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

TEST(SessionMonitoredItemServicesGuard, DeleteMonitoredItemsOnDeadSessionReturnsBadSessionIdInvalid)
{
  DeadSessionHarness harness;
  auto items = harness.live().monitored_items();
  ASSERT_TRUE(harness.kill());

  bool called = false;
  StatusCode status;
  items.delete_monitored_items_async(DeleteMonitoredItemsRequest{},
    [&](auto result)
    {
      called = true;
      status = result.status_code();
    });

  EXPECT_TRUE(called);
  EXPECT_EQ(status, StatusCode{Status::BadSessionIdInvalid});
}

// --- Service-result and per-item / per-link error surfacing (CL-MI-022, CL-MI-029) ---
//
// The MonitoredItem service set is a tier-0 forwarder: each *_async call sends the request down the
// real Session -> SecureChannel send path and hands the whole Result<Response> back to the caller.
// The requirement obligations these tests pin are:
//   * op-level per-item / per-link bad StatusCodes reach the caller positionally WITHOUT the call as
//     a whole being aborted (a bad item is not fatal to the batch); and
//   * a service-level failure surfaces as a bad Result carrying the server's ErrorDetail, not a good
//     empty response and not a stripped detail.
// Each test drives the real service method over the capture harness, injects a synthetic response,
// and asserts the surfaced Result. A forwarder that collapsed a bad per-item code into a whole-call
// failure, dropped the per-item vector, reordered results, or discarded the ErrorDetail would fail.

namespace
{

using namespace std::chrono_literals;
using ua::client::test_capture::CaptureHarness;

/// Blocks a test thread until an async service callback fires and captures the delivered Result.
template<typename ResponseT>
class ResultSink
{
public:
  std::function<void(ua::Result<ResponseT>)> callback()
  {
    return [this](ua::Result<ResponseT> result)
    {
      {
        std::lock_guard<std::mutex> lock(mMutex);
        mResult.emplace(std::move(result));
        mCondition.notify_one();
      }
    };
  }

  [[nodiscard]] bool await(std::chrono::milliseconds timeout = 1000ms)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mCondition.wait_for(lock, timeout, [this] { return mResult.has_value(); });
  }

  [[nodiscard]] const ua::Result<ResponseT>& result() const
  {
    return *mResult;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::optional<ua::Result<ResponseT>> mResult;
};

/// Resolve the oldest parked channel request with a bad ServiceResponseResult carrying an ErrorDetail,
/// reproducing the post-decode state the SecureChannel produces for a server ServiceFault. This drives
/// the tier-0 forwarder's service-level-error branch, which must forward the status and ErrorDetail
/// unchanged rather than swallowing them, rewriting the code, or downcast-failing to Bad_DecodingError.
bool inject_service_fault(
  CaptureHarness& harness, StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
{
  return SecureChannelTestAccess::on_strand(*harness.channel,
    [status, detail = std::move(detail)](auto& guard) mutable
    {
      auto& pending = guard.pending_requests();
      if (pending.empty())
      {
        return false;
      }
      auto it = pending.begin();
      auto callback = std::move(it->second);
      pending.erase(it);
      callback(SecureChannelImpl::ServiceResponseResult{status, std::move(detail)});
      return true;
    });
}

}  // namespace

// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST(SessionMonitoredItemServicesErrors, ModifySurfacesPerItemBadResultWithoutAbortingCall)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<ModifyMonitoredItemsResponse> sink;
    items.modify_monitored_items_async(ModifyMonitoredItemsRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "modify_monitored_items_async must forward the request down the real send path";
    ASSERT_TRUE(harness.first_captured<ModifyMonitoredItemsRequest>().has_value())
      << "the ModifyMonitoredItemsRequest must travel the real Session -> SecureChannel path";

    auto response = std::make_shared<ModifyMonitoredItemsResponse>();
    response->response_header().service_result() = Status::Good;
    MonitoredItemModifyResult goodItem;
    goodItem.status_code() = Status::Good;
    MonitoredItemModifyResult badItem;
    badItem.status_code() = Status::BadMonitoredItemIdInvalid;
    response->results().push_back(std::move(goodItem));
    response->results().push_back(std::move(badItem));
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_good())
      << "a per-item bad status must not abort the whole Modify call at the tier-0 forwarder";
    ASSERT_EQ(result.value().results().size(), 2u);
    EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::Good});
    EXPECT_EQ(result.value().results()[1].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
      << "the per-item bad StatusCode must reach the caller positionally";
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST(SessionMonitoredItemServicesErrors, SetMonitoringModeSurfacesFirstItemBadResultWithoutAbortingCall)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<SetMonitoringModeResponse> sink;
    items.set_monitoring_mode_async(SetMonitoringModeRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "set_monitoring_mode_async must forward the request down the real send path";
    ASSERT_TRUE(harness.first_captured<SetMonitoringModeRequest>().has_value())
      << "the SetMonitoringModeRequest must travel the real Session -> SecureChannel path";

    // First item bad: proves a bad head-of-list result does not abort the batch.
    auto response = std::make_shared<SetMonitoringModeResponse>();
    response->response_header().service_result() = Status::Good;
    response->results().push_back(StatusCode{Status::BadMonitoringModeInvalid});
    response->results().push_back(StatusCode{Status::Good});
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_good())
      << "a bad first per-item status must not abort the whole SetMonitoringMode call";
    ASSERT_EQ(result.value().results().size(), 2u);
    EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadMonitoringModeInvalid})
      << "the per-item bad StatusCode must reach the caller positionally";
    EXPECT_EQ(result.value().results()[1], StatusCode{Status::Good});
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST(SessionMonitoredItemServicesErrors, DeleteSurfacesPerItemBadResultWithoutAbortingCall)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<DeleteMonitoredItemsResponse> sink;
    items.delete_monitored_items_async(DeleteMonitoredItemsRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "delete_monitored_items_async must forward the request down the real send path";
    ASSERT_TRUE(harness.first_captured<DeleteMonitoredItemsRequest>().has_value())
      << "the DeleteMonitoredItemsRequest must travel the real Session -> SecureChannel path";

    auto response = std::make_shared<DeleteMonitoredItemsResponse>();
    response->response_header().service_result() = Status::Good;
    response->results().push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_good())
      << "a per-item bad status must not abort the whole Delete call at the tier-0 forwarder";
    ASSERT_EQ(result.value().results().size(), 1u);
    EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadMonitoredItemIdInvalid})
      << "the per-item bad StatusCode must reach the caller";
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST(SessionMonitoredItemServicesErrors, ModifyServiceLevelErrorSurfacesWithErrorDetail)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<ModifyMonitoredItemsResponse> sink;
    items.modify_monitored_items_async(ModifyMonitoredItemsRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "modify_monitored_items_async must forward the request down the real send path";

    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::make_error_detail("ServiceFault", "Server returned a ServiceFault", "server"));
    ASSERT_TRUE(inject_service_fault(harness, Status::BadTooManyOperations, std::move(detail)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_bad())
      << "a service-level failure must surface as a bad Result, not a good empty response";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
    ASSERT_NE(result.shared_detail(), nullptr) << "the server ErrorDetail must not be discarded";
    EXPECT_EQ(result.shared_detail()->code, "ServiceFault");
    EXPECT_EQ(result.shared_detail()->source, "server");
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST(SessionMonitoredItemServicesErrors, SetTriggeringSurfacesPerLinkBadResultsWithoutAbortingCall)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<SetTriggeringResponse> sink;
    items.set_triggering_async(SetTriggeringRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "set_triggering_async must forward the request down the real send path";
    ASSERT_TRUE(harness.first_captured<SetTriggeringRequest>().has_value())
      << "the SetTriggeringRequest must travel the real Session -> SecureChannel path";

    // Distinct per-link outcomes in both add and remove lists: both arrays must survive intact.
    auto response = std::make_shared<SetTriggeringResponse>();
    response->response_header().service_result() = Status::Good;
    response->add_results().push_back(StatusCode{Status::Good});
    response->add_results().push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
    response->remove_results().push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
    ASSERT_TRUE(harness.inject_channel_response(std::move(response)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_good()) << "per-link bad results must not abort the whole SetTriggering call";
    ASSERT_EQ(result.value().add_results().size(), 2u);
    EXPECT_EQ(result.value().add_results()[0], StatusCode{Status::Good});
    EXPECT_EQ(result.value().add_results()[1], StatusCode{Status::BadMonitoredItemIdInvalid})
      << "the per-link addResults bad StatusCode must reach the caller positionally";
    ASSERT_EQ(result.value().remove_results().size(), 1u);
    EXPECT_EQ(result.value().remove_results()[0], StatusCode{Status::BadMonitoredItemIdInvalid})
      << "the per-link removeResults bad StatusCode must reach the caller";
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}

// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST(SessionMonitoredItemServicesErrors, SetTriggeringServiceLevelErrorSurfacesWithErrorDetail)
{
  boost::asio::thread_pool pool;
  auto harness = CaptureHarness::create_active(pool.get_executor());
  {
    auto session = harness.session_handle();
    auto items = session.monitored_items();

    ResultSink<SetTriggeringResponse> sink;
    items.set_triggering_async(SetTriggeringRequest{}, sink.callback());

    ASSERT_TRUE(harness.wait_for_pending_request())
      << "set_triggering_async must forward the request down the real send path";

    auto detail = std::shared_ptr<const ua::ErrorDetail>(
      ua::make_error_detail("ServiceFault", "Server returned a ServiceFault", "server"));
    ASSERT_TRUE(inject_service_fault(harness, Status::BadNothingToDo, std::move(detail)));

    ASSERT_TRUE(sink.await()) << "the caller callback must fire";
    const auto& result = sink.result();
    ASSERT_TRUE(result.is_bad()) << "a service-level SetTriggering failure must surface as a bad Result";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
    ASSERT_NE(result.shared_detail(), nullptr) << "the server ErrorDetail must not be discarded";
    EXPECT_EQ(result.shared_detail()->code, "ServiceFault");
  }
  harness.cleanup_sync();
  harness.release();
  ua::test_utils::drain_with_timeout(pool);
}
