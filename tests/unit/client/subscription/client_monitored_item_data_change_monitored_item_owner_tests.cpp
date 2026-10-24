// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Tests for the unified, self-acting ua::client::MonitoredItem handle, its abstract
// ua::client::detail::MonitoredItemOwner interface, the opt-in ua::client::ScopedMonitoredItem RAII wrapper
// (client design section 7.4 / tier_remediation_design section 2.2/section 2.3), and the T17 filter
// invariant.
//
// The handle's OWN logic is exercised against a FakeMonitoredItemOwner (no ConnectionImpl, no pipeline, no
// executor - the mockable owner interface is the whole point of T13/TR-3):
//   - modify / set_mode / delete forward through the weak owner interface by clientHandle;
//   - a gone owner (or empty handle) completes Bad_SubscriptionIdInvalid with a source-tagged ErrorDetail;
//   - a bad owner Result (op-level failure) surfaces with its ErrorDetail unchanged (CL-MI-022);
//   - dropping a MonitoredItem is a no-op (persist-on-drop - D-DIAG-1);
//   - ScopedMonitoredItem deletes on drop; a bare MonitoredItem drop does NOT; release()/move transfer the
//     drop-cancel duty exactly once.
//
// Falsifiability: an owner that dropped the call fails the recorded-handle assertion; a handle that flattened
// the ErrorDetail fails CL-MI-022; a ScopedMonitoredItem that never fired fails DropIssuesDelete; a bare
// MonitoredItem that DID delete fails BareDropDoesNotDelete.
//
// @verifies CL-MI-001
// @relation(CL-MI-001, scope=file)
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=file)

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_client_monitored_item.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_change_monitored_item_owner.h"

#include "ua_error_detail.h"

#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::DataChangeCallback;
using ua::client::EventMonitorRequest;
using ua::client::MonitoredItem;
using ua::client::MonitoredItemKind;
using ua::client::MonitorRequest;
using ua::client::ScopedMonitoredItem;
using ua::client::detail::MonitoredItemFactory;
using ua::client::detail::MonitoredItemOwner;

// --- Additional handles for the real-owner revised-state fixture (D5, CL-MI-019/020/021) ---
using ua::client::Connection;
using ua::client::DataChangeEvent;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::Subscription;
using ua::client::SubscriptionConfig;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

// Records every self-action routed to it and replies with a configurable Result (default Good). Synchronous:
// the handle's logic has no strand, so an inline completion faithfully exercises the forward path.
class FakeMonitoredItemOwner : public MonitoredItemOwner
{
public:
  struct ModifyCall
  {
    ua::client::MonitoredItemId handle = 0;
    MonitorRequest request;
  };

  struct SetModeCall
  {
    ua::client::MonitoredItemId handle = 0;
    ua::MonitoringMode mode = ua::MonitoringMode::Reporting;
  };

  std::vector<ModifyCall> modifyCalls;
  std::vector<SetModeCall> setModeCalls;
  std::vector<ua::client::MonitoredItemId> deleteHandles;
  VoidResult nextResult{};  // Good by default

  void mi_modify_async(ua::client::MonitoredItemId clientHandle, MonitorRequest request,
    std::function<void(VoidResult)> callback) noexcept override
  {
    modifyCalls.push_back(ModifyCall{clientHandle, std::move(request)});
    callback(nextResult);
  }

  void mi_set_mode_async(ua::client::MonitoredItemId clientHandle, ua::MonitoringMode mode,
    std::function<void(VoidResult)> callback) noexcept override
  {
    setModeCalls.push_back(SetModeCall{clientHandle, mode});
    callback(nextResult);
  }

  void mi_delete_async(
    ua::client::MonitoredItemId clientHandle, std::function<void(VoidResult)> callback) noexcept override
  {
    deleteHandles.push_back(clientHandle);
    callback(nextResult);
  }
};

MonitoredItem make_item(const std::shared_ptr<FakeMonitoredItemOwner>& owner,
  ua::client::MonitoredItemId handle = 7, MonitoredItemKind kind = MonitoredItemKind::DataChange,
  ua::MonitoringMode mode = ua::MonitoringMode::Reporting)
{
  return MonitoredItemFactory::create(owner, handle, ua::NodeId{2, 100}, ua::AttributeId::Value, kind, mode);
}

// --- Immutable identity / snapshot (CL-MI-001) ---

TEST(MonitoredItem, SnapshotAccessorsReturnConstructionValues)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  const auto item = MonitoredItemFactory::create(owner,
    99,
    ua::NodeId{3, 55},
    ua::AttributeId::DisplayName,
    MonitoredItemKind::Event,
    ua::MonitoringMode::Sampling);

  EXPECT_EQ(item.client_handle(), 99u);
  EXPECT_EQ(item.node_id(), (ua::NodeId{3, 55}));
  EXPECT_EQ(item.attribute(), ua::AttributeId::DisplayName);
  EXPECT_EQ(item.kind(), MonitoredItemKind::Event);
  EXPECT_EQ(item.mode(), ua::MonitoringMode::Sampling);
}

// --- Self-actions reach the owner by clientHandle ---

TEST(MonitoredItem, ModifyReachesOwnerWithHandleAndRequest)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  auto item = make_item(owner, 11);

  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 100};
  request.samplingIntervalMs = 250.0;

  VoidResult received{Status::BadInternalError};
  item.modify_async(request, [&received](VoidResult result) { received = result; });

  ASSERT_EQ(owner->modifyCalls.size(), 1u);
  EXPECT_EQ(owner->modifyCalls.front().handle, 11u);
  EXPECT_EQ(owner->modifyCalls.front().request.samplingIntervalMs, 250.0);
  EXPECT_TRUE(received.is_good());
}

TEST(MonitoredItem, SetModeReachesOwnerWithHandleAndMode)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  auto item = make_item(owner, 12);

  VoidResult received{Status::BadInternalError};
  item.set_mode_async(ua::MonitoringMode::Disabled, [&received](VoidResult result) { received = result; });

  ASSERT_EQ(owner->setModeCalls.size(), 1u);
  EXPECT_EQ(owner->setModeCalls.front().handle, 12u);
  EXPECT_EQ(owner->setModeCalls.front().mode, ua::MonitoringMode::Disabled);
  EXPECT_TRUE(received.is_good());
}

TEST(MonitoredItem, DeleteReachesOwnerWithHandle)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  auto item = make_item(owner, 13);

  VoidResult received{Status::BadInternalError};
  item.delete_async([&received](VoidResult result) { received = result; });

  ASSERT_EQ(owner->deleteHandles.size(), 1u);
  EXPECT_EQ(owner->deleteHandles.front(), 13u);
  EXPECT_TRUE(received.is_good());
}

// A bad owner Result (an op-level DeleteMonitoredItems / Modify / SetMonitoringMode failure) surfaces with
// its ErrorDetail unchanged - the handle never flattens the diagnostic.
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST(MonitoredItem, BadOwnerResultSurfacesErrorDetailUnchanged)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  owner->nextResult = VoidResult{ua::StatusCode{Status::BadUserAccessDenied},
    ua::make_error_detail("Downstream", "op-level delete failure", "test.owner")};
  auto item = make_item(owner, 14);

  VoidResult received{};
  item.delete_async([&received](VoidResult result) { received = result; });

  ASSERT_TRUE(received.is_bad());
  EXPECT_EQ(received.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value());
  ASSERT_NE(received.shared_detail(), nullptr) << "the owner's ErrorDetail must survive (CL-MI-022)";
  EXPECT_EQ(received.shared_detail()->source, "test.owner");
}

// --- Gone owner / empty handle ---

// A gone owner (the weak lock fails) is a fully-closed Connection - the owner is a Connection-lifetime
// component, so a failed lock IS the Connection being gone -> Bad_ConnectionClosed (section 7.4, J19). This
// is DISTINCT from a live-owner registry-lookup miss (Bad_SubscriptionIdInvalid), asserted on the real owner.
TEST(MonitoredItem, GoneOwnerCompletesBadConnectionClosed)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  auto item = make_item(owner, 15);
  owner.reset();  // the connection-lifetime owner is gone; the weak lock fails

  VoidResult modifyResult{};
  item.modify_async(MonitorRequest{}, [&modifyResult](VoidResult result) { modifyResult = result; });
  ASSERT_TRUE(modifyResult.is_bad());
  EXPECT_EQ(modifyResult.status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value());
  ASSERT_NE(modifyResult.shared_detail(), nullptr);
  EXPECT_EQ(modifyResult.shared_detail()->source, "client.tier1.monitored_item.owner_gone");

  VoidResult setModeResult{};
  item.set_mode_async(
    ua::MonitoringMode::Reporting, [&setModeResult](VoidResult result) { setModeResult = result; });
  EXPECT_EQ(setModeResult.status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value());

  VoidResult deleteResult{};
  item.delete_async([&deleteResult](VoidResult result) { deleteResult = result; });
  EXPECT_EQ(deleteResult.status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value());
}

// An empty (default-constructed) handle has no owner at all - the weak lock fails -> Bad_ConnectionClosed
// (there is no live Connection behind it), the same lock-fail surface as a gone owner (J19).
TEST(MonitoredItem, EmptyHandleFastFails)
{
  MonitoredItem empty;  // no owner

  VoidResult result{};
  empty.delete_async([&result](VoidResult r) { result = r; });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value());
}

// --- persist-on-drop: destroying a MonitoredItem is a no-op (D-DIAG-1) ---

TEST(MonitoredItem, DropIsANoOpPersistOnDrop)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  {
    auto item = make_item(owner, 21);
    (void)item;
  }  // item destroyed
  EXPECT_TRUE(owner->deleteHandles.empty())
    << "dropping a MonitoredItem must NOT delete it (persist-on-drop)";
}

// --- Sync wrappers bridge the async forward path ---

TEST(MonitoredItem, TryDeleteSyncReturnsOwnerResult)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  owner->nextResult = VoidResult{ua::StatusCode{Status::BadUserAccessDenied}};
  auto item = make_item(owner, 22);

  const auto result = item.try_delete_sync();
  ASSERT_EQ(owner->deleteHandles.size(), 1u);
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadUserAccessDenied}.value());
}

// --- ScopedMonitoredItem (opt-in RAII drop-cancel, D-DIAG-1) ---

TEST(ScopedMonitoredItem, DropIssuesDelete)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  {
    ScopedMonitoredItem scoped{make_item(owner, 31)};
    EXPECT_EQ(scoped.get().client_handle(), 31u);
  }  // scoped destroyed -> fire-and-forget delete
  ASSERT_EQ(owner->deleteHandles.size(), 1u);
  EXPECT_EQ(owner->deleteHandles.front(), 31u);
}

TEST(ScopedMonitoredItem, BareMonitoredItemDropDoesNotDelete)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  {
    MonitoredItem bare = make_item(owner, 32);
    (void)bare;
  }
  EXPECT_TRUE(owner->deleteHandles.empty()) << "only ScopedMonitoredItem cancels on drop, not a bare handle";
}

TEST(ScopedMonitoredItem, ReleaseCancelsDropDelete)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  {
    ScopedMonitoredItem scoped{make_item(owner, 33)};
    MonitoredItem released = scoped.release();
    EXPECT_EQ(released.client_handle(), 33u);
  }  // scoped destroyed after release -> NO delete
  EXPECT_TRUE(owner->deleteHandles.empty()) << "release() relinquishes the drop-cancel duty";
}

TEST(ScopedMonitoredItem, MoveTransfersDropDutyExactlyOnce)
{
  auto owner = std::make_shared<FakeMonitoredItemOwner>();
  {
    ScopedMonitoredItem first{make_item(owner, 34)};
    ScopedMonitoredItem second{std::move(first)};
    EXPECT_EQ(second.get().client_handle(), 34u);
  }  // both destroyed; only the live one deletes
  EXPECT_EQ(owner->deleteHandles.size(), 1u) << "a moved-from wrapper must not double-delete";
}

// --- T17 filter invariant: compile-time partitioning of data-change vs event filters ---

// The data-change MonitorRequest.filter variant admits a DataChangeFilter/AggregateFilter but NOT an
// EventFilter; the event monitor uses the dedicated EventMonitorRequest with a required EventFilter. This is
// enforced at COMPILE time (a header static_assert); the runtime test documents the partition and pins the
// admissible alternatives so a regression that widened the variant would fail to compile here too.
TEST(MonitorRequestFilterInvariant, DataChangeVariantExcludesEventFilter)
{
  using FilterVariant = decltype(MonitorRequest::filter);
  static_assert(!ua::client::detail::variant_has_alternative<FilterVariant, ua::EventFilter>::value,
    "T17: a data-change MonitorRequest must not admit an EventFilter alternative");
  static_assert(ua::client::detail::variant_has_alternative<FilterVariant, ua::DataChangeFilter>::value,
    "a data-change MonitorRequest admits a DataChangeFilter");
  static_assert(ua::client::detail::variant_has_alternative<FilterVariant, ua::AggregateFilter>::value,
    "a data-change MonitorRequest admits an AggregateFilter");

  MonitorRequest dataChange;
  dataChange.filter = ua::DataChangeFilter{};
  EXPECT_TRUE(std::holds_alternative<ua::DataChangeFilter>(dataChange.filter));

  EventMonitorRequest event;  // event filter lives on the dedicated request, and is REQUIRED
  event.filter = ua::EventFilter{};
  EXPECT_EQ(event.attribute, ua::AttributeId::EventNotifier);
}

// ============================================================================================================
// Revised-state mutability through the REAL DataChangeMonitoredItemOwner (D5, CL-MI-019/020/021)
//
// The FakeMonitoredItemOwner above drives only the handle's forward path; it never applies the server's
// revised values back to the shared MonitoredItemState. These tests therefore exercise the PRODUCTION update
// path end-to-end: a live ConnectionImpl + the real DataChangeMonitoredItemOwner over the tier-0
// FakeSessionOps interface (mirroring SubscriptionHandleTest in subscription_tests.cpp). An item is created
// through the public Subscription facade; modify / set_mode are scripted with responses carrying revised
// values, and the handle's accessors are read AFTER the (blocking) self-action returns - so a Good outcome
// must surface the new values and a Bad outcome must leave the create-time snapshot untouched.
//
// Falsifiability: an owner that failed to store the revised sampling/queue would fail ModifyUpdates...; one
// that updated on a BAD modify would fail FailedModifyKeepsRevisedSnapshot; a set-mode that did not store the
// applied mode would fail SetModeUpdatesLocalMode; a create path that dropped discardOldest onto the wire (or
// the handle) would fail DiscardOldestSurfacedOnHandle; a per-item (non-shared) state would fail
// HandleCopyObservesModify.
// ============================================================================================================

ReconnectPolicy revised_state_fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A single-good-item StatusCode response (DeleteMonitoredItems / DeleteSubscriptions).
template<class Response>
Response make_status_response()
{
  Response response;
  response.results().push_back(ua::StatusCode{Status::Good});
  return response;
}

// A one-item CreateMonitoredItems response carrying the server's revised sampling interval + queue size, so
// the create-time snapshot the handle seeds from is under test control.
ua::CreateMonitoredItemsResponse make_create_response(
  std::uint32_t monitoredItemId, double revisedSampling, std::uint32_t revisedQueue)
{
  ua::CreateMonitoredItemsResponse response;
  ua::MonitoredItemCreateResult item;
  item.status_code() = ua::StatusCode{Status::Good};
  item.monitored_item_id() = monitoredItemId;
  item.revised_sampling_interval() = revisedSampling;
  item.revised_queue_size() = revisedQueue;
  response.results().push_back(std::move(item));
  return response;
}

// A one-item ModifyMonitoredItems response carrying a per-item status + the server's revised sampling/queue.
ua::ModifyMonitoredItemsResponse make_modify_response(double revisedSampling, std::uint32_t revisedQueue,
  ua::StatusCode itemStatus = ua::StatusCode{Status::Good})
{
  ua::ModifyMonitoredItemsResponse response;
  ua::MonitoredItemModifyResult item;
  item.status_code() = itemStatus;
  item.revised_sampling_interval() = revisedSampling;
  item.revised_queue_size() = revisedQueue;
  response.results().push_back(std::move(item));
  return response;
}

// A one-item SetMonitoringMode response carrying the per-item status.
ua::SetMonitoringModeResponse make_set_mode_response(ua::StatusCode itemStatus = ua::StatusCode{Status::Good})
{
  ua::SetMonitoringModeResponse response;
  response.results().push_back(itemStatus);
  return response;
}

// Create-time revised snapshot the fixture seeds every item with (distinct from the modify values below so a
// stale value that failed to update is caught).
constexpr double createSamplingMs = 100.0;
constexpr std::uint32_t createQueue = 5;

// A live Active ConnectionImpl + real DataChangeMonitoredItemOwner over FakeSessionOps (see the block
// comment).
class MonitoredItemRevisedStateTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    ua::CreateSubscriptionResponse createResponse;
    createResponse.subscription_id() = 42;
    createResponse.revised_publishing_interval() = 480.0;
    mSession->createSubscription.set_result(
      Result<ua::CreateSubscriptionResponse>{std::move(createResponse)});
    mSession->createMonitoredItems.set_result(Result<ua::CreateMonitoredItemsResponse>{
      make_create_response(/*monitoredItemId=*/1, createSamplingMs, createQueue)});
    mSession->deleteMonitoredItems.set_result(
      Result<ua::DeleteMonitoredItemsResponse>{make_status_response<ua::DeleteMonitoredItemsResponse>()});
    mSession->deleteSubscriptions.set_result(
      Result<ua::DeleteSubscriptionsResponse>{make_status_response<ua::DeleteSubscriptionsResponse>()});

    mConnection = ConnectionImplTestAccess::create_with_ops(mRuntime.executor(),
      mSession,
      ConnectionConfig{},
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      revised_state_fast_policy(),
      {});
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  Subscription make_subscription()
  {
    Connection connection = ConnectionHandleFactory::make_connection(mConnection);
    return connection.subscriptions().create_sync(SubscriptionConfig{500.0});
  }

  // Creates one data-change item (create-time snapshot createSamplingMs / createQueue) via the public
  // facade.
  MonitoredItem make_created_item(bool discardOldest = true)
  {
    MonitorRequest request;
    request.nodeId = ua::NodeId{2, 7};
    request.discardOldest = discardOldest;
    auto subscription = make_subscription();
    const auto result = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
    EXPECT_TRUE(result.is_good());
    return result.value();
  }
};

// @verifies CL-MI-019
// @relation(CL-MI-019, scope=function)
TEST_F(MonitoredItemRevisedStateTest, ModifyUpdatesRevisedSamplingIntervalAndQueueSize)
{
  MonitoredItem item = make_created_item();
  ASSERT_EQ(item.revised_sampling_interval(), createSamplingMs);
  ASSERT_EQ(item.revised_queue_size(), createQueue);

  mSession->modifyMonitoredItems.set_result(ua::Result<ua::ModifyMonitoredItemsResponse>{
    make_modify_response(/*revisedSampling=*/250.0, /*revisedQueue=*/9)});

  MonitorRequest modifyRequest;
  modifyRequest.samplingIntervalMs = 200.0;
  modifyRequest.queueSize = 8;
  ASSERT_TRUE(item.try_modify_sync(modifyRequest).is_good());

  EXPECT_EQ(item.revised_sampling_interval(), 250.0) << "a Good modify surfaces the server-revised interval";
  EXPECT_EQ(item.revised_queue_size(), 9u) << "a Good modify surfaces the server-revised queue size";
}

// @verifies CL-MI-019
// @relation(CL-MI-019, scope=function)
TEST_F(MonitoredItemRevisedStateTest, FailedModifyKeepsRevisedSnapshot)
{
  MonitoredItem item = make_created_item();

  mSession->modifyMonitoredItems.set_result(ua::Result<ua::ModifyMonitoredItemsResponse>{make_modify_response(
    /*revisedSampling=*/999.0, /*revisedQueue=*/99, ua::StatusCode{Status::BadMonitoredItemIdInvalid})});

  ASSERT_TRUE(item.try_modify_sync(MonitorRequest{}).is_bad());

  EXPECT_EQ(item.revised_sampling_interval(), createSamplingMs)
    << "a bad modify must NOT overwrite the create-time revised interval";
  EXPECT_EQ(item.revised_queue_size(), createQueue)
    << "a bad modify must NOT overwrite the create-time revised queue size";
}

// @verifies CL-MI-021
// @relation(CL-MI-021, scope=function)
TEST_F(MonitoredItemRevisedStateTest, SetModeUpdatesLocalMode)
{
  MonitoredItem item = make_created_item();
  ASSERT_EQ(item.mode(), ua::MonitoringMode::Reporting);

  mSession->setMonitoringMode.set_result(ua::Result<ua::SetMonitoringModeResponse>{make_set_mode_response()});

  ASSERT_TRUE(item.try_set_mode_sync(ua::MonitoringMode::Disabled).is_good());

  EXPECT_EQ(item.mode(), ua::MonitoringMode::Disabled) << "a Good set-mode surfaces the applied mode";
}

// @verifies CL-MI-021
// @relation(CL-MI-021, scope=function)
TEST_F(MonitoredItemRevisedStateTest, FailedSetModeKeepsMode)
{
  MonitoredItem item = make_created_item();
  ASSERT_EQ(item.mode(), ua::MonitoringMode::Reporting);

  mSession->setMonitoringMode.set_result(ua::Result<ua::SetMonitoringModeResponse>{
    make_set_mode_response(ua::StatusCode{Status::BadMonitoredItemIdInvalid})});

  ASSERT_TRUE(item.try_set_mode_sync(ua::MonitoringMode::Disabled).is_bad());

  EXPECT_EQ(item.mode(), ua::MonitoringMode::Reporting) << "a bad set-mode must NOT change the local mode";
}

// @verifies CL-MI-020
// @relation(CL-MI-020, scope=function)
TEST_F(MonitoredItemRevisedStateTest, DiscardOldestSurfacedOnHandle)
{
  MonitoredItem item = make_created_item(/*discardOldest=*/false);

  EXPECT_FALSE(item.discard_oldest()) << "the requested discardOldest=false is surfaced on the handle";

  const auto requests = mSession->createMonitoredItems.requests();
  ASSERT_EQ(requests.size(), 1u);
  ASSERT_EQ(requests.front().items_to_create().size(), 1u);
  EXPECT_FALSE(requests.front().items_to_create()[0].requested_parameters().discard_oldest())
    << "the wire MonitoringParameters must carry discard_oldest=false (not the hardcoded true)";
}

// @verifies CL-MI-019
// @relation(CL-MI-019, scope=function)
TEST_F(MonitoredItemRevisedStateTest, HandleCopyObservesModify)
{
  MonitoredItem item = make_created_item();
  MonitoredItem copy = item;  // a COPY shares the same MonitoredItemState (shared_ptr)
  ASSERT_EQ(copy.revised_sampling_interval(), createSamplingMs);

  mSession->modifyMonitoredItems.set_result(ua::Result<ua::ModifyMonitoredItemsResponse>{
    make_modify_response(/*revisedSampling=*/300.0, /*revisedQueue=*/12)});

  // Apply the modify through the ORIGINAL handle; the copy must observe it via the shared state.
  ASSERT_TRUE(item.try_modify_sync(MonitorRequest{}).is_good());

  EXPECT_EQ(copy.revised_sampling_interval(), 300.0)
    << "a handle copy shares the state, so it observes a modify applied through the original";
  EXPECT_EQ(copy.revised_queue_size(), 12u);
}

}  // namespace
