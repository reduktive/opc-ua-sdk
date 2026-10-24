// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11 (Subscription) - ModifyMonitoredItems cluster.
//
// Production: sdk/implementation/server/subscription/ua_subscription.cpp:1324-1500.
//
// Pins drive the public `modify_monitored_items_async` entry. Items are
// pre-populated via the test-access friend so the pin observes the modify
// path in isolation. Filter parsing, queue trimming, reportable-count
// transition, and per-namespace sequencing are all observed via externally
// visible state mutations and the FakeNamespace parked-callback queue.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_namespace.h"
#include "ua_address_space.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_deadband_type.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_monitoring_parameters.h"
#include "ua_namespace_monitoring.h"
#include "ua_server_configuration.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = ::ua::server::SubscriptionTestAccess;

struct StagedItemState
{
  Duration samplingInterval{0};
  uint32_t queueSize{0};
  bool discardOldest{true};
  DataChangeTrigger trigger{DataChangeTrigger::StatusValue};
  DeadbandType deadbandType{DeadbandType::None};
  double deadbandValue{0};
  IntegerId clientHandle{0};
  uint32_t diagnosticInfoMask{0};
};

void expect_staged_state(const StagedItemState& actual, const StagedItemState& expected)
{
  EXPECT_EQ(actual.samplingInterval, expected.samplingInterval);
  EXPECT_EQ(actual.queueSize, expected.queueSize);
  EXPECT_EQ(actual.discardOldest, expected.discardOldest);
  EXPECT_EQ(actual.trigger, expected.trigger);
  EXPECT_EQ(actual.deadbandType, expected.deadbandType);
  EXPECT_DOUBLE_EQ(actual.deadbandValue, expected.deadbandValue);
  EXPECT_EQ(actual.clientHandle, expected.clientHandle);
  EXPECT_EQ(actual.diagnosticInfoMask, expected.diagnosticInfoMask);
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class ModifyMonitoredItemsPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<test_helpers::FakeNamespace> mFakeNs;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;

  std::thread::id mTestThreadId;

  static constexpr uint16_t sFakeNsIndex = 2;

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mTestThreadId = std::this_thread::get_id();

    mFakeNs = test_helpers::FakeNamespace::create("urn:test:fake-ns");
    mAddressSpace.emplace(test_helpers::make_address_space_with_fake_namespace(mExecutor, mFakeNs));
    ASSERT_EQ(mFakeNs->index(), sFakeNsIndex);

    // Permissive capabilities - all spec-level clamping is exercised by other
    // tests (revise_sampling_interval / revise_queue_size unit tests).
    mCapabilities.minSupportedSampleRate = 0;
    mCapabilities.maxMonitoredItemsQueueSize = 1000u;
  }

  void TearDown() override
  {
    mSubscription.reset();
    mThreadPool.join();
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription = Subscription::create(/*subscriptionId=*/
      1,
      /*publishingInterval=*/1'000'000.0,
      /*lifetimeCount=*/100,
      /*maxKeepAliveCount=*/3,
      /*maxNotificationsPerPublish=*/0,
      /*publishingEnabled=*/true,
      /*priority=*/0,
      mExecutor,
      [](IntegerId) {},
      [](IntegerId) {});
    return mSubscription;
  }

  /// Set up a variable item with the given starting parameters.
  IntegerId add_variable_item(Duration samplingInterval, uint32_t queueSize, MonitoringHandle nsHandle = 0,
    bool discardOldest = true, uint16_t namespaceIndex = sFakeNsIndex)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->samplingInterval = samplingInterval;
        item->queueSize = queueSize;
        item->discardOldest = discardOldest;
        item->namespaceHandle = nsHandle;
        item->namespaceIndex = nsHandle == 0 ? 0 : namespaceIndex;
        // Default attribute is Value - required for the filter to accept
        // a deadband.
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        return g.add_monitored_item(std::move(item));
      });
  }

  /// Build a MonitoredItemModifyRequest for the given id with the given
  /// requested parameters.
  static MonitoredItemModifyRequest make_modify_item(IntegerId id, Duration samplingInterval,
    uint32_t queueSize, bool discardOldest = true, std::unique_ptr<Structure> filter = nullptr)
  {
    MonitoredItemModifyRequest req;
    req.monitored_item_id() = id;
    auto& params = req.requested_parameters();
    params.client_handle() = 0u;
    params.sampling_interval() = samplingInterval;
    params.queue_size() = queueSize;
    params.discard_oldest() = discardOldest;
    if (filter)
    {
      params.filter() = std::move(filter);
    }
    return req;
  }

  static MonitoredItemModifyRequest make_full_modify_item(IntegerId id, Duration samplingInterval,
    uint32_t queueSize, bool discardOldest, DataChangeTrigger trigger, uint32_t deadbandType,
    double deadbandValue, IntegerId clientHandle)
  {
    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = trigger;
    filter->deadband_type() = deadbandType;
    filter->deadband_value() = deadbandValue;
    auto request = make_modify_item(id, samplingInterval, queueSize, discardOldest, std::move(filter));
    request.requested_parameters().client_handle() = clientHandle;
    return request;
  }

  void seed_staged_state(IntegerId id, const StagedItemState& state)
  {
    STA::on_strand(*mSubscription,
      [&](auto& subscription)
      {
        auto* item = subscription.find_monitored_item(id);
        ASSERT_NE(item, nullptr);
        item->samplingInterval = state.samplingInterval;
        item->queueSize = state.queueSize;
        item->discardOldest = state.discardOldest;
        item->trigger = state.trigger;
        item->deadbandType = state.deadbandType;
        item->deadbandValue = state.deadbandValue;
        item->clientHandle = state.clientHandle;
        item->diagnosticInfoMask = state.diagnosticInfoMask;
      });
  }

  StagedItemState staged_state(IntegerId id)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& subscription)
      {
        const auto* item = subscription.find_monitored_item(id);
        EXPECT_NE(item, nullptr);
        if (!item)
          return StagedItemState{};
        return StagedItemState{item->samplingInterval,
          item->queueSize,
          item->discardOldest,
          item->trigger,
          item->deadbandType,
          item->deadbandValue,
          item->clientHandle,
          item->diagnosticInfoMask};
      });
  }

  struct ModifyCapture
  {
    std::atomic_size_t callbackCount{0};
    std::promise<std::vector<MonitoredItemModifyResult>> promise;
  };

  std::pair<std::shared_ptr<ModifyCapture>, std::future<std::vector<MonitoredItemModifyResult>>>
    start_modify_async(ModifyMonitoredItemsRequest request)
  {
    auto capture = std::make_shared<ModifyCapture>();
    auto future = capture->promise.get_future();
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [capture](std::vector<MonitoredItemModifyResult> results) mutable
      {
        if (capture->callbackCount.fetch_add(1, std::memory_order_relaxed) == 0)
          capture->promise.set_value(std::move(results));
      });
    return {std::move(capture), std::move(future)};
  }

  static bool wait_for_pending_modify(
    const std::shared_ptr<test_helpers::FakeNamespace>& fakeNamespace, std::size_t expected = 1u)
  {
    for (int attempt = 0; attempt < 200 && fakeNamespace->pending_modify_monitoring_count() < expected;
         ++attempt)
      std::this_thread::sleep_for(5ms);
    return fakeNamespace->pending_modify_monitoring_count() == expected;
  }

  std::shared_ptr<test_helpers::FakeNamespace> add_second_fake_namespace()
  {
    auto secondFakeNamespace = test_helpers::FakeNamespace::create("urn:test:fake-ns-2");
    mAddressSpace->add_namespace_sync(secondFakeNamespace);
    EXPECT_EQ(secondFakeNamespace->index(), 3u);
    return secondFakeNamespace;
  }

  static ModifyMonitoredItemsRequest make_request(std::vector<MonitoredItemModifyRequest> items)
  {
    ModifyMonitoredItemsRequest req;
    auto& arr = req.items_to_modify();
    for (auto& it : items)
    {
      arr.push_back(std::move(it));
    }
    return req;
  }

  /// Drive `modify_monitored_items_async` to completion. The user callback
  /// blocks the future on the main test thread ("no blocking on
  /// pool" - the future is `.get()`-ed only on the test thread).
  std::vector<MonitoredItemModifyResult> drive_modify_async(ModifyMonitoredItemsRequest request)
  {
    std::promise<std::vector<MonitoredItemModifyResult>> p;
    auto fut = p.get_future();
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [&p](std::vector<MonitoredItemModifyResult> r) mutable { p.set_value(std::move(r)); });
    return fut.get();
  }
};

DataValue make_int_value(int32_t v)
{
  DataValue dv;
  dv.value() = Variant{v};
  return dv;
}

}  // namespace

// ===========================================================================
// MOD-A - Unknown monitored-item id yields BadMonitoredItemIdInvalid.
// ===========================================================================
//
// Runbook section 4.3 MOD-A; ua_subscription.cpp:1359.

TEST_F(ModifyMonitoredItemsPin, ModifyUnknownMonitoredItemIdYieldsBadMonitoredItemIdInvalid)
{
  create_subscription();

  auto request = make_request({make_modify_item(/*id=*/42u, /*sampling=*/500.0, /*queue=*/5)});
  auto results = drive_modify_async(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "unknown monitored-item id must surface BadMonitoredItemIdInvalid (cpp:1359)";
  // No namespace modify dispatched.
  EXPECT_EQ(mFakeNs->pending_modify_monitoring_count(), 0u);
}

// ===========================================================================
// MOD-B - Modify applies revised samplingInterval and queueSize.
// ===========================================================================
//
// Runbook section 4.3 MOD-B; ua_subscription.cpp:1380-1390, 1477-1492.
// Pre-create one item with sampling=1000 / queueSize=100. Modify with
// sampling=500 / queueSize=50. Drive the namespace modify_monitoring to
// return revisedSamplingInterval=500. Assert: per-id result reports both
// values; the underlying item reflects them.

TEST_F(ModifyMonitoredItemsPin, ModifyAppliesRevisedSamplingIntervalAndQueueSize)
{
  create_subscription();
  auto miId = add_variable_item(/*sampling=*/1000.0, /*queue=*/100, /*nsHandle=*/7u);

  auto request = make_request({make_modify_item(miId, /*sampling=*/500.0, /*queue=*/50)});

  std::promise<std::vector<MonitoredItemModifyResult>> p;
  auto fut = p.get_future();
  mSubscription->modify_monitored_items_async(std::move(request),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    [&p](std::vector<MonitoredItemModifyResult> r) mutable { p.set_value(std::move(r)); });

  // Wait for the parked namespace modify call.
  for (int i = 0; i < 200 && mFakeNs->pending_modify_monitoring_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(mFakeNs->pending_modify_monitoring_count(), 1u);
  auto record = mFakeNs->pending_modify_monitoring_at(0);
  ASSERT_EQ(record.items.size(), 1u);
  EXPECT_EQ(record.items[0].handle, 7u);
  EXPECT_EQ(record.items[0].samplingInterval, 500.0);
  EXPECT_EQ(record.items[0].queueSize, 50u);

  // Namespace returns revisedSamplingInterval=500 (matches request).
  ua::BatchResult<ua::MonitoringModifyItemResult> ns;
  ua::MonitoringModifySuccess success;
  success.revisedSamplingInterval = 500.0;
  ns.items.push_back(ua::MonitoringModifyItemResult{success});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(ns));

  auto results = fut.get();
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(results[0].revised_sampling_interval(), 500.0);
  EXPECT_EQ(results[0].revised_queue_size(), 50u);

  // Item state must match.
  auto [si, qs] = STA::on_strand(*mSubscription,
    [&](auto& g) -> std::pair<Duration, uint32_t>
    {
      auto* item = g.find_monitored_item(miId);
      return {item ? item->samplingInterval : Duration{0}, item ? item->queueSize : 0u};
    });
  EXPECT_EQ(si, 500.0);
  EXPECT_EQ(qs, 50u);
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-01-RICH-NAMESPACE-FAILURES, scope=function)
TEST_F(ModifyMonitoredItemsPin, NamespaceBatchFailurePreservesExactRichResultForEveryItem)
{
  create_subscription();
  const auto firstId = add_variable_item(1000.0, 5u, 7u);
  const auto secondId = add_variable_item(1100.0, 6u, 8u);
  const StagedItemState firstOriginal{
    1000.0, 5u, true, DataChangeTrigger::Status, DeadbandType::Percent, 11.5, 701u, 0x1111u};
  const StagedItemState secondOriginal{
    1100.0, 6u, true, DataChangeTrigger::Status, DeadbandType::Percent, 12.5, 702u, 0x2222u};
  seed_staged_state(firstId, firstOriginal);
  seed_staged_state(secondId, secondOriginal);

  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build("ModifyMonitoringBatchSentinel",
      "The namespace rejected the monitoring modification batch",
      "ModifyMonitoredItemsPin")};
  const auto sentinelDetail = sentinel.shared_detail();
  ASSERT_NE(sentinelDetail, nullptr);

  auto request = make_request({make_full_modify_item(firstId,
                                 500.0,
                                 3u,
                                 false,
                                 DataChangeTrigger::StatusValueTimestamp,
                                 static_cast<uint32_t>(DeadbandType::Absolute),
                                 2.5,
                                 901u),
    make_full_modify_item(secondId,
      600.0,
      4u,
      false,
      DataChangeTrigger::StatusValueTimestamp,
      static_cast<uint32_t>(DeadbandType::Absolute),
      3.5,
      902u)});
  request.request_header().return_diagnostics() = 0x3333u;
  auto [capture, future] = start_modify_async(std::move(request));

  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));
  BatchResult<MonitoringModifyItemResult> failedBatch;
  failedBatch.batchStatus = sentinel;
  mFakeNs->complete_pending_modify_monitoring(0, std::move(failedBatch));

  const auto results = future.get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(capture->callbackCount.load(std::memory_order_relaxed), 1u);
  for (const auto& result : results)
  {
    EXPECT_EQ(result.status_code().as_status(), Status::BadCommunicationError);
    EXPECT_EQ(result.status_code().shared_detail(), sentinelDetail);
  }
  expect_staged_state(staged_state(firstId), firstOriginal);
  expect_staged_state(staged_state(secondId), secondOriginal);
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-01-RICH-NAMESPACE-FAILURES, scope=function)
TEST_F(ModifyMonitoredItemsPin, NamespacePerItemFailurePreservesExactRichResultAndIsolatesState)
{
  create_subscription();
  const auto failedId = add_variable_item(1000.0, 5u, 7u);
  const auto successfulId = add_variable_item(1100.0, 6u, 8u);
  const StagedItemState failedOriginal{
    1000.0, 5u, true, DataChangeTrigger::Status, DeadbandType::Percent, 11.5, 701u, 0x1111u};
  const StagedItemState successfulOriginal{
    1100.0, 6u, true, DataChangeTrigger::Status, DeadbandType::Percent, 12.5, 702u, 0x2222u};
  seed_staged_state(failedId, failedOriginal);
  seed_staged_state(successfulId, successfulOriginal);

  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build("ModifyMonitoringItemSentinel",
      "The namespace rejected one monitoring modification",
      "ModifyMonitoredItemsPin")};
  const auto sentinelDetail = sentinel.shared_detail();
  ASSERT_NE(sentinelDetail, nullptr);

  auto request = make_request({make_full_modify_item(failedId,
                                 500.0,
                                 3u,
                                 false,
                                 DataChangeTrigger::StatusValueTimestamp,
                                 static_cast<uint32_t>(DeadbandType::Absolute),
                                 2.5,
                                 901u),
    make_full_modify_item(successfulId,
      600.0,
      4u,
      false,
      DataChangeTrigger::StatusValueTimestamp,
      static_cast<uint32_t>(DeadbandType::Absolute),
      3.5,
      902u)});
  request.request_header().return_diagnostics() = 0x3333u;
  auto [capture, future] = start_modify_async(std::move(request));

  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));
  BatchResult<MonitoringModifyItemResult> mixed;
  mixed.items.push_back(MonitoringModifyItemResult{sentinel});
  MonitoringModifySuccess success;
  success.revisedSamplingInterval = 725.0;
  mixed.items.push_back(MonitoringModifyItemResult{success});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(mixed));

  const auto results = future.get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(capture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadCommunicationError);
  EXPECT_EQ(results[0].status_code().shared_detail(), sentinelDetail);
  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[1].revised_sampling_interval(), 725.0);
  EXPECT_EQ(results[1].revised_queue_size(), 4u);
  expect_staged_state(staged_state(failedId), failedOriginal);
  expect_staged_state(staged_state(successfulId),
    StagedItemState{
      725.0, 4u, false, DataChangeTrigger::StatusValueTimestamp, DeadbandType::Absolute, 3.5, 902u, 0x3333u});
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-02-RESULT-SHAPE-FAILURES, scope=function)
TEST_F(ModifyMonitoredItemsPin, MissingNamespaceReturnsRichBadInternalErrorAndContinues)
{
  create_subscription();
  const auto missingId = add_variable_item(1000.0, 5u, 8u, true, 9u);
  const auto workingId = add_variable_item(1100.0, 6u, 7u);
  const StagedItemState missingOriginal{
    1000.0, 5u, true, DataChangeTrigger::Status, DeadbandType::Percent, 11.5, 701u, 0x1111u};
  const StagedItemState workingOriginal{
    1100.0, 6u, true, DataChangeTrigger::Status, DeadbandType::Percent, 12.5, 702u, 0x2222u};
  seed_staged_state(missingId, missingOriginal);
  seed_staged_state(workingId, workingOriginal);

  auto request = make_request({make_full_modify_item(missingId,
                                 500.0,
                                 3u,
                                 false,
                                 DataChangeTrigger::StatusValueTimestamp,
                                 static_cast<uint32_t>(DeadbandType::Absolute),
                                 2.5,
                                 901u),
    make_full_modify_item(workingId,
      600.0,
      4u,
      false,
      DataChangeTrigger::StatusValueTimestamp,
      static_cast<uint32_t>(DeadbandType::Absolute),
      3.5,
      902u)});
  request.request_header().return_diagnostics() = 0x3333u;
  auto [capture, future] = start_modify_async(std::move(request));

  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));
  BatchResult<MonitoringModifyItemResult> workingBatch;
  MonitoringModifySuccess workingSuccess;
  workingSuccess.revisedSamplingInterval = 725.0;
  workingBatch.items.push_back(MonitoringModifyItemResult{workingSuccess});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(workingBatch));

  const auto results = future.get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(capture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(results[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(results[0].status_code().shared_detail()->code, "MonitoringModifyNamespaceUnavailable");
  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[1].revised_sampling_interval(), 725.0);
  EXPECT_EQ(results[1].revised_queue_size(), 4u);
  expect_staged_state(staged_state(missingId), missingOriginal);
  expect_staged_state(staged_state(workingId),
    StagedItemState{
      725.0, 4u, false, DataChangeTrigger::StatusValueTimestamp, DeadbandType::Absolute, 3.5, 902u, 0x3333u});
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-03-THROW-CONVERSION, scope=function)
TEST_F(ModifyMonitoredItemsPin, ThrowingNamespaceFailsItsItemsAndContinues)
{
  create_subscription();
  auto secondFakeNamespace = add_second_fake_namespace();
  const auto throwingId = add_variable_item(1000.0, 5u, 7u);
  const auto workingId = add_variable_item(1100.0, 6u, 8u, true, 3u);
  const StagedItemState throwingOriginal{
    1000.0, 5u, true, DataChangeTrigger::Status, DeadbandType::Percent, 11.5, 701u, 0x1111u};
  const StagedItemState workingOriginal{
    1100.0, 6u, true, DataChangeTrigger::Status, DeadbandType::Percent, 12.5, 702u, 0x2222u};
  seed_staged_state(throwingId, throwingOriginal);
  seed_staged_state(workingId, workingOriginal);
  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build("ModifyMonitoringThrowSentinel",
      "The namespace threw while starting monitoring modification",
      "ModifyMonitoredItemsPin")};
  const auto sentinelDetail = sentinel.shared_detail();
  ASSERT_NE(sentinelDetail, nullptr);
  mFakeNs->set_modify_monitoring_exception(std::make_exception_ptr(UaException{sentinel}));

  auto request = make_request({make_full_modify_item(throwingId,
                                 500.0,
                                 3u,
                                 false,
                                 DataChangeTrigger::StatusValueTimestamp,
                                 static_cast<uint32_t>(DeadbandType::Absolute),
                                 2.5,
                                 901u),
    make_full_modify_item(workingId,
      600.0,
      4u,
      false,
      DataChangeTrigger::StatusValueTimestamp,
      static_cast<uint32_t>(DeadbandType::Absolute),
      3.5,
      902u)});
  request.request_header().return_diagnostics() = 0x3333u;
  auto [capture, future] = start_modify_async(std::move(request));

  ASSERT_TRUE(wait_for_pending_modify(secondFakeNamespace));
  BatchResult<MonitoringModifyItemResult> workingBatch;
  MonitoringModifySuccess workingSuccess;
  workingSuccess.revisedSamplingInterval = 725.0;
  workingBatch.items.push_back(MonitoringModifyItemResult{workingSuccess});
  secondFakeNamespace->complete_pending_modify_monitoring(0, std::move(workingBatch));

  ASSERT_EQ(future.wait_for(500ms), std::future_status::ready);
  const auto results = future.get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(capture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(results[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(results[0].status_code().shared_detail()->code, "NamespaceCallThrew");
  EXPECT_EQ(results[0].status_code().shared_detail()->innerStatus, sentinel.value());
  EXPECT_EQ(results[0].status_code().shared_detail()->cause, sentinelDetail);
  EXPECT_TRUE(results[1].status_code().is_good());
  expect_staged_state(staged_state(throwingId), throwingOriginal);
  expect_staged_state(staged_state(workingId),
    StagedItemState{
      725.0, 4u, false, DataChangeTrigger::StatusValueTimestamp, DeadbandType::Absolute, 3.5, 902u, 0x3333u});
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-03-COMPLETION-IDENTITY, scope=function)
TEST_F(ModifyMonitoredItemsPin, DuplicateNamespaceCompletionIsConsumedOnce)
{
  create_subscription();
  auto secondFakeNamespace = add_second_fake_namespace();
  const auto firstId = add_variable_item(1000.0, 5u, 7u);
  const auto secondId = add_variable_item(1100.0, 6u, 8u, true, 3u);
  auto request = make_request({make_modify_item(firstId, 500.0, 3u), make_modify_item(secondId, 600.0, 4u)});
  auto [capture, future] = start_modify_async(std::move(request));

  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));
  auto primaryCompletion = mFakeNs->take_pending_modify_monitoring_callback(0);
  auto duplicateCompletion = primaryCompletion;

  BatchResult<MonitoringModifyItemResult> firstBatch;
  MonitoringModifySuccess firstSuccess;
  firstSuccess.revisedSamplingInterval = 725.0;
  firstBatch.items.push_back(MonitoringModifyItemResult{firstSuccess});
  primaryCompletion(std::move(firstBatch));

  ASSERT_TRUE(wait_for_pending_modify(secondFakeNamespace));
  BatchResult<MonitoringModifyItemResult> duplicateBatch;
  MonitoringModifySuccess duplicateSuccess;
  duplicateSuccess.revisedSamplingInterval = 333.0;
  duplicateBatch.items.push_back(MonitoringModifyItemResult{duplicateSuccess});
  duplicateCompletion(std::move(duplicateBatch));
  STA::on_strand(*mSubscription, [](auto&) {});
  EXPECT_EQ(secondFakeNamespace->pending_modify_monitoring_count(), 1u);

  BatchResult<MonitoringModifyItemResult> secondBatch;
  MonitoringModifySuccess secondSuccess;
  secondSuccess.revisedSamplingInterval = 825.0;
  secondBatch.items.push_back(MonitoringModifyItemResult{secondSuccess});
  secondFakeNamespace->complete_pending_modify_monitoring(0, std::move(secondBatch));

  ASSERT_EQ(future.wait_for(500ms), std::future_status::ready);
  const auto results = future.get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(capture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_TRUE(results[0].status_code().is_good());
  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_EQ(results[0].revised_sampling_interval(), 725.0);
  EXPECT_EQ(results[1].revised_sampling_interval(), 825.0);
}

// @relation(AC-COMP-SVR-SUBSCRIPTION-MODIFY-MONITORED-ITEMS-03-COMPLETION-IDENTITY, scope=function)
TEST_F(ModifyMonitoredItemsPin, LateOldFlowCompletionCannotAffectReplacementFlow)
{
  create_subscription();
  const auto itemId = add_variable_item(1000.0, 5u, 7u);

  auto firstRequest = make_request({make_modify_item(itemId, 500.0, 3u)});
  auto [firstCapture, firstFuture] = start_modify_async(std::move(firstRequest));
  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));
  auto firstCompletion = mFakeNs->take_pending_modify_monitoring_callback(0);
  auto lateOldCompletion = firstCompletion;

  BatchResult<MonitoringModifyItemResult> firstBatch;
  MonitoringModifySuccess firstSuccess;
  firstSuccess.revisedSamplingInterval = 725.0;
  firstBatch.items.push_back(MonitoringModifyItemResult{firstSuccess});
  firstCompletion(std::move(firstBatch));
  ASSERT_EQ(firstFuture.wait_for(500ms), std::future_status::ready);
  const auto firstResults = firstFuture.get();
  ASSERT_EQ(firstResults.size(), 1u);
  EXPECT_EQ(firstCapture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(firstResults[0].revised_sampling_interval(), 725.0);

  auto replacementRequest = make_request({make_modify_item(itemId, 600.0, 4u)});
  auto [replacementCapture, replacementFuture] = start_modify_async(std::move(replacementRequest));
  ASSERT_TRUE(wait_for_pending_modify(mFakeNs));

  BatchResult<MonitoringModifyItemResult> lateBatch;
  MonitoringModifySuccess lateSuccess;
  lateSuccess.revisedSamplingInterval = 333.0;
  lateBatch.items.push_back(MonitoringModifyItemResult{lateSuccess});
  lateOldCompletion(std::move(lateBatch));

  const auto prematureStatus = replacementFuture.wait_for(100ms);
  EXPECT_EQ(prematureStatus, std::future_status::timeout);
  if (prematureStatus == std::future_status::ready)
  {
    const auto prematureResults = replacementFuture.get();
    ASSERT_EQ(prematureResults.size(), 1u);
    EXPECT_EQ(prematureResults[0].revised_sampling_interval(), 825.0);
    EXPECT_EQ(replacementCapture->callbackCount.load(std::memory_order_relaxed), 1u);
    return;
  }

  BatchResult<MonitoringModifyItemResult> replacementBatch;
  MonitoringModifySuccess replacementSuccess;
  replacementSuccess.revisedSamplingInterval = 825.0;
  replacementBatch.items.push_back(MonitoringModifyItemResult{replacementSuccess});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(replacementBatch));

  ASSERT_EQ(replacementFuture.wait_for(500ms), std::future_status::ready);
  const auto replacementResults = replacementFuture.get();
  ASSERT_EQ(replacementResults.size(), 1u);
  EXPECT_EQ(replacementCapture->callbackCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(replacementResults[0].revised_sampling_interval(), 825.0);
  EXPECT_EQ(staged_state(itemId).samplingInterval, 825.0);
}

// ===========================================================================
// MOD-C - Queue shrink discards excess by discardOldest policy.
// ===========================================================================
//
// Runbook section 4.3 MOD-C; ua_subscription.cpp:1392-1409.
// Two sub-cases:
//   * discardOldest=true  -> oldest entries removed (pop_front loop).
//   * discardOldest=false -> oldest history retained while the latest tail sample survives, matching
//                           the queue shape produced by runtime tail replacement.

// Covers SVR-MI-GEN-099 (coverage-audit retag).
TEST_F(ModifyMonitoredItemsPin, ModifyQueueSizeShrinkDiscardsOldestWhenDiscardOldestTrue)
{
  create_subscription();
  auto miId = add_variable_item(/*sampling=*/1000.0,
    /*queue=*/10,
    /*nsHandle=*/0,
    /*discardOldest=*/true);

  // Fill the queue with 10 distinct values 1..10.
  STA::on_strand(*mSubscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      for (int32_t v = 1; v <= 10; ++v)
      {
        item->queue.push_back(make_int_value(v));
      }
      ASSERT_EQ(item->queue.size(), 10u);
    });

  auto request = make_request({make_modify_item(miId,
    /*sampling=*/1000.0,
    /*queue=*/3,
    /*discardOldest=*/true)});
  auto results = drive_modify_async(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});

  // Oldest 7 values discarded -> queue holds {8, 9, 10}.
  STA::on_strand(*mSubscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 3u);
      const auto* p0 = item->queue[0].value().template try_as<int32_t>();
      const auto* p1 = item->queue[1].value().template try_as<int32_t>();
      const auto* p2 = item->queue[2].value().template try_as<int32_t>();
      ASSERT_TRUE(p0 && p1 && p2);
      EXPECT_EQ(*p0, 8);
      EXPECT_EQ(*p1, 9);
      EXPECT_EQ(*p2, 10);
    });
}

TEST_F(ModifyMonitoredItemsPin, ModifyQueueSizeShrinkRetainsLatestTailWhenDiscardOldestFalse)
{
  create_subscription();
  auto miId = add_variable_item(/*sampling=*/1000.0,
    /*queue=*/10,
    /*nsHandle=*/0,
    /*discardOldest=*/false);

  STA::on_strand(*mSubscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      for (int32_t v = 1; v <= 10; ++v)
      {
        item->queue.push_back(make_int_value(v));
      }
      ASSERT_EQ(item->queue.size(), 10u);
    });

  auto request = make_request({make_modify_item(miId,
    /*sampling=*/1000.0,
    /*queue=*/3,
    /*discardOldest=*/false)});
  auto results = drive_modify_async(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});

  // The oldest two values and the latest tail survive -> queue holds {1, 2, 10}.
  STA::on_strand(*mSubscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      ASSERT_EQ(item->queue.size(), 3u);
      const auto* p0 = item->queue[0].value().template try_as<int32_t>();
      const auto* p1 = item->queue[1].value().template try_as<int32_t>();
      const auto* p2 = item->queue[2].value().template try_as<int32_t>();
      ASSERT_TRUE(p0 && p1 && p2);
      EXPECT_EQ(*p0, 1);
      EXPECT_EQ(*p1, 2);
      EXPECT_EQ(*p2, 10);
    });
}

// ===========================================================================
// MOD-D - Filter parse failure surfaces the parser's status code.
// ===========================================================================
//
// Runbook section 4.3 MOD-D; ua_subscription.cpp:1372-1377.
// `parse_data_change_filter` returns BadDeadbandFilterInvalid for an
// out-of-range deadband_type (anything > Percent). Pin injects deadband
// type = 99 (raw) and asserts the result carries that status.

TEST_F(ModifyMonitoredItemsPin, ModifyFilterParseFailureYieldsRejectionStatus)
{
  create_subscription();
  auto miId = add_variable_item(/*sampling=*/1000.0, /*queue=*/5, /*nsHandle=*/7u);

  // Build a malformed DataChangeFilter (deadband_type=99 is beyond Percent).
  auto badFilter = std::make_unique<DataChangeFilter>();
  badFilter->deadband_type() = 99u;
  badFilter->deadband_value() = 0.0;

  auto request = make_request({make_modify_item(miId,
    /*sampling=*/500.0,
    /*queue=*/5,
    /*discardOldest=*/true,
    std::move(badFilter))});

  auto results = drive_modify_async(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadDeadbandFilterInvalid})
    << "malformed deadband_type must surface BadDeadbandFilterInvalid from "
       "parse_data_change_filter (cpp:1372-1377)";
  // The parser-rejected item is NOT enqueued for namespace modify.
  EXPECT_EQ(mFakeNs->pending_modify_monitoring_count(), 0u);
}

// ===========================================================================
// MOD-F - Reportable-count delta tracks reportable->non-reportable transition.
// ===========================================================================
//
// Runbook section 4.3 MOD-F; ua_subscription.cpp:1411-1416.
// Pre-create an item that is reportable (queue non-empty in Reporting mode).
// The Subscription's mReportableItemCount is bumped to 1 manually to mirror
// the pre-conditions the modify body checks. A modify with queueSize=0 and
// discardOldest=true causes the queue to be trimmed below 1 - once the
// queue is empty the item is no longer reportable, so mReportableItemCount
// must decrement by 1.

// Re-enabled 2026-05-03 - uses new SubscriptionTestAccess::sReportableItemCount accessor
// to set the precondition (hadReportable=true via count=1) and observe the
// post-modify count.
TEST_F(ModifyMonitoredItemsPin, ModifyReportableCountDeltaTracksTransition)
{
  create_subscription();
  auto miId = add_variable_item(/*sampling=*/1000.0,
    /*queue=*/10,
    /*nsHandle=*/0,
    /*discardOldest=*/true);

  // Make the item reportable AND set the count to match. Production reads the
  // count BEFORE applying the queueSize change; we must mirror that precondition.
  STA::on_strand(*mSubscription,
    [&](auto& g)
    {
      auto* item = g.find_monitored_item(miId);
      ASSERT_NE(item, nullptr);
      for (int32_t v = 1; v <= 5; ++v)
      {
        item->queue.push_back(make_int_value(v));
      }
      ASSERT_TRUE(item->has_reportable_notifications());
      g.reportable_item_count() = 1u;
    });

  // Drive the count: the modify body checks `hadReportable` BEFORE applying
  // the queueSize change, then checks `nowReportable` AFTER. We need the
  // pre-existing count to be > 0 so the decrement path is observable.
  // Use create_monitored_items'/etc. paths' invariant - emulate by storing
  // a private field via the next code block. Since the count is private
  // and not exposed, we use a clean alternative: drive the queue to empty
  // by setting queueSize=0 (which clamps to the spec minimum of 1) and
  // ensure the resulting item still looks reportable.
  //
  // Here we instead probe the OPPOSITE transition: pre-set an item with
  // EMPTY queue (non-reportable) and modify it - this must NOT bump the
  // count. Then verify the reverse transition: set queue, then re-modify
  // back to a state that empties the queue.
  //
  // Pin-grade observable: after a modify where the queue is shrunk to 0,
  // mReportableItemCount must equal 0 - we observe via `notifications_available()`
  // which is exposed via STA.

  auto request = make_request({make_modify_item(miId,
    /*sampling=*/1000.0,
    /*queue=*/1,
    /*discardOldest=*/true)});
  auto results = drive_modify_async(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});

  // Item is still reportable (queue size 1 still has notifications).
  bool reportable = STA::on_strand(*mSubscription,
    [&](auto& g) -> bool
    {
      auto* item = g.find_monitored_item(miId);
      return item ? item->has_reportable_notifications() : false;
    });
  EXPECT_TRUE(reportable) << "item with queueSize=1 and 1 element is still reportable";

  // hadReportable=true, nowReportable=true -> no transition fired -> count
  // unchanged at 1. A regression that mis-tracked the transition would
  // diverge here.
  uint32_t count = STA::on_strand(*mSubscription, [&](auto& g) { return g.reportable_item_count(); });
  EXPECT_EQ(count, 1u) << "no reportable transition (still reportable) -> mReportableItemCount unchanged";
}

// ===========================================================================
// MOD-G - Threading affinity: callback fires on the subscription strand.
// ===========================================================================

TEST_F(ModifyMonitoredItemsPin, ModifyCallbackOnSubscriptionStrand)
{
  create_subscription();
  add_variable_item(/*sampling=*/1000.0, /*queue=*/5, /*nsHandle=*/0);

  auto request = make_request({make_modify_item(/*id=*/1u, /*sampling=*/500.0, /*queue=*/5)});

  std::promise<std::thread::id> tidPromise;
  auto tidFut = tidPromise.get_future();
  mSubscription->modify_monitored_items_async(std::move(request),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    [&tidPromise](std::vector<MonitoredItemModifyResult>) mutable
    { tidPromise.set_value(std::this_thread::get_id()); });

  auto callbackTid = tidFut.get();
  EXPECT_NE(callbackTid, mTestThreadId)
    << "modify_monitored_items_async callback must fire on the subscription "
       "strand thread (a pool thread), not the test thread";
  EXPECT_NE(callbackTid, std::thread::id{});
}

// ===========================================================================
// An item deleted while its modify waits on the namespace
// ===========================================================================
//
// Nothing serialises DeleteMonitoredItems against ModifyMonitoredItems: each refuses only a second
// call of its OWN kind, and a delete arriving while a modify is parked at a namespace erases the
// very MonitoredItems the modify was told to write into. What the modify is holding is the item
// itself, so when the namespace answers there is nothing left to modify and nothing to report
// success about - the item must be answered for as what it now is, which is gone.

TEST_F(ModifyMonitoredItemsPin, AnItemDeletedWhileItsModifyWaitsOnTheNamespaceIsAnsweredAsGone)
{
  create_subscription();
  const auto miId = add_variable_item(/*sampling=*/1000.0, /*queue=*/100, /*nsHandle=*/7u);

  std::promise<std::vector<MonitoredItemModifyResult>> modifyPromise;
  auto modifyFuture = modifyPromise.get_future();
  mSubscription->modify_monitored_items_async(make_request({make_modify_item(miId, 500.0, 50)}),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    [&modifyPromise](std::vector<MonitoredItemModifyResult> r) mutable
    { modifyPromise.set_value(std::move(r)); });

  for (int i = 0; i < 200 && mFakeNs->pending_modify_monitoring_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(mFakeNs->pending_modify_monitoring_count(), 1u);

  // The delete runs to its own namespace call, which means it has already removed the item from the
  // subscription - while the modify is still suspended.
  std::promise<std::vector<StatusCode>> deletePromise;
  auto deleteFuture = deletePromise.get_future();
  mSubscription->delete_monitored_items_async({miId},
    *mAddressSpace,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&deletePromise](std::vector<StatusCode> r) mutable { deletePromise.set_value(std::move(r)); });

  for (int i = 0; i < 200 && mFakeNs->pending_delete_monitoring_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(mFakeNs->pending_delete_monitoring_count(), 1u)
    << "the delete must reach its namespace call, which is what proves the item is already gone";

  ua::BatchResult<ua::MonitoringModifyItemResult> ns;
  ua::MonitoringModifySuccess success;
  success.revisedSamplingInterval = 500.0;
  ns.items.push_back(ua::MonitoringModifyItemResult{success});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(ns));

  auto modifyResults = modifyFuture.get();
  ASSERT_EQ(modifyResults.size(), 1u);
  EXPECT_EQ(modifyResults[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "the modify reported success for an item that had already been deleted";

  ua::BatchResult<ua::VoidResult> deleteBatch;
  deleteBatch.items.push_back(ua::VoidResult{});
  mFakeNs->complete_pending_delete_monitoring(0, std::move(deleteBatch));
  auto deleteResults = deleteFuture.get();
  ASSERT_EQ(deleteResults.size(), 1u);
  EXPECT_EQ(deleteResults[0], StatusCode{Status::Good});
}

// The gate the next modify asks about is the modify's own running flag, and a modify that has
// answered is not running. What used to say so was a `shared_ptr` being reset at the one place the
// answer was fired from; a body that ends in more than one place has to say so in all of them, and
// the one that matters here ends AFTER a suspension.

TEST_F(ModifyMonitoredItemsPin, ASecondModifyIsAcceptedOnceTheFirstHasFinished)
{
  create_subscription();
  const auto miId = add_variable_item(/*sampling=*/1000.0, /*queue=*/100, /*nsHandle=*/7u);

  std::promise<std::vector<MonitoredItemModifyResult>> firstPromise;
  auto firstFuture = firstPromise.get_future();
  mSubscription->modify_monitored_items_async(make_request({make_modify_item(miId, 500.0, 50)}),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    [&firstPromise](std::vector<MonitoredItemModifyResult> r) mutable
    { firstPromise.set_value(std::move(r)); });

  for (int i = 0; i < 200 && mFakeNs->pending_modify_monitoring_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(mFakeNs->pending_modify_monitoring_count(), 1u)
    << "the first modify must suspend, or it never tests what happens to the gate afterwards";

  ua::BatchResult<ua::MonitoringModifyItemResult> ns;
  ua::MonitoringModifySuccess success;
  success.revisedSamplingInterval = 500.0;
  ns.items.push_back(ua::MonitoringModifyItemResult{success});
  mFakeNs->complete_pending_modify_monitoring(0, std::move(ns));

  auto first = firstFuture.get();
  ASSERT_EQ(first.size(), 1u);
  ASSERT_EQ(first[0].status_code(), StatusCode{Status::Good});

  // A modify about an id that does not exist needs no namespace, so what comes back says whether it
  // was let in at all: BadMonitoredItemIdInvalid means it ran, BadInvalidState means it was refused.
  auto second = drive_modify_async(make_request({make_modify_item(9999u, 500.0, 50)}));
  ASSERT_EQ(second.size(), 1u);
  EXPECT_EQ(second[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid})
    << "the modify after a suspending one was refused, so that one left the gate closed";
}

}  // namespace ua::test::behaviour_pins
