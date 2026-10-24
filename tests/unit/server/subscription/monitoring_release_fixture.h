// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The MonitoringRelease fixture, shared by monitoring_release_tests.cpp and the tests of the release
// routine's own API (monitoring_release_api_tests.cpp): GoogleTest requires every test of one suite to use
// one fixture class, so the class lives here rather than in either file's anonymous namespace.

#ifndef UA_TEST_MONITORING_RELEASE_FIXTURE_H
#define UA_TEST_MONITORING_RELEASE_FIXTURE_H

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "monitoring_recording_namespace.h"
#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_error_detail.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <optional>
#include <sstream>
#include <variant>
#include <mutex>
#include <span>
#include <stdexcept>

namespace ua::test::monitoring_release
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;
using ua::test::MonitoringRecordingNamespace;

inline std::vector<MonitoringHandle> sorted(std::vector<MonitoringHandle> handles)
{
  std::sort(handles.begin(), handles.end());
  return handles;
}

inline std::string text(const std::vector<MonitoringHandle>& handles)
{
  std::string out = "{";
  for (const auto handle : handles)
  {
    out += (out.size() > 1 ? ", " : "") + std::to_string(handle);
  }
  return out + "}";
}

inline bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 3s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(2ms);
  }
  return true;
}

class MonitoringRelease : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mNs2 = MonitoringRecordingNamespace::create("urn:test:monitoring-release:2", mExecutor, 100);
    mNs3 = MonitoringRecordingNamespace::create("urn:test:monitoring-release:3", mExecutor, 300);
    for (const auto& [ns, expected] : {std::pair{mNs2, uint16_t{2}}, std::pair{mNs3, uint16_t{3}}})
    {
      auto index = mAddressSpace->try_add_namespace_sync(ns);
      ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
      ASSERT_EQ(index.value(), expected) << "the test names its namespaces by index";
    }
    for (uint32_t i = 1; i <= 3; ++i)
    {
      create_variable(NodeId{2, i});
      create_variable(NodeId{3, i});
    }
    // After the namespaces are registered: the security context grants every default namespace to its Role.
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    mCapabilities.minSupportedSampleRate = 0;
  }

  void TearDown() override
  {
    for (const auto& ns : {mNs2, mNs3})
    {
      if (ns)
      {
        ns->release_create_answers();
        ns->release_delete_answers();
        ns->release_value_reads();
      }
    }
    mSecurityContext.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_variable(const NodeId& nodeId)
  {
    auto node = mAddressSpace->create_node_sync(nodeId, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{nodeId.namespace_index(), "Value"});
    accessor->set_data_type(NodeId{DataTypeId::Double});
    accessor->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    accessor->write_value_sync(Variant{0.0});
  }

  std::shared_ptr<Subscription> make_subscription()
  {
    return Subscription::create(
      1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  static MonitoredItemCreateRequest value_item(
    const NodeId& nodeId, uint32_t clientHandle, std::unique_ptr<DataChangeFilter> filter = nullptr)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = nodeId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 100;
    item.requested_parameters().queue_size() = 1;
    item.requested_parameters().discard_oldest() = true;
    if (filter)
    {
      item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
    }
    return item;
  }

  static std::unique_ptr<DataChangeFilter> percent_deadband(double percent)
  {
    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Percent);
    filter->deadband_value() = percent;
    return filter;
  }

  std::future<std::vector<MonitoredItemCreateResult>> start_create(
    Subscription& subscription, std::vector<MonitoredItemCreateRequest> items)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& item : items)
    {
      request.items_to_create().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    subscription.create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      mSecurityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<MonitoredItemCreateResult> results) { promise->set_value(std::move(results)); });
    return future;
  }

  static std::vector<MonitoredItemCreateResult> finish(
    std::future<std::vector<MonitoredItemCreateResult>>& future)
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return {};
    }
    return future.get();
  }

  std::vector<MonitoredItemCreateResult> create(
    Subscription& subscription, std::vector<MonitoredItemCreateRequest> items)
  {
    auto future = start_create(subscription, std::move(items));
    return finish(future);
  }

  /// Creates one item on each of @p nodeIds, every one expected Good; returns their ids.
  std::vector<IntegerId> create_good(Subscription& subscription, const std::vector<NodeId>& nodeIds)
  {
    std::vector<MonitoredItemCreateRequest> items;
    uint32_t clientHandle = 1;
    for (const auto& nodeId : nodeIds)
    {
      items.push_back(value_item(nodeId, clientHandle++));
    }
    const auto results = create(subscription, std::move(items));
    std::vector<IntegerId> ids;
    EXPECT_EQ(results.size(), nodeIds.size());
    for (const auto& result : results)
    {
      EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
      ids.push_back(result.monitored_item_id());
    }
    return ids;
  }

  std::future<std::vector<StatusCode>> start_delete(Subscription& subscription, std::vector<IntegerId> ids)
  {
    auto promise = std::make_shared<std::promise<std::vector<StatusCode>>>();
    auto future = promise->get_future();
    subscription.delete_monitored_items_async(std::move(ids),
      *mAddressSpace,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<StatusCode> results) { promise->set_value(std::move(results)); });
    return future;
  }

  static void close(Subscription& subscription)
  {
    std::promise<void> closed;
    auto done = closed.get_future();
    subscription.close_async([&closed] { closed.set_value(); });
    ASSERT_EQ(done.wait_for(5s), std::future_status::ready) << "close_async did not complete";
  }

  /// Drops the last reference to @p subscription and waits until it has been destroyed.
  static void destroy(std::shared_ptr<Subscription>& subscription)
  {
    std::weak_ptr<Subscription> weak = subscription;
    subscription.reset();
    ASSERT_TRUE(wait_until([&weak] { return weak.expired(); })) << "the Subscription was not destroyed";
  }

  /// Deletes @p subscription as DeleteSubscriptions does: closes it, then drops it.
  static void delete_subscription(std::shared_ptr<Subscription>& subscription)
  {
    close(*subscription);
    destroy(subscription);
  }

  std::size_t item_count(Subscription& subscription)
  {
    return STA::on_strand(subscription, [](auto& guard) { return guard.monitored_items().size(); });
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<MonitoringRecordingNamespace> mNs2;
  std::shared_ptr<MonitoringRecordingNamespace> mNs3;
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

/// A namespace with real nodes - so a Subscription can look them up, authorize them and read their initial
/// values - that overrides only the batched monitoring members (`create_monitoring_async`,
/// `modify_monitoring_async`, `delete_monitoring_async`), not the older ones, and records each call:
///
/// - the create issues handles from a counter (or from the list the test gives) and answers each item Good,
///   with the sampling interval it was given; it can instead throw `std::runtime_error`, or complete twice,
///   each completion with new handles.
/// - the modify answers each item Good with the sampling interval it was given, or with a revised interval
/// the
///   test gives; it can instead throw `std::runtime_error`, or answer one Good result whatever the item
///   count.
/// - the delete answers each handle Good.
///
/// Every answer is given inline, on the thread that calls the member.
class BatchedMonitoringNamespace final : public default_ns::Namespace
{
public:
  enum class CreateAnswer
  {
    Issue,  ///< One completion with a handle for every item.
    Throw,  ///< Throws `std::runtime_error`, completing nothing.
    IssueTwice,  ///< Two completions, one after the other, each with a new handle for every item.
    IssueThenThrow,  ///< One completion with a handle for every item, then throws `std::runtime_error`.
  };

  enum class ModifyAnswer
  {
    Echo,  ///< Every item Good, revised to the sampling interval it was given.
    Revise,  ///< Every item Good, revised to the interval given to @ref answer_modifies.
    Throw,  ///< Throws `std::runtime_error`, completing nothing.
    OneResult,  ///< One Good result, revised to the interval given to @ref answer_modifies, for any item
                ///< count.
  };

  /// One `create_monitoring_async` call: its item count and the `caller` it was given.
  struct CreateCall
  {
    std::size_t items{0};
    const CallerInfo* caller{nullptr};
  };

  static std::shared_ptr<BatchedMonitoringNamespace> create(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle = 1)
  {
    return std::shared_ptr<BatchedMonitoringNamespace>(
      new BatchedMonitoringNamespace(uri, std::move(executor), firstHandle));
  }

  void answer_creates(CreateAnswer how)
  {
    const std::lock_guard lock{mMutex};
    mCreateAnswer = how;
  }

  void answer_modifies(ModifyAnswer how, Duration revised = 0)
  {
    const std::lock_guard lock{mMutex};
    mModifyAnswer = how;
    mRevised = revised;
  }

  /// The handles the next completions issue, in order, before the counter is used again.
  void issue_next(std::vector<MonitoringHandle> handles)
  {
    const std::lock_guard lock{mMutex};
    mScripted.insert(mScripted.end(), handles.begin(), handles.end());
  }

  std::vector<CreateCall> create_calls() const
  {
    const std::lock_guard lock{mMutex};
    return mCreateCalls;
  }

  /// The handles each `modify_monitoring_async` call named, one entry per call.
  std::vector<std::vector<MonitoringHandle>> modify_calls() const
  {
    const std::lock_guard lock{mMutex};
    return mModifyCalls;
  }

  /// The handles each `delete_monitoring_async` call named, one entry per call.
  std::vector<std::vector<MonitoringHandle>> delete_calls() const
  {
    const std::lock_guard lock{mMutex};
    return mDeleteCalls;
  }

  /// Every handle a `delete_monitoring_async` call named, in order.
  std::vector<MonitoringHandle> released_handles() const
  {
    const std::lock_guard lock{mMutex};
    std::vector<MonitoringHandle> out;
    for (const auto& call : mDeleteCalls)
    {
      out.insert(out.end(), call.begin(), call.end());
    }
    return out;
  }

  void create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete) override
  {
    (void)request;
    CreateAnswer how{CreateAnswer::Issue};
    BatchResult<MonitoringCreateItemResult> first;
    BatchResult<MonitoringCreateItemResult> second;
    {
      const std::lock_guard lock{mMutex};
      mCreateCalls.push_back(CreateCall{items.size(), caller});
      how = mCreateAnswer;
      if (how != CreateAnswer::Throw)
      {
        first = issue_locked(items);
      }
      if (how == CreateAnswer::IssueTwice)
      {
        second = issue_locked(items);
      }
    }
    if (how == CreateAnswer::Throw)
    {
      throw std::runtime_error{"the test namespace's create_monitoring_async throws"};
    }
    complete(std::move(first));
    if (how == CreateAnswer::IssueTwice)
    {
      complete(std::move(second));
    }
    if (how == CreateAnswer::IssueThenThrow)
    {
      throw std::runtime_error{"the test namespace's create_monitoring_async throws after answering"};
    }
  }

  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) override
  {
    (void)request;
    ModifyAnswer how{ModifyAnswer::Echo};
    Duration revised = 0;
    {
      const std::lock_guard lock{mMutex};
      std::vector<MonitoringHandle> handles;
      for (const auto& item : items)
      {
        handles.push_back(item.handle);
      }
      mModifyCalls.push_back(std::move(handles));
      how = mModifyAnswer;
      revised = mRevised;
    }
    if (how == ModifyAnswer::Throw)
    {
      throw std::runtime_error{"the test namespace's modify_monitoring_async throws"};
    }
    BatchResult<MonitoringModifyItemResult> answer;
    if (how == ModifyAnswer::OneResult)
    {
      answer.items.emplace_back(MonitoringModifySuccess{revised});
    }
    else
    {
      for (const auto& item : items)
      {
        answer.items.emplace_back(
          MonitoringModifySuccess{how == ModifyAnswer::Revise ? revised : item.samplingInterval});
      }
    }
    complete(std::move(answer));
  }

  void delete_monitoring_async(const RequestInfo& request, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> complete) override
  {
    (void)request;
    {
      const std::lock_guard lock{mMutex};
      mDeleteCalls.emplace_back(handles.begin(), handles.end());
    }
    BatchResult<VoidResult> answer;
    answer.items.resize(handles.size());
    complete(std::move(answer));
  }

private:
  BatchedMonitoringNamespace(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle)
    : default_ns::Namespace(uri, std::move(executor)), mNextHandle(firstHandle)
  {}

  /// A completion with a new handle for each of @p items. Called with the mutex held.
  BatchResult<MonitoringCreateItemResult> issue_locked(std::span<const MonitoringCreateItem> items)
  {
    BatchResult<MonitoringCreateItemResult> answer;
    for (const auto& item : items)
    {
      MonitoringHandle handle = 0;
      if (!mScripted.empty())
      {
        handle = mScripted.front();
        mScripted.erase(mScripted.begin());
      }
      else
      {
        handle = mNextHandle++;
      }
      answer.items.emplace_back(MonitoringCreateSuccess{handle, item.samplingInterval});
    }
    return answer;
  }

  mutable std::mutex mMutex;
  CreateAnswer mCreateAnswer{CreateAnswer::Issue};
  ModifyAnswer mModifyAnswer{ModifyAnswer::Echo};
  Duration mRevised{0};
  MonitoringHandle mNextHandle;
  std::vector<MonitoringHandle> mScripted;
  std::vector<CreateCall> mCreateCalls;
  std::vector<std::vector<MonitoringHandle>> mModifyCalls;
  std::vector<std::vector<MonitoringHandle>> mDeleteCalls;
};

/// A namespace with real nodes that overrides only the older monitoring members (`create_monitoring`,
/// `modify_monitoring`, `delete_monitoring`), not the batched ones, so it is reached through the batched
/// members' temporary defaults:
///
/// - the create answers each item Good with a handle from a counter, inline.
/// - the modify answers each item Good, revised to the interval the test gives (else the one it was given),
///   inline, and then throws `UaException` with the status the test gives, if it gives one.
/// - the delete records the handles, answers each Good, inline, and then throws `UaException` with the status
///   the test gives, if it gives one.
class OlderMonitoringNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<OlderMonitoringNamespace> create(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle = 1)
  {
    return std::shared_ptr<OlderMonitoringNamespace>(
      new OlderMonitoringNamespace(uri, std::move(executor), firstHandle));
  }

  /// Later modify calls answer every item Good revised to @p revised, then throw `UaException` with @p
  /// thrown.
  void modify_answers_then_throws(Duration revised, StatusCode thrown)
  {
    const std::lock_guard lock{mMutex};
    mModifyRevised = revised;
    mModifyThrow = thrown;
  }

  /// Later delete calls answer every handle Good, then throw `UaException` with @p thrown.
  void delete_answers_then_throws(StatusCode thrown)
  {
    const std::lock_guard lock{mMutex};
    mDeleteThrow = thrown;
  }

  /// Every handle a delete call named, in order.
  std::vector<MonitoringHandle> released_handles() const
  {
    const std::lock_guard lock{mMutex};
    return mReleased;
  }

  void create_monitoring_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
    std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> callback) override
  {
    BatchResult<MonitoringCreateItemResult> answer;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        answer.items.emplace_back(MonitoringCreateSuccess{mNextHandle++, item.samplingInterval});
      }
    }
    callback(std::move(answer));
  }

  void modify_monitoring_async(const RequestInfo& /*request*/, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> callback) override
  {
    std::optional<Duration> revised;
    std::optional<StatusCode> thrown;
    {
      const std::lock_guard lock{mMutex};
      revised = mModifyRevised;
      thrown = mModifyThrow;
    }
    BatchResult<MonitoringModifyItemResult> answer;
    for (const auto& item : items)
    {
      answer.items.emplace_back(MonitoringModifySuccess{revised.value_or(item.samplingInterval)});
    }
    callback(std::move(answer));
    if (thrown)
    {
      throw UaException(*thrown);
    }
  }

  void delete_monitoring_async(const RequestInfo& /*request*/, std::span<const MonitoringHandle> handles,
    std::function<void(BatchResult<VoidResult>)> callback) override
  {
    std::optional<StatusCode> thrown;
    {
      const std::lock_guard lock{mMutex};
      mReleased.insert(mReleased.end(), handles.begin(), handles.end());
      thrown = mDeleteThrow;
    }
    BatchResult<VoidResult> answer;
    answer.items.resize(handles.size());
    callback(std::move(answer));
    if (thrown)
    {
      throw UaException(*thrown);
    }
  }

private:
  OlderMonitoringNamespace(
    string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle)
    : default_ns::Namespace(uri, std::move(executor)), mNextHandle(firstHandle)
  {}

  mutable std::mutex mMutex;
  MonitoringHandle mNextHandle;
  std::optional<Duration> mModifyRevised;
  std::optional<StatusCode> mModifyThrow;
  std::optional<StatusCode> mDeleteThrow;
  std::vector<MonitoringHandle> mReleased;
};

/// Records what is logged: level, message and the structured fields' values rendered as text.
class CapturedLog final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string message;
    std::vector<std::string> fieldValues;
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::visit(
        [&copy](const auto& value)
        {
          std::ostringstream rendered;
          rendered << value;
          copy.fieldValues.push_back(rendered.str());
        },
        field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  std::vector<Entry> entries() const
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// The MonitoringRoute fixture: the MonitoringRelease fixture's helpers over two namespaces that override
/// only the batched monitoring members, registered as namespaces 2 (@ref mRouteA) and 3 (@ref mRouteB), and
/// one that overrides only the older members, registered as namespace 4 (@ref mOlder), each with Variables
/// i=1..3. Shared by monitoring_route_tests.cpp and sampled_caller_tests.cpp.
class MonitoringRoute : public MonitoringRelease
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mRouteA = BatchedMonitoringNamespace::create("urn:test:monitoring-route:a", mExecutor, 100);
    mRouteB = BatchedMonitoringNamespace::create("urn:test:monitoring-route:b", mExecutor, 300);
    mOlder = OlderMonitoringNamespace::create("urn:test:monitoring-route:older", mExecutor, 500);
    const std::vector<std::pair<std::shared_ptr<ua::Namespace>, uint16_t>> namespaces{
      {mRouteA, uint16_t{2}}, {mRouteB, uint16_t{3}}, {mOlder, uint16_t{4}}};
    for (const auto& [ns, expected] : namespaces)
    {
      auto index = mAddressSpace->try_add_namespace_sync(ns);
      ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
      ASSERT_EQ(index.value(), expected) << "the test names its namespaces by index";
    }
    for (uint32_t i = 1; i <= 3; ++i)
    {
      create_variable(NodeId{2, i});
      create_variable(NodeId{3, i});
      create_variable(NodeId{4, i});
    }
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    mCapabilities.minSupportedSampleRate = 0;
  }

  void TearDown() override
  {
    // Today's subscription reaches the in-memory namespace's own older members, which register real
    // sampling; stopping it lets the pool drain.
    for (const auto& ns : {std::static_pointer_cast<default_ns::Namespace>(mRouteA),
           std::static_pointer_cast<default_ns::Namespace>(mRouteB),
           std::static_pointer_cast<default_ns::Namespace>(mOlder)})
    {
      if (ns)
      {
        ns->shutdown_async([](VoidResult) {});
      }
    }
    MonitoringRelease::TearDown();
  }

  /// Creates @p items as CreateMonitoredItems does, with @p context as the Session's security context;
  /// counts the answers in @p answers.
  std::vector<MonitoredItemCreateResult> create_counted(Subscription& subscription,
    std::vector<MonitoredItemCreateRequest> items, std::shared_ptr<SessionSecurityContext> context,
    std::shared_ptr<std::atomic<int>> answers)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    for (auto& item : items)
    {
      request.items_to_create().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    subscription.create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      std::move(context),
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise, answers](std::vector<MonitoredItemCreateResult> results)
      {
        if (answers->fetch_add(1) == 0)
        {
          promise->set_value(std::move(results));
        }
      });
    return finish(future);
  }

  /// Modifies the items @p ids of @p subscription to @p samplingInterval in one request, as
  /// ModifyMonitoredItems does; counts the answers in @p answers.
  std::vector<MonitoredItemModifyResult> modify_counted(Subscription& subscription,
    const std::vector<IntegerId>& ids, Duration samplingInterval, std::shared_ptr<std::atomic<int>> answers)
  {
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    uint32_t clientHandle = 1;
    for (const auto id : ids)
    {
      MonitoredItemModifyRequest item;
      item.monitored_item_id() = id;
      item.requested_parameters().client_handle() = clientHandle++;
      item.requested_parameters().sampling_interval() = samplingInterval;
      item.requested_parameters().queue_size() = 1;
      item.requested_parameters().discard_oldest() = true;
      request.items_to_modify().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemModifyResult>>>();
    auto future = promise->get_future();
    subscription.modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [promise, answers](std::vector<MonitoredItemModifyResult> results)
      {
        if (answers->fetch_add(1) == 0)
        {
          promise->set_value(std::move(results));
        }
      });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the modify did not answer";
      return {};
    }
    return future.get();
  }

  /// The sampling interval of the item @p id of @p subscription; -1 when there is no such item.
  static Duration sampling_interval(Subscription& subscription, IntegerId id)
  {
    return STA::on_strand(subscription,
      [id](auto& guard)
      {
        const auto& items = guard.monitored_items();
        const auto found = items.find(id);
        return found == items.end() ? Duration{-1} : found->second->samplingInterval;
      });
  }

  /// The ErrorDetail code @p status carries, or "absent".
  static std::string detail_code(const StatusCode& status)
  {
    const auto& detail = status.shared_detail();
    return detail ? detail->code : std::string{"absent"};
  }

  /// A logger at Trace level that records into @ref mLog.
  Logger captured_logger() const
  {
    return Logger{mLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
  }

  std::shared_ptr<BatchedMonitoringNamespace> mRouteA;
  std::shared_ptr<BatchedMonitoringNamespace> mRouteB;
  std::shared_ptr<OlderMonitoringNamespace> mOlder;
  std::shared_ptr<CapturedLog> mLog = std::make_shared<CapturedLog>();
};

}  // namespace ua::test::monitoring_release

#endif  // UA_TEST_MONITORING_RELEASE_FIXTURE_H
