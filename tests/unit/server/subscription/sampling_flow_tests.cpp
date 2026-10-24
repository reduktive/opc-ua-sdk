// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How a namespace's monitoring helper reads its Sampled registrations at a tick
// (COMP-SVR-NAMESPACE-CALLS-14): the Values of Variables with one `read_values_async` to the registered
// namespace per distinct caller of their sinks, with the server's own RequestInfo and each item carrying the
// registration's Node, split by the address space's MaxNodesPerRead, giving up the thread between the calls;
// any other attribute from the Node's description.
//
// The registrations are made through the namespace's own helper (`context().monitoring()`) by a recording
// in-memory namespace that marks every item Sampled, so that the calls each tick makes into it are counted.

#include <gtest/gtest.h>

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_default_variable_node.h"
#include "ua_localized_text.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_service_operation_limits.h"
#include "ua_sinks.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "access_control_test_support.h"
#include "batch_recording_namespace.h"
#include "test_utilities.h"

using namespace ua;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Call = BatchRecordingNamespace::Call;
using Member = BatchRecordingNamespace::Member;
using CreateResults = std::vector<default_ns::NamespaceMonitoringSupport::CreateResult>;

namespace
{

/// The `read_values_async` calls the namespace had received when a sink was first pushed a sample. A tick
/// pushes only once its reads have answered, and the bucket's next tick starts only after that push, so these
/// are the calls of the first tick that delivered anything.
class FirstTickReads
{
public:
  explicit FirstTickReads(std::weak_ptr<BatchRecordingNamespace> nameSpace) : mNamespace{std::move(nameSpace)}
  {}

  /// Called by a sink as it is pushed; takes the record at the first call only.
  void on_push()
  {
    std::unique_lock lock{mMutex};
    if (mCalls)
    {
      return;
    }
    lock.unlock();
    std::vector<Call> calls;
    if (const auto nameSpace = mNamespace.lock())
    {
      calls = nameSpace->calls(Member::ReadValues);
    }
    lock.lock();
    if (!mCalls)
    {
      mCalls = std::move(calls);
    }
    lock.unlock();
    mTaken.notify_all();
  }

  /// Waits until a sink was pushed, or @p limit passes.
  /// @return Whether a sink was pushed.
  bool wait(std::chrono::milliseconds limit) const
  {
    std::unique_lock lock{mMutex};
    return mTaken.wait_for(lock, limit, [this] { return mCalls.has_value(); });
  }

  std::vector<Call> calls() const
  {
    const std::lock_guard lock{mMutex};
    return mCalls.value_or(std::vector<Call>{});
  }

private:
  std::weak_ptr<BatchRecordingNamespace> mNamespace;
  mutable std::mutex mMutex;
  mutable std::condition_variable mTaken;
  std::optional<std::vector<Call>> mCalls;
};

/// A sink whose `caller()` answers the CallerInfo it was given, and that records each sample and notice it is
/// given, in order.
class RecordingSink final : public SampleSink
{
public:
  struct Event
  {
    bool notice{false};
    IntegerId monitoredItemId{0};
    DataValue value;
    StatusCode status;
  };

  RecordingSink(std::shared_ptr<const CallerInfo> caller, std::shared_ptr<FirstTickReads> firstTick)
    : mCaller{std::move(caller)}, mFirstTick{std::move(firstTick)}
  {}

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    if (mFirstTick)
    {
      mFirstTick->on_push();
    }
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
      {
        const StatusCode status = sample.second.status().value_or(StatusCode{Status::Good});
        mEvents.push_back({false, sample.first, std::move(sample.second), status});
      }
    }
    mArrived.notify_all();
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    {
      const std::lock_guard lock{mMutex};
      mEvents.push_back({true, monitoredItemId, DataValue{}, reason});
    }
    mArrived.notify_all();
  }

  void detach() override
  {}

  std::shared_ptr<const CallerInfo> caller() const override
  {
    return mCaller;
  }

  bool wait_for_samples(std::size_t count, std::chrono::milliseconds limit) const
  {
    std::unique_lock lock{mMutex};
    return mArrived.wait_for(lock, limit, [&] { return samples_locked().size() >= count; });
  }

  std::vector<Event> samples() const
  {
    const std::lock_guard lock{mMutex};
    return samples_locked();
  }

  std::size_t notices() const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(
      std::count_if(mEvents.begin(), mEvents.end(), [](const Event& event) { return event.notice; }));
  }

  std::string text() const
  {
    const std::lock_guard lock{mMutex};
    std::string text = "the sink received:";
    for (const auto& event : mEvents)
    {
      if (event.notice)
      {
        text += " notice " + to_string(event.status) + ";";
      }
      else
      {
        text += " sample " + to_string(event.value.value()) + " [" + to_string(event.status) + "];";
      }
    }
    return text;
  }

private:
  std::vector<Event> samples_locked() const
  {
    std::vector<Event> samples;
    std::copy_if(mEvents.begin(),
      mEvents.end(),
      std::back_inserter(samples),
      [](const Event& event) { return !event.notice; });
    return samples;
  }

  std::shared_ptr<const CallerInfo> mCaller;
  std::shared_ptr<FirstTickReads> mFirstTick;
  mutable std::mutex mMutex;
  mutable std::condition_variable mArrived;
  std::vector<Event> mEvents;
};

/// The caller of the Session @p session.
std::shared_ptr<const CallerInfo> caller_of_session(uint32_t session)
{
  auto caller = std::make_shared<CallerInfo>();
  caller->sessionId = NodeId{1, session};
  return caller;
}

/// The size of each call, in order.
std::vector<std::size_t> sizes_of(const std::vector<Call>& calls)
{
  std::vector<std::size_t> sizes;
  sizes.reserve(calls.size());
  for (const auto& call : calls)
  {
    sizes.push_back(call.nodeIds.size());
  }
  return sizes;
}

std::string describe(const std::vector<Call>& calls)
{
  std::string text = std::to_string(calls.size()) + " read_values_async call(s):";
  for (const auto& call : calls)
  {
    text += " [" + std::to_string(call.nodeIds.size()) + " item(s), caller " +
            (call.caller != nullptr ? to_string(call.callerSessionId) : std::string{"none"}) + "]";
  }
  return text;
}

/// Whether @p results are @p count Good results.
::testing::AssertionResult all_created(const CreateResults& results, std::size_t count)
{
  if (results.size() != count)
  {
    return ::testing::AssertionFailure() << results.size() << " results for " << count << " items";
  }
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    if (!results[i].result.is_good())
    {
      return ::testing::AssertionFailure()
             << "item " << i << " was refused " << to_string(results[i].result.status_code());
    }
  }
  return ::testing::AssertionSuccess();
}

class SamplingFlow : public ::testing::Test
{
protected:
  void TearDown() override
  {
    mSubscription.reset();
    mSecurity.reset();
    if (mNamespace)
    {
      mNamespace->on_value_read({});
      mNamespace->release_held_value_reads();
    }
    mAddressSpace.reset();
    mNamespace.reset();
    if (mPool)
    {
      ::ua::test_utils::drain_with_timeout(*mPool);
    }
  }

  /// An address space whose executor has @p threads threads with the recording namespace registered, and then
  /// its MaxNodesPerRead set to @p maxNodesPerRead when one is given (never set otherwise). The limit is set
  /// after the registration, as a server sets its limits after namespaces 0 and 1 are registered, so a helper
  /// that took the limit when its namespace was registered reads with no limit.
  void start(std::size_t threads, std::optional<uint32_t> maxNodesPerRead)
  {
    mPool.emplace(threads);
    mAddressSpace.emplace(AddressSpace::create("urn:test:sampling-flow", mPool->get_executor()));
    mNamespace = std::make_shared<BatchRecordingNamespace>("urn:test:sampling-flow:n", mPool->get_executor());
    const auto added = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
    mIndex = added.value();
    if (maxNodesPerRead)
    {
      ServiceOperationLimits limits;
      limits.maxNodesPerRead = maxNodesPerRead;
      mAddressSpace->set_operation_limits(limits);
    }
    mNamespace->reset();
  }

  std::shared_ptr<FirstTickReads> first_tick() const
  {
    return std::make_shared<FirstTickReads>(mNamespace);
  }

  /// A Variable of the namespace holding @p value.
  std::shared_ptr<default_ns::VariableNode> variable(uint32_t identifier, Variant value)
  {
    const NodeId nodeId{mIndex, identifier};
    auto node = mNamespace->create_node<default_ns::VariableNode>(nodeId);
    EXPECT_NE(node, nullptr) << "creating " << to_string(nodeId);
    if (node == nullptr)
    {
      return nullptr;
    }
    WriteValue write;
    write.node_id() = nodeId;
    write.attribute_id() = utils::to_underlying(AttributeId::Value);
    write.value() = DataValue{std::move(value)};
    std::optional<VoidResult> written;
    node->write_value_async(write, nullptr, [&written](VoidResult result) { written = std::move(result); });
    EXPECT_TRUE(written.has_value() && written->is_good()) << "the Value of " << to_string(nodeId);
    return node;
  }

  /// Writes @p text to @p node's DisplayName.
  static void set_display_name(const std::shared_ptr<default_ns::VariableNode>& node, const std::string& text)
  {
    std::optional<VoidResult> written;
    node->write_attribute_async(AttributeId::DisplayName,
      Variant{LocalizedText{LocaleId{"en"}, String{text}}},
      [&written](VoidResult result) { written = std::move(result); });
    ASSERT_TRUE(written.has_value() && written->is_good()) << "the DisplayName could not be set";
  }

  /// An item on @p attribute of @p node at 100 ms, delivered to @p sink.
  static MonitoringCreateItem item(const std::shared_ptr<default_ns::VariableNode>& node,
    AttributeId attribute, IntegerId monitoredItemId, std::shared_ptr<SampleSink> sink)
  {
    return MonitoringCreateItem{.nodeId = node->node_id(),
      .node = node,
      .attributeId = attribute,
      .monitoredItemId = monitoredItemId,
      .samplingInterval = 100,
      .queueSize = 1,
      .sink = std::move(sink)};
  }

  /// A readable Variable of the namespace of @p dataType with ValueRank 1 holding @p value, made through the
  /// address space.
  NodeId array_variable(uint32_t identifier, const NodeId& dataType, Variant value)
  {
    const NodeId nodeId{mIndex, identifier};
    auto created = mAddressSpace->try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << to_string(nodeId) << ": "
                                   << to_string(created.status_code());
    if (created.is_bad())
    {
      return nodeId;
    }
    auto accessor = created.value();
    accessor.set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    accessor.set_data_type(dataType);
    accessor.set_value_rank(ValueRank{1});
    write_array(nodeId, std::move(value));
    return nodeId;
  }

  /// Writes @p value to the Value of the Variable @p nodeId through the address space.
  void write_array(const NodeId& nodeId, Variant value)
  {
    auto accessor = mAddressSpace->find_node_sync(nodeId).as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value()) << to_string(nodeId) << " is not a Variable";
    const auto written = accessor->try_write_value_sync(DataValue{std::move(value)});
    ASSERT_TRUE(written.is_good()) << "writing " << to_string(nodeId) << ": "
                                   << to_string(written.status_code());
  }

  /// A VariableType of the namespace of Int32 with ValueRank 1 holding @p value.
  NodeId array_variable_type(uint32_t identifier, Variant value)
  {
    const NodeId typeId{mIndex, identifier};
    auto created = mAddressSpace->try_create_node_sync(typeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << "the VariableType could not be created";
    if (created.is_bad())
    {
      return typeId;
    }
    auto type = created.value().as<VariableTypeAccessor>();
    EXPECT_TRUE(type.has_value());
    if (!type.has_value())
    {
      return typeId;
    }
    type->set_data_type(NodeId{DataTypeId::Int32});
    type->set_value_rank(ValueRank{1});
    type->set_value(DataValue{std::move(value)});
    return typeId;
  }

  /// Changes the VariableType @p typeId's Value through VariableTypeAccessor::set_value.
  void set_type_value(const NodeId& typeId, Variant value)
  {
    auto type = mAddressSpace->find_node_sync(typeId).as<VariableTypeAccessor>();
    ASSERT_TRUE(type.has_value());
    type->set_value(DataValue{std::move(value)});
  }

  /// A Value item on @p nodeId with @p indexRange, Reporting at @p samplingInterval, discarding the oldest.
  static MonitoredItemCreateRequest ranged_value_item(const NodeId& nodeId, const char* indexRange,
    uint32_t clientHandle, Duration samplingInterval, uint32_t queueSize)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = nodeId;
    item.item_to_monitor().attribute_id() = utils::to_underlying(AttributeId::Value);
    item.item_to_monitor().index_range() = indexRange;
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = samplingInterval;
    item.requested_parameters().queue_size() = queueSize;
    item.requested_parameters().discard_oldest() = true;
    return item;
  }

  /// Creates @p item on a Subscription of a Session allowed to read the namespace's Nodes, made at the first
  /// call; returns the item's result.
  MonitoredItemCreateResult subscribe(MonitoredItemCreateRequest item)
  {
    if (!mSubscription)
    {
      mSecurity = std::make_shared<ua::test_helpers::TestSessionSecurityContext>(*mAddressSpace);
      mSubscription = server::Subscription::create(
        1, 1'000'000.0, 100, 3, 0, true, 0, mPool->get_executor(), [](IntegerId) {}, [](IntegerId) {});
    }
    server::ServerConfig::ServerCapabilities capabilities;
    capabilities.minSupportedSampleRate = 0;
    capabilities.maxMonitoredItemsQueueSize = 1000u;
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));
    auto answered = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto results = answered->get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      capabilities,
      server::ServerConfig::SubscriptionLimits{},
      mSecurity,
      std::weak_ptr<server::EventBus>{},
      nullptr,
      [answered](std::vector<MonitoredItemCreateResult> created)
      { answered->set_value(std::move(created)); });
    if (results.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return MonitoredItemCreateResult{};
    }
    auto created = results.get();
    EXPECT_EQ(created.size(), 1u);
    return created.empty() ? MonitoredItemCreateResult{} : std::move(created.front());
  }

  /// Takes one Publish from the Subscription and records the notifications of every item.
  void publish_once()
  {
    const auto published = server::SubscriptionTestAccess::on_strand(*mSubscription,
      [](auto& guard)
      {
        guard.set_publish_req_queued(true);
        return guard.fulfill_publish(1);
      });
    for (const auto& result : published)
    {
      for (const auto& data : result.message.notification_data())
      {
        const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
        if (change == nullptr)
        {
          continue;
        }
        for (const auto& notification : change->monitored_items())
        {
          mReported.emplace_back(notification.client_handle(), notification.value());
        }
      }
    }
  }

  /// Publishes, recording every notification, until @p done holds or @p limit passes.
  bool publish_until(const std::function<bool()>& done, std::chrono::milliseconds limit = 3s)
  {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    for (;;)
    {
      publish_once();
      if (done())
      {
        return true;
      }
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(5ms);
    }
  }

  /// Publishes, recording every notification, for @p duration.
  void publish_for(std::chrono::milliseconds duration)
  {
    publish_until([] { return false; }, duration);
  }

  /// The notifications recorded for @p clientHandle, in order.
  std::vector<DataValue> reports_of(uint32_t clientHandle) const
  {
    std::vector<DataValue> found;
    for (const auto& [handle, value] : mReported)
    {
      if (handle == clientHandle)
      {
        found.push_back(value);
      }
    }
    return found;
  }

  std::string reports_text(uint32_t clientHandle) const
  {
    std::string text = "the item reported:";
    for (const auto& value : reports_of(clientHandle))
    {
      text += " " + to_string(value.value()) + " [" + to_string(value.status().value_or(StatusCode{})) + "];";
    }
    return text;
  }

  /// How many samples the namespace's observed sinks passed on for the item it was given as @p
  /// monitoredItemId.
  std::size_t samples_delivered(IntegerId monitoredItemId) const
  {
    const auto deliveries = mNamespace->deliveries();
    return static_cast<std::size_t>(std::count_if(deliveries.begin(),
      deliveries.end(),
      [monitoredItemId](const BatchRecordingNamespace::Delivery& delivery)
      { return delivery.monitoredItemId == monitoredItemId && delivery.sample.has_value(); }));
  }

  /// Waits until the namespace's observed sinks have passed on @p count samples for @p monitoredItemId, or 3
  /// s pass, then lets the Subscription's strand take what was passed on.
  bool wait_for_samples_delivered(IntegerId monitoredItemId, std::size_t count)
  {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (samples_delivered(monitoredItemId) < count)
    {
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(2ms);
    }
    server::SubscriptionTestAccess::on_strand(*mSubscription, [](auto&) {});
    return true;
  }

  /// The monitoredItemId the namespace was given for an item on @p nodeId, or 0.
  IntegerId registered_id(const NodeId& nodeId) const
  {
    for (const auto& call : mNamespace->calls(Member::CreateMonitoring))
    {
      for (std::size_t k = 0; k < call.nodeIds.size() && k < call.monitoredItemIds.size(); ++k)
      {
        if (call.nodeIds[k] == nodeId)
        {
          return call.monitoredItemIds[k];
        }
      }
    }
    return 0;
  }

  std::optional<boost::asio::thread_pool> mPool;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<BatchRecordingNamespace> mNamespace;
  uint16_t mIndex{0};
  std::shared_ptr<ua::test_helpers::TestSessionSecurityContext> mSecurity;
  std::shared_ptr<server::Subscription> mSubscription;
  std::vector<std::pair<uint32_t, DataValue>> mReported;
};

/// Whether @p value is Good and holds the Int32 array @p expected.
bool is_good_slice(const DataValue& value, const Array<int32_t>& expected)
{
  return value.status().value_or(StatusCode{}).is_good() && value.value() == Variant{expected};
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-ONE-VALUE-READ-PER-SESSION-PER-TICK, scope=function)
TEST_F(SamplingFlow, OneValueReadPerSessionPerTick)
{
  start(4, std::nullopt);
  const auto callerA = caller_of_session(101);
  const auto callerB = caller_of_session(102);
  const auto firstTick = first_tick();
  const auto sinkA1 = std::make_shared<RecordingSink>(callerA, firstTick);
  const auto sinkA2 = std::make_shared<RecordingSink>(callerA, firstTick);
  const auto sinkB = std::make_shared<RecordingSink>(callerB, firstTick);
  const auto first = variable(1, Variant{int32_t{1}});
  const auto second = variable(2, Variant{int32_t{2}});
  const auto third = variable(3, Variant{int32_t{3}});
  ASSERT_TRUE(first && second && third);

  const std::vector<MonitoringCreateItem> items{item(first, AttributeId::Value, 1, sinkA1),
    item(second, AttributeId::Value, 2, sinkA2),
    item(third, AttributeId::Value, 3, sinkB)};
  ASSERT_TRUE(all_created(mNamespace->create_sampled(items), 3));

  ASSERT_TRUE(firstTick->wait(3s)) << "no tick pushed a sample";
  const auto calls = firstTick->calls();
  ASSERT_EQ(calls.size(), 2u) << describe(calls);

  const auto callOf = [&calls](const std::shared_ptr<const CallerInfo>& caller) -> const Call*
  {
    const auto found = std::find_if(
      calls.begin(), calls.end(), [&caller](const Call& call) { return call.caller == caller.get(); });
    return found == calls.end() ? nullptr : &*found;
  };
  const Call* readForA = callOf(callerA);
  const Call* readForB = callOf(callerB);
  ASSERT_NE(readForA, nullptr) << "no call was made for caller A; " << describe(calls);
  ASSERT_NE(readForB, nullptr) << "no call was made for caller B; " << describe(calls);

  auto nodesOfA = readForA->itemNodes;
  std::sort(nodesOfA.begin(), nodesOfA.end());
  std::vector<const Node*> expectedOfA{first.get(), second.get()};
  std::sort(expectedOfA.begin(), expectedOfA.end());
  EXPECT_EQ(nodesOfA, expectedOfA) << "the items of caller A's call do not carry their registrations' Nodes";
  EXPECT_EQ(readForB->itemNodes, (std::vector<const Node*>{third.get()}))
    << "the item of caller B's call does not carry its registration's Node";
  for (const Call* call : {readForA, readForB})
  {
    EXPECT_TRUE(call->hasRequest);
    EXPECT_EQ(call->deadline, std::chrono::steady_clock::time_point::max())
      << "the call for " << to_string(call->callerSessionId)
      << " does not carry the server's own RequestInfo";
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-A-TICKS-READS-ARE-SPLIT-BY-MAX-NODES-PER-READ, scope=function)
TEST_F(SamplingFlow, ATicksReadsAreSplitByMaxNodesPerRead)
{
  start(4, 100u);
  const auto firstTick = first_tick();
  const auto onlySink = std::make_shared<RecordingSink>(caller_of_session(101), firstTick);
  std::vector<MonitoringCreateItem> items;
  std::vector<NodeId> registered;
  for (uint32_t i = 0; i < 250; ++i)
  {
    const auto node = variable(1000 + i, Variant{static_cast<int32_t>(i)});
    ASSERT_NE(node, nullptr);
    items.push_back(item(node, AttributeId::Value, i + 1, onlySink));
    registered.push_back(node->node_id());
  }
  ASSERT_TRUE(all_created(mNamespace->create_sampled(items), 250));

  ASSERT_TRUE(firstTick->wait(5s)) << "no tick pushed a sample";
  const auto calls = firstTick->calls();
  auto sizes = sizes_of(calls);
  std::sort(sizes.rbegin(), sizes.rend());
  EXPECT_EQ(sizes, (std::vector<std::size_t>{100, 100, 50})) << describe(calls);

  std::vector<NodeId> named;
  for (const auto& call : calls)
  {
    named.insert(named.end(), call.nodeIds.begin(), call.nodeIds.end());
  }
  std::sort(named.begin(), named.end());
  std::sort(registered.begin(), registered.end());
  EXPECT_TRUE(named == registered) << "the tick's calls name " << named.size()
                                   << " NodeIds, not each of the 250 registrations once";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-A-TICK-GIVES-UP-ITS-THREAD-BETWEEN-READS, scope=function)
TEST_F(SamplingFlow, ATickGivesUpItsThreadBetweenReads)
{
  start(1, 100u);

  // On the first call, a probe is posted to the address space's executor; it notes how many calls N had
  // received when it ran.
  struct Probe
  {
    std::atomic<bool> posted{false};
    std::promise<std::size_t> ran;
  };

  const auto probe = std::make_shared<Probe>();
  auto ranAt = probe->ran.get_future();
  const std::weak_ptr<BatchRecordingNamespace> weakNamespace = mNamespace;
  mNamespace->on_value_read(
    [probe, weakNamespace, executor = mAddressSpace->executor()](const Call&)
    {
      if (probe->posted.exchange(true))
      {
        return;
      }
      boost::asio::post(executor,
        [probe, weakNamespace]
        {
          const auto nameSpace = weakNamespace.lock();
          probe->ran.set_value(nameSpace ? nameSpace->count(Member::ReadValues) : 0);
        });
    });

  const auto onlySink = std::make_shared<RecordingSink>(caller_of_session(101), nullptr);
  std::vector<MonitoringCreateItem> items;
  for (uint32_t i = 0; i < 250; ++i)
  {
    const auto node = variable(1000 + i, Variant{static_cast<int32_t>(i)});
    ASSERT_NE(node, nullptr);
    items.push_back(item(node, AttributeId::Value, i + 1, onlySink));
  }
  ASSERT_TRUE(all_created(mNamespace->create_sampled(items), 250));

  ASSERT_TRUE(mNamespace->wait_for_calls(Member::ReadValues, 3, 5s))
    << "N received " << mNamespace->count(Member::ReadValues) << " read_values_async calls";
  ASSERT_EQ(ranAt.wait_for(5s), std::future_status::ready) << "the probe never ran";
  // A call's answeredInline is noted when the call returns. The first tick's third call has returned once the
  // bucket's next tick has entered its first: both run on the executor's one thread, and a bucket's ticks do
  // not overlap.
  ASSERT_TRUE(mNamespace->wait_for_calls(Member::ReadValues, 4, 5s)) << "the bucket's next tick did not read";

  // The stimulus held: the first tick's reads were the three parts of its split, each answered inline.
  auto calls = mNamespace->calls(Member::ReadValues);
  calls.resize(3);
  auto sizes = sizes_of(calls);
  std::sort(sizes.rbegin(), sizes.rend());
  ASSERT_EQ(sizes, (std::vector<std::size_t>{100, 100, 50})) << describe(calls);
  for (const auto& call : calls)
  {
    ASSERT_TRUE(call.answeredInline) << "call " << call.sequence << " was not answered inline";
  }

  EXPECT_LT(ranAt.get(), 3u)
    << "the probe ran only once the tick's third read_values_async call had been entered";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-A-SAMPLED-NON-VALUE-ATTRIBUTE-IS-READ-FROM-THE-DESCRIPTION, scope=function)
TEST_F(SamplingFlow, ASampledNonValueAttributeIsReadFromTheDescription)
{
  start(4, std::nullopt);
  const auto onlySink = std::make_shared<RecordingSink>(nullptr, nullptr);
  const auto node = variable(1, Variant{int32_t{1}});
  ASSERT_NE(node, nullptr);
  set_display_name(node, "First");
  const Variant firstName{LocalizedText{LocaleId{"en"}, String{"First"}}};
  const Variant secondName{LocalizedText{LocaleId{"en"}, String{"Second"}}};

  ASSERT_TRUE(all_created(mNamespace->create_sampled(std::vector<MonitoringCreateItem>{
                            item(node, AttributeId::DisplayName, 1, onlySink)}),
    1));
  ASSERT_TRUE(onlySink->wait_for_samples(1, 2s)) << onlySink->text();
  const auto firstSample = onlySink->samples().front();
  EXPECT_TRUE(firstSample.status == StatusCode{Status::Good}) << onlySink->text();
  EXPECT_TRUE(firstSample.value.value() == firstName) << onlySink->text();

  set_display_name(node, "Second");
  onlySink->wait_for_samples(2, 500ms);
  const auto samples = onlySink->samples();
  ASSERT_EQ(samples.size(), 2u) << onlySink->text();
  EXPECT_TRUE(samples[1].status == StatusCode{Status::Good}) << onlySink->text();
  EXPECT_TRUE(samples[1].value.value() == secondName) << onlySink->text();
  EXPECT_EQ(onlySink->notices(), 0u) << onlySink->text();
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-THE-READS-OF-ONE-TICK-ARE-STARTED-TOGETHER, scope=function)
TEST_F(SamplingFlow, TheReadsOfOneTickAreStartedTogether)
{
  start(4, std::nullopt);
  const auto callerA = caller_of_session(101);
  const auto callerB = caller_of_session(102);
  const auto sinkA = std::make_shared<RecordingSink>(callerA, nullptr);
  const auto sinkB = std::make_shared<RecordingSink>(callerB, nullptr);
  const auto variableOfA = variable(1, Variant{int32_t{1}});
  const auto variableOfB = variable(2, Variant{int32_t{2}});
  ASSERT_TRUE(variableOfA && variableOfB);

  // Every call names one of the two Variables, so N holds every call until released.
  mNamespace->hold_value_reads_of({variableOfA->node_id(), variableOfB->node_id()});
  const std::vector<MonitoringCreateItem> items{
    item(variableOfA, AttributeId::Value, 1, sinkA), item(variableOfB, AttributeId::Value, 2, sinkB)};
  ASSERT_TRUE(all_created(mNamespace->create_sampled(items), 2));

  ASSERT_TRUE(mNamespace->wait_for_held_value_reads(1, 3s))
    << "N holds no call; " << describe(mNamespace->calls(Member::ReadValues));
  const bool twoHeld = mNamespace->wait_for_held_value_reads(2, 2s);
  const auto calls = mNamespace->calls(Member::ReadValues);
  const auto heldFor = [&calls](const std::shared_ptr<const CallerInfo>& caller)
  {
    return std::count_if(
      calls.begin(), calls.end(), [&caller](const Call& call) { return call.caller == caller.get(); });
  };
  EXPECT_TRUE(twoHeld && calls.size() == 2 && heldFor(callerA) == 1 && heldFor(callerB) == 1)
    << "N did not hold one call for caller A and one for caller B at once; " << describe(calls);

  mNamespace->release_held_value_reads();
  ASSERT_TRUE(sinkA->wait_for_samples(1, 3s)) << "caller A's sink: " << sinkA->text();
  ASSERT_TRUE(sinkB->wait_for_samples(1, 3s)) << "caller B's sink: " << sinkB->text();
  EXPECT_TRUE(sinkA->samples().front().value.value() == Variant{int32_t{1}}) << sinkA->text();
  EXPECT_TRUE(sinkB->samples().front().value.value() == Variant{int32_t{2}}) << sinkB->text();
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2 (NR-14 rule 1): whoever produces a value narrows it, so a tick's read of
// a ranged Value item the namespace samples carries the item's IndexRange, and the item reports the slice the
// namespace answered without narrowing it again. The in-memory namespace samples a Value item at 100 ms and
// answers a ranged read with the slice.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SAMPLED-READ-CARRIES-THE-ITEMS-INDEXRANGE, scope=function)
TEST_F(SamplingFlow, ASampledReadCarriesTheItemsIndexRange)
{
  constexpr uint32_t clientHandle = 7;
  start(4, std::nullopt);
  const NodeId variableId =
    array_variable(1, NodeId{DataTypeId::Int32}, Variant{Array<int32_t>{1, 2, 3, 4, 5}});

  const auto created = subscribe(ranged_value_item(variableId, "2:3", clientHandle, 100.0, 5));
  ASSERT_TRUE(created.status_code().is_good()) << to_string(created.status_code());

  // The create's own read of the initial Value has been answered; what N records from here are the ticks'. A
  // bucket's next tick starts only after the last one pushed, so once two are recorded the first one's sample
  // has reached the Subscription.
  mNamespace->reset();
  ASSERT_TRUE(mNamespace->wait_for_calls(Member::ReadValues, 2, 3s))
    << describe(mNamespace->calls(Member::ReadValues));
  const auto tickRead = mNamespace->calls(Member::ReadValues).front();
  ASSERT_EQ(tickRead.nodeIds, (std::vector<NodeId>{variableId})) << describe({tickRead});
  ASSERT_EQ(tickRead.itemRanges.size(), 1u);
  EXPECT_EQ(std::string{std::string_view{tickRead.itemRanges[0]}}, "2:3")
    << "the tick's read did not carry the item's IndexRange";

  publish_for(500ms);
  const auto reported = reports_of(clientHandle);
  ASSERT_FALSE(reported.empty()) << reports_text(clientHandle);
  for (const auto& value : reported)
  {
    EXPECT_TRUE(is_good_slice(value, Array<int32_t>{3, 4})) << reports_text(clientHandle);
  }
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2, a guard: a Sampled item on a VariableType's Value is read from the
// Node's description at each tick, and what it reports is narrowed to its IndexRange at every sample, never a
// value larger than the range.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SAMPLED-VALUE-FROM-THE-DESCRIPTION-IS-NARROWED, scope=function)
TEST_F(SamplingFlow, ASampledValueFromTheDescriptionIsNarrowed)
{
  constexpr uint32_t clientHandle = 8;
  start(4, std::nullopt);
  const NodeId typeId = array_variable_type(2, Variant{Array<int32_t>{1, 2, 3, 4}});

  const auto created = subscribe(ranged_value_item(typeId, "1:2", clientHandle, 100.0, 10));
  ASSERT_TRUE(created.status_code().is_good()) << to_string(created.status_code());

  ASSERT_TRUE(publish_until([&] { return !reports_of(clientHandle).empty(); }))
    << "the item reported nothing";
  publish_for(300ms);
  const auto beforeWrite = reports_of(clientHandle).size();
  set_type_value(typeId, Variant{Array<int32_t>{5, 6, 7, 8}});
  publish_until(
    [&]
    {
      const auto reported = reports_of(clientHandle);
      return std::any_of(reported.begin() + static_cast<std::ptrdiff_t>(beforeWrite),
        reported.end(),
        [](const DataValue& value) { return is_good_slice(value, Array<int32_t>{6, 7}); });
    });

  const auto reported = reports_of(clientHandle);
  ASSERT_GT(reported.size(), beforeWrite)
    << "nothing was reported after the write; " << reports_text(clientHandle);
  for (std::size_t i = 0; i < reported.size(); ++i)
  {
    const Array<int32_t> expected = i < beforeWrite ? Array<int32_t>{2, 3} : Array<int32_t>{6, 7};
    EXPECT_TRUE(is_good_slice(reported[i], expected))
      << "notification " << i + 1 << "; " << reports_text(clientHandle);
  }
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2, a guard: a Value item at sampling interval 0 is told of each change,
// and reports each one narrowed to its IndexRange.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-REPORTED-ITEM-AT-INTERVAL-ZERO-REPORTS-EACH-CHANGE-NARROWED, scope=function)
TEST_F(SamplingFlow, AReportedItemAtIntervalZeroReportsEachChangeNarrowed)
{
  constexpr uint32_t clientHandle = 9;
  start(4, std::nullopt);
  const NodeId variableId = array_variable(3, NodeId{DataTypeId::Int32}, Variant{Array<int32_t>{10, 20, 30}});

  const auto created = subscribe(ranged_value_item(variableId, "1", clientHandle, 0.0, 5));
  ASSERT_TRUE(created.status_code().is_good()) << to_string(created.status_code());
  write_array(variableId, Variant{Array<int32_t>{10, 21, 30}});
  write_array(variableId, Variant{Array<int32_t>{10, 22, 30}});

  publish_until([&] { return reports_of(clientHandle).size() >= 3; });
  const auto reported = reports_of(clientHandle);
  ASSERT_EQ(reported.size(), 3u) << reports_text(clientHandle);
  EXPECT_TRUE(is_good_slice(reported[0], Array<int32_t>{20})) << reports_text(clientHandle);
  EXPECT_TRUE(is_good_slice(reported[1], Array<int32_t>{21})) << reports_text(clientHandle);
  EXPECT_TRUE(is_good_slice(reported[2], Array<int32_t>{22})) << reports_text(clientHandle);
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 5 (NR-14 rule 5), a guard: the DataChangeFilter compares the narrowed
// values, so a change outside the IndexRange is no change, and a change inside it larger than the deadband is
// reported. OPC 10000-4 7.22.2 is silent on the IndexRange; comparing the ranged value is the SDK's choice.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-DATA-CHANGE-FILTER-SEES-THE-NARROWED-VALUE, scope=function)
TEST_F(SamplingFlow, ADataChangeFilterSeesTheNarrowedValue)
{
  constexpr uint32_t clientHandle = 10;
  start(4, std::nullopt);
  const NodeId variableId =
    array_variable(4, NodeId{DataTypeId::Double}, Variant{Array<double>{10.0, 20.0, 30.0}});
  mNamespace->observe_deliveries();
  auto item = ranged_value_item(variableId, "0", clientHandle, 0.0, 5);
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = 5.0;
  item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);

  const auto created = subscribe(std::move(item));
  ASSERT_TRUE(created.status_code().is_good()) << to_string(created.status_code());
  const IntegerId registered = registered_id(variableId);
  ASSERT_NE(registered, 0u) << "the item was not registered with N";
  ASSERT_TRUE(publish_until([&] { return !reports_of(clientHandle).empty(); }))
    << "the item reported nothing";
  const auto first = reports_of(clientHandle);
  ASSERT_EQ(first.size(), 1u) << reports_text(clientHandle);
  ASSERT_TRUE(first[0].value() == (Variant{Array<double>{10.0}})) << reports_text(clientHandle);

  const auto delivered = samples_delivered(registered);
  write_array(variableId, Variant{Array<double>{10.0, 20.0, 300.0}});
  ASSERT_TRUE(wait_for_samples_delivered(registered, delivered + 1))
    << "the first write did not reach the item";
  publish_once();
  EXPECT_EQ(reports_of(clientHandle).size(), 1u)
    << "a change outside the range was reported; " << reports_text(clientHandle);

  write_array(variableId, Variant{Array<double>{16.0, 20.0, 300.0}});
  ASSERT_TRUE(wait_for_samples_delivered(registered, delivered + 2))
    << "the second write did not reach the item";
  publish_until([&] { return reports_of(clientHandle).size() >= 2; });
  const auto reported = reports_of(clientHandle);
  ASSERT_EQ(reported.size(), 2u) << reports_text(clientHandle);
  EXPECT_TRUE(reported[1].status().value_or(StatusCode{}).is_good() &&
              reported[1].value() == (Variant{Array<double>{16.0}}))
    << reports_text(clientHandle);
}
