// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The monitoring helper fixtures, shared by monitoring_helper_tests.cpp and the arms of NR-70 B4c that name
// MonitoringCreateItem::indexRange (monitoring_helper_range_tests.cpp): GoogleTest requires every test of one
// suite to use one fixture class, so the classes live here rather than in either file's anonymous namespace.

#ifndef UA_TEST_MONITORING_HELPER_FIXTURE_H
#define UA_TEST_MONITORING_HELPER_FIXTURE_H

#include <gtest/gtest.h>

#include "per_item_join.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_default_base_node.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_error_detail.h"
#include "ua_namespace_context.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_sinks.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace ua::test::monitoring_helper
{

using namespace ua;
using namespace std::chrono_literals;
using Helper = default_ns::NamespaceMonitoringSupport;

/// An in-memory namespace that exposes the helper its context answers, and records its `shutdown_async`
/// calls.
class ExposedNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<ExposedNamespace> create(string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<ExposedNamespace>(new ExposedNamespace(uri, std::move(executor)));
  }

  /// The helper `context().monitoring()` answers now.
  Helper& helper() const
  {
    return context().monitoring();
  }

  /// A copy of the context this namespace holds.
  NamespaceContext context_copy() const
  {
    return context();
  }

  /// Runs @p hook on each `shutdown_async` call, before the call is answered.
  void on_shutdown(std::function<void()> hook)
  {
    const std::lock_guard lock{mHookMutex};
    mShutdownHook = std::move(hook);
  }

  int shutdown_calls() const
  {
    return mShutdownCalls.load();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    mShutdownCalls.fetch_add(1);
    std::function<void()> hook;
    {
      const std::lock_guard lock{mHookMutex};
      hook = mShutdownHook;
    }
    if (hook)
      hook();
    default_ns::Namespace::shutdown_async(std::move(callback));
  }

  /// Reads a @ref SwitchableVariable an item carries through its own Value read, as the test scripts it;
  /// every other item through the in-memory member.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;

private:
  ExposedNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  std::atomic<int> mShutdownCalls{0};
  std::mutex mHookMutex;
  std::function<void()> mShutdownHook;
};

/// A Variable whose `deleted()` and Value read the test switches. Its Value read answers at once with the
/// Value it holds, unless reads are held, or the read is the one the test chose to delete the Node and fail.
class SwitchableVariable final : public default_ns::BaseNode
{
public:
  static std::shared_ptr<SwitchableVariable> create(const NodeId& nodeId, Variant value)
  {
    return std::shared_ptr<SwitchableVariable>(new SwitchableVariable(nodeId, std::move(value)));
  }

  NodeClass get_node_class() const override
  {
    return NodeClass::Variable;
  }

  bool deleted() const noexcept override
  {
    return mSwitchedDeleted.load(std::memory_order_acquire);
  }

  void read_value(Duration, bool, const ReadValueId&, const AccessIdentity*,
    ReadValueCompleteCallback callback) const override
  {
    std::unique_lock lock{mMutex};
    ++mReads;
    if (mDeleteOnRead != 0 && mReads == mDeleteOnRead)
    {
      mSwitchedDeleted.store(true, std::memory_order_release);
      lock.unlock();
      mCv.notify_all();
      callback(DataValueResult{StatusCode{Status::BadNodeIdUnknown}});
      return;
    }
    if (mHoldReads)
    {
      mHeld.push_back(std::move(callback));
      lock.unlock();
      mCv.notify_all();
      return;
    }
    DataValue value{mValue};
    lock.unlock();
    mCv.notify_all();
    callback(DataValueResult{std::move(value)});
  }

  /// Answers `deleted()` true from now on.
  void mark_deleted()
  {
    mSwitchedDeleted.store(true, std::memory_order_release);
  }

  /// The @p readNumber-th Value read marks the Node deleted and fails with Bad_NodeIdUnknown.
  void delete_on_read(size_t readNumber)
  {
    const std::lock_guard lock{mMutex};
    mDeleteOnRead = readNumber;
  }

  /// Holds the answers to later Value reads until @ref release_reads.
  void hold_reads()
  {
    const std::lock_guard lock{mMutex};
    mHoldReads = true;
  }

  /// Stops holding and answers every held read with the Value held, on the calling thread.
  void release_reads()
  {
    std::vector<ReadValueCompleteCallback> held;
    DataValue value;
    {
      const std::lock_guard lock{mMutex};
      mHoldReads = false;
      held.swap(mHeld);
      value = DataValue{mValue};
    }
    for (auto& callback : held)
      callback(DataValueResult{value});
  }

  size_t held_reads() const
  {
    const std::lock_guard lock{mMutex};
    return mHeld.size();
  }

  bool is_read_held() const
  {
    return held_reads() > 0;
  }

  /// Waits until @p count Value reads were made, or @p timeout passes.
  bool wait_for_reads(size_t count, std::chrono::milliseconds timeout) const
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mReads >= count; });
  }

  /// Waits until a read is held, or @p timeout passes.
  bool wait_for_held_read(std::chrono::milliseconds timeout) const
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return !mHeld.empty(); });
  }

private:
  SwitchableVariable(const NodeId& nodeId, Variant value)
    : default_ns::BaseNode(nodeId, NodeClass::Variable), mValue(std::move(value))
  {}

  mutable std::mutex mMutex;
  mutable std::condition_variable mCv;
  mutable std::atomic<bool> mSwitchedDeleted{false};
  mutable size_t mReads{0};
  mutable std::vector<ReadValueCompleteCallback> mHeld;
  size_t mDeleteOnRead{0};
  bool mHoldReads{false};
  Variant mValue;
};

inline void ExposedNamespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  auto join = std::make_shared<test::PerItemJoin<DataValueResult>>(items.size(), std::move(complete));
  for (std::size_t index = 0; index < items.size(); ++index)
  {
    const ValueReadItem& item = items[index];
    if (const auto* switchable = dynamic_cast<const SwitchableVariable*>(&item.node))
    {
      switchable->read_value(maxAge,
        setSourceTimestamp,
        item.value,
        nullptr,
        [join, index](DataValueResult read) { join->answer(index, std::move(read)); });
      continue;
    }
    const ValueReadItem one[]{item};
    default_ns::Namespace::read_values_async(request,
      caller,
      one,
      maxAge,
      setSourceTimestamp,
      [join, index](BatchResult<DataValueResult> read)
      { join->answer(index, test::only_item(std::move(read))); });
  }
  join->started();
}

/// A sink that records what reaches it, in order: each pushed sample and each notice. Its `push` can be made
/// to block until released.
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

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    std::unique_lock lock{mMutex};
    for (auto& sample : samples)
      mEvents.push_back({false, sample.first, std::move(sample.second), StatusCode{Status::Good}});
    ++mPushesEntered;
    mCv.notify_all();
    mCv.wait(lock, [&] { return !mBlockPushes; });
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    const std::lock_guard lock{mMutex};
    mEvents.push_back({true, monitoredItemId, DataValue{}, reason});
    mCv.notify_all();
  }

  void detach() override
  {}

  void mark_semantics_changed(IntegerId monitoredItemId) override
  {
    const std::lock_guard lock{mMutex};
    mSemanticsMarks.push_back(monitoredItemId);
    mCv.notify_all();
  }

  /// The items marked with SemanticsChanged, in order.
  std::vector<IntegerId> semantics_marks() const
  {
    const std::lock_guard lock{mMutex};
    return mSemanticsMarks;
  }

  /// Later pushes block until @ref release_pushes.
  void block_pushes()
  {
    const std::lock_guard lock{mMutex};
    mBlockPushes = true;
  }

  void release_pushes()
  {
    {
      const std::lock_guard lock{mMutex};
      mBlockPushes = false;
    }
    mCv.notify_all();
  }

  bool wait_for_push_entered(std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mPushesEntered > 0; });
  }

  bool wait_for_samples(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return count_samples_locked() >= count; });
  }

  bool wait_for_notices(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return count_notices_locked() >= count; });
  }

  std::vector<Event> events() const
  {
    const std::lock_guard lock{mMutex};
    return mEvents;
  }

  size_t samples() const
  {
    const std::lock_guard lock{mMutex};
    return count_samples_locked();
  }

  size_t notices() const
  {
    const std::lock_guard lock{mMutex};
    return count_notices_locked();
  }

  /// How many samples carry the Int32 @p value.
  size_t samples_of(int32_t value) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<size_t>(std::count_if(mEvents.begin(),
      mEvents.end(),
      [&](const Event& event) {
        return !event.notice && event.value.value().is_int32() && event.value.value().as<int32_t>() == value;
      }));
  }

  std::string text() const
  {
    const std::lock_guard lock{mMutex};
    std::string text = "the sink received:";
    for (const auto& event : mEvents)
    {
      if (event.notice)
        text += " notice " + to_string(event.status) + ";";
      else
        text += " sample " + to_string(event.value.value()) + " [" +
                to_string(event.value.status().value_or(StatusCode{Status::Good})) + "];";
    }
    return text;
  }

private:
  size_t count_samples_locked() const
  {
    return static_cast<size_t>(
      std::count_if(mEvents.begin(), mEvents.end(), [](const Event& event) { return !event.notice; }));
  }

  size_t count_notices_locked() const
  {
    return static_cast<size_t>(
      std::count_if(mEvents.begin(), mEvents.end(), [](const Event& event) { return event.notice; }));
  }

  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<Event> mEvents;
  std::vector<IntegerId> mSemanticsMarks;
  size_t mPushesEntered{0};
  bool mBlockPushes{false};
};

/// Whether @p status is Bad_NotSupported with the ErrorDetail NamespaceNotRegistered.
inline ::testing::AssertionResult refused_as_unregistered(const StatusCode& status)
{
  if (status != StatusCode{Status::BadNotSupported})
    return ::testing::AssertionFailure() << "the status is " << to_string(status);
  const auto detail = status.shared_detail();
  if (detail == nullptr)
    return ::testing::AssertionFailure() << "Bad_NotSupported carries no ErrorDetail";
  if (detail->code != "NamespaceNotRegistered")
    return ::testing::AssertionFailure() << "the ErrorDetail's code is " << detail->code;
  return ::testing::AssertionSuccess();
}

/// Writes @p value to an in-memory Variable's Value.
inline void write_value(const std::shared_ptr<default_ns::BaseNode>& node, Variant value)
{
  WriteValue writeValue;
  writeValue.node_id() = node->node_id();
  writeValue.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeValue.value() = DataValue{std::move(value)};
  auto completion = std::make_shared<std::promise<VoidResult>>();
  auto written = completion->get_future();
  node->write_value_async(
    writeValue, nullptr, [completion](VoidResult result) { completion->set_value(result); });
  ASSERT_EQ(written.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(written.get().is_good());
}

inline Helper::ResolvedMonitoringItem resolved(const NodeId& nodeId, AttributeId attributeId,
  IntegerId monitoredItemId, Duration samplingInterval, std::shared_ptr<SampleSink> sink,
  std::shared_ptr<Node> node, Helper::Delivery delivery)
{
  Helper::ResolvedMonitoringItem item;
  item.item = MonitoringCreateItem{.nodeId = nodeId,
    .node = std::move(node),
    .attributeId = attributeId,
    .monitoredItemId = monitoredItemId,
    .samplingInterval = samplingInterval,
    .queueSize = 10,
    .sink = std::move(sink)};
  item.delivery = delivery;
  return item;
}

class MonitoringHelperTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test:monitoring-helper", mExecutor));
  }

  void TearDown() override
  {
    for (const auto& node : mSwitchable)
      node->release_reads();
    for (const auto& sink : mSinks)
      sink->release_pushes();
    mAddressSpace.reset();
    mNamespaces.clear();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// An in-memory namespace registered with the address space.
  std::shared_ptr<ExposedNamespace> registered_namespace(string_view uri)
  {
    auto ns = ExposedNamespace::create(uri, mExecutor);
    const auto added = mAddressSpace->try_add_namespace_sync(ns);
    EXPECT_TRUE(added.is_good()) << to_string(added.status_code());
    mNamespaces.push_back(ns);
    return ns;
  }

  std::shared_ptr<RecordingSink> sink()
  {
    auto created = std::make_shared<RecordingSink>();
    mSinks.push_back(created);
    return created;
  }

  std::shared_ptr<SwitchableVariable> switchable(const NodeId& nodeId, Variant value)
  {
    auto node = SwitchableVariable::create(nodeId, std::move(value));
    mSwitchable.push_back(node);
    return node;
  }

  /// An in-memory Variable in @p ns holding @p value.
  static std::shared_ptr<default_ns::VariableNode> variable(
    ExposedNamespace& ns, uint32_t identifier, Variant value)
  {
    const NodeId nodeId{ns.context_copy().index(), identifier};
    auto node = ns.create_node<default_ns::VariableNode>(nodeId);
    write_value(node, std::move(value));
    return node;
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::vector<std::shared_ptr<ExposedNamespace>> mNamespaces;
  std::vector<std::shared_ptr<RecordingSink>> mSinks;
  std::vector<std::shared_ptr<SwitchableVariable>> mSwitchable;
};

class MonitoringHelperOwnership : public MonitoringHelperTest
{};

class MonitoringHelperIndex : public MonitoringHelperTest
{};

class MonitoringHelperShutdown : public MonitoringHelperTest
{};

class NamespaceMonitoringSupportSemantics : public MonitoringHelperTest
{};

// Not MonitoringHelperModify: that suite's fixture is monitoring_helper_behaviour_tests.cpp's, and one suite
// has one fixture class.
class MonitoringHelperModifyReported : public MonitoringHelperTest
{};

}  // namespace ua::test::monitoring_helper

#endif  // UA_TEST_MONITORING_HELPER_FIXTURE_H
