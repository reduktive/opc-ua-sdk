// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A PercentDeadband item's range follows its EURange Property (Part 8 sections 6.2 and 5.3.2.2; NR-62;
// DL-12).
//
// The Subscription is driven as the pipeline drives it: CreateMonitoredItems and ModifyMonitoredItems through
// their asynchronous entries, values reaching it through the namespace's monitoring of a real Variable, the
// SemanticsChanged mark raised by the namespace (a write of a semantic Property), and notifications taken by
// fulfill_publish. The namespace is a default namespace whose Nodes, as the Subscription looks them up, can
// hold back or fail the answer to a read of their Value, and which can hold back its answer to a monitoring
// change: the orderings the criteria name are reachable only that way.
//
// Each test also monitors the same Variable with a second item that has no filter (the probe). It reports
// every change, so waiting for the probe to report a value is waiting until that value has reached the item
// under test: a value the item under test does not report is then known not to be on its way.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "per_item_join.h"
#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_namespace_monitoring.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_range.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cmath>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;

namespace
{

constexpr uint32_t itemHandle = 7;
constexpr uint32_t probeHandle = 8;

/// What the namespace does with the answers to reads of a Node's Value, shared with the reads in flight.
struct ValueReadGate
{
  struct Parked
  {
    NodeId nodeId;
    std::function<void()> answer;
  };

  mutable std::mutex mutex;
  std::unordered_set<NodeId> held;
  std::unordered_map<NodeId, DataValueResult> scripted;
  std::vector<Parked> parked;
  std::unordered_map<NodeId, size_t> answered;
};

/// The answers to monitoring changes the namespace holds back.
struct ModifyAnswerGate
{
  std::mutex mutex;
  bool hold = false;
  std::vector<std::function<void()>> parked;
};

/// A default namespace whose Value reads, as the Subscription makes them, and whose answers to monitoring
/// changes can be held back or failed by the test.
class GatedNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<GatedNamespace> create(string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<GatedNamespace>(new GatedNamespace(uri, std::move(executor)));
  }

  /// Holds back the answers to reads of @p nodeId's Value until they are released.
  void hold_value_reads(const NodeId& nodeId)
  {
    const std::lock_guard lock{mReadGate->mutex};
    mReadGate->held.insert(nodeId);
  }

  void stop_holding_value_reads(const NodeId& nodeId)
  {
    const std::lock_guard lock{mReadGate->mutex};
    mReadGate->held.erase(nodeId);
  }

  /// Answers every later read of @p nodeId's Value with @p status.
  void fail_value_reads(const NodeId& nodeId, StatusCode status)
  {
    const std::lock_guard lock{mReadGate->mutex};
    mReadGate->scripted.insert_or_assign(nodeId, DataValueResult{std::move(status)});
  }

  /// Answers every later read of @p nodeId's Value with a read that succeeded and gave @p value.
  void answer_value_reads(const NodeId& nodeId, DataValue value)
  {
    const std::lock_guard lock{mReadGate->mutex};
    mReadGate->scripted.insert_or_assign(nodeId, DataValueResult{std::move(value)});
  }

  /// Answers every later read of @p nodeId's Value with @p value and the code @p code on the answer.
  void answer_value_reads(const NodeId& nodeId, DataValue value, StatusCode code)
  {
    const std::lock_guard lock{mReadGate->mutex};
    mReadGate->scripted.insert_or_assign(nodeId, DataValueResult{std::move(value), std::move(code)});
  }

  /// Answers every later lookup of @p nodeId with @p status.
  void fail_lookups(const NodeId& nodeId, StatusCode status)
  {
    const std::lock_guard lock{mLookupMutex};
    mLookupFailures.insert_or_assign(nodeId, std::move(status));
  }

  /// The answers to reads of @p nodeId's Value held back now.
  size_t held_value_reads(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mReadGate->mutex};
    size_t count = 0;
    for (const auto& parked : mReadGate->parked)
    {
      count += parked.nodeId == nodeId ? 1u : 0u;
    }
    return count;
  }

  /// Delivers the @p ordinal-th held answer to a read of @p nodeId's Value (0 is the one held first).
  bool release_value_read(const NodeId& nodeId, size_t ordinal)
  {
    std::function<void()> answer;
    {
      const std::lock_guard lock{mReadGate->mutex};
      for (auto it = mReadGate->parked.begin(); it != mReadGate->parked.end(); ++it)
      {
        if (it->nodeId != nodeId)
        {
          continue;
        }
        if (ordinal-- == 0)
        {
          answer = std::move(it->answer);
          mReadGate->parked.erase(it);
          break;
        }
      }
    }
    if (!answer)
    {
      return false;
    }
    boost::asio::post(mExecutor, std::move(answer));
    return true;
  }

  /// The reads of @p nodeId's Value answered so far.
  size_t answered_value_reads(const NodeId& nodeId) const
  {
    const std::lock_guard lock{mReadGate->mutex};
    const auto found = mReadGate->answered.find(nodeId);
    return found == mReadGate->answered.end() ? 0u : found->second;
  }

  void hold_modify_answers(bool hold)
  {
    const std::lock_guard lock{mModifyGate->mutex};
    mModifyGate->hold = hold;
  }

  size_t held_modify_answers() const
  {
    const std::lock_guard lock{mModifyGate->mutex};
    return mModifyGate->parked.size();
  }

  void release_modify_answers()
  {
    std::vector<std::function<void()>> parked;
    {
      const std::lock_guard lock{mModifyGate->mutex};
      mModifyGate->hold = false;
      parked.swap(mModifyGate->parked);
    }
    for (auto& answer : parked)
    {
      boost::asio::post(mExecutor, std::move(answer));
    }
  }

  /// Stops holding anything and delivers every answer held back.
  void release_everything()
  {
    release_modify_answers();
    std::vector<ValueReadGate::Parked> parked;
    {
      const std::lock_guard lock{mReadGate->mutex};
      mReadGate->held.clear();
      parked.swap(mReadGate->parked);
    }
    for (auto& entry : parked)
    {
      boost::asio::post(mExecutor, std::move(entry.answer));
    }
  }

  void modify_monitoring_async(const RequestInfo& request, std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> callback) override
  {
    default_ns::Namespace::modify_monitoring_async(request,
      items,
      [gate = mModifyGate, callback = std::move(callback)](
        BatchResult<MonitoringModifyItemResult> result) mutable
      {
        auto shared = std::make_shared<BatchResult<MonitoringModifyItemResult>>(std::move(result));
        std::function<void()> answer = [callback = std::move(callback), shared]() mutable
        {
          callback(std::move(*shared));
        };
        {
          const std::lock_guard lock{gate->mutex};
          if (gate->hold)
          {
            gate->parked.push_back(std::move(answer));
            return;
          }
        }
        answer();
      });
  }

  /// Reads each Value through the in-memory member, one item at a time, and answers it as the gate says: a
  /// scripted answer in its place, or the read's answer held back or posted to the executor; each answer
  /// delivered is counted.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    auto join = std::make_shared<test::PerItemJoin<DataValueResult>>(items.size(), std::move(complete));
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const NodeId nodeId = items[index].value.node_id();
      auto deliver = [gate = mReadGate, join, index, nodeId](DataValueResult result)
      {
        join->answer(index, std::move(result));
        const std::lock_guard lock{gate->mutex};
        ++gate->answered[nodeId];
      };
      std::optional<DataValueResult> scripted;
      {
        const std::lock_guard lock{mReadGate->mutex};
        if (const auto found = mReadGate->scripted.find(nodeId); found != mReadGate->scripted.end())
        {
          scripted = found->second;
        }
      }
      if (scripted)
      {
        boost::asio::post(
          mExecutor, [deliver, scripted = std::move(*scripted)]() mutable { deliver(std::move(scripted)); });
        continue;
      }
      const ValueReadItem one[]{items[index]};
      default_ns::Namespace::read_values_async(request,
        caller,
        one,
        maxAge,
        setSourceTimestamp,
        [gate = mReadGate, executor = mExecutor, nodeId, deliver](BatchResult<DataValueResult> read)
        {
          std::function<void()> answer = [deliver, result = test::only_item(std::move(read))]() mutable
          {
            deliver(std::move(result));
          };
          {
            const std::lock_guard lock{gate->mutex};
            if (gate->held.contains(nodeId))
            {
              gate->parked.push_back({nodeId, std::move(answer)});
              return;
            }
          }
          boost::asio::post(executor, std::move(answer));
        });
    }
    join->started();
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    {
      const std::lock_guard lock{mLookupMutex};
      if (const auto found = mLookupFailures.find(nodeId); found != mLookupFailures.end())
      {
        return NodeResult{found->second};
      }
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  GatedNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, executor), mExecutor(std::move(executor))
  {}

  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<ValueReadGate> mReadGate = std::make_shared<ValueReadGate>();
  std::shared_ptr<ModifyAnswerGate> mModifyGate = std::make_shared<ModifyAnswerGate>();
  std::mutex mLookupMutex;
  std::unordered_map<NodeId, StatusCode> mLookupFailures;
};

/// Records what the Subscription logs, its structured fields rendered as text.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::vector<std::string> fieldValues;
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::visit(
        [&copy](const auto& value)
        {
          std::ostringstream text;
          text << value;
          copy.fieldValues.push_back(text.str());
        },
        field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  /// The warnings in the category "subscription" whose message is @p message.
  std::vector<Entry> subscription_warnings(const std::string& message) const
  {
    const std::lock_guard lock{mMutex};
    std::vector<Entry> found;
    for (const auto& entry : mEntries)
    {
      if (entry.level == LogLevel::Warning && entry.category == "subscription" && entry.message == message)
      {
        found.push_back(entry);
      }
    }
    return found;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// Whether some field of @p entry contains @p text.
bool names(const RecordingLogSink::Entry& entry, const std::string& text)
{
  for (const auto& value : entry.fieldValues)
  {
    if (value.find(text) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

/// The warnings of @p warnings that name the item @p item in a field of their own.
std::vector<RecordingLogSink::Entry> about_item(
  const std::vector<RecordingLogSink::Entry>& warnings, IntegerId item)
{
  std::vector<RecordingLogSink::Entry> found;
  for (const auto& entry : warnings)
  {
    for (const auto& value : entry.fieldValues)
    {
      if (value == std::to_string(item))
      {
        found.push_back(entry);
        break;
      }
    }
  }
  return found;
}

/// Expects @p status to be Part 8 Table 29's refusal of a PercentDeadband for want of an EURange, and returns
/// its ErrorDetail (owned by @p status), or null when it has none.
const ErrorDetail* expect_eu_range_refusal(const StatusCode& status, const std::string& subject)
{
  EXPECT_EQ(status.as_status(), Status::BadDeadbandFilterInvalid) << subject << ": " << to_string(status);
  const ErrorDetail* detail = status.detail();
  EXPECT_NE(detail, nullptr) << subject << ": " << to_string(status);
  if (detail != nullptr)
  {
    EXPECT_EQ(detail->code, "PercentDeadbandWithoutEuRange") << subject;
  }
  return detail;
}

/// Expects @p status to be the refusal of a PercentDeadband whose EURange read the namespace answered with
/// the Uncertain code @p uncertain: the refusal's cause is the SDK's refusal of that answer
/// (Bad_InternalError, ReadAnswerUncertain), which carries @p uncertain as its inner status.
void expect_uncertain_eu_range_refusal(const StatusCode& status, Status uncertain, const std::string& subject)
{
  const ErrorDetail* detail = expect_eu_range_refusal(status, subject);
  if (detail == nullptr)
  {
    return;
  }
  EXPECT_EQ(detail->innerStatus, utils::to_underlying(Status::BadInternalError))
    << subject << ": the refusal's cause is not the refusal of the Uncertain answer";
  ASSERT_NE(detail->cause, nullptr) << subject << ": the refusal has no cause";
  EXPECT_EQ(detail->cause->code, "ReadAnswerUncertain") << subject << ": " << to_string(*detail);
  EXPECT_EQ(detail->cause->innerStatus, utils::to_underlying(uncertain))
    << subject << ": the cause does not carry the namespace's " << to_string(uncertain);
}

const std::string rangeNotUsableWarning =
  "A PercentDeadband item's EURange is no longer a usable range; the item reports every change";
const std::string rangeNotReadWarning =
  "A PercentDeadband item's EURange could not be read again; the item keeps the range it holds";

Range make_range(double low, double high)
{
  Range range;
  range.low() = low;
  range.high() = high;
  return range;
}

std::unique_ptr<DataChangeFilter> percent_deadband(double percent)
{
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Percent);
  filter->deadband_value() = percent;
  return filter;
}

std::unique_ptr<DataChangeFilter> absolute_deadband(double value)
{
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = value;
  return filter;
}

class PercentDeadband : public ::testing::Test
{
protected:
  struct Reported
  {
    uint32_t handle;
    double value;
    bool semanticsChanged;
  };

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mNamespace = GatedNamespace::create("urn:test:percent-deadband", mExecutor);
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mNsIndex = index.value();
    // After the namespace is registered: the security context grants every default namespace to its Role.
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    mCapabilities.minSupportedSampleRate = 0;
    mCapabilities.maxMonitoredItemsQueueSize = 1000u;
    mSubscription =
      Subscription::create(1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    mSubscription->set_logger(Logger{mLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  }

  void TearDown() override
  {
    if (mNamespace)
    {
      mNamespace->release_everything();
    }
    mSubscription.reset();
    mSecurityContext.reset();
    mNodes.clear();
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeId id(uint32_t identifier) const
  {
    return NodeId{mNsIndex, identifier};
  }

  /// A Double Variable with the Value 0.0 that the Session may read, write and monitor.
  void create_analog_variable(const NodeId& variable)
  {
    auto node = mAddressSpace->create_node_sync(variable, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{mNsIndex, "Analog"});
    accessor->set_data_type(NodeId{DataTypeId::Double});
    accessor->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    accessor->write_value_sync(Variant{0.0});
    mNodes.insert_or_assign(variable, node);
  }

  /// Gives @p variable an EURange Property @p property holding {@p low, @p high}. The Property holds both
  /// halves of HasProperty before its Value is written, so the namespace marks the Variable's items with
  /// SemanticsChanged for that first Value.
  void add_eu_range(const NodeId& variable, const NodeId& property, double low, double high)
  {
    auto node = mAddressSpace->create_node_sync(property, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{0, "EURange"});
    accessor->set_data_type(NodeId{DataTypeId::Range});
    mNodes.insert_or_assign(property, node);
    auto owner = mNodes.at(variable);
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, property);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, variable, false);
    accessor->write_value_sync(Variant{make_range(low, high)});
  }

  /// Gives @p variable a Property @p property, a Double with the BrowseName (0, "EngineeringUnits"). Writing
  /// its Value marks the Variable's items with SemanticsChanged, as the first Value does.
  void add_other_property(const NodeId& variable, const NodeId& property)
  {
    auto node = mAddressSpace->create_node_sync(property, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{0, "EngineeringUnits"});
    accessor->set_data_type(NodeId{DataTypeId::Double});
    mNodes.insert_or_assign(property, node);
    auto owner = mNodes.at(variable);
    owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, property);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, variable, false);
    accessor->write_value_sync(Variant{0.0});
  }

  void write_value(const NodeId& variable, double value)
  {
    auto accessor = mNodes.at(variable).as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->write_value_sync(Variant{value});
  }

  /// Writes the EURange Property @p property of @p variable; the namespace marks the Variable's items with
  /// SemanticsChanged, as Part 8 section 5.3.2.2 asks for a change of the EURange. Without @p mark the
  /// Property does not name its owner for the write, so nothing is marked.
  void write_eu_range(
    const NodeId& variable, const NodeId& property, double low, double high, bool mark = true)
  {
    auto node = mNodes.at(property);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    if (!mark)
    {
      node.remove_reference_sync(NodeId{ReferenceTypeId::HasProperty}, variable, false);
    }
    accessor->write_value_sync(Variant{make_range(low, high)});
    if (!mark)
    {
      node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, variable, false);
    }
  }

  MonitoredItemCreateRequest item_request(
    const NodeId& variable, uint32_t clientHandle, std::unique_ptr<DataChangeFilter> filter)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = variable;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 0;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;
    if (filter)
    {
      item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
    }
    return item;
  }

  std::future<std::vector<MonitoredItemCreateResult>> start_create(MonitoredItemCreateRequest item)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      mSecurityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<MonitoredItemCreateResult> results) { promise->set_value(std::move(results)); });
    return future;
  }

  MonitoredItemCreateResult finish_create(std::future<std::vector<MonitoredItemCreateResult>>& future)
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return {};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the create answered " << results.size() << " results for one item";
      return {};
    }
    return results[0];
  }

  MonitoredItemCreateResult create(
    const NodeId& variable, uint32_t clientHandle, std::unique_ptr<DataChangeFilter> filter)
  {
    auto future = start_create(item_request(variable, clientHandle, std::move(filter)));
    return finish_create(future);
  }

  /// Monitors @p variable with the item under test (@p filter) and with the probe, and takes both initial
  /// values. Returns the id of the item under test, 0 when it could not be created.
  IntegerId monitor(const NodeId& variable, std::unique_ptr<DataChangeFilter> filter)
  {
    const auto item = create(variable, itemHandle, std::move(filter));
    EXPECT_TRUE(item.status_code().is_good()) << to_string(item.status_code());
    add_probe(variable);
    return item.status_code().is_good() ? item.monitored_item_id() : 0;
  }

  void add_probe(const NodeId& variable)
  {
    const auto probe = create(variable, probeHandle, nullptr);
    EXPECT_TRUE(probe.status_code().is_good()) << to_string(probe.status_code());
    mProbeId = probe.monitored_item_id();
    EXPECT_TRUE(publish_until(probeHandle, 0.0)) << "the probe's initial value was not published";
  }

  std::future<std::vector<MonitoredItemModifyResult>> start_modify(
    IntegerId monitoredItemId, std::unique_ptr<DataChangeFilter> filter)
  {
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    MonitoredItemModifyRequest item;
    item.monitored_item_id() = monitoredItemId;
    item.requested_parameters().client_handle() = itemHandle;
    item.requested_parameters().sampling_interval() = 0;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;
    if (filter)
    {
      item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
    }
    request.items_to_modify().push_back(std::move(item));
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemModifyResult>>>();
    auto future = promise->get_future();
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [promise](std::vector<MonitoredItemModifyResult> results) { promise->set_value(std::move(results)); });
    return future;
  }

  StatusCode finish_modify(std::future<std::vector<MonitoredItemModifyResult>>& future)
  {
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the modify did not answer";
      return StatusCode{Status::BadTimeout};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the modify answered " << results.size() << " results for one item";
      return StatusCode{Status::BadInternalError};
    }
    return results[0].status_code();
  }

  StatusCode modify(IntegerId monitoredItemId, std::unique_ptr<DataChangeFilter> filter)
  {
    auto future = start_modify(monitoredItemId, std::move(filter));
    return finish_modify(future);
  }

  /// Publishes until the item with @p clientHandle reports @p value, at most 3 s; every value published
  /// meanwhile is recorded. Returns whether it was reported.
  bool publish_until(uint32_t clientHandle, double value)
  {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    for (;;)
    {
      auto published = STA::on_strand(*mSubscription,
        [](auto& guard)
        {
          guard.set_publish_req_queued(true);
          return guard.fulfill_publish(1);
        });
      bool seen = false;
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
            const auto* number = notification.value().value().try_as<double>();
            const bool semanticsChanged =
              notification.value().status().has_value() && notification.value().status()->semantics_changed();
            mReported.push_back(
              {notification.client_handle(), number != nullptr ? *number : std::nan(""), semanticsChanged});
            seen =
              seen || (notification.client_handle() == clientHandle && number != nullptr && *number == value);
          }
        }
      }
      if (seen)
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

  /// Writes @p value to @p variable, waits until the sample has reached the Subscription (the probe has
  /// queued it) and only then publishes, until the probe has reported it. No publish comes between the write
  /// and the sample's arrival, so a value written while the item is marked SemanticsChanged reaches it while
  /// it is still marked.
  void write_and_settle(const NodeId& variable, double value)
  {
    write_value(variable, value);
    const bool queued = wait_until(
      [&]
      {
        return STA::on_strand(*mSubscription,
          [&](auto& guard)
          {
            const auto* probe = guard.find_monitored_item(mProbeId);
            if (probe == nullptr || !probe->lastQueuedValue.has_value())
            {
              return false;
            }
            const auto* number = probe->lastQueuedValue->value().template try_as<double>();
            return number != nullptr && *number == value;
          });
      });
    EXPECT_TRUE(queued) << "the sample " << value << " never reached the Subscription";
    flush_subscription();
    EXPECT_TRUE(publish_until(probeHandle, value)) << "the probe did not report " << value;
  }

  /// Waits until the reads of @p property's Value answered reach @p count, then until the Subscription has
  /// handled what they posted. A wait that times out is not a failure: the observations that follow are.
  void settle_reads(const NodeId& property, size_t count)
  {
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (mNamespace->answered_value_reads(property) < count && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(2ms);
    }
    flush_subscription();
  }

  /// Waits until @p predicate holds or 1 s passes.
  template<typename Predicate>
  bool wait_until(Predicate predicate)
  {
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (!predicate())
    {
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(2ms);
    }
    return true;
  }

  void flush_subscription()
  {
    for (int round = 0; round < 3; ++round)
    {
      STA::on_strand(*mSubscription, [](auto&) {});
    }
  }

  /// Whether the item under test reported @p value; with @p semanticsChanged, carrying the SemanticsChanged
  /// bit.
  bool item_reported(double value, bool semanticsChanged = false) const
  {
    for (const auto& reported : mReported)
    {
      if (reported.handle == itemHandle && reported.value == value &&
          (!semanticsChanged || reported.semanticsChanged))
      {
        return true;
      }
    }
    return false;
  }

  std::string item_reports() const
  {
    std::ostringstream text;
    text << "the item reported:";
    for (const auto& reported : mReported)
    {
      if (reported.handle == itemHandle)
      {
        text << ' ' << reported.value << (reported.semanticsChanged ? "(SemanticsChanged)" : "");
      }
    }
    return text.str();
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<GatedNamespace> mNamespace;
  uint16_t mNsIndex{0};
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  std::shared_ptr<Subscription> mSubscription;
  std::shared_ptr<RecordingLogSink> mLog = std::make_shared<RecordingLogSink>();
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
  std::unordered_map<NodeId, NodeAccessor> mNodes;
  std::vector<Reported> mReported;
  IntegerId mProbeId{0};
};

}  // namespace

// Part 8 section 6.2: the deadband is (deadbandValue/100) * (high - low) of the EURange; section 5.3.2.2
// marks the item SemanticsChanged when the EURange changes; NR-62 makes the deadband the new range's.
// @relation(AC-SVR-DA-022-DEADBAND-FOLLOWS-EURANGE-CHANGE, scope=function)
TEST_F(PercentDeadband, ARereadEuRangeReplacesTheItemsRange)
{
  const NodeId variable = id(100);
  const NodeId property = id(101);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  ASSERT_NE(monitor(variable, percent_deadband(10.0)), 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(property);
  ASSERT_GE(readsAtCreate, 1u) << "the create's read of the EURange did not reach the namespace";

  write_and_settle(variable, 5.0);
  write_eu_range(variable, property, 0.0, 20.0);
  settle_reads(property, readsAtCreate + 1);
  write_and_settle(variable, 1.0);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 5.0);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0, a change of 3, is above the deadband of 2 that {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(5.0)) << "a change of 1 is within the deadband of 2; " << item_reports();
}

// Part 8 section 6.2's formula gives {50, 50} a deadband of 0, so every change is reported; the SDK logs that
// the item's range is no longer usable, naming the item.
// @relation(AC-SVR-DA-022-UNUSABLE-EURANGE-REPORTS-EVERY-CHANGE, scope=function)
TEST_F(PercentDeadband, AnUnusableRereadRangeIsLoggedAndReportsEveryChange)
{
  const NodeId variable = id(110);
  const NodeId property = id(111);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(property);

  write_eu_range(variable, property, 50.0, 50.0);
  settle_reads(property, readsAtCreate + 1);
  write_and_settle(variable, 1.0);
  write_and_settle(variable, 2.0);
  write_and_settle(variable, 2.5);

  EXPECT_TRUE(item_reported(1.0)) << item_reports();
  EXPECT_TRUE(item_reported(2.0)) << item_reports();
  EXPECT_TRUE(item_reported(2.5)) << item_reports();
  const auto warnings = mLog->subscription_warnings(rangeNotUsableWarning);
  ASSERT_EQ(warnings.size(), 1u) << "no warning in the category subscription that the range is not usable";
  EXPECT_TRUE(names(warnings[0], std::to_string(item))) << "the warning does not name the item " << item;
}

// NR-62 rule 3: a mark that arrives after the item's EURange was read and before the create commits is kept
// and applied at commit. The window is held open by holding back the namespace's answer to the create's read
// of the item's initial value, the step after the EURange read.
// @relation(AC-SVR-DA-022-MARK-BEFORE-COMMIT-APPLIED, scope=function)
TEST_F(PercentDeadband, AMarkBeforeCommitIsAppliedAtCommit)
{
  const NodeId variable = id(120);
  const NodeId property = id(121);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);

  mNamespace->hold_value_reads(variable);
  auto creating = start_create(item_request(variable, itemHandle, percent_deadband(10.0)));
  ASSERT_TRUE(wait_until([&] { return mNamespace->held_value_reads(variable) == 1u; }))
    << "the create's read of the initial value never reached the namespace";
  // The namespace counts an answer after delivering it, and the create goes on to the read held above as soon
  // as the EURange answer is delivered, so the count of that answer can still be on its way. While the read
  // of the initial value is held no later read of the EURange can start.
  wait_until([&] { return mNamespace->answered_value_reads(property) >= 1u; });
  const size_t readsBeforeMark = mNamespace->answered_value_reads(property);
  EXPECT_GE(readsBeforeMark, 1u) << "the EURange was not read before the initial value";
  write_eu_range(variable, property, 0.0, 20.0);
  flush_subscription();
  mNamespace->stop_holding_value_reads(variable);
  ASSERT_TRUE(mNamespace->release_value_read(variable, 0));
  const auto created = finish_create(creating);
  ASSERT_TRUE(created.status_code().is_good()) << to_string(created.status_code());
  settle_reads(property, readsBeforeMark + 1);
  add_probe(variable);

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 5.0);

  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that {0, 20} gives; " << item_reports();
  EXPECT_FALSE(item_reported(5.0)) << "a change of 1 is within the deadband of 2 that {0, 20} gives; "
                                   << item_reports();
}

// Part 4 section 5.12.3.1: a modify is applied at once; Part 8 section 6.2 defines the PercentDeadband by the
// EURange. NR-62 rule 4: a modify that sets a PercentDeadband reads the EURange.
// @relation(AC-SVR-DA-022-MODIFY-TO-PERCENT-USES-EURANGE, scope=function)
TEST_F(PercentDeadband, AModifyToPercentDeadbandReadsTheEuRange)
{
  const NodeId variable = id(130);
  const NodeId property = id(131);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, nullptr);
  ASSERT_NE(item, 0u);

  const auto modified = modify(item, percent_deadband(10.0));
  EXPECT_TRUE(modified.is_good()) << to_string(modified);
  write_and_settle(variable, 5.0);
  write_and_settle(variable, 20.0);

  EXPECT_FALSE(item_reported(5.0)) << "a change of 5 is within the deadband of 10; " << item_reports();
  EXPECT_TRUE(item_reported(20.0)) << item_reports();
}

// Part 8 Table 29: Bad_DeadbandFilterInvalid when a PercentDeadband is not supported because no EURange is
// configured; the refused modify leaves the item as it was.
// @relation(AC-SVR-DA-022-MODIFY-TO-PERCENT-WITHOUT-EURANGE-REFUSED, scope=function)
TEST_F(PercentDeadband, AModifyToPercentDeadbandOnANodeWithoutEuRangeAnswersDeadbandFilterInvalid)
{
  const NodeId variable = id(140);
  create_analog_variable(variable);
  const IntegerId item = monitor(variable, nullptr);
  ASSERT_NE(item, 0u);

  const auto modified = modify(item, percent_deadband(10.0));
  EXPECT_EQ(modified.as_status(), Status::BadDeadbandFilterInvalid) << to_string(modified);
  ASSERT_NE(modified.shared_detail(), nullptr);
  EXPECT_EQ(modified.shared_detail()->code, "PercentDeadbandWithoutEuRange");
  write_and_settle(variable, 0.1);
  write_and_settle(variable, 0.2);

  EXPECT_TRUE(item_reported(0.1)) << item_reports();
  EXPECT_TRUE(item_reported(0.2)) << item_reports();
}

// Of two quick EURange changes the item ends with the second range, even when the re-read for the first
// answers last: each mark makes any read already on its way stale.
// @relation(AC-SVR-DA-022-LATEST-EURANGE-CHANGE-WINS, scope=function)
TEST_F(PercentDeadband, AStaleRereadIsNotApplied)
{
  const NodeId variable = id(150);
  const NodeId property = id(151);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  ASSERT_NE(monitor(variable, percent_deadband(10.0)), 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(property);
  ASSERT_GE(readsAtCreate, 1u) << "the create's read of the EURange did not reach the namespace";

  mNamespace->hold_value_reads(property);
  write_eu_range(variable, property, 0.0, 20.0);
  EXPECT_TRUE(wait_until([&] { return mNamespace->held_value_reads(property) == 1u; }))
    << "no re-read of the EURange reached the namespace after the first change";
  write_eu_range(variable, property, 0.0, 200.0);
  EXPECT_TRUE(wait_until([&] { return mNamespace->held_value_reads(property) == 2u; }))
    << "no re-read of the EURange reached the namespace after the second change";
  if (mNamespace->release_value_read(property, 1))
  {
    settle_reads(property, readsAtCreate + 1);
  }
  if (mNamespace->release_value_read(property, 0))
  {
    settle_reads(property, readsAtCreate + 2);
  }
  mNamespace->release_everything();

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 16.0);
  write_and_settle(variable, 40.0);

  EXPECT_TRUE(item_reported(1.0)) << item_reports();
  EXPECT_FALSE(item_reported(16.0)) << "a change of 15 is within the deadband of 20 that {0, 200} gives; "
                                    << item_reports();
  EXPECT_TRUE(item_reported(40.0)) << item_reports();
}

// A modify that read the EURange before a mark arrived reads it again after it commits.
// @relation(AC-SVR-DA-022-MARK-DURING-MODIFY-APPLIED, scope=function)
TEST_F(PercentDeadband, AMarkDuringAModifyIsAppliedAfterItCommits)
{
  const NodeId variable = id(160);
  const NodeId property = id(161);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, nullptr);
  ASSERT_NE(item, 0u);

  mNamespace->hold_modify_answers(true);
  auto modifying = start_modify(item, percent_deadband(10.0));
  ASSERT_TRUE(wait_until([&] { return mNamespace->held_modify_answers() == 1u; }))
    << "the modify's monitoring change never reached the namespace";
  const size_t readsBeforeMark = mNamespace->answered_value_reads(property);
  write_eu_range(variable, property, 0.0, 20.0);
  flush_subscription();
  mNamespace->release_modify_answers();
  const auto modified = finish_modify(modifying);
  EXPECT_TRUE(modified.is_good()) << to_string(modified);
  settle_reads(property, readsBeforeMark + 1);

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 4.5);

  EXPECT_TRUE(item_reported(1.0)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that {0, 20} gives; " << item_reports();
  EXPECT_FALSE(item_reported(4.5)) << "a change of 0.5 is within the deadband of 2; " << item_reports();
}

// A modify of a PercentDeadband item serves from the range it holds; once the EURange is not usable, a modify
// to a PercentDeadband is refused with Bad_DeadbandFilterInvalid.
// @relation(AC-SVR-DA-022-MODIFY-OF-PERCENT-ITEM-USES-HELD-RANGE, scope=function)
TEST_F(PercentDeadband, AModifyOfAPercentDeadbandItemWithAnUnusableRangeIsRefused)
{
  const NodeId variable = id(170);
  const NodeId property = id(171);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);

  const auto first = modify(item, percent_deadband(5.0));
  EXPECT_TRUE(first.is_good()) << to_string(first);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 7.0);
  EXPECT_FALSE(item_reported(4.0)) << "a change of 4 is within the deadband of 5; " << item_reports();
  EXPECT_TRUE(item_reported(7.0)) << "a change of 7 is above the deadband of 5; " << item_reports();

  const size_t readsBeforeMark = mNamespace->answered_value_reads(property);
  write_eu_range(variable, property, 50.0, 50.0);
  settle_reads(property, readsBeforeMark + 1);
  const auto second = modify(item, percent_deadband(2.0));
  EXPECT_EQ(second.as_status(), Status::BadDeadbandFilterInvalid) << to_string(second);
  ASSERT_NE(second.shared_detail(), nullptr) << to_string(second);
  EXPECT_EQ(second.shared_detail()->code, "PercentDeadbandWithoutEuRange");
}

// DL-12: a modify that keeps an item's PercentDeadband keeps the range the item holds at commit, so a re-read
// applied while the modify ran is kept.
// @relation(AC-SVR-DA-022-MODIFY-KEEPING-PERCENT-KEEPS-REREAD-RANGE, scope=function)
TEST_F(PercentDeadband, AModifyKeepingThePercentDeadbandKeepsARereadAppliedMeanwhile)
{
  const NodeId variable = id(180);
  const NodeId property = id(181);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);

  mNamespace->hold_modify_answers(true);
  auto modifying = start_modify(item, percent_deadband(5.0));
  ASSERT_TRUE(wait_until([&] { return mNamespace->held_modify_answers() == 1u; }))
    << "the modify's monitoring change never reached the namespace";
  const size_t readsBeforeMark = mNamespace->answered_value_reads(property);
  write_eu_range(variable, property, 0.0, 20.0);
  settle_reads(property, readsBeforeMark + 1);
  mNamespace->release_modify_answers();
  const auto modified = finish_modify(modifying);
  EXPECT_TRUE(modified.is_good()) << to_string(modified);

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 2.5);
  write_and_settle(variable, 3.0);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(2.5)) << "a change of 1.5 is above the deadband of 1 that 5% of {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(3.0)) << "a change of 0.5 is within the deadband of 1; " << item_reports();
}

// DL-12 as amended after the fourth review: whether a modify keeps the held range is decided when its row is
// checked, so a re-read that makes the range unusable while the modify's namespace call is outstanding is
// applied: the item reports every change (Part 8 section 6.2's formula gives {50, 50} a deadband of 0) and
// the modify, valid when its row was checked, answers Good. Under the {0, 100} range the item held, 5% is a
// deadband of 5, which would suppress 1.2 and 1.3.
// @relation(AC-SVR-DA-022-UNUSABLE-REREAD-DURING-MODIFY-APPLIED, scope=function)
TEST_F(PercentDeadband, AnUnusableRereadDuringAModifyIsAppliedAndTheModifyAnswersGood)
{
  const NodeId variable = id(230);
  const NodeId property = id(231);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);

  mNamespace->hold_modify_answers(true);
  auto modifying = start_modify(item, percent_deadband(5.0));
  ASSERT_TRUE(wait_until([&] { return mNamespace->held_modify_answers() == 1u; }))
    << "the modify's monitoring change never reached the namespace";
  const size_t readsBeforeMark = mNamespace->answered_value_reads(property);
  write_eu_range(variable, property, 50.0, 50.0);
  settle_reads(property, readsBeforeMark + 1);
  mNamespace->release_modify_answers();
  const auto modified = finish_modify(modifying);
  EXPECT_TRUE(modified.is_good()) << "the modify answered " << to_string(modified);

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 1.2);
  write_and_settle(variable, 1.3);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(1.2)) << "the item does not report every change; " << item_reports();
  EXPECT_TRUE(item_reported(1.3)) << "the item does not report every change; " << item_reports();
  const auto warnings = mLog->subscription_warnings(rangeNotUsableWarning);
  ASSERT_EQ(warnings.size(), 1u) << "no warning in the category subscription that the range is not usable";
  EXPECT_TRUE(names(warnings[0], std::to_string(item))) << "the warning does not name the item " << item;
}

// DL-12: the re-read looks the EURange Property up by its browse name, as the create does, because the mark
// may report a new Property Node.
// @relation(AC-SVR-DA-022-REPLACED-EURANGE-PROPERTY-LOOKED-UP-AGAIN, scope=function)
TEST_F(PercentDeadband, AReplacedEuRangePropertyIsLookedUpAgain)
{
  const NodeId variable = id(190);
  const NodeId firstProperty = id(191);
  const NodeId secondProperty = id(192);
  create_analog_variable(variable);
  add_eu_range(variable, firstProperty, 0.0, 100.0);
  ASSERT_NE(monitor(variable, percent_deadband(10.0)), 0u);

  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(firstProperty, false).is_good());
  mNodes.erase(firstProperty);
  add_eu_range(variable, secondProperty, 0.0, 20.0);
  settle_reads(secondProperty, 1);

  write_and_settle(variable, 1.0);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 5.0);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that the new Property's {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(5.0)) << "a change of 1 is within the deadband of 2; " << item_reports();
}

// DL-12: a modify to a PercentDeadband of an item whose held range is not usable reads the range again. The
// change of the Property without a mark isolates the read: only a modify that reads it finds {0, 20}.
// @relation(AC-SVR-DA-022-MODIFY-OF-ITEM-WITH-UNUSABLE-RANGE-READS-AGAIN, scope=function)
TEST_F(PercentDeadband, AModifyOfAnItemWithAnUnusableRangeReadsTheRangeAgain)
{
  const NodeId variable = id(200);
  const NodeId property = id(201);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(property);

  write_eu_range(variable, property, 50.0, 50.0);
  settle_reads(property, readsAtCreate + 1);
  write_eu_range(variable, property, 0.0, 20.0, /*mark=*/false);
  const auto modified = modify(item, percent_deadband(5.0));
  EXPECT_TRUE(modified.is_good()) << to_string(modified);

  write_and_settle(variable, 10.0);
  write_and_settle(variable, 10.5);
  write_and_settle(variable, 12.0);

  EXPECT_TRUE(item_reported(10.0)) << item_reports();
  EXPECT_FALSE(item_reported(10.5))
    << "a change of 0.5 is within the deadband of 1 that 5% of {0, 20} gives; " << item_reports();
  EXPECT_TRUE(item_reported(12.0)) << "a change of 2 is above the deadband of 1; " << item_reports();
}

// DL-12 (fourth review): a re-read that fails with anything but Bad_NodeIdUnknown says nothing about the
// range, and the item keeps the one it holds; a missing EURange Property leaves it without one. Both are
// logged with their cause.
// @relation(AC-SVR-DA-022-FAILED-REREAD-KEEPS-HELD-RANGE, scope=function)
TEST_F(PercentDeadband, AFailedRereadKeepsTheHeldRange)
{
  const NodeId variable = id(210);
  const NodeId property = id(211);
  create_analog_variable(variable);
  add_eu_range(variable, property, 0.0, 100.0);
  const IntegerId item = monitor(variable, percent_deadband(10.0));
  ASSERT_NE(item, 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(property);

  // (1) A usable new range.
  write_eu_range(variable, property, 0.0, 20.0);
  settle_reads(property, readsAtCreate + 1);
  write_and_settle(variable, 1.0);
  write_and_settle(variable, 4.0);
  write_and_settle(variable, 5.0);

  // (2) The read of the range fails.
  mNamespace->fail_value_reads(property,
    StatusCode{Status::BadCommunicationError,
      ErrorDetail::build("ReadFailed", "The EURange could not be read", "PercentDeadbandTest")});
  write_eu_range(variable, property, 0.0, 20.0);
  settle_reads(property, readsAtCreate + 2);
  write_and_settle(variable, 6.0);
  write_and_settle(variable, 7.0);
  write_and_settle(variable, 9.5);

  // (3) The EURange Property is gone.
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(property, false).is_good());
  mNodes.erase(property);
  add_other_property(variable, id(212));
  wait_until([&] { return !mLog->subscription_warnings(rangeNotUsableWarning).empty(); });
  flush_subscription();
  write_and_settle(variable, 10.0);
  write_and_settle(variable, 10.5);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that {0, 20} gives; " << item_reports();
  EXPECT_FALSE(item_reported(5.0)) << "a change of 1 is within the deadband of 2; " << item_reports();
  EXPECT_TRUE(item_reported(6.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_FALSE(item_reported(7.0))
    << "the item keeps {0, 20} after a failed read: a change of 1 is within its "
       "deadband of 2; "
    << item_reports();
  EXPECT_TRUE(item_reported(9.5)) << item_reports();
  EXPECT_TRUE(item_reported(10.0)) << item_reports();
  EXPECT_TRUE(item_reported(10.5)) << "without an EURange Property the item reports every change; "
                                   << item_reports();

  const auto notRead = mLog->subscription_warnings(rangeNotReadWarning);
  ASSERT_EQ(notRead.size(), 1u) << "no warning that the range could not be read again";
  EXPECT_TRUE(names(notRead[0], std::to_string(item)));
  EXPECT_TRUE(names(notRead[0], to_string(Status::BadCommunicationError)));
  EXPECT_TRUE(names(notRead[0], "ReadFailed"));
  const auto notUsable = mLog->subscription_warnings(rangeNotUsableWarning);
  ASSERT_EQ(notUsable.size(), 1u) << "no warning that the item has no usable range";
  EXPECT_TRUE(names(notUsable[0], std::to_string(item)));
  EXPECT_TRUE(names(notUsable[0], to_string(Status::BadNodeIdUnknown)));
}

// DL-12 (fourth review): a refusal of a PercentDeadband because no range was found carries the read's answer
// as its cause: none for a range that was read and is not usable.
// @relation(AC-SVR-DA-022-REFUSAL-CARRIES-THE-READS-CAUSE, scope=function)
TEST_F(PercentDeadband, ARefusalCarriesTheReadsCause)
{
  const NodeId withoutProperty = id(220);
  const NodeId failingRead = id(221);
  const NodeId failingProperty = id(222);
  const NodeId zeroWidth = id(223);
  const NodeId zeroWidthProperty = id(224);
  create_analog_variable(withoutProperty);
  create_analog_variable(failingRead);
  add_eu_range(failingRead, failingProperty, 0.0, 100.0);
  create_analog_variable(zeroWidth);
  add_eu_range(zeroWidth, zeroWidthProperty, 50.0, 50.0);
  mNamespace->fail_value_reads(failingProperty,
    StatusCode{Status::BadCommunicationError,
      ErrorDetail::build("ReadFailed", "The EURange could not be read", "PercentDeadbandTest")});

  const auto refusedFor = [](const StatusCode& status) -> const ErrorDetail*
  {
    EXPECT_EQ(status.as_status(), Status::BadDeadbandFilterInvalid) << to_string(status);
    const ErrorDetail* detail = status.detail();
    EXPECT_NE(detail, nullptr) << to_string(status);
    if (detail != nullptr)
    {
      EXPECT_EQ(detail->code, "PercentDeadbandWithoutEuRange");
    }
    return detail;
  };

  const auto missingCreate = create(withoutProperty, itemHandle, percent_deadband(10.0)).status_code();
  if (const auto* missing = refusedFor(missingCreate))
  {
    EXPECT_EQ(missing->innerStatus, utils::to_underlying(Status::BadNodeIdUnknown))
      << "the refusal does not carry the lookup's Bad_NodeIdUnknown";
  }

  const auto failedCreate = create(failingRead, itemHandle, percent_deadband(10.0)).status_code();
  if (const auto* failed = refusedFor(failedCreate))
  {
    EXPECT_EQ(failed->innerStatus, utils::to_underlying(Status::BadCommunicationError))
      << "the refusal does not carry the read's Bad_CommunicationError";
    EXPECT_TRUE(failed->cause != nullptr && failed->cause->code == "ReadFailed")
      << "the refusal does not carry the read's ErrorDetail as its cause";
  }

  const auto zeroWidthCreate = create(zeroWidth, itemHandle, percent_deadband(10.0)).status_code();
  if (const auto* notUsable = refusedFor(zeroWidthCreate))
  {
    EXPECT_EQ(notUsable->innerStatus, utils::to_underlying(Status::Good))
      << "a read that succeeded has no inner status";
    EXPECT_EQ(notUsable->cause, nullptr) << "a read that succeeded has no cause";
  }

  const auto absolute = create(failingRead, itemHandle, absolute_deadband(1.0));
  ASSERT_TRUE(absolute.status_code().is_good()) << to_string(absolute.status_code());
  const auto modified = modify(absolute.monitored_item_id(), percent_deadband(10.0));
  if (const auto* failedModify = refusedFor(modified))
  {
    EXPECT_EQ(failedModify->innerStatus, utils::to_underlying(Status::BadCommunicationError))
      << "the modify's refusal does not carry the read's Bad_CommunicationError";
    EXPECT_TRUE(failedModify->cause != nullptr && failedModify->cause->code == "ReadFailed")
      << "the modify's refusal does not carry the read's ErrorDetail as its cause";
  }
}

// Part 8 section 5.6.2 gives a limit that is not known as NaN, and section 6.2's deadband needs a number for
// high - low. A range with a limit that is NaN or not finite, or whose width is not finite, is not usable:
// the create refuses it as Table 29's PercentDeadband without an EURange, with no inner status and no cause
// because the read succeeded. A usable range is accepted (the control).
// @relation(AC-SVR-DA-022-RANGE-WITHOUT-A-FINITE-WIDTH-IS-NOT-USABLE, scope=function)
TEST_F(PercentDeadband, ARangeWithoutAFiniteWidthIsRefusedAtCreate)
{
  constexpr double nan = std::numeric_limits<double>::quiet_NaN();
  constexpr double infinity = std::numeric_limits<double>::infinity();
  constexpr double largest = std::numeric_limits<double>::max();

  struct Case
  {
    std::string name;
    double low;
    double high;
  };

  const std::vector<Case> notUsable{{"V1 {NaN, 100}", nan, 100.0},
    {"V2 {0, NaN}", 0.0, nan},
    {"V3 {0, +inf}", 0.0, infinity},
    {"V4 {-max, max}", -largest, largest}};
  uint32_t next = 300;
  for (const auto& range : notUsable)
  {
    const NodeId variable = id(next++);
    const NodeId property = id(next++);
    create_analog_variable(variable);
    add_eu_range(variable, property, range.low, range.high);
    const auto created = create(variable, itemHandle, percent_deadband(10.0));
    if (const auto* detail = expect_eu_range_refusal(created.status_code(), range.name + "'s create"))
    {
      EXPECT_EQ(detail->innerStatus, utils::to_underlying(Status::Good))
        << range.name << ": a read that succeeded has no inner status";
      EXPECT_EQ(detail->cause, nullptr) << range.name << ": a read that succeeded has no cause";
    }
  }

  const NodeId usable = id(next++);
  const NodeId usableProperty = id(next++);
  create_analog_variable(usable);
  add_eu_range(usable, usableProperty, 0.0, 100.0);
  const auto accepted = create(usable, itemHandle, percent_deadband(10.0));
  EXPECT_TRUE(accepted.status_code().is_good()) << "V5 {0, 100}: " << to_string(accepted.status_code());
}

// The modify refuses a range whose limit is not known as the create does, and the refused modify leaves the
// item as it was: with no filter it reports every change.
// @relation(AC-SVR-DA-022-RANGE-WITHOUT-A-FINITE-WIDTH-IS-NOT-USABLE, scope=function)
TEST_F(PercentDeadband, ARangeWithoutAFiniteWidthIsRefusedAtModify)
{
  const NodeId variable = id(310);
  const NodeId property = id(311);
  create_analog_variable(variable);
  add_eu_range(variable, property, std::numeric_limits<double>::quiet_NaN(), 100.0);
  const IntegerId item = monitor(variable, nullptr);
  ASSERT_NE(item, 0u);

  const StatusCode modified = modify(item, percent_deadband(10.0));
  expect_eu_range_refusal(modified, "the modify");
  write_and_settle(variable, 0.1);
  write_and_settle(variable, 0.2);

  EXPECT_TRUE(item_reported(0.1)) << "the item keeps no filter; " << item_reports();
  EXPECT_TRUE(item_reported(0.2)) << "the item keeps no filter; " << item_reports();
}

// A re-read range with a limit that is not known (V7) or a width that is not finite (V8) is not usable: the
// item reports every change, and the SDK logs that its range is no longer usable, naming the item.
// @relation(AC-SVR-DA-022-RANGE-WITHOUT-A-FINITE-WIDTH-IS-NOT-USABLE, scope=function)
TEST_F(PercentDeadband, ARereadRangeWithoutAFiniteWidthMakesTheItemReportEveryChange)
{
  struct Case
  {
    std::string name;
    NodeId variable;
    NodeId property;
    double low;
    double high;
  };

  const double largest = std::numeric_limits<double>::max();
  const std::vector<Case> cases{
    {"V7 {0, NaN}", id(320), id(321), 0.0, std::numeric_limits<double>::quiet_NaN()},
    {"V8 {-max, max}", id(322), id(323), -largest, largest}};
  for (const auto& range : cases)
  {
    mReported.clear();
    create_analog_variable(range.variable);
    add_eu_range(range.variable, range.property, 0.0, 100.0);
    const IntegerId item = monitor(range.variable, percent_deadband(10.0));
    ASSERT_NE(item, 0u) << range.name;
    const size_t readsAtCreate = mNamespace->answered_value_reads(range.property);

    write_eu_range(range.variable, range.property, range.low, range.high);
    settle_reads(range.property, readsAtCreate + 1);
    write_and_settle(range.variable, 1.0);
    write_and_settle(range.variable, 2.0);
    write_and_settle(range.variable, 2.5);

    EXPECT_TRUE(item_reported(1.0)) << range.name << ": " << item_reports();
    EXPECT_TRUE(item_reported(2.0)) << range.name << ": the item does not report every change; "
                                    << item_reports();
    EXPECT_TRUE(item_reported(2.5)) << range.name << ": the item does not report every change; "
                                    << item_reports();
    EXPECT_EQ(about_item(mLog->subscription_warnings(rangeNotUsableWarning), item).size(), 1u)
      << range.name << ": no warning in the category subscription naming the item " << item
      << " that its range is not usable";
  }
}

// Part 4 section 7.11: a value whose StatusCode is Bad is not usable, so a Range read with a Bad status is a
// failed read, and so is an Uncertain answer that holds no value: the create and the modify refuse with the
// read's status as the inner status (an Uncertain answer through its refusal, ReadAnswerUncertain), and a
// re-read keeps the held range and logs it. The deadband is computed from a Good Range only, so a DataValue
// of Uncertain quality is refused in the same way even when it holds a usable Range.
// @relation(AC-SVR-DA-022-BAD-QUALITY-OR-UNCERTAIN-READ-IS-A-FAILED-READ, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(PercentDeadband, AReadOfBadQualityOrUncertainIsAFailedRead)
{
  const auto expectRefusedWith = [](const StatusCode& status, Status inner, const std::string& subject)
  {
    if (inner != Status::Uncertain)
    {
      if (const auto* detail = expect_eu_range_refusal(status, subject))
      {
        EXPECT_EQ(detail->innerStatus, utils::to_underlying(inner))
          << subject << ": the refusal does not carry the read's " << to_string(inner);
      }
      return;
    }
    expect_uncertain_eu_range_refusal(status, Status::Uncertain, subject);
  };

  // (1) The create and the modify.
  const NodeId v1 = id(330);
  const NodeId p1 = id(331);
  const NodeId v2 = id(332);
  const NodeId p2 = id(333);
  create_analog_variable(v1);
  add_eu_range(v1, p1, 0.0, 20.0);
  create_analog_variable(v2);
  add_eu_range(v2, p2, 0.0, 20.0);
  mNamespace->answer_value_reads(
    p1, DataValue{Variant{make_range(0.0, 20.0)}, StatusCode{Status::BadWaitingForInitialData}});
  mNamespace->fail_value_reads(p2, StatusCode{Status::Uncertain});

  const auto createdOnV1 = create(v1, itemHandle, percent_deadband(10.0));
  expectRefusedWith(createdOnV1.status_code(), Status::BadWaitingForInitialData, "V1's create");
  const auto createdOnV2 = create(v2, itemHandle, percent_deadband(10.0));
  expectRefusedWith(createdOnV2.status_code(), Status::Uncertain, "V2's create");
  const auto absoluteOnV1 = create(v1, itemHandle, absolute_deadband(1.0));
  ASSERT_TRUE(absoluteOnV1.status_code().is_good()) << to_string(absoluteOnV1.status_code());
  const auto absoluteOnV2 = create(v2, itemHandle, absolute_deadband(1.0));
  ASSERT_TRUE(absoluteOnV2.status_code().is_good()) << to_string(absoluteOnV2.status_code());
  const StatusCode modifiedOnV1 = modify(absoluteOnV1.monitored_item_id(), percent_deadband(10.0));
  expectRefusedWith(modifiedOnV1, Status::BadWaitingForInitialData, "V1's modify");
  const StatusCode modifiedOnV2 = modify(absoluteOnV2.monitored_item_id(), percent_deadband(10.0));
  expectRefusedWith(modifiedOnV2, Status::Uncertain, "V2's modify");

  // (2) The re-read: the held {0, 20} gives a deadband of 2, the Bad DataValue's {0, 100} one of 10, and no
  // range none.
  const NodeId v3 = id(334);
  const NodeId p3 = id(335);
  create_analog_variable(v3);
  add_eu_range(v3, p3, 0.0, 20.0);
  const IntegerId item = monitor(v3, percent_deadband(10.0));
  ASSERT_NE(item, 0u);
  const size_t readsAtCreate = mNamespace->answered_value_reads(p3);

  mNamespace->answer_value_reads(
    p3, DataValue{Variant{make_range(0.0, 100.0)}, StatusCode{Status::BadWaitingForInitialData}});
  write_eu_range(v3, p3, 0.0, 20.0);
  settle_reads(p3, readsAtCreate + 1);
  write_and_settle(v3, 1.0);
  write_and_settle(v3, 4.0);
  write_and_settle(v3, 4.5);

  mNamespace->fail_value_reads(p3, StatusCode{Status::Uncertain});
  write_eu_range(v3, p3, 0.0, 20.0);
  settle_reads(p3, readsAtCreate + 2);
  write_and_settle(v3, 5.0);
  write_and_settle(v3, 8.0);
  write_and_settle(v3, 8.5);

  // A usable Range of Uncertain quality: the {0, 100} it holds would give a deadband of 10.
  mNamespace->answer_value_reads(
    p3, DataValue{Variant{make_range(0.0, 100.0)}, StatusCode{Status::Uncertain}});
  write_eu_range(v3, p3, 0.0, 20.0);
  settle_reads(p3, readsAtCreate + 3);
  write_and_settle(v3, 11.0);
  write_and_settle(v3, 14.0);
  write_and_settle(v3, 14.5);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that the held {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(4.5)) << "a change of 0.5 is within the deadband of 2; " << item_reports();
  EXPECT_TRUE(item_reported(5.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(8.0)) << "8.0 is above the deadband of 2 that the held {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(8.5)) << "a change of 0.5 is within the deadband of 2; " << item_reports();
  EXPECT_TRUE(item_reported(11.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(14.0)) << "14.0 is above the deadband of 2 that the held {0, 20} gives, and the "
                                      "Uncertain {0, 100} was not used; "
                                   << item_reports();
  EXPECT_FALSE(item_reported(14.5)) << "a change of 0.5 is within the deadband of 2; " << item_reports();
  const auto notRead = about_item(mLog->subscription_warnings(rangeNotReadWarning), item);
  EXPECT_EQ(notRead.size(), 3u) << "not one warning naming the item " << item
                                << " that its range could not be read again for each re-read";
  if (notRead.size() == 3u)
  {
    EXPECT_TRUE(names(notRead[0], to_string(Status::BadWaitingForInitialData)));
    EXPECT_TRUE(names(notRead[1], "ReadAnswerUncertain"))
      << "the second warning does not name the refusal of the Uncertain answer";
    EXPECT_TRUE(names(notRead[2], "ReadAnswerUncertain"))
      << "the third warning does not name the refusal of the Range of Uncertain quality";
  }

  // (3) A DataValue of Uncertain quality holding a usable Range is refused at the create, with the refusal of
  // that quality (ReadAnswerUncertain) as the cause.
  const NodeId v4 = id(336);
  const NodeId p4 = id(337);
  create_analog_variable(v4);
  add_eu_range(v4, p4, 0.0, 100.0);
  mNamespace->answer_value_reads(
    p4, DataValue{Variant{make_range(0.0, 20.0)}, StatusCode{Status::Uncertain}});
  const auto createdOnV4 = create(v4, itemHandle, percent_deadband(10.0));
  expectRefusedWith(
    createdOnV4.status_code(), Status::Uncertain, "V4's create, a Range of Uncertain quality");
}

// The deadband is computed from the EURange the namespace answered, so an Uncertain answer to the read of its
// Value is refused whether or not it holds a usable Range: the create and the modify refuse the
// PercentDeadband with the refusal of the Uncertain answer as the cause. The third Variable is the control:
// the same Range answered Good is used.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(PercentDeadband, AnUncertainEuRangeAnswerIsRefusedWithOrWithoutARange)
{
  const NodeId withRange = id(350);
  const NodeId withRangeProperty = id(351);
  const NodeId withoutRange = id(352);
  const NodeId withoutRangeProperty = id(353);
  const NodeId control = id(354);
  const NodeId controlProperty = id(355);
  create_analog_variable(withRange);
  add_eu_range(withRange, withRangeProperty, 0.0, 20.0);
  create_analog_variable(withoutRange);
  add_eu_range(withoutRange, withoutRangeProperty, 0.0, 20.0);
  create_analog_variable(control);
  add_eu_range(control, controlProperty, 0.0, 20.0);
  mNamespace->answer_value_reads(withRangeProperty,
    DataValue{Variant{make_range(0.0, 20.0)}},
    StatusCode{Status::UncertainLastUsableValue});
  mNamespace->fail_value_reads(withoutRangeProperty, StatusCode{Status::UncertainLastUsableValue});

  const auto createdWithRange = create(withRange, itemHandle, percent_deadband(10.0));
  expect_uncertain_eu_range_refusal(
    createdWithRange.status_code(), Status::UncertainLastUsableValue, "the create, an answer with a Range");
  const auto createdWithoutRange = create(withoutRange, itemHandle, percent_deadband(10.0));
  expect_uncertain_eu_range_refusal(createdWithoutRange.status_code(),
    Status::UncertainLastUsableValue,
    "the create, an answer without a Range");
  const auto createdControl = create(control, itemHandle, percent_deadband(10.0));
  EXPECT_TRUE(createdControl.status_code().is_good())
    << "the control's create: " << to_string(createdControl.status_code());

  const auto absolute = create(withRange, itemHandle, absolute_deadband(1.0));
  ASSERT_TRUE(absolute.status_code().is_good()) << to_string(absolute.status_code());
  const StatusCode modified = modify(absolute.monitored_item_id(), percent_deadband(10.0));
  expect_uncertain_eu_range_refusal(
    modified, Status::UncertainLastUsableValue, "the modify, an answer with a Range");
}

// DL-12: a Property that could not be looked up may be the EURange Property, so the EURange lookup answers
// its failure: the create's refusal carries it as its cause, and a re-read keeps the held range and logs it.
// @relation(AC-SVR-DA-022-UNRESOLVED-PROPERTY-MAKES-THE-EURANGE-LOOKUP-FAIL, scope=function)
TEST_F(PercentDeadband, AnUnresolvedPropertyMakesTheEuRangeLookupFail)
{
  const StatusCode lookupFailed{Status::BadCommunicationError,
    ErrorDetail::build("LookupFailed", "The Node could not be looked up", "PercentDeadbandTest")};

  // (1) No EURange Property, and a Property that cannot be looked up.
  const NodeId v1 = id(340);
  const NodeId unresolvedOfV1 = id(341);
  create_analog_variable(v1);
  add_other_property(v1, unresolvedOfV1);
  mNamespace->fail_lookups(unresolvedOfV1, lookupFailed);
  const auto created = create(v1, itemHandle, percent_deadband(10.0));
  if (const auto* detail = expect_eu_range_refusal(created.status_code(), "V1's create"))
  {
    EXPECT_EQ(detail->innerStatus, utils::to_underlying(Status::BadCommunicationError))
      << "the refusal does not carry the lookup's Bad_CommunicationError";
    EXPECT_TRUE(detail->cause != nullptr && detail->cause->code == "LookupFailed")
      << "the refusal does not carry the lookup's ErrorDetail as its cause";
  }

  // (2) The re-read after the EURange Property is deleted, with a Property that cannot be looked up.
  const NodeId v2 = id(342);
  const NodeId propertyOfV2 = id(343);
  const NodeId unresolvedOfV2 = id(344);
  create_analog_variable(v2);
  add_eu_range(v2, propertyOfV2, 0.0, 20.0);
  // Added before the item: its first Value marks the Variable's items, and a re-read it started would race
  // the failing lookup set below.
  add_other_property(v2, unresolvedOfV2);
  const IntegerId item = monitor(v2, percent_deadband(10.0));
  ASSERT_NE(item, 0u);
  mNamespace->fail_lookups(unresolvedOfV2, lookupFailed);
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(propertyOfV2, false).is_good());
  mNodes.erase(propertyOfV2);
  write_value(unresolvedOfV2, 0.0);
  wait_until([&] { return !about_item(mLog->subscription_warnings(rangeNotReadWarning), item).empty(); });
  flush_subscription();
  write_and_settle(v2, 1.0);
  write_and_settle(v2, 4.0);
  write_and_settle(v2, 4.5);

  EXPECT_TRUE(item_reported(1.0, /*semanticsChanged=*/true)) << item_reports();
  EXPECT_TRUE(item_reported(4.0)) << "4.0 is above the deadband of 2 that the held {0, 20} gives; "
                                  << item_reports();
  EXPECT_FALSE(item_reported(4.5)) << "the item keeps {0, 20}: a change of 0.5 is within its deadband of 2; "
                                   << item_reports();
  const auto notRead = about_item(mLog->subscription_warnings(rangeNotReadWarning), item);
  ASSERT_EQ(notRead.size(), 1u) << "no warning naming the item " << item
                                << " that its range could not be read again";
  EXPECT_TRUE(names(notRead[0], to_string(Status::BadCommunicationError)));
}
