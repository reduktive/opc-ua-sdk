// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The in-memory namespace and an application's value source: the code a source answers with reaches the
// write's answer and the monitored items' notifications, and an Uncertain answer the namespace would act on
// is refused (COMP-SVR-STATUS-ROUTING-01, -02, -05).

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_log_sink.h"
#include "ua_log_entry.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_to_string.h"
#include "ua_value_source.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// The summary of the ErrorDetail with which the SDK refuses an Uncertain answer it would act on.
constexpr std::string_view uncertainSummary{
  "The SDK does not act on an answer the namespace is uncertain of"};

/// An application source that answers every read of item i with the i-th of the read answers the test gives
/// it (the last one past the end), and every write of item i with the i-th of the write answers (Good past
/// the end), counting the writes it is given.
class AnsweringSource final : public ValueSource
{
public:
  AnsweringSource(std::vector<DataValueResult> reads, std::vector<WriteResult> writes = {})
    : mReads(std::move(reads)), mWrites(std::move(writes))
  {}

  void read_async(const ReadContext&, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answered;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answered.items.push_back(mReads.at(std::min(i, mReads.size() - 1)));
    }
    complete(std::move(answered));
  }

  void write_async(const WriteContext&, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    mWritten.fetch_add(items.size());
    BatchResult<WriteResult> answered;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      answered.items.push_back(i < mWrites.size() ? mWrites[i] : WriteResult{Written{}});
    }
    complete(std::move(answered));
  }

  /// How many items it was given to write.
  std::size_t written() const
  {
    return mWritten.load();
  }

private:
  std::vector<DataValueResult> mReads;
  std::vector<WriteResult> mWrites;
  std::atomic<std::size_t> mWritten{0};
};

/// A sink that keeps every sample it is pushed.
class CollectingSink final : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
      {
        mSamples.push_back(std::move(sample));
      }
    }
    mChanged.notify_all();
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  /// The first sample of @p item, waiting at most 5 s for it.
  std::optional<DataValue> first_of(IntegerId item)
  {
    std::unique_lock lock{mMutex};
    std::optional<DataValue> found;
    mChanged.wait_for(lock,
      5s,
      [&]
      {
        for (const auto& [id, value] : mSamples)
        {
          if (id == item)
          {
            found = value;
            return true;
          }
        }
        return false;
      });
    return found;
  }

private:
  std::mutex mMutex;
  std::condition_variable mChanged;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
};

/// A sink that keeps each Warning it is given: its message and its "status" field.
class WarningRecorder final : public LogSink
{
public:
  struct Warning
  {
    std::string message;
    std::string status;
  };

  void log(const LogEntry& entry) override
  {
    if (entry.level != LogLevel::Warning)
    {
      return;
    }
    Warning warning{entry.message, {}};
    for (const auto& field : entry.fields)
    {
      if (field.key == "status")
      {
        if (const auto* text = std::get_if<std::string_view>(&field.value))
        {
          warning.status = std::string{*text};
        }
      }
    }
    const std::lock_guard lock{mMutex};
    mWarnings.push_back(std::move(warning));
  }

  std::vector<Warning> warnings() const
  {
    const std::lock_guard lock{mMutex};
    return mWarnings;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Warning> mWarnings;
};

class DefaultNamespaceStatusRouting : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:default-status-routing", mPool.get_executor()));
    mAddressSpace->set_logger(Logger{
      mWarnings, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "default-status-routing"});
    mNamespace = default_ns::Namespace::create("urn:test:default-status-routing:own", mPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// An Int32 Variable @p id, its Value 0 in its default source.
  VariableAccessor int32_variable(const NodeId& id)
  {
    auto created = mAddressSpace->create_node_sync(id, NodeClass::Variable);
    auto variable = created.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value()) << to_string(id);
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(DataValue{Variant{int32_t{0}}});
    return *variable;
  }

  /// The in-memory Node of @p id.
  std::shared_ptr<default_ns::VariableNode> in_memory(const NodeId& id)
  {
    auto found = mNamespace->find_node(id, std::nullopt);
    if (!found.has_value() || !found->is_good())
    {
      ADD_FAILURE() << "the namespace does not hold " << to_string(id);
      return nullptr;
    }
    return std::dynamic_pointer_cast<default_ns::VariableNode>(found->value());
  }

  /// Gives the Value of @p id to @p source.
  void attach(const NodeId& id, const std::shared_ptr<ValueSource>& source)
  {
    auto node = in_memory(id);
    ASSERT_NE(node, nullptr);
    const auto attached = node->set_value_source(source);
    ASSERT_TRUE(attached.is_good()) << to_string(attached.status_code());
  }

  /// Writes @p attributeId of @p node, waiting at most 5 s for the answer.
  static VoidResult write_attribute(NodeAccessor& node, AttributeId attributeId, Variant value)
  {
    auto answered = std::make_shared<std::promise<VoidResult>>();
    auto future = answered->get_future();
    node.write_attribute_async(attributeId,
      std::move(value),
      [answered](VoidResult result) { answered->set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the write did not answer";
      return VoidResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  }

  /// Writes the Int32 @p value to each Variable of @p ids through the namespace's write_async, as the
  /// server's own write, waiting at most 5 s for the answer.
  BatchResult<VoidResult> write_values(const std::vector<NodeId>& ids, int32_t value)
  {
    std::vector<std::shared_ptr<default_ns::VariableNode>> nodes;
    std::vector<WriteValue> writes;
    for (const NodeId& id : ids)
    {
      nodes.push_back(in_memory(id));
      WriteValue write;
      write.node_id() = id;
      write.attribute_id() = utils::to_underlying(AttributeId::Value);
      write.value() = DataValue{Variant{value}};
      writes.push_back(std::move(write));
    }
    std::vector<ValueWriteItem> items;
    for (std::size_t i = 0; i < ids.size(); ++i)
    {
      if (nodes[i] == nullptr)
      {
        return BatchResult<VoidResult>{};
      }
      items.push_back(ValueWriteItem{*nodes[i], writes[i]});
    }
    auto answered = std::make_shared<std::promise<BatchResult<VoidResult>>>();
    auto future = answered->get_future();
    mNamespace->write_async(RequestInfo{},
      nullptr,
      items,
      [answered](BatchResult<VoidResult> written, std::vector<VersionedNode>)
      { answered->set_value(std::move(written)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the write did not answer";
      return BatchResult<VoidResult>{};
    }
    return future.get();
  }

  /// Monitors the Value of each of @p ids at @p samplingInterval, item i + 1 for @p ids[i], into @p sink.
  void monitor(
    const std::vector<NodeId>& ids, Duration samplingInterval, const std::shared_ptr<SampleSink>& sink)
  {
    std::vector<MonitoringCreateItem> items;
    for (std::size_t i = 0; i < ids.size(); ++i)
    {
      MonitoringCreateItem item;
      item.nodeId = ids[i];
      item.attributeId = AttributeId::Value;
      item.monitoredItemId = IntegerId{static_cast<uint32_t>(i + 1)};
      item.samplingInterval = samplingInterval;
      item.queueSize = 1;
      item.sink = sink;
      items.push_back(std::move(item));
    }
    auto answered = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>();
    auto future = answered->get_future();
    mNamespace->create_monitoring_async(RequestInfo{},
      nullptr,
      items,
      [answered](BatchResult<MonitoringCreateItemResult> created)
      { answered->set_value(std::move(created)); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "create_monitoring_async did not answer";
    const auto created = future.get();
    ASSERT_EQ(created.items.size(), ids.size());
    for (const auto& item : created.items)
    {
      ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
    }
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<WarningRecorder> mWarnings = std::make_shared<WarningRecorder>();
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mIndex{0};
};

/// The status a notification's DataValue carries: Good when it has none.
StatusCode notified_status(const DataValue& value)
{
  return value.status().value_or(StatusCode{Status::Good});
}

}  // namespace

// The in-memory namespace computes a Node's next NodeVersion from the Value of its NodeVersion Property. When
// an application source holds that Value and answers its read Uncertain, with or without a Value, the
// namespace does not act on the answer: the change that would advance the version answers Uncertain with the
// refusal's ErrorDetail (ReadAnswerUncertain, its cause the source's code), and the source is given no
// version. A Good read, which advances the version, is the control.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(DefaultNamespaceStatusRouting, AnUncertainNodeVersionReadIsNotActedOn)
{
  const StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue};

  struct Arm
  {
    const char* name;
    DataValueResult answer;
    bool refused;
  };

  const std::vector<Arm> arms{{"Uncertain without a Value", DataValueResult{uncertain}, true},
    {"Uncertain holding a Value", DataValueResult{DataValue{Variant{String{"5"}}}, uncertain}, true},
    {"Good", DataValueResult{DataValue{Variant{String{"5"}}}}, false}};

  for (std::size_t a = 0; a < arms.size(); ++a)
  {
    SCOPED_TRACE(arms[a].name);
    const NodeId variableId{mIndex, static_cast<uint32_t>(100 + (2 * a))};
    const NodeId versionId{mIndex, static_cast<uint32_t>(101 + (2 * a))};
    auto created = mAddressSpace->create_node_sync(variableId, NodeClass::Variable);
    auto variable = created.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    auto versionNode = mAddressSpace->create_node_sync(versionId, NodeClass::Variable);
    versionNode.set_browse_name(QualifiedName{0, "NodeVersion"});
    created.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
    const auto source = std::make_shared<AnsweringSource>(std::vector<DataValueResult>{arms[a].answer});
    attach(versionId, source);

    const VoidResult written =
      write_attribute(*variable, AttributeId::DataType, Variant{NodeId{DataTypeId::Double}});

    EXPECT_EQ(variable->get_data_type(), NodeId{DataTypeId::Double}) << "the DataType was not stored";
    if (!arms[a].refused)
    {
      EXPECT_TRUE(written.is_good()) << to_string(written.status_code());
      EXPECT_EQ(source->written(), 1U) << "the control did not advance the NodeVersion";
      continue;
    }
    EXPECT_EQ(written.status_code().as_uint32(), StatusCode{Status::Uncertain}.as_uint32())
      << to_string(written.status_code());
    ASSERT_NE(written.shared_detail(), nullptr);
    EXPECT_EQ(written.shared_detail()->code, "ReadAnswerUncertain");
    EXPECT_EQ(written.shared_detail()->summary, uncertainSummary);
    EXPECT_EQ(written.shared_detail()->innerStatus, uncertain.value());
    EXPECT_EQ(source->written(), 0U) << "the NodeVersion was advanced from an Uncertain read";
  }
}

// A Value write an application source answers Uncertain is answered with that code, whether or not the source
// held a Written outcome with it; a Good subcode is kept as the control.
// @relation(AC-COMP-SVR-STATUS-ROUTING-05-AN-UNCERTAIN-ANSWER-WITHOUT-A-VALUE-REACHES-THE-CALLER, scope=function)
TEST_F(DefaultNamespaceStatusRouting, AnUncertainWriteAnswerOfAnApplicationSourceReachesTheCaller)
{
  const StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue};
  const StatusCode overridden{Status::GoodLocalOverride};
  const std::vector<NodeId> ids{NodeId{mIndex, 200U}, NodeId{mIndex, 201U}, NodeId{mIndex, 202U}};
  const auto source = std::make_shared<AnsweringSource>(
    std::vector<DataValueResult>{DataValueResult{DataValue{Variant{int32_t{0}}}}},
    std::vector<ValueSource::WriteResult>{ValueSource::WriteResult{uncertain},
      ValueSource::WriteResult{ValueSource::Written{}, uncertain},
      ValueSource::WriteResult{ValueSource::Written{}, overridden}});
  for (const NodeId& id : ids)
  {
    (void)int32_variable(id);
    attach(id, source);
  }

  const auto answered = write_values(ids, 7);

  ASSERT_TRUE(answered.batchStatus.is_good()) << to_string(answered.batchStatus.status_code());
  ASSERT_EQ(answered.items.size(), ids.size());
  EXPECT_EQ(answered.items[0].status_code(), uncertain)
    << "without a Written outcome: " << to_string(answered.items[0].status_code());
  EXPECT_EQ(answered.items[1].status_code(), uncertain)
    << "with a Written outcome: " << to_string(answered.items[1].status_code());
  EXPECT_EQ(answered.items[2].status_code(), overridden) << to_string(answered.items[2].status_code());
}

// A sampled notification's DataValue carries the code combined_status gives for the code of the source's
// answer and the Value's own status: a Good subcode or an Uncertain code on the answer reaches it, a Value's
// own worse status is kept, and an answer without a code of its own leaves the Value's status.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-NOTIFICATIONS-CARRY-THE-COMBINED-CODE, scope=function)
TEST_F(DefaultNamespaceStatusRouting, ASampledNotificationCarriesTheCombinedCode)
{
  DataValue badValue{Variant{int32_t{42}}};
  badValue.status() = StatusCode{Status::BadOutOfRange};
  DataValue clampedValue{Variant{int32_t{42}}};
  clampedValue.status() = StatusCode{Status::GoodClamped};

  struct Arm
  {
    const char* name;
    DataValueResult answer;
    StatusCode notified;
  };

  const std::vector<Arm> arms{
    {"Good subcode on the answer",
      DataValueResult{DataValue{Variant{int32_t{42}}}, StatusCode{Status::GoodLocalOverride}},
      StatusCode{Status::GoodLocalOverride}},
    {"Uncertain answer holding a Value",
      DataValueResult{DataValue{Variant{int32_t{42}}}, StatusCode{Status::UncertainLastUsableValue}},
      StatusCode{Status::UncertainLastUsableValue}},
    {"Bad Value under a Good subcode",
      DataValueResult{badValue, StatusCode{Status::GoodLocalOverride}},
      StatusCode{Status::BadOutOfRange}},
    {"Good subcode of the Value under plain Good",
      DataValueResult{clampedValue},
      StatusCode{Status::GoodClamped}}};
  std::vector<NodeId> ids;
  for (std::size_t a = 0; a < arms.size(); ++a)
  {
    ids.emplace_back(mIndex, static_cast<uint32_t>(300 + a));
    (void)int32_variable(ids.back());
    attach(ids.back(), std::make_shared<AnsweringSource>(std::vector<DataValueResult>{arms[a].answer}));
  }
  const auto sink = std::make_shared<CollectingSink>();

  monitor(ids, Duration{50}, sink);

  for (std::size_t a = 0; a < arms.size(); ++a)
  {
    SCOPED_TRACE(arms[a].name);
    const auto notified = sink->first_of(IntegerId{static_cast<uint32_t>(a + 1)});
    ASSERT_TRUE(notified.has_value()) << "no notification";
    EXPECT_EQ(notified_status(*notified), arms[a].notified) << to_string(notified_status(*notified));
    EXPECT_EQ(notified->value(), Variant{int32_t{42}});
  }
}

// A Value an application source holds is read back after a write and reported to the Variable's Reported
// registrations; that notification carries the code of the read's answer as a sampled one does.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-NOTIFICATIONS-CARRY-THE-COMBINED-CODE, scope=function)
TEST_F(DefaultNamespaceStatusRouting, AReadBackNotificationCarriesTheCombinedCode)
{
  const NodeId id{mIndex, 400U};
  auto variable = int32_variable(id);
  // A MinimumSamplingInterval of 0 makes a registration at 0 a Reported one.
  variable.set_minimum_sampling_interval(Duration{0});
  attach(id,
    std::make_shared<AnsweringSource>(std::vector<DataValueResult>{
      DataValueResult{DataValue{Variant{int32_t{7}}}, StatusCode{Status::GoodLocalOverride}}}));
  const auto sink = std::make_shared<CollectingSink>();
  monitor({id}, Duration{0}, sink);

  const auto answered = write_values({id}, 7);

  ASSERT_EQ(answered.items.size(), 1U);
  ASSERT_TRUE(answered.items[0].is_good()) << to_string(answered.items[0].status_code());
  const auto notified = sink->first_of(IntegerId{1});
  ASSERT_TRUE(notified.has_value()) << "the written Value was not reported";
  EXPECT_EQ(notified_status(*notified), StatusCode{Status::GoodLocalOverride})
    << to_string(notified_status(*notified));
  EXPECT_EQ(notified->value(), Variant{int32_t{7}});

  const NodeId uncertainId{mIndex, 401U};
  auto uncertainVariable = int32_variable(uncertainId);
  uncertainVariable.set_minimum_sampling_interval(Duration{0});
  attach(uncertainId,
    std::make_shared<AnsweringSource>(std::vector<DataValueResult>{
      DataValueResult{DataValue{Variant{int32_t{8}}}, StatusCode{Status::UncertainLastUsableValue}}}));
  const auto uncertainSink = std::make_shared<CollectingSink>();
  monitor({uncertainId}, Duration{0}, uncertainSink);

  const auto uncertainAnswered = write_values({uncertainId}, 8);

  ASSERT_EQ(uncertainAnswered.items.size(), 1U);
  ASSERT_TRUE(uncertainAnswered.items[0].is_good()) << to_string(uncertainAnswered.items[0].status_code());
  const auto uncertainNotified = uncertainSink->first_of(IntegerId{1});
  ASSERT_TRUE(uncertainNotified.has_value());
  EXPECT_EQ(notified_status(*uncertainNotified), StatusCode{Status::UncertainLastUsableValue});
  EXPECT_EQ(uncertainNotified->value(), Variant{int32_t{8}});
}

// When the read-back's answer and the Value it holds both carry a SubCode, the notification carries the
// Value's own status and the source's code on the read is logged at Warning, as a sampled notification's is.
// An answer whose code is reported logs nothing.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-NOTIFICATIONS-CARRY-THE-COMBINED-CODE, scope=function)
TEST_F(DefaultNamespaceStatusRouting, AReadBackNotificationLogsTheSourcesCodeItDoesNotCarry)
{
  DataValue clampedValue{Variant{int32_t{7}}};
  clampedValue.status() = StatusCode{Status::GoodClamped};
  const NodeId logged{mIndex, 410U};
  const NodeId carried{mIndex, 411U};
  for (const auto& [id, answer] :
    {std::pair{logged, DataValueResult{clampedValue, StatusCode{Status::GoodLocalOverride}}},
      std::pair{
        carried, DataValueResult{DataValue{Variant{int32_t{7}}}, StatusCode{Status::GoodLocalOverride}}}})
  {
    auto variable = int32_variable(id);
    // A MinimumSamplingInterval of 0 makes a registration at 0 a Reported one.
    variable.set_minimum_sampling_interval(Duration{0});
    attach(id, std::make_shared<AnsweringSource>(std::vector<DataValueResult>{answer}));
  }
  const auto sink = std::make_shared<CollectingSink>();
  monitor({logged, carried}, Duration{0}, sink);

  const auto answered = write_values({logged, carried}, 7);

  ASSERT_EQ(answered.items.size(), 2U);
  const auto notified = sink->first_of(IntegerId{1});
  ASSERT_TRUE(notified.has_value()) << "the written Value was not reported";
  EXPECT_EQ(notified_status(*notified), StatusCode{Status::GoodClamped})
    << to_string(notified_status(*notified));
  const auto control = sink->first_of(IntegerId{2});
  ASSERT_TRUE(control.has_value()) << "the written Value was not reported";
  EXPECT_EQ(notified_status(*control), StatusCode{Status::GoodLocalOverride})
    << to_string(notified_status(*control));

  const auto warnings = mWarnings->warnings();
  const std::string sourceCode = to_string(StatusCode{Status::GoodLocalOverride});
  const auto count = std::count_if(warnings.begin(),
    warnings.end(),
    [&](const WarningRecorder::Warning& warning)
    { return warning.status == sourceCode && warning.message.find("read back") != std::string::npos; });
  EXPECT_EQ(count, 1) << "the source's code on the read-back of " << to_string(logged)
                      << " was not logged once";
}
