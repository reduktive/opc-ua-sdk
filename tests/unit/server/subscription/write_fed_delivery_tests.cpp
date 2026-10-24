// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Which Value items of the in-memory namespace are write-fed ("Reported"), and what a write-fed item is told
// after a write (DL-124 (5), DL-115 (3), NR-49): an application source owns its Variable's Value, so an
// absent MinimumSamplingInterval does not make its items write-fed, and a committed write to it is reported
// with the Value the source then holds, read back, while the default source's write is reported as written.

#include <gtest/gtest.h>

#include "monitoring_helper_fixture.h"

#include "ua_date_time.h"
#include "ua_request_info.h"
#include "ua_value_source.h"

#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;
using namespace ua::test::monitoring_helper;

namespace
{

/// A sink that records the samples it receives and answers the caller the test sets, as a Subscription's
/// sink answers its Session's current caller (NR-49).
class CallerSink final : public SampleSink
{
public:
  explicit CallerSink(std::shared_ptr<const CallerInfo> caller) : mCaller(std::move(caller))
  {}

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
        mValues.push_back(std::move(sample.second.value()));
    }
    mCv.notify_all();
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  std::shared_ptr<const CallerInfo> caller() const override
  {
    const std::lock_guard lock{mMutex};
    return mCaller;
  }

  void set_caller(std::shared_ptr<const CallerInfo> caller)
  {
    const std::lock_guard lock{mMutex};
    mCaller = std::move(caller);
  }

  /// Waits until a sample carrying the String @p text arrives, or @p timeout passes.
  bool wait_for_text(const std::string& text, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock,
      timeout,
      [&]
      {
        for (const auto& value : mValues)
        {
          if (value.is_string() && std::string{std::string_view{value.as<String>()}} == text)
            return true;
        }
        return false;
      });
  }

  /// Waits until @p count samples arrived, or @p timeout passes.
  bool wait_for_samples(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mValues.size() >= count; });
  }

  std::vector<Variant> values() const
  {
    const std::lock_guard lock{mMutex};
    return mValues;
  }

  std::string text() const
  {
    const std::lock_guard lock{mMutex};
    std::string text = "the sink received:";
    for (const auto& value : mValues)
      text += " " + to_string(value) + ";";
    return text;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::shared_ptr<const CallerInfo> mCaller;
  std::vector<Variant> mValues;
};

/// A caller whose user is @p user.
std::shared_ptr<const CallerInfo> caller_named(std::string_view user)
{
  auto caller = std::make_shared<CallerInfo>();
  caller->clientUserId = String{user};
  return caller;
}

/// A source whose Value differs per caller: it answers the caller's user, or "server" for no caller.
std::shared_ptr<ValueSource> per_caller_source()
{
  return make_value_source(
    [](const ValueSource::ReadContext& context,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        complete)
    {
      const String user = context.caller != nullptr ? context.caller->clientUserId : String{"server"};
      complete(DataValueResult{DataValue{Variant{user}}});
    });
}

/// A source that holds one Int32 per Variable, starting at 50, and keeps a written value clamped to
/// [0, 100]; it counts its reads.
class ClampingSource final : public ValueSource
{
public:
  void read_async(const ReadContext&, std::span<const ReadItem> items,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    {
      const std::lock_guard lock{mMutex};
      ++mReads;
      for (const auto& item : items)
      {
        const auto held = mHeld.find(item.value.node_id());
        answer.items.emplace_back(DataValue{Variant{held == mHeld.end() ? int32_t{50} : held->second}});
      }
    }
    complete(std::move(answer));
  }

  void write_async(const WriteContext&, std::span<const WriteItem> items,
    std::function<void(BatchResult<WriteResult>)> complete) override
  {
    BatchResult<WriteResult> answer;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        const int32_t written = item.value.value().value().as<int32_t>();
        mHeld[item.value.node_id()] = std::clamp(written, int32_t{0}, int32_t{100});
        answer.items.emplace_back(Written{});
      }
    }
    complete(std::move(answer));
  }

  size_t reads() const
  {
    const std::lock_guard lock{mMutex};
    return mReads;
  }

private:
  mutable std::mutex mMutex;
  std::map<NodeId, int32_t> mHeld;
  size_t mReads{0};
};

class WriteFedDelivery : public MonitoringHelperTest
{
protected:
  /// Creates one item on the Value of @p nodeId through the namespace's `create_monitoring_async`, which
  /// decides the item's delivery.
  static MonitoringCreateItemResult monitor_value(
    ExposedNamespace& ns, const NodeId& nodeId, IntegerId monitoredItemId, std::shared_ptr<SampleSink> sink)
  {
    std::vector<MonitoringCreateItem> items{{.nodeId = nodeId,
      .attributeId = AttributeId::Value,
      .monitoredItemId = monitoredItemId,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = std::move(sink)}};
    auto promise = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>();
    auto future = promise->get_future();
    ns.create_monitoring_async(RequestInfo{},
      nullptr,
      items,
      [promise](BatchResult<MonitoringCreateItemResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return MonitoringCreateItemResult{StatusCode{Status::BadTimeout}};
    }
    auto results = future.get();
    if (results.items.size() != 1u)
    {
      ADD_FAILURE() << "the create answered " << results.items.size() << " results for one item";
      return MonitoringCreateItemResult{StatusCode{Status::BadInternalError}};
    }
    return std::move(results.items.front());
  }

  /// A Variable of @p ns with no Value written, whose MinimumSamplingInterval is @p minimumSamplingInterval
  /// (absent when nullopt) and whose Value @p source owns.
  static std::shared_ptr<default_ns::VariableNode> sourced_variable(ExposedNamespace& ns, uint32_t identifier,
    std::optional<Duration> minimumSamplingInterval, std::shared_ptr<ValueSource> source)
  {
    auto node = ns.create_node<default_ns::VariableNode>(NodeId{ns.context_copy().index(), identifier});
    if (minimumSamplingInterval)
    {
      auto completion = std::make_shared<std::promise<VoidResult>>();
      auto written = completion->get_future();
      node->write_attribute_async(AttributeId::MinimumSamplingInterval,
        Variant{*minimumSamplingInterval},
        [completion](VoidResult result) { completion->set_value(std::move(result)); });
      EXPECT_EQ(written.wait_for(2s), std::future_status::ready);
      EXPECT_TRUE(written.get().is_good());
    }
    EXPECT_TRUE(node->set_value_source(std::move(source)).is_good());
    return node;
  }

  /// Writes @p values, one item each, through the namespace's `write_async` in one call; returns each item's
  /// answer.
  static std::vector<VoidResult> write_values(ExposedNamespace& ns,
    const std::vector<std::shared_ptr<default_ns::VariableNode>>& nodes, const std::vector<DataValue>& values)
  {
    std::vector<WriteValue> writes(nodes.size());
    std::vector<ValueWriteItem> items;
    for (size_t index = 0; index < nodes.size(); ++index)
    {
      writes[index].node_id() = nodes[index]->node_id();
      writes[index].attribute_id() = utils::to_underlying(AttributeId::Value);
      writes[index].value() = values[index];
    }
    for (size_t index = 0; index < nodes.size(); ++index)
      items.push_back(ValueWriteItem{*nodes[index], writes[index]});
    auto promise = std::make_shared<std::promise<BatchResult<VoidResult>>>();
    auto future = promise->get_future();
    ns.write_async(RequestInfo{},
      nullptr,
      items,
      [promise](BatchResult<VoidResult> written, std::vector<VersionedNode>)
      { promise->set_value(std::move(written)); });
    if (future.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the write did not answer";
      return {};
    }
    auto written = future.get();
    EXPECT_TRUE(written.batchStatus.is_good()) << to_string(written.batchStatus.status_code());
    return std::vector<VoidResult>(written.items.begin(), written.items.end());
  }

  static void expect_all_good(const std::vector<VoidResult>& answers, size_t count)
  {
    ASSERT_EQ(answers.size(), count);
    for (const auto& answer : answers)
      EXPECT_TRUE(answer.is_good()) << to_string(answer.status_code());
  }

  /// The Int32 values of the samples @p recorded received, in order.
  static std::vector<int32_t> int32_samples(const RecordingSink& recorded)
  {
    std::vector<int32_t> values;
    for (const auto& event : recorded.events())
    {
      if (!event.notice && event.value.value().is_int32())
        values.push_back(event.value.value().as<int32_t>());
    }
    return values;
  }
};

}  // namespace

// DL-124 (5), NR-49: a Variable created with no MinimumSamplingInterval whose Value an application source
// owns, monitored at interval 0, is sampled, each read made for the sink's current caller: once the caller
// changes, the item receives the new caller's Value. Write-fed, the item would keep the first caller's Value,
// since nothing is written. Control: the first caller's Value arrives either way.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-AN-APPLICATION-SOURCE-WITHOUT-AN-INTERVAL-IS-SAMPLED, scope=function)
TEST_F(WriteFedDelivery, AnApplicationSourceWithNoMinimumSamplingIntervalIsSampledForTheCurrentCaller)
{
  auto ns = registered_namespace("urn:test:write-fed:per-caller");
  auto node = sourced_variable(*ns, 7200, std::nullopt, per_caller_source());
  ASSERT_FALSE(node->attributes().minimum_sampling_interval().has_value());
  auto item = std::make_shared<CallerSink>(caller_named("alice"));
  const auto created = monitor_value(*ns, node->node_id(), 1, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_TRUE(item->wait_for_text("alice", 3s)) << item->text();

  item->set_caller(caller_named("bob"));
  EXPECT_TRUE(item->wait_for_text("bob", 3s)) << item->text();
}

// DL-124 (5): an explicit MinimumSamplingInterval of 0 is the source's claim that it reports every change
// through notify_value_changed, so its item at interval 0 stays write-fed: a pushed Value the source would
// never answer to a read reaches it. A write-fed item is given no initial sample by the namespace (the
// Subscription reads the initial Value). Control for the test above; holds on the unchanged code.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-AN-APPLICATION-SOURCE-WITH-AN-INTERVAL-OF-ZERO-IS-WRITE-FED, scope=function)
TEST_F(WriteFedDelivery, AnApplicationSourceWithAnExplicitZeroIsWriteFed)
{
  auto ns = registered_namespace("urn:test:write-fed:explicit-zero");
  auto constant =
    make_value_source([](const ValueSource::ReadContext&,
                        const Node&,
                        const ReadValueId&,
                        std::function<void(DataValueResult)>
                          complete) { complete(DataValueResult{DataValue{Variant{int32_t{1}}}}); });
  auto node = sourced_variable(*ns, 7201, Duration{0}, constant);
  auto item = sink();
  const auto created = monitor_value(*ns, node->node_id(), 1, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  EXPECT_DOUBLE_EQ(created.value().revisedSamplingInterval, 0);

  node->notify_value_changed(DataValue{Variant{int32_t{2}}});
  ASSERT_TRUE(item->wait_for_samples(1, 3s)) << item->text();
  EXPECT_EQ(int32_samples(*item), (std::vector<int32_t>{2})) << item->text();
}

// DL-115 (3): a write-fed item on a Variable whose application source clamps what it is given is told the
// Value the source then holds, read back, not the Value written: through the namespace's one-item write
// (150 is held as 100) and through a write made on the Node itself (-20 is held as 0). The unchanged code
// reports 150 and -20.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-WRITE-TO-AN-APPLICATION-SOURCE-IS-REPORTED-AS-THE-SOURCE-HOLDS-IT, scope=function)
TEST_F(WriteFedDelivery, AClampedOneItemWriteIsReportedAsTheSourceHoldsIt)
{
  auto ns = registered_namespace("urn:test:write-fed:clamped-one");
  auto source = std::make_shared<ClampingSource>();
  auto node = sourced_variable(*ns, 7202, Duration{0}, source);
  auto item = sink();
  const auto created = monitor_value(*ns, node->node_id(), 1, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  expect_all_good(write_values(*ns, {node}, {DataValue{Variant{int32_t{150}}}}), 1);
  ASSERT_TRUE(item->wait_for_samples(1, 3s)) << item->text();

  WriteValue write;
  write.node_id() = node->node_id();
  write.attribute_id() = utils::to_underlying(AttributeId::Value);
  write.value() = DataValue{Variant{int32_t{-20}}};
  auto completion = std::make_shared<std::promise<VoidResult>>();
  auto answered = completion->get_future();
  node->write_value_async(write, nullptr, [completion](VoidResult result) { completion->set_value(result); });
  ASSERT_EQ(answered.wait_for(2s), std::future_status::ready);
  ASSERT_TRUE(answered.get().is_good());

  ASSERT_TRUE(item->wait_for_samples(2, 3s)) << item->text();
  EXPECT_EQ(int32_samples(*item), (std::vector<int32_t>{100, 0})) << item->text();
}

// DL-115 (3) through a multi-item write: two Variables of one clamping source written in one call (the
// namespace's one-source path), then again together with a Variable on its default source (the grouped
// path). Each write-fed item is told the clamped Value. The unchanged code reports the Values written.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-WRITE-TO-AN-APPLICATION-SOURCE-IS-REPORTED-AS-THE-SOURCE-HOLDS-IT, scope=function)
TEST_F(WriteFedDelivery, AClampedMultiItemWriteIsReportedAsTheSourceHoldsIt)
{
  auto ns = registered_namespace("urn:test:write-fed:clamped-many");
  auto source = std::make_shared<ClampingSource>();
  auto first = sourced_variable(*ns, 7203, Duration{0}, source);
  auto second = sourced_variable(*ns, 7204, Duration{0}, source);
  auto plain = variable(*ns, 7205, Variant{int32_t{0}});
  auto firstItem = sink();
  auto secondItem = sink();
  ASSERT_TRUE(monitor_value(*ns, first->node_id(), 1, firstItem).is_good());
  ASSERT_TRUE(monitor_value(*ns, second->node_id(), 2, secondItem).is_good());

  expect_all_good(
    write_values(*ns, {first, second}, {DataValue{Variant{int32_t{150}}}, DataValue{Variant{int32_t{-20}}}}),
    2);
  ASSERT_TRUE(firstItem->wait_for_samples(1, 3s)) << firstItem->text();
  ASSERT_TRUE(secondItem->wait_for_samples(1, 3s)) << secondItem->text();

  expect_all_good(
    write_values(*ns,
      {first, second, plain},
      {DataValue{Variant{int32_t{-5}}}, DataValue{Variant{int32_t{500}}}, DataValue{Variant{int32_t{7}}}}),
    3);
  ASSERT_TRUE(firstItem->wait_for_samples(2, 3s)) << firstItem->text();
  ASSERT_TRUE(secondItem->wait_for_samples(2, 3s)) << secondItem->text();
  EXPECT_EQ(int32_samples(*firstItem), (std::vector<int32_t>{100, 0})) << firstItem->text();
  EXPECT_EQ(int32_samples(*secondItem), (std::vector<int32_t>{0, 100})) << secondItem->text();
}

// DL-115 (3): the default source keeps exactly what it is given, so its write is reported from the Value
// written, with no read-back: the written ServerTimestamp reaches the item, where a read with maxAge 0 would
// answer the time of the read. Control; holds on the unchanged code.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-DEFAULT-SOURCE-WRITE-IS-REPORTED-AS-WRITTEN, scope=function)
TEST_F(WriteFedDelivery, ADefaultSourceWriteIsReportedAsWrittenWithNoReadBack)
{
  auto ns = registered_namespace("urn:test:write-fed:default-source");
  auto node = variable(*ns, 7206, Variant{int32_t{0}});
  auto item = sink();
  const auto created = monitor_value(*ns, node->node_id(), 1, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  EXPECT_DOUBLE_EQ(created.value().revisedSamplingInterval, 0);

  const DateTime stamp{2001, 2, 3, 4, 5, 6.0};
  DataValue written{Variant{int32_t{7}}};
  written.server_timestamp() = stamp;
  expect_all_good(write_values(*ns, {node}, {written}), 1);
  ASSERT_TRUE(item->wait_for_samples(1, 3s)) << item->text();

  const auto events = item->events();
  ASSERT_GE(events.size(), 1u);
  const DataValue& reported = events[0].value;
  ASSERT_TRUE(reported.value().is_int32()) << item->text();
  EXPECT_EQ(reported.value().as<int32_t>(), 7);
  ASSERT_TRUE(reported.server_timestamp().has_value());
  EXPECT_TRUE(*reported.server_timestamp() == stamp) << to_string(*reported.server_timestamp());
}

// DL-115 (3): the read-back is made only while the Variable has a write-fed item; a write to an application
// source with none reads nothing. Control; holds on the unchanged code.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-NO-READ-BACK-WITHOUT-A-REPORTED-ITEM, scope=function)
TEST_F(WriteFedDelivery, AWriteWithNoWriteFedItemIsNotReadBack)
{
  auto ns = registered_namespace("urn:test:write-fed:no-item");
  auto source = std::make_shared<ClampingSource>();
  auto node = sourced_variable(*ns, 7207, Duration{0}, source);

  expect_all_good(write_values(*ns, {node}, {DataValue{Variant{int32_t{150}}}}), 1);
  EXPECT_EQ(source->reads(), 0u);
}
