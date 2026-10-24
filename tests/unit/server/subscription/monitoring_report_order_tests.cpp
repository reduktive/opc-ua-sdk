// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// What the in-memory namespace's monitored items receive when two writes of one Node race, and the interval a
// Value item is revised to when the Variable's MinimumSamplingInterval is above the largest sampling bucket
// (NR-47 rule 2, NR-48 rule 4).
//
// The race is made deterministic with a second registration on the same (NodeId, attribute) whose Node holds
// the first write's report: the helper asks every registered Node `deleted()` while it reports a change, so a
// Node that blocks there on the first writer's thread holds that report until the test releases it.

#include <gtest/gtest.h>

#include "monitoring_helper_fixture.h"

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;
using namespace ua::test::monitoring_helper;

namespace
{

/// A Node whose `deleted()` blocks once, on the thread the test names, until the test releases it; it answers
/// false on every other call.
class ReportHoldingNode final : public default_ns::BaseNode
{
public:
  static std::shared_ptr<ReportHoldingNode> create(const NodeId& nodeId)
  {
    return std::shared_ptr<ReportHoldingNode>(new ReportHoldingNode(nodeId));
  }

  NodeClass get_node_class() const override
  {
    return NodeClass::Variable;
  }

  bool deleted() const noexcept override
  {
    std::unique_lock lock{mHookMutex};
    if (mHoldOn == std::this_thread::get_id())
    {
      mHoldOn = std::thread::id{};
      mHeld = true;
      mCv.notify_all();
      mCv.wait(lock, [this] { return mReleased; });
    }
    return false;
  }

  /// The next `deleted()` call on the calling thread blocks until @ref release.
  void hold_next_call_on_this_thread()
  {
    const std::lock_guard lock{mHookMutex};
    mHoldOn = std::this_thread::get_id();
  }

  bool wait_until_held(std::chrono::milliseconds timeout) const
  {
    std::unique_lock lock{mHookMutex};
    return mCv.wait_for(lock, timeout, [this] { return mHeld; });
  }

  void release()
  {
    {
      const std::lock_guard lock{mHookMutex};
      mReleased = true;
    }
    mCv.notify_all();
  }

private:
  explicit ReportHoldingNode(const NodeId& nodeId) : default_ns::BaseNode(nodeId, NodeClass::Variable)
  {}

  mutable std::mutex mHookMutex;
  mutable std::condition_variable mCv;
  mutable std::thread::id mHoldOn;
  mutable bool mHeld{false};
  bool mReleased{false};
};

class MonitoringReportOrder : public MonitoringHelperTest
{
protected:
  /// Creates one item on @p attributeId of @p nodeId through the namespace's `create_monitoring_async`, which
  /// resolves the Node and marks the delivery by the in-memory rule.
  static MonitoringCreateItemResult create_through_namespace(ExposedNamespace& ns, const NodeId& nodeId,
    AttributeId attributeId, IntegerId monitoredItemId, Duration samplingInterval,
    std::shared_ptr<SampleSink> sink)
  {
    std::vector<MonitoringCreateItem> items{{.nodeId = nodeId,
      .attributeId = attributeId,
      .monitoredItemId = monitoredItemId,
      .samplingInterval = samplingInterval,
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

  /// Adds a Reported registration on @p attributeId of @p nodeId whose Node is @p holding.
  static void register_holding_node(ExposedNamespace& ns, const NodeId& nodeId, AttributeId attributeId,
    Duration samplingInterval, const std::shared_ptr<ReportHoldingNode>& holding,
    std::shared_ptr<SampleSink> sink)
  {
    const Helper::ResolvedMonitoringItem items[]{resolved(
      nodeId, attributeId, 99, samplingInterval, std::move(sink), holding, Helper::Delivery::Reported)};
    const auto created = ns.helper().create_monitoring(items);
    ASSERT_EQ(created.size(), 1u);
    ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  }

  /// Whether the first write's report was held, and each write's answer.
  struct Race
  {
    bool firstHeld{false};
    VoidResult first;
    VoidResult second;
  };

  /// Runs @p first on a thread whose report @p holding holds, then @p second on another thread while it is
  /// held; releases the hold once @p second has answered or 500 ms have passed, and waits for both.
  static Race race(const std::shared_ptr<ReportHoldingNode>& holding,
    const std::function<void(std::function<void(VoidResult)>)>& first,
    const std::function<void(std::function<void(VoidResult)>)>& second)
  {
    auto firstAnswer = std::make_shared<std::promise<VoidResult>>();
    auto secondAnswer = std::make_shared<std::promise<VoidResult>>();
    auto firstFuture = firstAnswer->get_future();
    auto secondFuture = secondAnswer->get_future();
    std::thread firstWriter(
      [&holding, &first, firstAnswer]
      {
        holding->hold_next_call_on_this_thread();
        first([firstAnswer](VoidResult result) { firstAnswer->set_value(std::move(result)); });
      });
    Race outcome;
    outcome.firstHeld = holding->wait_until_held(2s);
    std::thread secondWriter([&second, secondAnswer]
      { second([secondAnswer](VoidResult result) { secondAnswer->set_value(std::move(result)); }); });
    // Reported after its lock is released, the second write is committed and reported while the first one's
    // report is held, and answers at once. Reported under that lock, it waits for the first write to finish,
    // and this wait ends at its timeout.
    secondFuture.wait_for(500ms);
    holding->release();
    firstWriter.join();
    secondWriter.join();
    outcome.first = firstFuture.get();
    outcome.second = secondFuture.get();
    return outcome;
  }

  /// The UInt32 values of the samples @p recorded received, in order.
  static std::vector<uint32_t> uint32_samples(const RecordingSink& recorded)
  {
    std::vector<uint32_t> values;
    for (const auto& event : recorded.events())
    {
      if (const auto* value = event.notice ? nullptr : event.value.value().try_as<uint32_t>())
        values.push_back(*value);
    }
    return values;
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

class MonitoringMinimumSamplingInterval : public MonitoringReportOrder
{};

/// Writes @p minimumSamplingInterval to @p node's MinimumSamplingInterval.
void set_minimum_sampling_interval(default_ns::VariableNode& node, Duration minimumSamplingInterval)
{
  auto completion = std::make_shared<std::promise<VoidResult>>();
  auto written = completion->get_future();
  node.write_attribute_async(AttributeId::MinimumSamplingInterval,
    Variant{minimumSamplingInterval},
    [completion](VoidResult result) { completion->set_value(std::move(result)); });
  ASSERT_EQ(written.wait_for(2s), std::future_status::ready);
  const auto result = written.get();
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
}

}  // namespace

// NR-48 rule 4: two writes of one Node's WriteMask, committed 1 then 2, are reported 1 then 2, so the item
// on it ends on 2, the value the Node holds. The first write's report is held until the second write has
// answered or 500 ms have passed. Control: the Node holds 2 in either case.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-AN-ATTRIBUTE-CHANGE-IS-REPORTED-IN-THE-ORDER-IT-WAS-COMMITTED, scope=function)
TEST_F(MonitoringReportOrder, TwoAttributeWritesAreReportedInTheOrderTheyWereCommitted)
{
  auto ns = registered_namespace("urn:test:report-order:attribute");
  auto node = variable(*ns, 7000, Variant{int32_t{0}});
  const NodeId nodeId = node->node_id();
  auto item = sink();
  const auto created = create_through_namespace(*ns, nodeId, AttributeId::WriteMask, 1, 50, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  auto holding = ReportHoldingNode::create(nodeId);
  register_holding_node(*ns, nodeId, AttributeId::WriteMask, 50, holding, sink());

  const auto writeMask = [node](uint32_t mask)
  {
    return [node, mask](std::function<void(VoidResult)> answer)
    {
      node->write_attribute_async(AttributeId::WriteMask, Variant{mask}, std::move(answer));
    };
  };
  const auto outcome = race(holding, writeMask(1), writeMask(2));
  ASSERT_TRUE(outcome.firstHeld) << "the first write's report was not held";
  ASSERT_TRUE(outcome.first.is_good()) << to_string(outcome.first.status_code());
  ASSERT_TRUE(outcome.second.is_good()) << to_string(outcome.second.status_code());
  ASSERT_EQ(node->read_attribute(AttributeId::WriteMask).as<uint32_t>(), 2u);

  const auto lastIsTwo = [&]
  {
    const auto values = uint32_samples(*item);
    return !values.empty() && values.back() == 2u;
  };
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  while (!lastIsTwo() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(10ms);
  // Six ticks of the item's 50 ms bucket: a value still pending is delivered by then.
  std::this_thread::sleep_for(300ms);
  EXPECT_TRUE(lastIsTwo()) << item->text();
}

// NR-48 rule 4: two Value writes of one Variable on its default source, committed 1 then 2, reach a queued
// item (interval 0, no MinimumSamplingInterval) as 1 then 2. The first write's report is held until the
// second write has answered or 500 ms have passed. Control: the Variable holds 2 in either case.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-VALUE-CHANGE-IS-REPORTED-IN-THE-ORDER-IT-WAS-COMMITTED, scope=function)
TEST_F(MonitoringReportOrder, TwoValueWritesAreReportedInTheOrderTheyWereCommitted)
{
  auto ns = registered_namespace("urn:test:report-order:value");
  auto node = variable(*ns, 7001, Variant{int32_t{0}});
  const NodeId nodeId = node->node_id();
  auto item = sink();
  const auto created = create_through_namespace(*ns, nodeId, AttributeId::Value, 1, 0, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_DOUBLE_EQ(created.value().revisedSamplingInterval, 0) << "the item is not the queued one";
  auto holding = ReportHoldingNode::create(nodeId);
  register_holding_node(*ns, nodeId, AttributeId::Value, 0, holding, sink());

  const auto writeValueOf = [node, nodeId](int32_t value)
  {
    return [node, nodeId, value](std::function<void(VoidResult)> answer)
    {
      WriteValue write;
      write.node_id() = nodeId;
      write.attribute_id() = utils::to_underlying(AttributeId::Value);
      write.value() = DataValue{Variant{value}};
      node->write_value_async(write, nullptr, std::move(answer));
    };
  };
  const auto outcome = race(holding, writeValueOf(1), writeValueOf(2));
  ASSERT_TRUE(outcome.firstHeld) << "the first write's report was not held";
  ASSERT_TRUE(outcome.first.is_good()) << to_string(outcome.first.status_code());
  ASSERT_TRUE(outcome.second.is_good()) << to_string(outcome.second.status_code());
  const auto held = node->read_default_source(0.0, false);
  ASSERT_TRUE(held.value().is_int32());
  ASSERT_EQ(held.value().as<int32_t>(), 2);

  ASSERT_TRUE(item->wait_for_samples(2, 3s)) << item->text();
  EXPECT_EQ(int32_samples(*item), (std::vector<int32_t>{1, 2})) << item->text();
}

// NR-48 rule 4 on the namespace's one-item write, which the Write service and an accessor's write take: two
// Value writes through `write_async`, committed 1 then 2, reach a queued item as 1 then 2. Control: the
// Variable holds 2.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-VALUE-CHANGE-IS-REPORTED-IN-THE-ORDER-IT-WAS-COMMITTED, scope=function)
TEST_F(MonitoringReportOrder, TwoOneItemNamespaceWritesAreReportedInTheOrderTheyWereCommitted)
{
  auto ns = registered_namespace("urn:test:report-order:namespace-write");
  auto node = variable(*ns, 7002, Variant{int32_t{0}});
  const NodeId nodeId = node->node_id();
  auto item = sink();
  const auto created = create_through_namespace(*ns, nodeId, AttributeId::Value, 1, 0, item);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_DOUBLE_EQ(created.value().revisedSamplingInterval, 0) << "the item is not the queued one";
  auto holding = ReportHoldingNode::create(nodeId);
  register_holding_node(*ns, nodeId, AttributeId::Value, 0, holding, sink());

  const auto writeValueOf = [ns, node, nodeId](int32_t value)
  {
    return [ns, node, nodeId, value](std::function<void(VoidResult)> answer)
    {
      WriteValue write;
      write.node_id() = nodeId;
      write.attribute_id() = utils::to_underlying(AttributeId::Value);
      write.value() = DataValue{Variant{value}};
      const ValueWriteItem one{*node, write};
      ns->write_async(RequestInfo{},
        nullptr,
        std::span<const ValueWriteItem>{&one, 1},
        [answer = std::move(answer)](BatchResult<VoidResult> written, std::vector<VersionedNode>)
        { answer(written.items.empty() ? VoidResult{Status::BadInternalError} : written.items.front()); });
    };
  };
  const auto outcome = race(holding, writeValueOf(1), writeValueOf(2));
  ASSERT_TRUE(outcome.firstHeld) << "the first write's report was not held";
  ASSERT_TRUE(outcome.first.is_good()) << to_string(outcome.first.status_code());
  ASSERT_TRUE(outcome.second.is_good()) << to_string(outcome.second.status_code());
  const auto held = node->read_default_source(0.0, false);
  ASSERT_TRUE(held.value().is_int32());
  ASSERT_EQ(held.value().as<int32_t>(), 2);

  ASSERT_TRUE(item->wait_for_samples(2, 3s)) << item->text();
  EXPECT_EQ(int32_samples(*item), (std::vector<int32_t>{1, 2})) << item->text();
}

// NR-47 rule 2 and Part 4 5.12.1.2: a Value item on a Variable whose MinimumSamplingInterval is 90000, above
// the largest sampling bucket (60000), is revised to at least 90000, whether 1000 or 0 is requested. Control:
// a Variable whose MinimumSamplingInterval is 5000 is revised to 5000 for a request of 1000.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-THE-REVISED-INTERVAL-IS-NEVER-BELOW-THE-MINIMUM-SAMPLING-INTERVAL, scope=function)
TEST_F(MonitoringMinimumSamplingInterval, AMinimumAboveTheLargestBucketIsTheRevisedInterval)
{
  auto ns = registered_namespace("urn:test:report-order:minimum-sampling-interval");
  auto slow = variable(*ns, 7100, Variant{int32_t{0}});
  set_minimum_sampling_interval(*slow, 90000);
  auto control = variable(*ns, 7101, Variant{int32_t{0}});
  set_minimum_sampling_interval(*control, 5000);

  IntegerId monitoredItemId = 1;
  for (const Duration requested : {Duration{1000}, Duration{0}})
  {
    const auto created = create_through_namespace(
      *ns, slow->node_id(), AttributeId::Value, monitoredItemId++, requested, sink());
    ASSERT_TRUE(created.is_good()) << "requested " << requested << ": " << to_string(created.status_code());
    EXPECT_GE(created.value().revisedSamplingInterval, 90000) << "requested " << requested;
  }

  const auto controlled =
    create_through_namespace(*ns, control->node_id(), AttributeId::Value, monitoredItemId, 1000, sink());
  ASSERT_TRUE(controlled.is_good()) << to_string(controlled.status_code());
  EXPECT_DOUBLE_EQ(controlled.value().revisedSamplingInterval, 5000);
}
