// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_accessor.h"
#include <gtest/gtest.h>

#include "monitored_item_probe.h"
#include "test_utilities.h"

#include "ua_datatype_id.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_default_variable_node.h"
#include "ua_node.h"
#include "ua_namespace_monitoring.h"
#include "ua_sinks.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_write_value.h"

#include <algorithm>
#include <optional>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

class FakeSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>>) override
  {}

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}
};

/// Test SampleSink that records pushed samples (mirrors the one in sampling_engine_tests).
class TestSampleSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    std::lock_guard lock{mMutex};
    for (auto& sample : samples)
    {
      mSamples.push_back(std::move(sample));
    }
    mPushCount++;
    mCv.notify_all();
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    std::lock_guard lock{mMutex};
    if (mInvalidations.empty())
    {
      mSamplesAtFirstInvalidation = mSamples.size();
    }
    mInvalidations.emplace_back(monitoredItemId, reason);
    mCv.notify_all();
  }

  void detach() override
  {
    detached = true;
  }

  bool wait_for_samples(size_t count, std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mSamples.size() >= count; });
  }

  bool wait_for_invalidations(size_t count, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mInvalidations.size() >= count; });
  }

  /// The samples pushed before the first invalidation, or nullopt when none has arrived.
  std::optional<size_t> samples_at_first_invalidation()
  {
    std::lock_guard lock{mMutex};
    return mSamplesAtFirstInvalidation;
  }

  std::vector<std::pair<IntegerId, DataValue>> samples()
  {
    std::lock_guard lock{mMutex};
    return mSamples;
  }

  size_t sample_count()
  {
    std::lock_guard lock{mMutex};
    return mSamples.size();
  }

  std::vector<std::pair<IntegerId, StatusCode>> invalidations()
  {
    std::lock_guard lock{mMutex};
    return mInvalidations;
  }

  std::atomic<bool> detached{false};

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
  std::vector<std::pair<IntegerId, StatusCode>> mInvalidations;
  std::optional<size_t> mSamplesAtFirstInvalidation;
  int mPushCount{0};
};

/// Helper to write a value to a VariableNode via the write_value path.
void write_variable_value(
  const std::shared_ptr<default_ns::VariableNode>& node, const NodeId& nodeId, Variant value)
{
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{std::move(value)};

  auto completion = std::make_shared<std::promise<VoidResult>>();
  auto completionFuture = completion->get_future();
  node->write_value_async(
    writeVal, nullptr, [completion](VoidResult result) { completion->set_value(std::move(result)); });
  ASSERT_EQ(completionFuture.wait_for(2s), std::future_status::ready);
  const auto result = completionFuture.get();
  EXPECT_TRUE(result.is_good()) << "Failed to write value: " << to_string(result.status_code())
                                << (result.shared_detail() ? " " + to_string(*result.shared_detail()) : "");
}

}  // namespace

// ===== Tests for namespace with executor (real monitoring) =====

class NamespaceMonitoringSupportTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mNamespace = default_ns::Namespace::create("urn:test", mExecutor);
    mAddressSpace.emplace(AddressSpace::create("urn:test:monitoring-host", mExecutor));
    const auto registered = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
    mIndex = registered.value();
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// Helper to create a variable node in the namespace with a value.
  std::shared_ptr<default_ns::VariableNode> create_variable(uint32_t numericId, Variant value)
  {
    auto nodeId = NodeId{mIndex, numericId};
    auto node = mNamespace->create_node<default_ns::VariableNode>(nodeId);

    WriteValue writeVal;
    writeVal.node_id() = nodeId;
    writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
    writeVal.value() = DataValue{std::move(value)};

    VoidResult writeResult{StatusCode{Status::BadInternalError}};
    node->write_value_async(writeVal, nullptr, [&writeResult](VoidResult r) { writeResult = std::move(r); });
    EXPECT_TRUE(writeResult.is_good());

    return node;
  }

  /// Helper to create a variable with MinimumSamplingInterval set.
  std::shared_ptr<default_ns::VariableNode> create_variable_with_min_sampling(
    uint32_t numericId, Variant value, Duration minSampling)
  {
    auto node = create_variable(numericId, std::move(value));
    mAddressSpace->find_node_sync(NodeId{mIndex, numericId})
      .write_attribute_sync(AttributeId::MinimumSamplingInterval, Variant{minSampling});
    return node;
  }

  boost::asio::thread_pool mThreadPool{2};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mIndex{0};
};

TEST_F(NamespaceMonitoringSupportTest, VariableNodeMinSamplingZeroRequestedZeroIsExceptionQueued)
{
  create_variable(1000, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1000u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> results;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&results](BatchResult<MonitoringCreateItemResult> r) { results = std::move(r); });

  ASSERT_EQ(results.items.size(), 1u);
  ASSERT_TRUE(results.items[0].is_good());
  EXPECT_GT(results.items[0].value().handle, 0u);
  // ExceptionQueued reports revisedInterval as 0.
  EXPECT_DOUBLE_EQ(results.items[0].value().revisedSamplingInterval, 0);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-005, scope=function)
TEST_F(NamespaceMonitoringSupportTest, VariableNodeMinSampling100Requested50IsPolled)
{
  create_variable_with_min_sampling(1001, Variant{42}, 100);

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1001u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 2,
      .samplingInterval = 50,
      .queueSize = 1,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> results;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&results](BatchResult<MonitoringCreateItemResult> r) { results = std::move(r); });

  ASSERT_EQ(results.items.size(), 1u);
  EXPECT_TRUE(results.items[0].is_good());
  // Polled: revised interval should be >= 100 (bucketized).
  EXPECT_GE(results.items[0].value().revisedSamplingInterval, 100);
}

// @relation(SVR-MI-GEN-071, scope=function)
TEST_F(NamespaceMonitoringSupportTest, NonValueAttributeIsExceptionLatest)
{
  create_variable(1002, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1002u},
      .attributeId = AttributeId::BrowseName,
      .monitoredItemId = 3,
      .samplingInterval = 100,
      .queueSize = 1,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> results;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&results](BatchResult<MonitoringCreateItemResult> r) { results = std::move(r); });

  ASSERT_EQ(results.items.size(), 1u);
  EXPECT_TRUE(results.items[0].is_good());
  // ExceptionLatest: revised interval should be a bucket interval.
  EXPECT_GT(results.items[0].value().revisedSamplingInterval, 0);
}

TEST_F(NamespaceMonitoringSupportTest, NodeNotFoundReturnsBadNodeIdUnknown)
{
  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 9999u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 4,
      .samplingInterval = 100,
      .queueSize = 1,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> results;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&results](BatchResult<MonitoringCreateItemResult> r) { results = std::move(r); });

  ASSERT_EQ(results.items.size(), 1u);
  EXPECT_EQ(results.items[0].status_code(), StatusCode{Status::BadNodeIdUnknown});
  // Enriched with an ErrorDetail carrying the unresolved node id + monitored-item id.
  const auto detail = results.items[0].status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  const bool hasNodeId = std::any_of(detail->context.begin(),
    detail->context.end(),
    [](const NamedValue& entry) { return entry.key == ContextKeys::nodeId.value(); });
  EXPECT_TRUE(hasNodeId);
}

TEST_F(NamespaceMonitoringSupportTest, DeleteMonitoringValidHandles)
{
  create_variable(1003, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1003u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 5,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&createResults](BatchResult<MonitoringCreateItemResult> r) { createResults = std::move(r); });

  ASSERT_EQ(createResults.items.size(), 1u);
  ASSERT_TRUE(createResults.items[0].is_good());

  std::vector<MonitoringHandle> handles{createResults.items[0].value().handle};

  BatchResult<VoidResult> deleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    handles,

    [&deleteResults](BatchResult<VoidResult> r) { deleteResults = std::move(r); });

  ASSERT_EQ(deleteResults.items.size(), 1u);
  EXPECT_TRUE(deleteResults.items[0].is_good());
}

TEST_F(NamespaceMonitoringSupportTest, DeleteMonitoringInvalidHandles)
{
  std::vector<MonitoringHandle> handles{999};

  BatchResult<VoidResult> deleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    handles,

    [&deleteResults](BatchResult<VoidResult> r) { deleteResults = std::move(r); });

  ASSERT_EQ(deleteResults.items.size(), 1u);
  EXPECT_EQ(deleteResults.items[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
}

// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-TOMBSTONE-LIFECYCLE, scope=function)
// @defect(D-NAMESPACE-MONITORING-INVALIDATION-ERASES-LIVE-MONITORED-ITEM-HANDLE)
TEST_F(NamespaceMonitoringSupportTest, InvalidatedRegistrationRemainsModifiableAndDeletable)
{
  const NodeId nodeId{mIndex, 1011u};
  auto retainedNode = create_variable(1011, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> createItems{
    {.nodeId = nodeId,
      .attributeId = AttributeId::Value,
      .monitoredItemId = 31,
      .samplingInterval = 100,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    createItems,
    [&createResults](BatchResult<MonitoringCreateItemResult> result) { createResults = std::move(result); });

  ASSERT_EQ(createResults.items.size(), 1u);
  ASSERT_TRUE(createResults.items[0].is_good());
  const auto handle = createResults.items[0].value().handle;
  ASSERT_TRUE(sink->wait_for_samples(1)) << "the real polled registration must sample before invalidation";

  const auto deleteNodeResult = mNamespace->delete_node(nodeId, true);
  ASSERT_TRUE(deleteNodeResult.is_good());

  // The helper finds the deletion at the registration's next tick (DL-68 (6)), so the notice is awaited.
  ASSERT_TRUE(sink->wait_for_invalidations(1, 1s)) << "no Bad_NodeIdUnknown notice within 1 s";
  const auto invalidations = sink->invalidations();
  ASSERT_EQ(invalidations.size(), 1u);
  EXPECT_EQ(invalidations[0].first, IntegerId{31});
  EXPECT_EQ(invalidations[0].second, StatusCode{Status::BadNodeIdUnknown});
  // A sample read before the deletion may still precede the notice; none may follow it.
  const auto samplesAtInvalidation = sink->samples_at_first_invalidation();
  ASSERT_TRUE(samplesAtInvalidation.has_value());

  // Keep the erased Node object alive. If invalidation left the 100 ms polled SamplingEngine
  // registration active, it would read the retained cached Value and deliver another sample during
  // this three-interval observation window. A deleted Node's public write surface correctly returns
  // BadNodeIdUnknown, so a post-deletion write is not a valid stimulus here.
  UA_UNUSED(retainedNode);
  EXPECT_FALSE(sink->wait_for_samples(*samplesAtInvalidation + 1, 300ms));
  EXPECT_EQ(sink->sample_count(), *samplesAtInvalidation);
  EXPECT_EQ(sink->invalidations().size(), 1u) << "the deletion was noticed more than once";

  std::vector<MonitoringModifyItem> modifyItems{
    {.handle = handle, .samplingInterval = 250, .queueSize = 4},
  };
  BatchResult<MonitoringModifyItemResult> modifyResults;
  mNamespace->modify_monitoring_async(RequestInfo{},
    modifyItems,
    [&modifyResults](BatchResult<MonitoringModifyItemResult> result) { modifyResults = std::move(result); });

  ASSERT_EQ(modifyResults.items.size(), 1u);
  ASSERT_TRUE(modifyResults.items[0].is_good());
  EXPECT_DOUBLE_EQ(modifyResults.items[0].value().revisedSamplingInterval, 250);

  const MonitoringHandle neverIssuedHandle = handle + 100000u;
  std::vector<MonitoringModifyItem> unknownModifyItems{
    {.handle = neverIssuedHandle, .samplingInterval = 125, .queueSize = 2},
  };
  BatchResult<MonitoringModifyItemResult> unknownModifyResults;
  mNamespace->modify_monitoring_async(RequestInfo{},
    unknownModifyItems,
    [&unknownModifyResults](BatchResult<MonitoringModifyItemResult> result)
    { unknownModifyResults = std::move(result); });
  ASSERT_EQ(unknownModifyResults.items.size(), 1u);
  EXPECT_EQ(unknownModifyResults.items[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});

  std::vector<MonitoringHandle> unknownHandles{neverIssuedHandle};
  BatchResult<VoidResult> unknownDeleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    unknownHandles,
    [&unknownDeleteResults](BatchResult<VoidResult> result) { unknownDeleteResults = std::move(result); });
  ASSERT_EQ(unknownDeleteResults.items.size(), 1u);
  EXPECT_EQ(unknownDeleteResults.items[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});

  std::vector<MonitoringHandle> handles{handle};
  BatchResult<VoidResult> firstDeleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    handles,
    [&firstDeleteResults](BatchResult<VoidResult> result) { firstDeleteResults = std::move(result); });
  ASSERT_EQ(firstDeleteResults.items.size(), 1u);
  EXPECT_TRUE(firstDeleteResults.items[0].is_good());

  BatchResult<VoidResult> secondDeleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    handles,
    [&secondDeleteResults](BatchResult<VoidResult> result) { secondDeleteResults = std::move(result); });
  ASSERT_EQ(secondDeleteResults.items.size(), 1u);
  EXPECT_EQ(secondDeleteResults.items[0].status_code(), StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(NamespaceMonitoringSupportTest, WriteValueTriggersSampleViaMonitoring)
{
  auto node = create_variable(1004, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1004u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 10,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&createResults](BatchResult<MonitoringCreateItemResult> r) { createResults = std::move(r); });

  ASSERT_EQ(createResults.items.size(), 1u);
  ASSERT_TRUE(createResults.items[0].is_good());

  // Write a value to the node - should trigger write notifier -> engine -> sink.
  write_variable_value(node, NodeId{mIndex, 1004u}, Variant{99});

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].first, IntegerId{10});
  EXPECT_EQ(samples[0].second.value(), Variant{99});
}

TEST_F(NamespaceMonitoringSupportTest, AppNotifyValueChangedTriggersSample)
{
  auto node = create_variable(1005, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1005u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 11,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&createResults](BatchResult<MonitoringCreateItemResult> r) { createResults = std::move(r); });

  ASSERT_EQ(createResults.items.size(), 1u);
  ASSERT_TRUE(createResults.items[0].is_good());

  // Use ExternalValueSource::notify_value_changed to signal a value change.
  auto* source = node->external_value_source();
  ASSERT_NE(source, nullptr);

  DataValue newValue;
  newValue.value() = Variant{77};
  source->notify_value_changed(std::move(newValue));

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].first, IntegerId{11});
  EXPECT_EQ(samples[0].second.value(), Variant{77});
}

TEST_F(NamespaceMonitoringSupportTest, DeleteMonitoringStopsSamples)
{
  auto node = create_variable(1006, Variant{42});

  auto sink = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1006u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 12,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&createResults](BatchResult<MonitoringCreateItemResult> r) { createResults = std::move(r); });

  ASSERT_EQ(createResults.items.size(), 1u);
  ASSERT_TRUE(createResults.items[0].is_good());

  // Write to trigger a first sample.
  write_variable_value(node, NodeId{mIndex, 1006u}, Variant{99});
  ASSERT_TRUE(sink->wait_for_samples(1));

  // Delete monitoring.
  std::vector<MonitoringHandle> handles{createResults.items[0].value().handle};
  BatchResult<VoidResult> deleteResults;
  mNamespace->delete_monitoring_async(RequestInfo{},
    handles,

    [&deleteResults](BatchResult<VoidResult> r) { deleteResults = std::move(r); });
  ASSERT_EQ(deleteResults.items.size(), 1u);
  ASSERT_TRUE(deleteResults.items[0].is_good());

  auto countAfterDelete = sink->sample_count();

  // Write again - should NOT produce more samples after monitoring was deleted.
  write_variable_value(node, NodeId{mIndex, 1006u}, Variant{200});
  EXPECT_FALSE(sink->wait_for_samples(countAfterDelete + 1, 200ms));
}

TEST_F(NamespaceMonitoringSupportTest, MultipleSubscriptionsSameNodeBothGetSamples)
{
  auto node = create_variable(1007, Variant{42});

  auto sink1 = std::make_shared<TestSampleSink>();
  auto sink2 = std::make_shared<TestSampleSink>();
  std::vector<MonitoringCreateItem> items{
    {.nodeId = NodeId{mIndex, 1007u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 20,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink1},
    {.nodeId = NodeId{mIndex, 1007u},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 21,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink2},
  };

  BatchResult<MonitoringCreateItemResult> createResults;
  mNamespace->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&createResults](BatchResult<MonitoringCreateItemResult> r) { createResults = std::move(r); });

  ASSERT_EQ(createResults.items.size(), 2u);
  EXPECT_TRUE(createResults.items[0].is_good());
  EXPECT_TRUE(createResults.items[1].is_good());

  // Write a value - both sinks should receive samples.
  write_variable_value(node, NodeId{mIndex, 1007u}, Variant{55});

  ASSERT_TRUE(sink1->wait_for_samples(1));
  ASSERT_TRUE(sink2->wait_for_samples(1));

  EXPECT_EQ(sink1->samples()[0].first, IntegerId{20});
  EXPECT_EQ(sink2->samples()[0].first, IntegerId{21});
  EXPECT_EQ(sink1->samples()[0].second.value(), Variant{55});
  EXPECT_EQ(sink2->samples()[0].second.value(), Variant{55});
}

// ===== ExternalValueSource and write_attribute notification tests =====

// A value change an application reports through the Variable's ExternalValueSource reaches an item
// monitoring the Value at sampling interval 0.
TEST(ExternalValueSourceTests, NotifyValueChangedReachesAMonitoredItem)
{
  boost::asio::thread_pool pool{1};
  auto addressSpace = AddressSpace::create("urn:test:notify-value-changed", pool.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 100}, NodeClass::Variable);
  auto& node = dynamic_cast<default_ns::VariableNode&>(*accessor);
  auto sink = std::make_shared<test::RecordingSampleSink>();
  const auto created = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 100},
      .attributeId = AttributeId::Value,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = sink});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  DataValue newValue;
  newValue.value() = Variant{42};
  node.notify_value_changed(std::move(newValue));

  ASSERT_TRUE(sink->wait_for_samples(1, 1s));
  EXPECT_EQ(sink->samples().front().first, IntegerId{1});
  EXPECT_EQ(sink->samples().front().second.value(), Variant{42});

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, created.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(pool);
}

// A write of a non-Value Attribute (DataType) reaches an item monitoring that Attribute.
TEST(ExternalValueSourceTests, WriteAttributeReachesAMonitoredItem)
{
  boost::asio::thread_pool pool{1};
  auto addressSpace = AddressSpace::create("urn:test:write-attribute-notifier", pool.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 101}, NodeClass::Variable);
  auto sink = std::make_shared<test::RecordingSampleSink>();
  const auto created = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 101},
      .attributeId = AttributeId::DataType,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = sink});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  // Write the DataType attribute.
  accessor.write_attribute_sync(AttributeId::DataType, Variant{NodeId{DataTypeId::Int32}});

  ASSERT_TRUE(sink->wait_for_samples(1, 1s));
  EXPECT_EQ(sink->samples().front().second.value(), Variant{NodeId{DataTypeId::Int32}});

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, created.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(pool);
}
