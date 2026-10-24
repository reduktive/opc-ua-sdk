// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "node_value_reader.h"
#include "test_utilities.h"

#include "ua_sampling_engine.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace_monitoring.h"

#include "ua_default_variable_node.h"
#include "ua_value_source.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_write_value.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <optional>
#include <thread>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Test SampleSink that records pushed samples.
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
    mInvalidations.emplace_back(monitoredItemId, reason);
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

  bool wait_for_pushes(int count, std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mPushCount >= count; });
  }

  std::vector<std::pair<IntegerId, DataValue>> samples()
  {
    std::lock_guard lock{mMutex};
    return mSamples;
  }

  int push_count()
  {
    std::lock_guard lock{mMutex};
    return mPushCount;
  }

  size_t sample_count()
  {
    std::lock_guard lock{mMutex};
    return mSamples.size();
  }

  std::atomic<bool> detached{false};

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
  std::vector<std::pair<IntegerId, StatusCode>> mInvalidations;
  int mPushCount{0};
};

/// Helper to create a VariableNode with a known value.
std::shared_ptr<default_ns::VariableNode> create_variable_with_value(const NodeId& nodeId, Variant value)
{
  auto node = default_ns::VariableNode::create(nodeId);
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{std::move(value)};

  VoidResult writeResult{StatusCode{Status::BadInternalError}};
  node->write_value_async(writeVal, nullptr, [&writeResult](VoidResult r) { writeResult = std::move(r); });
  EXPECT_TRUE(writeResult.is_good()) << "Failed to write initial value";
  return node;
}

/// Helper to write a value to a VariableNode.
void write_variable_value(
  const std::shared_ptr<default_ns::VariableNode>& node, const NodeId& nodeId, Variant value)
{
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{std::move(value)};

  VoidResult writeResult{StatusCode{Status::BadInternalError}};
  node->write_value_async(writeVal, nullptr, [&writeResult](VoidResult r) { writeResult = std::move(r); });
  EXPECT_TRUE(writeResult.is_good()) << "Failed to write value";
}

/// Helper to create a PolledRegistration.
default_ns::SamplingEngine::PolledRegistration make_polled(std::shared_ptr<Node> node, NodeId nodeId,
  IntegerId monitoredItemId, Duration requestedInterval, std::shared_ptr<SampleSink> sink)
{
  default_ns::SamplingEngine::PolledRegistration reg;
  reg.node = std::move(node);
  reg.nodeId = std::move(nodeId);
  reg.monitoredItemId = monitoredItemId;
  reg.requestedInterval = requestedInterval;
  reg.sink = std::move(sink);
  return reg;
}

/// Helper to create an ExceptionRegistration.
default_ns::SamplingEngine::ExceptionRegistration make_exception(std::shared_ptr<Node> node, NodeId nodeId,
  IntegerId monitoredItemId, Duration requestedInterval, std::shared_ptr<SampleSink> sink,
  uint32_t queueSize = 100)
{
  default_ns::SamplingEngine::ExceptionRegistration reg;
  reg.node = std::move(node);
  reg.nodeId = std::move(nodeId);
  reg.monitoredItemId = monitoredItemId;
  reg.requestedInterval = requestedInterval;
  reg.queueSize = queueSize;
  reg.sink = std::move(sink);
  return reg;
}

// ===== round_to_bucket tests =====

class SamplingEngineTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
  }

  void TearDown() override
  {
    mEngine.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_engine()
  {
    mEngine =
      std::make_shared<default_ns::SamplingEngine>(mExecutor, test_utils::node_value_reader(mExecutor));
  }

  boost::asio::thread_pool mThreadPool{2};
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<default_ns::SamplingEngine> mEngine;
};

TEST_F(SamplingEngineTest, RoundToBucketZeroReturnsSmallest)
{
  create_engine();
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(0), 50);
}

TEST_F(SamplingEngineTest, RoundToBucketNegativeReturnsSmallest)
{
  create_engine();
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(-100), 50);
}

TEST_F(SamplingEngineTest, RoundToBucketExactMatch)
{
  create_engine();
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(50), 50);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(100), 100);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(1000), 1000);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(60000), 60000);
}

// @relation(SVR-MI-GEN-003, scope=function)
TEST_F(SamplingEngineTest, RoundToBucketRoundsUp)
{
  create_engine();
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(25), 50);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(75), 100);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(999), 1000);
}

// NR-47 rule 2 and Part 4 5.12.1.2: above the largest bucket (60 s) the engine is given a Variable's
// MinimumSamplingInterval, which the revised interval is never below, so the interval is kept, rounded up to
// a whole millisecond; it was cut to 60 s. Control: NaN still gets the largest bucket, and an infinite
// interval the longest period a timer holds, which is above every finite interval asked of it here.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-THE-REVISED-INTERVAL-IS-NEVER-BELOW-THE-MINIMUM-SAMPLING-INTERVAL, scope=function)
TEST_F(SamplingEngineTest, RoundToBucketAboveTheLargestBucketKeepsTheInterval)
{
  create_engine();
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(100000), 100000);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(60001), 60001);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(90000.25), 90001);
  EXPECT_DOUBLE_EQ(mEngine->round_to_bucket(std::numeric_limits<double>::quiet_NaN()), 60000);
  const Duration longest = mEngine->round_to_bucket(std::numeric_limits<double>::infinity());
  EXPECT_TRUE(std::isfinite(longest));
  EXPECT_GT(longest, 1.0e12);
}

// ===== Lifecycle tests =====

TEST_F(SamplingEngineTest, CreateAndShutdown)
{
  create_engine();
  mEngine->shutdown();
}

TEST_F(SamplingEngineTest, AddPolledReturnsValidHandle)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_polled(make_polled(node, nodeId, 1, 100, sink));

  EXPECT_GT(result.handle, 0u);
  EXPECT_DOUBLE_EQ(result.revisedInterval, 100);
}

TEST_F(SamplingEngineTest, AddPolledAfterShutdownReturnsZero)
{
  create_engine();
  mEngine->shutdown();

  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_polled(make_polled(node, nodeId, 1, 100, sink));

  EXPECT_EQ(result.handle, 0u);
}

// ===== Polled sampling tests =====

TEST_F(SamplingEngineTest, SinglePolledItemReceivesSample)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].first, IntegerId{1});
  EXPECT_EQ(samples[0].second.value(), Variant{42});
}

TEST_F(SamplingEngineTest, MultipleItemsSameBucketBatchedPush)
{
  create_engine();
  auto nodeId1 = NodeId{1, 1000};
  auto nodeId2 = NodeId{1, 1001};
  auto node1 = create_variable_with_value(nodeId1, Variant{10});
  auto node2 = create_variable_with_value(nodeId2, Variant{20});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node1, nodeId1, 1, 50, sink));
  mEngine->add_polled(make_polled(node2, nodeId2, 2, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(2));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 2u);

  bool foundItem1 = false;
  bool foundItem2 = false;
  for (auto& [id, dv] : samples)
  {
    if (id == IntegerId{1})
    {
      foundItem1 = true;
    }
    if (id == IntegerId{2})
    {
      foundItem2 = true;
    }
  }
  EXPECT_TRUE(foundItem1);
  EXPECT_TRUE(foundItem2);
}

TEST_F(SamplingEngineTest, ChangeDetectionUnchangedValueNotPushed)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(1));

  // Value hasn't changed, so no new pushes should arrive.
  EXPECT_FALSE(sink->wait_for_samples(2, 200ms));
}

TEST_F(SamplingEngineTest, ChangeDetectionNewValuePushed)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(1));

  write_variable_value(node, nodeId, Variant{99});

  ASSERT_TRUE(sink->wait_for_samples(2, 2000ms));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 2u);
  EXPECT_EQ(samples.back().second.value(), Variant{99});
}

TEST_F(SamplingEngineTest, RemoveStopsPushes)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(1));

  mEngine->remove(result.handle);

  auto countAfterRemove = sink->sample_count();

  write_variable_value(node, nodeId, Variant{99});

  // No additional samples should arrive after removal.
  EXPECT_FALSE(sink->wait_for_samples(countAfterRemove + 1, 200ms));
}

TEST_F(SamplingEngineTest, RemoveLastInBucketStopsTimer)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  ASSERT_TRUE(sink->wait_for_samples(1));

  mEngine->remove(result.handle);

  auto nodeId2 = NodeId{1, 2000};
  auto node2 = create_variable_with_value(nodeId2, Variant{100});
  auto sink2 = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node2, nodeId2, 2, 100, sink2));

  ASSERT_TRUE(sink2->wait_for_samples(1));

  auto originalCount = sink->sample_count();
  // No additional samples should arrive on the removed sink's bucket.
  EXPECT_FALSE(sink->wait_for_samples(originalCount + 1, 200ms));
}

TEST_F(SamplingEngineTest, MultipleEntriesSameNodeDifferentSinks)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});

  auto sink1 = std::make_shared<TestSampleSink>();
  auto sink2 = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink1));
  mEngine->add_polled(make_polled(node, nodeId, 2, 50, sink2));

  ASSERT_TRUE(sink1->wait_for_samples(1));
  ASSERT_TRUE(sink2->wait_for_samples(1));

  EXPECT_EQ(sink1->samples()[0].first, IntegerId{1});
  EXPECT_EQ(sink2->samples()[0].first, IntegerId{2});
}

TEST_F(SamplingEngineTest, DifferentBucketsTickIndependently)
{
  create_engine();
  auto nodeId1 = NodeId{1, 1000};
  auto nodeId2 = NodeId{1, 1001};
  auto node1 = create_variable_with_value(nodeId1, Variant{10});
  auto node2 = create_variable_with_value(nodeId2, Variant{20});

  auto sink1 = std::make_shared<TestSampleSink>();
  auto sink2 = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node1, nodeId1, 1, 50, sink1));
  mEngine->add_polled(make_polled(node2, nodeId2, 2, 200, sink2));

  ASSERT_TRUE(sink1->wait_for_samples(1));
  ASSERT_TRUE(sink2->wait_for_samples(1));

  EXPECT_EQ(sink1->samples()[0].second.value(), Variant{10});
  EXPECT_EQ(sink2->samples()[0].second.value(), Variant{20});
}

TEST_F(SamplingEngineTest, RemoveNonExistentHandleIsNoOp)
{
  create_engine();
  mEngine->remove(12345);
}

// ===== ExceptionLatest tests =====

TEST_F(SamplingEngineTest, ExceptionLatestReturnsValidHandleAndBucketInterval)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 100, sink));

  EXPECT_GT(result.handle, 0u);
  EXPECT_DOUBLE_EQ(result.revisedInterval, 100);
}

TEST_F(SamplingEngineTest, ExceptionLatestWritePendingThenTickPushes)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  // Post a value via write-path notification.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].first, IntegerId{1});
  EXPECT_EQ(samples[0].second.value(), Variant{100});
}

TEST_F(SamplingEngineTest, ExceptionLatestMultipleWritesOnlyLatestPushed)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  // Multiple writes before a tick - only latest should be pushed.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{200}});
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{300}});

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].second.value(), Variant{300});
}

TEST_F(SamplingEngineTest, ExceptionLatestNoWriteNoPush)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  // No attribute_changed call - no pending value, so nothing should be pushed.
  EXPECT_FALSE(sink->wait_for_samples(1, 200ms));
}

TEST_F(SamplingEngineTest, ExceptionLatestChangeDetectionSameValueNotPushedAgain)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  // First write - should push.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  ASSERT_TRUE(sink->wait_for_samples(1));

  // Write same value again - should not push (change detection filters it).
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  EXPECT_FALSE(sink->wait_for_samples(2, 200ms));
}

TEST_F(SamplingEngineTest, ExceptionLatestNanToNanSuppressed)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  const auto nan = std::numeric_limits<double>::quiet_NaN();

  // First NaN - should push.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{nan}});
  ASSERT_TRUE(sink->wait_for_samples(1));

  // Second NaN - change detection should suppress (NaN == NaN for monitoring).
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{nan}});
  EXPECT_FALSE(sink->wait_for_pushes(2, 200ms));
}

// @relation(SVR-MI-GEN-052, scope=function)
TEST_F(SamplingEngineTest, ExceptionLatestNanTransitionReported)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  const auto nan = std::numeric_limits<double>::quiet_NaN();

  // 1.0 -> reported (push 1)
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{1.0}});
  ASSERT_TRUE(sink->wait_for_samples(1));

  // NaN -> reported (push 2)
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{nan}});
  ASSERT_TRUE(sink->wait_for_samples(2));

  // NaN -> suppressed (still 2 pushes)
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{nan}});
  EXPECT_FALSE(sink->wait_for_pushes(3, 200ms));

  // 2.0 -> reported (push 3)
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{2.0}});
  ASSERT_TRUE(sink->wait_for_samples(3));

  // NaN -> reported (push 4)
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{nan}});
  ASSERT_TRUE(sink->wait_for_samples(4));

  auto samples = sink->samples();
  ASSERT_EQ(samples.size(), 4u);
  EXPECT_EQ(samples[0].second.value(), Variant{1.0});
  EXPECT_TRUE(std::isnan(samples[1].second.value().as<double>()));
  EXPECT_EQ(samples[2].second.value(), Variant{2.0});
  EXPECT_TRUE(std::isnan(samples[3].second.value().as<double>()));
}

TEST_F(SamplingEngineTest, PolledNanSameValueNotPushedAgain)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  const auto nan = std::numeric_limits<double>::quiet_NaN();
  auto node = create_variable_with_value(nodeId, Variant{nan});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));

  // First tick delivers the initial NaN sample.
  ASSERT_TRUE(sink->wait_for_samples(1));

  // Value hasn't changed (still NaN), so no new pushes should arrive.
  EXPECT_FALSE(sink->wait_for_samples(2, 200ms));
}

// ===== ExceptionQueued tests =====

TEST_F(SamplingEngineTest, ExceptionQueuedReturnsZeroRevisedInterval)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink));

  EXPECT_GT(result.handle, 0u);
  EXPECT_DOUBLE_EQ(result.revisedInterval, 0);
}

TEST_F(SamplingEngineTest, ExceptionQueuedWritePendingThenTickPushes)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink));

  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].first, IntegerId{1});
  EXPECT_EQ(samples[0].second.value(), Variant{100});
}

TEST_F(SamplingEngineTest, ExceptionQueuedMultipleWritesAllPreservedInOrder)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink));

  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{200}});
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{300}});

  ASSERT_TRUE(sink->wait_for_samples(3));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 3u);
  EXPECT_EQ(samples[0].second.value(), Variant{100});
  EXPECT_EQ(samples[1].second.value(), Variant{200});
  EXPECT_EQ(samples[2].second.value(), Variant{300});
}

TEST_F(SamplingEngineTest, ExceptionQueuedZeroQueueSizeIsBoundedNotUnlimited)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  // queueSize 0 must NOT mean "unlimited": the engine floors the pending-queue bound to 1, so a burst
  // of writes collapses to the latest value (DiscardOldest) rather than buffering without limit. Before
  // the floor, maxPendingCount 0 disabled the bound and all five values would be delivered.
  auto result = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink, /*queueSize=*/0));

  for (int32_t v : {100, 200, 300, 400, 500})
  {
    mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{v}});
  }

  ASSERT_TRUE(sink->wait_for_samples(1));
  // The burst must stay bounded - far fewer than five delivered - and the most recent value survives.
  EXPECT_FALSE(sink->wait_for_samples(5, 200ms));
  auto samples = sink->samples();
  EXPECT_LT(samples.size(), 5u);
  ASSERT_FALSE(samples.empty());
  EXPECT_EQ(samples.back().second.value(), Variant{500});
}

TEST_F(SamplingEngineTest, ExceptionQueuedNoWriteNoPush)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink));

  // No attribute_changed call - nothing should be pushed.
  EXPECT_FALSE(sink->wait_for_samples(1, 200ms));
}

// ===== attribute_changed edge cases =====

TEST_F(SamplingEngineTest, AttributeChangedWithNoEntryIsNoOp)
{
  create_engine();
  // No entries registered - nothing is monitored on (ns=1;i=999, Value).
  mEngine->attribute_changed(NodeId{1, 999}, AttributeId::Value, DataValue{Variant{42}});
  // Should not crash.
}

TEST_F(SamplingEngineTest, AttributeChangedAfterShutdownIsNoOp)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));
  mEngine->shutdown();

  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  // Should not crash.
}

// ===== Mixed modes =====

TEST_F(SamplingEngineTest, MixedPolledAndExceptionInSameEngine)
{
  create_engine();
  auto nodeId1 = NodeId{1, 1000};
  auto nodeId2 = NodeId{1, 1001};
  auto node1 = create_variable_with_value(nodeId1, Variant{10});
  auto node2 = create_variable_with_value(nodeId2, Variant{20});

  auto sink1 = std::make_shared<TestSampleSink>();
  auto sink2 = std::make_shared<TestSampleSink>();

  // Polled entry
  mEngine->add_polled(make_polled(node1, nodeId1, 1, 50, sink1));

  // ExceptionLatest entry
  auto exResult = mEngine->add_exception_latest(make_exception(node2, nodeId2, 2, 50, sink2));

  // Polled should get value from reading.
  ASSERT_TRUE(sink1->wait_for_samples(1));
  EXPECT_EQ(sink1->samples()[0].second.value(), Variant{10});

  // ExceptionLatest needs a write notification.
  mEngine->attribute_changed(nodeId2, AttributeId::Value, DataValue{Variant{99}});
  ASSERT_TRUE(sink2->wait_for_samples(1));
  EXPECT_EQ(sink2->samples()[0].second.value(), Variant{99});
}

// ===== Unregister exception entries =====

TEST_F(SamplingEngineTest, RemoveExceptionEntryStopsPushes)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink));

  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{100}});
  ASSERT_TRUE(sink->wait_for_samples(1));

  mEngine->remove(result.handle);

  // Further writes should not cause pushes after removal.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{200}});
  EXPECT_FALSE(sink->wait_for_samples(2, 200ms));
}

TEST_F(SamplingEngineTest, ExceptionAfterShutdownReturnsZero)
{
  create_engine();
  mEngine->shutdown();

  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto result = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 100, sink));
  EXPECT_EQ(result.handle, 0u);

  auto result2 = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink));
  EXPECT_EQ(result2.handle, 0u);
}

// ===== Per-MI dispatch key tests =====

TEST_F(SamplingEngineTest, TwoEntriesSameNodeAreEachNotified)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink1 = std::make_shared<TestSampleSink>();
  auto sink2 = std::make_shared<TestSampleSink>();

  auto result1 = mEngine->add_exception_latest(make_exception(node, nodeId, 1, 50, sink1));
  auto result2 = mEngine->add_exception_latest(make_exception(node, nodeId, 2, 50, sink2));

  EXPECT_NE(result1.handle, result2.handle);

  // One change of the Node's Value reaches each MI on it.
  mEngine->attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{99}});

  ASSERT_TRUE(sink1->wait_for_samples(1));
  ASSERT_TRUE(sink2->wait_for_samples(1));

  EXPECT_EQ(sink1->samples()[0].second.value(), Variant{99});
  EXPECT_EQ(sink2->samples()[0].second.value(), Variant{99});
}

// ===== Write-path notification via VariableNode =====

// The in-memory write path reaches the engine through the monitoring helper of the namespace's
// registration: an item at interval 0 on a registered namespace's Variable is fed by the Node's write.
namespace
{

struct RegisteredVariable
{
  std::optional<AddressSpace> addressSpace;
  std::shared_ptr<default_ns::Namespace> ns;
  NodeId nodeId;
  std::shared_ptr<default_ns::VariableNode> node;
};

RegisteredVariable registered_variable(const boost::asio::any_io_executor& executor, Variant value)
{
  RegisteredVariable registered;
  registered.addressSpace.emplace(AddressSpace::create("urn:test:sampling-engine-write-path", executor));
  registered.ns = default_ns::Namespace::create("urn:test:sampling-engine-write-path:ns", executor);
  const auto added = registered.addressSpace->try_add_namespace_sync(registered.ns);
  EXPECT_TRUE(added.is_good());
  registered.nodeId = NodeId{added.is_good() ? added.value() : uint16_t{2}, 1000};
  registered.node = registered.ns->create_node<default_ns::VariableNode>(registered.nodeId);
  write_variable_value(registered.node, registered.nodeId, std::move(value));
  return registered;
}

bool monitor_at_interval_0(RegisteredVariable& registered, std::shared_ptr<SampleSink> sink)
{
  std::vector<MonitoringCreateItem> items{{.nodeId = registered.nodeId,
    .attributeId = AttributeId::Value,
    .monitoredItemId = 1,
    .samplingInterval = 0,
    .queueSize = 100,
    .sink = std::move(sink)}};
  BatchResult<MonitoringCreateItemResult> created;
  registered.ns->create_monitoring_async(RequestInfo{},
    nullptr,
    items,
    [&created](BatchResult<MonitoringCreateItemResult> result) { created = std::move(result); });
  return created.items.size() == 1u && created.items[0].is_good();
}

}  // namespace

TEST_F(SamplingEngineTest, VariableNodeWriteReachesTheItemThroughTheRegistrationsHelper)
{
  auto registered = registered_variable(mExecutor, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();
  ASSERT_TRUE(monitor_at_interval_0(registered, sink));

  // Write to the node - the node reports it to the helper -> engine -> sink.
  write_variable_value(registered.node, registered.nodeId, Variant{99});

  ASSERT_TRUE(sink->wait_for_samples(1));

  auto samples = sink->samples();
  ASSERT_GE(samples.size(), 1u);
  EXPECT_EQ(samples[0].second.value(), Variant{99});
}

TEST_F(SamplingEngineTest, VariableNodeFailedWriteIsNotReported)
{
  auto registered = registered_variable(mExecutor, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();
  ASSERT_TRUE(monitor_at_interval_0(registered, sink));
  auto& node = registered.node;
  const auto& nodeId = registered.nodeId;

  // Set a handler that rejects writes.
  node->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               callback) { callback(DataValue{Variant{42}}); },
    [](const ValueSource::WriteContext&,
      const Node&,
      const WriteValue&,
      std::function<void(ValueSource::WriteResult)>
        callback) { callback(ValueSource::WriteResult{StatusCode{Status::BadNotWritable}}); }));

  // Write to the node - handler rejects, nothing is reported.
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{Variant{99}};

  VoidResult writeResult{StatusCode{Status::BadInternalError}};
  node->write_value_async(writeVal, nullptr, [&writeResult](VoidResult r) { writeResult = std::move(r); });
  EXPECT_FALSE(writeResult.is_good());

  // No sample should arrive since the write was rejected.
  EXPECT_FALSE(sink->wait_for_samples(1, 200ms));
}

// ===== modify() tests =====

TEST_F(SamplingEngineTest, ModifyIntervalMovesToNewBucket)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto addResult = mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));
  EXPECT_DOUBLE_EQ(addResult.revisedInterval, 50);

  default_ns::SamplingEngine::ModifyRegistration reg;
  reg.requestedInterval = 500;
  reg.queueSize = 1;

  auto modResult = mEngine->modify(addResult.handle, reg);

  EXPECT_DOUBLE_EQ(modResult.revisedInterval, 500);
  EXPECT_EQ(modResult.kind, default_ns::SamplingKind::Polled);
}

TEST_F(SamplingEngineTest, ModifyQueueSizeUpdated)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto addResult = mEngine->add_exception_queued(make_exception(node, nodeId, 1, 0, sink, 10));

  default_ns::SamplingEngine::ModifyRegistration reg;
  reg.requestedInterval = 0;
  reg.queueSize = 20;
  reg.delivery = default_ns::SamplingEngine::Delivery::Reported;

  auto modResult = mEngine->modify(addResult.handle, reg);

  // Should remain ExceptionQueued with revised interval 0.
  EXPECT_DOUBLE_EQ(modResult.revisedInterval, 0);
  EXPECT_EQ(modResult.kind, default_ns::SamplingKind::ExceptionQueued);
}

TEST_F(SamplingEngineTest, ModifyAfterShutdownReturnsZero)
{
  create_engine();
  auto nodeId = NodeId{1, 1000};
  auto node = create_variable_with_value(nodeId, Variant{42});
  auto sink = std::make_shared<TestSampleSink>();

  auto addResult = mEngine->add_polled(make_polled(node, nodeId, 1, 50, sink));
  mEngine->shutdown();

  default_ns::SamplingEngine::ModifyRegistration reg;
  reg.requestedInterval = 500;
  reg.queueSize = 1;

  auto modResult = mEngine->modify(addResult.handle, reg);

  EXPECT_DOUBLE_EQ(modResult.revisedInterval, 0);
}

TEST_F(SamplingEngineTest, ModifyNonExistentHandleReturnsZero)
{
  create_engine();

  default_ns::SamplingEngine::ModifyRegistration reg;
  reg.requestedInterval = 500;
  reg.queueSize = 1;

  auto modResult = mEngine->modify(12345, reg);

  EXPECT_DOUBLE_EQ(modResult.revisedInterval, 0);
}

// Pins the section 8.2 mutex-only design: bucket ticks for distinct buckets fire on the
// pool concurrently and serialise their state access through mMutex while reads and
// sink pushes parallelise. A future regression that reintroduces shared bucket
// state, drops the lock from snapshot/writeback, or makes Node::read_value or
// SampleSink::push non-thread-safe would race here under TSan.
TEST_F(SamplingEngineTest, ConcurrentTicksAndPushesDoNotRace)
{
  create_engine();

  constexpr size_t polledNodeCount = 8;
  constexpr size_t queuedNodeCount = 8;

  // Bucket A: polled entries at the smallest interval (50ms).
  std::vector<std::shared_ptr<default_ns::VariableNode>> polledNodes;
  std::vector<std::shared_ptr<TestSampleSink>> polledSinks;
  for (size_t i = 0; i < polledNodeCount; ++i)
  {
    auto nodeId = NodeId{1, static_cast<uint32_t>(2000 + i)};
    polledNodes.push_back(create_variable_with_value(nodeId, Variant{static_cast<int32_t>(i)}));
    auto sink = std::make_shared<TestSampleSink>();
    polledSinks.push_back(sink);
    mEngine->add_polled(
      make_polled(polledNodes.back(), nodeId, IntegerId{static_cast<uint32_t>(i + 1)}, 50, sink));
  }

  // Bucket B: ExceptionQueued entries (10ms internal batch interval).
  std::vector<std::shared_ptr<default_ns::VariableNode>> queuedNodes;
  std::vector<std::shared_ptr<TestSampleSink>> queuedSinks;
  std::vector<NodeId> queuedNodeIds;
  for (size_t i = 0; i < queuedNodeCount; ++i)
  {
    auto nodeId = NodeId{1, static_cast<uint32_t>(3000 + i)};
    queuedNodes.push_back(create_variable_with_value(nodeId, Variant{static_cast<int32_t>(i)}));
    auto sink = std::make_shared<TestSampleSink>();
    queuedSinks.push_back(sink);
    auto added = mEngine->add_exception_queued(
      make_exception(queuedNodes.back(), nodeId, IntegerId{static_cast<uint32_t>(100 + i)}, 0, sink, 32));
    ASSERT_GT(added.handle, 0u);
    queuedNodeIds.push_back(nodeId);
  }

  // Two pusher threads slamming attribute_changed concurrently with ticks.
  std::atomic<bool> stop{false};
  auto pusher = [&](int seed)
  {
    int counter = seed;
    while (!stop.load(std::memory_order_relaxed))
    {
      for (size_t i = 0; i < queuedNodeIds.size(); ++i)
      {
        DataValue v;
        v.value() = Variant{counter++};
        mEngine->attribute_changed(queuedNodeIds[i], AttributeId::Value, v);
      }
      std::this_thread::yield();
    }
  };
  std::thread pusher1(pusher, 100000);
  std::thread pusher2(pusher, 200000);

  // Let the buckets tick and the pushers run for a few cycles.
  for (auto& sink : polledSinks)
  {
    EXPECT_TRUE(sink->wait_for_samples(1));
  }
  for (auto& sink : queuedSinks)
  {
    EXPECT_TRUE(sink->wait_for_samples(1));
  }

  stop.store(true, std::memory_order_relaxed);
  pusher1.join();
  pusher2.join();

  // Engine teardown must be clean despite in-flight pushers having just exited.
  mEngine->shutdown();
}

}  // namespace
