// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// section 8.2 Hazard 3 regression - the SamplingEngine bucket tick must
// tolerate a Node::read_value implementation whose completion callback
// fires asynchronously (after the synchronous return path).
//
// Pre-fix the read phase declared a stack-local DataValue and captured
// it by reference; an async callback would dangle that reference. The
// fix is BucketTickOperation - a per-tick flow that owns the snapshot
// vector for the lifetime of the read phase and finalises only after
// all reads complete.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_data_value.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_namespace_monitoring.h"
#include "ua_sinks.h"
#include "ua_value_source.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_write_value.h"

#include <optional>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

class CountingSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    std::lock_guard lock{mMutex};
    for (auto& sample : samples)
    {
      mSamples.push_back(std::move(sample));
    }
    mCv.notify_all();
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  bool wait_for_samples(size_t count, std::chrono::milliseconds timeout = 5000ms)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mSamples.size() >= count; });
  }

  std::vector<std::pair<IntegerId, DataValue>> samples()
  {
    std::lock_guard lock{mMutex};
    return mSamples;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
};

// A SampleSink whose push() always throws after recording the attempt. SampleSink::push is invoked
// from inside an Asio completion handler (the bucket-timer notifier / posted read continuation), so a
// throw that escapes finalise_bucket_tick would unwind out of io_context::run() -> std::terminate. The
// engine must contain it (invoke_user_callback) and keep ticking.
class ThrowingSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>>) override
  {
    {
      std::lock_guard lock{mMutex};
      ++mPushes;
    }
    mCv.notify_all();
    throw std::runtime_error("sink push failure");
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  bool wait_for_pushes(int count, std::chrono::milliseconds timeout = 5000ms)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mPushes >= count; });
  }

private:
  std::mutex mMutex;
  std::condition_variable mCv;
  int mPushes{0};
};

}  // namespace

// Install an ExternalValueSource read handler that defers its callback
// onto a worker thread (one strand turn of latency). Drive a polled
// monitoring entry through the SamplingEngine and assert the eventual
// sink push contains the staged value. Pre-fix this would either crash
// (UB on the dangling stack reference) or push a zero-initialised value;
// post-fix the heap-owned snapshot survives the latency window.
TEST(SamplingEngineAsyncRead, AsyncReadHandlerCompletesBucketTick)
{
  boost::asio::thread_pool tp{2};
  std::optional<AddressSpace> addressSpace;
  addressSpace.emplace(AddressSpace::create("urn:test:hazard3-host", tp.get_executor()));
  auto ns = default_ns::Namespace::create("uri://hazard3", tp.get_executor());
  const auto registered = addressSpace->try_add_namespace_sync(ns);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());

  NodeId nodeId{registered.value(), "asyncvar"};
  auto node = ns->create_node<default_ns::VariableNode>(nodeId);

  // Seed an initial value via a sync write so that comparison against
  // mLastPushedValue produces a change on the first bucket tick.
  WriteValue initial;
  initial.node_id() = nodeId;
  initial.attribute_id() = utils::to_underlying(AttributeId::Value);
  initial.value() = DataValue{Variant{int32_t{0}}};
  std::atomic<bool> initialWritten{false};
  node->write_value_async(initial, nullptr, [&initialWritten](VoidResult) mutable { initialWritten = true; });
  while (!initialWritten.load())
  {
    std::this_thread::sleep_for(100us);
  }

  // Async read handler: posts the callback completion to a detached
  // worker thread that runs after on_bucket_tick has already returned.
  // Shared-ptr counters so detached workers outliving this scope don't UAF.
  auto readsRequested = std::make_shared<std::atomic<int>>(0);
  auto readsDelivered = std::make_shared<std::atomic<int>>(0);
  // Workers still delivering. Each posts its answer onto the engine's strand, so the test waits for
  // them before the pool goes: one still sleeping would post onto a destroyed executor and corrupt
  // whatever the next test allocates there. Counted before the stop check, so a wait that has already
  // seen zero also sees the stop.
  auto readsInFlight = std::make_shared<std::atomic<int>>(0);
  auto readsStopped = std::make_shared<std::atomic<bool>>(false);
  const auto waitForReads = [readsInFlight, readsStopped]
  {
    readsStopped->store(true);
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (readsInFlight->load() != 0 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(readsInFlight->load(), 0) << "a delayed read never finished delivering";
  };

  // Also on an early return from a failed assertion: destroyed before the pool it outlives.
  struct ReadsGuard
  {
    std::function<void()> wait;

    ~ReadsGuard()
    {
      wait();
    }
  } readsGuard{waitForReads};

  node->set_value_source(make_value_source(
    [readsRequested, readsDelivered, readsInFlight, readsStopped](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        complete)
    {
      readsRequested->fetch_add(1);
      readsInFlight->fetch_add(1);
      if (readsStopped->load())
      {
        readsInFlight->fetch_sub(1);
        complete(DataValueResult{StatusCode{Status::BadShutdown}});
        return;
      }
      // Move the callback onto a detached worker thread that introduces a
      // small delay before delivery - simulates a database fetch / executor
      // hop. This is the scenario where the pre-fix code would dangle the
      // stack `currentValue` reference.
      std::thread{[complete = std::move(complete), readsDelivered, readsInFlight]() mutable
        {
          std::this_thread::sleep_for(15ms);
          DataValue dv;
          dv.value() = Variant{int32_t{42}};
          dv.source_timestamp() = DateTime::now();
          // Record delivery BEFORE invoking complete(): complete() pushes the value to the sink,
          // which wakes the waiter (wait_for_samples) on the main thread, and the waiter then reads
          // readsDelivered at the assertion. Incrementing after complete() races the woken main
          // thread - observed as a flake where readsDelivered == 0 at line 166 even though the
          // sample arrived (wait_for_samples passed). Order the increment before the delivery that
          // releases the waiter so the counter is deterministically visible.
          readsDelivered->fetch_add(1);
          {
            // Released before the count drops: the completion holds the engine's strand.
            auto done = std::move(complete);
            done(std::move(dv));
          }
          readsInFlight->fetch_sub(1);
        }}
        .detach();
    }));

  auto sink = std::make_shared<CountingSink>();

  // Polled monitoring with a non-zero sampling interval - forces the
  // entry into the polled bucket where on_bucket_tick issues a real
  // read_value. 50ms is the smallest default bucket.
  MonitoringCreateItem item;
  item.nodeId = nodeId;
  item.attributeId = AttributeId::Value;
  item.monitoredItemId = 1;
  item.samplingInterval = 50;
  item.queueSize = 1;
  item.sink = sink;

  std::vector<MonitoringCreateItem> items{std::move(item)};

  std::atomic<bool> created{false};
  ns->create_monitoring_async(RequestInfo{},
    nullptr,
    items,

    [&created](BatchResult<MonitoringCreateItemResult>) mutable { created = true; });
  while (!created.load())
  {
    std::this_thread::sleep_for(100us);
  }

  // Wait for the bucket tick to issue at least one read AND for the
  // sink to receive the staged value. With the fix the BucketTickOperation
  // heap-allocates the snapshot so the 15ms-delayed read callback
  // completes against valid storage and the sink receives the value.
  ASSERT_TRUE(sink->wait_for_samples(1));

  auto pushed = sink->samples();
  ASSERT_FALSE(pushed.empty());
  EXPECT_EQ(pushed[0].first, IntegerId{1});
  EXPECT_EQ(pushed[0].second.value().as<int32_t>(), 42);

  EXPECT_GT(readsRequested->load(), 0);
  EXPECT_GT(readsDelivered->load(), 0);

  // Drop executor-pinned refs before draining: the namespace holds the
  // strand, sink holds a callback chain that captured the executor, etc.
  waitForReads();

  sink.reset();
  ns.reset();
  addressSpace.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Stage 3b #2: a user-supplied SampleSink::push that throws must be contained inside
// finalise_bucket_tick (invoke_user_callback), never escape the bucket-tick Asio handler ->
// std::terminate. The engine must survive the first throwing push and keep ticking, so a second value
// change still reaches the sink. Pre-fix the first throwing push aborts the process.
TEST(SamplingEngineAsyncRead, ThrowingSinkPushIsContainedAndEngineKeepsTicking)
{
  boost::asio::thread_pool tp{2};
  std::optional<AddressSpace> addressSpace;
  addressSpace.emplace(AddressSpace::create("urn:test:throwingsink-host", tp.get_executor()));
  auto ns = default_ns::Namespace::create("uri://throwingsink", tp.get_executor());
  const auto registered = addressSpace->try_add_namespace_sync(ns);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());

  NodeId nodeId{registered.value(), "throwvar"};
  auto node = ns->create_node<default_ns::VariableNode>(nodeId);

  auto writeValueSync = [&](int32_t payload)
  {
    WriteValue wv;
    wv.node_id() = nodeId;
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value() = DataValue{Variant{payload}};
    std::atomic<bool> written{false};
    node->write_value_async(wv, nullptr, [&written](VoidResult) mutable { written = true; });
    while (!written.load())
    {
      std::this_thread::sleep_for(100us);
    }
  };

  writeValueSync(0);  // seed so the first tick sees a change vs the unset lastPushedValue

  auto sink = std::make_shared<ThrowingSink>();

  MonitoringCreateItem item;
  item.nodeId = nodeId;
  item.attributeId = AttributeId::Value;
  item.monitoredItemId = 1;
  item.samplingInterval = 50;
  item.queueSize = 1;
  item.sink = sink;

  std::vector<MonitoringCreateItem> items{std::move(item)};
  std::atomic<bool> created{false};
  ns->create_monitoring_async(RequestInfo{},
    nullptr,
    items,
    [&created](BatchResult<MonitoringCreateItemResult>) mutable { created = true; });
  while (!created.load())
  {
    std::this_thread::sleep_for(100us);
  }

  // First tick delivers value 0 to the sink, which throws. The throw must be swallowed (no terminate).
  ASSERT_TRUE(sink->wait_for_pushes(1)) << "the bucket tick must have attempted a push";

  // Engine survived the throw and is still ticking: a second value change must reach the sink again.
  writeValueSync(7);
  EXPECT_TRUE(sink->wait_for_pushes(2))
    << "the engine must keep ticking after a throwing sink push (the throw was contained)";

  sink.reset();
  ns.reset();
  addressSpace.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}
