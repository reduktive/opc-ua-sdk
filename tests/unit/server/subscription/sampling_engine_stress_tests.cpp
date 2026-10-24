// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Robustness/profiling tests for SamplingEngine under large monitored-item
// counts. These exercise the 5000-item regime that the UACTT Subscription
// Basic CU drives (MAXMONITOREDITEMLIMITS) and assert the engine stays
// serviceable, makes forward progress, and tears down promptly under load.

#include <gtest/gtest.h>

// AddressSanitizer detection. Under ASan, detect_stack_use_after_return (on by
// default in modern GCC/Clang) relocates function frames onto a heap-allocated
// "fake stack", so taking the address of a local no longer yields a meaningful
// stack offset - see InlineReadsDoNotGrowTheStackPerItem.
#if defined(__SANITIZE_ADDRESS__)
#define UA_TEST_ASAN_ACTIVE 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UA_TEST_ASAN_ACTIVE 1
#endif
#endif

#include "node_value_reader.h"
#include "test_utilities.h"

#include "ua_sampling_engine.h"

#include "ua_default_variable_node.h"
#include "ua_value_source.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_write_value.h"

#include "batch_recording_namespace.h"
#include "ua_address_space.h"
#include "ua_namespace_monitoring.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <time.h>
#endif

using namespace ua;
using namespace std::chrono_literals;

namespace
{

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point start)
{
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

/// The work this thread has done so far: CPU nanoseconds on POSIX, CPU cycles on Windows (whose thread CPU
/// time is counted in scheduler ticks of about 15 ms). Only ratios of two readings are meaningful. Unlike
/// wall time, it does not grow while the thread is descheduled, so a busy host does not inflate it.
double thread_work()
{
#if defined(_WIN32)
  ULONG64 cycles = 0;
  QueryThreadCycleTime(GetCurrentThread(), &cycles);
  return static_cast<double>(cycles);
#else
  timespec now{};
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
  return static_cast<double>(now.tv_sec) * 1e9 + static_cast<double>(now.tv_nsec);
#endif
}

/// Sink that counts pushes and total samples across all monitored items.
class CountingSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    mPushes.fetch_add(1, std::memory_order_relaxed);
    mSamples.fetch_add(samples.size(), std::memory_order_relaxed);
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {
    detached.store(true);
  }

  uint64_t pushes() const
  {
    return mPushes.load();
  }

  uint64_t samples() const
  {
    return mSamples.load();
  }

  std::atomic<bool> detached{false};

private:
  std::atomic<uint64_t> mPushes{0};
  std::atomic<uint64_t> mSamples{0};
};

std::shared_ptr<default_ns::VariableNode> make_node(const NodeId& nodeId, int32_t value)
{
  auto node = default_ns::VariableNode::create(nodeId);
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{Variant{value}};
  VoidResult result{StatusCode{Status::BadInternalError}};
  node->write_value_async(writeVal, nullptr, [&result](VoidResult r) { result = std::move(r); });
  EXPECT_TRUE(result.is_good());
  return node;
}

void write_node(const std::shared_ptr<default_ns::VariableNode>& node, const NodeId& nodeId, int32_t value)
{
  WriteValue writeVal;
  writeVal.node_id() = nodeId;
  writeVal.attribute_id() = utils::to_underlying(AttributeId::Value);
  writeVal.value() = DataValue{Variant{value}};
  VoidResult result{StatusCode{Status::BadInternalError}};
  node->write_value_async(writeVal, nullptr, [&result](VoidResult r) { result = std::move(r); });
}

class SamplingEngineStressTest : public ::testing::Test
{
protected:
  void TearDown() override
  {
    if (mEngine)
    {
      mEngine->shutdown();
    }
    mEngine.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  // Mirror the compliance server: a shared thread pool drives both sampling
  // and (in the real server) every other strand. A small pool makes
  // monopolisation observable.
  boost::asio::thread_pool mThreadPool{4};
  std::shared_ptr<default_ns::SamplingEngine> mEngine;
  std::vector<std::shared_ptr<default_ns::VariableNode>> mNodes;
};

// 5000 polled items on the fastest bucket. The engine must (a) register them
// quickly, (b) keep delivering change notifications, and (c) remain able to
// service a fresh add/remove probe while fully loaded - i.e. not monopolise
// the pool such that unrelated work starves.
TEST_F(SamplingEngineStressTest, FiveThousandPolledItemsStayServiceable)
{
  constexpr size_t itemCount = 5000;
  mEngine = std::make_shared<default_ns::SamplingEngine>(
    mThreadPool.get_executor(), test_utils::node_value_reader(mThreadPool.get_executor()));
  auto sink = std::make_shared<CountingSink>();

  mNodes.reserve(itemCount);
  std::vector<MonitoringHandle> handles;
  handles.reserve(itemCount);

  const auto registerStart = Clock::now();
  for (size_t i = 0; i < itemCount; ++i)
  {
    NodeId nodeId{1, static_cast<uint32_t>(1000 + i)};
    auto node = make_node(nodeId, 0);
    default_ns::SamplingEngine::PolledRegistration reg;
    reg.node = node;
    reg.nodeId = nodeId;
    reg.monitoredItemId = static_cast<IntegerId>(i + 1);
    reg.requestedInterval = 50;  // fastest bucket
    reg.sink = sink;
    auto result = mEngine->add_polled(std::move(reg));
    ASSERT_GT(result.handle, 0u);
    handles.push_back(result.handle);
    mNodes.push_back(std::move(node));
  }
  const double registerMs = ms_since(registerStart);

  // Drive change: flip every node's value so each tick has work to push.
  for (size_t i = 0; i < itemCount; ++i)
  {
    write_node(mNodes[i], NodeId{1, static_cast<uint32_t>(1000 + i)}, 1);
  }

  // Let several 50ms ticks elapse and confirm forward progress.
  std::this_thread::sleep_for(400ms);
  const uint64_t samplesAfterChange = sink->samples();
  EXPECT_GT(samplesAfterChange, 0u) << "engine made no forward progress under load";

  // Responsiveness probe: under full 5000-item load, a fresh add+remove must
  // complete promptly (the public API is mutex-guarded, never blocked behind
  // a tick). Measure wall-clock for a probe registration.
  const auto probeStart = Clock::now();
  NodeId probeId{1, 999999};
  auto probeNode = make_node(probeId, 7);
  default_ns::SamplingEngine::PolledRegistration probe;
  probe.node = probeNode;
  probe.nodeId = probeId;
  probe.monitoredItemId = 999999;
  probe.requestedInterval = 50;
  probe.sink = sink;
  auto probeResult = mEngine->add_polled(std::move(probe));
  mEngine->remove(probeResult.handle);
  const double probeMs = ms_since(probeStart);

  // Bulk teardown must be prompt.
  const auto removeStart = Clock::now();
  for (auto handle : handles)
  {
    mEngine->remove(handle);
  }
  const double removeMs = ms_since(removeStart);

  std::printf(
    "[stress] register=%.1fms probe(add+remove)=%.3fms remove5000=%.1fms samples=%llu pushes=%llu\n",
    registerMs,
    probeMs,
    removeMs,
    static_cast<unsigned long long>(sink->samples()),
    static_cast<unsigned long long>(sink->pushes()));

  // The probe must not be stuck behind a multi-ms tick holding the lock for
  // its whole duration. A generous ceiling still catches gross monopolisation.
  EXPECT_LT(probeMs, 500.0) << "engine unresponsive under load - public op blocked behind a tick";
  EXPECT_GT(probeResult.handle, 0u);
  // (removeMs asserted for complexity in BulkRemovalScalesLinearly below.)
}

// 5000 exception-queued (interval 0) value items - the snapshot-heavy path.
// Every 10ms internal tick snapshots all entries; with writes flowing this is
// the worst case for lock hold time. Assert forward progress + prompt teardown.
TEST_F(SamplingEngineStressTest, FiveThousandExceptionItemsDeliverAndTearDown)
{
  constexpr size_t itemCount = 5000;
  mEngine = std::make_shared<default_ns::SamplingEngine>(
    mThreadPool.get_executor(), test_utils::node_value_reader(mThreadPool.get_executor()));
  auto sink = std::make_shared<CountingSink>();

  mNodes.reserve(itemCount);
  std::vector<MonitoringHandle> handles;
  std::vector<NodeId> nodeIds;
  handles.reserve(itemCount);
  nodeIds.reserve(itemCount);

  for (size_t i = 0; i < itemCount; ++i)
  {
    NodeId nodeId{1, static_cast<uint32_t>(1000 + i)};
    auto node = make_node(nodeId, 0);
    default_ns::SamplingEngine::ExceptionRegistration reg;
    reg.node = node;
    reg.nodeId = nodeId;
    reg.monitoredItemId = static_cast<IntegerId>(i + 1);
    reg.requestedInterval = 0;
    reg.queueSize = 10;
    reg.sink = sink;
    auto result = mEngine->add_exception_queued(std::move(reg));
    ASSERT_GT(result.handle, 0u);
    handles.push_back(result.handle);
    nodeIds.push_back(nodeId);
    mNodes.push_back(std::move(node));
  }

  // Push a value into every item via the write path.
  for (size_t i = 0; i < itemCount; ++i)
  {
    mEngine->attribute_changed(
      nodeIds[i], AttributeId::Value, DataValue{Variant{static_cast<int32_t>(i + 1)}});
  }

  std::this_thread::sleep_for(200ms);
  EXPECT_GT(sink->samples(), 0u) << "exception-queued items delivered nothing";

  const auto removeStart = Clock::now();
  for (auto handle : handles)
  {
    mEngine->remove(handle);
  }
  const double removeMs = ms_since(removeStart);
  std::printf("[stress] exception remove5000=%.1fms samples=%llu\n",
    removeMs,
    static_cast<unsigned long long>(sink->samples()));
}

// Complexity guard (machine-independent): removing all items from a single
// bucket must scale linearly, not quadratically. The pre-fix vector membership
// erased each handle with a linear scan, making full teardown O(N^2); the set
// makes it O(N). Measuring two sizes and asserting the ratio tracks the size
// ratio (~4x, not ~16x) catches a regression without depending on absolute
// wall-clock - both measurements stretch together under load.
// Not compiled under AddressSanitizer:
// This is a wall-clock timing-ratio test. SamplingEngine::remove() is O(1)
// average - mEntries/mDispatchIndex are unordered_map, the bucket's membership
// set is unordered_set, and the handles are sequential uint32_t with identity
// hashing - so bulk removal is O(N). Under AddressSanitizer the instrumented
// allocator perturbs this free-heavy loop super-linearly, inflating the 4x-size
// ratio into the "quadratic" zone and tripping the bound spuriously. The O(N)
// scaling this guards is verified by every non-instrumented build (gcc/clang,
// 32- and 64-bit unit jobs), where the ratio stays well under the bound.
#ifndef UA_TEST_ASAN_ACTIVE
TEST_F(SamplingEngineStressTest, BulkRemovalScalesLinearly)
{
  // Register `count` items in ONE bucket on a shared node, then measure the work
  // of removing them all. A 60s bucket guarantees no tick fires during the
  // measurement, so it isolates membership-removal cost. Returns the removing
  // thread's work (see thread_work): wall time also counted the time the thread
  // spent descheduled, and on a shared host a 4x set once measured 21x.
  auto measureRemoval = [this](size_t count) -> double
  {
    auto engine = std::make_shared<default_ns::SamplingEngine>(
      mThreadPool.get_executor(), test_utils::node_value_reader(mThreadPool.get_executor()));
    NodeId nodeId{1, 5555};
    auto node = make_node(nodeId, 0);
    auto sink = std::make_shared<CountingSink>();

    std::vector<MonitoringHandle> handles;
    handles.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      default_ns::SamplingEngine::PolledRegistration reg;
      reg.node = node;
      reg.nodeId = nodeId;
      reg.monitoredItemId = static_cast<IntegerId>(i + 1);
      reg.requestedInterval = 60000;  // single far-future bucket; no ticks fire
      reg.sink = sink;
      handles.push_back(engine->add_polled(std::move(reg)).handle);
    }

    const double start = thread_work();
    for (auto handle : handles)
    {
      engine->remove(handle);
    }
    const double work = thread_work() - start;
    engine->shutdown();
    return work;
  };

  // Sizes large enough that each measurement is tens of milliseconds of CPU, and the least of three runs, so
  // a cache or allocator hiccup in one run does not decide the ratio.
  constexpr size_t smallCount = 20000;
  constexpr size_t large = 80000;  // 4x the size
  auto leastOfThree = [&measureRemoval](size_t count)
  {
    return std::min({measureRemoval(count), measureRemoval(count), measureRemoval(count)});
  };
  // Warm up to avoid first-touch allocator skew biasing the ratio.
  measureRemoval(smallCount);
  const double smallWork = leastOfThree(smallCount);
  const double largeWork = leastOfThree(large);

  const double ratio = largeWork / std::max(smallWork, 1.0);
  std::printf(
    "[stress] removal scaling (thread work): %zu=%.0f %zu=%.0f ratio=%.1f (linear~4, quadratic~16)\n",
    smallCount,
    smallWork,
    large,
    largeWork,
    ratio);

  // Linear removal of a 4x set takes ~4x plus cache/allocator overhead (~7x
  // observed). A quadratic regression lands near 16x; 11x separates the two
  // with headroom for slower hardware. The max() floor guards against a
  // near-zero smallWork inflating the ratio.
  EXPECT_LT(ratio, 11.0) << "bulk removal is super-linear - O(N^2) bucket membership regression";
}
#endif  // UA_TEST_ASAN_ACTIVE

// Stack-depth bound (deterministic, machine-independent): a bucket holding many Sampled items of a registered
// namespace whose reads complete INLINE must be read without one stack frame per item anywhere on the path
// from the tick into the namespace - the helper's reader, the address space's route and the namespace's
// read_values_async, which here is the Namespace default answering item by item through each Node's
// read_value. Each Node has a read handler that records the address of a local stack variable at the moment
// it runs; across all per-item reads in one tick the spread between the shallowest and deepest sample reveals
// the recursion depth. Without recursion it is a small constant regardless of item count; a per-item
// recursion grows it ~linearly with N (and eventually overflows the stack and crashes the server outright -
// observed in the field under the UACTT Subscription CU). Not compiled under AddressSanitizer: This test
// detects per-item stack recursion by measuring the address span of a stack local (&stackProbe) across many
// inline reads. Under AddressSanitizer, detect_stack_use_after_return places each frame's locals on a
// heap-based fake stack, so those addresses are unrelated heap pointers rather than monotonic stack offsets -
// the measured span balloons to ~1 MB of noise regardless of the (correct, loop-based) read path. The
// loop-not-recursion property this guards is verified by every non-instrumented build (gcc/clang, 32- and
// 64-bit).
#ifndef UA_TEST_ASAN_ACTIVE
TEST_F(SamplingEngineStressTest, InlineReadsDoNotGrowTheStackPerItem)
{
  constexpr size_t itemCount = 500;
  auto sink = std::make_shared<CountingSink>();

  // Key the depth window by thread: a 50ms bucket ticks several times over the
  // measurement window and successive ticks may land on different pool threads
  // whose stacks are megabytes apart. Within ONE thread, every inline read of a
  // single tick (and every later tick) runs at the same depth, so the
  // per-thread span is what reveals recursion.
  //
  // The probe state is shared_ptr-owned and captured by value into every read
  // handler: a bucket tick can still fire between the measurement and the
  // address space's shutdown, so the state must outlive the test locals.
  struct Probe
  {
    std::mutex mutex;
    std::map<std::thread::id, std::pair<uintptr_t, uintptr_t>> window;  // tid -> {min,max}
    size_t reads{0};
  };

  auto probe = std::make_shared<Probe>();

  auto addressSpace = AddressSpace::create("urn:test:sampling-stress", mThreadPool.get_executor());
  auto nameSpace = std::make_shared<ua::test::BatchRecordingNamespace>(
    "urn:test:sampling-stress:n", mThreadPool.get_executor());
  const uint16_t index = addressSpace.add_namespace_sync(nameSpace);

  std::vector<MonitoringCreateItem> items;
  items.reserve(itemCount);
  for (size_t i = 0; i < itemCount; ++i)
  {
    NodeId nodeId{index, static_cast<uint32_t>(1000 + i)};
    auto node = nameSpace->create_node<default_ns::VariableNode>(nodeId);
    ASSERT_NE(node, nullptr);
    // Inline-completing read handler that snapshots the current stack depth.
    node->set_value_source(make_value_source(
      [probe](const ValueSource::ReadContext&,
        const Node&,
        const ReadValueId&,
        std::function<void(DataValueResult)>
          callback)
      {
        char stackProbe = 0;
        auto here = reinterpret_cast<uintptr_t>(&stackProbe);
        {
          std::lock_guard<std::mutex> lock(probe->mutex);
          auto& window = probe->window[std::this_thread::get_id()];
          if (window.second == 0)  // freshly default-inserted {0,0}
          {
            window = {here, here};
          }
          window.first = std::min(window.first, here);
          window.second = std::max(window.second, here);
          ++probe->reads;
        }
        callback(DataValue{Variant{int32_t{1}}});
      },
      [](const ValueSource::WriteContext&,
        const Node&,
        const WriteValue&,
        std::function<void(ValueSource::WriteResult)>
          cb) { cb(ValueSource::Written{}); }));

    items.push_back(MonitoringCreateItem{.nodeId = nodeId,
      .node = node,
      .attributeId = AttributeId::Value,
      .monitoredItemId = static_cast<IntegerId>(i + 1),
      .samplingInterval = 50,  // all in one bucket; one tick reads all N
      .queueSize = 1,
      .sink = sink});
  }
  const auto created = nameSpace->create_sampled(items);
  ASSERT_EQ(created.size(), itemCount);
  ASSERT_TRUE(
    std::all_of(created.begin(), created.end(), [](const auto& item) { return item.result.is_good(); }))
    << "a registration was refused";

  // Let at least one full bucket tick read every item.
  std::this_thread::sleep_for(200ms);

  uintptr_t span = 0;
  size_t observedReads = 0;
  {
    std::lock_guard<std::mutex> lock(probe->mutex);
    ASSERT_GT(probe->reads, 0u) << "no reads ran - tick never fired";
    for (const auto& [tid, window] : probe->window)
    {
      span = std::max(span, window.second - window.first);
    }
    observedReads = probe->reads;
  }

  std::printf("[stress] inline-read stack span=%zu bytes over %zu reads (~%.1f bytes/item)\n",
    static_cast<size_t>(span),
    observedReads,
    static_cast<double>(span) / static_cast<double>(itemCount));

  // Without recursion every inline read runs at the same depth: the span is a few
  // hundred bytes of handler locals, flat in N. A per-item recursion would put
  // >=hundreds of bytes between consecutive items - for 500 items, tens to
  // hundreds of KB. 32 KB cleanly separates the two and tolerates the small
  // jitter from reads that happen to land on different pool threads.
  EXPECT_LT(span, 32u * 1024u)
    << "inline reads grow the stack per item - the tick's read path recurses instead of looping";
}
#endif  // UA_TEST_ASAN_ACTIVE

// Liveness: the per-bucket tickInFlight guard must be released at the end of
// every cycle, not latched after the first. A continuously-mutated item on the
// fastest bucket must therefore deliver across many cycles. If the guard ever
// stuck true, delivery would freeze after a single push.
TEST_F(SamplingEngineStressTest, TickGuardReleasedEveryCycle)
{
  mEngine = std::make_shared<default_ns::SamplingEngine>(
    mThreadPool.get_executor(), test_utils::node_value_reader(mThreadPool.get_executor()));
  auto sink = std::make_shared<CountingSink>();

  NodeId nodeId{1, 4242};
  auto node = make_node(nodeId, 0);
  default_ns::SamplingEngine::PolledRegistration reg;
  reg.node = node;
  reg.nodeId = nodeId;
  reg.monitoredItemId = 1;
  reg.requestedInterval = 50;  // 50ms bucket
  reg.sink = sink;
  auto result = mEngine->add_polled(std::move(reg));
  ASSERT_GT(result.handle, 0u);
  mNodes.push_back(node);

  // Mutate the value faster than the bucket period so every tick has a fresh
  // change to detect and push. Over ~600ms of 50ms ticks we expect ~10+ pushes;
  // assert a conservative floor that a latched guard (1 push) would fail.
  const auto deadline = Clock::now() + 600ms;
  int32_t next = 1;
  while (Clock::now() < deadline)
  {
    write_node(node, nodeId, next++);
    std::this_thread::sleep_for(20ms);
  }

  std::printf("[stress] guard-liveness pushes=%llu over ~600ms@50ms\n",
    static_cast<unsigned long long>(sink->pushes()));
  EXPECT_GE(sink->pushes(), 5u) << "tick guard latched - delivery froze after the first cycle";

  mEngine->remove(result.handle);
}

}  // namespace
