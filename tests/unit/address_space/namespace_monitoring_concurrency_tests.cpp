// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// section 8.2 monitoring hazard regression tests for the default Namespace's
// monitoring path. Each test below targets exactly one of the three hazards
// described in migration plan (deleted)
//
//   Hazard 1: NamespaceMonitoringSupport::mRecords concurrent races
//             - TSan-targeted: two threads concurrently driving
//               create_monitoring / delete_monitoring against the same
//               Namespace.
//   Hazard 2: write-notifier UAF on Namespace destruction during write
//             - ASan-targeted: install a notifier; trigger writes; destroy
//               the Namespace; surviving writes must not deref a freed
//               support pointer (weak_ptr capture per fix).
//   Hazard 3: SamplingEngine on_bucket_tick read phase against an async
//             ReadValueHandler whose callback fires after the synchronous
//             return path.
//             - Per-bucket continuation chain holds heap state, so the
//               read callback completes against valid storage. Lives in
//               sampling_engine_async_read_tests.cpp.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_namespace_monitoring.h"
#include "ua_sinks.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_write_value.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

class RecordingSink : public SampleSink
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

  size_t sample_count()
  {
    std::lock_guard lock{mMutex};
    return mSamples.size();
  }

private:
  std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
};

}  // namespace

// section 8.2 Hazard 1 - concurrent create_monitoring / delete_monitoring against
// the same Namespace must not race on mRecords. The fix is the std::mutex
// inside NamespaceMonitoringSupport that this test exercises. Surfaces
// only under TSan but is correctness-relevant under any model: without the
// fix mRecords mutations from two threads can corrupt the unordered_map.
TEST(NamespaceMonitoringConcurrency, ConcurrentCreateDeleteIsRaceFree)
{
  boost::asio::thread_pool tp{2};
  auto addressSpace = AddressSpace::create("urn:test:hazard1-host", tp.get_executor());
  auto ns = default_ns::Namespace::create("uri://hazard1", tp.get_executor());
  const auto registered = addressSpace.try_add_namespace_sync(ns);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
  const uint16_t nsIndex = registered.value();

  // Pre-create some variable nodes for the create-monitoring requests to
  // resolve against. Use stable string ids so both threads can address
  // distinct nodes deterministically.
  constexpr int nodeCount = 32;
  for (int i = 0; i < nodeCount; ++i)
  {
    auto node = ns->create_node<default_ns::VariableNode>(NodeId{nsIndex, "var-" + std::to_string(i)});

    WriteValue wv;
    wv.node_id() = NodeId{nsIndex, "var-" + std::to_string(i)};
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value() = DataValue{Variant{int32_t{i}}};
    VoidResult ignored{StatusCode{Status::BadInternalError}};
    node->write_value_async(wv, nullptr, [&ignored](VoidResult r) mutable { ignored = std::move(r); });
  }

  auto sink = std::make_shared<RecordingSink>();

  std::atomic<bool> stop{false};
  std::atomic<int> createCount{0};
  std::atomic<int> deleteCount{0};

  auto driver = [&](int seedOffset)
  {
    while (!stop.load(std::memory_order_relaxed))
    {
      // Issue a small create batch.
      std::vector<MonitoringCreateItem> items;
      const int base = (createCount.fetch_add(1) + seedOffset) % nodeCount;
      MonitoringCreateItem item;
      item.nodeId = NodeId{nsIndex, "var-" + std::to_string(base)};
      item.attributeId = AttributeId::Value;
      item.monitoredItemId = static_cast<IntegerId>(createCount.load());
      item.samplingInterval = 0;  // Exception path - exercises mNextHandle / mRecords.
      item.queueSize = 1;
      item.sink = sink;
      items.push_back(std::move(item));

      MonitoringHandle createdHandle{0};
      std::atomic<bool> created{false};
      ns->create_monitoring_async(RequestInfo{},
        nullptr,
        items,

        [&createdHandle, &created](BatchResult<MonitoringCreateItemResult> r) mutable
        {
          if (!r.items.empty() && r.items[0].is_good())
          {
            createdHandle = r.items[0].value().handle;
          }
          created = true;
        });
      while (!created.load())
      {
        std::this_thread::sleep_for(100us);
      }

      if (createdHandle != 0)
      {
        std::vector<MonitoringHandle> handles{createdHandle};
        std::atomic<bool> deleted{false};
        ns->delete_monitoring_async(RequestInfo{},
          handles,

          [&deleted](BatchResult<VoidResult>) mutable { deleted = true; });
        while (!deleted.load())
        {
          std::this_thread::sleep_for(100us);
        }
        deleteCount.fetch_add(1);
      }
    }
  };

  std::thread t1{driver, 0};
  std::thread t2{driver, nodeCount / 2};

  // Run for ~150ms - long enough for TSan to surface a race if any exists,
  // short enough to keep the test fast.
  std::this_thread::sleep_for(150ms);
  stop.store(true);
  t1.join();
  t2.join();

  EXPECT_GT(createCount.load(), 0);
  EXPECT_GT(deleteCount.load(), 0);

  ::ua::test_utils::drain_with_timeout(tp);
}

// section 8.2 Hazard 2 - a Node that outlives its namespace and the monitoring helper of the
// namespace's registration must not reach the freed helper when it is written: the Node holds
// no strong reference to the helper, and a write after both are gone completes and reports
// nothing.
TEST(NamespaceMonitoringConcurrency, AWriteAfterTheNamespaceAndItsHelperAreGoneCompletes)
{
  boost::asio::thread_pool tp{1};
  std::shared_ptr<default_ns::VariableNode> node;
  std::shared_ptr<RecordingSink> sink;
  uint16_t nsIndex{0};
  {
    auto addressSpace = AddressSpace::create("urn:test:hazard2-host", tp.get_executor());
    auto ns = default_ns::Namespace::create("uri://hazard2", tp.get_executor());
    const auto registered = addressSpace.try_add_namespace_sync(ns);
    ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
    nsIndex = registered.value();

    NodeId nodeId{nsIndex, "var"};
    node = ns->create_node<default_ns::VariableNode>(nodeId);

    sink = std::make_shared<RecordingSink>();

    MonitoringCreateItem item;
    item.nodeId = nodeId;
    item.attributeId = AttributeId::Value;
    item.monitoredItemId = 1;
    item.samplingInterval = 0;
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
    // ns and its address space go out of scope here, and with the address space the
    // registration's monitoring helper. The Node, on whose Value an item was reported,
    // outlives them; it is the next write that exercises the path to a helper that is
    // gone.
  }

  // Were the Node to reach the freed helper, this write would crash under ASan or
  // scribble memory under release builds. It completes, and the item's sink is given
  // nothing.
  WriteValue wv;
  wv.node_id() = NodeId{nsIndex, "var"};
  wv.attribute_id() = utils::to_underlying(AttributeId::Value);
  wv.value() = DataValue{Variant{int32_t{42}}};

  std::atomic<bool> wrote{false};
  node->write_value_async(wv, nullptr, [&wrote](VoidResult) mutable { wrote = true; });
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (!wrote.load() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(100us);
  }

  EXPECT_TRUE(wrote.load()) << "the write did not complete";
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(sink->sample_count(), 0u) << "a write after the helper was gone was delivered";

  ::ua::test_utils::drain_with_timeout(tp);
}
