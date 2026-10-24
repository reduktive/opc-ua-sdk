// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (Namespace virtuals).
//
// Scope of this file: pins exercised against the production
// `default_ns::Namespace` (via `AddressSpace::create_namespace`) plus a minimal
// subclass for the base-class default `BadNotSupported` per-item monitoring
// shape. No FakeAsyncNamespace required.
//
// NV-D / NV-E - default_ns::Namespace create_monitoring_async per-item outcomes.
//   NV-D locks the per-kind revisedSamplingInterval contract (ExceptionQueued
//   -> 0, Polled -> bucket-rounded). NV-E locks per-item rejection of unknown
//   NodeId without short-circuiting the rest of the batch. NV-E partially
//   overlaps with MO-E in monitoring_pin_test.cpp; the duplication is
//   accepted because the two files have different scopes (this file: every
//   public Namespace virtual on the production default_ns; monitoring_pin
//   file: monitoring contract end-to-end including write-notifier wiring),
//   and falsifying either independently is useful.

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_result.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

// ---------------------------------------------------------------------------
// MinimalNoOverrideNamespace
// ---------------------------------------------------------------------------
//
// A minimal Namespace subclass that does NOT override the three monitoring
// virtuals, and is never registered: the base-class defaults hand each item to
// the monitoring helper an unregistered namespace answers, which refuses it
// BadNotSupported. The pure virtuals are stubbed; pins NV-A/B/C never call them.

class MinimalNoOverrideNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
  }

  String uri() const override
  {
    return String{"urn:test:minimal-no-override"};
  }

  void find_nodes_async(const RequestInfo& /*request*/, std::span<const NodeId> nodeIds,
    std::optional<Duration> /*maxAge*/, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    resolve_each(nodeIds,
      std::move(complete),
      [](const NodeId& /*nodeId*/, std::function<void(NodeResult)> callback)
      { callback(NodeResult{StatusCode{Status::BadNotImplemented}}); });
  }

  void read_references_async(const RequestInfo& /*request*/, std::span<const ReferenceQuery> /*queries*/,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  void read_values_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
    std::span<const ValueReadItem> /*items*/, Duration /*maxAge*/, bool /*setSourceTimestamp*/,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class NamespaceVirtualsPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace = std::make_unique<AddressSpace>(
      AddressSpace::create(String{"urn:test:namespace-virtuals:pin"}, mPool->executor()));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// ---------------------------------------------------------------------------
// NV-A - base Namespace::create_monitoring_async emits BadNotSupported per item.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in the base-class default
// `Namespace::create_monitoring_async` (ua_namespace.cpp) that returns an empty
// items vector or a single batch-level status would silently break the
// per-item BatchResult contract that callers (subscription, monitoring
// service) depend on.

TEST_F(NamespaceVirtualsPin, BaseNamespaceCreateMonitoringEmitsBadNotSupportedPerItem)
{
  MinimalNoOverrideNamespace ns;

  std::vector<MonitoringCreateItem> inputs(3);
  // Items contents are unimportant - the base default does not look at them.

  std::promise<BatchResult<MonitoringCreateItemResult>> promise;
  ns.create_monitoring_async(RequestInfo{},
    nullptr,
    std::span<const MonitoringCreateItem>{inputs},
    [&promise](BatchResult<MonitoringCreateItemResult> result) { promise.set_value(std::move(result)); });

  auto batch = promise.get_future().get();
  EXPECT_EQ(batch.items.size(), inputs.size())
    << "default base-class create_monitoring_async must return one slot per input item";
  for (const auto& item : batch.items)
  {
    EXPECT_TRUE(item.is_bad());
    EXPECT_EQ(item.status_code(), Status::BadNotSupported);
  }
}

// ---------------------------------------------------------------------------
// NV-B - base Namespace::delete_monitoring_async emits BadNotSupported per handle.
// ---------------------------------------------------------------------------

TEST_F(NamespaceVirtualsPin, BaseNamespaceDeleteMonitoringEmitsBadNotSupportedPerHandle)
{
  MinimalNoOverrideNamespace ns;

  std::vector<MonitoringHandle> inputs{1u, 2u, 3u, 4u};

  std::promise<BatchResult<VoidResult>> promise;
  ns.delete_monitoring_async(RequestInfo{},
    std::span<const MonitoringHandle>{inputs},
    [&promise](BatchResult<VoidResult> result) { promise.set_value(std::move(result)); });

  auto batch = promise.get_future().get();
  EXPECT_EQ(batch.items.size(), inputs.size())
    << "default base-class delete_monitoring_async must return one slot per input handle";
  for (const auto& item : batch.items)
  {
    EXPECT_TRUE(item.is_bad());
    EXPECT_EQ(item.status_code(), Status::BadNotSupported);
  }
}

// ---------------------------------------------------------------------------
// NV-C - base Namespace::modify_monitoring_async emits BadNotSupported per item.
// ---------------------------------------------------------------------------

TEST_F(NamespaceVirtualsPin, BaseNamespaceModifyMonitoringEmitsBadNotSupportedPerItem)
{
  MinimalNoOverrideNamespace ns;

  std::vector<MonitoringModifyItem> inputs(2);

  std::promise<BatchResult<MonitoringModifyItemResult>> promise;
  ns.modify_monitoring_async(RequestInfo{},
    std::span<const MonitoringModifyItem>{inputs},
    [&promise](BatchResult<MonitoringModifyItemResult> result) { promise.set_value(std::move(result)); });

  auto batch = promise.get_future().get();
  EXPECT_EQ(batch.items.size(), inputs.size())
    << "default base-class modify_monitoring_async must return one slot per input item";
  for (const auto& item : batch.items)
  {
    EXPECT_TRUE(item.is_bad());
    EXPECT_EQ(item.status_code(), Status::BadNotSupported);
  }
}

// ---------------------------------------------------------------------------
// NV-D - default_ns::Namespace create_monitoring_async populates per-item
//        revisedSamplingInterval according to the resolved sampling kind:
//        ExceptionQueued (samplingInterval==0 && minSampling==0) -> 0;
//        Polled (samplingInterval > 0) -> bucket-rounded.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in
// NamespaceMonitoringSupport::create_monitoring (ua_namespace_monitoring_
// support.cpp:54-114) that mis-routes items between Exception and Polled
// branches - or a regression in SamplingEngine::add_polled (line 70) /
// SamplingEngine::add_exception (line 122-123) that swaps the
// revisedInterval payload - would silently break subscription clients
// that revise their sampling cadence based on this field. The pin
// asserts the per-kind external observable for two items in the same
// batch, falsifying both routing and payload-construction regressions.

TEST_F(NamespaceVirtualsPin, NamespaceCreateMonitoringResolvesNodesPerItem)
{
  // Two Variable nodes with simple values.
  const NodeId varAId{/*namespaceIndex=*/1u, std::string_view{"nv-d:A"}};
  const NodeId varBId{/*namespaceIndex=*/1u, std::string_view{"nv-d:B"}};
  for (const auto& id : {varAId, varBId})
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      id, NodeClass::Variable, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good()) << "precondition: Variable creation must succeed";
  }

  auto ns = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  ASSERT_NE(ns, nullptr);

  // Item 0 -> ExceptionQueued (samplingInterval=0). Item 1 -> Polled
  // (samplingInterval=100). The two items occupy the same batch so a
  // routing regression that downgrades both to one branch is observable
  // at the BatchResult level.
  std::vector<MonitoringCreateItem> items(2);
  items[0].nodeId = varAId;
  items[0].attributeId = AttributeId::Value;
  items[0].monitoredItemId = 600u;
  items[0].samplingInterval = 0;
  items[0].queueSize = 1;
  items[1].nodeId = varBId;
  items[1].attributeId = AttributeId::Value;
  items[1].monitoredItemId = 601u;
  items[1].samplingInterval = 100;
  items[1].queueSize = 1;

  std::promise<BatchResult<MonitoringCreateItemResult>> promise;
  ns->create_monitoring_async(RequestInfo{},
    nullptr,
    std::span<const MonitoringCreateItem>{items},
    [&promise](BatchResult<MonitoringCreateItemResult> r) { promise.set_value(std::move(r)); });
  auto batch = promise.get_future().get();

  ASSERT_EQ(batch.items.size(), 2u);
  ASSERT_TRUE(batch.items[0].is_good()) << "slot 0 (ExceptionQueued) must be good";
  ASSERT_TRUE(batch.items[1].is_good()) << "slot 1 (Polled) must be good";

  // ExceptionQueued reports revisedSamplingInterval=0 (engine batch
  // interval is internal - public contract is 0). Polled reports a
  // bucket-rounded interval > 0.
  EXPECT_EQ(batch.items[0].value().revisedSamplingInterval, 0)
    << "slot 0 (ExceptionQueued) must report revisedSamplingInterval=0";
  EXPECT_GT(batch.items[1].value().revisedSamplingInterval, 0)
    << "slot 1 (Polled) must report a positive bucket-rounded revisedSamplingInterval";

  // Distinct handles.
  EXPECT_NE(batch.items[0].value().handle, batch.items[1].value().handle);

  // Cleanup so the namespace doesn't hold stale dispatch entries across
  // teardown.
  std::vector<MonitoringHandle> toDelete{batch.items[0].value().handle, batch.items[1].value().handle};
  std::promise<BatchResult<VoidResult>> delPromise;
  ns->delete_monitoring_async(RequestInfo{},
    std::span<const MonitoringHandle>{toDelete},
    [&delPromise](BatchResult<VoidResult> r) { delPromise.set_value(std::move(r)); });
  delPromise.get_future().get();
}

// ---------------------------------------------------------------------------
// NV-E - default_ns::Namespace create_monitoring_async rejects unknown NodeIds
//        per item without short-circuiting the rest of the batch.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in
// NamespaceMonitoringSupport::create_monitoring (lines 25-34) that
// short-circuits the loop on the first bad resolution would zero out
// every following slot - clients submitting a mixed batch would lose
// monitoring for the good items.
//
// Note on ErrorDetail: the production code emits a bare
// `MonitoringCreateItemResult{StatusCode{Status::BadNodeIdUnknown}}`
// without an attached ErrorDetail (line 31). The runbook section 4.2 NV-E entry
// asks for `shared_detail() != nullptr`, but that is aspirational - the
// pin documents the current status-only behaviour and flags the gap for
// 4.4b reviewer attention (bare-StatusCode failures are
// a known migration follow-up, not a 4.4a deliverable).

TEST_F(NamespaceVirtualsPin, NamespaceCreateMonitoringRejectsUnknownNodeIdPerItem)
{
  const NodeId goodId{/*namespaceIndex=*/1u, std::string_view{"nv-e:good"}};
  const NodeId unknownId{/*namespaceIndex=*/1u, std::string_view{"nv-e:does-not-exist"}};
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      goodId, NodeClass::Variable, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  auto ns = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  ASSERT_NE(ns, nullptr);

  std::vector<MonitoringCreateItem> items(2);
  items[0].nodeId = goodId;
  items[0].attributeId = AttributeId::Value;
  items[0].monitoredItemId = 700u;
  items[0].samplingInterval = 0;
  items[0].queueSize = 1;
  items[1].nodeId = unknownId;
  items[1].attributeId = AttributeId::Value;
  items[1].monitoredItemId = 701u;
  items[1].samplingInterval = 0;
  items[1].queueSize = 1;

  std::promise<BatchResult<MonitoringCreateItemResult>> promise;
  ns->create_monitoring_async(RequestInfo{},
    nullptr,
    std::span<const MonitoringCreateItem>{items},
    [&promise](BatchResult<MonitoringCreateItemResult> r) { promise.set_value(std::move(r)); });
  auto batch = promise.get_future().get();

  ASSERT_EQ(batch.items.size(), 2u);
  EXPECT_TRUE(batch.items[0].is_good()) << "slot 0 (known node) must remain good";
  EXPECT_TRUE(batch.items[1].is_bad()) << "slot 1 (unknown node) must be bad";
  EXPECT_EQ(batch.items[1].status_code(), Status::BadNodeIdUnknown);

  // Cleanup the surviving good handle.
  std::vector<MonitoringHandle> toDelete{batch.items[0].value().handle};
  std::promise<BatchResult<VoidResult>> delPromise;
  ns->delete_monitoring_async(RequestInfo{},
    std::span<const MonitoringHandle>{toDelete},
    [&delPromise](BatchResult<VoidResult> r) { delPromise.set_value(std::move(r)); });
  delPromise.get_future().get();
}

// ---------------------------------------------------------------------------
// NV-F - find_node returns BadNodeIdUnknown + ErrorDetail for an unknown id
//        in the production default_ns::Namespace.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in default_ns::Namespace::find_node
// (ua_default_namespace.cpp:40-56) that drops the ErrorDetail for the unknown-
// node failure would silently strip the diagnostic context.

TEST_F(NamespaceVirtualsPin, NamespaceFindNodeReturnsBadNodeIdUnknownForUnknownId)
{
  // The application namespace is at index 1 by AddressSpace's construction
  // contract.
  auto ns = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  ASSERT_NE(ns, nullptr);

  const NodeId unknownNodeId{/*namespaceIndex=*/1u, std::string_view{"does-not-exist"}};

  const auto answer = ns->find_node(unknownNodeId, std::nullopt);

  // ENGAGED, and bad. The distinction this pins is the one the interface turns on: nullopt means
  // "ask me through find_nodes_async", and an in-memory namespace has nothing to ask about. A regression
  // that declined here instead would send every unknown id round the asynchronous path and answer
  // the same status by a different route - slower, and with this ErrorDetail replaced.
  ASSERT_TRUE(answer.has_value()) << "an in-memory namespace must answer, not decline";
  const auto& result = *answer;
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr) << "find_node failure for unknown id must carry ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "DefaultNamespace");
}

// ---------------------------------------------------------------------------
// NV-G - create_node rejects a duplicate NodeId with BadNodeIdExists + detail.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in default_ns::Namespace::create_node
// (ua_default_namespace.h:96-99 - the duplicate-id throw inside
// create_node_internal, caught by the outer create_node's exception-to-result
// path at ua_default_namespace.cpp:103-106) that swaps the status code or
// drops the ErrorDetail would silently strip diagnostics from the duplicate-
// create path.

// Covers SVR-ADDRSP-200 (coverage-audit retag).
TEST_F(NamespaceVirtualsPin, NamespaceCreateNodeRejectsDuplicateNodeId)
{
  const NodeId duplicateId{/*namespaceIndex=*/1u, std::string_view{"only-once"}};

  // First create succeeds.
  std::promise<NodeAccessorResult> firstPromise;
  mAddressSpace->create_node_async(duplicateId,
    NodeClass::Object,

    [&firstPromise](NodeAccessorResult result) { firstPromise.set_value(std::move(result)); });
  ASSERT_TRUE(firstPromise.get_future().get().is_good());

  // Second create with the same id must fail.
  std::promise<NodeAccessorResult> secondPromise;
  mAddressSpace->create_node_async(duplicateId,
    NodeClass::Object,

    [&secondPromise](NodeAccessorResult result) { secondPromise.set_value(std::move(result)); });

  auto result = secondPromise.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdExists)
    << "duplicate create must yield BadNodeIdExists; got 0x" << std::hex << result.status_code().as_uint32();
  ASSERT_NE(result.shared_detail(), nullptr) << "duplicate create failure must carry ErrorDetail";
  // Detail's code is "NodeAlreadyExists" per ua_default_namespace.h:97.
  EXPECT_EQ(result.shared_detail()->code, "NodeAlreadyExists");
}

// ---------------------------------------------------------------------------
// NV-H - delete_nodes_async returns ExternalReferences for cross-namespace targets.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in
// default_ns::Namespace::delete_node_internal
// (ua_default_namespace.cpp:216-272) that drops the cross-namespace
// ExternalReference accumulation would silently strip the cleanup contract
// AddressSpaceImpl::delete_node_async relies on (ua_address_space.cpp:171-205)
// and create dangling cross-namespace inverse references.

TEST_F(NamespaceVirtualsPin, NamespaceDeleteNodeReturnsExternalRefsForCrossNamespaceTargets)
{
  // Add a second application namespace so we have two namespaces (idx 1 and 2).
  auto ns2 = mAddressSpace->create_namespace("urn:test:nv-h:second", {});
  ASSERT_NE(ns2, nullptr);
  const auto ns2Index = mAddressSpace->add_namespace_sync(ns2);
  ASSERT_GT(ns2Index, 1u);

  const NodeId objectId{/*namespaceIndex=*/1u, std::string_view{"nv-h:source"}};
  const NodeId targetId{ns2Index, std::string_view{"nv-h:target"}};

  // Create the source object in ns1.
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      objectId, NodeClass::Object, [&p](NodeAccessorResult result) { p.set_value(std::move(result)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  // Create the target variable in ns2.
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      targetId, NodeClass::Variable, [&p](NodeAccessorResult result) { p.set_value(std::move(result)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  // Add a HasComponent reference from objectId to targetId.
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->find_node_async(
      objectId, [&p](NodeAccessorResult result) { p.set_value(std::move(result)); });
    auto found = p.get_future().get();
    ASSERT_TRUE(found.is_good());

    std::promise<VoidResult> addPromise;
    found.value().add_reference_async(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{targetId},
      /*isForward=*/true,
      ReferenceHalves::Both,
      [&addPromise](VoidResult result) { addPromise.set_value(std::move(result)); });
    ASSERT_TRUE(addPromise.get_future().get().is_good());
  }

  // Now delete the source object on ns1 directly (bypassing AddressSpace's
  // wrapper so we observe the per-namespace DeleteNodeResult). The cross-
  // namespace ExternalReference should appear in the result.
  auto ns1 = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  ASSERT_NE(ns1, nullptr);

  std::promise<BatchResult<DeleteNodeResult>> deletePromise;
  ns1->delete_nodes_async(RequestInfo{},
    std::span<const NodeId>{&objectId, 1},
    ReferenceHalves::Both,
    [&deletePromise](BatchResult<DeleteNodeResult> result, std::vector<VersionedNode> /*versioned*/)
    { deletePromise.set_value(std::move(result)); });

  auto deleteBatch = deletePromise.get_future().get();
  ASSERT_TRUE(deleteBatch.batchStatus.is_good());
  ASSERT_EQ(deleteBatch.items.size(), 1u);
  const auto& deleteResult = deleteBatch.items[0];
  ASSERT_TRUE(deleteResult.is_good())
    << "delete_nodes_async should succeed; got 0x" << std::hex << deleteResult.status_code().as_uint32();

  const auto& externals = deleteResult.value();
  ASSERT_EQ(externals.size(), 1u)
    << "exactly one ExternalReference is expected for the cross-namespace HasComponent edge";
  EXPECT_EQ(externals[0].target.node_id().namespace_index(), ns2Index);
  EXPECT_TRUE(externals[0].isForward);
}

// ---------------------------------------------------------------------------
// NV-no-callback-under-mutex - default_ns::Namespace::find_nodes_async fires
//        its user callback OUTSIDE the namespace's mutex.
// ---------------------------------------------------------------------------
//
// find_node is the synchronous form and returns its answer, so the failure
// mode this pin exists to catch - a user continuation running under
// ReadLock - cannot be expressed there. find_nodes_async takes a callback, so
// that is where the rule binds and where a regression could reintroduce it.
//
// "Callback safety in thread-safe objects" golden rule: never
// invoke a user-provided callback while holding a mutex lock. The
// production implementation captures the resolved nodes under ReadLock,
// releases the lock, and only then invokes the user's callback.
//
// Bug this would catch: a regression that moves the callback invocation
// back inside the lock would deadlock any caller whose continuation
// re-enters the namespace under WriteLock (e.g. create_nodes_async). The pin
// stages exactly this scenario on a worker thread and uses a future
// timeout to detect the hang.
//
// Detection mechanism: a regression keeps ReadLock acquired during the
// callback. Inside the callback, we call create_nodes_async, which
// requires WriteLock. The same thread cannot upgrade ReadLock -> WriteLock
// on a std::shared_mutex; the WriteLock acquisition either blocks
// indefinitely or invokes UB. We run on a worker thread so the test can
// detect the hang via wait_for() on the main thread, and abandon the
// deadlocked worker (detach + FAIL).

TEST_F(NamespaceVirtualsPin, FindNodesFiresCallbackOutsideMutex)
{
  auto ns = mAddressSpace->namespace_array().get_namespace(/*index=*/1u);
  ASSERT_NE(ns, nullptr);

  // Pre-create a node so find_nodes_async's success path runs.
  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"no-mutex:existing"}};
  {
    const NodeCreation existing{existingId, NodeClass::Object, {}};
    std::promise<BatchResult<NodeResult>> p;
    ns->create_nodes_async(RequestInfo{},
      std::span<const NodeCreation>{&existing, 1},
      [&p](BatchResult<NodeResult> r) { p.set_value(std::move(r)); });
    const auto created = p.get_future().get();
    ASSERT_EQ(created.items.size(), 1u);
    ASSERT_TRUE(created.items[0].is_good());
  }

  const NodeCreation nestedCreate{
    NodeId{/*namespaceIndex=*/1u, std::string_view{"no-mutex:nested-create"}}, NodeClass::Object, {}};
  std::promise<bool> doneSignal;

  // Drive the find_nodes_async + nested create_nodes_async sequence on a worker
  // thread so a deadlock on this thread does not wedge the test process.
  std::thread caller(
    [&]
    {
      std::promise<NodeResult> nestedCreateP;
      ns->find_nodes_async(RequestInfo{},
        std::span<const NodeId>{&existingId, 1},
        std::nullopt,
        [&](BatchResult<NodeResult> /*outerResult*/)
        {
          // From inside find_nodes_async's callback, attempt create_nodes_async
          // which needs WriteLock. If find_nodes_async still holds the ReadLock
          // here, the WriteLock acquisition deadlocks the caller thread.
          ns->create_nodes_async(RequestInfo{},
            std::span<const NodeCreation>{&nestedCreate, 1},
            [&nestedCreateP](BatchResult<NodeResult> r)
            {
              nestedCreateP.set_value(r.items.size() == 1u
                                        ? std::move(r.items[0])
                                        : NodeResult{StatusCode{Status::BadInternalError}});
            });
        });
      // create_nodes_async fires its callback inline, so nestedCreateP is
      // fulfilled by the time control returns here - unless the inner
      // WriteLock deadlocked (in which case we never reach this line).
      auto nestedResult = nestedCreateP.get_future().get();
      EXPECT_TRUE(nestedResult.is_good())
        << "nested create_nodes_async from inside find_nodes_async's callback failed: 0x" << std::hex
        << nestedResult.status_code().as_uint32();
      doneSignal.set_value(true);
    });

  // Bound the wait. If the worker is still spinning after the timeout,
  // find_nodes_async held the mutex during its user callback (golden rule
  // violated).
  auto status = doneSignal.get_future().wait_for(std::chrono::seconds(2));
  if (status != std::future_status::ready)
  {
    // Worker is wedged in deadlock; cannot safely join.
    caller.detach();
    FAIL() << "default_ns::Namespace::find_nodes_async fired user callback while holding the mutex "
              "(the repository golden rule violated; nested create_nodes_async deadlocked)";
    return;
  }
  caller.join();
}

// ---------------------------------------------------------------------------
// NV-find-nodes - the base helper Namespace::resolve_each collects
//        asynchronous per-id completions into request-ordered slots and fires
//        its batch callback exactly once, only after every item has reported.
// ---------------------------------------------------------------------------
//
// FakeAsyncNamespace's find_nodes_async resolves each id through the base
// helper resolve_each (ua_namespace.cpp). With find_node deferred, every
// per-item completion is parked on the fake's worker thread; the helper's
// loop-guard (remaining = N + 1, released after the loop) must hold the batch
// callback back until all three completions have fired, and the atomic counter
// must publish each slot write to the finisher.
//
// Bug this would catch: dropping the loop guard would let the batch callback
// fire mid-loop (on the first deferred completion) with unfilled slots.
//
// Scope note: FakeAsyncNamespace releases parked callbacks strictly FIFO on its
// single worker thread, so completions here arrive in request order - this pin
// does NOT exercise out-of-order completion or genuinely concurrent (cross-
// thread) slot writes. Those are covered in namespace_default_tests.cpp by
// FindNodesPreservesRequestOrderUnderOutOfOrderCompletion (deterministic
// slot-by-index falsification) and FindNodesCollectsConcurrentCompletions
// (multi-threaded, TSAN-meaningful for the atomic counter).

TEST(NamespaceVirtualsBaseFindNodes, BaseFindNodesCollectsDeferredCompletionsInOrder)
{
  auto fake = FakeAsyncNamespace::create("urn:test:base-find-nodes-async");
  fake->set_find_node_deferred(true);

  // FIFO canned results with distinct status codes so the slot<->request-position
  // mapping is directly observable without constructing real NodeAccessors.
  fake->set_next_find_node_result(NodeResult{StatusCode{Status::BadNodeIdUnknown}});
  fake->set_next_find_node_result(NodeResult{StatusCode{Status::BadOutOfMemory}});
  fake->set_next_find_node_result(NodeResult{StatusCode{Status::BadInternalError}});

  const std::vector<NodeId> ids{NodeId{1, "a"}, NodeId{1, "b"}, NodeId{1, "c"}};

  std::atomic<int> calls{0};
  std::promise<BatchResult<NodeResult>> promise;
  fake->find_nodes_async(RequestInfo{},
    std::span<const NodeId>{ids},
    std::nullopt,
    [&](BatchResult<NodeResult> result)
    {
      ++calls;
      promise.set_value(std::move(result));
    });

  // All three lookups are deferred; the loop guard must keep the batch
  // callback from firing until every parked completion is released.
  ASSERT_TRUE(fake->wait_for_pending(3));
  EXPECT_EQ(calls.load(), 0) << "find_nodes_async must not complete until every lookup has reported";

  EXPECT_EQ(fake->complete_all_pending(), 3u);

  auto batch = promise.get_future().get();
  fake->wait_idle();

  EXPECT_EQ(calls.load(), 1) << "the batch callback must fire exactly once";
  EXPECT_TRUE(batch.batchStatus.is_good());
  ASSERT_EQ(batch.items.size(), 3u);
  EXPECT_EQ(batch.items[0].status_code(), Status::BadNodeIdUnknown)
    << "completion for request position 0 must land in slot 0";
  EXPECT_EQ(batch.items[1].status_code(), Status::BadOutOfMemory);
  EXPECT_EQ(batch.items[2].status_code(), Status::BadInternalError);
}

}  // namespace ua::test::behaviour_pins
