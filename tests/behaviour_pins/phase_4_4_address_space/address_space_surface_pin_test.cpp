// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (AddressSpace public surface).
//
// Scope:
//   AS-A/B/C - namespace-not-found pre-check (production default_ns).
//   AS-D/E   - argument forwarding to the selected Namespace
//              (FakeAsyncNamespace, recorded calls).
//   AS-F/G/H - delete_node_async cleanup loop, status propagation, and
//              cleanup-failure swallow contract (FakeAsyncNamespace +
//              FakeNode).
//   AS-I / AS-I' - typed find_async<T> BadNodeClassInvalid + match-success
//              (production default_ns).
//   AS-H'    - end-to-end cross-namespace cleanup verification on
//              production default_ns.
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. These pins drive `*_async` only.

#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"
#include "fake_node.h"

#include "ua_address_space.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_namespace.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

class EnumerateFailureNamespace final : public Namespace
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

  explicit EnumerateFailureNamespace(shared_ptr<const ErrorDetail> failure) : mFailure(std::move(failure))
  {}

  String uri() const override
  {
    return "urn:test:as-enumerate-failure";
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

  void enumerate_nodes_async(
    const RequestInfo& /*request*/, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    complete(Result<std::vector<NodeId>>{Status::BadInternalError, mFailure});
  }

private:
  shared_ptr<const ErrorDetail> mFailure;
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// AddressSpace requires an boost::asio::any_io_executor at construction. We provide a real
// boost::asio::thread_pool but the default `default_ns::Namespace` completes its callbacks
// inline on the calling thread, so the test does not actually post any work to
// the pool - std::promise / std::future on the main test thread is sufficient.
// The pool is held only because it is part of the AddressSpace's construction
// contract.

class AddressSpaceSurfacePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace = std::make_unique<AddressSpace>(
      AddressSpace::create(String{"urn:test:addr-space:pin"}, mPool->executor()));
  }

  void TearDown() override
  {
    // Explicit boost::asio::thread_pool::stop() in test teardown.
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
// AS-A - find_node_async rejects unknown namespace index with detail.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression that drops the namespace-not-found
// pre-check in `AddressSpaceImpl::find_node_async` (ua_address_space.cpp:43-51)
// would forward the call to a null pointer - UAF/crash. A regression that
// returns BadNodeIdUnknown without a detail would silently strip context that
// downstream services rely on.

TEST_F(AddressSpaceSurfacePin, FindNodeAsyncRejectsUnknownNamespaceIndex)
{
  // Namespace index 99 is not present in the array (the AddressSpace only
  // creates index 0 = "" and index 1 = the application namespace).
  const NodeId unknownNsNodeId{/*namespaceIndex=*/99u, std::string_view{"foo"}};

  std::promise<NodeAccessorResult> promise;
  mAddressSpace->find_node_async(unknownNsNodeId,

    [&promise](NodeAccessorResult result) { promise.set_value(std::move(result)); });

  auto result = promise.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr)
    << "namespace-not-found failure must carry an ErrorDetail (the highest repository priority)";
  // Source attribution: the detail was emitted by the AddressSpace layer.
  EXPECT_EQ(result.shared_detail()->source, "AddressSpace");
  EXPECT_EQ(result.shared_detail()->code, "NamespaceNotFound");
}

// ---------------------------------------------------------------------------
// AS-B - create_node_async rejects unknown namespace index with detail.
// ---------------------------------------------------------------------------

TEST_F(AddressSpaceSurfacePin, CreateNodeAsyncRejectsUnknownNamespaceIndex)
{
  const NodeId unknownNsNodeId{/*namespaceIndex=*/99u, std::string_view{"foo"}};

  std::promise<NodeAccessorResult> promise;
  mAddressSpace->create_node_async(unknownNsNodeId,
    NodeClass::Object,

    [&promise](NodeAccessorResult result) { promise.set_value(std::move(result)); });

  auto result = promise.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr) << "namespace-not-found failure must carry an ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "AddressSpace");
  EXPECT_EQ(result.shared_detail()->code, "NamespaceNotFound");
}

// ---------------------------------------------------------------------------
// AS-C - delete_node_async rejects unknown namespace index with detail.
// ---------------------------------------------------------------------------

TEST_F(AddressSpaceSurfacePin, DeleteNodeAsyncRejectsUnknownNamespaceIndex)
{
  const NodeId unknownNsNodeId{/*namespaceIndex=*/99u, std::string_view{"foo"}};

  std::promise<VoidResult> promise;
  mAddressSpace->delete_node_async(unknownNsNodeId,
    /*deleteForwardHierarchicalRefs=*/true,
    ReferenceHalves::Both,
    [&promise](VoidResult result) { promise.set_value(std::move(result)); });

  auto result = promise.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr) << "namespace-not-found failure must carry an ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "AddressSpace");
  EXPECT_EQ(result.shared_detail()->code, "NamespaceNotFound");
}

// ---------------------------------------------------------------------------
// AS-D - find_node_async forwards the NodeId verbatim to the selected
//        Namespace, and the user callback receives the staged result.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_address_space.cpp:43-52 that
// silently rewrites the NodeId (e.g. drops the namespace index, swaps the
// identifier kind) before forwarding to the namespace would silently
// corrupt every cross-namespace request. Asserting the recorded NodeId
// equals the requested NodeId catches all such regressions.

// @relation(AC-COMP-SVR-AS-RESULT-ROUTING-01-FIND, scope=function)
TEST_F(AddressSpaceSurfacePin, FindNodeAsyncForwardsNodeIdToSelectedNamespace)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:as-d:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 1u);

  const NodeId targetId{fakeIndex, std::string_view{"as-d:foo"}};
  shared_ptr<const ErrorDetail> stagedDetail =
    make_error_detail("AsDStub", "stubbed by AS-D", "FakeAsyncNamespace");
  fakeNs->set_next_find_node_result(NodeResult{Status::BadNodeIdUnknown, stagedDetail});

  std::promise<NodeAccessorResult> p;
  mAddressSpace->find_node_async(targetId, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  // Recorded call: exactly one find_node with the target NodeId.
  auto recorded = fakeNs->recorded_calls();
  ASSERT_EQ(recorded.size(), 1u) << "expected exactly one recorded namespace call";
  EXPECT_EQ(recorded[0].op, FakeAsyncNamespace::Op::FindNode);
  EXPECT_EQ(recorded[0].nodeId, targetId);

  // User callback receives the canned result (status + detail).
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  EXPECT_EQ(result.shared_detail(), stagedDetail);
}

// @relation(AC-COMP-SVR-AS-RESULT-ROUTING-02-FIND-BATCH, scope=function)
TEST_F(AddressSpaceSurfacePin, FindNodesAsyncPreservesPerItemSentinelFailure)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:as-batch:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 1u);

  const std::vector<NodeId> requested{
    NodeId{fakeIndex, std::string_view{"as-batch:good"}},
    NodeId{fakeIndex, std::string_view{"as-batch:bad"}},
  };
  auto goodNode = std::make_shared<FakeNode>(requested[0], NodeClass::Object);
  shared_ptr<const ErrorDetail> stagedDetail =
    make_error_detail("AsBatchStub", "stubbed batch failure", "FakeAsyncNamespace");
  fakeNs->set_next_find_node_result(NodeResult{std::shared_ptr<Node>{goodNode}});
  fakeNs->set_next_find_node_result(NodeResult{Status::BadNodeIdUnknown, stagedDetail});

  std::promise<BatchResult<NodeAccessorResult>> promise;
  mAddressSpace->find_nodes_async(
    requested, [&promise](BatchResult<NodeAccessorResult> result) { promise.set_value(std::move(result)); });
  auto result = promise.get_future().get();

  EXPECT_TRUE(result.batchStatus.is_good());
  ASSERT_EQ(result.items.size(), requested.size());
  ASSERT_TRUE(result.items[0].is_good());
  EXPECT_EQ(result.items[0].value().get_node_id(), requested[0]);
  EXPECT_EQ(result.items[1].status_code(), Status::BadNodeIdUnknown);
  EXPECT_EQ(result.items[1].shared_detail(), stagedDetail);
}

// @relation(AC-COMP-SVR-AS-RESULT-ROUTING-03-ENUMERATE, scope=function)
TEST_F(AddressSpaceSurfacePin, EnumerateNodesAsyncPreservesSentinelFailure)
{
  shared_ptr<const ErrorDetail> stagedDetail =
    make_error_detail("AsEnumerateStub", "stubbed enumeration failure", "EnumerateFailureNamespace");
  auto failureNamespace = std::make_shared<EnumerateFailureNamespace>(stagedDetail);
  const auto failureIndex = mAddressSpace->add_namespace_sync(failureNamespace);
  ASSERT_GT(failureIndex, 1u);

  std::promise<Result<std::vector<NodeId>>> promise;
  mAddressSpace->enumerate_nodes_async(
    failureIndex, [&promise](Result<std::vector<NodeId>> result) { promise.set_value(std::move(result)); });
  auto result = promise.get_future().get();

  EXPECT_EQ(result.status_code(), Status::BadInternalError);
  EXPECT_EQ(result.shared_detail(), stagedDetail);
}

// ---------------------------------------------------------------------------
// AS-E - create_node_async forwards (NodeId, NodeClass) verbatim to the
//        selected Namespace.
// ---------------------------------------------------------------------------
//
// The optional KeyValuePair extensions array is not recorded by
// FakeAsyncNamespace's minimal recorder (extensions semantics are
// namespace-impl-specific and the runbook section 4.0.1 deliberately keeps the
// recorder lean). NodeId + NodeClass are sufficient to falsify forwarding-
// fidelity regressions; extensions threading is exercised at the
// namespace-impl pin layer (4.4b territory).

// @relation(AC-COMP-SVR-AS-RESULT-ROUTING-04-CREATE, scope=function)
TEST_F(AddressSpaceSurfacePin, CreateNodeAsyncForwardsArgsToSelectedNamespace)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:as-e:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 1u);

  const NodeId targetId{fakeIndex, std::string_view{"as-e:newnode"}};
  shared_ptr<const ErrorDetail> stagedDetail =
    make_error_detail("AsEStub", "stubbed by AS-E", "FakeAsyncNamespace");
  fakeNs->set_next_create_node_result(NodeResult{Status::BadNodeIdExists, stagedDetail});

  std::promise<NodeAccessorResult> p;
  mAddressSpace->create_node_async(
    targetId, NodeClass::Method, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  auto recorded = fakeNs->recorded_calls();
  ASSERT_EQ(recorded.size(), 1u);
  EXPECT_EQ(recorded[0].op, FakeAsyncNamespace::Op::CreateNode);
  EXPECT_EQ(recorded[0].nodeId, targetId);
  EXPECT_EQ(recorded[0].nodeClass, NodeClass::Method);

  EXPECT_EQ(result.status_code(), Status::BadNodeIdExists);
  EXPECT_EQ(result.shared_detail(), stagedDetail);
}

// ---------------------------------------------------------------------------
// AS-G - delete_node_async forwards a bad DeleteNodeResult to the user
//        callback with status + ErrorDetail (lossless propagation).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_address_space.cpp:185-186 that
// drops `result.shared_detail()` (lossy substitution) breaks the
// ErrorDetail-propagation invariant. Asserting pointer-identity on the
// staged detail catches this.

// @relation(AC-COMP-SVR-AS-RESULT-ROUTING-05-DELETE, scope=function)
TEST_F(AddressSpaceSurfacePin, DeleteNodeAsyncFinalCallbackForwardsStatusOnFailure)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:as-g:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 1u);

  auto stagedDetail = make_error_detail("AsGStub", "stubbed by AS-G", "FakeAsyncNamespace");
  std::shared_ptr<const ErrorDetail> stagedDetailPtr{std::move(stagedDetail)};
  fakeNs->set_next_delete_node_result(DeleteNodeResult{Status::BadInternalError, stagedDetailPtr});

  const NodeId deletedId{fakeIndex, std::string_view{"as-g:deleted"}};
  std::promise<VoidResult> p;
  mAddressSpace->delete_node_async(deletedId,
    // Single-node delete + cross-namespace external-reference cleanup (this is the
    // path that runs the cleanup loop). The cascade semantics of `true` are exercised
    // by the instantiation/cascade tests, not here.
    /*deleteForwardHierarchicallyReferencedNodes=*/false,
    ReferenceHalves::Both,
    [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInternalError);
  // Lossless propagation (pointer identity).
  EXPECT_EQ(result.shared_detail(), stagedDetailPtr);
}

// ---------------------------------------------------------------------------
// AS-H - delete_node_async answers Good when the namespace of a referrer named
//        by an ExternalReference does not hold that referrer.
// ---------------------------------------------------------------------------
//
// For the ExternalReferences the source namespace's delete reports, the
// address space removes each referrer's half with one remove_references_async
// per referrer namespace (remove_other_halves in ua_node_deletion.cpp), without
// looking the referrer up first. A removal answered Bad_NodeIdUnknown means
// that namespace does not hold the referrer, so no half is left behind and the
// user callback observes Good.

TEST_F(AddressSpaceSurfacePin, DeleteNodeAsyncSwallowsExternalReferenceCleanupFailures)
{
  auto sourceNs = FakeAsyncNamespace::create("urn:test:as-h:source");
  auto targetNs = FakeAsyncNamespace::create("urn:test:as-h:target");
  const auto sourceIndex = mAddressSpace->add_namespace_sync(sourceNs);
  const auto targetIndex = mAddressSpace->add_namespace_sync(targetNs);
  ASSERT_GT(sourceIndex, 1u);

  const NodeId deletedId{sourceIndex, std::string_view{"as-h:deleted"}};
  const NodeId externalTargetId{targetIndex, std::string_view{"as-h:bar"}};

  // Source returns one ExternalReference.
  std::vector<ExternalReference> exts;
  exts.push_back(ExternalReference{NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{externalTargetId},
    /*is_forward=*/true});
  sourceNs->set_next_delete_node_result(DeleteNodeResult{std::move(exts)});

  // The target namespace does not hold the referrer: its removal of the referrer's half answers
  // Bad_NodeIdUnknown.
  targetNs->set_next_remove_reference(externalTargetId,
    VoidResult{StatusCode{Status::BadNodeIdUnknown},
      make_error_detail("AsHStub", "stubbed by AS-H", "FakeAsyncNamespace")});

  std::promise<VoidResult> p;
  mAddressSpace->delete_node_async(deletedId,
    // Single-node delete + cross-namespace external-reference cleanup (this is the
    // path that runs the cleanup loop). The cascade semantics of `true` are exercised
    // by the instantiation/cascade tests, not here.
    /*deleteForwardHierarchicallyReferencedNodes=*/false,
    ReferenceHalves::Both,
    [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_good())
    << "a referrer its namespace does not hold leaves no half behind; the user callback observes Good. "
    << "Got status 0x" << std::hex << result.status_code().as_uint32();

  // The source recorded the delete. The target recorded no lookup and one removal: the referrer's half, the
  // inverse of the reported ExternalReference.
  EXPECT_EQ(sourceNs->recorded_calls().size(), 1u);
  EXPECT_TRUE(targetNs->recorded_calls().empty());
  const auto removed = targetNs->recorded_remove_reference_calls(externalTargetId);
  ASSERT_EQ(removed.size(), 1u);
  EXPECT_EQ(removed[0].type, NodeId{ReferenceTypeId::HasComponent});
  EXPECT_EQ(removed[0].target, ExpandedNodeId{deletedId});
  EXPECT_FALSE(removed[0].isForward);
}

// ---------------------------------------------------------------------------
// AS-I - find_async<T> template helper returns BadNodeClassInvalid on type
//        mismatch (e.g. asking for a MethodAccessor when the resolved node is
//        a Variable).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in the typed-wrapper template at
// ua_address_space.h:58-76 that fails to map "node found but wrong class" to
// BadNodeClassInvalid would either UAF (nullopt unwrapped) or silently return
// an unrelated status. The pin asserts the documented contract.

TEST_F(AddressSpaceSurfacePin, FindAsyncTemplateReturnsBadNodeClassInvalidOnTypeMismatch)
{
  // Create a Variable node in the application namespace (index 1 by default).
  const NodeId variableNodeId{/*namespaceIndex=*/1u, std::string_view{"a-variable"}};
  std::promise<NodeAccessorResult> createPromise;
  mAddressSpace->create_node_async(variableNodeId,
    NodeClass::Variable,

    [&createPromise](NodeAccessorResult result) { createPromise.set_value(std::move(result)); });
  auto createResult = createPromise.get_future().get();
  ASSERT_TRUE(createResult.is_good()) << "precondition: Variable node should be creatable; got status 0x"
                                      << std::hex << createResult.status_code().as_uint32();

  // Now ask for it as a MethodAccessor - must yield BadNodeClassInvalid.
  std::promise<MethodAccessorResult> findPromise;
  mAddressSpace->find_async<MethodAccessor>(variableNodeId,
    [&findPromise](MethodAccessorResult result) { findPromise.set_value(std::move(result)); });

  auto result = findPromise.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeClassInvalid)
    << "find_async<MethodAccessor> on a Variable node must yield BadNodeClassInvalid; got 0x" << std::hex
    << result.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// AS-I' - find_async<T> template helper returns the typed accessor on a
//         class match (success-branch counterpart to AS-I).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in the typed-wrapper template's
// success path (ua_address_space.h:64-65 - `callback(std::move(*typed))`)
// that returns a default-constructed result, swaps the typed value, or
// fails to unwrap the optional would silently break every consumer of
// typed find_async helpers. AS-I locks the failure branch; AS-I' locks the
// success branch - the pair is the falsifiable contract for the helper.

TEST_F(AddressSpaceSurfacePin, FindAsyncTemplateReturnsTypedAccessorOnTypeMatch)
{
  // Create a Method node in the application namespace.
  const NodeId methodNodeId{/*namespaceIndex=*/1u, std::string_view{"as-i-prime:method"}};
  std::promise<NodeAccessorResult> createPromise;
  mAddressSpace->create_node_async(methodNodeId,
    NodeClass::Method,

    [&createPromise](NodeAccessorResult result) { createPromise.set_value(std::move(result)); });
  ASSERT_TRUE(createPromise.get_future().get().is_good());

  // find_async<MethodAccessor> on a Method node must yield the typed
  // accessor with status Good and matching node id.
  std::promise<MethodAccessorResult> findPromise;
  mAddressSpace->find_async<MethodAccessor>(
    methodNodeId, [&findPromise](MethodAccessorResult result) { findPromise.set_value(std::move(result)); });

  auto result = findPromise.get_future().get();
  ASSERT_TRUE(result.is_good()) << "find_async<MethodAccessor> on a Method node must yield Good; got 0x"
                                << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(result.value().get_node_id(), methodNodeId);
}

// ---------------------------------------------------------------------------
// AS-H' - delete_node_async runs the external-reference cleanup loop end-to-
//         end against cross-namespace inverse references.
// ---------------------------------------------------------------------------
//
// Strengthens the deferred AS-H pin (which documents current behaviour for
// fire-and-forget cleanup-failure handling). AS-H' verifies the
// observable side-effect of the cleanup loop at
// ua_address_space.cpp:171-205 - for each ExternalReference returned by
// the source namespace's delete_node, the impl must remove the target's
// half through the target namespace's remove_references_async to drop the
// dangling inverse edge.
//
// Bug this would catch: a regression that drops the cleanup loop entirely
// (or replaces it with a no-op) leaves the target's inverse reference in
// place. The pin observes via get_references_async on the target node
// after the source delete completes - pre-delete the target carries the
// inverse, post-delete it carries nothing.

TEST_F(AddressSpaceSurfacePin, DeleteNodeAsyncCleanupRemovesInverseReferencesEndToEnd)
{
  // Add a second namespace alongside the application namespace (idx 1).
  auto ns2 = mAddressSpace->create_namespace("urn:test:as-h-prime:second", {});
  ASSERT_NE(ns2, nullptr);
  const auto ns2Index = mAddressSpace->add_namespace_sync(ns2);
  ASSERT_GT(ns2Index, 1u);

  const NodeId sourceId{/*namespaceIndex=*/1u, std::string_view{"as-h-prime:source"}};
  const NodeId targetId{ns2Index, std::string_view{"as-h-prime:target"}};

  // Create source (Object in ns1) and target (Variable in ns2).
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      sourceId, NodeClass::Object, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      targetId, NodeClass::Variable, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  // Add forward HasComponent reference source -> target (cross-namespace).
  {
    std::promise<NodeAccessorResult> findP;
    mAddressSpace->find_node_async(
      sourceId, [&findP](NodeAccessorResult r) { findP.set_value(std::move(r)); });
    auto source = findP.get_future().get();
    ASSERT_TRUE(source.is_good());

    std::promise<VoidResult> addP;
    source.value().add_reference_async(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{targetId},
      /*isForward=*/true,
      ReferenceHalves::Both,
      [&addP](VoidResult r) { addP.set_value(std::move(r)); });
    ASSERT_TRUE(addP.get_future().get().is_good());
  }

  // Add inverse HasComponent reference target -> source (cross-namespace).
  // This mirrors what a complete bi-directional reference setup looks like;
  // it is also the inverse the cleanup loop is expected to clear.
  {
    std::promise<NodeAccessorResult> findP;
    mAddressSpace->find_node_async(
      targetId, [&findP](NodeAccessorResult r) { findP.set_value(std::move(r)); });
    auto target = findP.get_future().get();
    ASSERT_TRUE(target.is_good());

    std::promise<VoidResult> addP;
    target.value().add_reference_async(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{sourceId},
      /*isForward=*/false,
      ReferenceHalves::Both,
      [&addP](VoidResult r) { addP.set_value(std::move(r)); });
    ASSERT_TRUE(addP.get_future().get().is_good());
  }

  // Precondition: target carries exactly the inverse reference.
  {
    std::promise<NodeAccessorResult> findP;
    mAddressSpace->find_node_async(
      targetId, [&findP](NodeAccessorResult r) { findP.set_value(std::move(r)); });
    auto target = findP.get_future().get();
    ASSERT_TRUE(target.is_good());

    std::promise<NodeAccessor::ReferencesResult> refsP;
    target.value().get_references_async(
      [&refsP](NodeAccessor::ReferencesResult r) { refsP.set_value(std::move(r)); });
    auto refs = refsP.get_future().get();
    ASSERT_TRUE(refs.is_good());
    ASSERT_EQ(refs.value().size(), 1u) << "precondition: target should hold the inverse ref before delete";
  }

  // Delete source via AddressSpace - the cleanup loop must walk the
  // ExternalReferences returned from ns1's delete_node and call
  // remove_references_async for the matching target node in ns2.
  {
    std::promise<VoidResult> p;
    mAddressSpace->delete_node_async(sourceId,
      /*deleteForwardHierarchicalRefs=*/true,
      ReferenceHalves::Both,
      [&p](VoidResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  // Postcondition: target's inverse ref is gone - cleanup loop ran.
  {
    std::promise<NodeAccessorResult> findP;
    mAddressSpace->find_node_async(
      targetId, [&findP](NodeAccessorResult r) { findP.set_value(std::move(r)); });
    auto target = findP.get_future().get();
    ASSERT_TRUE(target.is_good()) << "target should still exist after source delete";

    std::promise<NodeAccessor::ReferencesResult> refsP;
    target.value().get_references_async(
      [&refsP](NodeAccessor::ReferencesResult r) { refsP.set_value(std::move(r)); });
    auto refs = refsP.get_future().get();
    ASSERT_TRUE(refs.is_good());
    EXPECT_EQ(refs.value().size(), 0u)
      << "cleanup loop must remove the half held by each ExternalReference target";
  }
}

}  // namespace ua::test::behaviour_pins
